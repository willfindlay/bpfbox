/*
 *  🐝 BPFBox 📦  Application-transparent sandboxing rules with eBPF.
 *  Copyright (C) 2020  William Findlay
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  This file provides the kernelspace BPF program logic for BPFBox.
 *
 *  2020-Apr-10  William Findlay  Created this.
 *  2020-Jun-29  William Findlay  Updated to use LSM probes and ringbufs.
 */

#include "bpfbox/bpf/policy.h"

#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#error BPFBox requires Linux 5.8+
#endif

/* =========================================================================
 * Processes
 * ========================================================================= */

BPF_TABLE("lru_hash", u32, struct bpfbox_process_t, processes,
          BPFBOX_MAX_PROCESSES);

/* =========================================================================
 * Profiles
 * ========================================================================= */

BPF_HASH(profiles, u64, struct bpfbox_profile_t, BPFBOX_MAX_POLICY_SIZE);

/* =========================================================================
 * Policy
 * ========================================================================= */

BPF_HASH(fs_policy, struct bpfbox_fs_policy_key_t, struct bpfbox_policy_t,
         BPFBOX_MAX_POLICY_SIZE);

BPF_HASH(procfs_policy, struct bpfbox_procfs_policy_key_t,
         struct bpfbox_policy_t, BPFBOX_MAX_POLICY_SIZE);

/* =========================================================================
 * Auditing
 * ========================================================================= */

BPF_RINGBUF_OUTPUT(fs_audit_events, BPFBOX_AUDIT_RINGBUF_PAGES);

static __always_inline void audit_fs(struct bpfbox_process_t *process,
                                     enum bpfbox_action_t action,
                                     struct inode *inode,
                                     bpfbox_accesss_t access)
{
    FILTER_AUDIT(action);

    struct bpfbox_fs_audit_event_t *event =
        fs_audit_events.ringbuf_reserve(sizeof(struct bpfbox_fs_audit_event_t));

    DO_AUDIT_COMMON(event, process, action);

    event->st_ino = inode->i_ino;
    event->st_dev = (u32)new_encode_dev(inode->i_sb->s_dev);
    bpf_probe_read_str(event->s_id, sizeof(event->s_id), inode->i_sb->s_id);
    event->access = access;

    fs_audit_events.ringbuf_submit(event, 0);
}

// BPF_RINGBUF_OUTPUT(network_audit_events, BPFBOX_AUDIT_RINGBUF_PAGES);
//
// struct network_audit_event_t {
//     STRUCT_AUDIT_COMMON
// };
//
// static __always_inline void audit_network(struct bpfbox_process_t *process,
//                                           enum bpfbox_action_t action)
// {
//     FILTER_AUDIT(action);
//
//     struct network_audit_event_t *event =
//     network_audit_events.ringbuf_reserve(
//         sizeof(struct bpfbox_inode_audit_event_t));
//
//     DO_AUDIT_COMMON(event, process, action);
//
//     network_audit_events.ringbuf_submit(event, 0);
// }

/* =========================================================================
 * Helper Functions
 * ========================================================================= */

static __always_inline struct bpfbox_process_t *create_process(u32 pid,
                                                               u32 tgid,
                                                               u64 profile_key,
                                                               u8 tainted)
{
    struct bpfbox_process_t new_process = {};
    new_process.pid = pid;
    new_process.tgid = tgid;
    new_process.profile_key = profile_key;
    new_process.tainted = tainted;

    processes.update(&pid, &new_process);

    return processes.lookup(&pid);
}

static __always_inline struct bpfbox_process_t *get_current_process()
{
    u32 pid = bpf_get_current_pid_tgid();
    return processes.lookup(&pid);
}

static __always_inline enum bpfbox_action_t policy_decision(
    struct bpfbox_process_t *process, struct bpfbox_policy_t *policy,
    u32 access)
{
    // Set deny action based on whether or not we are enforcing
#ifndef BPFBOX_ENFORCING
    enum bpfbox_action_t deny_action = ACTION_COMPLAIN;
#else
    enum bpfbox_action_t deny_action = ACTION_DENY;
#endif

    // If we have no policy for this object, either deny or allow,
    // depending on if the process is tainted or not
    if (!policy) {
        if (process->tainted) {
            return deny_action;
        } else {
            return ACTION_ALLOW;
        }
    }

    // Set allow action based on whether or not we want to audit
    enum bpfbox_action_t allow_action = ACTION_ALLOW;
    if (access & policy->audit) {
        allow_action |= ACTION_AUDIT;
    }

    // Taint process if we hit a taint rule
    if (!process->tainted && (access & policy->taint)) {
        process->tainted = 1;
        return allow_action | ACTION_TAINT;
    }

    // If we are not tainted
    if (!process->tainted) {
        return allow_action;
    }

    // If we are tainted, but the operation is allowed
    if ((access & policy->allow) == access) {
        return allow_action;
    }

    // Default deny
    return deny_action;
}

/* Linux access mask to bpfbox access */
static __always_inline enum bpfbox_fs_access_t file_mask_to_access(int mask)
{
    enum bpfbox_fs_access_t access = 0;

    if (mask & MAY_READ) {
        access |= FS_READ;
    }

    // Appending and writing are mutually exclusive
    if (mask & MAY_APPEND) {
        access |= FS_APPEND;
    } else if (mask & MAY_WRITE) {
        access |= FS_WRITE;
    }

    if (mask & MAY_EXEC) {
        access |= FS_EXEC;
    }

    return access;
}

/* Linux fmode mask to bpfbox access */
static __always_inline enum bpfbox_fs_access_t fmode_to_access(umode_t mask)
{
    enum bpfbox_fs_access_t access = 0;

    if (mask & (FMODE_READ | FMODE_PREAD)) {
        access |= FS_READ;
    }

    // Appending and writing are mutually exclusive
    if (mask & (FMODE_WRITE | FMODE_PWRITE)) {
        if (mask & FMODE_LSEEK) {
            access |= FS_WRITE;
        } else {
            access |= FS_APPEND;
        }
    }

    if (mask & FMODE_EXEC) {
        access |= FS_EXEC;
    }

    if (mask & FMODE_WRITE_IOCTL) {
        access |= FS_IOCTL;
    }

    return access;
}

static __always_inline enum bpfbox_action_t fs_policy_decision(
    struct bpfbox_process_t *process, struct inode *inode,
    enum bpfbox_fs_access_t access)
{
    struct bpfbox_fs_policy_key_t key = {
        .st_ino = inode->i_ino,
        .st_dev = (u32)new_encode_dev(inode->i_sb->s_dev),
        .profile_key = process->profile_key,
    };

    struct bpfbox_policy_t *policy = fs_policy.lookup(&key);

    return policy_decision(process, policy, access);
}

/* =========================================================================
 * LSM Programs
 * ========================================================================= */

/* A task requests access @mask to @inode */
LSM_PROBE(inode_permission, struct inode *inode, int mask)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_fs_access_t access = file_mask_to_access(mask);

    if (!access)
        return 0;

    enum bpfbox_action_t action = fs_policy_decision(process, inode, access);
    audit_fs(process, action, inode, access);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to create @dentry in @dir */
LSM_PROBE(inode_create, struct inode *dir, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_action_t action = fs_policy_decision(process, dir, FS_WRITE);
    audit_fs(process, action, dir, FS_WRITE);

    // FIXME: if it's a temporary file, perhaps we should implicitly allow this
    // profile to open it in the future?

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to create a symbolic link @dentry in @dir */
LSM_PROBE(inode_symlink, struct inode *dir, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_action_t action = fs_policy_decision(process, dir, FS_WRITE);
    audit_fs(process, action, dir, FS_WRITE);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to create @dentry in @dir */
LSM_PROBE(inode_mkdir, struct inode *dir, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_action_t action = fs_policy_decision(process, dir, FS_WRITE);
    audit_fs(process, action, dir, FS_WRITE);

    // FIXME: if it's a temporary directory, perhaps we should implicitly allow
    // this profile to open it in the future?

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to remove @dentry in @dir */
LSM_PROBE(inode_rmdir, struct inode *dir, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_action_t action = fs_policy_decision(process, dir, FS_WRITE);
    audit_fs(process, action, dir, FS_WRITE);
    if (action & ACTION_DENY) {
        return -EPERM;
    }

    struct inode *inode = dentry->d_inode;

    action = fs_policy_decision(process, inode, FS_RM);
    audit_fs(process, action, inode, FS_RM);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to unlink @dentry in @dir */
LSM_PROBE(inode_unlink, struct inode *dir, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_action_t action = fs_policy_decision(process, dir, FS_WRITE);
    audit_fs(process, action, dir, FS_WRITE);
    if (action & ACTION_DENY) {
        return -EPERM;
    }

    struct inode *inode = dentry->d_inode;

    action = fs_policy_decision(process, inode, FS_RM);
    audit_fs(process, action, inode, FS_RM);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to create a hard link from @old_dentry to @dir/@new_dentry */
LSM_PROBE(inode_link, struct dentry *old_dentry, struct inode *dir,
          struct dentry *new_dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_action_t action = fs_policy_decision(process, dir, FS_WRITE);
    audit_fs(process, action, dir, FS_WRITE);
    if (action & ACTION_DENY) {
        return -EPERM;
    }

    struct inode *old_inode = old_dentry->d_inode;

    action = fs_policy_decision(process, old_inode, FS_ADD_LINK);
    audit_fs(process, action, old_inode, FS_ADD_LINK);

    return action & ACTION_DENY ? -EPERM : 0;

    // FIXME: perhaps we should implcitly grant same permissions to new link?
}

/* A task attempts to rename @old_dir/@old_dentry to @new_dir/@new_dentry */
LSM_PROBE(inode_rename, struct inode *old_dir, struct dentry *old_dentry,
          struct inode *new_dir, struct dentry *new_dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_action_t action =
        fs_policy_decision(process, old_dir, FS_WRITE);
    audit_fs(process, action, old_dir, FS_WRITE);
    if (action & ACTION_DENY) {
        return -EPERM;
    }

    struct inode *old_inode = old_dentry->d_inode;

    action = fs_policy_decision(process, old_inode, FS_RM);
    audit_fs(process, action, old_inode, FS_RM);
    if (action & ACTION_DENY) {
        return -EPERM;
    }

    action = fs_policy_decision(process, new_dir, FS_WRITE);
    audit_fs(process, action, new_dir, FS_WRITE);
    if (action & ACTION_DENY) {
        return -EPERM;
    }

    return action & ACTION_DENY ? -EPERM : 0;

    // FIXME: perhaps we should implcitly grant same permissions to new link?
}

/* A task attempts to change an attribute of @dentry */
LSM_PROBE(inode_setattr, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    struct inode *inode = dentry->d_inode;

    enum bpfbox_action_t action =
        fs_policy_decision(process, inode, FS_SETATTR);
    audit_fs(process, action, inode, FS_SETATTR);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to read an attribute of @path */
LSM_PROBE(inode_getattr, struct path *path)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    struct inode *inode = path->dentry->d_inode;

    enum bpfbox_action_t action =
        fs_policy_decision(process, inode, FS_GETATTR);
    audit_fs(process, action, inode, FS_GETATTR);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to change an extended attribute of @dentry */
LSM_PROBE(inode_setxattr, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    struct inode *inode = dentry->d_inode;

    enum bpfbox_action_t action =
        fs_policy_decision(process, inode, FS_SETATTR);
    audit_fs(process, action, inode, FS_SETATTR);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to get an extended attribute of @dentry */
LSM_PROBE(inode_getxattr, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    struct inode *inode = dentry->d_inode;

    enum bpfbox_action_t action =
        fs_policy_decision(process, inode, FS_GETATTR);
    audit_fs(process, action, inode, FS_GETATTR);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to list the extended attributes of @dentry */
LSM_PROBE(inode_listxattr, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    struct inode *inode = dentry->d_inode;

    enum bpfbox_action_t action =
        fs_policy_decision(process, inode, FS_GETATTR);
    audit_fs(process, action, inode, FS_GETATTR);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* A task attempts to remove an extended attribute from @dentry */
LSM_PROBE(inode_removexattr, struct dentry *dentry)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    struct inode *inode = dentry->d_inode;

    enum bpfbox_action_t action =
        fs_policy_decision(process, inode, FS_SETATTR);
    audit_fs(process, action, inode, FS_SETATTR);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* Bookkeeping for procfs, etc. */
LSM_PROBE(task_to_inode, struct task_struct *target, struct inode *inode)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    struct bpfbox_fs_policy_key_t key = {
        .st_ino = inode->i_ino,
        .st_dev = (u32)new_encode_dev(inode->i_sb->s_dev),
        .profile_key = process->profile_key,
    };

    struct bpfbox_policy_t policy = {};

    // Allow a process to access itself
    if (process->tgid == target->tgid) {
        policy.allow =
            FS_READ | FS_WRITE | FS_APPEND | FS_EXEC | FS_GETATTR | FS_SETATTR;
        fs_policy.update(&key, &policy);
        return 0;
    }

    // Look up target process
    u32 target_pid = target->pid;
    struct bpfbox_process_t *other_process = processes.lookup(&target_pid);
    if (!other_process) {
        return 0;
    }

    struct bpfbox_procfs_policy_key_t pfs_key = {
        .subject_profile_key = process->profile_key,
        .object_profile_key = other_process->profile_key,
    };

    // Look up procfs policy from subject to object
    struct bpfbox_policy_t *pfs_policy = procfs_policy.lookup(&pfs_key);
    if (!pfs_policy) {
        return 0;
    }

    // Set fs policy according to procfs policy
    policy.allow = pfs_policy->allow;
    policy.taint = pfs_policy->taint;
    policy.audit = pfs_policy->audit;

    fs_policy.update(&key, &policy);

    return 0;
}

/* =========================================================================
 * Sched Tracepoints for Bookkeeping
 * ========================================================================= */

/* A task fork()s/clone()s/vfork()s */
RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct bpfbox_process_t *process;
    struct bpfbox_process_t *parent_process;

    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_struct *c = (struct task_struct *)ctx->args[1];

    u32 ppid = p->pid;
    u32 cpid = c->pid;
    u32 ctgid = c->tgid;

    // Are we watching parent?
    parent_process = processes.lookup(&ppid);
    if (!parent_process) {
        return 0;
    }

    // Create the child
    process = create_process(cpid, ctgid, parent_process->profile_key,
                             parent_process->tainted);

    if (!process) {
        // TODO: log error
    }

    return 0;
}

/* A task execve()s */
RAW_TRACEPOINT_PROBE(sched_process_exec)
{
    struct bpfbox_process_t *process;
    struct bpfbox_profile_t *profile;

    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // Yoink the linux_binprm
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    // Calculate profile_key by taking inode number and filesystem device number
    // together
    u64 profile_key =
        (u64)bprm->file->f_path.dentry->d_inode->i_ino |
        ((u64)new_encode_dev(bprm->file->f_path.dentry->d_inode->i_sb->s_dev)
         << 32);

    profile = profiles.lookup(&profile_key);
    if (!profile) {
        return 0;
    }

    process = create_process(pid, tgid, profile_key, profile->taint_on_exec);

    if (!process) {
        // TODO: log error
    }

    return 0;
}

/* A task exit()s/exit_group()s or is killed by kernel */
RAW_TRACEPOINT_PROBE(sched_process_exit)
{
    // Delete the process if it exists
    u32 pid = (u32)bpf_get_current_pid_tgid();
    processes.delete(&pid);

    return 0;
}

/* =========================================================================
 * Uprobes for libbpfbox Operations
 * ========================================================================= */

int add_profile(struct pt_regs *ctx)
{
    u64 profile_key = PT_REGS_PARM1(ctx);
    u8 taint_on_exec = PT_REGS_PARM2(ctx);

    struct bpfbox_profile_t _init = {};
    struct bpfbox_profile_t *profile =
        profiles.lookup_or_try_init(&profile_key, &_init);
    if (!profile) {
        // TODO log error
        return 1;
    }

    profile->taint_on_exec = taint_on_exec;

    return 0;
}

int add_fs_rule(struct pt_regs *ctx)
{
    u64 profile_key = PT_REGS_PARM1(ctx);
    u32 st_ino = PT_REGS_PARM2(ctx);
    u32 st_dev = PT_REGS_PARM3(ctx);
    u32 access_mask = PT_REGS_PARM4(ctx);
    enum bpfbox_action_t action = PT_REGS_PARM5(ctx);

    if (action & (ACTION_DENY | ACTION_COMPLAIN)) {
        // TODO log error
        return 1;
    }

    if (!(action & (ACTION_ALLOW | ACTION_AUDIT | ACTION_TAINT))) {
        // TODO log error
        return 1;
    }

    struct bpfbox_profile_t *profile = profiles.lookup(&profile_key);
    if (!profile) {
        // TODO log error
        return 1;
    }

    struct bpfbox_fs_policy_key_t key = {};
    key.profile_key = profile_key;
    key.st_ino = st_ino;
    key.st_dev = st_dev;

    struct bpfbox_policy_t _init = {};
    struct bpfbox_policy_t *policy = fs_policy.lookup_or_try_init(&key, &_init);
    if (!policy) {
        // TODO log error
        return 1;
    }

    if (action & ACTION_TAINT) {
        policy->taint |= access_mask;
    }

    if (action & ACTION_ALLOW) {
        policy->allow |= access_mask;
    }

    if (action & ACTION_AUDIT) {
        policy->audit |= access_mask;
    }

    return 0;
}

int add_procfs_rule(struct pt_regs *ctx)
{
    u64 subject_profile_key = PT_REGS_PARM1(ctx);
    u64 object_profile_key = PT_REGS_PARM2(ctx);
    u32 access = PT_REGS_PARM3(ctx);
    enum bpfbox_action_t action = PT_REGS_PARM4(ctx);

    if (action & (ACTION_DENY | ACTION_COMPLAIN)) {
        // TODO log error
        return 1;
    }

    if (!(action & (ACTION_ALLOW | ACTION_AUDIT | ACTION_TAINT))) {
        // TODO log error
        return 1;
    }

    struct bpfbox_profile_t *profile = profiles.lookup(&subject_profile_key);
    if (!profile) {
        // TODO log error
        return 1;
    }

    // Create object profile if it does not exist
    struct bpfbox_profile_t _profile_init = {
        .taint_on_exec = 0,
    };
    struct bpfbox_profile_t *object_profile =
        profiles.lookup_or_try_init(&object_profile_key, &_profile_init);
    if (!object_profile) {
        // TODO log error
        return 1;
    }

    struct bpfbox_procfs_policy_key_t key = {};
    key.subject_profile_key = subject_profile_key;
    key.object_profile_key = object_profile_key;

    struct bpfbox_policy_t _init = {};
    struct bpfbox_policy_t *policy =
        procfs_policy.lookup_or_try_init(&key, &_init);
    if (!policy) {
        // TODO log error
        return 1;
    }

    if (action & ACTION_TAINT) {
        policy->taint |= access;
    }

    if (action & ACTION_ALLOW) {
        policy->allow |= access;
    }

    if (action & ACTION_AUDIT) {
        policy->audit |= access;
    }

    return 0;
}
