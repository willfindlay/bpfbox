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

BPF_HASH(ipc_policy, struct bpfbox_ipc_policy_key_t, struct bpfbox_policy_t,
         BPFBOX_MAX_POLICY_SIZE);

BPF_HASH(net_policy, struct bpfbox_network_policy_key_t, struct bpfbox_policy_t,
         BPFBOX_MAX_POLICY_SIZE);

/* =========================================================================
 * Auditing
 * ========================================================================= */

BPF_RINGBUF_OUTPUT(fs_audit_events, BPFBOX_AUDIT_RINGBUF_PAGES);

static __always_inline void audit_fs(struct bpfbox_process_t *process,
                                     enum bpfbox_action_t action,
                                     struct inode *inode,
                                     bpfbox_access_t access)
{
    FILTER_AUDIT(action);

    struct bpfbox_fs_audit_event_t *event =
        fs_audit_events.ringbuf_reserve(sizeof(struct bpfbox_fs_audit_event_t));

    DO_AUDIT_COMMON(event, process, action);

    event->st_ino = inode->i_ino;
    event->st_dev = (u32)new_encode_dev(inode->i_sb->s_dev);
    bpf_probe_read_str(event->s_id, sizeof(event->s_id), inode->i_sb->s_id);

    fs_audit_events.ringbuf_submit(event, 0);
}

BPF_RINGBUF_OUTPUT(ipc_audit_events, BPFBOX_AUDIT_RINGBUF_PAGES);

static __always_inline void audit_ipc(struct bpfbox_process_t *subject_process,
                                      struct bpfbox_process_t *object_process,
                                      u32 object_uid, bpfbox_access_t access,
                                      enum bpfbox_action_t action)
{
    FILTER_AUDIT(action);

    struct bpfbox_ipc_audit_event_t *event = ipc_audit_events.ringbuf_reserve(
        sizeof(struct bpfbox_ipc_audit_event_t));

    DO_AUDIT_COMMON(event, subject_process, action);

    // TODO: make this work
    event->object_uid = object_uid;
    event->object_pid = object_process->pid;
    event->object_profile_key = object_process->profile_key;

    ipc_audit_events.ringbuf_submit(event, 0);
}

BPF_RINGBUF_OUTPUT(network_audit_events, BPFBOX_AUDIT_RINGBUF_PAGES);

struct network_audit_event_t {
    STRUCT_AUDIT_COMMON
};

static __always_inline void audit_network(struct bpfbox_process_t *process,
                                          bpfbox_access_t access,
                                          enum bpfbox_network_family_t family,
                                          enum bpfbox_action_t action)
{
    FILTER_AUDIT(action);

    struct bpfbox_network_audit_event_t *event =
        network_audit_events.ringbuf_reserve(
            sizeof(struct bpfbox_network_audit_event_t));

    DO_AUDIT_COMMON(event, process, action);

    event->family = family;

    network_audit_events.ringbuf_submit(event, 0);
}

/* =========================================================================
 * Helper Functions
 * ========================================================================= */

static __always_inline struct bpfbox_process_t *create_process(
    u32 pid, u32 tgid, u64 profile_key, u64 state, bool tainted)
{
    struct bpfbox_process_t new_process = {};
    new_process.pid = pid;
    new_process.tgid = tgid;
    new_process.profile_key = profile_key;
    new_process.state = state;
    new_process.tainted = tainted;

    return processes.lookup_or_try_init(&pid, &new_process);
}

static __always_inline struct bpfbox_process_t *get_current_process()
{
    u32 pid = bpf_get_current_pid_tgid();
    return processes.lookup(&pid);
}

static __always_inline struct bpfbox_profile_t *create_profile(u64 profile_key,
                                                               u8 taint_on_exec)
{
    struct bpfbox_profile_t new_profile = {};
    new_profile.taint_on_exec = taint_on_exec;

    return profiles.lookup_or_try_init(&profile_key, &new_profile);
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

    enum bpfbox_action_t allow_action = ACTION_ALLOW;

    bool tainted = process->tainted;

    // If we have no policy for this object, either deny or allow,
    // depending on if the process is tainted or not
    if (!policy) {
        if (tainted) {
            return deny_action;
        } else {
            return allow_action;
        }
    }

    // Set allow action based on whether or not we want to audit
    if (access & policy->audit.access && (!policy->audit.state || process->state & policy->audit.state)) {
        allow_action |= ACTION_AUDIT;
    }

    // Taint process if we hit a taint rule
    if (!tainted && (access & policy->taint.access) && (!policy->taint.state || process->state & policy->taint.state)) {
        process->tainted = 1;
        return allow_action | ACTION_TAINT;
    }

    // If we are not tainted
    if (!tainted) {
        return allow_action;
    }

    // If we are tainted, but the operation is allowed
    if ((access & policy->allow.access) == access && (!policy->allow.state || process->state & policy->allow.state)) {
        return allow_action;
    }

    // Default deny
    return deny_action;
}

/* =========================================================================
 * File System Policy Programs
 * ========================================================================= */

/* Linux access mask to bpfbox access */
static __always_inline enum bpfbox_fs_access_t file_mask_to_access(int mask)
{
    enum bpfbox_fs_access_t access = 0;

    if (mask & MAY_READ) {
        access |= FS_READ;
    }

    // Appending and writing are mutually exclusive,
    // but MAY_APPEND is typically seen with MAY_WRITE
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

/* Linux prot mask to bpfbox access */
static __always_inline enum bpfbox_fs_access_t prot_mask_to_access(int mask,
                                                                   bool shared)
{
    enum bpfbox_fs_access_t access = 0;

    if (mask & PROT_READ) {
        access |= FS_READ;
    }

    if (shared && (mask & PROT_WRITE)) {
        access |= FS_WRITE;
    }

    if (mask & PROT_EXEC) {
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

/* A task requests access @mask to @inode */
LSM_PROBE(inode_permission, struct inode *inode, int mask)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_fs_access_t access = file_mask_to_access(mask);

    if (S_ISDIR(inode->i_mode))
        access &= ~FS_EXEC;

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

    action = fs_policy_decision(process, old_inode, FS_LINK);
    audit_fs(process, action, old_inode, FS_LINK);

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
    struct bpfbox_process_t *subject_process = get_current_process();
    if (!subject_process) {
        return 0;
    }

    struct bpfbox_fs_policy_key_t key = {
        .st_ino = inode->i_ino,
        .st_dev = (u32)new_encode_dev(inode->i_sb->s_dev),
        .profile_key = subject_process->profile_key,
    };

    struct bpfbox_policy_t policy = {};

    // Allow a process to access itself
    if ((struct task_struct *)bpf_get_current_task() == target) {
        policy.allow.access =
            FS_READ | FS_WRITE | FS_APPEND | FS_EXEC | FS_GETATTR | FS_SETATTR;
        fs_policy.update(&key, &policy);

        return 0;
    }

    // Look up target subject_process
    u32 target_pid = target->pid;
    struct bpfbox_process_t *object_process = processes.lookup(&target_pid);
    if (!object_process) {
        return 0;
    }

    struct bpfbox_procfs_policy_key_t pfs_key = {
        .subject_profile_key = subject_process->profile_key,
        .object_profile_key = object_process->profile_key,
    };

    // Look up procfs policy from subject to object
    struct bpfbox_policy_t *pfs_policy = procfs_policy.lookup(&pfs_key);
    if (!pfs_policy) {
        return 0;
    }

    // Set fs policy according to procfs policy
    policy.allow.access = pfs_policy->allow.access;
    policy.taint.access = pfs_policy->taint.access;
    policy.audit.access = pfs_policy->audit.access;
    policy.allow.state = pfs_policy->allow.state;
    policy.taint.state = pfs_policy->taint.state;
    policy.audit.state = pfs_policy->audit.state;

    fs_policy.update(&key, &policy);

    return 0;
}

/* =========================================================================
 * mmap Policy
 * ========================================================================= */

LSM_PROBE(mmap_file, struct file *file, unsigned long reqprot,
          unsigned long prot, unsigned long flags)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    if (!file) {
        return 0;
    }

    struct inode *inode = file->f_inode;

    enum bpfbox_fs_access_t access =
        prot_mask_to_access(prot, (flags & MAP_TYPE) == MAP_SHARED);

    if (!access)
        return 0;

    enum bpfbox_action_t action = fs_policy_decision(process, inode, access);
    audit_fs(process, action, inode, access);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
          unsigned long prot)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    if (!vma) {
        return 0;
    }

    struct file *file = vma->vm_file;

    if (!file) {
        return 0;
    }

    struct inode *inode = file->f_inode;

    enum bpfbox_fs_access_t access =
        prot_mask_to_access(prot, vma->vm_flags & VM_SHARED);

    if (!access)
        return 0;

    enum bpfbox_action_t action = fs_policy_decision(process, inode, access);
    audit_fs(process, action, inode, access);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* =========================================================================
 * IPC Policy
 * ========================================================================= */

// TODO: keep going with this

static __always_inline enum bpfbox_action_t ipc_policy_decision(
    struct bpfbox_process_t *subject_process,
    struct bpfbox_process_t *object_process, enum bpfbox_ipc_access_t access)
{
    struct bpfbox_ipc_policy_key_t key = {
        .subject_key = subject_process->profile_key,
        .object_key = object_process->profile_key,
    };

    struct bpfbox_policy_t *policy = ipc_policy.lookup(&key);

    return policy_decision(subject_process, policy, access);
}

static __always_inline enum bpfbox_ipc_access_t signal_to_ipc_access(int sig)
{
    switch (sig) {
        case 0:
            return IPC_SIGCHECK;
            break;
        case SIGCHLD:
            return IPC_SIGCHLD;
            break;
        case SIGKILL:
            return IPC_SIGKILL;
            break;
        case SIGSTOP:
            return IPC_SIGSTOP;
            break;
        default:
            return IPC_SIGMISC;
            break;
    }
}

LSM_PROBE(task_kill, struct task_struct *target, struct kernel_siginfo *info,
          int sig, const struct cred *cred)
{
    // Signal from kernel
    if (info == (void *)1) {
        return 0;
    }

    struct bpfbox_process_t *subject_process = get_current_process();

    u32 target_pid = target->pid;
    struct bpfbox_process_t *object_process = processes.lookup(&target_pid);

    enum bpfbox_ipc_access_t access = signal_to_ipc_access(sig);

    // Neither task is confined
    if (!subject_process && !object_process) {
        return 0;
    }

    // An unconfined task is attempting to signal a confined task
    if (!subject_process) {
        return 0;
    }

    enum bpfbox_action_t action;

    // An confined task is attempting to signal an "unconfined" task
    if (!object_process) {
        struct bpfbox_process_t unknown = {
            .pid = target->pid,
            .tgid = target->tgid,
            .profile_key = 0,
            .state = 0,
        };
#ifdef BPFBOX_ENFORCING
        action = ACTION_DENY;
#else
        action = ACTION_COMPLAIN;
#endif
        audit_ipc(subject_process, &unknown, target->cred->uid.val, access,
                  action);
        goto out;
    }

    action = ipc_policy_decision(subject_process, object_process, access);
    audit_ipc(subject_process, object_process, target->cred->uid.val, access,
              action);

out:
    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(ptrace_access_check, struct task_struct *target, unsigned int mode)
{
    struct bpfbox_process_t *subject_process = get_current_process();

    u32 target_pid = target->pid;
    struct bpfbox_process_t *object_process = processes.lookup(&target_pid);

    enum bpfbox_ipc_access_t access = IPC_PTRACE;

    // Neither task is confined
    if (!subject_process && !object_process) {
        return 0;
    }

    // An unconfined task is attempting to ptrace a confined task
    if (!subject_process) {
        return 0;
    }

    enum bpfbox_action_t action;

    // An confined task is attempting to ptrace an "unconfined" task
    if (!object_process) {
        struct bpfbox_process_t unknown = {
            .pid = target->pid,
            .tgid = target->tgid,
            .profile_key = 0,
            .state = 0,
        };
#ifdef BPFBOX_ENFORCING
        action = ACTION_DENY;
#else
        action = ACTION_COMPLAIN;
#endif
        audit_ipc(subject_process, &unknown, target->cred->uid.val, access,
                  action);
        goto out;
    }

    action = ipc_policy_decision(subject_process, object_process, access);
    audit_ipc(subject_process, object_process, target->cred->uid.val, access,
              action);

out:
    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(ptrace_traceme, struct task_struct *parent)
{
    struct bpfbox_process_t *object_process = get_current_process();

    u32 parent_pid = parent->pid;
    struct bpfbox_process_t *subject_process = processes.lookup(&parent_pid);

    enum bpfbox_ipc_access_t access = IPC_PTRACE;

    // Neither task is confined
    if (!subject_process && !object_process) {
        return 0;
    }

    // An unconfined task is attempting to ptrace a confined task
    if (!subject_process) {
        return 0;
    }

    enum bpfbox_action_t action;

    // An confined task is attempting to ptrace an "unconfined" task
    if (!object_process) {
#ifdef BPFBOX_ENFORCING
        action = ACTION_DENY;
#else
        action = ACTION_COMPLAIN;
#endif
        goto out;
    }

    action = ipc_policy_decision(subject_process, object_process, access);
    audit_ipc(subject_process, object_process, bpf_get_current_uid_gid(),
              access, action);

out:
    return action & ACTION_DENY ? -EPERM : 0;
}

/* =========================================================================
 * Networking Policy
 * ========================================================================= */

static __always_inline enum bpfbox_action_t net_policy_decision(
    struct bpfbox_process_t *process, enum bpfbox_network_family_t family,
    enum bpfbox_network_access_t access)
{
    struct bpfbox_network_policy_key_t key = {};

    key.profile_key = process->profile_key;
    key.family = family;

    struct bpfbox_policy_t *policy = net_policy.lookup(&key);

    return policy_decision(process, policy, access);
}

static __always_inline enum bpfbox_network_family_t af_to_network_family(
    int family)
{
    if (family >= NET_FAMILY_UNKNOWN)
        return NET_FAMILY_UNKNOWN;
    return family;
}

LSM_PROBE(socket_create, int _family, int type, int protocol, int kern)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_CREATE;
    enum bpfbox_network_family_t family = af_to_network_family(_family);

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(socket_bind, struct socket *sock, struct sockaddr *address,
          int addrlen)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_BIND;
    enum bpfbox_network_family_t family =
        af_to_network_family(address->sa_family);

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address,
          int addrlen)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_CONNECT;
    enum bpfbox_network_family_t family =
        af_to_network_family(address->sa_family);

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(unix_stream_connect, struct socket *sock, struct socket *other,
          struct socket *newsock)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_CONNECT;
    enum bpfbox_network_family_t family = NET_FAMILY_UNIX;

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(unix_may_send, struct socket *sock, struct socket *other)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_SEND;
    enum bpfbox_network_family_t family = NET_FAMILY_UNIX;

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(socket_listen, struct socket *sock, int backlog)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_LISTEN;
    enum bpfbox_network_family_t family =
        af_to_network_family(sock->sk->sk_family);

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(socket_accept, struct socket *sock, struct socket *newsock)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_ACCEPT;
    enum bpfbox_network_family_t family =
        af_to_network_family(sock->sk->sk_family);

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_SEND;
    enum bpfbox_network_family_t family =
        af_to_network_family(sock->sk->sk_family);

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(socket_recvmsg, struct socket *sock, struct msghdr *msg, int size,
          int flags)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_RECV;
    enum bpfbox_network_family_t family =
        af_to_network_family(sock->sk->sk_family);

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

LSM_PROBE(socket_shutdown, struct socket *sock, int how)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    enum bpfbox_network_access_t access = NET_SHUTDOWN;
    enum bpfbox_network_family_t family =
        af_to_network_family(sock->sk->sk_family);

    enum bpfbox_action_t action = net_policy_decision(process, family, access);
    audit_network(process, access, family, action);

    return action & ACTION_DENY ? -EPERM : 0;
}

/* =========================================================================
 * BPF Policy
 * ========================================================================= */

LSM_PROBE(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    // TODO: deny permission if ANY process other than bpfboxd
    // is trying to modify BPFBox's maps

    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    return -EPERM;
}

/* =========================================================================
 * Process/Profile Creation and Related Bookkeeping
 * ========================================================================= */

LSM_PROBE(bprm_committing_creds, struct linux_binprm *bprm)
{
    struct bpfbox_process_t *process;
    struct bpfbox_profile_t *profile;

    /* Calculate profile_key by taking inode number and filesystem device
     * number together */
    u64 profile_key =
        (u64)bprm->file->f_path.dentry->d_inode->i_ino |
        ((u64)new_encode_dev(bprm->file->f_path.dentry->d_inode->i_sb->s_dev)
         << 32);

    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    profile = profiles.lookup(&profile_key);
    if (!profile) {
        return 0;
    }

    process = create_process(pid, tgid, profile_key, 0, profile->taint_on_exec);

    if (!process) {
        // TODO: log error
    }

    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork)
{
    struct bpfbox_process_t *process;
    struct bpfbox_process_t *parent_process;

    u32 ppid = args->parent_pid;
    u32 cpid = args->child_pid;
    u32 ctgid = bpf_get_current_pid_tgid() >> 32;

    // Are we watching parent?
    parent_process = processes.lookup(&ppid);
    if (!parent_process) {
        return 0;
    }

    // Create the child
    process = create_process(cpid, ctgid, parent_process->profile_key,
                             parent_process->state, parent_process->tainted);

    if (!process) {
        // TODO: log error
    }

    return 0;
}

LSM_PROBE(task_free, struct task_struct *task)
{
    u32 pid = task->pid;
    processes.delete(&pid);

    return 0;
}

/* =========================================================================
 * Uprobes for libbpfbox Operations
 * ========================================================================= */

static __always_inline void add_policy_common(struct bpfbox_policy_t *policy,
                                              struct bpfbox_profile_t *profile,
                                              u32 access_mask,
                                              u64 state_mask,
                                              enum bpfbox_action_t action)
{
    if (action & ACTION_TAINT) {
        profile->taint_on_exec = 0;
        policy->taint.access |= access_mask;
        policy->taint.state |= state_mask;
    }

    if (action & ACTION_ALLOW) {
        policy->allow.access |= access_mask;
        policy->allow.state |= state_mask;
    }

    if (action & ACTION_AUDIT) {
        policy->audit.access |= access_mask;
        policy->audit.state |= state_mask;
    }
}

int add_profile(struct pt_regs *ctx)
{
    u64 profile_key = PT_REGS_PARM1(ctx);
    u8 taint_on_exec = PT_REGS_PARM2(ctx);

    struct bpfbox_profile_t *profile =
        create_profile(profile_key, taint_on_exec);
    if (!profile) {
        // TODO log error
        return 1;
    }

    // We need to make sure we always overwrite taint_on_exec
    profile->taint_on_exec = taint_on_exec;

    return 0;
}

int add_fs_rule(struct pt_regs *ctx)
{
    u64 profile_key = PT_REGS_PARM1(ctx);
    u32 st_ino = PT_REGS_PARM2(ctx);
    u32 st_dev = PT_REGS_PARM3(ctx);
    u32 access_mask = PT_REGS_PARM4(ctx);
    u64 state = PT_REGS_PARM5(ctx);
    enum bpfbox_action_t action = PT_REGS_PARM6(ctx);

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
    //key.state = state;

    struct bpfbox_policy_t _init = {};
    struct bpfbox_policy_t *policy = fs_policy.lookup_or_try_init(&key, &_init);
    if (!policy) {
        // TODO log error
        return 1;
    }

    add_policy_common(policy, profile, access_mask, state, action);

    return 0;
}

int add_procfs_rule(struct pt_regs *ctx)
{
    u64 subject_profile_key = PT_REGS_PARM1(ctx);
    u64 object_profile_key = PT_REGS_PARM2(ctx);
    u32 access_mask = PT_REGS_PARM3(ctx);
    u64 state = PT_REGS_PARM4(ctx);
    enum bpfbox_action_t action = PT_REGS_PARM5(ctx);

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
    struct bpfbox_profile_t *object_profile =
        create_profile(object_profile_key, 0);
    if (!object_profile) {
        // TODO log error
        return 1;
    }

    struct bpfbox_procfs_policy_key_t key = {};
    key.subject_profile_key = subject_profile_key;
    key.object_profile_key = object_profile_key;
    //key.state = state;

    struct bpfbox_policy_t _init = {};
    struct bpfbox_policy_t *policy =
        procfs_policy.lookup_or_try_init(&key, &_init);
    if (!policy) {
        // TODO log error
        return 1;
    }

    add_policy_common(policy, profile, access_mask, state, action);

    return 0;
}

int add_ipc_rule(struct pt_regs *ctx)
{
    u64 subject_key = PT_REGS_PARM1(ctx);
    u64 object_key = PT_REGS_PARM2(ctx);
    u32 access_mask = PT_REGS_PARM3(ctx);
    u64 state = PT_REGS_PARM4(ctx);
    enum bpfbox_action_t action = PT_REGS_PARM5(ctx);

    if (action & (ACTION_DENY | ACTION_COMPLAIN)) {
        // TODO log error
        return 1;
    }

    if (!(action & (ACTION_ALLOW | ACTION_AUDIT | ACTION_TAINT))) {
        // TODO log error
        return 1;
    }

    struct bpfbox_profile_t *profile = profiles.lookup(&subject_key);
    if (!profile) {
        // TODO log error
        return 1;
    }

    // Create object profile if it does not exist
    struct bpfbox_profile_t *object_profile = create_profile(object_key, 0);
    if (!object_profile) {
        // TODO log error
        return 1;
    }

    struct bpfbox_ipc_policy_key_t key = {};
    key.subject_key = subject_key;
    key.object_key = object_key;
    //key.state = state;

    struct bpfbox_policy_t _init = {};
    struct bpfbox_policy_t *policy =
        ipc_policy.lookup_or_try_init(&key, &_init);
    if (!policy) {
        // TODO log error
        return 1;
    }

    add_policy_common(policy, profile, access_mask, state, action);

    return 0;
}

int add_net_rule(struct pt_regs *ctx)
{
    u64 profile_key = PT_REGS_PARM1(ctx);
    u32 access = PT_REGS_PARM2(ctx);
    u32 family = PT_REGS_PARM3(ctx);
    u64 state = PT_REGS_PARM4(ctx);
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

    // Create object profile if it does not exist
    struct bpfbox_profile_t *object_profile = create_profile(profile_key, 0);
    if (!object_profile) {
        // TODO log error
        return 1;
    }

    struct bpfbox_network_policy_key_t key = {};
    key.profile_key = profile_key;
    key.family = family;
    //key.state = state;

    struct bpfbox_policy_t _init = {};
    struct bpfbox_policy_t *policy =
        net_policy.lookup_or_try_init(&key, &_init);
    if (!policy) {
        // TODO log error
        return 1;
    }

    add_policy_common(policy, profile, access, state, action);

    return 0;
}
