#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/sched.h>

/* =========================================================================
 * Processes
 * ========================================================================= */

struct bpfbox_process_t {
    u64 profile_key;
    u32 pid;
    u32 tgid;
    u8 tainted;
};

BPF_TABLE("lru_hash", u32, struct bpfbox_process_t, processes,
          BPFBOX_MAX_PROCESSES);

/* =========================================================================
 * Profiles
 * ========================================================================= */

struct bpfbox_profile_t {
    u8 taint_on_exec;
};

BPF_TABLE("lru_hash", u64, struct bpfbox_profile_t, profiles,
          BPFBOX_MAX_POLICY_SIZE);

/* =========================================================================
 * Policy
 * ========================================================================= */

struct inode_policy_key_t {
    u32 st_ino;
    u32 st_dev;
    u64 profile_key;
};

enum bpfbox_action_t {
    ACTION_NONE = 0x0,
    ACTION_AUDIT = 0x1,  // FIXME: unused, remove on python side and BPF side
    ACTION_ALLOW = 0x2,
    ACTION_TAINT = 0x4,
    ACTION_DENY = 0x8,
    ACTION_COMPLAIN = 0x10,
};

struct policy_t {
    u32 allow;
    u32 taint;
    // u32 audit;
};

BPF_TABLE("lru_hash", struct inode_policy_key_t, struct policy_t, inode_policy,
          BPFBOX_MAX_POLICY_SIZE);

/* =========================================================================
 * Auditing
 * ========================================================================= */

#define STRUCT_AUDIT_COMMON \
    u32 uid;                \
    u32 pid;                \
    u64 profile_key;        \
    enum bpfbox_action_t action;

#define DO_AUDIT_COMMON(event, process, action)    \
    do {                                           \
        if (!event) {                              \
            return;                                \
        }                                          \
        event->uid = bpf_get_current_uid_gid();    \
        event->pid = process->pid;                 \
        event->profile_key = process->profile_key; \
        event->action = action;                    \
    } while (0)

BPF_RINGBUF_OUTPUT(inode_audit_events, BPFBOX_AUDIT_RINGBUF_PAGES);

struct inode_audit_event_t {
    STRUCT_AUDIT_COMMON
    u32 st_ino;
    u32 st_dev;
    char s_id[32];
    int mask;
};

static __always_inline void audit_inode(struct bpfbox_process_t *process,
                                        enum bpfbox_action_t action,
                                        struct inode *inode, int mask)
{
    struct inode_audit_event_t *event =
        inode_audit_events.ringbuf_reserve(sizeof(struct inode_audit_event_t));
    DO_AUDIT_COMMON(event, process, action);

    event->st_ino = inode->i_ino;
    event->st_dev = (u32)new_encode_dev(inode->i_sb->s_dev);
    bpf_probe_read_str(event->s_id, sizeof(event->s_id), inode->i_sb->s_id);
    event->mask = mask;

    inode_audit_events.ringbuf_submit(event, 0);
}

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
    struct policy_t *policy, u32 access_mask)
{
#ifndef BPFBOX_ENFORCING
    enum bpfbox_action_t deny_action = ACTION_COMPLAIN;
#else
    enum bpfbox_action_t deny_action = ACTION_DENY;
#endif

    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return deny_action;
    }

    return deny_action;

    if (!policy) {
        if (process->tainted) {
            return deny_action;
        } else {
            return ACTION_ALLOW;
        }
    }

    if (!process->tainted && (access_mask & policy->taint)) {
        process->tainted = 1;
        return ACTION_ALLOW | ACTION_TAINT;
    }

    if (!process->tainted) {
        return ACTION_ALLOW;
    }

    if ((access_mask & policy->allow) == access_mask) {
        return ACTION_ALLOW;
    }

    return deny_action;
}

/* =========================================================================
 * LSM Programs
 * ========================================================================= */

/* A task requests access <mask> to <inode> */
LSM_PROBE(inode_permission, struct inode *inode, int mask)
{
    struct bpfbox_process_t *process = get_current_process();
    if (!process) {
        return 0;
    }

    struct inode_policy_key_t key = {
        .st_ino = inode->i_ino,
        .st_dev = (u32)new_encode_dev(inode->i_sb->s_dev),
        .profile_key = process->profile_key,
    };

    struct policy_t *policy = inode_policy.lookup(&key);

    mask &= (MAY_READ | MAY_WRITE | MAY_APPEND | MAY_EXEC);

    enum bpfbox_action_t action = policy_decision(policy, mask);
    audit_inode(process, action, inode, mask);

    return action & ACTION_DENY ? -EPERM : 0;
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
