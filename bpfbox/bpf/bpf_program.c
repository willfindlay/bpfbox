#include "bpfbox/bpf/bpf_program.h"

#include "bpfbox/bpf/defs.h"
#include "bpfbox/bpf/helpers.h"

/* ========================================================================= *
 * Perf Buffers                                                              *
 * ========================================================================= */

BPF_PERF_OUTPUT(on_process_create);  // TODO: either link or delete this
BPF_PERF_OUTPUT(on_fs_enforcement);
BPF_PERF_OUTPUT(on_net_enforcement);

/* ========================================================================= *
 * Map Definitions                                                           *
 * ========================================================================= */

// TODO: use the PINNED_MAPS flag to determine whether we want to load
// maps that have been pinned to bpffs rather than creating new maps

/* This map holds information about currently running processes */
BPF_TABLE("lru_hash", u32, struct bpfbox_process, processes,
          BPFBOX_MAX_PROCESSES);

/* This map holds information about the profiles bpfbox currently knows about */
BPF_TABLE("lru_hash", u64, struct bpfbox_profile, profiles,
          BPFBOX_MAX_PROFILES);

/* This map holds rules that will be tail called on fs policy events */
BPF_PROG_ARRAY(fs_policy, BPFBOX_MAX_PROFILES);
BPF_PROG_ARRAY(net_policy, BPFBOX_MAX_PROFILES);
// TODO: add other policy categories

/* ========================================================================= *
 * Intermediate Maps                                                         *
 * ========================================================================= */

/* This array holds intermediate values between entry and exit points to
 * do_filp_open */
BPF_ARRAY(__do_filp_open_intermediate, struct open_flags, 1);
// BPF_ARRAY(__net_intermediate, struct bpfbox_net_intermediate, 1);

/* ========================================================================= *
 * Helper Functions                                                          *
 * ========================================================================= */

static __always_inline struct bpfbox_process *create_process(void *ctx, u32 pid,
                                                             u32 tgid) {
    int zero = 0;
    struct bpfbox_process process = {};

    process.tainted = 0;
    process.profile_key = 0;
    process.pid = pid;
    process.tgid = tgid;

    return processes.lookup_or_try_init(&pid, &process);
}

/* Policy enforcement helpers below this line ------------------------------ */

static __always_inline int fs_enforce(void *ctx, struct bpfbox_process *process,
                                      struct bpfbox_profile *profile, u32 inode,
                                      u32 parent_inode, u32 st_dev,
                                      int access) {
#ifdef BPFBOX_ENFORCING
    bpf_send_signal(SIGKILL);
#endif

    struct fs_enforcement_event event = {};

#ifdef BPFBOX_ENFORCING
    event.enforcing = 1;
#else
    event.enforcing = 0;
#endif
    event.pid = process->pid;
    event.tgid = process->tgid;
    event.profile_key = process->profile_key;

    event.inode = inode;
    event.parent_inode = parent_inode;
    event.st_dev = st_dev;
    event.access = access;

    on_fs_enforcement.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

static __always_inline int net_enforce(void *ctx,
                                       struct bpfbox_process *process,
                                       struct bpfbox_profile *profile) {
#ifdef BPFBOX_ENFORCING
    bpf_send_signal(SIGKILL);
#endif

    struct net_enforcement_event event = {};

#ifdef BPFBOX_ENFORCING
    event.enforcing = 1;
#else
    event.enforcing = 0;
#endif
    event.pid = process->pid;
    event.tgid = process->tgid;
    event.profile_key = process->profile_key;

    // event.inode = inode;
    // event.parent_inode = parent_inode;
    // event.st_dev = st_dev;
    // event.access = access;

    on_net_enforcement.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

/* ========================================================================= *
 * BPF Programs                                                              *
 * ========================================================================= */

/* When a task forks */
RAW_TRACEPOINT_PROBE(sched_process_fork) {
    struct bpfbox_process *process;
    struct bpfbox_process *parent_process;

    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_struct *c = (struct task_struct *)ctx->args[1];

    u32 ppid = p->pid;
    u32 cpid = c->pid;
    u32 ctgid = c->tgid;

    // Create the process
    process = create_process(ctx, cpid, ctgid);
    if (!process) {
        // TODO: print error to logs here
        return -1;
    }

    // Attempt to look up parent process if we know about it
    parent_process = processes.lookup(&ppid);
    if (!parent_process) {
        return 0;
    }

    // Assign child profile to parent profile if it exists
    process->profile_key = parent_process->profile_key;

    // If parent process is tained, child should be too
    process->tainted = parent_process->tainted;

    return 0;
}

/* When a task loads a program with execve */
RAW_TRACEPOINT_PROBE(sched_process_exec) {
    u32 pid = (u32)bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);

    // Get out if process does not exist
    if (!process) return 0;

    // Yoink the linux_binprm
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    // Calculate profile_key
    // Take inode number and filesystem device number together
    u64 profile_key =
        (u64)bprm->file->f_path.dentry->d_inode->i_ino |
        ((u64)new_encode_dev(bprm->file->f_path.dentry->d_inode->i_sb->s_dev)
         << 32);

    // Look up the profile if it exists
    struct bpfbox_profile *profile = profiles.lookup(&profile_key);
    if (!profile) {
        return 0;
    }

    process->profile_key = profile_key;

    // taint after execve?
    if (profile->taint_on_exec) process->tainted = 1;

    return 0;
}

/* When a task exits */
RAW_TRACEPOINT_PROBE(sched_process_exit) {
    u32 pid = (u32)bpf_get_current_pid_tgid();
    processes.delete(&pid);

    return 0;
}

/* File system policy entrypoints below this line -------------------------- */

/* A kprobe that checks the arguments to do_filp_open
 * (underlying implementation of open, openat, and openat2). */
int kprobe__do_filp_open(struct pt_regs *ctx, int dfd,
                         struct filename *pathname,
                         const struct open_flags *op) {
    // Check pid and lookup process if it exists
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);
    if (!process) return 0;

    int zero = 0;
    struct open_flags tmp;
    bpf_probe_read(&tmp, sizeof(tmp), op);

    __do_filp_open_intermediate.update(&zero, &tmp);

    return 0;
}

/* A kretprobe that checks the file struct pointer returned
 * by do_filp_open (underlying implementation of open, openat,
 * and openat2). */
int kretprobe__do_filp_open(struct pt_regs *ctx) {
    // Check pid and lookup process if it exists
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);
    if (!process) return 0;

    // Look up profile
    struct bpfbox_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile) return 0;

    // Yoink file pointer from return value
    struct file *fp = (struct file *)PT_REGS_RC(ctx);
    if (fp <= 0) return 0;

    fs_policy.call(ctx, profile->tail_call_index);

    return 0;
}

/* Network event entrypoints below this line ------------------------------- */
