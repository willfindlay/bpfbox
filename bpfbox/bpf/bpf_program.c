#include "bpfbox/bpf/bpf_program.h"
#include "bpfbox/bpf/helpers.h"
#include "bpfbox/bpf/defs.h"

/* ========================================================================= *
 * Initializer Arrays                                                        *
 * ========================================================================= */

BPF_ARRAY(__init_process, struct bpfbox_process, 1);

BPF_ARRAY(__init_profile, struct bpfbox_profile, 1);

/* A global counter that stores the tail call index for new profiles.
 * This counter is used to set the NEXT profile's tail_call_index. */
BPF_ARRAY(__tail_call_index, int, 1);

/* ========================================================================= *
 * Perf Buffers                                                              *
 * ========================================================================= */

BPF_PERF_OUTPUT(on_profile_create);

/* ========================================================================= *
 * Map Definitions                                                           *
 * ========================================================================= */

/* This map holds information about currently running processes */
BPF_TABLE("lru_hash", u32, struct bpfbox_process, processes, 10240);

/* This map holds information about the profiles bpfbox currently knows about */
BPF_TABLE("lru_hash", u64, struct bpfbox_profile, profiles, 10240);

/* This map holds rules that will be tail called when an enforcing process makes a system call */
BPF_PROG_ARRAY(rules, 10240);

/* ========================================================================= *
 * Helper Functions                                                          *
 * ========================================================================= */

/* Assign a unique tail_index to a profile and increment the global counters */
static __always_inline int set_tail_index(void *ctx, struct bpfbox_profile *profile)
{
    int zero = 0;
    int *curr_idx = __tail_call_index.lookup(&zero);

    if(!curr_idx)
    {
        return -1;
    }

    int temp = *curr_idx;
    lock_xadd(curr_idx, 1);
    profile->tail_call_index = temp;

    return 0;
}

static __always_inline struct bpfbox_process *create_process(void *ctx, u32 pid)
{
    int zero = 0;
    struct bpfbox_process *process = __init_process.lookup(&zero);

    if (!process)
        return NULL;

    process = processes.lookup_or_try_init(&pid, process);
    if (!process)
        return NULL;

    return process;
}

static __always_inline struct bpfbox_profile *create_profile(void *ctx, u64 key, const char *comm)
{
    int zero = 0;
    struct bpfbox_profile *profile = __init_profile.lookup(&zero);

    if (!profile)
        return NULL;

    /* Set tail call index */
    set_tail_index(ctx, profile);
    bpf_probe_read_str(profile->comm, sizeof(profile->comm), comm);

    profile = profiles.lookup_or_try_init(&key, profile);
    if (!profile)
        return NULL;

    on_profile_create.perf_submit(ctx, profile, sizeof(*profile));

    return profile;
}

static __always_inline int enforce(void *ctx, struct bpfbox_process *process, struct bpfbox_profile *profile, long syscall)
{
    #ifdef BPFBOX_ENFORCING
    bpf_send_signal(SIGKILL);
    #endif
    bpf_trace_printk("Enforcement for %s on system call %ld\n", profile->comm, syscall);
    return 0;
}

/* ========================================================================= *
 * BPF Programs                                                              *
 * ========================================================================= */

/* System call entrypoint */
TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);

    /* Get out if process does not exist */
    if (!process)
        return 0;

    /* Lookup profile if it exists */
    struct bpfbox_profile *profile = profiles.lookup(&process->profile_key);

    /* Process is enforcing */
    if (process->enforcing && profile)
    {
        rules.call((struct pt_regs *)args, profile->tail_call_index);

        /* Default deny */
        enforce(args, process, profile, args->id);
    }

    return 0;
}

/* When a task forks */
RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct bpfbox_process *process;
    struct bpfbox_process *parent_process;

    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_struct *c = (struct task_struct *)ctx->args[1];

    u32 ppid = p->pid;
    u32 cpid = c->pid;

    /* Create the process */
    process = create_process(ctx, cpid);
    process = processes.lookup(&cpid);
    if (!process)
    {
        /* TODO: print error to logs here */
        return -1;
    }

    process->enforcing = false;
    process->profile_key = 0;

    /* Attempt to look up parent process if we know about it */
    parent_process = processes.lookup(&ppid);
    if (!parent_process)
    {
        return 0;
    }

    /* Assign child profile to parent profile if it exists */
    process->profile_key = parent_process->profile_key;

    return 0;
}

/* When a task loads a program with execve */
RAW_TRACEPOINT_PROBE(sched_process_exec)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);

    /* Get out if process does not exist */
    if (!process)
        return 0;

    /* Yoink the linux_binprm */
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    /* Calculate profile_key
     * Take inode number and filesystem device number together */
    u64 profile_key = (u64)bprm->file->f_path.dentry->d_inode->i_ino | ((u64)new_encode_dev(bprm->file->f_path.dentry->d_inode->i_sb->s_dev) << 32);

    /* Either lookup or create profile */
    struct bpfbox_profile *profile = profiles.lookup(&profile_key);
    if (!profile)
    {
        profile = create_profile(ctx, profile_key, bprm->file->f_path.dentry->d_name.name);
    }
    if (!profile)
    {
        // TODO: print error to logs here
        return -1;
    }

    process->profile_key = profile_key;

    return 0;
}

/* When a task exits */
RAW_TRACEPOINT_PROBE(sched_process_exit)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    processes.delete(&pid);

    return 0;
}

/* Uprobe attached to userspace load_profile function */
int uprobe__load_profile(struct pt_regs *ctx)
{
    // TODO: write this
    // FIXME: write userspace component and attach the two
    return 0;
}
