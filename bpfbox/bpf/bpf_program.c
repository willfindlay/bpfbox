#include "bpfbox/bpf/bpf_program.h"
#include "bpfbox/bpf/helpers.h"
#include "bpfbox/bpf/defs.h"

/* ========================================================================= *
 * Perf Buffers                                                              *
 * ========================================================================= */

BPF_PERF_OUTPUT(on_process_create);
BPF_PERF_OUTPUT(on_enforcement);
BPF_PERF_OUTPUT(on_would_have_enforced);

/* ========================================================================= *
 * Map Definitions                                                           *
 * ========================================================================= */

/* This map holds information about currently running processes */
BPF_TABLE("lru_hash", u32, struct bpfbox_process, processes, BPFBOX_MAX_PROCESSES);

/* This map holds information about the profiles bpfbox currently knows about */
BPF_TABLE("lru_hash", u64, struct bpfbox_profile, profiles, BPFBOX_MAX_PROFILES);

/* This map holds rules that will be tail called on events */
BPF_PROG_ARRAY(policy, BPFBOX_MAX_PROFILES);

/* ========================================================================= *
 * Helper Functions                                                          *
 * ========================================================================= */

static __always_inline struct bpfbox_process *create_process(void *ctx, u32 pid)
{
    int zero = 0;
    struct bpfbox_process *process = __init_process.lookup(&zero);

    if (!process)
        return NULL;

    process = processes.lookup_or_try_init(&pid, process);
    if (!process)
        return NULL;

    process->enforcing = 0;
    process->profile_key = 0;
    process->pid = pid;

    return process;
}

static __always_inline int enforce(void *ctx, struct bpfbox_process *process, struct bpfbox_profile *profile, long syscall)
{
    #ifdef BPFBOX_ENFORCING
    bpf_send_signal(SIGKILL);
    #endif

    struct enforcement_event event = {};

    event.syscall = syscall;
    event.pid = process->pid;
    event.tid = process->tid;
    event.profile_key = process->profile_key;

    #ifdef BPFBOX_ENFORCING
    on_enforcement.perf_submit(ctx, &event, sizeof(event));
    #else
    on_would_have_enforced.perf_submit(ctx, &event, sizeof(event));
    #endif

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

     /* FIXME: delete this block, just testing on the ls binary for now! */
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    /* Test enforcing on ls */
    if (!bpf_strncmp("ls", comm, 3) && args->id == __NR_exit_group)
        process->enforcing = 1;

    /* Process is enforcing */
    if (process->enforcing && profile)
    {
        rules.call(args, profile->tail_call_index);

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
        return 0;
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

// TODO: remove this define when we get the substitution working
#define BPFBOX_POLICY ;
BPFBOX_POLICY
