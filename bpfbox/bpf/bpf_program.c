#include "bpfbox/bpf/bpf_program.h"

/* Initializer arrays below this line --------------------------------------- */

BPF_ARRAY(__init_process, struct bpfbox_process, 1);
BPF_ARRAY(__init_profile, struct bpfbox_profile, 1);

/* Map definitions below this line ------------------------------------------ */

BPF_TABLE("lru_hash", u32, struct bpfbox_process, processes, 10240);
BPF_TABLE("lru_hash", u64, struct bpfbox_profile, profiles, 10240);

/* Helper functions below this line ----------------------------------------- */

static __always_inline struct bpfbox_process *create_process(u32 pid)
{
    int zero = 0;
    struct bpfbox_process *process = __init_process.lookup(&zero);

    if (!process)
        return NULL;

    process = processes.lookup_or_try_init(&pid, process);

    return process;
}

static __always_inline struct bpfbox_profile *create_profile(u64 key)
{
    int zero = 0;
    struct bpfbox_profile *profile = __init_profile.lookup(&zero);

    if (!profile)
        return NULL;

    profile = profiles.lookup_or_try_init(&key, profile);

    return profile;
}

/* BPF programs below this line --------------------------------------------- */

RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct bpfbox_process *process;
    struct bpfbox_process *parent_process;

    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_struct *c = (struct task_struct *)ctx->args[1];

    u32 ppid = p->pid;
    u32 cpid = c->pid;

    /* Create the process */
    process = create_process(cpid);
    process = processes.lookup(&cpid);
    if (!process)
    {
        /* TODO: print error to logs here */
        return -1;
    }

    process->enforcing = false;
    process->profile_key = 0;

    /* Attempt to look up parent process */
    parent_process = processes.lookup(&ppid);
    if (!parent_process)
    {
        return 0;
    }

    /* Assign child profile to parent profile if it exists */
    process->profile_key = parent_process->profile_key;

    return 0;
}

//RAW_TRACEPOINT_PROBE(sched_process_exec)
//{
//    u32 pid = ebpH_get_pid();
//
//    /* Look up process */
//    struct ebpH_process *process = processes.lookup(&pid);
//    if (!process)
//    {
//        return 0;
//    }
//
//    /* Yoink the linux_binprm */
//    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
//
//    /* Calculate profile_key
//     * Take inode number and filesystem device number together */
//    u64 profile_key = (u64)bprm->file->f_path.dentry->d_inode->i_ino | ((u64)bprm->file->f_path.dentry->d_inode->i_rdev << 32);
//
//    /* Create profile if necessary */
//    ebpH_create_profile(&profile_key, bprm->file->f_path.dentry->d_name.name, (struct pt_regs *)ctx);
//
//    /* Look up profile */
//    struct ebpH_profile *profile = profiles.lookup(&profile_key);
//    if (!profile)
//    {
//        EBPH_ERROR("sched_process_exec: Unable to lookup profile", (struct pt_regs *)ctx);
//        return 0;
//    }
//
//    /* Reset process' sequence stack */
//    for (u32 i = 0; i < EBPH_SEQSTACK_SIZE; i++)
//    {
//        process->stack.seq[i].count = 0;
//        for (u32 j = 0; j < EBPH_SEQLEN; j++)
//        {
//            process->stack.seq[i].seq[j] = EBPH_EMPTY;
//        }
//    }
//
//    /* Start tracing the process */
//    ebpH_start_tracing(profile, process, (struct pt_regs *)ctx);
//
//    return 0;
//}
//
///* When a task exits */
//RAW_TRACEPOINT_PROBE(sched_process_exit)
//{
//    u32 pid = ebpH_get_pid();
//    processes.delete(&pid);
//
//    return 0;
//}
