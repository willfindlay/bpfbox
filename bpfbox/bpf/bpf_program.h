#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <uapi/asm/unistd_64.h>

/* Struct definitions below this line --------------------------------------- */

struct bpfbox_profile
{
    char comm[TASK_COMM_LEN];
};

struct bpfbox_process
{
    bool enforcing;
    u64 profile_key;
};

/* Helper functions definitions below this line ----------------------------- */

static __always_inline struct bpfbox_process *create_process(u32 pid);
static __always_inline struct bpfbox_profile *create_profile(u64 key);

#endif /* BPF_PROGRAM_H */
