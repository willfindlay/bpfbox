#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <uapi/linux/ptrace.h>
#include <uapi/asm/unistd_64.h>

/* ========================================================================= *
 * Datatypes                                                                 *
 * ========================================================================= */

struct bpfbox_path
{
    char path[PATH_MAX];
};

struct bpfbox_profile
{
    int tail_call_index;
    char comm[TASK_COMM_LEN];
};

struct bpfbox_process
{
    bool enforcing;
    u64 profile_key;
};

/* ========================================================================= *
 * Function Declarations                                                     *
 * ========================================================================= */

static __always_inline struct bpfbox_process *create_process(void *ctx, u32 pid);
static __always_inline struct bpfbox_profile *create_profile(void *ctx, u64 key, const char *comm);

static __always_inline int set_tail_index(void *ctx, struct bpfbox_profile *profile);

#endif /* BPF_PROGRAM_H */
