#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

// PATH_MAX
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/kdev_t.h>

#include <linux/binfmts.h>
#include <uapi/linux/ptrace.h>

// system call numbers
#include <uapi/asm/unistd_64.h>

// binfmt (not needed for proof of concept, but needed for final version)
#include <linux/binfmts.h>

// socketaddr struct
#include <linux/socket.h>

// open, openat, openat2 flags
#include <uapi/linux/fcntl.h>
#include <linux/fs.h>

// FIXME: why can't we find this header file?
// fs/internal.h
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

/* ========================================================================= *
 * Datatypes                                                                 *
 * ========================================================================= */

/* #####################################
   #  WARNING WARNING WARNING WARNING  #
   #                                   #
   #  Keep in sync with structs.py     #
   #                                   #
   #  WARNING WARNING WARNING WARNING  #
   ##################################### */

struct bpfbox_profile
{
    int tail_call_index;
};

struct bpfbox_process
{
    u32 pid;
    u32 tid;
    u64 profile_key;
    u8 enforcing;
};

/* ========================================================================= *
 * Event Data                                                                *
 * ========================================================================= */

struct enforcement_event
{
    long syscall;
    u32 pid;
    u32 tid;
    u64 profile_key;
};

/* ========================================================================= *
 * Function Declarations                                                     *
 * ========================================================================= */

static __always_inline
    struct bpfbox_process *create_process(void *ctx, u32 pid);

static __always_inline
    struct bpfbox_profile *create_profile(void *ctx,u64 key, const char *comm);

#endif /* BPF_PROGRAM_H */
