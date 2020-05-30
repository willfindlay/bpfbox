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
    u8 taint_on_exec;
};

struct bpfbox_process
{
    u32 pid;
    u32 tgid;
    u64 profile_key;
    u8 tainted;
};

/* ========================================================================= *
 * Intermediate Data                                                         *
 * ========================================================================= */

// Networking policy categories
//struct bpfbox_net_intermediate
//{
//    int syscall;
//    long arg1;
//    long arg2;
//    long arg3;
//    long arg4;
//    long arg5;
//    long arg6;
//};

/* ========================================================================= *
 * Event Data                                                                *
 * ========================================================================= */

#define ENFORCEMENT_COMMON \
    u8 enforcing; \
    u32 pid; \
    u32 tgid; \
    u64 profile_key;

struct fs_enforcement_event
{
    ENFORCEMENT_COMMON
    u32 inode;
    u32 parent_inode;
    u32 st_dev;
    int access;
};

struct net_enforcement_event
{
    ENFORCEMENT_COMMON
    u32 inode;
    u32 parent_inode;
    u32 st_dev;
    int category;
};

/* ========================================================================= *
 * Function Declarations                                                     *
 * ========================================================================= */

#endif /* BPF_PROGRAM_H */
