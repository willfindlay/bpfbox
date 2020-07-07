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
 *  This file provides definitions for BPF program data structures.
 *
 *  2020-Jul-01  William Findlay  Created this.
 */

/* =========================================================================
 * Profiles and Processes
 * ========================================================================= */

/* bpfbox-related information associated with a process (task) */
struct bpfbox_process_t {
    u64 profile_key;
    u32 pid;
    u32 tgid;
    u8 tainted;
};

/* bpfbox-related information associated with a profile */
struct bpfbox_profile_t {
    u8 taint_on_exec;
};

/* =========================================================================
 * Policies and Actions
 * ========================================================================= */

/* use a #define here instead of typedef to help userspace
 * interpret arguments */
#define bpfbox_accesss_t u32

/* each action represents a BPFBox policy decision. */
enum bpfbox_action_t {
    ACTION_NONE = 0x00000000,
    ACTION_ALLOW = 0x00000001,
    ACTION_AUDIT = 0x00000002,
    ACTION_TAINT = 0x00000004,
    ACTION_DENY = 0x00000008,
    ACTION_COMPLAIN = 0x00000010,
};

/* represents allow, taint, and audit access vectors */
struct bpfbox_policy_t {
    bpfbox_accesss_t allow;
    bpfbox_accesss_t taint;
    bpfbox_accesss_t audit;
};

/* =========================================================================
 * File System Policy
 * ========================================================================= */

enum bpfbox_fs_access_t {
    FS_NONE = 0x00000000,
    FS_READ = 0x00000001,
    FS_WRITE = 0x00000002,
    FS_APPEND = 0x00000004,
    FS_EXEC = 0x00000008,
    FS_SETATTR = 0x00000010,
    FS_GETATTR = 0x00000020,
    FS_IOCTL = 0x00000040,
    FS_RM = 0x00000080,
    FS_ADD_LINK = 0x00000100,
};

/* uniquely computes an (inode, profile) pair. */
struct bpfbox_fs_policy_key_t {
    u32 st_ino;
    u32 st_dev;
    u64 profile_key;
};

/* maps subject profile to object profile. */
struct bpfbox_procfs_policy_key_t {
    u64 subject_profile_key;
    u64 object_profile_key;
};

/* =========================================================================
 * IPC Policy
 * ========================================================================= */

enum bpfbox_ipc_access_t {
    IPC_NONE = 0x00000000,
    IPC_SIGCHLD = 0x00000001,
    IPC_SIGKILL = 0x00000002,
    IPC_SIGSTOP = 0x00000004,
    IPC_SIGMISC = 0x00000008,
    IPC_SIGCHECK = 0x00000010,
    IPC_PTRACE = 0x00000020,
};
#define IPC_SIGANY \
    (IPC_SIGCHLD | IPC_SIGKILL | IPC_SIGSTOP | IPC_SIGMISC | IPC_SIGCHECK)

struct bpfbox_ipc_policy_key_t {
    u64 subject_key;
    u64 object_key;
};

/* =========================================================================
 * Audit Data Structures
 * ========================================================================= */

#define STRUCT_AUDIT_COMMON  \
    u32 uid;                 \
    u32 pid;                 \
    u64 profile_key;         \
    bpfbox_accesss_t access; \
    enum bpfbox_action_t action;

#define FILTER_AUDIT(action)                                          \
    if (!(action & (ACTION_COMPLAIN | ACTION_DENY | ACTION_AUDIT))) { \
        return;                                                       \
    }

#define DO_AUDIT_COMMON(event, process, action)    \
    do {                                           \
        if (!event) {                              \
            return;                                \
        }                                          \
        event->uid = bpf_get_current_uid_gid();    \
        event->pid = process->pid;                 \
        event->profile_key = process->profile_key; \
        event->action = action;                    \
        event->access = access;                    \
    } while (0)

/* for auditing inode events */
struct bpfbox_fs_audit_event_t {
    STRUCT_AUDIT_COMMON u32 st_ino;
    u32 st_dev;
    char s_id[32];
};

/* for auditing ipc */
struct bpfbox_ipc_audit_event_t {
    STRUCT_AUDIT_COMMON
    u32 object_uid;
    u32 object_pid;
    u64 object_profile_key;
};
