#include <linux/sched.h>
#include <linux/fs.h>

/* =========================================================================
 * Maps
 * ========================================================================= */

BPF_

/* =========================================================================
 * Ring Buffers and Helpers
 * ========================================================================= */

BPF_RINGBUF_OUTPUT(inode_audit_events, BB_AUDIT_RINGBUF_PAGES);

struct inode_audit_event_t {
    u32 uid;
    u32 pid;
    char comm[16];
    u32 st_ino;
    u32 st_dev;
    char s_id[32];
    int mask;
};

static __always_inline void audit_inode(struct inode *inode, int mask) {
    struct inode_audit_event_t *event = inode_audit_events.ringbuf_reserve(sizeof(struct inode_audit_event_t));
    if (!event) {
        return;
    }

    event->uid = bpf_get_current_uid_gid();

    event->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    event->st_ino = inode->i_ino;
    event->st_dev = (u32)new_encode_dev(inode->i_sb->s_dev);
    bpf_probe_read_str(event->s_id, sizeof(event->s_id), inode->i_sb->s_id);
    event->mask = mask;

    inode_audit_events.ringbuf_submit(event, 0);
}

/* =========================================================================
 * LSM Programs
 * ========================================================================= */

LSM_PROBE(inode_permission, struct inode *inode, int mask) {
    audit_inode(inode, mask);
    return 0;
}
