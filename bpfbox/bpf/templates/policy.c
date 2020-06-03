/* fs_policy template */

int fs_policy_PROFILEKEY(struct pt_regs *ctx) {
    // Lookup process
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);
    if (!process) return 0;

    // Look up profile
    struct bpfbox_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile) return 0;

    // Yoink file pointer from return value
    struct file *fp = (struct file *)PT_REGS_RC(ctx);
    if (fp <= 0) return 0;

    // Access the open_flags struct from the entrypoint arguments
    int zero = 0;
    struct open_flags *op = __do_filp_open_intermediate.lookup(&zero);
    if (op <= 0) return 0;

    // Extract file inode and parent dir inode
    struct dentry *dentry = fp->f_path.dentry;
    struct dentry *parent = fp->f_path.dentry->d_parent;
    u32 inode = dentry->d_inode->i_ino;
    u32 parent_inode = parent ? parent->d_inode->i_ino : 0;
    u32 st_dev = (u32)new_encode_dev(dentry->d_inode->i_sb->s_dev);

    // Extract access mode
    int acc_mode = op->acc_mode;

    /*
     * Potentially an interesting design choice here:
     * When we encounter an inode, parent inode, and st_dev of 0,
     * it means that we ran into a permission error opening the file.
     *
     * We have two choices here:
     * 1. Simply return at this point, as the OS' reference monitor should allow
     *    the application to fail gracefully.
     * 2. Continue and call fs_enforce with 100% probability, even if the user
     *    specified a rule to allow such behavior.
     *
     * Neither of these options seems ideal. In case 1, the user may have been
     * expecting bpfbox to outright kill the application in question. Allowing
     * the application to continue (even though the open failed) may constituted
     * an unexpected result.
     *
     * Similarly, in case 2, the user may not be expecting the application to
     * die if they specified a rule that should allow the behavior to continue.
     *
     * For now, we will go with option 1, but this is something that should be
     * revisited before release. TODO: discuss with Anil */
    if (!inode && !parent_inode && !st_dev) return 0;

    FS_RULES

    if (process->tainted)
            fs_enforce(ctx, process, profile, inode, parent_inode, st_dev,
                       acc_mode);

    return 0;
}

/* net_policy templates */

int net_bind_policy_PROFILEKEY(struct pt_regs *ctx)
{
    // Lookup process
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);
    if (!process)
        return 0;

    // Look up profile
    struct bpfbox_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile)
        return 0;

    BIND_RULES

    if (process->tainted)
        net_enforce(ctx, process, profile, BPFBOX_BIND);

    return 0;
}

int net_connect_policy_PROFILEKEY(struct pt_regs *ctx)
{
    // Lookup process
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);
    if (!process)
        return 0;

    // Look up profile
    struct bpfbox_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile)
        return 0;

    CONNECT_RULES

    if (process->tainted)
        net_enforce(ctx, process, profile, BPFBOX_CONNECT);

    return 0;
}

int net_send_policy_PROFILEKEY(struct pt_regs *ctx)
{
    // Lookup process
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);
    if (!process)
        return 0;

    // Look up profile
    struct bpfbox_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile)
        return 0;

    int syscall = PT_REGS_PARM1(ctx);

    SEND_RULES

    if (process->tainted)
        net_enforce(ctx, process, profile, BPFBOX_SEND);

    return 0;
}

int net_recv_policy_PROFILEKEY(struct pt_regs *ctx)
{
    // Lookup process
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);
    if (!process)
        return 0;

    // Look up profile
    struct bpfbox_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile)
        return 0;

    int syscall = PT_REGS_PARM1(ctx);

    RECV_RULES

    if (process->tainted)
        net_enforce(ctx, process, profile, BPFBOX_RECV);

    return 0;
}
