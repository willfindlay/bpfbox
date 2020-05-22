/* fs_policy template */

int fs_policy_PROFILEKEY(struct pt_regs *ctx)
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

    // Yoink file pointer from return value
    struct file *fp = (struct file*)PT_REGS_RC(ctx);
    if (!fp)
        return 0;

    // Access the open_flags struct from the entrypoint arguments
    int zero = 0;
    struct open_flags *op = __do_filp_open_intermediate.lookup(&zero);
    if (!op)
        return 0;

    // Extract file inode and parent dir inode
    struct dentry *dentry = fp->f_path.dentry;
    struct dentry *parent = fp->f_path.dentry->d_parent;
    u32 inode = dentry->d_inode->i_ino;
    u32 parent_inode = parent ? parent->d_inode->i_ino : 0;
    u32 st_dev = (u32)new_encode_dev(dentry->d_inode->i_sb->s_dev);

    // Extract access mode
    int acc_mode = op->acc_mode;

    // Apply taint rules if not tainted
    if (!process->tainted)
    {
        if (FS_TAINT_RULES)
        {
            process->tainted = 1;
            return 0;
        }
    }

    // Enforce policy if tainted
    if (process->tainted)
    {
        if (!(FS_ALLOW_RULES))
        {
            fs_enforce(ctx, process, profile, inode, parent_inode, st_dev, acc_mode);
            return 0;
        }
    }

    return 0;
}
