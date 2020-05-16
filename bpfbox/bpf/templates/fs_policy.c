/* fs_policy template */

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

// Extract access mode
int acc_mode = op->acc_mode;

// TODO: TAINT_RULE here

// Enforce policy if tainted
if (process->tainted)
{
    // Enforce write policy
    if (acc_mode & MAY_WRITE)
    {
        if (FS_WRITE_POLICY)
            return 0;
        else
            enforce(process, profile);
    }

    // Enforce read policy
    if (acc_mode & MAY_READ)
    {
        if (FS_READ_POLICY)
            return 0;
        else
            enforce(process, profile);
    }

    // Enforce append policy
    if (acc_mode & MAY_APPEND)
    {
        if (FS_APPEND_POLICY)
            return 0;
        else
            enforce(process, profile);
    }

    // Enforce execute policy
    if (acc_mode & MAY_EXEC)
    {
        if (FS_EXEC_POLICY)
            return 0;
        else
            enforce(process, profile);
    }

    // Default deny
    enforce(process, profile);
}

return 0;
