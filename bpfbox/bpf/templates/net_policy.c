/* net_policy template */

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

    int syscall = PT_REGS_PARM1(ctx);

    bpf_trace_printk("hello networking syscall world %d\n", syscall);

    // Apply taint rules if not tainted
    if (!process->tainted)
    {
        if (NET_TAINT_RULES)
        {
            process->tainted = 1;
            return 0;
        }
    }

    // Enforce policy if tainted
    if (process->tainted)
    {
        if (!(NET_ALLOW_RULES))
        {
            net_enforce(ctx, process, profile);
            return 0;
        }
    }

    return 0;
}
