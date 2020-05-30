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

    int syscall = PT_REGS_PARM1(ctx);

    // Apply taint rules if not tainted
    if (!process->tainted)
    {
        if (BIND_TAINT_RULES)
        {
            process->tainted = 1;
            return 0;
        }
    }

    // Enforce policy if tainted
    if (process->tainted)
    {
        if (!(BIND_ALLOW_RULES))
        {
            net_enforce(ctx, process, profile, BPFBOX_BIND);
            return 0;
        }
    }

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

    // Apply taint rules if not tainted
    if (!process->tainted)
    {
        if (RECV_TAINT_RULES)
        {
            process->tainted = 1;
            return 0;
        }
    }

    // Enforce policy if tainted
    if (process->tainted)
    {
        if (!(RECV_ALLOW_RULES))
        {
            net_enforce(ctx, process, profile, BPFBOX_SEND);
            return 0;
        }
    }

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

    // Apply taint rules if not tainted
    if (!process->tainted)
    {
        if (RECV_TAINT_RULES)
        {
            process->tainted = 1;
            return 0;
        }
    }

    // Enforce policy if tainted
    if (process->tainted)
    {
        if (!(RECV_ALLOW_RULES))
        {
            net_enforce(ctx, process, profile, BPFBOX_RECV);
            return 0;
        }
    }

    return 0;
}
