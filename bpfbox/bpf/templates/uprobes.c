int uprobe_CONTEXTMASK_PROFILEKEY(struct pt_regs *ctx) {
    // Lookup process
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);
    if (!process) return 0;

    // Look up profile
    struct bpfbox_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile) return 0;

    // Set context mask bit
    process->context_mask |= CONTEXTMASK;

    return 0;
}

int uretprobe_CONTEXTMASK_PROFILEKEY(struct pt_regs *ctx) {
    // Lookup process
    u32 pid = bpf_get_current_pid_tgid();
    struct bpfbox_process *process = processes.lookup(&pid);
    if (!process) return 0;

    // Look up profile
    struct bpfbox_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile) return 0;

    // Unset context mask bit
    process->context_mask &= ~CONTEXTMASK;

    return 0;
}
