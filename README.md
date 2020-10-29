# 🐝 bpfbox 📦

`bpfbox` is a policy enforcement engine written in eBPF to confine process access to security-sensitive system resources.

## Roadmap / TODO

- Implement auto attachment of uprobes/kprobes for process state
- Fully implement the uprobe/kprobe support in the policy language (see below)
- Re-visit policy langugage
    - Move to yaml / rego?
- Document final version of policy language

## Requirements

1. Linux 5.8+ compiled with at least CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_BPF_JIT=y, CONFIG_TRACEPOINTS=y, CONFIG_BPF_LSM=y, CONFIG_DEBUG_INFO=y, CONFIG_DEBUG_INFO_BTF=y, CONFIG_LSM="bpf". pahole >= 0.16 must be installed for the kernel to be built with BTF info.
1. Either the latest version of bcc from https://github.com/iovisor/bcc or bcc version 0.16+. If building from source, be sure to include -DPYTHON_CMD=python3 in your the cmake flags
1. Python 3.8+

## Installation

- Coming soon, for now just run from the `bin` directory in this repository.

## Usage

1. Install policy files in `/var/lib/bpfbox/policy`
1. Run the daemon using `sudo bpfboxd`
1. Inspect audit logs with `tail -f /var/log/bpfbox/bpfbox.log`
