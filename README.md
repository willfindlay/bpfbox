# 🐝 bpfbox 📦

`bpfbox` is a policy enforcement engine written in eBPF to confine process access to security-sensitive system resources.

## bpfbox is EOL

BPFBox is being replaced by [BPFContain](https://github.com/willfindlay/bpfcontain-rs/), a new confinement solution written in Rust using libbpf-rs.

## Links

Our research paper: https://www.cisl.carleton.ca/~will/written/conference/bpfbox-ccsw2020.pdf

## Disclaimer

`bpfbox` is very much a research prototype at this stage. Not recommended for production use before version 1.0.0.

## Roadmap / TODO

- Implement auto attachment of uprobes/kprobes for process state
- Fully implement the uprobe/kprobe support in the policy language (see below)
- Re-visit policy langugage
    - Move to yaml / rego?
- Document final version of policy language
- Add more unit tests / document code coverage

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

## Citation

If you would like to cite this work, we request that you use the following bibtex entry:
```bibtex
@inproceedings{findlay2020_bpfbox,
    author    = {Findlay, William and Somayaji, Anil and Barrera, David},
    title     = {{bpfbox: Simple Precise Process Confinement with eBPF}},
    year      = {2020},
    isbn      = {9781450380843},
    publisher = {Association for Computing Machinery},
    address   = {New York, NY, USA},
    doi       = {10.1145/3411495.3421358},
    booktitle = {Proceedings of the 2020 ACM SIGSAC Conference on Cloud Computing Security Workshop},
    pages     = {91–103},
    numpages  = {13},
    keywords  = {ebpf, application confinement, access control, sandboxing, operating system security, linux},
    location  = {Virtual Event, USA},
    series    = {CCSW'20}
}
```
