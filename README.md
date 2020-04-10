# bpfbox

Exploring externally enforced sandboxing rules with eBPF

## TODO:

- Figure out how to associate prog array entries with profiles
    - Probably need some kind of global counter for this (`BPF_HIST`?) that we can use `lock_xadd` on
    - Each profile gets its own index into the array based on this counter?
    - Otherwise we need to hash the prog array somehow... This could get messy!
- Write a python class for managing rules (BPF programs that go into our prog array)
    - these rules will then be modified in real time and tail called when processes enter system calls
- Once we have our rules, it should be enough to have them make policy decisions based on what the user has specified
    - Programs will probably have default deny if enforcing and the tail call fails (this only makes sense)
    - If we're not enforcing, we should definitely just return from the tracepoint (tail call won't need to happen anyway)

## Long Term Stuff:

- Start auto generating rules based on profiles
- Figure out a way to generate semantic profiles, based on Inoue's work
    - https://www.cs.unm.edu/~forrest/dissertations/inoue-dissertation.pdf
