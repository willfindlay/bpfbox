# bpfbox

Exploring externally enforced sandboxing rules with eBPF

## TODO:

- Migrate rules from static definition to dynamic definition (using tail calls instead of embedding code into tracepoints)
- Once we have our rules, it should be enough to have them make policy decisions based on what the user has specified
    - Programs will probably have default deny if enforcing and the tail call fails (this only makes sense)
    - If we're not enforcing, we should definitely just return from the tracepoint (tail call won't need to happen anyway)

## Long Term Stuff:

- Start auto generating rules based on profiles
- Figure out a way to generate semantic profiles, based on Inoue's work
    - https://www.cs.unm.edu/~forrest/dissertations/inoue-dissertation.pdf

## Dynamic Sandboxing

### System Calls / Function Calls

- original work looks at Java methods
- can we do the same with system calls?
    - perhaps it would be worth considering function calls too
    - use eBPF to collect stack traces?
    - but what to do about unresolved symbols?

### Java-Like Permission Model

- original work also looks at using Java permission model
- we can do the same thing with eBPF
- need to come up with a language to define rules
    - compile these rules into eBPF programs
    - tail call these programs (bpfbox can already do this)
- **the question:**
    - *what kind of syntax to use for rules?*
    - *what kind of semantics to use for rules?*
