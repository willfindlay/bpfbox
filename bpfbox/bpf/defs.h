#ifndef DEFS_H
#define DEFS_H

/* Maximum number of profiles (and their tail called BPF programs) that can be
 * active at anuy given time. */
#define BPFBOX_MAX_PROFILES  10240

/* Maximum number of processes that can be observed at any given time. */
#define BPFBOX_MAX_PROCESSES 10240

/* Network event types */
#define BPFBOX_BIND 0x1
#define BPFBOX_SEND 0x2
#define BPFBOX_RECV 0x4
#endif /* DEFS_H */
