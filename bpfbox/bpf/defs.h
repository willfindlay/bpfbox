#ifndef DEFS_H
#define DEFS_H

/* Maximum number of profiles (and their tail called BPF programs) that can be
 * active at anuy given time. */
#define BPFBOX_MAX_PROFILES 10240

/* Maximum number of processes that can be observed at any given time. */
#define BPFBOX_MAX_PROCESSES 10240

/* Network event types */
#define BPFBOX_BIND = 0x01
#define BPFBOX_CONNECT = 0x02
#define BPFBOX_ACCEPT = 0x04
#define BPFBOX_SEND = 0x08
#define BPFBOX_RECV = 0x10
#endif /* DEFS_H */
