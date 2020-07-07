CC     = gcc
LDLAGS =
CFLAGS = -O0

EXES   = open ipc

.PHONY: all
all: $(EXES)

.PHONY: clean
clean:
	rm -f $(EXES) *.o

open: open.c or_die.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o open open.c

ipc: ipc.c or_die.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o ipc ipc.c
