CC     = gcc
LDLAGS =
CFLAGS = -O0

EXES   = open

.PHONY: all
all: $(EXES)

.PHONY: clean
clean:
	rm -f $(EXES) *.o

open: open.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o open open.c
