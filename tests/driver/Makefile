CC     = gcc
LDLAGS =
CFLAGS = -O0

EXES   = open silly_program

.PHONY: all
all: $(EXES)

.PHONY: clean
clean:
	rm -f $(EXES) *.o

open: open.c or_die.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o open open.c

silly_program: silly_program.c or_die.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o silly_program silly_program.c
