CC     = gcc
LDLAGS =
CFLAGS =

EXES   = networking

.PHONY: all
all: $(EXES)

.PHONY: clean
clean:
	rm -f $(EXES) *.o

networking: networking.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o networking networking.c
