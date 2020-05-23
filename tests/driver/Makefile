TESTFILESDIR = /tmp/bpfbox

CC     = gcc
LDLAGS =
CFLAGS =

EXES   = networking open

.PHONY: all
all: testfiles $(EXES)

.PHONY: clean
clean:
	rm -f $(EXES) *.o

testfiles:
	mkdir -p $(TESTFILESDIR)
	touch $(TESTFILESDIR)/a
	touch $(TESTFILESDIR)/b
	touch $(TESTFILESDIR)/c
	touch $(TESTFILESDIR)/d

networking: networking.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o networking networking.c

open: open.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o open open.c
