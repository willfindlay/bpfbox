TESTFILESDIR = /tmp/bpfbox

CC     = gcc
LDLAGS =
CFLAGS = -O0

EXES   = open

.PHONY: all
all: $(EXES)

.PHONY: clean
clean:
	rm -f $(EXES) *.o

.PHONY: testfiles
testfiles:
	mkdir -p $(TESTFILESDIR)
	touch $(TESTFILESDIR)/a
	touch $(TESTFILESDIR)/b
	touch $(TESTFILESDIR)/c
	touch $(TESTFILESDIR)/d

open: open.c | testfiles
	$(CC) $(CFLAGS) $(LDFLAGS) -o open open.c
