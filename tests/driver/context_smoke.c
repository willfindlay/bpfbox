#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void testificate_a() {
    int fd = 0;
    fd = open("/tmp/bpfbox/a", O_RDONLY);
    close(fd);
}

void testificate_b() {
    int fd = 0;
    fd = open("/tmp/bpfbox/b", O_RDONLY);
    close(fd);
}

void testificate_c() {
    int fd = 0;
    fd = open("/tmp/bpfbox/c", O_RDONLY);
    close(fd);
}

int main(int argc, char **argv) {
    int fd = 0;

    fd = open("/tmp/bpfbox/a", O_RDONLY);
    close(fd);

    testificate_a();
    testificate_b();
    testificate_c();

    return 0;
}
