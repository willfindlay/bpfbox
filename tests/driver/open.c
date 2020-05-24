#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int fd = 0;

    fd = open("/tmp/bpfbox/a", O_RDONLY);
    close(fd);
    fd = open("/tmp/bpfbox/a", O_RDONLY);
    close(fd);
    fd = open("/tmp/bpfbox/b", O_WRONLY);
    close(fd);
    fd = open("/tmp/bpfbox/c", O_RDWR);
    close(fd);

    fd = open("/tmp/bpfbox/a", O_WRONLY | O_APPEND);
    close(fd);

    char *new_argv[] = {"/tmp/bpfbox/d", NULL};
    execve("/tmp/bpfbox/d", new_argv, NULL);

    return 0;
}
