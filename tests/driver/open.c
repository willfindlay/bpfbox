#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int open_or_die(const char *path, int flags)
{
    int rc = open(path, flags);

    if (rc < 0) {
        fprintf(stderr, "open(%s, %d) failed with %d\n", path, flags, rc);
        exit(1);
    }

    return rc;
}

// TODO: move to exec.c
void execve_or_die(const char *path, char **argv, char **envp)
{
    int rc = execve(path, argv, envp);

    if (rc < 0) {
        fprintf(stderr, "execve(%s) failed with %d\n", path, rc);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    int fd;

    if (argc < 2) {
        return 0;
    }

    // For tainting
    fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);

    if (!strcmp(argv[1], "1a")) {
        fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);
        close(fd);
    }

    if (!strcmp(argv[1], "1b")) {
        fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/a", O_WRONLY);
        close(fd);
    }

    if (!strcmp(argv[1], "1c")) {
        fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/a", O_RDWR);
        close(fd);
    }

    return 0;
}
