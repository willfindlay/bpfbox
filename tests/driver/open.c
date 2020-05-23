#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
    int fd = 0;

    fd = open("/tmp/bpfbox/a", O_RDONLY);
    close(fd);
    fd = open("/tmp/bpfbox/b", O_WRONLY);
    close(fd);
    fd = open("/tmp/bpfbox/c", O_RDWR);
    close(fd);

    char *new_argv[] = {"/tmp/bpfbox/d", NULL};
    execve("/tmp/bpfbox/d", new_argv, NULL);

    return 0;
}
