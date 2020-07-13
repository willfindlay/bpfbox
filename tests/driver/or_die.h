#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>

int open_or_die(const char *path, int flags)
{
    int rc = open(path, flags);

    if (rc < 0 && errno == EPERM) {
        fprintf(stderr, "open(%s, %d) failed with %d\n", path, flags, rc);
        exit(1);
    }

    return rc;
}

void execve_or_die(const char *path)
{
    int rc = execve(path, NULL, NULL);

    if (rc < 0 && errno == EPERM) {
        fprintf(stderr, "execve(%s) failed with %d\n", path, rc);
        exit(1);
    }
}

void chown_or_die(const char *path, uid_t owner, gid_t group)
{
    int rc = chown(path, owner, group);

    if (rc < 0 && errno == EPERM) {
        fprintf(stderr, "chown(%s, %d, %d) failed with %d\n", path, owner,
                group, rc);
        exit(1);
    }
}

int creat_or_die(const char *path, mode_t mode)
{
    int rc = creat(path, mode);

    if (rc < 0 && errno == EPERM) {
        fprintf(stderr, "creat(%s, %d) failed with %d\n", path, mode, rc);
        exit(1);
    }

    return rc;
}

void mkdir_or_die(const char *path, mode_t mode)
{
    int rc = mkdir(path, mode);

    if (rc < 0 && errno == EPERM) {
        fprintf(stderr, "mkdir(%s, %d) failed with %d\n", path, mode, rc);
        exit(1);
    }
}

void rmdir_or_die(const char *path)
{
    int rc = rmdir(path);

    if (rc < 0 && errno == EPERM) {
        fprintf(stderr, "rmdir(%s) failed with %d\n", path, rc);
        exit(1);
    }
}

void unlink_or_die(const char *path)
{
    int rc = unlink(path);

    if (rc < 0 && errno == EPERM) {
        fprintf(stderr, "unlink(%s) failed with %d\n", path, rc);
        exit(1);
    }
}

void link_or_die(const char *old, const char *new)
{
    int rc = link(old, new);

    if (rc < 0 && errno == EPERM) {
        fprintf(stderr, "link(%s, %s) failed with %d\n", old, new, rc);
        exit(1);
    }
}

void rename_or_die(const char *old, const char *new)
{
    int rc = rename(old, new);

    if (rc < 0 && errno == EPERM) {
        fprintf(stderr, "rename(%s, %s) failed with %d\n", old, new, rc);
        exit(1);
    }
}

void symlink_or_die(const char *old, const char *new)
{
    int rc = symlink(old, new);

    if (rc < 0) {
        fprintf(stderr, "symlink(%s, %s) failed with %d\n", old, new, rc);
        if (errno == EPERM)
            exit(1);
    }
}

int pipe_or_die(int pipefd[2])
{
    int rc = pipe(pipefd);

    if (rc < 0) {
        fprintf(stderr, "pipe() failed with %d\n", rc);
        if (errno == EPERM)
            exit(1);
    }

    return rc;
}

int kill_or_die(pid_t pid, int sig)
{
    int rc = kill(pid, sig);

    if (rc < 0) {
        fprintf(stderr, "kill(%d, %d) failed with %d\n", pid, sig, rc);
        if (errno == EPERM)
            exit(1);
    }

    return rc;
}

long ptrace_or_die(enum __ptrace_request request, pid_t pid, void *addr, void *data)
{
    long rc = ptrace(request, pid, addr, data);

    if (rc < 0) {
        fprintf(stderr, "ptrace(%d, %d, %x, %x) failed with %d\n", request, pid, addr, data);
        if (errno == EPERM)
            exit(1);
    }

    return rc;
}
