/*
 *  🐝 BPFBox 📦  Application-transparent sandboxing rules with eBPF.
 *  Copyright (C) 2020  William Findlay
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Driver for filesystem enforcement tests.
 *
 *  2020-Jun-30  William Findlay  Created this.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
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

int main(int argc, char **argv)
{
    int fd;

    if (argc < 2) {
        return 0;
    }

    // For tainting
    fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);

    if (!strcmp(argv[1], "simple-read")) {
        fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);
        close(fd);
    }

    if (!strcmp(argv[1], "simple-read-and-write")) {
        fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/a", O_WRONLY);
        close(fd);
    }

    if (!strcmp(argv[1], "simple-read-and-readwrite")) {
        fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/a", O_RDWR);
        close(fd);
    }

    if (!strcmp(argv[1], "simple-write-append")) {
        fd = open_or_die("/tmp/bpfbox/a", O_WRONLY | O_APPEND);
        close(fd);
    }

    if (!strcmp(argv[1], "simple-write-no-append")) {
        fd = open_or_die("/tmp/bpfbox/a", O_WRONLY);
        close(fd);
    }

    if (!strcmp(argv[1], "complex")) {
        fd = open_or_die("/tmp/bpfbox/a", O_RDWR);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/b", O_WRONLY | O_APPEND);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/c", O_RDONLY);
        close(fd);
        execve_or_die("/tmp/bpfbox/d");
    }

    if (!strcmp(argv[1], "complex-with-extra")) {
        fd = open_or_die("/tmp/bpfbox/a", O_RDWR);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/a", O_WRONLY);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/b", O_WRONLY | O_APPEND);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/c", O_RDONLY);
        close(fd);
        execve_or_die("/tmp/bpfbox/d");
    }

    if (!strcmp(argv[1], "complex-with-invalid")) {
        fd = open_or_die("/tmp/bpfbox/a", O_RDWR);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/a", O_WRONLY);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/b", O_WRONLY | O_APPEND);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/c", O_RDONLY);
        close(fd);
        fd = open_or_die("/tmp/bpfbox/d", O_WRONLY);
        close(fd);
        execve_or_die("/tmp/bpfbox/d");
    }

    if (!strcmp(argv[1], "parent-child")) {
        int pid = fork();

        // Parent and child
        fd = open_or_die("/tmp/bpfbox/a", O_RDONLY);
        close(fd);
        // Child only
        if (pid) {
            fd = open_or_die("/tmp/bpfbox/a", O_WRONLY);
            close(fd);
        }

        // Forward child's exit status
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            exit(WEXITSTATUS(status));
        }
    }

    if (!strcmp(argv[1], "proc-self")) {
        fd = open_or_die("/proc/self/status", O_RDONLY);
        close(fd);
    }

    if (!strcmp(argv[1], "proc-1")) {
        fd = open_or_die("/proc/1/status", O_RDONLY);
        close(fd);
    }

    if (!strcmp(argv[1], "proc-sleep") && argc > 2) {
        int sleep_pid = atoi(argv[2]);
        char sleep_path[256];
        sprintf(sleep_path, "/proc/%d/status", sleep_pid);
        fd = open_or_die(sleep_path, O_RDONLY);
        close(fd);
    }

    if (!strcmp(argv[1], "chown-a")) {
        chown_or_die("/tmp/bpfbox/a", 0, 0);
        close(fd);
    }

    if (!strcmp(argv[1], "create-file")) {
        fd = creat_or_die("/tmp/bpfbox/e", 0);
        close(fd);
    }

    if (!strcmp(argv[1], "create-dir")) {
        mkdir_or_die("/tmp/bpfbox/f", 0);
        close(fd);
    }

    if (!strcmp(argv[1], "rmdir")) {
        rmdir_or_die("/tmp/bpfbox/e");
        close(fd);
    }

    if (!strcmp(argv[1], "unlink")) {
        unlink_or_die("/tmp/bpfbox/e");
        close(fd);
    }

    if (!strcmp(argv[1], "link")) {
        link_or_die("/tmp/bpfbox/a", "/tmp/bpfbox/e");
        close(fd);
    }

    if (!strcmp(argv[1], "rename")) {
        rename_or_die("/tmp/bpfbox/a", "/tmp/bpfbox/new_dir/a");
        close(fd);
    }

    return 0;
}
