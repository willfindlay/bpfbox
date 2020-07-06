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

#include "or_die.h"

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
    }

    if (!strcmp(argv[1], "create-file")) {
        fd = creat_or_die("/tmp/bpfbox/e", 0);
    }

    if (!strcmp(argv[1], "create-dir")) {
        mkdir_or_die("/tmp/bpfbox/f", 0);
    }

    if (!strcmp(argv[1], "rmdir")) {
        rmdir_or_die("/tmp/bpfbox/e");
    }

    if (!strcmp(argv[1], "unlink")) {
        unlink_or_die("/tmp/bpfbox/e");
    }

    if (!strcmp(argv[1], "link")) {
        link_or_die("/tmp/bpfbox/a", "/tmp/bpfbox/e");
    }

    if (!strcmp(argv[1], "rename")) {
        rename_or_die("/tmp/bpfbox/a", "/tmp/bpfbox/new_dir/a");
    }

    if (!strcmp(argv[1], "symlink")) {
        symlink_or_die("/tmp/bpfbox/a", "/tmp/bpfbox/e");
    }

    if (!strcmp(argv[1], "malicious-symlink-read")) {
        symlink_or_die("/tmp/bpfbox/a", "/tmp/bpfbox/e");
        fd = open_or_die("/tmp/bpfbox/e", O_RDONLY);
        char buf[256];
        read(fd, buf, 255);
        fprintf(stderr, "read: %s\n", buf);
        close(fd);
    }

    return 0;
}
