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
