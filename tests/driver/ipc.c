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
    if (argc < 2) {
        return 0;
    }

    // For tainting
    kill_or_die(getpid(), 0);

    if (!strcmp(argv[1], "kill-self")) {
        kill_or_die(getpid(), SIGKILL);
    }

    if (!strcmp(argv[1], "kill-target")) {
        int target_pid = atoi(argv[2]);
        kill_or_die(target_pid, SIGKILL);
    }

    if (!strcmp(argv[1], "check-self")) {
        kill_or_die(getpid(), 0);
    }

    if (!strcmp(argv[1], "check-target")) {
        int target_pid = atoi(argv[2]);
        kill_or_die(target_pid, 0);
    }

    if (!strcmp(argv[1], "stop-self")) {
        kill_or_die(getpid(), SIGSTOP);
    }

    if (!strcmp(argv[1], "stop-target")) {
        int target_pid = atoi(argv[2]);
        kill_or_die(target_pid, SIGSTOP);
    }

    if (!strcmp(argv[1], "chld-self")) {
        kill_or_die(getpid(), SIGCHLD);
    }

    if (!strcmp(argv[1], "chld-target")) {
        int target_pid = atoi(argv[2]);
        kill_or_die(target_pid, SIGCHLD);
    }

    if (!strcmp(argv[1], "usr1-self")) {
        kill_or_die(getpid(), SIGUSR1);
    }

    if (!strcmp(argv[1], "usr1-target")) {
        int target_pid = atoi(argv[2]);
        kill_or_die(target_pid, SIGUSR1);
    }

    if (!strcmp(argv[1], "traceme")) {
        int pid = fork();

        if (pid) {
        } else {
            ptrace_or_die(PTRACE_TRACEME, 0, NULL, NULL);
        }
    }

    return 0;
}
