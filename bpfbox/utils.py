"""
    🐝 BPFBox 📦  Application-transparent sandboxing rules with eBPF.
    Copyright (C) 2020  William Findlay

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    This file provides several utility functions and helpers that can be
    reused throughout the program.

    2020-Apr-10  William Findlay  Created this.
"""


import os
import sys
import itertools
import signal
import subprocess


def get_inode_and_device(path, follow_symlink=True):
    """
    Return (inode#, device#) tuple for path.
    """
    stat = os.stat(path) if follow_symlink else os.lstat(path)
    return (stat.st_ino, stat.st_dev)


def calculate_profile_key(path, follow_symlink=True):
    """
    Convert a path to a profile key using the same
    logic as bpf_program.c
    """
    st_ino, st_dev = get_inode_and_device(path, follow_symlink)
    return st_ino | (st_dev << 32)


def check_root():
    """
    Check for root privileges.
    """
    return os.geteuid() == 0


def drop_privileges(function):
    """
    Decorator to drop root privileges.
    """

    def inner(*args, **kwargs):
        # Get sudoer's UID
        try:
            sudo_uid = int(os.environ['SUDO_UID'])
        except (KeyError, ValueError):
            print("Could not get UID for sudoer", file=sys.stderr)
            return
        # Get sudoer's GID
        try:
            sudo_gid = int(os.environ['SUDO_GID'])
        except (KeyError, ValueError):
            print("Could not get GID for sudoer", file=sys.stderr)
            return
        # Make sure groups are reset
        try:
            os.setgroups([])
        except PermissionError:
            pass
        # Drop root
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)
        # Execute function
        ret = function(*args, **kwargs)
        # Get root back
        os.setresgid(0, 0, -1)
        os.setresuid(0, 0, -1)
        return ret

    return inner


def read_chunks(f, size=1024):
    """
    Read a file in chunks.
    Default chunk size is 1024.
    """
    while 1:
        data = f.read(size)
        if not data:
            break
        yield data


def powerperm(ell):
    """
    Calculate powerset permutations.
    """
    s = list(ell)
    perms = itertools.chain.from_iterable(
        itertools.permutations(s, r) for r in range(1, len(s) + 1)
    )
    perms = map(lambda p: ''.join(list(p)), perms)
    return list(perms)


def which(program):
    import os

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


@drop_privileges
def run_binary(args_str):
    """
    Drop privileges and run a binary if it exists.
    """
    args = args_str.split()
    binary = which(args[0])
    if not binary:
        return -1
    pid = os.fork()
    if pid == 0:
        os.execvp(binary, args)
    return pid
