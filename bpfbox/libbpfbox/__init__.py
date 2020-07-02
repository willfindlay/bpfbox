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

    Provides an interface to libbpfbox, which is used to issue complex
    commands to the BPF program. BPFBox instruments uprobes on itself and
    calls these functions as needed.  Doing it this way saves on bpf(2)
    syscalls for operations like adding rules.

    **********************************************************************
    **********************************************************************
       WARNING: Keep this file in sync with libbpfbox.c at all times!
    **********************************************************************
    **********************************************************************

    2020-Jun-29  William Findlay  Created this.
"""

import os
import sys
import ctypes as ct

from bpfbox import defs
from bpfbox.logger import get_logger

logger = get_logger()

try:
    logger.info(f'Loading {defs.libbpfbox}...')
    lib = ct.CDLL(defs.libbpfbox)
    logger.info(f'Loaded {defs.libbpfbox}.')
except:
    logger.error(f'Unable to load {defs.libbpfbox}. Have you run make?')
    sys.exit(-1)

commands = []


def _add_command(command, argtypes, restype=None):
    commands.append((command, argtypes, restype))


_add_command('add_profile', [ct.c_ulonglong, ct.c_uint8])
_add_command('add_fs_rule', [ct.c_ulonglong, ct.c_ulong, ct.c_ulong, ct.c_ulong, ct.c_uint])
_add_command('add_procfs_rule', [ct.c_ulonglong, ct.c_ulonglong, ct.c_ulong, ct.c_uint])


def register_uprobes(bpf):
    for item in commands:
        command, argtypes, restype = item
        getattr(lib, command).argtypes = argtypes
        getattr(lib, command).restype = restype
        bpf.attach_uprobe(
            name=defs.libbpfbox, sym=command, pid=os.getpid(), fn_name=command
        )
        logger.debug(f'Registered uprobe for {command}.')
