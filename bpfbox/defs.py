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

    William Findlay created this.
        williamfindlay <àŧ> cmail.carleton.ca
"""

import os, sys

# Path to project directory
project_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Path to bpf program
bpf_prog_path = os.path.join(project_path, 'bpfbox/bpf/policy.c')

# Time to sleep between daemon ticks in seconds
ticksleep = 0.1

# Path to working directory
working_directory = '/var/lib/bpfbox'

# Path to profiles directory
profiles_directory = os.path.join(working_directory, 'policy')

# Path to pidfile
pidfile = '/var/run/bpfboxd.pid'

# Path to logfile
logfile = '/var/log/bpfbox/bpfbox.log'

# Path to bpffs
bpffs = '/sys/fs/bpf'

# Size (in bits) of context masks for policy
context_mask_size = 64

# Maximum string size in bytes
max_string_size = 128

# Ringbuf sizes in pages
audit_ringbuf_pages = 1 << 8

# Size of policy maps
# Higher values allow more policy to be defined for each category, but
# result in higher memory consumption
max_policy_size = 10240

# Size of processes map
# Higher values allow bpfbox to monitor more processes at once
# But results in higher memory consumption
max_processes = 10240


def init(args):
    """
    Make sure things are setup properly.
    """
    # Make working_directory or set permissions of existing working_directory
    try:
        os.makedirs(working_directory, mode=0o1700, exist_ok=True)
    except OSError:
        os.chmod(working_directory, mode=0o1700)

    # Make profiles_directory or set permissions of existing profiles_directory
    try:
        os.makedirs(profiles_directory, mode=0o1700, exist_ok=True)
    except OSError:
        os.chmod(profiles_directory, mode=0o1700)

    from bpfbox.logger import setup_logger

    setup_logger(args)

    # Make pidfile parent directory
    os.makedirs(os.path.dirname(pidfile), exist_ok=True)
