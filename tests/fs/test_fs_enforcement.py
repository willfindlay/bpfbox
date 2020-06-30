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

    Tests bpfbox's filesystem policy enforcement.

    2020-Jun-30  William Findlay  Created this.
"""

import subprocess
import pytest
import os
import signal
import logging
import time

from bpfbox.argument_parser import parse_args
from bpfbox.bpf_program import BPFProgram
from bpfbox.logger import BPFBoxLoggerClass
from bpfbox.utils import get_inode_and_device
from bpfbox.flags import BPFBOX_ACTION, FS_ACCESS
from bpfbox import defs

DRIVER_PATH = os.path.join(defs.project_path, 'tests/driver')
OPEN_PATH = os.path.join(DRIVER_PATH, 'open')
AUDIT = BPFBoxLoggerClass.AUDIT


@pytest.fixture()
def bpf_program(caplog):
    # Set log level
    caplog.set_level(AUDIT)

    # Load BPF program
    args = parse_args('--nodaemon'.split())
    defs.init(args)
    b = BPFProgram(enforcing=True, debug=True)
    b.load_bpf()

    yield b

    # Clean up BPF program
    b.cleanup()


def test_fs_implicit_taint(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, True)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call(OPEN_PATH)


def test_fs_no_taint(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)

    subprocess.check_call(OPEN_PATH)


def test_fs_taint(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.MAY_READ, BPFBOX_ACTION.TAINT)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, '1a'])


def test_fs_allow_read_only(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.MAY_READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.MAY_READ)

    subprocess.check_call([OPEN_PATH, '1a'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, '1b'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, '1c'])


def test_fs_allow_read_write(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.MAY_READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.MAY_READ | FS_ACCESS.MAY_WRITE)

    subprocess.check_call([OPEN_PATH, '1a'])

    subprocess.check_call([OPEN_PATH, '1b'])

    subprocess.check_call([OPEN_PATH, '1c'])

