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
from bpfbox.utils import get_inode_and_device, which
from bpfbox.flags import BPFBOX_ACTION, FS_ACCESS
from bpfbox import defs

DRIVER_PATH = os.path.join(defs.project_path, 'tests/driver')
OPEN_PATH = os.path.join(DRIVER_PATH, 'open')


def test_fs_implicit_taint(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, True)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call(OPEN_PATH)


def test_fs_no_taint(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)

    subprocess.check_call(OPEN_PATH)


def test_fs_taint(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-read'])


def test_fs_allow_read_only(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ)

    subprocess.check_call([OPEN_PATH, 'simple-read'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-read-and-write'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-read-and-readwrite'])


def test_fs_allow_read_write(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ | FS_ACCESS.WRITE)

    subprocess.check_call([OPEN_PATH, 'simple-read'])

    subprocess.check_call([OPEN_PATH, 'simple-read-and-write'])

    subprocess.check_call([OPEN_PATH, 'simple-read-and-readwrite'])


def test_fs_allow_append_only(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.APPEND)

    subprocess.check_call([OPEN_PATH, 'simple-write-append'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-write-no-append'])


def test_fs_allow_write_only(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.WRITE)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-write-append'])

    subprocess.check_call([OPEN_PATH, 'simple-write-no-append'])


def test_fs_allow_write_and_append(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.WRITE | FS_ACCESS.APPEND)

    subprocess.check_call([OPEN_PATH, 'simple-write-append'])

    subprocess.check_call([OPEN_PATH, 'simple-write-no-append'])


def test_fs_complex_policy(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ | FS_ACCESS.WRITE)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/b', FS_ACCESS.APPEND)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/c', FS_ACCESS.READ)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/d', FS_ACCESS.EXEC)

    subprocess.check_call([OPEN_PATH, 'complex'])

    subprocess.check_call([OPEN_PATH, 'complex-with-extra'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'complex-with-invalid'])


def test_parent_child(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'parent-child'])


def test_procfs(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/proc', FS_ACCESS.EXEC)

    subprocess.check_call([OPEN_PATH, 'proc-self'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'proc-1'])


@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_procfs_other_process(bpf_program: BPFProgram, caplog):
    sleep_path = which('sleep')
    bpf_program.add_profile(OPEN_PATH, False)
    bpf_program.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    bpf_program.add_fs_rule(OPEN_PATH, '/proc', FS_ACCESS.EXEC)
    bpf_program.add_procfs_rule(OPEN_PATH, sleep_path, FS_ACCESS.READ)

    subprocess.check_call([OPEN_PATH, 'proc-self'])

    # for some reason Popen's pid is always off by 1
    sleep_pid = subprocess.Popen([sleep_path, '10']).pid + 1

    subprocess.check_call([OPEN_PATH, 'proc-sleep', str(sleep_pid)])


@pytest.mark.skipif(not which('exa'), reason='exa not found on system')
def test_exa(bpf_program: BPFProgram, caplog):
    exa = which('exa')
    bpf_program.add_profile(exa, True)
    bpf_program.add_fs_rule(exa, "/etc/ld.so.cache", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/usr/lib/libz.so.1", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/usr/lib/libdl.so.2", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/usr/lib/librt.so.1", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/usr/lib/libpthread.so.0", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/usr/lib/libgcc_s.so.1", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/usr/lib/libc.so.6", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/usr/lib/perl5/5.30/core_perl/CORE/dquote_inline.h", FS_ACCESS.EXEC,)
    bpf_program.add_fs_rule(exa, "/usr/lib/libnss_files-2.31.so", FS_ACCESS.EXEC | FS_ACCESS.READ,)
    bpf_program.add_fs_rule(exa, "/etc/localtime", FS_ACCESS.READ | FS_ACCESS.EXEC,)
    bpf_program.add_fs_rule(exa, "/usr/lib/locale/locale-archive", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/etc/nsswitch.conf", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/etc/passwd", FS_ACCESS.READ)
    bpf_program.add_fs_rule(exa, "/var", FS_ACCESS.EXEC)
    bpf_program.add_fs_rule(exa, "/run/nscd", FS_ACCESS.EXEC)
    bpf_program.add_fs_rule(exa, '/proc', FS_ACCESS.EXEC)
    bpf_program.add_fs_rule(exa, '/tmp/bpfbox', FS_ACCESS.READ | FS_ACCESS.EXEC)

    out = subprocess.check_output([exa, '/tmp/bpfbox']).decode('utf-8')
    assert out.strip() == '\n'.join(sorted(os.listdir('/tmp/bpfbox')))

@pytest.mark.skipif(not which('ls'), reason='ls not found on system')
def test_ls(bpf_program: BPFProgram, caplog):
    ls = which('ls')
    bpf_program.add_profile(ls, True)
    bpf_program.add_fs_rule(ls, "/etc/ld.so.cache", FS_ACCESS.READ)
    bpf_program.add_fs_rule(ls, "/usr/lib/libcap.so.2", FS_ACCESS.READ)
    bpf_program.add_fs_rule(ls, "/usr/lib/libc.so.6", FS_ACCESS.READ)
    bpf_program.add_fs_rule(ls, "/usr/lib/locale/locale-archive", FS_ACCESS.READ)
    bpf_program.add_fs_rule(ls, '/proc', FS_ACCESS.EXEC)
    bpf_program.add_fs_rule(ls, '/tmp/bpfbox', FS_ACCESS.READ)

    out = subprocess.check_output([ls, '/tmp/bpfbox']).decode('utf-8')
    assert out.strip() == '\n'.join(sorted(os.listdir('/tmp/bpfbox')))
