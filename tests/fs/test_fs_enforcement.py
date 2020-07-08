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
from shutil import rmtree

from bpfbox.argument_parser import parse_args
from bpfbox.bpf_program import BPFProgram
from bpfbox.logger import BPFBoxLoggerClass
from bpfbox.utils import get_inode_and_device, which
from bpfbox.flags import BPFBOX_ACTION, FS_ACCESS
from bpfbox import defs
from bpfbox.libbpfbox import Commands

DRIVER_PATH = os.path.join(defs.project_path, 'tests/driver')
OPEN_PATH = os.path.join(DRIVER_PATH, 'open')

@pytest.fixture
def setup_testdir():
    rmtree('/tmp/bpfbox', ignore_errors=True)
    os.mkdir('/tmp/bpfbox')
    open('/tmp/bpfbox/a', 'a').close()
    open('/tmp/bpfbox/b', 'a').close()
    open('/tmp/bpfbox/c', 'a').close()
    open('/tmp/bpfbox/d', 'a').close()
    os.chmod('/tmp/bpfbox/d', 0o755)


def test_fs_implicit_taint(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, True)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call(OPEN_PATH)


def test_fs_no_taint(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)

    subprocess.check_call(OPEN_PATH)


def test_fs_taint(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-read'])


def test_fs_allow_read_only(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ)

    subprocess.check_call([OPEN_PATH, 'simple-read'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-read-and-write'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-read-and-readwrite'])


def test_fs_allow_read_write(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ | FS_ACCESS.WRITE)

    subprocess.check_call([OPEN_PATH, 'simple-read'])

    subprocess.check_call([OPEN_PATH, 'simple-read-and-write'])

    subprocess.check_call([OPEN_PATH, 'simple-read-and-readwrite'])


def test_fs_allow_append_only(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.APPEND)

    subprocess.check_call([OPEN_PATH, 'simple-write-append'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-write-no-append'])


def test_fs_allow_write_only(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.WRITE)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'simple-write-append'])

    subprocess.check_call([OPEN_PATH, 'simple-write-no-append'])


def test_fs_allow_write_and_append(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.WRITE | FS_ACCESS.APPEND)

    subprocess.check_call([OPEN_PATH, 'simple-write-append'])

    subprocess.check_call([OPEN_PATH, 'simple-write-no-append'])


def test_fs_complex_policy(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ | FS_ACCESS.WRITE)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/b', FS_ACCESS.APPEND)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/c', FS_ACCESS.READ)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/d', FS_ACCESS.EXEC)

    subprocess.check_call([OPEN_PATH, 'complex'])

    subprocess.check_call([OPEN_PATH, 'complex-with-extra'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'complex-with-invalid'])


def test_parent_child(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'parent-child'])


def test_procfs(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/proc', FS_ACCESS.EXEC)

    subprocess.check_call([OPEN_PATH, 'proc-self'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'proc-other', '1'])


@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_procfs_other_process(bpf_program: BPFProgram, caplog, setup_testdir):
    sleep_path = which('sleep')
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/proc', FS_ACCESS.EXEC)
    Commands.add_procfs_rule(OPEN_PATH, sleep_path, FS_ACCESS.READ | FS_ACCESS.EXEC)

    subprocess.check_call([OPEN_PATH, 'proc-self'])

    sleep_pid = subprocess.Popen([sleep_path, '10']).pid
    subprocess.check_call([OPEN_PATH, 'proc-other', str(sleep_pid)])


@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_procfs_other_process_not_allowed(bpf_program: BPFProgram, caplog, setup_testdir):
    sleep_path = which('sleep')
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/proc', FS_ACCESS.EXEC)

    subprocess.check_call([OPEN_PATH, 'proc-self'])

    sleep_pid = subprocess.Popen([sleep_path, '10']).pid

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'proc-other', str(sleep_pid)])


def test_chown_allowed(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ | FS_ACCESS.SETATTR)

    subprocess.check_call([OPEN_PATH, 'chown-a'])


def test_chown_disallowed(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'chown-a'])


def test_create_file_allowed(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE | FS_ACCESS.EXEC)

    subprocess.check_call([OPEN_PATH, 'create-file'])


def test_create_file_disallowed(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.READ | FS_ACCESS.EXEC)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'create-file'])


def test_create_dir_allowed(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE | FS_ACCESS.EXEC)

    subprocess.check_call([OPEN_PATH, 'create-dir'])


def test_create_dir_no_write(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.EXEC)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'create-dir'])


def test_create_dir_no_exec(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'create-dir'])


def test_rmdir_allowed(bpf_program: BPFProgram, caplog, setup_testdir):
    os.mkdir('/tmp/bpfbox/e')
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE | FS_ACCESS.EXEC)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/e', FS_ACCESS.RM)

    subprocess.check_call([OPEN_PATH, 'rmdir'])


def test_rmdir_no_write(bpf_program: BPFProgram, caplog, setup_testdir):
    os.mkdir('/tmp/bpfbox/e')
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.EXEC)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/e', FS_ACCESS.RM)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'rmdir'])


def test_rmdir_no_rm(bpf_program: BPFProgram, caplog, setup_testdir):
    os.mkdir('/tmp/bpfbox/e')
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE | FS_ACCESS.EXEC)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'rmdir'])


def test_unlink_allowed(bpf_program: BPFProgram, caplog, setup_testdir):
    open('/tmp/bpfbox/e', 'a').close()
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE | FS_ACCESS.EXEC)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/e', FS_ACCESS.RM)

    subprocess.check_call([OPEN_PATH, 'unlink'])


def test_unlink_no_write(bpf_program: BPFProgram, caplog, setup_testdir):
    open('/tmp/bpfbox/e', 'a').close()
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.EXEC)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/e', FS_ACCESS.RM)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'unlink'])


def test_unlink_no_rm(bpf_program: BPFProgram, caplog, setup_testdir):
    open('/tmp/bpfbox/e', 'a').close()
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE | FS_ACCESS.EXEC)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'unlink'])


def test_link_allowed(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.ADD_LINK)

    subprocess.check_call([OPEN_PATH, 'link'])


def test_link_no_write(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.ADD_LINK)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'link'])


def test_link_no_link(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'link'])


def test_rename_allowed(bpf_program: BPFProgram, caplog, setup_testdir):
    os.mkdir('/tmp/bpfbox/new_dir')
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/new_dir', FS_ACCESS.WRITE | FS_ACCESS.EXEC)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.RM)

    subprocess.check_call([OPEN_PATH, 'rename'])


def test_rename_no_olddir_write(bpf_program: BPFProgram, caplog, setup_testdir):
    os.mkdir('/tmp/bpfbox/new_dir')
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/new_dir', FS_ACCESS.WRITE | FS_ACCESS.EXEC)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.RM)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'rename'])


def test_rename_no_newdir_write(bpf_program: BPFProgram, caplog, setup_testdir):
    os.mkdir('/tmp/bpfbox/new_dir')
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/new_dir', FS_ACCESS.EXEC)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.RM)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'rename'])


def test_rename_no_old_rm(bpf_program: BPFProgram, caplog, setup_testdir):
    os.mkdir('/tmp/bpfbox/new_dir')
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/new_dir', FS_ACCESS.WRITE | FS_ACCESS.EXEC)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'rename'])


def test_symlink_allowed(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE | FS_ACCESS.EXEC)

    subprocess.check_call([OPEN_PATH, 'symlink'])


def test_symlink_disallowed(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.READ | FS_ACCESS.EXEC)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'symlink'])


def test_malicious_symlink_cannot_write_dir(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'malicious-symlink-read'])


def test_malicious_symlink_cannot_add_link(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'malicious-symlink-read'])


def test_malicious_symlink_cannot_read_original(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.ADD_LINK)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'malicious-symlink-read'])


def test_non_malicious_symlink_can_read_original(bpf_program: BPFProgram, caplog, setup_testdir):
    Commands.add_profile(OPEN_PATH, False)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ, BPFBOX_ACTION.TAINT)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox', FS_ACCESS.WRITE)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.ADD_LINK)
    Commands.add_fs_rule(OPEN_PATH, '/tmp/bpfbox/a', FS_ACCESS.READ)

    subprocess.check_call([OPEN_PATH, 'malicious-symlink-read'])


@pytest.mark.skipif(not which('exa'), reason='exa not found on system')
def test_exa(bpf_program: BPFProgram, caplog, setup_testdir):
    exa = which('exa')
    Commands.add_profile(exa, True)
    Commands.add_fs_rule(exa, "/etc/ld.so.cache", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/usr/lib/libz.so.1", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/usr/lib/libdl.so.2", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/usr/lib/librt.so.1", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/usr/lib/libpthread.so.0", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/usr/lib/libgcc_s.so.1", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/usr/lib/libc.so.6", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/usr/lib/perl5/5.30/core_perl/CORE/dquote_inline.h", FS_ACCESS.EXEC | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/usr/lib/libnss_files-2.31.so", FS_ACCESS.EXEC | FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/etc/localtime", FS_ACCESS.READ | FS_ACCESS.EXEC | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/usr/lib/locale/locale-archive", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/etc/nsswitch.conf", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/etc/passwd", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/var", FS_ACCESS.EXEC | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, "/run/nscd", FS_ACCESS.EXEC | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, '/proc', FS_ACCESS.EXEC | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, '/tmp/bpfbox', FS_ACCESS.READ | FS_ACCESS.EXEC | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, '/tmp/bpfbox/a', FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, '/tmp/bpfbox/b', FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, '/tmp/bpfbox/c', FS_ACCESS.GETATTR)
    Commands.add_fs_rule(exa, '/tmp/bpfbox/d', FS_ACCESS.GETATTR)

    out = subprocess.check_output([exa, '/tmp/bpfbox']).decode('utf-8')
    assert out.strip() == '\n'.join(sorted(os.listdir('/tmp/bpfbox')))

@pytest.mark.skipif(not which('ls'), reason='ls not found on system')
def test_ls(bpf_program: BPFProgram, caplog, setup_testdir):
    ls = which('ls')
    Commands.add_profile(ls, True)
    Commands.add_fs_rule(ls, "/etc/ld.so.cache", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(ls, "/usr/lib/libcap.so.2", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(ls, "/usr/lib/libc.so.6", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(ls, "/usr/lib/locale/locale-archive", FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(ls, '/proc', FS_ACCESS.EXEC)
    Commands.add_fs_rule(ls, '/tmp/bpfbox', FS_ACCESS.READ | FS_ACCESS.GETATTR)
    Commands.add_fs_rule(ls, '/tmp/bpfbox/a', FS_ACCESS.GETATTR)
    Commands.add_fs_rule(ls, '/tmp/bpfbox/b', FS_ACCESS.GETATTR)
    Commands.add_fs_rule(ls, '/tmp/bpfbox/c', FS_ACCESS.GETATTR)
    Commands.add_fs_rule(ls, '/tmp/bpfbox/d', FS_ACCESS.GETATTR)

    out = subprocess.check_output([ls, '/tmp/bpfbox']).decode('utf-8')
    assert out.strip() == '\n'.join(sorted(os.listdir('/tmp/bpfbox')))
