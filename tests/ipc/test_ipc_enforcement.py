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
from bpfbox.flags import BPFBOX_ACTION, IPC_ACCESS
from bpfbox import defs

DRIVER_PATH = os.path.join(defs.project_path, 'tests/driver')
IPC_PATH = os.path.join(DRIVER_PATH, 'ipc')

def test_ipc_no_taint(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(IPC_PATH, False)

    rc = subprocess.Popen([IPC_PATH, 'kill-self']).wait()
    assert rc == -signal.SIGKILL

def test_ipc_kill_self(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    rc = subprocess.Popen([IPC_PATH, 'kill-self']).wait()
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGKILL)
    rc = subprocess.Popen([IPC_PATH, 'kill-self']).wait()
    assert rc == -signal.SIGKILL

@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_ipc_kill_target(bpf_program: BPFProgram, caplog):
    sleep_path = which('sleep')
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'kill-target', str(target_pid)]).wait()
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, sleep_path, IPC_ACCESS.SIGKILL)
    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'kill-target', str(target_pid)]).wait()
    assert rc == 0


def test_ipc_check_self(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    rc = subprocess.Popen([IPC_PATH, 'check-self']).wait()
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK)
    rc = subprocess.Popen([IPC_PATH, 'check-self']).wait()
    assert rc == 0

@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_ipc_check_target(bpf_program: BPFProgram, caplog):
    sleep_path = which('sleep')
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'check-target', str(target_pid)]).wait()
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, sleep_path, IPC_ACCESS.SIGCHECK)
    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'check-target', str(target_pid)]).wait()
    assert rc == 0


def test_ipc_stop_self(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    p = subprocess.Popen([IPC_PATH, 'stop-self'])
    try:
        rc = p.wait(1)
    except subprocess.TimeoutExpired:
        os.kill(p.pid, signal.SIGCONT)
        rc = p.wait(1)
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGSTOP)
    p = subprocess.Popen([IPC_PATH, 'stop-self'])
    try:
        rc = p.wait(1)
    except subprocess.TimeoutExpired:
        os.kill(p.pid, signal.SIGCONT)
        rc = p.wait(1)
    assert rc == 0

@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_ipc_stop_target(bpf_program: BPFProgram, caplog):
    sleep_path = which('sleep')
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'stop-target', str(target_pid)]).wait()
    try:
        os.kill(target_pid, signal.SIGCONT)
    except:
        pass
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, sleep_path, IPC_ACCESS.SIGSTOP)
    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'stop-target', str(target_pid)]).wait()
    try:
        os.kill(target_pid, signal.SIGCONT)
    except:
        pass
    assert rc == 0


def test_ipc_chld_self(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    rc = subprocess.Popen([IPC_PATH, 'chld-self']).wait()
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHLD)
    rc = subprocess.Popen([IPC_PATH, 'chld-self']).wait()
    assert rc == 0

@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_ipc_chld_target(bpf_program: BPFProgram, caplog):
    sleep_path = which('sleep')
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'chld-target', str(target_pid)]).wait()
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, sleep_path, IPC_ACCESS.SIGCHLD)
    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'chld-target', str(target_pid)]).wait()
    assert rc == 0


def test_ipc_usr1_self(bpf_program: BPFProgram, caplog):
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    rc = subprocess.Popen([IPC_PATH, 'usr1-self']).wait()
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGMISC)
    rc = subprocess.Popen([IPC_PATH, 'usr1-self']).wait()
    assert rc == -signal.SIGUSR1

@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_ipc_usr1_target(bpf_program: BPFProgram, caplog):
    sleep_path = which('sleep')
    bpf_program.add_profile(IPC_PATH, False)
    bpf_program.add_ipc_rule(IPC_PATH, IPC_PATH, IPC_ACCESS.SIGCHECK, BPFBOX_ACTION.TAINT)

    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'usr1-target', str(target_pid)]).wait()
    assert rc == 1

    bpf_program.add_ipc_rule(IPC_PATH, sleep_path, IPC_ACCESS.SIGMISC)
    target_pid = subprocess.Popen([sleep_path, '10']).pid
    rc = subprocess.Popen([IPC_PATH, 'usr1-target', str(target_pid)]).wait()
    assert rc == 0
