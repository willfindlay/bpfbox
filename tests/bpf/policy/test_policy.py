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

    Tests bpfbox's policy DSL and policy generation therein.

    2020-Jul-04  William Findlay  Created this.
"""

import subprocess
import pytest
import os
import signal
import logging
import time
from shutil import rmtree

from bpfbox.bpf_program import BPFProgram
from bpfbox.dsl import PolicyParser
from bpfbox.utils import which
from bpfbox import defs

DRIVER_PATH = os.path.join(defs.project_path, 'tests/driver')
OPEN_PATH = os.path.join(DRIVER_PATH, 'open')
IPC_PATH = os.path.join(DRIVER_PATH, 'ipc')
NET_PATH = os.path.join(DRIVER_PATH, 'net')

@pytest.fixture
def setup_testdir():
    rmtree('/tmp/bpfbox', ignore_errors=True)
    os.mkdir('/tmp/bpfbox')
    open('/tmp/bpfbox/a', 'a').close()
    open('/tmp/bpfbox/b', 'a').close()
    open('/tmp/bpfbox/c', 'a').close()
    open('/tmp/bpfbox/d', 'a').close()
    os.chmod('/tmp/bpfbox/d', 0o755)

@pytest.fixture
def policy_parser(bpf_program: BPFProgram):
    yield PolicyParser()


def test_open_complex_policy_no_execute_permission(policy_parser: PolicyParser, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', read)

    #[allow] {
        fs('/tmp/bpfbox/a', read|write)
        fs('/tmp/bpfbox/b', append)
        fs('/tmp/bpfbox/c', read)
    }

    """ % (OPEN_PATH)

    policy_parser.process_policy_text(text)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'complex'])


def test_open_complex_policy(policy_parser: PolicyParser, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', read)

    #[allow] {
        fs('/tmp/bpfbox/a', read|write)
        fs('/tmp/bpfbox/b', append)
        fs('/tmp/bpfbox/c', read)
        fs('/tmp/bpfbox/d', exec)
    }

    """ % (OPEN_PATH)

    policy_parser.process_policy_text(text)

    subprocess.check_call([OPEN_PATH, 'complex'])


def test_open_complex_policy_implicit_allow(policy_parser: PolicyParser, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', read)

    fs('/tmp/bpfbox/a', read|write)
    fs('/tmp/bpfbox/b', append)
    fs('/tmp/bpfbox/c', read)
    fs('/tmp/bpfbox/d', exec)

    """ % (OPEN_PATH)

    policy_parser.process_policy_text(text)

    subprocess.check_call([OPEN_PATH, 'complex'])


def test_open_link_policy(policy_parser: PolicyParser, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', read)

    fs('/tmp/bpfbox', write)
    fs('/tmp/bpfbox/a', link)

    """ % (OPEN_PATH)

    policy_parser.process_policy_text(text)

    subprocess.check_call([OPEN_PATH, 'link'])


def test_open_implicit_taint(policy_parser: PolicyParser, setup_testdir):
    text = """
    #![profile '%s']
    """ % (OPEN_PATH)

    policy_parser.process_policy_text(text)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_output([OPEN_PATH])


@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_ipc_policy(policy_parser: PolicyParser, setup_testdir):
    sleep_path = which('sleep')
    text = """
    #![profile '%s']

    #[taint]
    signal(self, sigcheck)

    signal('%s', sigkill)
    """ % (IPC_PATH, sleep_path)

    policy_parser.process_policy_text(text)

    target_pid = subprocess.Popen([sleep_path, '10']).pid

    rc = subprocess.Popen([IPC_PATH, 'kill-target', str(target_pid)]).wait()
    assert rc == 0


@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_open_procfs_rules(policy_parser: PolicyParser, setup_testdir):
    sleep_path = which('sleep')

    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', read)

    fs('/proc', exec)
    proc('%s', read|exec)
    """ % (OPEN_PATH, sleep_path)

    policy_parser.process_policy_text(text)

    # /proc/self should always work
    subprocess.check_call([OPEN_PATH, 'proc-self'])

    sleep_pid = subprocess.Popen([sleep_path, '10']).pid
    subprocess.check_call([OPEN_PATH, 'proc-other', str(sleep_pid)])


@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_open_proc_other_not_allowed(policy_parser: PolicyParser, setup_testdir):
    sleep_path = which('sleep')

    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', read)

    fs('/proc', exec)
    """ % (OPEN_PATH)

    policy_parser.process_policy_text(text)

    # /proc/self should always work
    subprocess.check_call([OPEN_PATH, 'proc-self'])

    sleep_pid = subprocess.Popen([sleep_path, '10']).pid
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'proc-other', str(sleep_pid)])

@pytest.xfail('Need to update ls policy to be more generic')
@pytest.mark.skipif(not which('ls'), reason='ls not found on system')
def test_ls(policy_parser: PolicyParser, setup_testdir):
    ls = which('ls')

    text = """
    #![profile '%s']

    fs('%s', read|exec)
    fs('/etc/ld.so.cache', read|exec|getattr)
    fs('/usr/lib/ld-2.31.so', read|exec|getattr)
    fs('/lib64/ld-linux-x86-64.so.2', read)
    fs('/usr/lib/libcap.so.2', read|exec|getattr)
    fs('/usr/lib/libc.so.6', read|exec|getattr)
    fs('/usr/lib/locale/locale-archive', read|getattr)
    fs('/usr/share', exec)
    fs('/proc', exec)
    fs('/tmp/bpfbox', read|exec|getattr)
    fs('/tmp/bpfbox/a', getattr)
    fs('/tmp/bpfbox/b', getattr)
    fs('/tmp/bpfbox/c', getattr)
    fs('/tmp/bpfbox/d', getattr)
    proc('/usr/bin/ls', getattr)
    """ % (ls, ls)

    policy_parser.process_policy_text(text)

    out = subprocess.check_output([ls, '/tmp/bpfbox']).decode('utf-8')
    assert out.strip() == '\n'.join(sorted(os.listdir('/tmp/bpfbox')))

def test_fs_policy_missing_file(policy_parser: PolicyParser, setup_testdir):

    text = """
    #![profile '%s']

    fs('/sdfoihsdfo/asdihsdfoui/asdpisdhf', read|write|exec)
    proc('/sdfoihsdfo/asdihsdfoui/asdpisdhf', getattr)
    """ % (OPEN_PATH)

    policy_parser.process_policy_text(text)

def test_net_policy_smoke(policy_parser: PolicyParser, setup_testdir):
    text = """
    #![profile '%s']

    #[taint] {
        net(inet,  bind|connect)
        net(inet6, bind|connect)
    }

    #[allow] {
        net(inet,  accept|listen|send|recv)
        net(inet6, accept|listen|send|recv)
    }

    #[audit] {
        net(inet,  create|shutdown)
        net(inet6, create|shutdown)
    }
    """ % (NET_PATH)

    policy_parser.process_policy_text(text)

def test_net_policy(policy_parser: PolicyParser, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    net(inet,  create)

    #[allow] {
        net(inet6, create|connect)
    }
    """ % (NET_PATH)

    policy_parser.process_policy_text(text)

    subprocess.check_call([NET_PATH, 'inet-create-and-connect'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([NET_PATH, 'create-unix'])
