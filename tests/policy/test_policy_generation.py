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
from bpfbox.dsl import PolicyGenerator
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
def policy_generator(bpf_program: BPFProgram):
    yield PolicyGenerator()


def test_open_complex_policy_no_execute_permission(policy_generator: PolicyGenerator, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', r)

    #[allow] {
        fs('/tmp/bpfbox/a', rw)
        fs('/tmp/bpfbox/b', a)
        fs('/tmp/bpfbox/c', r)
    }

    """ % (OPEN_PATH)

    policy_generator.process_policy_text(text)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'complex'])


def test_open_complex_policy(policy_generator: PolicyGenerator, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', r)

    #[allow] {
        fs('/tmp/bpfbox/a', rw)
        fs('/tmp/bpfbox/b', a)
        fs('/tmp/bpfbox/c', r)
        fs('/tmp/bpfbox/d', x)
    }

    """ % (OPEN_PATH)

    policy_generator.process_policy_text(text)

    subprocess.check_call([OPEN_PATH, 'complex'])


def test_open_complex_policy_implicit_allow(policy_generator: PolicyGenerator, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', r)

    fs('/tmp/bpfbox/a', rw)
    fs('/tmp/bpfbox/b', a)
    fs('/tmp/bpfbox/c', r)
    fs('/tmp/bpfbox/d', x)

    """ % (OPEN_PATH)

    policy_generator.process_policy_text(text)

    subprocess.check_call([OPEN_PATH, 'complex'])


def test_open_link_policy(policy_generator: PolicyGenerator, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', r)

    fs('/tmp/bpfbox', w)
    fs('/tmp/bpfbox/a', l)

    """ % (OPEN_PATH)

    policy_generator.process_policy_text(text)

    subprocess.check_call([OPEN_PATH, 'link'])


def test_open_implicit_taint(policy_generator: PolicyGenerator, setup_testdir):
    text = """
    #![profile '%s']
    """ % (OPEN_PATH)

    policy_generator.process_policy_text(text)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_output([OPEN_PATH])


@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_ipc_policy(policy_generator: PolicyGenerator, setup_testdir):
    sleep_path = which('sleep')
    text = """
    #![profile '%s']

    #[taint]
    signal(self, sigcheck)

    signal('%s', sigkill)
    """ % (IPC_PATH, sleep_path)

    policy_generator.process_policy_text(text)

    target_pid = subprocess.Popen([sleep_path, '10']).pid

    rc = subprocess.Popen([IPC_PATH, 'kill-target', str(target_pid)]).wait()
    assert rc == 0


@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_open_procfs_rules(policy_generator: PolicyGenerator, setup_testdir):
    sleep_path = which('sleep')

    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', r)

    fs('/proc', x)
    proc('%s', rx)
    """ % (OPEN_PATH, sleep_path)

    policy_generator.process_policy_text(text)

    # /proc/self should always work
    subprocess.check_call([OPEN_PATH, 'proc-self'])

    sleep_pid = subprocess.Popen([sleep_path, '10']).pid
    subprocess.check_call([OPEN_PATH, 'proc-other', str(sleep_pid)])


@pytest.mark.skipif(not which('sleep'), reason='sleep not found on system')
def test_open_proc_other_not_allowed(policy_generator: PolicyGenerator, setup_testdir):
    sleep_path = which('sleep')

    text = """
    #![profile '%s']

    #[taint]
    fs('/tmp/bpfbox/a', r)

    fs('/proc', x)
    """ % (OPEN_PATH)

    policy_generator.process_policy_text(text)

    # /proc/self should always work
    subprocess.check_call([OPEN_PATH, 'proc-self'])

    sleep_pid = subprocess.Popen([sleep_path, '10']).pid
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([OPEN_PATH, 'proc-other', str(sleep_pid)])

@pytest.mark.skipif(not which('ls'), reason='ls not found on system')
def test_ls(policy_generator: PolicyGenerator, setup_testdir):
    ls = which('ls')

    text = """
    #![profile '%s']

    fs('/etc/ld.so.cache', rg)
    fs('/usr/lib/libcap.so.2', rg)
    fs('/usr/lib/libc.so.6', rg)
    fs('/usr/lib/locale/locale-archive', rg)
    fs('/usr/share', x)
    fs('/proc', x)
    fs('/tmp/bpfbox', rxg)
    fs('/tmp/bpfbox/a', g)
    fs('/tmp/bpfbox/b', g)
    fs('/tmp/bpfbox/c', g)
    fs('/tmp/bpfbox/d', g)
    proc('/usr/bin/ls', g)
    """ % (ls)

    policy_generator.process_policy_text(text)

    out = subprocess.check_output([ls, '/tmp/bpfbox']).decode('utf-8')
    assert out.strip() == '\n'.join(sorted(os.listdir('/tmp/bpfbox')))

def test_fs_policy_missing_file(policy_generator: PolicyGenerator, setup_testdir):

    text = """
    #![profile '%s']

    fs('/sdfoihsdfo/asdihsdfoui/asdpisdhf', rwx)
    proc('/sdfoihsdfo/asdihsdfoui/asdpisdhf', g)
    """ % (OPEN_PATH)

    policy_generator.process_policy_text(text)

def test_net_policy_smoke(policy_generator: PolicyGenerator, setup_testdir):
    text = """
    #![profile '%s']

    #[taint] {
        net(inet,  bind)
        net(inet6, bind)
        net(inet,  connect)
        net(inet6, connect)
    }

    #[allow] {
        net(inet,  accept)
        net(inet6, accept)
        net(inet,  listen)
        net(inet6, listen)
        net(inet,  send)
        net(inet6, send)
        net(inet,  recv)
        net(inet6, recv)
    }

    #[audit] {
        net(inet,  create)
        net(inet6, create)
        net(inet,  shutdown)
        net(inet6, shutdown)
    }
    """ % (NET_PATH)

    policy_generator.process_policy_text(text)

def test_net_policy(policy_generator: PolicyGenerator, setup_testdir):
    text = """
    #![profile '%s']

    #[taint]
    net(inet,  create)

    #[allow] {
        net(inet6, create)
        net(inet6, connect)
    }
    """ % (NET_PATH)

    policy_generator.process_policy_text(text)

    subprocess.check_call([NET_PATH, 'inet-create-and-connect'])

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([NET_PATH, 'create-unix'])
