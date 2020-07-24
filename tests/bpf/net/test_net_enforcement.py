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
from bpfbox.flags import BPFBOX_ACTION, NET_ACCESS, NET_FAMILY
from bpfbox import defs
from bpfbox.libbpfbox import Commands

DRIVER_PATH = os.path.join(defs.project_path, 'tests/driver')
NET_PATH = os.path.join(DRIVER_PATH, 'net')

def test_net_no_taint(bpf_program: BPFProgram, caplog):
    Commands.add_profile(NET_PATH, False)

    subprocess.check_call([NET_PATH, 'create-inet6'])


def test_net_taint(bpf_program: BPFProgram, caplog):
    Commands.add_profile(NET_PATH, False)
    Commands.add_net_rule(NET_PATH, NET_ACCESS.CREATE, NET_FAMILY.INET, BPFBOX_ACTION.TAINT)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([NET_PATH, 'create-inet6'])


def test_net_create_rules(bpf_program: BPFProgram, caplog):
    Commands.add_profile(NET_PATH, False)
    Commands.add_net_rule(NET_PATH, NET_ACCESS.CREATE, NET_FAMILY.INET, BPFBOX_ACTION.TAINT)

    # Creating an INET6 socket should fail
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([NET_PATH, 'create-inet6'])

    # Creating a UNIX socket should fail
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([NET_PATH, 'create-unix'])

    # Allow the creation of an INET6 socket
    Commands.add_net_rule(NET_PATH, NET_ACCESS.CREATE, NET_FAMILY.INET6, BPFBOX_ACTION.ALLOW)

    # Creating an INET6 socket should succeed
    subprocess.check_call([NET_PATH, 'create-inet6'])

    # Creating a UNIX socket should still fail
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([NET_PATH, 'create-unix'])

    # Allow the creation of a UNIX socket
    Commands.add_net_rule(NET_PATH, NET_ACCESS.CREATE, NET_FAMILY.UNIX, BPFBOX_ACTION.ALLOW)

    # Both should now succeed
    subprocess.check_call([NET_PATH, 'create-inet6'])
    subprocess.check_call([NET_PATH, 'create-unix'])


def test_net_connect_rules(bpf_program: BPFProgram, caplog):
    Commands.add_profile(NET_PATH, False)
    Commands.add_net_rule(NET_PATH, NET_ACCESS.CREATE, NET_FAMILY.INET, BPFBOX_ACTION.TAINT)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([NET_PATH, 'inet-create-and-connect'])

    Commands.add_net_rule(NET_PATH, NET_ACCESS.CREATE, NET_FAMILY.INET6, BPFBOX_ACTION.ALLOW)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([NET_PATH, 'inet-create-and-connect'])

    Commands.add_net_rule(NET_PATH, NET_ACCESS.CONNECT, NET_FAMILY.INET6, BPFBOX_ACTION.ALLOW)

    subprocess.check_call([NET_PATH, 'inet-create-and-connect'])


def test_net_socketpair(bpf_program: BPFProgram, caplog):
    Commands.add_profile(NET_PATH, False)
    Commands.add_net_rule(NET_PATH, NET_ACCESS.CREATE, NET_FAMILY.INET, BPFBOX_ACTION.TAINT)

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.check_call([NET_PATH, 'create-unix-socketpair'])

    Commands.add_net_rule(NET_PATH, NET_ACCESS.CREATE, NET_FAMILY.UNIX, BPFBOX_ACTION.ALLOW)

    subprocess.check_call([NET_PATH, 'create-unix-socketpair'])
