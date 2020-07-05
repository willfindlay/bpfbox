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
from bpfbox import defs

DRIVER_PATH = os.path.join(defs.project_path, 'tests/driver')
SILLY_PATH = os.path.join(DRIVER_PATH, 'silly_program')

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
    yield PolicyGenerator(bpf_program)


@pytest.mark.xfail(reason='Not yet implemented')
def test_silly_program_policy_smoke(policy_generator: PolicyGenerator, setup_testdir):
    text = """
    #![profile '%s']
    """ % (SILLY_PATH)

    subprocess.check_output([SILLY_PATH])