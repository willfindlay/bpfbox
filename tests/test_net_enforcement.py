import subprocess
import pytest
import os
import signal
import logging
import time

from bpfbox.argument_parser import parse_args
from bpfbox.bpfboxd import BPFBoxd
from bpfbox.logger import BPFBoxLoggerClass
from bpfbox.policy import Policy
from bpfbox.utils import get_inode_and_device
from bpfbox import defs

DRIVERPATH = os.path.join(defs.project_path, 'tests/driver')
NETPATH = os.path.join(DRIVERPATH, 'networking')
POLICY = BPFBoxLoggerClass.POLICY


@pytest.fixture()
def bpfboxd(caplog):
    # Set log level
    caplog.set_level(POLICY, 'ebpH')

    # Load BPF program
    args = parse_args('--nodaemon'.split())
    defs.init(args)
    b = BPFBoxd(args)

    yield b

    # Clean up BPF program
    b.cleanup()


def test_it_works(bpfboxd: BPFBoxd, caplog):
    assert 1 + 1 == 2
