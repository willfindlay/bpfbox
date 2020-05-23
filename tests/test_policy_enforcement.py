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
from bpfbox.rules import AccessMode
from bpfbox.utils import get_inode_and_device
from bpfbox import defs

DRIVERPATH = os.path.join(defs.project_path, 'tests/driver')
POLICY = BPFBoxLoggerClass.POLICY


@pytest.fixture()
def bpfboxd(caplog):
    caplog.set_level(POLICY, 'ebpH')
    args = parse_args('--nodaemon'.split())
    defs.init(args)
    b = BPFBoxd(args)
    yield b


def test_fs_implicit_taint(bpfboxd: BPFBoxd, caplog):
    p = Policy(os.path.join(DRIVERPATH, 'open'))
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(os.path.join(DRIVERPATH, "open")).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    # Capture the policy log message
    records = [r for r in caplog.records if r.levelname == 'POLICY']
    assert len(records) == 1

    # Make sure we enforced on the correct access
    inode, device = get_inode_and_device('/etc/ld.so.cache')
    assert f'inode={inode}' in records[0].message
    assert f'st_dev={device}' in records[0].message

    assert rc == -9


def test_fs_taint(bpfboxd: BPFBoxd, caplog):
    p = Policy(os.path.join(DRIVERPATH, 'open'))
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)

    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()
    rc = subprocess.Popen(os.path.join(DRIVERPATH, "open")).wait()

    assert rc == -9
