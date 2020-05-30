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
OPENPATH = os.path.join(DRIVERPATH, 'open')
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


def test_fs_implicit_taint(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()

    assert rc == -9


def test_fs_taint(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    assert rc == -9

    # Capture the policy log message
    records = [r for r in caplog.records if r.levelname == 'POLICY']
    assert len(records) == 1

    # Make sure we enforced on the correct access
    inode, device = get_inode_and_device('/tmp/bpfbox/a')
    assert f'inode={inode}' in records[0].message
    assert f'st_dev={device}' in records[0].message


def test_allow_read(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/a', AccessMode.MAY_READ)
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    assert rc == -9

    # Capture the policy log message
    records = [r for r in caplog.records if r.levelname == 'POLICY']
    assert len(records) == 1

    # Make sure we enforced on the correct access
    inode, device = get_inode_and_device('/tmp/bpfbox/b')
    assert f'inode={inode}' in records[0].message
    assert f'st_dev={device}' in records[0].message


def test_allow_write(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/b', AccessMode.MAY_WRITE)
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    assert rc == -9

    # Capture the policy log message
    records = [r for r in caplog.records if r.levelname == 'POLICY']
    assert len(records) == 1

    # Make sure we enforced on the correct access
    inode, device = get_inode_and_device('/tmp/bpfbox/c')
    assert f'inode={inode}' in records[0].message
    assert f'st_dev={device}' in records[0].message


def test_rw_when_rdonly_allowed(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/b', AccessMode.MAY_WRITE)
    p.fs_allow('/tmp/bpfbox/c', AccessMode.MAY_READ)
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    assert rc == -9

    # Capture the policy log message
    records = [r for r in caplog.records if r.levelname == 'POLICY']
    assert len(records) == 1

    # Make sure we enforced on the correct access
    inode, device = get_inode_and_device('/tmp/bpfbox/c')
    assert f'inode={inode}' in records[0].message
    assert f'st_dev={device}' in records[0].message


def test_rw_when_wronly_allowed(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/b', AccessMode.MAY_WRITE)
    p.fs_allow('/tmp/bpfbox/c', AccessMode.MAY_WRITE)
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    assert rc == -9

    # Capture the policy log message
    records = [r for r in caplog.records if r.levelname == 'POLICY']
    assert len(records) == 1

    # Make sure we enforced on the correct access
    inode, device = get_inode_and_device('/tmp/bpfbox/c')
    assert f'inode={inode}' in records[0].message
    assert f'st_dev={device}' in records[0].message


def test_allow_rw(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/b', AccessMode.MAY_WRITE)
    p.fs_allow('/tmp/bpfbox/c', AccessMode.MAY_READ | AccessMode.MAY_WRITE)
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    assert rc == -9

    # Capture the policy log message
    records = [r for r in caplog.records if r.levelname == 'POLICY']
    assert len(records) == 1

    # Make sure we enforced on the correct access
    inode, device = get_inode_and_device('/tmp/bpfbox/a')
    assert f'inode={inode}' in records[0].message
    assert f'st_dev={device}' in records[0].message


def test_allow_append(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/b', AccessMode.MAY_WRITE)
    p.fs_allow('/tmp/bpfbox/c', AccessMode.MAY_READ | AccessMode.MAY_WRITE)
    p.fs_allow('/tmp/bpfbox/a', AccessMode.MAY_WRITE | AccessMode.MAY_APPEND)
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    assert rc == -9

    # Capture the policy log message
    records = [r for r in caplog.records if r.levelname == 'POLICY']
    assert len(records) == 1

    # Make sure we enforced on the correct access
    inode, device = get_inode_and_device('/tmp/bpfbox/d')
    assert f'inode={inode}' in records[0].message
    assert f'st_dev={device}' in records[0].message


def test_allow_exec(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow('/tmp/bpfbox/b', AccessMode.MAY_WRITE)
    p.fs_allow('/tmp/bpfbox/c', AccessMode.MAY_READ | AccessMode.MAY_WRITE)
    p.fs_allow('/tmp/bpfbox/a', AccessMode.MAY_WRITE | AccessMode.MAY_APPEND)
    p.fs_allow('/tmp/bpfbox/d', AccessMode.MAY_READ | AccessMode.MAY_EXEC)
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    assert rc == 0


def test_extra_access_modes(bpfboxd: BPFBoxd, caplog):
    p = Policy(OPENPATH)
    p.fs_taint('/tmp/bpfbox/a', AccessMode.MAY_READ)
    p.fs_allow(
        '/tmp/bpfbox/a',
        AccessMode.MAY_READ
        | AccessMode.MAY_WRITE
        | AccessMode.MAY_APPEND
        | AccessMode.MAY_EXEC,
    )
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(OPENPATH).wait()
    bpfboxd.bpf.perf_buffer_poll(20)

    assert rc == -9

    # Capture the policy log message
    records = [r for r in caplog.records if r.levelname == 'POLICY']
    assert len(records) == 1

    # Make sure we enforced on the correct access
    inode, device = get_inode_and_device('/tmp/bpfbox/b')
    assert f'inode={inode}' in records[0].message
    assert f'st_dev={device}' in records[0].message
