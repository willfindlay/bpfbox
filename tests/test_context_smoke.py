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
CONTEXT_SMOKE_PATH = os.path.join(DRIVERPATH, 'context_smoke')
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


def test_context_sym_smoke(bpfboxd: BPFBoxd, caplog):
    p = Policy(CONTEXT_SMOKE_PATH)
    p.add_rule_context(sym='main')
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(CONTEXT_SMOKE_PATH).wait()

    assert rc == -9


def test_context_allow_many_context_smoke(bpfboxd: BPFBoxd, caplog):
    p = Policy(CONTEXT_SMOKE_PATH)
    p.add_rule_context(sym='main').fs_taint(
        '/tmp/bpfbox/a', AccessMode.MAY_READ
    )
    p.add_rule_context(sym='testificate_a').fs_allow(
        '/tmp/bpfbox/a', AccessMode.MAY_READ
    )
    p.add_rule_context(sym='testificate_b').fs_allow(
        '/tmp/bpfbox/b', AccessMode.MAY_READ
    )
    p.add_rule_context(sym='testificate_c').fs_allow(
        '/tmp/bpfbox/c', AccessMode.MAY_READ
    )
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(CONTEXT_SMOKE_PATH).wait()

    assert rc == 0


def test_context_allow_wrong_context_smoke(bpfboxd: BPFBoxd, caplog):
    p = Policy(CONTEXT_SMOKE_PATH)
    p.add_rule_context(sym='main').fs_taint(
        '/tmp/bpfbox/a', AccessMode.MAY_READ
    )
    p.add_rule_context(sym='testificate_b').fs_allow(
        '/tmp/bpfbox/a', AccessMode.MAY_READ
    )
    p.add_rule_context(sym='testificate_b').fs_allow(
        '/tmp/bpfbox/b', AccessMode.MAY_READ
    )
    p.add_rule_context(sym='testificate_c').fs_allow(
        '/tmp/bpfbox/c', AccessMode.MAY_READ
    )
    bpfboxd.policy.append(p)
    bpfboxd.load_bpf()

    rc = subprocess.Popen(CONTEXT_SMOKE_PATH).wait()

    assert rc == -9
