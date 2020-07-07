import logging

import pytest

from bpfbox.argument_parser import parse_args
from bpfbox.bpf_program import BPFProgram
from bpfbox.logger import BPFBoxLoggerClass
from bpfbox import defs

AUDIT = BPFBoxLoggerClass.AUDIT
DEBUG = logging.DEBUG

# Load BPF program
args = parse_args('--nodaemon --debug'.split())
defs.init(args)
b = BPFProgram(enforcing=True, debug=True)
b.load_bpf()


@pytest.fixture(scope='function')
def bpf_program(caplog):
    # Set log level
    caplog.set_level(DEBUG)

    yield b

    b.bpf.ring_buffer_consume()

    # Clear all maps
    b.bpf['processes'].clear()
    b.bpf['profiles'].clear()
    b.bpf['fs_policy'].clear()
    b.bpf['procfs_policy'].clear()
    b.bpf['ipc_policy'].clear()
    # IMPORTANT NOTE: remember to put new maps here

    b.profile_key_to_exe.clear()
