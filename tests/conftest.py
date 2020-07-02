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

    # Clean up BPF program
    b.bpf.ring_buffer_consume()
    b._soft_cleanup()
