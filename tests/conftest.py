import logging

import pytest

from bpfbox.argument_parser import parse_args
from bpfbox.bpf_program import BPFProgram
from bpfbox.logger import BPFBoxLoggerClass
from bpfbox import defs

AUDIT = BPFBoxLoggerClass.AUDIT
DEBUG = logging.DEBUG


@pytest.fixture(scope='function')
def bpf_program(caplog):
    # Set log level
    caplog.set_level(DEBUG)

    # Load BPF program
    args = parse_args('--nodaemon --debug'.split())
    defs.init(args)
    b = BPFProgram(enforcing=True, debug=True)
    b.load_bpf()

    yield b

    # Clean up BPF program
    b.bpf.ring_buffer_consume()
    b.cleanup()
