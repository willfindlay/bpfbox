import pytest

from bpfbox.argument_parser import parse_args
from bpfbox.bpf_program import BPFProgram
from bpfbox.logger import BPFBoxLoggerClass
from bpfbox import defs

AUDIT = BPFBoxLoggerClass.AUDIT


@pytest.fixture(scope='function')
def bpf_program(caplog):
    # Set log level
    caplog.set_level(AUDIT)

    # Load BPF program
    args = parse_args('--nodaemon'.split())
    defs.init(args)
    b = BPFProgram(enforcing=True, debug=True)
    b.load_bpf()

    yield b

    # Clean up BPF program
    b.bpf.ring_buffer_consume()
    b.cleanup()
