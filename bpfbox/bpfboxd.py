import time

from bcc import BPF

from bpfbox import defs

class BPFBoxd:
    """
    BPFBox's daemon class.
    Manages BPF programs and reads events in an event loop.
    """
    def __init__(self, args):
        self.bpf = None
        self.ticksleep = defs.ticksleep

        self.init_bpf()

    def init_bpf(self):
        """
        Initialize BPF program.
        """
        assert self.bpf is None
        # Read BPF program
        with open(defs.bpf_prog_path, 'r') as f:
            text = f.read()
        # Set flags
        flags = []
        flags.append(f'-I{defs.project_path}/bpfbox/bpf')
        self.bpf = BPF(text=text, cflags=flags)

    def loop_forever(self):
        """
        BPFBoxd main event loop.
        """
        while 1:
            time.sleep(self.ticksleep)

def main(args):
    """
    Main entrypoint for BPFBox daemon.
    Generally should be invoked with parse_args.
    """
    b = BPFBoxd(args)
    b.loop_forever()
