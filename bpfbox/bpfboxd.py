import os, sys
import atexit
import signal
import time

from bcc import BPF

from bpfbox import defs
from bpfbox.daemon_mixin import DaemonMixin

signal.signal(signal.SIGTERM, lambda x,y: sys.exit(0))
signal.signal(signal.SIGINT, lambda x,y: sys.exit(0))

class BPFBoxd(DaemonMixin):
    """
    BPFBox's daemon class.
    Manages BPF programs and reads events in an event loop.
    """
    def __init__(self, args):
        self.bpf = None
        self.ticksleep = defs.ticksleep

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
        flags.append(f'-I{defs.project_path}')
        self.bpf = BPF(text=text, cflags=flags)
        atexit.register(self.cleanup)

    def write_profile_data_to_disk(self):
        pass

    def cleanup(self):
        """
        Perform cleanup hooks before exit.
        """
        # FIXME: delete this, for testing purposes
        for profile in self.bpf['profiles'].values():
            print(f'{profile.comm.decode("utf-8")} has tail call index {profile.tail_call_index}')
        self.write_profile_data_to_disk()
        self.bpf = None

    def loop_forever(self):
        """
        BPFBoxd main event loop.
        """
        self.init_bpf()
        while 1:
            time.sleep(self.ticksleep)

def main(args):
    """
    Main entrypoint for BPFBox daemon.
    Generally should be invoked with parse_args.
    """
    defs.init()
    b = BPFBoxd(args)

    if args.nodaemon:
        print('Starting in foreground mode...', file=sys.stderr)
        b.loop_forever()
        sys.exit(0)

    if args.operation == 'start':
        b.start_daemon()
    if args.operation == 'stop':
        try:
            b.stop_daemon()
        except DaemonNotRunningError:
            print('pidfile for bpfboxd is empty. If the daemon is still running, '
                  'you may need to kill manually.', file=sys.stderr)
    if args.operation == 'restart':
        b.restart_daemon()
