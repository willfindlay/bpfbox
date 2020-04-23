import os, sys
import atexit
import signal
import time
import ctypes as ct

from bcc import BPF

from bpfbox import defs
from bpfbox.daemon_mixin import DaemonMixin, DaemonNotRunningError
from bpfbox.logger import get_logger
from bpfbox.utils import syscall_name
from bpfbox.bpf import structs
from bpfbox.rules import Rules

logger = get_logger()

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
        self.enforcing = args.enforcing
        # Set flags
        self.flags = []
        self.flags.append(f'-I{defs.project_path}')
        if self.enforcing:
            self.flags.append(f'-DBPFBOX_ENFORCING')

    def load_bpf(self):
        """
        Initialize BPF program.
        """
        assert self.bpf is None
        # Read BPF program
        with open(defs.bpf_prog_path, 'r') as f:
            source = f.read()
        # Load the bpf program
        self.bpf = BPF(text=source, cflags=self.flags)
        # Register exit hooks
        atexit.register(self.cleanup)
        # Register perf buffers
        self.register_perf_buffers()

    def register_perf_buffers(self):
        """
        Define and register perf buffers.
        """
        # FIXME: get rid of this, just for testing
        def on_profile_create(cpu, data, size):
            event = self.bpf['on_profile_create'].event(data)
            if event.comm == b'ls':
                ls_rules = Rules(self.bpf, self.flags)
                ls_rules.generate(event)
        self.bpf['on_profile_create'].open_perf_buffer(on_profile_create)

        # Policy enforcement event
        def on_enforcement(cpu, data, size):
            event = self.bpf['on_enforcement'].event(data)
            enforcement = 'Enforcing' if self.enforcing else 'Would have enforced'
            try:
                profile = self.bpf['profiles'][ct.c_uint64(event.profile_key)]
            except KeyError:
                profile = structs.BPFBoxProfileStruct()
                profile.comm = b'UNKNOWN'
            logger.policy(f'{enforcement} on {syscall_name(event.syscall)} in PID {event.pid} ({profile.comm.decode("utf-8")})')
        self.bpf['on_enforcement'].open_perf_buffer(on_enforcement)

    def save_profiles(self):
        """
        Write all profile data to disk.
        """
        pass

    def save_profile(self):
        """
        Save one profile's data to disk.
        """

    def load_profiles(self):
        """
        Load all profile data from disk.
        """
        pass

    def load_profile(self):
        """
        Load one profile's data from disk.
        """

    def dump_debug_data(self):
        import logging
        if not logger.level == logging.DEBUG:
            return
        for profile in sorted(self.bpf['profiles'].values(), key=lambda p: p.tail_call_index):
            logger.debug(f'{profile.comm.decode("utf-8")} has tail call index {profile.tail_call_index}')

    def cleanup(self):
        """
        Perform cleanup hooks before exit.
        """
        self.dump_debug_data()
        self.save_profiles()
        self.bpf = None

    def loop_forever(self):
        """
        BPFBoxd main event loop.
        """
        self.load_bpf()
        while 1:
            self.bpf.perf_buffer_poll(30)
            time.sleep(self.ticksleep)

def main(args):
    """
    Main entrypoint for BPFBox daemon.
    Generally should be invoked with parse_args.
    """
    defs.init(args)
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
