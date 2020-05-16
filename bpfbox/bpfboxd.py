import os, sys
import atexit
import signal
import time
import ctypes as ct

from bcc import BPF
from bcc.libbcc import lib

from bpfbox import defs
from bpfbox.daemon_mixin import DaemonMixin, DaemonNotRunningError
from bpfbox.logger import get_logger
from bpfbox.utils import syscall_name
from bpfbox.bpf import structs

logger = get_logger()

# Handle termination signals gracefully
signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))


class BPFBoxd(DaemonMixin):
    """
    BPFBox's daemon class.
    Manages BPF programs and reads events in an event loop.
    """

    def __init__(self, args):
        self.bpf = None
        self.ticksleep = defs.ticksleep
        self.enforcing = args.enforcing

    def reload_bpf(self):
        self.bpf.cleanup()
        self.bpf = None
        self.load_bpf(maps_pinned=True)

    def load_bpf(self, maps_pinned=False):
        """
        Initialize BPF program.
        """
        assert self.bpf is None

        # Read BPF program
        with open(defs.bpf_prog_path, 'r') as f:
            source = f.read()

        # Set flags
        flags = []
        flags.append(f'-I{defs.project_path}')
        # Handle enforcing mode
        if self.enforcing:
            logger.debug('Loading BPF program in enforcing mode')
            flags.append(f'-DBPFBOX_ENFORCING')
        else:
            logger.debug('Loading BPF program in permissive mode')
        # Handle pinned maps
        if maps_pinned:
            logger.debug('Loading BPF program using pinned maps')
            flags.append(f'-DMAPS_PINNED')

        # Load the bpf program
        self.bpf = BPF(text=source, cflags=flags)

        # Register exit hooks
        atexit.register(self.cleanup)

        # Register perf buffers
        self.register_perf_buffers()

        # Pin maps
        if not maps_pinned:
            self.pin_map('on_enforcement')

    def register_perf_buffers(self):
        """
        Define and register perf buffers.
        """
        # enforce() called while enforcing
        def on_enforcement(cpu, data, size):
            event = self.bpf['on_enforcement'].event(data)
            logger.policy(f'Enforcing in PID {event.tgid} TID {event.pid}')

        self.bpf['on_enforcement'].open_perf_buffer(on_enforcement)

        # enforce() called while permissive
        def on_would_have_enforced(cpu, data, size):
            event = self.bpf['on_would_have_enforced'].event(data)
            logger.policy(
                f'Would have enforced in PID {event.tgid} TID {event.pid}'
            )

        self.bpf['on_would_have_enforced'].open_perf_buffer(
            on_would_have_enforced
        )

    def pin_map(self, name):
        """
        Pin a map to sysfs so that they can be accessed in subsequent runs.
        """
        fn = os.path.join(defs.bpffs, name)

        # remove filename before trying to pin
        if os.path.exists(fn):
            os.unlink(fn)

        # pin the map
        ret = lib.bpf_obj_pin(self.bpf[name].map_fd, fn.encode('utf-8'))
        if ret:
            logger.error(
                f"Could not pin map {name}: {os.strerror(ct.get_errno())}"
            )

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
        """
        Dump debugging data to logs if we are running in debug mode.
        """
        import logging

        if not logger.level == logging.DEBUG:
            return

        # Dump profiles TODO
        logger.debug('Dumping profiles...')
        for key, profile in self.bpf['profiles'].iteritems():
            logger.debug(key)

        # Dump processes TODO
        logger.debug('Dumping processes...')
        for key, process in self.bpf['processes'].iteritems():
            logger.debug(key)

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
            print(
                'pidfile for bpfboxd is empty. If the daemon is still running, '
                'you may need to kill manually.',
                file=sys.stderr,
            )
    if args.operation == 'restart':
        b.restart_daemon()
