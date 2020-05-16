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
        # FIXME: get rid of this, just for testing
        # def on_profile_create(cpu, data, size):
        #    event = self.bpf['on_profile_create'].event(data)
        #    if event.comm == b'ls':
        #        ls_rules = Rules(self.bpf, self.flags, event)
        #        # ls_rules.add_rule('exit_group()')
        #        ls_rules.generate()

        # self.bpf['on_profile_create'].open_perf_buffer(on_profile_create)

        # Policy enforcement event
        def on_enforcement(cpu, data, size):
            event = self.bpf['on_enforcement'].event(data)
            enforcement = (
                'Enforcing' if self.enforcing else 'Would have enforced'
            )
            try:
                profile = self.bpf['profiles'][ct.c_uint64(event.profile_key)]
            except KeyError:
                profile = structs.BPFBoxProfileStruct()
                profile.comm = b'UNKNOWN'
            logger.policy(
                f'{enforcement} on {syscall_name(event.syscall)} in PID {event.pid} ({profile.comm.decode("utf-8")})'
            )

        self.bpf['on_enforcement'].open_perf_buffer(on_enforcement)

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
        # TODO: call logger.debug() here to log useful data

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
