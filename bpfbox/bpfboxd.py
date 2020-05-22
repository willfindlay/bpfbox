import os
import sys
import atexit
import signal
import time
import ctypes as ct
from collections import defaultdict

from bcc import BPF
from bcc.libbcc import lib

from bpfbox import defs
from bpfbox.daemon_mixin import DaemonMixin, DaemonNotRunningError
from bpfbox.logger import get_logger
from bpfbox.utils import syscall_name, access_name
from bpfbox.policy import Policy
from bpfbox.rules import AccessMode

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
        self.debug = args.debug
        self.ticksleep = defs.ticksleep
        self.enforcing = args.enforcing
        self.profile_key_to_exe = defaultdict(lambda x: '[unknown]')

        # Holds the Policy objects that will be used to generate the BPF
        # programs TODO: maybe use a generator instead
        self.policy = []

        # FIXME: get rid of this, just testing
        p = Policy('/usr/bin/ls')
        # p.fs_taint('/etc/ld.so.cache', AccessMode.MAY_READ)
        p.fs_allow('/etc/ld.so.cache', AccessMode.MAY_READ)
        p.fs_allow('/usr/lib/libcap.so.2', AccessMode.MAY_READ)
        p.fs_allow('/usr/lib/locale/locale-archive', AccessMode.MAY_READ)
        p.fs_allow('/usr/lib/libc.so.6', AccessMode.MAY_READ)
        p.fs_allow(
            '/home/housedhorse/documents/projects/bpfbox', AccessMode.MAY_READ
        )
        self.policy.append(p)

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

        # Generate policy and register binary names
        for policy in self.policy:
            self.profile_key_to_exe[policy.profile_key] = policy.binary
            source = '\n'.join([source, policy.generate_bpf_program()])

        # Load the bpf program
        self.bpf = BPF(text=source, cflags=flags)

        # Register tail call programs and profile structs
        for policy in self.policy:
            policy.register_tail_calls(self.bpf)
            policy.register_profile_struct(self.bpf)

        # Register exit hooks
        atexit.register(self.cleanup)

        # Register perf buffers
        self.register_perf_buffers()

        # Pin maps
        if not maps_pinned:
            self.pin_map('on_fs_enforcement')

    def register_perf_buffers(self):
        """
        Define and register perf buffers.
        """

        def on_fs_enforcement(cpu, data, size):
            event = self.bpf['on_fs_enforcement'].event(data)
            enforcement_prefix = (
                'Enforcing' if event.enforcing else 'Would have enforced'
            )
            logger.policy(
                f'{enforcement_prefix} filesystem access in '
                f'{self.profile_key_to_exe[event.profile_key]} '
                f'(PID {event.tgid} TID {event.pid}): '
                f'inode={event.inode}, parent_inode={event.parent_inode}, '
                f'st_dev={event.st_dev}, access={access_name(event.access)}'
            )

        self.bpf['on_fs_enforcement'].open_perf_buffer(on_fs_enforcement)

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

    def trace_print(self):
        """
        Helper to print information from debugfs logfile until we have consumed it entirely.

        This is great for debugging, but should not be used in production, since the debugfs logfile
        is shared globally between all BPF programs.
        """
        while True:
            try:
                fields = self.bpf.trace_fields(nonblocking=True)
                msg = fields[-1]
                if msg == None:
                    return
                logger.debug(msg.decode('utf-8'))
            except:
                logger.warning(
                    "Could not correctly parse debug information from debugfs"
                )

    def loop_forever(self):
        """
        BPFBoxd main event loop.
        """
        self.load_bpf()
        while 1:
            if self.debug:
                self.trace_print()
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
