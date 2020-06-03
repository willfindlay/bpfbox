"""
    🐝 BPFBox 📦  Application-transparent sandboxing rules with eBPF.
    Copyright (C) 2020  William Findlay

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    William Findlay created this.
        williamfindlay <àŧ> cmail.carleton.ca

    This file provides the implementation of the bpfboxd daemon and defines
    its entrypoint.
"""

import os
import sys
import atexit
import signal
import time
import ctypes as ct
from collections import defaultdict
from typing import List, NoReturn

from bcc import BPF
from bcc.libbcc import lib

from bpfbox import defs
from bpfbox.daemon_mixin import DaemonMixin, DaemonNotRunningError
from bpfbox.logger import get_logger
from bpfbox.utils import syscall_name, access_name
from bpfbox.policy import Policy
from bpfbox.rules import AccessMode
from bpfbox.argument_parser import parse_args

logger = get_logger()

# Handle termination signals gracefully
signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))


class BPFBoxd(DaemonMixin):
    """BPFBoxd.

    BPFBox's daemon class.
    Manages BPF programs and reads events in an event loop.
    """

    def __init__(self, args: List[str]):
        self.bpf = None
        self.debug = args.debug
        self.ticksleep = defs.ticksleep
        self.enforcing = args.enforcing
        self.profile_key_to_exe = defaultdict(lambda x: '[unknown]')

        # Holds the Policy objects that will be used to generate the BPF
        # programs TODO: maybe use a generator instead
        self.policy = []

    def reload_bpf(self) -> None:
        """reload_bpf.

        Reload the BPF program, performing any necessary cleanup.

        Parameters
        ----------

        Returns
        -------
        None

        """
        try:
            self.cleanup()
        except AttributeError:
            pass
        self.bpf = None
        self.load_bpf(maps_pinned=True)

    def load_bpf(self, maps_pinned: bool = False) -> None:
        """load_bpf.

        Initialize BPF program.

        Parameters
        ----------
        maps_pinned : bool
            maps_pinned

        Returns
        -------
        None

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
            logger.debug('BPF program will be loaded in enforcing mode')
            flags.append(f'-DBPFBOX_ENFORCING')
        else:
            logger.debug('BPF program will be loaded in permissive mode')
        # Handle pinned maps
        if maps_pinned:
            flags.append(f'-DMAPS_PINNED')
        if self.debug:
            flags.append(f'-DBPFBOX_DEBUG')

        logger.debug(f'Using flags {" ".join(flags)}')

        # Generate policy and register binary names
        logger.info('Generating policy...')
        for policy in self.policy:
            self.profile_key_to_exe[policy.profile_key] = policy.binary
            source = '\n'.join([source, policy.generate_bpf_program()])

        # Load the bpf program
        logger.info('Loading BPF program...')
        logger.debug(source)
        self.bpf = BPF(text=source.encode('utf-8'), cflags=flags)

        # Register tail call programs and profile structs
        logger.info('Running post generation hooks...')
        for policy in self.policy:
            policy.post_generation_hooks(self.bpf)

        # Register exit hooks
        logger.info('Registering exit hooks...')
        atexit.register(self.cleanup)

        # Register perf buffers
        logger.info('Registering perf buffers...')
        self.register_perf_buffers()

        # Pin maps
        if not maps_pinned:
            logger.info('Pinnings maps...')
            self.pin_map('on_fs_enforcement')

    def register_perf_buffers(self) -> None:
        """register_perf_buffers.

        Define and register perf buffers with BPF program.

        Parameters
        ----------

        Returns
        -------
        None

        """

        def on_fs_enforcement(cpu, data, size):
            event = self.bpf[b'on_fs_enforcement'].event(data)
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

        self.bpf[b'on_fs_enforcement'].open_perf_buffer(on_fs_enforcement)

    def pin_map(self, name: str) -> None:
        """pin_map.

        Pin a map <name> to /sys/bpf/<name> so that it can be accessed
        in subsequent runs.

        Parameters
        ----------
        name : str
            name

        Returns
        -------
        None

        """
        fn = os.path.join(defs.bpffs, name)

        # remove filename before trying to pin
        if os.path.exists(fn):
            os.unlink(fn)

        # pin the map
        ret = lib.bpf_obj_pin(
            self.bpf[name.encode('utf-8')].map_fd, fn.encode('utf-8')
        )
        if ret:
            logger.error(
                f"Could not pin map {name}: {os.strerror(ct.get_errno())}"
            )
        else:
            logger.debug(f"Pinned map {name} to {fn}")

    def save_profiles(self) -> None:
        """save_profiles.

        Write all profile data to disk.
        TODO: implement this

        Parameters
        ----------

        Returns
        -------
        None

        """
        pass

    def save_profile(self) -> None:
        """save_profile.

        Save one profile's data to disk.
        TODO: implement this

        Parameters
        ----------

        Returns
        -------
        None

        """
        pass

    def load_profiles(self) -> None:
        """load_profiles.

        Load all profile data from disk.
        TODO: implement this

        Parameters
        ----------

        Returns
        -------
        None

        """
        pass

    def load_profile(self) -> None:
        """load_profile.

        Load one profile's data from disk.
        TODO: implement this

        Parameters
        ----------

        Returns
        -------
        None

        """
        pass

    def dump_debug_data(self) -> None:
        """dump_debug_data.

        Dump debugging data to logs if we are running in debug mode.

        Parameters
        ----------

        Returns
        -------
        None

        """
        import logging

        if not logger.level == logging.DEBUG:
            return

        # Dump profiles TODO
        logger.debug('Dumping profiles...')
        for key, profile in self.bpf[b'profiles'].iteritems():
            logger.debug(key)

        # Dump processes TODO
        logger.debug('Dumping processes...')
        for key, process in self.bpf[b'processes'].iteritems():
            logger.debug(key)

    def cleanup(self) -> None:
        """cleanup.

        Perform cleanup hooks before exit.

        Parameters
        ----------

        Returns
        -------
        None

        """
        self.dump_debug_data()
        self.save_profiles()
        try:
            self.bpf.cleanup()
        except AttributeError:
            logger.warning("Unable to properly clean up BPF program")

    def trace_print(self) -> None:
        """trace_print.

        Helper to print information from debugfs logfile until we have consumed it entirely.

        This is great for debugging, but should not be used in production, since the debugfs logfile
        is shared globally between all BPF programs.

        Parameters
        ----------

        Returns
        -------
        None

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

    def loop_forever(self) -> NoReturn:
        """loop_forever.

        BPFBoxd main event loop.

        Parameters
        ----------

        Returns
        -------
        NoReturn

        """
        self.load_bpf()
        while 1:
            if self.debug:
                self.trace_print()
            self.bpf.perf_buffer_poll(30)
            time.sleep(self.ticksleep)


def main(args=sys.argv[1:]) -> None:
    """main.

    Main entrypoint for BPFBox daemon.
    Generally should be invoked with parse_args.

    Parameters
    ----------
    args :
        args

    Returns
    -------
    None

    """
    args = parse_args(args)
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
