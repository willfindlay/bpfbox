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

    This file provides the implementation of the bpfboxd daemon and defines
    its entrypoint.

    2020-Apr-10  William Findlay  Created this.
"""

import sys
import atexit
import signal
import time
from collections import defaultdict
from typing import List, NoReturn

from bpfbox import defs
from bpfbox.daemon_mixin import DaemonMixin, DaemonNotRunningError
from bpfbox.logger import get_logger
from bpfbox.argument_parser import parse_args
from bpfbox.bpf_program import BPFProgram

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
        self.ticksleep = defs.ticksleep
        self.bpf_program = BPFProgram(self, enforcing=args.enforcing, debug=args.debug)

        self._register_exit_hooks()

    def loop_forever(self) -> NoReturn:
        """loop_forever.

        BPFBoxd main event loop.

        Parameters
        ----------

        Returns
        -------
        NoReturn

        """
        self._load_policy()
        while 1:
            self.bpf_program.do_tick()
            time.sleep(self.ticksleep)

    def _register_exit_hooks(self):
        # Register exit hooks
        logger.info('Registering exit hooks...')
        atexit.register(self._cleanup)

    def _cleanup(self):
        self.bpf_program.cleanup()

    def _load_policy(self):
        self.bpf_program.load_bpf(maps_pinned=False)


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
