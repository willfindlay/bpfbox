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

    This file provides a mixin class for daemonization.
"""

import os, sys
import signal

from daemon import DaemonContext, pidfile

from bpfbox import defs

from bpfbox.logger import get_logger

logger = get_logger()


class DaemonNotRunningError(Exception):
    """
    Triggered when the daemon is not running and we attemp to kill it.
    """

    pass


class DaemonMixin:
    def loop_forever(self):
        raise NotImplementedError(
            'Implement loop_forever(self) in the subclass.'
        )

    def get_pid(self):
        """
        Get pid of the running daemon.
        """
        try:
            with open(defs.pidfile, 'r') as f:
                return int(f.read().strip())
        except:
            return None

    def stop_daemon(self):
        """
        Stop the daemon.
        """
        pid = self.get_pid()
        try:
            os.kill(pid, signal.SIGTERM)
        except TypeError:
            raise DaemonNotRunningError

    def start_daemon(self):
        """
        Start the daemon.
        """
        with DaemonContext(
            umask=0o022,
            working_directory=defs.working_directory,
            pidfile=pidfile.TimeoutPIDLockFile(defs.pidfile),
            # Necessary to preserve logging
            files_preserve=[handler.stream for handler in logger.handlers],
        ):
            self.loop_forever()

    def restart_daemon(self):
        """
        Restart the daemon.
        """
        try:
            self.stop_daemon()
        except DaemonNotRunningError:
            pass
        self.start_daemon()
