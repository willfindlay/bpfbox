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

    This file extends the standard library's logging interface for BPFBox's
    purposes.

    2020-Apr-10  William Findlay  Created this.
"""

import os, sys
import stat
import pwd
import grp
import time
import gzip
import logging
from logging import handlers as handlers

from bpfbox.utils import read_chunks
from bpfbox import defs


class BPFBoxLoggerClass(logging.getLoggerClass()):
    """
    Custom logger class that allows for the logging of policy messages.
    """

    POLICY = logging.WARN - 2
    AUDIT = logging.WARN - 1

    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)

        logging.addLevelName(BPFBoxLoggerClass.POLICY, "POLICY")
        logging.addLevelName(BPFBoxLoggerClass.AUDIT, "AUDIT")

    def policy(self, msg, *args, **kwargs):
        """
        Write a policy message to logs.
        This should be used to inform the user about policy decisions/enforcement.
        """
        if self.isEnabledFor(BPFBoxLoggerClass.POLICY):
            self._log(BPFBoxLoggerClass.POLICY, msg, args, **kwargs)

    def audit(self, msg, *args, **kwargs):
        """
        Write a audit message to logs.
        This should be used to inform the user about audit decisions/enforcement.
        """
        if self.isEnabledFor(BPFBoxLoggerClass.AUDIT):
            self._log(BPFBoxLoggerClass.AUDIT, msg, args, **kwargs)


# Set logging to use custom BPFBoxLoggerClass
logging.setLoggerClass(BPFBoxLoggerClass)


class BPFBoxRotatingFileHandler(handlers.TimedRotatingFileHandler):
    """
    Rotates log files either when they have reached the specified
    time or when they have reached the specified size. Keeps
    backupCount many backups.

    This class uses camel casing because that's what the logging module uses.
    """

    def __init__(
        self,
        filename,
        maxBytes=0,
        backupCount=0,
        encoding=None,
        delay=0,
        when='h',
        interval=1,
        utc=False,
    ):
        handlers.TimedRotatingFileHandler.__init__(
            self, filename, when, interval, backupCount, encoding, delay, utc
        )
        self.maxBytes = maxBytes
        self.suffix = "%Y-%m-%d_%H-%M-%S"

        def rotator(source, dest):
            dest = f'{dest}.gz'
            try:
                os.unlink(dest)
            except FileNotFoundError:
                pass
            with open(source, 'r') as sf, gzip.open(dest, 'ab') as df:
                for chunk in read_chunks(sf):
                    df.write(chunk.encode('utf-8'))
            try:
                os.unlink(source)
            except FileNotFoundError:
                pass

        self.rotator = rotator

    def shouldRollover(self, record):
        """
        Overload shouldRollover method from base class.

        Does file exceed size limit or have we exceeded time limit?
        """
        if self.stream is None:
            self.stream = self._open()
        if self.maxBytes > 0:
            msg = f'{self.format(record)}\n'
            self.stream.seek(0, 2)
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return 1
        t = int(time.time())
        if t >= self.rolloverAt:
            return 1
        return 0


def setup_logger(args):
    # Make logfile parent directory
    os.makedirs(os.path.dirname(defs.logfile), exist_ok=True)

    # Configure logging
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    formatter.datefmt = '%Y-%m-%d %H:%M:%S'

    logger = get_logger()
    if args.verbose:
        logger.setLevel(logging.INFO)
    elif args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(BPFBoxLoggerClass.AUDIT)

    # Create and add handler
    if args.stdout:
        # Stream handler if we are writing to stdout
        handler = logging.StreamHandler()
    else:
        # Rotating handler if we are writing to log files
        # TODO: change this to allow configurable sizes, times, backup counts
        handler = BPFBoxRotatingFileHandler(
            defs.logfile,
            maxBytes=(1024 ** 3),
            backupCount=12,
            when='w0',
            interval=4,
        )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # A little debug message to tell us the logger has started
    logger.debug('Logging initialized.')


def get_logger(name='bpfbox'):
    return logging.getLogger(name)
