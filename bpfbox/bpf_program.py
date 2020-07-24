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

    This file provides the userspace BPF program logic for BPFBox.

    2020-Jun-29  William Findlay  Created this.
"""

import os
from collections import defaultdict
import ctypes as ct
from textwrap import indent, dedent
from typing import List

from bcc import BPF

from bpfbox import defs
from bpfbox.logger import get_logger
from bpfbox.flags import BPFBOX_ACTION, FS_ACCESS, IPC_ACCESS, NET_ACCESS, NET_FAMILY
from bpfbox.utils import calculate_profile_key, get_inode_and_device, which, profile_key_to_exe
from bpfbox.libbpfbox import register_uprobes

logger = get_logger()


def ringbuf_callback(bpf, map_name, infer_type=True):
    def _inner(func):
        def _wrapper(ctx, data, size):
            if infer_type:
                data = bpf[map_name].event(data)
            func(ctx, data, size)

        bpf[map_name].open_ring_buffer(_wrapper)

    return _inner


class BPFProgram:
    def __init__(self, enforcing=True, debug=False, show_ebpf=False):
        self.bpf = None
        self.debug = debug
        self.show_ebpf = show_ebpf
        self.enforcing = enforcing
        self.have_registered_uprobes = False

    def do_tick(self) -> None:
        """do_tick.

        Parameters
        ----------

        Returns
        -------
        None

        """
        self.bpf.ring_buffer_consume()

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

        cflags = self._set_cflags(maps_pinned)
        # Load the bpf program
        logger.info('Loading BPF program...')
        if self.show_ebpf:
            logger.debug('BPF program source:\n%s' % (source))
        self.bpf = BPF(text=source.encode('utf-8'), cflags=cflags)
        self._register_ring_buffers()
        self._register_uprobes()

        # Pin maps
        # if not maps_pinned:
        #    logger.info('Pinnings maps...')
        #    self._pin_map('on_fs_enforcement')

    def cleanup(self) -> None:
        """cleanup.

        Perform cleanup hooks before exit.

        Parameters
        ----------

        Returns
        -------
        None

        """
        self._dump_debug_data()
        try:
            self.bpf.cleanup()
        except AttributeError:
            logger.warning("Unable to properly clean up BPF program")

    def _format_exe(self, profile_key, pid=None, uid=None):
        if pid is None:
            return profile_key_to_exe[profile_key]
        if uid is None:
            extra_info = '(%d)' % (pid)
        else:
            extra_info = '(%d, %d)' % (pid, uid)
        return '%s %s' % (profile_key_to_exe[profile_key], extra_info)

    def _format_dev(self, s_id, st_dev):
        return '%d (%s)' % (st_dev, s_id)

    def _register_ring_buffers(self):
        logger.info('Registering ring buffers...')

        @ringbuf_callback(self.bpf, 'fs_audit_events')
        def fs_audit_events(ctx, event, size):
            logger.audit(
                'action=%s access=FS_%s exe=%s st_ino=%d st_dev=%s'
                % (
                    BPFBOX_ACTION(event.action),
                    FS_ACCESS(event.access),
                    self._format_exe(event.profile_key, event.pid, event.uid),
                    event.st_ino,
                    self._format_dev(event.s_id.decode('utf-8'), event.st_dev),
                )
            )

        @ringbuf_callback(self.bpf, 'ipc_audit_events')
        def ipc_audit_events(ctx, event, size):
            logger.audit(
                'action=%s access=IPC_%s exe=%s target=%s'
                % (
                    BPFBOX_ACTION(event.action),
                    IPC_ACCESS(event.access),
                    self._format_exe(event.profile_key, event.pid, event.uid),
                    self._format_exe(event.object_profile_key, event.object_pid, event.object_uid),
                )
            )

        @ringbuf_callback(self.bpf, 'network_audit_events')
        def network_audit_events(ctx, event, size):
            logger.audit(
                'action=%s access=NET_%s family=%s exe=%s'
                % (
                    BPFBOX_ACTION(event.action),
                    NET_ACCESS(event.access),
                    NET_FAMILY(event.family),
                    self._format_exe(event.profile_key, event.pid, event.uid),
                )
            )

        # Debugging below this line
        if not self.debug:
            return

        @ringbuf_callback(self.bpf, 'task_to_inode_debug_events')
        def task_to_inode_debug_events(ctx, event, size):
            logger.debug(
                'task_to_inode: subject=%s object=%s inode=%d'
                % (
                    self._format_exe(event.subject_key, event.subject_pid),
                    self._format_exe(event.object_key, event.object_pid),
                    event.st_ino,
                )
            )


    def _register_uprobes(self):
        logger.info('Registering uprobes...')
        register_uprobes(self.bpf)
        self.have_registered_uprobes = True

    def generate_policy(self):
        logger.info('Generating policy...')
        policy_files = []
        for (dirpath, dirnames, filenames) in os.walk(defs.policy_directory):
            policy_files.extend([os.path.join(dirpath, f) for f in filenames if f.endswith('.bpfbox')])
        for f in policy_files:
            logger.info(f'Generating policy for {f}...')
            try:
                from bpfbox.dsl import PolicyParser
                PolicyParser.process_policy_file(f)
            except:
                logger.error(f'Unable to generate policy for {f}!')
        logger.info('Generated policy successfully!')

    def _set_cflags(self, maps_pinned):
        flags = []

        flags.append(f'-I{defs.project_path}')

        # Handle enforcing mode
        if self.enforcing:
            logger.info('BPF program will be loaded in enforcing mode')
            flags.append(f'-DBPFBOX_ENFORCING')
        else:
            logger.info('BPF program will be loaded in permissive mode')
        # Handle pinned maps
        if maps_pinned:
            flags.append(f'-DBPFBOX_MAPS_PINNED')
        if self.debug:
            flags.append(f'-DBPFBOX_DEBUG')

        # Max string size
        flags.append('-DBPFBOX_MAX_STRING_SIZE=%d' % (defs.max_string_size))

        # Ringbuf sizes
        flags.append(
            '-DBPFBOX_AUDIT_RINGBUF_PAGES=%d' % (defs.audit_ringbuf_pages)
        )

        # Map sizes
        flags.append('-DBPFBOX_MAX_POLICY_SIZE=%d' % (defs.max_policy_size))
        flags.append('-DBPFBOX_MAX_PROCESSES=%d' % (defs.max_processes))

        logger.debug(
            'Using cflags:\n%s' % (indent('\n'.join(flags), ' ' * 32))
        )

        return flags

    def _pin_map(self, name: str) -> None:
        from bcc import lib

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

    def _dump_debug_data(self) -> None:
        import logging

        if not logger.level == logging.DEBUG:
            return

        # Dump profiles TODO

        # Dump processes TODO
        # logger.debug('Dumping processes...')
        # for key, process in self.bpf[b'processes'].iteritems():
        #    logger.debug(key)
