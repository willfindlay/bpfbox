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
from bpfbox.flags import BPFBOX_ACTION, FS_ACCESS
from bpfbox.utils import calculate_profile_key, get_inode_and_device, which
from bpfbox.libbpfbox import lib, register_uprobes

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
        self.profile_key_to_exe = defaultdict(lambda: '[unknown]')
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
        self._generate_policy()

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

    def _soft_cleanup(self) -> None:
        self.bpf['processes'].clear()
        self.bpf['profiles'].clear()
        self.bpf['fs_policy'].clear()
        self.bpf['procfs_policy'].clear()
        # IMPORTANT NOTE: remember to put new maps here

    def _format_exe(self, profile_key, pid):
        return '%s (%d)' % (self.profile_key_to_exe[profile_key], pid)

    def _format_dev(self, s_id, st_dev):
        return '%-4d (%s)' % (st_dev, s_id)

    def _register_ring_buffers(self):
        logger.info('Registering ring buffers...')

        @ringbuf_callback(self.bpf, 'fs_audit_events')
        def fs_audit_events(ctx, event, size):
            logger.audit(
                'event=FS action=%-8s uid=%-4d exe=%-18s st_ino=%-8d st_dev=%-12s access=%-11s'
                % (
                    BPFBOX_ACTION(event.action),
                    event.uid,
                    self._format_exe(event.profile_key, event.pid),
                    event.st_ino,
                    self._format_dev(event.s_id.decode('utf-8'), event.st_dev),
                    FS_ACCESS(event.access),
                )
            )

        # Debugging below this line  ---------------------------------------

        if not self.debug:
            return

        @ringbuf_callback(self.bpf, 'task_to_inode_debug_events')
        def task_to_inode_debug_events(ctx, event, size):
            logger.debug(
                'task_to_inode pid=%-8d exe=%-18s st_ino=%-8d st_dev=%-12s'
                % (
                    event.pid,
                    self._format_exe(event.profile_key, event.pid),
                    event.st_ino,
                    self._format_dev(event.s_id.decode('utf-8'), event.st_dev),
                )
            )

    def _register_uprobes(self):
        logger.info('Registering uprobes...')
        register_uprobes(self.bpf)
        self.have_registered_uprobes = True

    def _generate_policy(self):
        logger.info('Generating policy...')
        logger.warning('TODO')

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

    def _add_profile(self, profile_key: int, taint_on_exec: int) -> int:
        assert self.have_registered_uprobes
        lib.add_profile(profile_key, taint_on_exec)
        return 0

    def add_profile(self, exe: str, taint_on_exec: bool) -> int:
        profile_key = calculate_profile_key(exe)
        self.profile_key_to_exe[profile_key] = exe
        return self._add_profile(profile_key, taint_on_exec)

    def _add_fs_rule(
        self,
        profile_key: int,
        st_ino: int,
        st_dev: int,
        access_mask: FS_ACCESS,
        action: BPFBOX_ACTION,
    ) -> int:
        assert self.have_registered_uprobes
        if not (action & BPFBOX_ACTION.DENY | BPFBOX_ACTION.COMPLAIN):
            logger.error(
                '_add_fs_rule: Action must be one of ALLOW, TAINT, or AUDIT'
            )
            return 1
        lib.add_fs_rule(
            profile_key, st_ino, st_dev, access_mask.value, action.value
        )
        return 0

    def add_fs_rule(
        self,
        exe: str,
        path: str,
        access_mask: FS_ACCESS,
        action: BPFBOX_ACTION = BPFBOX_ACTION.ALLOW,
    ) -> int:
        profile_key = calculate_profile_key(exe)
        try:
            st_ino, st_dev = get_inode_and_device(path)
        except FileNotFoundError:
            logger.warning('add_fs_rule: Unable to find file %s' % (path))
            return -1

        self._add_fs_rule(profile_key, st_ino, st_dev, access_mask, action)

        if not (action & BPFBOX_ACTION.ALLOW):
            return 0

        # Handle full path access
        # FIXME: is this the best way to do this?
        try:
            head = os.readlink(path)
        except OSError:
            head = path
        while True:
            head, tail = os.path.split(head)
            if not head:
                break
            try:
                st_ino, st_dev = get_inode_and_device(head)
            except FileNotFoundError:
                logger.warning('add_fs_rule: Unable to find file %s' % (head))
                continue
            access_mask = FS_ACCESS.EXEC
            self._add_fs_rule(
                profile_key, st_ino, st_dev, access_mask, BPFBOX_ACTION.ALLOW
            )
            if not tail:
                break

    def _add_procfs_rule(
        self,
        subject_profile_key: int,
        object_profile_key: int,
        access: FS_ACCESS,
        action: BPFBOX_ACTION,
    ) -> int:
        assert self.have_registered_uprobes
        if not (action & BPFBOX_ACTION.DENY | BPFBOX_ACTION.COMPLAIN):
            logger.error(
                '_add_procfs_rule: Action must be one of ALLOW, TAINT, or AUDIT'
            )
            return 1
        lib.add_procfs_rule(
            subject_profile_key, object_profile_key, access.value, action.value
        )
        return 0

    def add_procfs_rule(
        self,
        subject_exe: str,
        object_exe: str,
        access: FS_ACCESS,
        action: BPFBOX_ACTION = BPFBOX_ACTION.ALLOW,
    ):
        subject_profile_key = calculate_profile_key(subject_exe)
        object_profile_key = calculate_profile_key(object_exe)
        self._add_procfs_rule(
            subject_profile_key, object_profile_key, access, action
        )
