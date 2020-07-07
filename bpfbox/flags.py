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

    This file provides a better Flag class as well as several enums/flags
    that correspond to those defined in the BPF program.

    **********************************************************************
    **********************************************************************
       WARNING: Keep this file in sync with bpf/policy.c at all times!
    **********************************************************************
    **********************************************************************

    2020-Jun-29  William Findlay  Created this.
"""

from enum import Enum, unique, _decompose, Flag as _Flag
from typing import List

from bpfbox.logger import get_logger

logger = get_logger()


class Flag(_Flag):
    """
    enum.Flag but with better printing
    """

    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return '%s' % (self._name_)
        members, uncovered = _decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return '%r' % (members[0]._value_)
        else:
            return '|'.join([str(m._name_ or m._value_) for m in members])


@unique
class BPFBOX_ACTION(Flag):
    NONE     = 0x00000000
    ALLOW    = 0x00000001
    AUDIT    = 0x00000002
    TAINT    = 0x00000004
    DENY     = 0x00000008
    COMPLAIN = 0x00000010

    @staticmethod
    def from_actions(actions: List[str]):
        action_map = {
            'taint': BPFBOX_ACTION.TAINT,
            'allow': BPFBOX_ACTION.ALLOW,
            'audit': BPFBOX_ACTION.AUDIT,
        }
        action = BPFBOX_ACTION.NONE
        for a in actions:
            try:
                action |= action_map[a]
            except KeyError:
                pass
        return action


@unique
class FS_ACCESS(Flag):
    NONE = 0x00000000
    READ = 0x00000001
    WRITE = 0x00000002
    APPEND = 0x00000004
    EXEC = 0x00000008
    SETATTR = 0x00000010
    GETATTR = 0x00000020
    IOCTL = 0x00000040
    RM = 0x00000080
    ADD_LINK = 0x00000100

    @staticmethod
    def from_string(s: str):
        access_map = {
            'r': FS_ACCESS.READ,
            'w': FS_ACCESS.WRITE,
            'a': FS_ACCESS.APPEND,
            'x': FS_ACCESS.EXEC,
            'l': FS_ACCESS.ADD_LINK,
            'i': FS_ACCESS.IOCTL,
            'g': FS_ACCESS.GETATTR,
            's': FS_ACCESS.SETATTR,
            'u': FS_ACCESS.RM
        }
        access = FS_ACCESS.NONE
        for ell in s:
            try:
                access |= access_map[ell]
            except:
                logger.warning('Unknown access "%s"' % (ell))
        return access

@unique
class IPC_ACCESS(Flag):
    NONE = 0x00000000
    SIGCHLD = 0x00000001
    SIGKILL = 0x00000002
    SIGSTOP = 0x00000004
    SIGMISC = 0x00000008
    SIGCHECK = 0x00000010
    PTRACE = 0x00000020

    @staticmethod
    def from_string(s: str):
        access_map = {
            'kill': IPC_ACCESS.SIGKILL,
            'chld': IPC_ACCESS.SIGCHLD,
            'stop': IPC_ACCESS.SIGSTOP,
            'misc': IPC_ACCESS.SIGMISC,
            'check': IPC_ACCESS.SIGCHECK,
            'ptrace': IPC_ACCESS.PTRACE,
        }
        access = IPC_ACCESS.NONE
        for ell in s:
            try:
                access |= access_map[ell]
            except:
                logger.warning('Unknown access "%s"' % (ell))
        return access

