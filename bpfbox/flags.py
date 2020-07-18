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

from enum import IntEnum as _IntEnum, IntFlag as _IntFlag, unique, auto, _decompose
from typing import List

from bpfbox.logger import get_logger

logger = get_logger()


class IntEnum(_IntEnum):
    def __str__(self):
        return "%s" % (self._name_)


class IntFlag(_IntFlag):
    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return '%s' % (self._name_)
        members, _uncovered = _decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return '%r' % (members[0]._value_)
        else:
            return '|'.join([str(m._name_ or m._value_) for m in members])


@unique
class BPFBOX_ACTION(IntFlag):
    NONE     = 0x00000000
    ALLOW    = 0x00000001
    AUDIT    = 0x00000002
    TAINT    = 0x00000004
    DENY     = 0x00000008
    COMPLAIN = 0x00000010

    @staticmethod
    def from_actions(actions: List[str]):
        action_map = {
                action.name.lower(): action for action in BPFBOX_ACTION if action != BPFBOX_ACTION.NONE
                }
        action = BPFBOX_ACTION.NONE
        for a in actions:
            try:
                action |= action_map[a]
            except KeyError:
                pass
        return action


@unique
class FS_ACCESS(IntFlag):
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
class IPC_ACCESS(IntFlag):
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
                access.name.lower(): access for access in IPC_ACCESS if access != IPC_ACCESS.NONE
                }
        try:
            return access_map[s]
        except KeyError:
            logger.warning('Unknown access "%s"' % (s))
            return IPC_ACCESS.NONE

@unique
class NET_FAMILY(IntEnum):
    NONE      = 0
    UNIX      = auto()
    INET      = auto()
    INET6     = auto()
    IPX       = auto()
    NETLINK   = auto()
    X25       = auto()
    AX25      = auto()
    ATMPVC    = auto()
    APPLETALK = auto()
    PACKET    = auto()
    # TODO: add more here
    UNKNOWN   = auto()

    @staticmethod
    def from_string(s: str):
        family_map = {
                family.name.lower(): family for family in NET_FAMILY if family != NET_FAMILY.NONE
                }
        try:
            return family_map[s]
        except KeyError:
            logger.warning('Unknown family "%s"' % (s))
            return NET_FAMILY.NONE

@unique
class NET_ACCESS(IntFlag):
    NONE    = 0x00000000
    CONNECT = 0x00000001
    BIND    = 0x00000002
    ACCEPT  = 0x00000004
    LISTEN  = 0x00000008
    SEND    = 0x00000010
    RECV    = 0x00000020
    CREATE  = 0x00000040
    SHUTDOWN = 0x00000080

    @staticmethod
    def from_string(s: str):
        access_map = {
                access.name.lower(): access for access in NET_ACCESS if access != NET_ACCESS.NONE
                }
        try:
            return access_map[s]
        except KeyError:
            logger.warning('Unknown access "%s"' % (s))
            return NET_ACCESS.NONE

