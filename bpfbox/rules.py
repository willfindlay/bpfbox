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

    This file defines the userspace representation of BPFBox rules
    and several enums that can be used to define them.
"""

import os
import enum
from abc import ABC, abstractmethod
from netaddr import IPAddress
from socket import AF_INET, AF_INET6

from bpfbox.utils import get_inode_and_device


@enum.unique
class RuleAction(enum.IntEnum):
    ALLOW = 0x1
    TAINT = 0x2


@enum.unique
class AccessMode(enum.IntFlag):
    """
    Access mode bitmask from linux/fs.h,
    used in filesystem rules for generation of predicates.
    """

    MAY_EXEC = 0x01
    MAY_WRITE = 0x02
    MAY_READ = 0x04
    MAY_APPEND = 0x08
    MAY_ACCESS = 0x10
    MAY_OPEN = 0x20
    MAY_CHDIR = 0x40
    # For non-blocking RCU
    # (perhaps we want to modify access_predicate to ignore this)
    MAY_NOT_BLOCK = 0x80


@enum.unique
class NetOperation(enum.IntEnum):
    """
    Types of network operation we want to mediate.
    """

    # bpf/defs.h
    BIND = 0x01
    CONNECT = 0x02
    ACCEPT = 0x04
    SEND = 0x08
    RECV = 0x10


class Rule:
    """
    This abstract class represents the standard interface of a bpfbox rule.
    """

    def __init__(self, action: RuleAction):
        assert isinstance(action, RuleAction)
        self.action = action

    @abstractmethod
    def generate(self):
        pass


class FSRule(Rule):
    """
    This class forms the userspace representation of a filesystem access rule.
    It is used to generate the predicates used in the tail called BPF program.
    """

    def __init__(self, path: str, mode: AccessMode, action: RuleAction):
        assert isinstance(path, str)
        assert isinstance(mode, AccessMode)
        assert os.path.exists(path)

        super().__init__(action)

        self.path = path
        self.mode = mode

    def generate(self):
        st_ino, st_dev = get_inode_and_device(self.path)
        # if our path is a directory, we want to allow the directory and all of
        # its immediate children to be opened
        # TODO: maybe change this behavior to allow more control
        if os.path.isdir(self.path):
            file_predicate = (
                f'((inode == {st_ino} || parent_inode == {st_ino})'
                f' && st_dev == {st_dev})'
            )
        else:
            file_predicate = f'(inode == {st_ino} && st_dev == {st_dev})'
        access_predicate = f'((acc_mode & {self.mode}) == acc_mode)'
        return f'({file_predicate} && {access_predicate})'


class NetRule(Rule):
    """
    This class forms the userspace representation of a network rule.
    It is used to generate the predicates used in the tail called BPF program.
    """

    def __init__(
        self,
        addr: IPAddress,
        port: int,
        operation: NetOperation,
        action: RuleAction,
    ):
        assert isinstance(addr, IPAddress)
        assert isinstance(port, int)
        assert isinstance(operation, NetOperation)

        super().__init__(action)

        self.addr = addr
        self.port = port
        self.operation = operation

    def generate(self):
        return f''  # TODO
