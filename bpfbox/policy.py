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

    This file defines the userspace representation of BPFBox policy,
    which collects rules and generates the BPF programs that correspond
    to them.
"""

import os
from itertools import count
import stat
from textwrap import dedent
import ctypes as ct
from typing import List, Callable

from bcc import BPF

from bpfbox.bpf.structs import BPFBoxProfileStruct
from bpfbox.defs import project_path
from bpfbox.utils import calculate_profile_key, get_inode_and_device
from bpfbox.logger import get_logger
from bpfbox.rules import Rule, FSRule, AccessMode, RuleAction, NetOperation

logger = get_logger()

TEMPLATE_PATH = os.path.join(project_path, 'bpfbox/bpf/templates')

# Keep in sync with BPF_PROG_ARRAYs in bpf/bpf_program.c
TAIL_CALLS = [
    'fs_policy',
    'net_bind_policy',
    'net_connect_policy',
    'net_send_policy',
    'net_recv_policy',
]

# Read template for fs_policy
with open(os.path.join(TEMPLATE_PATH, 'fs_policy.c'), 'r') as f:
    FS_POLICY_TEMPLATE = f.read()

# Read template for net_policy
with open(os.path.join(TEMPLATE_PATH, 'net_policy.c'), 'r') as f:
    NET_POLICY_TEMPLATE = f.read()


class Policy:
    """
    Provide's userspace's perspective of a bpfbox profile.
    """

    # This allows us to auto increment subsequent tail call indices in a
    # thread-safe manner. (Thread safety is not a concern at the moment,
    # but this is an easy way of future-proofing the code.)
    _next_tail_call_index = count()
    next(_next_tail_call_index)

    def __init__(self, binary):
        self.tail_call_index = next(Policy._next_tail_call_index)
        # TODO: deal with interpreted scripts
        self.profile_key = calculate_profile_key(binary)
        self.binary = binary

        self._next_context_mask = count()

        self.contexts = []

        self.fs_rules = []
        self.net_rules = []

    @classmethod
    def from_policy_file(path):
        """
        Load policy file at <path> and use it to create a policy object.
        """
        with open(path, 'r') as f:
            policy_text = f.read()
        for line in policy_text:
            pass
            # TODO

    def generate_bpf_program(self):
        """
        Generate the BPF programs based on the policy.
        """
        fs_policy = self._generate_fs_policy()
        logger.debug(fs_policy)
        net_policy = self._generate_net_policy()
        logger.debug(net_policy)
        # TODO generate other policy types here
        return dedent('\n'.join([fs_policy, net_policy]))

    def register_tail_calls(self, bpf):
        """
        Register BPF program with tail call index.
        """
        for name in TAIL_CALLS:
            fn = bpf.load_func(
                f'{name}_{self.profile_key}'.encode('utf-8'), BPF.KPROBE
            )
            bpf['{name}'.encode('utf-8')][
                ct.c_int(self.tail_call_index)
            ] = ct.c_int(fn.fd)

    def register_profile_struct(self, bpf):
        """
        Register profile struct with BPF program.
        """
        bpf[b'profiles'][
            ct.c_uint64(self.profile_key)
        ] = self._generate_profile_struct()

    def _infer_taint_on_exec(self):
        """
        Return True if we have no taint rules, False otherwise
        """
        taint_rules = [
            rule
            for rule in self.fs_rules + self.net_rules
            # TODO: add other taint rules
            if rule.action == RuleAction.TAINT
        ]
        return not taint_rules

    def _generate_profile_struct(self):
        """
        Generate the profile struct to associate the binary and its tail call
        program.
        """
        struct = BPFBoxProfileStruct()
        struct.tail_call_index = self.tail_call_index
        struct.taint_on_exec = ct.c_uint8(int(self._infer_taint_on_exec()))
        return struct

    def _generate_predicate(
        self, text: str, replace: str, rules: List[Rule], _filter: Callable,
    ) -> str:
        """_generate_predicate.

        Generate a predicate for <rules>, filtered by <filter>
        and replace <replace> in <text> with the predicate.
        Return new <text>.

        Parameters
        ----------
        text : str
            text
        replace : str
            replace
        rules : List[Rule]
            rules
        _filter : Callable
            _filter

        Returns
        -------
        str

        """
        rules = filter(_filter, rules)
        predicate = ' || '.join([r.generate() for r in rules]) or '0'
        return text.replace(replace, predicate)

    def _generate_fs_policy(self):
        """
        Generate the filesystem policy and return the corresponding BPF program.
        """
        text = FS_POLICY_TEMPLATE

        text = text.replace('PROFILEKEY', str(self.profile_key))

        # FS allow rules
        text = self._generate_predicate(
            text,
            'FS_ALLOW_RULES',
            self.fs_rules,
            lambda r: r.action == RuleAction.ALLOW,
        )

        # FS taint rules
        text = self._generate_predicate(
            text,
            'FS_TAINT_RULES',
            self.fs_rules,
            lambda r: r.action == RuleAction.TAINT,
        )

        return text

    def _generate_net_policy(self) -> None:
        """_generate_net_policy.

        Parameters
        ----------

        Returns
        -------
        None

        """
        text = NET_POLICY_TEMPLATE

        text = text.replace('PROFILEKEY', str(self.profile_key))

        # Bind rules -------------------------------------------

        text = self._generate_predicate(
            text,
            'BIND_TAINT_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.TAINT
            and r.operation == NetOperation.BIND,
        )

        text = self._generate_predicate(
            text,
            'BIND_ALLOW_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.ALLOW
            and r.operation == NetOperation.BIND,
        )

        # Connect rules ----------------------------------------

        text = self._generate_predicate(
            text,
            'CONNECT_TAINT_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.TAINT
            and r.operation == NetOperation.CONNECT,
        )

        text = self._generate_predicate(
            text,
            'CONNECT_ALLOW_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.ALLOW
            and r.operation == NetOperation.CONNECT,
        )

        # Accept rules -----------------------------------------

        text = self._generate_predicate(
            text,
            'ACCEPT_TAINT_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.TAINT
            and r.operation == NetOperation.ACCEPT,
        )

        text = self._generate_predicate(
            text,
            'ACCEPT_ALLOW_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.ALLOW
            and r.operation == NetOperation.ACCEPT,
        )

        # Send rules -------------------------------------------

        text = self._generate_predicate(
            text,
            'SEND_TAINT_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.TAINT
            and r.operation == NetOperation.SEND,
        )

        text = self._generate_predicate(
            text,
            'SEND_ALLOW_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.ALLOW
            and r.operation == NetOperation.SEND,
        )

        # Recv rules -------------------------------------------

        text = self._generate_predicate(
            text,
            'RECV_TAINT_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.TAINT
            and r.operation == NetOperation.RECV,
        )

        text = self._generate_predicate(
            text,
            'RECV_ALLOW_RULES',
            self.net_rules,
            lambda r: r.action == RuleAction.ALLOW
            and r.operation == NetOperation.RECV,
        )

        return text
