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
from collections import defaultdict
from typing import List, Callable

from bcc import BPF

from bpfbox.bpf.structs import BPFBoxProfileStruct
from bpfbox.defs import project_path, context_mask_size
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
with open(os.path.join(TEMPLATE_PATH, 'policy.c'), 'r') as f:
    POLICY_TEMPLATE = f.read()


def context_mask_counter():
    next_mask = 1
    while 1:
        if next_mask > context_mask_size:
            raise Exception('Function context limit reached')
        yield next_mask
        next_mask = next_mask << 1


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

        self.should_taint_on_exec = 0

        self._next_context_mask = context_mask_counter()

        self.contexts = []

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

    def add_rule_context(
        self, addr: int = None, sym: bytes = b''
    ) -> 'RuleContext':
        from bpfbox.context import RuleContext

        if addr or sym:
            context_mask = next(self._next_context_mask)
        else:
            context_mask = None

        rc = RuleContext(
            self.binary, context_mask=context_mask, addr=addr, sym=sym,
        )
        self.contexts.append(rc)
        return rc

    def generate_bpf_program(self):
        """
        Generate the BPF programs based on the policy.
        """
        policy = POLICY_TEMPLATE
        # Set profile key
        policy = policy.replace('PROFILEKEY', str(self.profile_key))
        # Generate uprobes for contexts and rules for contexts
        rules_agg = defaultdict(list)
        uprobes = []
        for c in self.contexts:
            uprobes.append(c.generate_uprobes())
            for k, v in c.generate_rules().items():
                rules_agg[k].append(v)
        for k, v in rules_agg.items():
            policy = policy.replace(k, '\n'.join(v))
        policy = '\n'.join([policy] + uprobes)
        # Set whether we should taint on exec
        if 'TAINT' not in policy:
            self.should_taint_on_exec = 1
        return policy

    def post_generation_hooks(self, bpf):
        """
        Hooks to be run once the BPF programs are loaded.
        """
        self._register_tail_calls(bpf)
        self._register_profile_struct(bpf)
        self._attach_uprobes(bpf)

    def _attach_uprobes(self, bpf):
        """
        Attach uprobes for contexts.
        """
        for c in self.contexts:
            c.attach_uprobes(bpf)

    def _register_tail_calls(self, bpf):
        """
        Register BPF program with tail call index.
        """
        for name in TAIL_CALLS:
            logger.debug(f'attempting to regsiter {name}')
            fn = bpf.load_func(
                f'{name}_{self.profile_key}'.encode('utf-8'), BPF.KPROBE
            )
            bpf[name.encode('utf-8')][
                ct.c_int(self.tail_call_index)
            ] = ct.c_int(fn.fd)

    def _register_profile_struct(self, bpf):
        """
        Register profile struct with BPF program.
        """
        bpf[b'profiles'][
            ct.c_uint64(self.profile_key)
        ] = self._generate_profile_struct()

    def _generate_profile_struct(self):
        """
        Generate the profile struct to associate the binary and its tail call
        program.
        """
        struct = BPFBoxProfileStruct()
        struct.tail_call_index = self.tail_call_index
        struct.taint_on_exec = ct.c_uint8(int(self.should_taint_on_exec))
        return struct
