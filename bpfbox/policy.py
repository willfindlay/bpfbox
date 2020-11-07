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

    Loading and generating BPFBox policy.

    2020-Nov-06  William Findlay  Created this.
"""

from __future__ import annotations
from typing import Union, IO, Dict, Any, Optional, List
from abc import ABC

from bpfbox.libbpfbox import Commands
from bpfbox.flags import BPFBOX_ACTION, FS_ACCESS, IPC_ACCESS, NET_FAMILY, NET_ACCESS

# from bcc import BPF
from jsonschema import validate


SCHEMA = {
    'type': 'object',
    'additionalProperties': False,
    'properties': {
        'profile': {'type': 'string'},
        'fs': {
            'type': 'array',
            'items': {
                'type': 'object',
                'allOf': [
                    {'$ref': '#/definitions/rule'},
                    {
                        'file': {
                            'anyOf': [
                                {'type': 'string'},
                                {'type': 'array', 'items': {'type': 'string'}},
                            ]
                        },
                        'access': {
                            'anyOf': [
                                {'$ref': '#/definitions/file_access'},
                                {
                                    'type': 'array',
                                    'items': {'$ref': '#/definitions/file_access'},
                                },
                            ]
                        },
                    },
                ],
                'required': ['file', 'access'],
            },
        },
        'net': {
            'type': 'array',
            'items': {
                'type': 'object',
                'allOf': [
                    {'$ref': '#/definitions/rule'},
                    {
                        'properties': {
                            'family': {
                                'anyOf': [
                                    {'$ref': '#/definitions/socket_families'},
                                    {
                                        'type': 'array',
                                        'items': {
                                            '$ref': '#/definitions/socket_families'
                                        },
                                    },
                                ]
                            },
                            'operation': {
                                'anyOf': [
                                    {'$ref': '#/definitions/socket_operations'},
                                    {
                                        'type': 'array',
                                        'items': {
                                            '$ref': '#/definitions/socket_operations'
                                        },
                                    },
                                ]
                            },
                        }
                    },
                ],
                'required': ['family', 'operation'],
            },
        },
        'signal': {
            'type': 'array',
            'items': {
                'type': 'object',
                'allOf': [
                    {'$ref': '#/definitions/rule'},
                    {
                        'properties': {
                            'signal': {
                                'anyOf': [
                                    {'$ref': '#/definitions/signal_signals'},
                                    {
                                        'type': 'array',
                                        'items': {
                                            '$ref': '#/definitions/signal_signals'
                                        },
                                    },
                                ]
                            },
                            'target': {
                                'anyOf': [
                                    {'type': 'string'},
                                    {'type': 'array', 'items': {'type': 'string'}},
                                ]
                            },
                        }
                    },
                ],
                'required': ['signal', 'target'],
            },
        },
    },
    'definitions': {
        'rule': {
            'type': 'object',
            'properties': {
                'action': {
                    'anyOf': [
                        {'$ref': '#/definitions/action'},
                        {'type': 'array', 'items': {'$ref': '#/definitions/action'},},
                    ]
                },
                'func': {
                    'anyOf': [
                        {'type': 'string'},
                        {'type': 'array', 'items': {'type': 'string'}},
                    ]
                },
                'kfunc': {
                    'anyOf': [
                        {'type': 'string'},
                        {'type': 'array', 'items': {'type': 'string'}},
                    ]
                },
            },
            'required': ['action'],
        },
        'action': {'enum': ['allow', 'audit', 'taint']},
        'file_access': {
            'enum': [
                'read',
                'write',
                'append',
                'exec',
                'getattr',
                'setattr',
                'ioctl',
                'rm',
                'link',
                'any',
            ]
        },
        'socket_operations': {
            'enum': [
                'connect',
                'bind',
                'accept',
                'listen',
                'send',
                'receive',
                'create',
                'shutdown',
                'any',
            ]
        },
        'socket_families': {
            'enum': [
                'unix',
                'inet',
                'ax25',
                'ipx',
                'appletalk',
                'netrom',
                'bridge',
                'atmpvc',
                'x25',
                'inet6',
                'rose',
                'decnet',
                'netbeui',
                'security',
                'key',
                'netlink',
                'packet',
                'ash',
                'econet',
                'atmsvc',
                'rds',
                'sna',
                'irda',
                'pppox',
                'wanpipe',
                'llc',
                'ib',
                'mpls',
                'can',
                'tipc',
                'bluetooth',
                'iucv',
                'rxrpc',
                'isdn',
                'phonet',
                'ieee802154',
                'caif',
                'alg',
                'nfc',
                'vsock',
                'kcm',
                'qipcrtr',
                'smc',
                'xdp',
                'any',
            ]
        },
        'signal_signals': {
            'enum': ['sigchld', 'sigkill', 'sigstop', 'misc', 'check', 'fatal',]
        },
    },
}


def listify(x):
    """
    Turn x into a list.
    """
    if x is None:
        return []
    return x if type(x) is list else [x]


class PolicyException(Exception):
    pass


class PolicyLoadException(Exception):
    pass


class Rule(ABC):
    """
    A base class for rules.
    """

    def __init__(self, rule_dict: Dict[str, Any]):
        self.action = listify(rule_dict.get('action', ['allow']))
        self.func = listify(rule_dict.get('func', []))
        self.kfunc = listify(rule_dict.get('kfunc', []))

        for action in self.action:
            assert action in ['allow', 'taint', 'audit']

    def __repr__(self):
        return f'{self.__class__.__name__}({self.__dict__}))'

    def calculate_state_number(self, policy: Policy):
        """
        Calculate the required state number based on funcs and kfuncs.
        """

        state = 0

        for func in self.func:
            state |= 1 << policy.funcs[(func, False)]

        for kfunc in self.kfunc:
            state |= 1 << policy.funcs[(kfunc, True)]

        return state

    def load(self, policy: Policy):
        """
        Load this rule into the kernel.
        """

        # Keep track of func numbers
        for func in self.func:
            # Don't double count
            if policy.funcs.get((func, False), None) is not None:
                continue
            policy.funcs[(func, False)] = len(policy.funcs)

        # Keep track of kfunc numbers
        for kfunc in self.kfunc:
            # Don't double count
            if policy.funcs.get((kfunc, True), None) is not None:
                continue
            policy.funcs[(kfunc, True)] = len(policy.funcs)


class FSRule(Rule):
    """
    A filesystem rule.
    """

    def __init__(self, rule_dict: Dict[str, Any]):
        super().__init__(rule_dict)

        self.access = listify(rule_dict.get('access', []))
        if not self.access:
            raise PolicyException(f"Please specify access in {self}")

        self.file = listify(rule_dict.get('file', []))
        if not self.file:
            raise PolicyException(f"Please specify file in {self}")

    def load(self, policy: Policy):
        super().load(policy)
        state = self.calculate_state_number(policy)
        for _file in self.file:
            Commands.add_fs_rule(
                policy.profile,
                _file,
                FS_ACCESS.from_list(self.access),
                BPFBOX_ACTION.from_list(self.action),
                state=state,
            )


class NetRule(Rule):
    """
    A network socket rule.
    """

    def __init__(self, rule_dict: Dict[str, Any]):
        super().__init__(rule_dict)

        self.operation = listify(rule_dict.get('operation', []))
        if not self.operation:
            raise PolicyException(f"Please specify operation in {self}")

        self.family = listify(rule_dict.get('family', []))
        if not self.family:
            raise PolicyException(f"Please specify family in {self}")

    def load(self, policy: Policy):
        super().load(policy)
        state = self.calculate_state_number(policy)
        for family in self.family:
            Commands.add_net_rule(
                policy.profile,
                NET_ACCESS.from_list(self.operation),
                NET_FAMILY.from_string(family),
                BPFBOX_ACTION.from_list(self.action),
                state,
            )


class SignalRule(Rule):
    """
    A signal rule.
    """

    def __init__(self, rule_dict: Dict[str, Any]):
        super().__init__(rule_dict)

        self.signal = listify(rule_dict.get('signal', []))
        if not self.signal:
            raise PolicyException(f"Please specify signal in {self}")

        self.target = listify(rule_dict.get('target', []))
        if not self.target:
            raise PolicyException(f"Please specify target in {self}")

    def load(self, policy: Policy):
        super().load(policy)
        state = self.calculate_state_number(policy)
        for target in self.target:
            Commands.add_ipc_rule(
                policy.profile,
                target,
                IPC_ACCESS.from_list(self.signal),
                BPFBOX_ACTION.from_list(self.action),
                state,
            )


class Policy:
    """
    Policy for one executable.
    """

    def __init__(self, policy_dict: Dict[str, Union[int, str]]) -> Policy:
        validate(policy_dict, SCHEMA)

        profile = policy_dict.get('profile', None)
        self.profile = profile

        # TODO: either infer this or make it explicit
        self.taint_on_exec = False

        # Dictionary of funcs and kfuncs
        self.funcs = {}

        self.rules = []

        self._parse_rules(policy_dict)

    def load(self, bpf):
        """
        Load policy into the kernel.
        """

        Commands.add_profile(self.profile, self.taint_on_exec)

        for rule in self.rules:
            rule.load(self)

        for (sym, is_kfunc), state_idx in self.funcs.items():
            fn_name = f'bpfbox_state_probe_{state_idx}'
            ret_fn_name = f'bpfbox_state_retprobe_{state_idx}'
            if is_kfunc:
                bpf.attach_kprobe(
                    sym=sym, fn_name=fn_name,
                )
                bpf.attach_kretprobe(
                    sym=sym, fn_name=ret_fn_name,
                )
            else:
                bpf.attach_uprobe(
                    name=self.profile, sym=sym, fn_name=fn_name,
                )
                bpf.attach_uretprobe(
                    name=self.profile, sym=sym, fn_name=ret_fn_name,
                )

    @staticmethod
    def from_string(policy_string: str) -> Policy:
        """
        Load policy from a yaml string.
        """
        from toml import loads

        policy_dict = loads(policy_string)

        return Policy(policy_dict)

    @staticmethod
    def from_file(f_name: str) -> Policy:
        """
        Load policy from file.
        """
        from toml import load

        try:
            with open(f_name, 'r') as f:
                policy_dict = load(f)

            return Policy(policy_dict)
        except Exception:
            raise PolicyLoadException(f"Failed to load policy from file {f_name}")

    def __repr__(self):
        return f"Policy({self.__dict__})"

    def _parse_rules(self, policy_dict: Dict[str, Union[str, List[str]]]):
        fs_rules = policy_dict.get('fs', [])
        net_rules = policy_dict.get('net', [])
        signal_rules = policy_dict.get('signal', [])

        for rule in fs_rules:  # type: Dict[str, Union[str, List[str]]]
            self.rules.append(FSRule(rule))

        for rule in net_rules:  # type: Dict[str, Union[str, List[str]]]
            self.rules.append(NetRule(rule))

        for rule in signal_rules:  # type: Dict[str, Union[str, List[str]]]
            self.rules.append(SignalRule(rule))


if __name__ == "__main__":
    from pprint import pprint

    p = Policy.from_file('../sample_policy/ls.toml')
    pprint(p.__dict__)
