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
                'additionalProperties': False,
                'properties': {
                    'action': {
                        'anyOf': [
                            {'$ref': '#/definitions/action'},
                            {
                                'type': 'array',
                                'items': {'$ref': '#/definitions/action'},
                            },
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
                'required': ['action', 'file', 'access'],
            },
        },
        'net': {
            'type': 'array',
            'items': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'action': {
                        'anyOf': [
                            {'$ref': '#/definitions/action'},
                            {
                                'type': 'array',
                                'items': {'$ref': '#/definitions/action'},
                            },
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
                    'family': {
                        'anyOf': [
                            {'$ref': '#/definitions/socket_families'},
                            {
                                'type': 'array',
                                'items': {'$ref': '#/definitions/socket_families'},
                            },
                        ]
                    },
                    'operation': {
                        'anyOf': [
                            {'$ref': '#/definitions/socket_operations'},
                            {
                                'type': 'array',
                                'items': {'$ref': '#/definitions/socket_operations'},
                            },
                        ]
                    },
                },
                'required': ['action', 'family', 'operation'],
            },
        },
        'signal': {
            'type': 'array',
            'items': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'action': {
                        'anyOf': [
                            {'$ref': '#/definitions/action'},
                            {
                                'type': 'array',
                                'items': {'$ref': '#/definitions/action'},
                            },
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
                    'signal': {
                        'anyOf': [
                            {'$ref': '#/definitions/signal_signals'},
                            {
                                'type': 'array',
                                'items': {'$ref': '#/definitions/signal_signals'},
                            },
                        ]
                    },
                    'target': {
                        'anyOf': [
                            {'type': 'string'},
                            {'type': 'array', 'items': {'type': 'string'}},
                        ]
                    },
                },
                'required': ['action', 'signal', 'target'],
            },
        },
    },
    'definitions': {
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


#    def attach(self, bpf: BPF):
#        fn_name = f'bpfbox_state_probe_{self.state_idx}'
#        ret_fn_name = f'bpfbox_state_retprobe_{self.state_idx}'
#
#        bpf.attach_uprobe(
#            name=self.profile_path,
#            event=self.symbol,
#            address=self.address,
#            fn_name=fn_name,
#        )
#        bpf.attach_uretprobe(
#            name=self.profile_path,
#            event=self.symbol,
#            address=self.address,
#            fn_name=ret_fn_name,
#        )
#
#    def attach(self, bpf: BPF):
#        fn_name = f'bpfbox_state_probe_{self.state_idx}'
#        ret_fn_name = f'bpfbox_state_retprobe_{self.state_idx}'
#
#        bpf.attach_kprobe(
#            event=self.symbol, address=self.address, fn_name=fn_name,
#        )
#        bpf.attach_kretprobe(
#            event=self.symbol, address=self.address, fn_name=ret_fn_name,
#        )


class Rule(ABC):
    """
    A base class for rules.
    """

    def __init__(self, policy: Policy, rule_dict: Dict[str, Any]):
        self.policy = policy
        self.action = listify(rule_dict.get('action', ['allow']))
        self.func = listify(rule_dict.get('func', []))
        self.kfunc = listify(rule_dict.get('kfunc', []))

        for action in self.action:
            assert action in ['allow', 'taint', 'audit']

    def __repr__(self):
        return f'{self.__class__.__name__}({self.__dict__})'

    def load(self):
        """
        Load this rule into the kernel.
        """

        raise NotImplementedError('Subclasses must implement Rule.load()')


class FSRule(Rule):
    """
    A filesystem rule.
    """

    def __init__(self, policy: Policy, rule_dict: Dict[str, Any]):
        super().__init__(policy, rule_dict)

        self.access = listify(rule_dict.get('access', []))
        if not self.access:
            raise PolicyException(f"Please specify access in {self}")

        self.file = listify(rule_dict.get('file', []))
        if not self.file:
            raise PolicyException(f"Please specify file in {self}")

    def load(self):
        pass  # TODO


class NetRule(Rule):
    """
    A network socket rule.
    """

    def __init__(self, policy: Policy, rule_dict: Dict[str, Any]):
        super().__init__(policy, rule_dict)

        self.operation = listify(rule_dict.get('operation', []))
        if not self.operation:
            raise PolicyException(f"Please specify operation in {self}")

        self.family = listify(rule_dict.get('family', []))
        if not self.family:
            raise PolicyException(f"Please specify family in {self}")

    def load(self):
        pass  # TODO


class SignalRule(Rule):
    """
    A signal rule.
    """

    def __init__(self, policy: Policy, rule_dict: Dict[str, Any]):
        super().__init__(policy, rule_dict)

        self.signal = listify(rule_dict.get('signal', []))
        if not self.signal:
            raise PolicyException(f"Please specify signal in {self}")

        self.target = listify(rule_dict.get('target', []))
        if not self.target:
            raise PolicyException(f"Please specify target in {self}")

    def load(self):
        pass  # TODO


class Policy:
    """
    Policy for one executable.
    """

    def __init__(self, policy_dict: Dict[str, Union[int, str]]) -> Policy:
        profile = policy_dict.get('profile', None)
        if profile is None:
            raise PolicyException("Policy must specify a 'profile'")
        # TODO: sanity check on profile type
        self.profile = profile

        validate(policy_dict, SCHEMA)

        # Dictionary of funcs and kfuncs
        self.funcs = {}

        self.rules = []

        self._parse_rules(policy_dict)

    def load(self):
        """
        Load policy into the kernel.
        """
        pass  # TODO

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
        return f"Policy('{self.profile}')"

    def _parse_rules(self, policy_dict: Dict[str, Union[str, List[str]]]):
        fs_rules = policy_dict.get('fs', [])
        net_rules = policy_dict.get('net', [])
        signal_rules = policy_dict.get('signal', [])

        for rule in fs_rules:  # type: Dict[str, Union[str, List[str]]]
            self.rules.append(FSRule(self, rule))

        for rule in net_rules:  # type: Dict[str, Union[str, List[str]]]
            self.rules.append(NetRule(self, rule))

        for rule in signal_rules:  # type: Dict[str, Union[str, List[str]]]
            self.rules.append(SignalRule(self, rule))


if __name__ == "__main__":
    p = Policy.from_file('../sample_policy/ls.toml')
    print(p)
