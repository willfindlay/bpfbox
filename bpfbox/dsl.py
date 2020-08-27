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

    Implements the parser for bpfbox's policy DSL.

    2020-Jul-04  William Findlay  Created this.
"""

from typing import Callable
from pprint import pformat, pprint

from pyparsing import *

from bpfbox.bpf_program import BPFProgram
from bpfbox.logger import get_logger
from bpfbox.flags import (
    BPFBOX_ACTION,
    FS_ACCESS,
    IPC_ACCESS,
    NET_ACCESS,
    NET_FAMILY,
)
from bpfbox.libbpfbox import Commands

logger = get_logger()


class PolicyParser:
    """
    Parses and loads BPFBox policy.
    """

    current_profile: str = None

    @classmethod
    def process_policy_file(cls, fname: str):
        with open(fname, 'r') as f:
            cls.process_policy_text(f.read())

    @classmethod
    def process_policy_text(cls, txt: str):
        policy = cls.parse_policy_text(txt)

        try:
            Commands.add_profile(policy.profile, True)
        except Exception as e:
            logger.error('Failed to create profile for {policy.profile}', exc_info=e)

        for rule in policy.rules:
            try:
                rule(policy.profile)
            except Exception as e:
                logger.error(f'Error applying rule {rule}', exc_info=e)

    @classmethod
    def parse_policy_text(cls, txt: str):
        return Policy.token.parseString(txt, True)[0]


COMMA = Suppress(',')
LPAREN = Suppress('(')
RPAREN = Suppress(')')
LCURL = Suppress('{')
RCURL = Suppress('}')


def flags(expr):
    return delimitedList(expr, delim='|')


PATHNAME = QuotedString("'") | QuotedString('"')


def parseable(expr: ParserElement):
    def inner(cls: object):
        class Parseable(cls):
            try:
                token = expr.setParseAction(cls.parse_action)
            except AttributeError:
                raise NotImplementedError(
                    f'{cls.__name__} must implement @classmethod parse_action(cls, toks)'
                ) from None

            def __repr__(self) -> str:
                return cls.__repr__(self)

        return Parseable

    return inner


@parseable(Keyword('allow') | Keyword('taint') | Keyword('audit'))
class MacroAction:
    """
    Parse the action component of a macro.
    """

    token: ParseExpression = None

    @classmethod
    def parse_action(cls, toks):
        def append_action(rule):
            rule.action |= BPFBOX_ACTION.from_string(toks[0])

        return append_action


@parseable(Suppress('#[') + (MacroAction.token) + Suppress(']'))
class Macro:
    """
    A parseable BPFBox macro.
    """

    token: ParseExpression = None

    def parse_action(self, toks):
        return toks[0]


class RuleBase:
    """
    A base class for BPFBox rules.
    """

    token: ParseExpression = None

    def __init__(self):
        self.action = BPFBOX_ACTION.NONE
        self.access = 0

    def __repr__(self) -> str:
        return str(self.__dict__)

    def __call__(self) -> None:
        raise NotImplementedError('Rules must implement __call__')


FS_ACCESS_TOKS = flags(
    MatchFirst(
        [
            Keyword(access.name.lower())
            for access in FS_ACCESS
            if access not in [FS_ACCESS.NONE]
        ]
    )
)


@parseable(
    ZeroOrMore(Macro.token)('macros')
    + Keyword('fs').suppress()
    + LPAREN
    + PATHNAME('pathname')
    + COMMA
    + FS_ACCESS_TOKS('access')
    + RPAREN
)
class FSRule(RuleBase):
    """
    A parseable BPFBox FS rule.
    """

    def __init__(self):
        RuleBase.__init__(self)
        self.pathname: str = None

    @classmethod
    def parse_action(cls, toks):
        rule = FSRule()
        rule.pathname = toks.get('pathname', '')
        rule.access = FS_ACCESS.from_list(toks.get('access', []))
        for macro in toks.get('macros', []):
            macro(rule)
        return rule

    def __call__(self, profile: str) -> int:
        return Commands.add_fs_rule(
            profile, self.pathname, self.access, self.action
        )


@parseable(
    ZeroOrMore(Macro.token)('macros')
    + Keyword('proc').suppress()
    + LPAREN
    + PATHNAME('pathname')
    + COMMA
    + FS_ACCESS_TOKS('access')
    + RPAREN
)
class ProcFSRule(RuleBase):
    """
    A parseable BPFBox ProcFS rule.
    """

    def __init__(self):
        RuleBase.__init__(self)
        self.other_exe: str = None

    @classmethod
    def parse_action(cls, toks):
        rule = ProcFSRule()
        rule.other_exe = toks.get('pathname', '')
        rule.access = FS_ACCESS.from_list(toks.get('access', []))
        for macro in toks.get('macros', []):
            macro(rule)
        return rule

    def __call__(self, profile: str) -> int:
        return Commands.add_procfs_rule(
            profile, self.other_exe, self.access, self.action
        )


SIGNAL_ACCESS_TOKS = flags(
    MatchFirst(
        [
            Keyword(access.name.lower())
            for access in IPC_ACCESS
            if access not in [IPC_ACCESS.NONE, IPC_ACCESS.PTRACE]
        ]
    )
)


@parseable(
    ZeroOrMore(Macro.token)('macros')
    + Keyword('signal').suppress()
    + LPAREN
    + (PATHNAME | Keyword('self'))('pathname')
    + COMMA
    + SIGNAL_ACCESS_TOKS('access')
    + RPAREN
)
class SignalRule(RuleBase):
    """
    A parseable BPFBox Signal rule.
    """

    def __init__(self):
        RuleBase.__init__(self)
        self.other_exe: str = None

    @classmethod
    def parse_action(cls, toks):
        rule = SignalRule()
        rule.other_exe = toks.get('pathname')
        rule.access = IPC_ACCESS.from_list(toks.get('access', []))
        for macro in toks.get('macros', []):
            macro(rule)
        return rule

    def __call__(self, profile: str) -> int:
        if self.other_exe == 'self':
            other_exe = profile
        else:
            other_exe = self.other_exe
        return Commands.add_ipc_rule(
            profile, other_exe, self.access, self.action
        )


@parseable(
    ZeroOrMore(Macro.token)('macros')
    + Keyword('ptrace').suppress()
    + LPAREN
    + (PATHNAME | Keyword('self'))('pathname')
    + RPAREN
)
class PtraceRule(RuleBase):
    """
    A parseable BPFBox Ptrace rule.
    """

    def __init__(self):
        RuleBase.__init__(self)
        self.other_exe: str = None

    @classmethod
    def parse_action(cls, toks):
        rule = PtraceRule()
        rule.other_exe = toks.get('pathname')
        rule.access = IPC_ACCESS.PTRACE
        for macro in toks.get('macros', []):
            macro(rule)
        return rule

    def __call__(self, profile: str) -> int:
        if self.other_exe == 'self':
            other_exe = profile
        else:
            other_exe = self.other_exe
        return Commands.add_ipc_rule(
            profile, other_exe, self.access, self.action
        )


NET_ACCESS_TOKS = flags(
    MatchFirst(
        [
            Keyword(access.name.lower())
            for access in NET_ACCESS
            if access != NET_ACCESS.NONE
        ]
    )
)
NET_FAMILY_TOKS = MatchFirst(
    [
        Keyword(family.name.lower())
        for family in NET_FAMILY
        if family != NET_FAMILY.UNKNOWN
    ]
)


@parseable(
    ZeroOrMore(Macro.token)('macros')
    + Keyword('net').suppress()
    + LPAREN
    + NET_FAMILY_TOKS('family')
    + COMMA
    + NET_ACCESS_TOKS('access')
    + RPAREN
)
class NetRule(RuleBase):
    """
    A parseable BPFBox Net rule.
    """

    def __init__(self):
        RuleBase.__init__(self)
        self.family = NET_FAMILY.UNSPEC

    @classmethod
    def parse_action(cls, toks):
        rule = NetRule()
        rule.family = NET_FAMILY.from_string(toks.get('family', ''))
        rule.access = NET_ACCESS.from_list(toks.get('access', []))
        for macro in toks.get('macros', []):
            macro(rule)
        return rule

    def __call__(self, profile: str) -> int:
        return Commands.add_net_rule(
            profile, self.access, self.family, self.action
        )


@parseable(
    ZeroOrMore(Macro.token)('macros')
    + LCURL
    + ZeroOrMore(
        FSRule.token
        | ProcFSRule.token
        | SignalRule.token
        | PtraceRule.token
        | NetRule.token
    )('rules')
    + RCURL
)
class Block:
    """
    A block of BPFBox rules.
    """

    token: ParserElement = None

    def __init__(self, rules):
        self.rules = rules

    def __repr__(self) -> str:
        return str(self.__dict__)

    @classmethod
    def parse_action(cls, toks):
        macros = toks.get('macros', [])
        rules = toks.get('rules', [])

        for macro in macros:
            for rule in rules:
                macro(rule)

        return Block(rules.asList())


RULE = (
    FSRule.token
    | ProcFSRule.token
    | SignalRule.token
    | PtraceRule.token
    | NetRule.token
)

BLOCK = Block.token


@parseable(
    Suppress('#![')
    + Keyword('profile').suppress()
    + PATHNAME('profile')
    + Suppress(']')
    + ZeroOrMore(RULE('rules*') | BLOCK('blocks*'))
)
class Policy:
    """
    A BPFBox policy.
    """

    token: ParserElement = None

    def __init__(self, profile: str):
        self.profile = profile
        self.rules = []

    def __repr__(self) -> str:
        return str(self.__dict__)

    @classmethod
    def parse_action(cls, toks):
        profile = toks.get('profile', '')
        policy = Policy(profile)

        rules = toks.get('rules', [])
        blocks = toks.get('blocks', [])

        for rule in rules:
            rule = rule[0]
            if not rule.action:
                rule.action = BPFBOX_ACTION.ALLOW
            policy.rules.append(rule)

        for block in blocks:
            for rule in block.rules:
                if not rule.action:
                    rule.action = BPFBOX_ACTION.ALLOW
                policy.rules.append(rule)

        return policy


if __name__ == '__main__':
    text = """
    #[allow]
    #[taint]
    fs("/usr/bin/hello", read|write|exec)
    """
    print(FSRule.token.parseString(text, True)[0])

    text = """
    #[allow]
    #[taint]
    proc("/usr/bin/hello", read|write|exec|ioctl|getattr)
    """
    print(ProcFSRule.token.parseString(text, True)[0])

    text = """
    #[allow]
    #[taint]
    #[audit]
    signal("/usr/bin/hello", sigkill|sigcheck|sigchld|sigmisc)
    """
    print(SignalRule.token.parseString(text, True)[0])

    text = """
    #[allow]
    #[taint]
    #[audit]
    signal(self, sigkill|sigcheck|sigchld|sigmisc)
    """
    print(SignalRule.token.parseString(text, True)[0])

    text = """
    #[allow]
    #[taint]
    #[audit]
    ptrace("/usr/bin/hello")
    """
    print(PtraceRule.token.parseString(text, True)[0])

    text = """
    #[allow]
    #[taint]
    #[audit]
    ptrace(self)
    """
    print(PtraceRule.token.parseString(text, True)[0])

    text = """
    #[allow]
    #[taint]
    #[audit]
    net(inet, connect|bind|accept)
    """
    print(NetRule.token.parseString(text, True)[0])

    text = """
    #[allow]
    #[taint] {
        net(inet, bind|accept)
        fs("/usr/bin/hello", read)
        fs("/usr/bin/goodbye", read|write|exec)
        #[audit]
        net(inet, accept)
    }
    """
    print(Block.token.parseString(text, True))

    text = """
    #![profile "/usr/bin/profile"]

    ptrace('/foo/bar/qux')

    #[allow]
    proc('/usr/bin/testificate', read|write)

    #[taint] {
        net(inet, bind|accept)
        fs("/usr/bin/hello", read)
        fs("/usr/bin/goodbye", read|write|exec)
        #[audit]
        net(inet, accept)
    }
    """
    print(Policy.token.parseString(text, True))
