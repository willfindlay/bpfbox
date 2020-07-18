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

from pyparsing import *

from bpfbox.bpf_program import BPFProgram
from bpfbox.logger import get_logger
from bpfbox.flags import BPFBOX_ACTION, FS_ACCESS, IPC_ACCESS, NET_ACCESS, NET_FAMILY
from bpfbox.libbpfbox import Commands

logger = get_logger()

comma = Literal(',').suppress()
quoted_string = QuotedString('"') | QuotedString("'")
comment = QuotedString(quoteChar='/*', endQuoteChar='*/', multiline=True).suppress()
lparen = Literal('(').suppress()
rparen = Literal(')').suppress()

pathname = quoted_string

fs_access = Word('rwaxligsu')
signal_access = MatchFirst([Keyword(access.name.lower()) for access in IPC_ACCESS if access not in [IPC_ACCESS.NONE, IPC_ACCESS.PTRACE]])
net_access = MatchFirst([Keyword(access.name.lower()) for access in NET_ACCESS if access != NET_ACCESS.NONE])
net_family = MatchFirst([Keyword(family.name.lower()) for family in NET_FAMILY if family not in [NET_FAMILY.NONE, NET_FAMILY.UNKNOWN]])


class RuleBase:
    def __init__(self, rule_dict: Dict):
        self.rule_dict = rule_dict

        self.rule_actions = [a for a in self.rule_dict['macros'] if a in ['allow', 'taint', 'audit']]
        if 'taint' not in self.rule_actions:
            self.rule_actions.append('allow')

    def __repr__(self):
        return self.__class__.__name__

    def __call__(self, exe):
        raise NotImplementedError('Rules must implement __call__')

class FSRule(RuleBase):
    def __init__(self, rule_dict: Dict):
        super().__init__(rule_dict)

    def __call__(self, exe):
        pathname = self.rule_dict['pathname']
        access = FS_ACCESS.from_string(self.rule_dict['access'])
        action = BPFBOX_ACTION.from_actions(self.rule_actions)
        Commands.add_fs_rule(exe, pathname, access, action)

class ProcFSRule(RuleBase):
    def __init__(self, rule_dict: Dict):
        super().__init__(rule_dict)

    def __call__(self, exe):
        pathname = self.rule_dict['pathname']
        access = FS_ACCESS.from_string(self.rule_dict['access'])
        action = BPFBOX_ACTION.from_actions(self.rule_actions)
        Commands.add_procfs_rule(exe, pathname, access, action)

class SignalRule(RuleBase):
    def __init__(self, rule_dict: Dict):
        super().__init__(rule_dict)

    def __call__(self, exe):
        pathname = self.rule_dict['pathname']
        access = IPC_ACCESS.from_string(self.rule_dict['access'])
        action = BPFBOX_ACTION.from_actions(self.rule_actions)
        Commands.add_ipc_rule(exe, pathname, access, action)

class PtraceRule(RuleBase):
    def __init__(self, rule_dict: Dict):
        super().__init__(rule_dict)

    def __call__(self, exe):
        pathname = self.rule_dict['pathname']
        access = IPC_ACCESS.PTRACE
        action = BPFBOX_ACTION.from_actions(self.rule_actions)
        Commands.add_ipc_rule(exe, pathname, access, action)

class NetRule(RuleBase):
    def __init__(self, rule_dict: Dict):
        super().__init__(rule_dict)

    def __call__(self, exe):
        access = NET_ACCESS.from_string(self.rule_dict['access'])
        family = NET_FAMILY.from_string(self.rule_dict['family'])
        action = BPFBOX_ACTION.from_actions(self.rule_actions)
        Commands.add_net_rule(exe, access, family, action)


class PolicyGenerator:
    """
    Parses policy files and generates rules for the BPF programs to enforce.
    """

    def __init__(self):
        self.bnf = self._make_bnf()
        self.exe = None
        self.rules = []

    def process_policy_file(self, policy_file: str):
        with open(policy_file, 'r') as f:
            self.process_policy_text(f.read())

    def process_policy_text(self, policy_text: str):
        self._parse_policy_text(policy_text)

        for rule in self.rules:
            try:
                rule(self.exe)
            except Exception as e:
                logger.warning(f'Failed to apply rule {rule} for {self.exe}: {e}', exc_info=e)

    def _parse_policy_text(self, policy_text: str) -> Dict:
        try:
            return self.bnf.parseString(policy_text, True).asDict()
        except ParseException as pe:
            logger.error('Unable to parse profile:')
            logger.error("    " + pe.line)
            logger.error("    " + " " * (pe.column - 1) + "^")
            logger.error("    %s" % (pe))
            raise pe
        except Exception as e:
            logger.error(f'Fatal error while parsing policy text: {e}')

    def _add_rule(self, rule_dict):
        if rule_dict['type'] == 'fs':
            rule = FSRule(rule_dict)
        elif rule_dict['type'] == 'proc':
            rule = ProcFSRule(rule_dict)
        elif rule_dict['type'] == 'signal':
            rule = SignalRule(rule_dict)
        elif rule_dict['type'] == 'ptrace':
            rule = PtraceRule(rule_dict)
        elif rule_dict['type'] == 'net':
            rule = NetRule(rule_dict)
        else:
            raise Exception('Unknown rule type %s' % (rule_dict['type']))
        self.rules.append(rule)

    def _rule_action(self, toks):
        rule_dict = toks.asDict()['rules'][0]
        self._add_rule(rule_dict)

    def _block_action(self, toks):
        block_dict = toks.asDict()['blocks'][0]
        for rule_dict in block_dict['rules']:
            rule_dict['macros'] += block_dict['macros']
            self._add_rule(rule_dict)

    def _profile_macro_action(self, toks):
        self.exe = toks[0]
        try:
            Commands.add_profile(self.exe, True)
        except:
            pass

    def _make_bnf(self) -> ParserElement:
        # Special required macro for profile
        profile_macro = (
            Literal('#![').suppress()
            + Keyword('profile').suppress()
            + quoted_string('profile')
            + Literal(']').suppress()
            + LineEnd().suppress()
        ).setParseAction(self._profile_macro_action)

        # Rules
        rule = self._rule().setParseAction(self._rule_action)

        # Blocks
        block = self._block().setParseAction(self._block_action)

        return ZeroOrMore(comment) + profile_macro + ZeroOrMore(
            (rule('rules*') | block('blocks*') | comment)
        )

    def _self_exe(self, toks):
        return self.exe

    def _macro_contents(self) -> ParserElement:
        taint = Keyword('taint')
        allow = Keyword('allow')
        audit = Keyword('audit')
        return allow | taint | audit

    def _macro(self) -> ParserElement:
        macro_contents = self._macro_contents()
        return (
            Literal('#[').suppress() + macro_contents + Literal(']').suppress()
        )

    def _fs_rule(self) -> ParserElement:
        rule_type = Literal('fs')('type')
        return (
            rule_type
            + lparen
            + pathname('pathname')
            + comma
            + fs_access('access')
            + rparen
        )

    def _procfs_rule(self) -> ParserElement:
        rule_type = Literal('proc')('type')
        return rule_type + lparen + pathname('pathname') + comma + fs_access('access') + rparen

    def _signal_rule(self) -> ParserElement:
        rule_type = Literal('signal')('type')
        pathname_or_self = pathname | Keyword('self').setParseAction(self._self_exe)
        return rule_type + lparen + pathname_or_self('pathname') + comma + signal_access('access') + rparen

    def _ptrace_rule(self) -> ParserElement:
        rule_type = Literal('ptrace')('type')
        pathname_or_self = pathname | Keyword('self').setParseAction(self._self_exe)
        return rule_type + lparen + pathname_or_self('pathname') + rparen

    def _net_rule(self) -> ParserElement:
        rule_type = Literal('net')('type')
        return rule_type + lparen + net_family('family') + comma + net_access('access') + rparen

    def _rule(self) -> ParserElement:
        fs_rule = self._fs_rule()
        procfs_rule = self._procfs_rule()
        signal_rule = self._signal_rule()
        ptrace_rule = self._ptrace_rule()
        net_rule = self._net_rule()
        # TODO add more rule types here
        return Group(Group(ZeroOrMore(self._macro()))('macros') + (fs_rule | procfs_rule | signal_rule | ptrace_rule | net_rule))

    def _block(self) -> ParserElement:
        begin = Literal('{').suppress()
        end = Literal('}').suppress()
        return Group(
            Group(ZeroOrMore(self._macro()))('macros')
            + Group(begin + ZeroOrMore(self._rule()) + end)('rules')
        )
