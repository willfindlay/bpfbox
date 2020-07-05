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

from pyparsing import *

from bpfbox.bpf_program import BPFProgram
from bpfbox.logger import get_logger
from bpfbox.flags import BPFBOX_ACTION, FS_ACCESS

logger = get_logger()

comma = Literal(',').suppress()
quoted_string = (QuotedString('"') | QuotedString("'"))
comment = QuotedString(quoteChar='/*', endQuoteChar='*/', multiline=True).suppress()
lparen = Literal('(').suppress()
rparen = Literal(')').suppress()


class PolicyGenerator:
    def __init__(self, bpf_program: BPFProgram):
        self.bpf_program = bpf_program
        self.bnf = self._make_bnf()

    def parse_profile_text(self, profile_text: str) -> Dict:
        try:
            return self.bnf.parseString(profile_text, True).asDict()
        except ParseException as pe:
            logger.error('Unable to parse profile:')
            logger.error("    " + pe.line)
            logger.error("    " + " " * (pe.column - 1) + "^")
            logger.error("    %s" % (pe))
            raise pe

    def _make_bnf(self) -> ParserElement:
        # Special required macro for profile
        profile_macro = Literal('#![').suppress() + Keyword('profile').suppress() + \
                quoted_string('profile') +  Literal(']').suppress() + LineEnd().suppress()

        # Rules
        rule = self._rule()

        # Blocks
        block = self._block()

        return profile_macro & ZeroOrMore((rule('rules*') | block('blocks*') | comment))

    def _macro_contents(self):
        taint = Keyword('taint')
        allow = Keyword('allow')
        audit = Keyword('audit')
        return (allow | taint | audit)

    def _macro(self):
        macro_contents = self._macro_contents()
        return Literal('#[').suppress() + macro_contents + Literal(']').suppress()

    def _fs_rule(self):
        rule_type = Literal('fs')('type')
        pathname = quoted_string
        access = Word('rwaxligsu')
        return rule_type + lparen + pathname('pathname') + comma + access('access') + rparen

    def _procfs_rule(self):
        rule_type = Literal('proc')('type')
        pathname = quoted_string
        return rule_type + lparen + pathname('pathname') + rparen

    def _rule(self):
        fs_rule = self._fs_rule()
        procfs_rule = self._procfs_rule()
        # TODO add more rule types here
        return Group(ZeroOrMore(self._macro())('macros') + (fs_rule | procfs_rule))

    def _block(self):
        begin = Literal('{').suppress()
        end = Literal('}').suppress()
        return Group(ZeroOrMore(self._macro())('macros') + Group(begin + ZeroOrMore(self._rule()) + end)('rules'))