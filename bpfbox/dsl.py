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

from pprint import pprint
from pyparsing import Word, Literal, Forward, Group, ZeroOrMore, Keyword, OneOrMore, QuotedString

comma = Literal(',').suppress()

def macro():
    begin = Literal('#[').suppress()
    end = Literal(']').suppress()
    macro_keywords = (
            Keyword('start on')
            )
    expr = begin + OneOrMore(macro_keywords) + end
    return expr

def fs_rule():
    begin = Literal('fs(').suppress()
    end = Literal(')').suppress()
    pathname = QuotedString('"') | QuotedString("'")
    access = Word('rwaxligsd')
    expr = Group(begin + pathname('pathname') + comma + access('access') + end)
    return expr

def block():
    begin = Literal('{').suppress()
    end = Literal('}').suppress()
    expr = Group(OneOrMore(macro())('macros') + Group(begin + ZeroOrMore(fs_rule())('fs') + end)('rules'))
    return expr

if __name__ == '__main__':
    text = """
    #[start on] {
        fs('/usr/lib/testificate', rwx)
        fs('/usr/lib/foo', rwx)
        fs('/usr/lib/bar', rwxl)
        fs('/usr/lib/qux', ax)
    }
    """

    pprint(OneOrMore(block()).parseString(text).asDict())

    #text = """
    #    fs('/usr/lib/testificate', rwx)
    #    fs('/usr/lib/foo', rwx)
    #    fs('/usr/lib/bar', rwxl)
    #    fs('/usr/lib/qux', ax)
    #"""
    #pprint(OneOrMore(fs_rule()).parseString(text).asDict())
