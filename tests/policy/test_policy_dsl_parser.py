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

    Tests bpfbox's policy DSL parsing.

    2020-Jul-04  William Findlay  Created this.
"""

import pytest
from pyparsing import ParseException
from bpfbox.dsl import Parser

parser = Parser()

def test_macro_smoke():
    macro = parser._macro()

    macro.parseString('#[allow]', True)
    macro.parseString('#[taint]', True)
    macro.parseString('#[audit]', True)

def test_bad_macro_syntax_smoke():
    macro = parser._macro()

    with pytest.raises(ParseException):
        macro.parseString('#[allow allow]', True)

    with pytest.raises(ParseException):
        macro.parseString('#[allow] #[allow]', True)

    with pytest.raises(ParseException):
        macro.parseString('#allow', True)

    with pytest.raises(ParseException):
        macro.parseString('[allow]', True)

    with pytest.raises(ParseException):
        macro.parseString('#[allow', True)

    with pytest.raises(ParseException):
        macro.parseString('allow]', True)

    with pytest.raises(ParseException):
        macro.parseString('#[[allow]', True)

    with pytest.raises(ParseException):
        macro.parseString('#[allow]]', True)

    with pytest.raises(ParseException):
        macro.parseString('#[[allow]]', True)

    with pytest.raises(ParseException):
        macro.parseString('allow', True)

def test_rule_smoke():
    rule = parser._rule()

    rule.parseString('fs("/usr/lib/test", rwx)', True)
    rule.parseString('fs(\'/usr/lib/test\', rwx)', True)
    rule.parseString('fs("/usr/lib/test", rwxlaigsd)', True)

def test_bad_rule_syntax_smoke():
    rule = parser._rule()

    with pytest.raises(ParseException):
        rule.parseString('fs("/usr/lib/test, rwx)', True)

    with pytest.raises(ParseException):
        rule.parseString('fs("/usr/lib/test, rwzzzzzzx)', True)

    with pytest.raises(ParseException):
        rule.parseString('fs("/usr/lib/test, rw x)', True)

    with pytest.raises(ParseException):
        rule.parseString('fs("/usr/lib/test, rw, x)', True)

    with pytest.raises(ParseException):
        rule.parseString('ffs("/usr/lib/test, rwx)', True)

def test_block_smoke():
    block = parser._block()

    text = """
    {}
    """
    block.parseString(text, True)

    text = """
    #[allow]
    {
        fs('/usr/lib/test', rwx)
    }
    """
    block.parseString(text, True)

    text = """
    #[allow]
    #[taint]
    #[audit]
    {
        fs('/usr/lib/test', rwx)
    }
    """
    block.parseString(text, True)

    text = """
    #[allow]
    #[taint]
    #[audit]
    {
        fs('/usr/lib/test', rwx)
        fs('/var/log/test', ra)
    }
    """
    block.parseString(text, True)

def test_bad_block_syntax_smoke():
    block = parser._block()

    text = """
    {{}
    """
    with pytest.raises(ParseException):
        block.parseString(text, True)

    text = """
    {
        fs('/usr/lib/test', rwx)
    }
    #[allow]
    """
    with pytest.raises(ParseException):
        block.parseString(text, True)

    text = """
    #[allow]
    #[taint]
    #[audit]
    {
        {fs('/usr/lib/test', rwx)}
    }
    """
    with pytest.raises(ParseException):
        block.parseString(text, True)

    text = """
    #[allow]
    #[taint]
    #[audit]
        fs('/usr/lib/test', rwx)
        fs('/var/log/test', ra)
    }
    """
    with pytest.raises(ParseException):
        block.parseString(text, True)
