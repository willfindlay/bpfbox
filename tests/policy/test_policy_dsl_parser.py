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
from pyparsing import ParseException, Group
from bpfbox.dsl import PolicyGenerator
from pprint import pprint

parser = PolicyGenerator()

def test_macro_smoke():
    macro = parser._macro()

    parsed = macro.parseString('#[allow]', True)
    assert parsed.asList() == ['allow']

    parsed = macro.parseString('#[taint]', True)
    assert parsed.asList() == ['taint']

    parsed = macro.parseString('#[audit]', True)
    assert parsed.asList() == ['audit']


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
    rule = parser._rule()('rule')

    parsed = rule.parseString('fs("/usr/lib/test", rwx)', True)
    assert parsed.rule.pathname == '/usr/lib/test'
    assert parsed.rule.access == 'rwx'

    parsed = rule.parseString('fs(\'/usr/lib/test\', rwx)', True)
    assert parsed.rule.pathname == '/usr/lib/test'
    assert parsed.rule.access == 'rwx'

    parsed = rule.parseString('fs("/usr/lib/test", rwxlaigsu)', True)
    assert parsed.rule.pathname == '/usr/lib/test'
    assert parsed.rule.access == 'rwxlaigsu'


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


def test_policy_smoke():
    text = """
    /* This is the profile name */
    #![profile '/usr/bin/ls']

    /* This is a block of taint rules */
    #[taint] {
        fs('/usr/lib/test', rwx)
        fs('/usr/lib/foo', rwx)
        #[allow]
        fs('/usr/lib/bar', rwxl)
        fs('/usr/lib/qux', ax)
    }

    /* This
       is
       a
       silly
       example
       of
       a
       multiline
       comment */

    /* A lone rule, without a macro */
    fs('/usr/lib/baz', r)

    #[allow]
    #[audit]
    #[taint] {
        fs('/var/lib/hello', rwx)
        fs('/var/lib/goodbye', rwx)
    }

    /* Since this is not a block, this macro applies
       only to the rule immediately following it. */
    #[audit]
    fs('/usr/lib/test', rwx)
    /* These rules have no macros */
    fs('/usr/lib/foo', rwx)
    fs('/usr/lib/bar', rwxl)
    """
    parsed = parser._parse_policy_text(text)
    pprint(parsed)

    # Profile
    assert parsed['profile'] == '/usr/bin/ls'

    # Correct number of blocks
    assert len(parsed['blocks']) == 2

    # First block
    assert parsed['blocks'][0]['macros'] == ['taint']
    assert len(parsed['blocks'][0]['rules']) == 4

    # Correct first block contents
    assert {'type': 'fs', 'pathname': '/usr/lib/test', 'macros': [], 'access': 'rwx'} in parsed['blocks'][0]['rules']
    assert {'type': 'fs', 'pathname': '/usr/lib/foo', 'macros': [], 'access': 'rwx'} in parsed['blocks'][0]['rules']
    assert {'type': 'fs', 'pathname': '/usr/lib/bar', 'macros': [], 'macros': ['allow'], 'access': 'rwxl'} in parsed['blocks'][0]['rules']
    assert {'type': 'fs', 'pathname': '/usr/lib/qux', 'macros': [], 'access': 'ax'} in parsed['blocks'][0]['rules']

    # Second block
    assert parsed['blocks'][1]['macros'] == ['allow', 'audit', 'taint']
    assert len(parsed['blocks'][1]['rules']) == 2

    # Correct second block contents
    assert {'type': 'fs', 'pathname': '/var/lib/hello', 'macros': [], 'access': 'rwx'} in parsed['blocks'][1]['rules']
    assert {'type': 'fs', 'pathname': '/var/lib/goodbye', 'macros': [], 'access': 'rwx'} in parsed['blocks'][1]['rules']

    # Correct number of rules
    assert len(parsed['rules']) == 4

    # Correct rule contents
    assert {'type': 'fs', 'pathname': '/usr/lib/baz', 'macros': [], 'access': 'r'} in parsed['rules']
    assert {'type': 'fs', 'pathname': '/usr/lib/test', 'macros': ['audit'], 'access': 'rwx'} in parsed['rules']
    assert {'type': 'fs', 'pathname': '/usr/lib/foo', 'macros': [], 'access': 'rwx'} in parsed['rules']
    assert {'type': 'fs', 'pathname': '/usr/lib/bar', 'macros': [], 'access': 'rwxl'} in parsed['rules']

def test_bad_policy_syntax_smoke():
    text = """
    #![profile '/usr/bin/ls']
    #![profile '/usr/bin/ls']
    """
    with pytest.raises(ParseException):
        parser._parse_policy_text(text)

    text = """
    #![profile '/usr/bin/ls']
    /* sdfhsodfhosdifhgosdfho
    """
    with pytest.raises(ParseException):
        parser._parse_policy_text(text)

    text = """
    /*#![profile '/usr/bin/ls']*/
    """
    with pytest.raises(ParseException):
        parser._parse_policy_text(text)

    text = """
    """
    with pytest.raises(ParseException):
        parser._parse_policy_text(text)

    text = """
    #![profile '/usr/bin/ls']
    /* hello /* There */ */
    """
    with pytest.raises(ParseException):
        parser._parse_policy_text(text)

    # We don't support nested blocks right now
    text = """
    #![profile '/usr/bin/ls']

    #[allow]
    #[audit]
    {
        fs('/var/log/file.txt', w)
        #[taint]
        {
            fs('/var/log/file.txt', r)
        }
    }
    """
    with pytest.raises(ParseException):
        parser._parse_policy_text(text)
