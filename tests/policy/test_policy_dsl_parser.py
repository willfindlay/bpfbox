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
from bpfbox.dsl import macro, fs_rule, block

def test_valid_macros_smoke(caplog):
    text = """
    #[start on]
    """
    parsed = macro().parseString(text, True).asList()
    assert parsed == ['start on']

def test_invalid_macros_smoke(caplog):
    text = """
    #[start off]
    """
    with pytest.raises(ParseException):
        macro().parseString(text, True)

    text = """
    #[start on]]
    """
    with pytest.raises(ParseException):
        macro().parseString(text, True)

    text = """
    #[[start on]
    """
    with pytest.raises(ParseException):
        macro().parseString(text, True)

    text = """
    #[start on #[start on]]
    """
    with pytest.raises(ParseException):
        macro().parseString(text, True)

    text = """
    #[]
    """
    with pytest.raises(ParseException):
        macro().parseString(text, True)

    text = """
    #[start]
    """
    with pytest.raises(ParseException):
        macro().parseString(text, True)

    text = """
    #[on]
    """
    with pytest.raises(ParseException):
        macro().parseString(text, True)

def test_blocks_smoke(caplog):
    text = """
    #[start on] {
    }
    """
    parsed = block().parseString(text, True)
    assert parsed.macros.asList() == ['start on']
    with pytest.raises(KeyError):
        assert parsed['rules']

    text = """
    #[start on] {
        fs('/usr/lib/testificate', rwx)
        fs('/usr/lib/foo', rwx)
        fs('/usr/lib/bar', rwxl)
        fs('/usr/lib/qux', ax)
    }
    """
    parsed = block().parseString(text, True)
    assert parsed.macros.asList() == ['start on']
    assert parsed.fs_rules.asList() == ['start on']
