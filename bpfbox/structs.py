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

    This file provides ctypes structures to match those defined in
    the BPF program. Only those that are needed are defined.

    **********************************************************************
    **********************************************************************
       WARNING: Keep this file in sync with bpf/policy.c at all times!
    **********************************************************************
    **********************************************************************

    2020-Jun-29  William Findlay  Created this.
"""

import ctypes as ct


class BPFBoxProfile(ct.Structure):
    _fields_ = (('taint_on_exec', ct.c_uint8),)


class Policy(ct.Structure):
    _fields_ = (
        ('allow', ct.c_uint32),
        ('taint', ct.c_uint32),
    )


class InodePolicyKey(ct.Structure):
    _fields_ = (
        ('st_ino', ct.c_uint32),
        ('st_dev', ct.c_uint32),
        ('profile_key', ct.c_uint64),
    )
