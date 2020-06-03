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

    William Findlay created this.
        williamfindlay <àŧ> cmail.carleton.ca

    This file defines ctypes structures that correspond to the
    structs defined in our BPF program. This is useful for defining
    structs in userspace and populating the BPF program's maps.

                  WARNING WARNING WARNING WARNING

                  Keep in sync with bpf_program.h

                  WARNING WARNING WARNING WARNING
"""

import ctypes as ct


class BPFBoxProfileStruct(ct.Structure):
    _fields_ = (('tail_call_index', ct.c_int), ('taint_on_exec', ct.c_uint8))
