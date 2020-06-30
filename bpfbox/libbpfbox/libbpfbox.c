/*
 *  🐝 BPFBox 📦  Application-transparent sandboxing rules with eBPF.
 *  Copyright (C) 2020  William Findlay
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Provides an interface to libbpfbox, which is used to issue complex
 *  commands to the BPF program. BPFBox instruments uprobes on itself and
 *  calls these functions as needed.  Doing it this way saves on bpf(2)
 *  syscalls for operations like adding rules.
 *
 *  **********************************************************************
 *  **********************************************************************
 *     WARNING: Keep this file in sync with __init__.py at all times!
 *  **********************************************************************
 *  **********************************************************************
 *
 *  2020-Jun-29  William Findlay  Created this.
 */

void add_profile(unsigned long long profile_key, unsigned char taint_on_exec){};

void add_fs_rule(unsigned long long profile_key, unsigned long st_ino,
                 unsigned long st_dev, unsigned long access_mask,
                 unsigned int action){};
