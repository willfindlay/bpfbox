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

#include <sys/types.h>

void add_profile(u_int64_t profile_key, u_int8_t taint_on_exec){};

void add_fs_rule(u_int64_t profile_key, u_int32_t st_ino, u_int32_t st_dev,
                 u_int32_t access_mask, u_int64_t state, u_int32_t action){};

void add_procfs_rule(u_int64_t subject_profile_key,
                     u_int64_t object_profile_key, u_int32_t access,
                     u_int64_t state,
                     u_int32_t action){};

void add_ipc_rule(u_int64_t subject_profile_key, u_int64_t object_profile_key,
                  u_int32_t access, u_int64_t state, u_int32_t action){};

void add_net_rule(u_int64_t profile_key, u_int32_t access, u_int32_t family, u_int64_t state,
                  u_int32_t action){};
