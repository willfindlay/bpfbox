import os
from itertools import count
import stat
from textwrap import dedent
import ctypes as ct

# TODO: we don't want glob in the final product, use our own syntax instead
from glob import glob

from bcc import BPF

from bpfbox.bpf.structs import BPFBoxProfileStruct
from bpfbox.defs import project_path
from bpfbox.utils import calculate_profile_key, powerperm
from bpfbox.logger import get_logger

logger = get_logger()

TEMPLATE_PATH = os.path.join(project_path, 'bpfbox/bpf/templates')

# Read template for fs_policy
with open(os.path.join(TEMPLATE_PATH, 'fs_policy.c'), 'r') as f:
    FS_POLICY_TEMPLATE = f.read()


class PolicyGenerationError(Exception):
    def __init__(self, hint):
        self.hint = hint
        super().__init__()


class Policy:
    """
    Provide's userspace's perspective of a bpfbox profile.
    """

    # This allows us to auto increment subsequent tail call indices in a
    # thread-safe manner. (Thread safety is not a concern at the moment,
    # but this is an easy way of future-proofing the code.)
    _next_tail_call_index = count()
    next(_next_tail_call_index)

    def __init__(self, binary):
        self.tail_call_index = next(Policy._next_tail_call_index)
        # TODO: deal with interpreted scripts
        self.profile_key = calculate_profile_key(binary)
        self.comm = binary

        self.fs_read_rules = []
        self.fs_write_rules = []
        self.fs_append_rules = []
        self.fs_exec_rules = []

    @classmethod
    def from_policy_file(path):
        """
        Load policy file at <path> and use it to create a policy object.
        """
        with open(path, 'r') as f:
            policy_text = f.read()
        # TODO

    def generate_bpf_program(self):
        """
        Generate the BPF programs based on the policy.
        """
        fs_policy = self._generate_fs_policy()
        # TODO generate other policy types here
        return dedent('\n'.join([fs_policy]))

    def register_tail_calls(self, bpf):
        # fs policy
        fn = bpf.load_func(f'fs_policy_{self.profile_key}', BPF.KPROBE)
        bpf['fs_policy'][ct.c_int(self.tail_call_index)] = ct.c_int(fn.fd)
        # TODO other policy types here
        # register profile struct
        struct = BPFBoxProfileStruct()
        struct.tail_call_index = self.tail_call_index
        bpf['profiles'][ct.c_uint64(self.profile_key)] = struct

    def _generate_fs_rule(self, mode, path, taint=False):
        """
        Generate an ALLOW rule for operation(s) <mode> on file <path>
        """
        if mode not in powerperm(['r', 'w', 'a', 'x']):
            raise PolicyGenerationError('Mode should be one of r,w,a,x.')

        # Path is a directory
        if os.path.isdir(path):
            rule = f'parent_inode == {os.lstat(path)[stat.ST_INO]}'
        # Path is a file
        elif os.path.isfile(path):
            rule = f'inode == {os.lstat(path)[stat.ST_INO]}'

        if 'r' in mode:
            self.fs_read_rules.append(rule)
        if 'w' in mode:
            self.fs_write_rules.append(rule)
        if 'a' in mode:
            self.fs_append_rules.append(rule)
        if 'x' in mode:
            self.fs_exec_rules.append(rule)

    def _generate_fs_policy(self):
        """
        Generate the filesystem policy and return the corresponding BPF program.
        """
        text = FS_POLICY_TEMPLATE
        text = text.replace('PROFILEKEY', str(self.profile_key))
        text = text.replace(
            'FS_READ_POLICY',
            ' || '.join(self.fs_read_rules) if self.fs_read_rules else '0',
        )
        text = text.replace(
            'FS_WRITE_POLICY',
            ' || '.join(self.fs_write_rules) if self.fs_write_rules else '0',
        )
        text = text.replace(
            'FS_APPEND_POLICY',
            ' || '.join(self.fs_append_rules) if self.fs_append_rules else '0',
        )
        text = text.replace(
            'FS_EXEC_POLICY',
            ' || '.join(self.fs_exec_rules) if self.fs_exec_rules else '0',
        )
        return text
