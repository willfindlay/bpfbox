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
from bpfbox.utils import calculate_profile_key, powerperm, get_inode_and_device
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

    # Types of rules
    TAINT_RULE = 1
    ALLOW_RULE = 2

    def __init__(self, binary, taint_on_exec=False):
        self.tail_call_index = next(Policy._next_tail_call_index)
        # TODO: deal with interpreted scripts
        self.profile_key = calculate_profile_key(binary)
        self.taint_on_exec = taint_on_exec
        self.binary = binary

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
        for line in policy_text:
            pass
            # TODO

    def generate_bpf_program(self):
        """
        Generate the BPF programs based on the policy.
        """
        fs_policy = self._generate_fs_policy()
        logger.debug(fs_policy)
        # TODO generate other policy types here
        return dedent('\n'.join([fs_policy]))

    def register_tail_calls(self, bpf):
        # fs policy
        fn = bpf.load_func(f'fs_policy_{self.profile_key}', BPF.KPROBE)
        bpf['fs_policy'][ct.c_int(self.tail_call_index)] = ct.c_int(fn.fd)
        # TODO other policy types here
        # register profile struct
        bpf['profiles'][
            ct.c_uint64(self.profile_key)
        ] = self._generate_profile_struct()

    def _generate_profile_struct(self):
        struct = BPFBoxProfileStruct()
        struct.tail_call_index = self.tail_call_index
        struct.taint_on_exec = ct.c_uint8(int(self.taint_on_exec))
        return struct

    def _generate_fs_rule(self, mode, path, rule_type=ALLOW_RULE):
        """
        Generate an ALLOW rule for operation(s) <mode> on file <path>
        """
        if mode not in powerperm(['r', 'w', 'a', 'x']):
            raise PolicyGenerationError('Mode should be one of r,w,a,x.')

        # If path refers to a directory, we want our generated rule to refer to
        # the parent directory of files
        inode_var = 'parent_inode' if os.path.isdir(path) else 'inode'

        if rule_type == Policy.TAINT_RULE:
            pass
        else:
            st_ino, st_dev = get_inode_and_device(path)
            rule = f'({inode_var} == {st_ino} && st_dev == {st_dev})'

        if 'r' in mode:
            self.fs_read_rules.append((rule, rule_type))
        if 'w' in mode:
            self.fs_write_rules.append((rule, rule_type))
        if 'a' in mode:
            self.fs_append_rules.append((rule, rule_type))
        if 'x' in mode:
            self.fs_exec_rules.append((rule, rule_type))

    def _generate_fs_policy(self):
        """
        Generate the filesystem policy and return the corresponding BPF program.
        """
        text = FS_POLICY_TEMPLATE
        # Replace PROFILEKEY with our profile key
        text = text.replace('PROFILEKEY', str(self.profile_key))
        # Read policy
        text = text.replace(
            'FS_READ_POLICY',
            ' || '.join(
                [
                    rule[0]
                    for rule in self.fs_read_rules
                    if rule[1] == Policy.ALLOW_RULE
                ]
            )
            if self.fs_read_rules
            else '0',
        )
        # Write policy
        text = text.replace(
            'FS_WRITE_POLICY',
            ' || '.join(
                [
                    rule[0]
                    for rule in self.fs_write_rules
                    if rule[1] == Policy.ALLOW_RULE
                ]
            )
            if self.fs_write_rules
            else '0',
        )
        # Append policy
        text = text.replace(
            'FS_APPEND_POLICY',
            ' || '.join(
                [
                    rule[0]
                    for rule in self.fs_append_rules
                    if rule[1] == Policy.ALLOW_RULE
                ]
            )
            if self.fs_append_rules
            else '0',
        )
        # Exec policy
        text = text.replace(
            'FS_EXEC_POLICY',
            ' || '.join(
                [
                    rule[0]
                    for rule in self.fs_exec_rules
                    if rule[1] == Policy.ALLOW_RULE
                ]
            )
            if self.fs_exec_rules
            else '0',
        )
        return text
