import os
from itertools import count
import stat
from textwrap import dedent
import ctypes as ct

from bcc import BPF

from bpfbox.bpf.structs import BPFBoxProfileStruct
from bpfbox.defs import project_path
from bpfbox.utils import calculate_profile_key, get_inode_and_device
from bpfbox.logger import get_logger
from bpfbox.rules import FSRule, AccessMode

logger = get_logger()

TEMPLATE_PATH = os.path.join(project_path, 'bpfbox/bpf/templates')

# Read template for fs_policy
with open(os.path.join(TEMPLATE_PATH, 'fs_policy.c'), 'r') as f:
    FS_POLICY_TEMPLATE = f.read()


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
        self.binary = binary

        self.fs_allow_rules = []
        self.fs_taint_rules = []

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
        """
        Register BPF program with tail call index.
        """
        # fs policy
        fn = bpf.load_func(
            f'fs_policy_{self.profile_key}'.encode('utf-8'), BPF.KPROBE
        )
        bpf[b'fs_policy'][ct.c_int(self.tail_call_index)] = ct.c_int(fn.fd)
        # TODO other policy types here

    def register_profile_struct(self, bpf):
        """
        Generate and register profile struct with BPF program.
        """
        bpf[b'profiles'][
            ct.c_uint64(self.profile_key)
        ] = self._generate_profile_struct()

    def fs_allow(self, path: str, mode: AccessMode):
        """
        Add a filesystem allow rule.
        """
        self.fs_allow_rules.append(FSRule(path, mode))

    def fs_taint(self, path: str, mode: AccessMode):
        """
        Add a filesystem taint rule.
        """
        self.fs_taint_rules.append(FSRule(path, mode))

    def _infer_taint_on_exec(self):
        """
        Return True if we have no taint rules, False otherwise
        """
        return not self.fs_taint_rules  # TODO "and" with other taint rules

    def _generate_profile_struct(self):
        """
        Generate the profile struct to associate the binary and its tail call
        program.
        """
        struct = BPFBoxProfileStruct()
        struct.tail_call_index = self.tail_call_index
        struct.taint_on_exec = ct.c_uint8(int(self._infer_taint_on_exec()))
        return struct

    def _generate_fs_policy(self):
        """
        Generate the filesystem policy and return the corresponding BPF program.
        """
        text = FS_POLICY_TEMPLATE

        text = text.replace('PROFILEKEY', str(self.profile_key))

        allow_rules = (
            ' || '.join([rule.generate() for rule in self.fs_allow_rules])
            or '0'
        )
        text = text.replace('FS_ALLOW_RULES', allow_rules)

        taint_rules = (
            ' || '.join([rule.generate() for rule in self.fs_taint_rules])
            or '0'
        )
        text = text.replace('FS_TAINT_RULES', taint_rules)

        return text
