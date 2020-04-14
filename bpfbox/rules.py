import os, sys
from abc import ABC
from enum import Enum

from bpfbox import defs
from bpfbox.utils import syscall_number

class ACTIONS(Enum):
    ALLOW = 0
    DENY  = 1

    @classmethod
    def str_to_action(_class, s):
        try:
            s = s.lower().strip()
        except AttributeError:
            return None
        if s == 'allow':
            return ACTIONS.ALLOW
        if s == 'deny':
            return ACTIONS.DENY
        return None

class RuleBase(ABC):
    """
    Base class for the definition of rules.

    Rules should at least consist of:
        - A path to the executable (from which we derive the key (devnum << 32 + inode))
        - An system call (maybe expand to include other events later?)
    """

    def __init__(self, path, syscall):
        self.path = path
        self.syscall = syscall if isinstance(syscall, int) else syscall_number(syscall)
        self.key = self.derive_key_from_path(path)
        # Setup rule base text
        self.text = {'prefix': '', 'body': '', 'suffix': ''}
        self.text['prefix'] = f'if (process->profile_key == {self.key} && args->id == {self.syscall}) {{'
        self.text['suffix'] = f'return 0; }}'

    def derive_key_from_path(self, path):
        """
        Derive a profile key from a path.
        """
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            # TODO: print warning to logs here
            return 0
        key = stat.st_ino + (stat.st_dev << 32)
        return key

    def generate_bpf(self):
        """
        Generate the BPF program component that corresponds to this rule.
        """
        return ' '.join([self.text['prefix'], self.text['body'], self.text['suffix']])

class StartEnforcementRule(RuleBase):
    """
    A rule that defines when a process should start enforcing.
    """
    def __init__(self, path, syscall):
        RuleBase.__init__(self, path, syscall)
        # Generate body
        self.text['body'] = 'process->enforcing = true;'

class ActionRule(RuleBase):
    """
    A rule that defines what action to perform on a system call.
    """
    def __init__(self, path, syscall, action):
        RuleBase.__init__(self, path, syscall)
        self.action = action if isinstance(action, ACTIONS) else ACTIONS.str_to_action(action)
        if self.action is None:
            self.action = ACTIONS.DENY
        # Generate body
        if self.action == ACTIONS.DENY:
            self.text['body'] = 'bpf_send_signal(SIGKILL);'
