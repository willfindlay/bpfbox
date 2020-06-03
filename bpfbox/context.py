import os
from typing import Union

from bcc import BPF

from bpfbox.policy import Policy
from bpfbox.rules import RuleAction, AccessMode, FSRule, NetRule
from bpfbox.defs import project_path
from bpfbox.utils import calculate_profile_key


TEMPLATE_PATH = os.path.join(project_path, 'bpfbox/bpf/templates')

# Read template for uprobes
with open(os.path.join(TEMPLATE_PATH, 'uprobes.c'), 'r') as f:
    UPROBES_TEMPLATE = f.read()


class RuleContext:
    """RuleContext.
    """

    def __init__(
        self,
        binary: str,
        context_mask: int = None,
        addr: int = None,
        sym: bytes = b'',
    ):
        assert isinstance(binary, str)
        assert not context_mask or isinstance(context_mask, int)
        assert not addr or isinstance(addr, int)
        assert isinstance(sym, bytes)
        if context_mask:
            assert addr or sym
        if addr or sym:
            assert context_mask

        self.binary = binary
        self.profile_key = calculate_profile_key(binary)
        self.context_mask = context_mask

        self.addr = addr
        self.sym = sym

        self.fs_rules = []
        self.net_rules = []

    def fs_allow(self, path: str, mode: AccessMode) -> 'RuleContext':
        """
        Add a filesystem allow rule.
        """
        self.fs_rules.append(FSRule(path, mode, RuleAction.ALLOW))
        return self

    def fs_taint(self, path: str, mode: AccessMode) -> 'RuleContext':
        """
        Add a filesystem taint rule.
        """
        self.fs_rules.append(FSRule(path, mode, RuleAction.TAINT))
        return self

    def generate_uprobes(self) -> str:
        if not self.addr and not self.sym:
            return ''

        text = UPROBES_TEMPLATE
        text = text.replace('CONTEXTMASK', str(self.context_mask))
        text = text.replace('PROFILEKEY', str(self.profile_key))

    def attach_uprobes(self, bpf: BPF) -> None:
        if not self.addr and not self.sym:
            return

        uprobe = f'uprobe_{self.context_mask}_{self.profile_key}'
        uretprobe = f'uretprobe_{self.context_mask}_{self.profile_key}'

        bpf.attach_uprobe(
            name=self.binary, sym=self.sym, addr=self.addr, fn_name=uprobe,
        )
        bpf.attach_uretprobe(
            name=self.binary, sym=self.sym, addr=self.addr, fn_name=uretprobe,
        )

    def generate_rules(self) -> dict:
        return {
            'FS_RULES': self._generate_fs_rules(),
            'BIND_RULES': self._generate_net_bind_rules(),
            'CONNECT_RULES': self._generate_net_connect_rules(),
            'SEND_RULES': self._generate_net_send_rules(),
            'RECV_RULES': self._generate_net_recv_rules(),
        }

    def _generate_fs_rules(self) -> str:
        return '\n'.join([r.generate() for r in self.fs_rules])

    def _generate_net_bind_rules(self) -> str:
        pass
        # TODO
        return ''

    def _generate_net_connect_rules(self) -> str:
        pass
        # TODO
        return ''

    def _generate_net_send_rules(self) -> str:
        pass
        # TODO
        return ''

    def _generate_net_recv_rules(self) -> str:
        pass
        # TODO
        return ''
