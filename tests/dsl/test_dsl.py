from pprint import pprint, pformat

import pytest

from bpfbox.dsl import PolicyParser
from bpfbox.flags import BPFBOX_ACTION, FS_ACCESS, NET_ACCESS, NET_FAMILY, IPC_ACCESS

def test_dsl_smoke(policy_parser: PolicyParser):
    text = """
    #![profile "/usr/bin/ls"]

    #[allow] {
        #[audit]
        fs("/tmp/bpfbox/a", read|write|exec)
        #[taint]
        fs("/tmp/bpfbox/b", getattr|setattr|ioctl|rm)
    }

    fs("/tmp/bpfbox/c", read)

    #[taint]
    fs("/tmp/bpfbox/d", write)

    #[allow]
    #[audit] {
        #[taint]
        net(inet, bind|connect|accept)
        proc("/foo/bar/qux", read)
    }

    #[audit]
    signal('/usr/bin/grep', sigkill|sigchld)

    #[allow]
    ptrace(self)
    """

    policy = policy_parser.parse_policy_text(text)

    pprint(policy)

    assert policy.profile == '/usr/bin/ls'

    assert len(policy.rules) == 8

    assert policy.rules[0].action == BPFBOX_ACTION.ALLOW
    assert policy.rules[0].access == FS_ACCESS.READ
    assert policy.rules[0].pathname == '/tmp/bpfbox/c'

    assert policy.rules[1].action == BPFBOX_ACTION.TAINT
    assert policy.rules[1].access == FS_ACCESS.WRITE
    assert policy.rules[1].pathname == '/tmp/bpfbox/d'

    assert policy.rules[2].action == BPFBOX_ACTION.AUDIT
    assert policy.rules[2].access == IPC_ACCESS.SIGKILL | IPC_ACCESS.SIGCHLD
    assert policy.rules[2].other_exe == '/usr/bin/grep'

    assert policy.rules[3].action == BPFBOX_ACTION.ALLOW
    assert policy.rules[3].access == IPC_ACCESS.PTRACE
    assert policy.rules[3].other_exe == 'self'

    assert policy.rules[4].action == BPFBOX_ACTION.ALLOW|BPFBOX_ACTION.AUDIT
    assert policy.rules[4].access == FS_ACCESS.READ|FS_ACCESS.WRITE|FS_ACCESS.EXEC
    assert policy.rules[4].pathname == '/tmp/bpfbox/a'

    assert policy.rules[5].action == BPFBOX_ACTION.ALLOW|BPFBOX_ACTION.TAINT
    assert policy.rules[5].access == FS_ACCESS.GETATTR|FS_ACCESS.SETATTR|FS_ACCESS.IOCTL|FS_ACCESS.RM
    assert policy.rules[5].pathname == '/tmp/bpfbox/b'

    assert policy.rules[6].action == BPFBOX_ACTION.ALLOW|BPFBOX_ACTION.TAINT|BPFBOX_ACTION.AUDIT
    assert policy.rules[6].access == NET_ACCESS.BIND | NET_ACCESS.CONNECT | NET_ACCESS.ACCEPT
    assert policy.rules[6].family == NET_FAMILY.INET

    assert policy.rules[7].action == BPFBOX_ACTION.ALLOW|BPFBOX_ACTION.AUDIT
    assert policy.rules[7].access == FS_ACCESS.READ
    assert policy.rules[7].other_exe == '/foo/bar/qux'
