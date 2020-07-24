from pprint import pprint

import pytest

from bpfbox.dsl import PolicyGenerator

def test_dsl_smoke(policy_generator: PolicyGenerator):
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
    """

    ##[allow]
    ##[audit] {
    #    #[taint]
    #    net(inet, bind|connect|accept)
    #    #[taint] {
    #        net(inet6, bind|connect|accept)
    #    }
    #}
    #"""

    parsed = policy_generator._parse_policy_text(text)
    pprint(parsed)
    assert False
