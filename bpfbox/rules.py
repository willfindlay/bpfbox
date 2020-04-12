import ctypes as ct

from bcc import BPF, libbcc

from bpfbox import defs

class RulesDefinition:
    """
    Defines a rule for whitelisting of a given process.
    TODO/FIXME: Need to re-work this to make the API more intuitive.
    """

    TEMPLATE = """
    #include "bpfbox/bpf/bpf_program.h"

    int rule(struct pt_regs *ctx)
    {{
        {}

        /* Default deny */
        bpf_send_signal(SIGKILL);

        return 0;
    }}
    """

    def __init__(self, bpf, index):
        self.index = index
        self.bpf = bpf
        self.rules = []
        self.flags = [f'-I{defs.project_path}']
        self.reload()

    def add_rule(self, rule):
        self.rules.append(rule)
        self.reload()

    def reload(self):
        text = self.TEMPLATE.format('\n'.join(self.rules))
        temp = BPF(text=text, cflags=self.flags)
        fn = temp.load_func('rule', BPF.TRACEPOINT)
        self.bpf['rules'][ct.c_int(self.index)] = ct.c_int(fn.fd)
