from textwrap import dedent
import ctypes as ct
import re

from bcc import BPF

from bpfbox.bpf import structs
from bpfbox.logger import get_logger
from bpfbox.utils import syscall_number

logger = get_logger()

class Rules:
    """
    Defines rules that will be compiled into a BPF program to be tail called.
    """

    rule_parser = re.compile(r'([a-zA-Z1-9_]+)\s*\(([^()]*)\)')

    def __init__(self, bpf, flags, profile):
        self.bpf = bpf
        self.flags = flags
        self.profile = profile
        self.rules = []

    def __generate_rules(self):
        """
        Generate the eBPF syntax to express the rules.
        """
        generated_rules = []

        # TODO: convert this so it makes more sense for semantic profiles
        for rule in self.rules:
            s = """
            if (args->id == {})
            {{
                return 0;
            }}
            """.format(rule['call'])
            generated_rules.append(s)

        return generated_rules

    def __generate_bpf(self):
        """
        Generate the BPF program that will be tail called for this profile.
        """
        # Get the profile's comm to help generate a semantic BPF program name
        comm = self.profile.comm.decode('utf-8')
        # The name of the BPF program that will be generated
        fn_name = f'{comm}_rules'
        # Beginning of BPF program
        start = """
        #include <linux/sched.h>

        int {}(struct tracepoint__raw_syscalls__sys_enter *args)
        {{
        """.format(fn_name)
        # End of BPF program
        end   = """
            // Default deny
            bpf_send_signal(SIGKILL); // FIXME: find a way to call enforce() here
            return 0;
        }}
        """.format()
        source = '\n'.join([start, *self.__generate_rules(), end])
        source = dedent(source)
        return fn_name, source

    def add_rule(self, rule):
        """
        TODO: convert this so it makes more sense for semantic profiles
        """
        match = Rules.rule_parser.fullmatch(rule.strip())
        if not match:
            logger.error(f'Unable to parse rule: {rule}.')
            return
        args = match[2].split(',')
        parsed_rule = {'call': syscall_number(match[1]), 'args': args}
        if not match:
            logger.error(f'Unable to parse rule {rule}.')
            return
        if parsed_rule['call'] < 0:
            logger.error(f'Unknown system call {match[1]} while parsing rule {rule}.')
            return
        logger.debug(f'Added rule {rule} to profile {self.profile.comm.decode("utf-8")}.')
        self.rules.append(parsed_rule)

    def generate(self):
        """
        Use self.__generate_bpf to generate the correct BPF program, then associate it with the correct profile.
        """
        # Get tail call index from profile
        tail_call_index = self.profile.tail_call_index
        # Generate the function name and BPF source
        fn_name, source = self.__generate_bpf()
        # Compile the tail call program
        tail_call_program = BPF(text=source, cflags=self.flags)
        # Load the tail call program
        fn = tail_call_program.load_func(fn_name, BPF.TRACEPOINT)
        # Associate the tail call program with the correct profile
        self.bpf['rules'][ct.c_int(tail_call_index)] = ct.c_int(fn.fd)
