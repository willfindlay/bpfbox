from textwrap import dedent
import ctypes as ct

from bcc import BPF

class Rules:
    """
    Defines rules that will be compiled into a BPF program to be tail called.
    """

    def __init__(self, bpf, flags):
        self.bpf = bpf
        self.flags = flags

    def __generate_rules(self):
        """
        Generate the eBPF syntax to express the rules.
        """
        generated_rules = []

        # FIXME: TESTING FOR NOW
        generated_rules.append("""
        if (args->id == 231)
            return 0;
                """)

        return generated_rules

    def __generate_bpf(self, profile):
        """
        Generate the BPF program that will be tail called for this profile.
        """
        # Get the profile's comm to help generate a semantic BPF program name
        comm = profile.comm.decode('utf-8')
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

    def generate(self, profile):
        """
        Use self.__generate_bpf to generate the correct BPF program, then associate it with the correct profile.
        """
        # Get tail call index from profile
        tail_call_index = profile.tail_call_index
        # Generate the function name and BPF source
        fn_name, source = self.__generate_bpf(profile)
        # Compile the tail call program
        tail_call_program = BPF(text=source, cflags=self.flags)
        # Load the tail call program
        fn = tail_call_program.load_func(fn_name, BPF.TRACEPOINT)
        # Associate the tail call program with the correct profile
        self.bpf['rules'][ct.c_int(tail_call_index)] = ct.c_int(fn.fd)
