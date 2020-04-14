import os, sys
import atexit
import signal
import time

from bcc import BPF

from bpfbox.rules import ACTIONS, StartEnforcementRule, ActionRule
from bpfbox import defs
from bpfbox.daemon_mixin import DaemonMixin, DaemonNotRunningError

hello = StartEnforcementRule('/bin/ls', 'read')

signal.signal(signal.SIGTERM, lambda x,y: sys.exit(0))
signal.signal(signal.SIGINT, lambda x,y: sys.exit(0))

class BPFBoxd(DaemonMixin):
    """
    BPFBox's daemon class.
    Manages BPF programs and reads events in an event loop.
    """
    def __init__(self, args):
        self.bpf = None
        self.ticksleep = defs.ticksleep
        self.enforcing = args.enforcing
        self.rules = []
        # FIXME: Detete this, just for testing
        self.rules = [
                StartEnforcementRule('/bin/ls', 'brk'),
                ActionRule('/bin/ls', 'capget', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'rt_sigaction', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'exit_group', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'openat', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'close', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'mmap', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'connect', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'fstat', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'read', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'socket', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'munmap', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'lseek', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'write', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'mprotect', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'lstat', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'getxattr', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'getdents64', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'brk', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'ioctl', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'pread64', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'access', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'prctl', ACTIONS.ALLOW),
                ActionRule('/bin/ls', 'arch_prctl', ACTIONS.ALLOW),
                ]

    def init_bpf(self):
        """
        Initialize BPF program.
        """
        assert self.bpf is None
        # Read BPF program
        with open(defs.bpf_prog_path, 'r') as f:
            text = f.read()
        # Set flags
        flags = []
        flags.append(f'-I{defs.project_path}')
        if self.enforcing:
            flags.append(f'-DBPFBOX_ENFORCING')
        # Set rules
        # TODO: We will start dynamically generating rules at some point, so this will be different
        text = self.generate_bpf_rules(text)
        # Load the bpf program
        self.bpf = BPF(text=text, cflags=flags)
        # Register exit hooks
        atexit.register(self.cleanup)
        # Register perf buffers
        self.register_perf_buffers()

    def generate_bpf_rules(self, text):
        """
        Generate BPF text for rules and sub them into main BPF text.
        """
        action_text = '\n'.join([rule.generate_bpf() for rule in self.rules
            if isinstance(rule, ActionRule)])
        start_enforcement_text = '\n'.join([rule.generate_bpf() for rule in self.rules
            if isinstance(rule, StartEnforcementRule)])
        text = text.replace('__BPFBOX_ACTION_RULES', action_text)
        text = text.replace('__BPFBOX_START_ENFORCEMENT_RULES', start_enforcement_text)
        return text

    def register_perf_buffers(self):
        """
        Define and register perf buffers.
        """
        # TODO/FIXME: This is probably NOT the way we want to create rules
        #             Rather, rules should be auto-generated based on collected profiles
        def on_profile_create(cpu, data, size):
            event = self.bpf['on_profile_create'].event(data)
        self.bpf['on_profile_create'].open_perf_buffer(on_profile_create)

    def write_profile_data_to_disk(self):
        """
        Write all profile data to disk.
        """
        pass

    def cleanup(self):
        """
        Perform cleanup hooks before exit.
        """
        # FIXME: delete this, for testing purposes
        for profile in self.bpf['profiles'].values():
            print(f'{profile.comm.decode("utf-8")} has tail call index {profile.tail_call_index}')
        self.write_profile_data_to_disk()
        self.bpf = None

    def loop_forever(self):
        """
        BPFBoxd main event loop.
        """
        self.init_bpf()
        while 1:
            self.bpf.perf_buffer_poll(30)
            time.sleep(self.ticksleep)

def main(args):
    """
    Main entrypoint for BPFBox daemon.
    Generally should be invoked with parse_args.
    """
    defs.init()
    b = BPFBoxd(args)

    if args.nodaemon:
        print('Starting in foreground mode...', file=sys.stderr)
        b.loop_forever()
        sys.exit(0)

    if args.operation == 'start':
        b.start_daemon()
    if args.operation == 'stop':
        try:
            b.stop_daemon()
        except DaemonNotRunningError:
            print('pidfile for bpfboxd is empty. If the daemon is still running, '
                  'you may need to kill manually.', file=sys.stderr)
    if args.operation == 'restart':
        b.restart_daemon()
