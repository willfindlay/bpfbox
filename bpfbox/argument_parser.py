import os, sys
import argparse

from bpfbox.utils import check_root

DESCRIPTION = """
🐝 BPFBox 📦
External, application-transparent, dynamic sandboxing with eBPF.
"""

EPILOG = """
"""

OPERATIONS = [
        'start',
        'stop',
        'restart',
        ]

def parse_args(sysargs=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    # Setup arguments
    # Operations
    operations = parser.add_argument_group('operations')
    operation = operations.add_mutually_exclusive_group()
    operation.add_argument('operation', choices=OPERATIONS, nargs='?',
            help='Operation to perform. One of ' + ', '.join(OPERATIONS) + '.')
    operation.add_argument('--nodaemon', action='store_true',
            help='Run as a foreground process instead of daemonizing. '
            'Required if not specifying an operation.')
    # Enforcement options
    enforcement = parser.add_argument_group('enforcement')
    enforcement_mode = enforcement.add_mutually_exclusive_group()
    enforcement_mode.add_argument('--enforcing', action='store_const', dest='enforcing', const=True, default=True,
            help='Run in enforcing mode. Kill all enforcing processes that violate policy.')
    enforcement_mode.add_argument('--permissive', action='store_const', dest='enforcing', const=False,
            help='Run in permissive mode. Write violations to logs, but do not kill them.')
    # Logging options
    log_options = parser.add_argument_group('logging')
    verbosity = log_options.add_mutually_exclusive_group()
    verbosity.add_argument('--verbose', '-v', action='store_true',
            help='Log in verbose mode.')
    verbosity.add_argument('--debug', action='store_true',
            help='Log in debug mode.')
    log_options.add_argument('--stdout', action='store_true',
            help='Write to terminal instead of log file. Only makes sense when running with --nodaemon.')
    # Miscellaneous options
    misc_options = parser.add_argument_group('misc.')

    # Parse arguments
    args = parser.parse_args(sysargs)

    # Check for correct permissions
    if not check_root():
        parser.error(f'{parser.prog} must be run with root privileges.')

    # Check for either --nodaemon or an operation
    if not args.operation and not args.nodaemon:
        parser.error(f'You must specify either --nodaemon or an operation.')

    # Check for --stdout with --nodaemon
    if args.stdout and not args.nodaemon:
        parser.error(f'Option --stdout only makes sense with --nodaemon.')

    return args
