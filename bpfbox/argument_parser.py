import os, sys
import argparse

from bpfbox.utils import check_root

DESCRIPTION = """
Externally enforced sandboxing with eBPF.
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
    operations = parser.add_argument_group('operations')
    operation = operations.add_mutually_exclusive_group()
    operation.add_argument('operation', choices=OPERATIONS, nargs='?',
            help='Operation to perform. One of ' + ', '.join(OPERATIONS) + '.')
    operation.add_argument('--nodaemon', action='store_true',
            help='Run as a foreground process instead of daemonizing. '
            'Required if not specifying an operation.')
    # Miscellaneous options
    misc_options = parser.add_argument_group('misc. options')

    # Parse arguments
    args = parser.parse_args(sysargs)

    # Check for correct permissions
    if not check_root():
        parser.error(f'{parser.prog} must be run with root privileges.')

    # Check for either --nodaemon or an operation
    if not args.operation and not args.nodaemon:
        parser.error(f'You must specify either --nodaemon or an operation.')

    return args
