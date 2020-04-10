import os, sys
import argparse

from bpfbox.utils import check_root

DESCRIPTION = """
Externally enforced sandboxing with eBPF.
"""

EPILOG = """
"""

def parse_args(sysargs=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    args = parser.parse_args(sysargs)

    if not check_root():
        parser.error(f"{parser.prog} must be run with root privileges.")

    return args
