import os, sys

# Paths here
project_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
bpf_prog_path = os.path.join(project_path, 'bpfbox/bpf/bpf_program.c')

# Time to sleep between daemon ticks in seconds
ticksleep = 0.1

# Path to working directory
working_directory = '/var/lib/bpfbox'

# Path to pidfile
pidfile = '/var/run/bpfboxd.pid'

# Path to logfile
logfile = '/var/log/bpfbox/bpfbox.log'

def init():
    """
    Make sure things are setup properly.
    """
    # Make logfile parent directory
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    # Make pidfile parent directory
    os.makedirs(os.path.dirname(pidfile), exist_ok=True)
    # Make working_directory or set permissions of existing working_directory
    try:
        os.makedirs(working_directory, mode=0o1700, exist_ok=True)
    except OSError:
        os.chmod(working_directory, mode=0o1700)
