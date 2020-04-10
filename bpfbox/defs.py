import os, sys

# Paths here
project_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
bpf_prog_path = os.path.join(project_path, 'bpfbox/bpf/bpf_program.c')

# Time to sleep between daemon ticks in seconds
ticksleep = 0.1
