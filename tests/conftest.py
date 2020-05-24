import subprocess
import pytest
import os

from bpfbox import defs

DRIVERPATH = os.path.join(defs.project_path, 'tests/driver')


def pytest_cmdline_main(config):
    subprocess.Popen(f'make -C {DRIVERPATH} clean'.split()).wait()
    subprocess.Popen(f'make -C {DRIVERPATH}'.split()).wait()
