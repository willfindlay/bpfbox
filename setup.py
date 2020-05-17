#!/usr/bin/env python3

import os, sys
from distutils.core import setup

setup(
    name='bpfbox',
    version='0.0.1',
    description='Exploring externally enforced sandboxing rules in BPF',
    author='William Findlay',
    author_email='william.findlay@carleton.ca',
    url='https://github.com/willfindlay/bpfbox',
    packages=['bpfbox'],
    python_version='>=3.6',
)
