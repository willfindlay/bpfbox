import logging

import pytest

from bpfbox.dsl import PolicyParser

DEBUG=logging.DEBUG

@pytest.fixture(scope='function')
def policy_parser(caplog):
    # Set log level
    caplog.set_level(DEBUG)

    yield PolicyParser
