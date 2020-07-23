import logging

import pytest

from bpfbox.dsl import PolicyGenerator

DEBUG=logging.DEBUG

@pytest.fixture(scope='function')
def policy_generator(caplog):
    # Set log level
    caplog.set_level(DEBUG)

    parser = PolicyGenerator()

    yield parser
