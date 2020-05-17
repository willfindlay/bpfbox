This folder contains unit tests for bpfbox.

To run tests, first make sure dependencies are installed with `pipenv install
--dev --site-packages`.  The `site-packages` flag is important for bcc to work.
Once dependencies are installed, run `pipenv run pytest`.

All tests must be located in `tests/` and must be named like `test_foo.py`.
