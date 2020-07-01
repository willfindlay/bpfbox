PYTEST_ARGS = -v -W ignore::DeprecationWarning

.PHONY: test
test: | driver
	pytest $(PYTEST_ARGS)

.PHONY: driver
driver:
	$(MAKE) -C driver
