FIXED_PYTEST_ARGS = -v -W ignore::DeprecationWarning

.PHONY: test
test: | driver
	pytest $(FIXED_PYTEST_ARGS) $(ARGS)

.PHONY: driver
driver:
	$(MAKE) -C driver
