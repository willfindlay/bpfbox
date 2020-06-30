PYTEST_ARGS = "-W ignore::DeprecationWarning"

.PHONY: all
all: | driver
	pytest $(PYTEST_ARGS)

.PHONY: driver
driver:
	$(MAKE) -C driver
