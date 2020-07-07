.PHONY: all
all: package

.PHONY: install
install: package libebph
	echo "Not yet implemented"

.PHONY: package
package: libbpfbox
	pip3 install -e . -r requirements.txt

.PHONY: libbpfbox
libbpfbox:
	$(MAKE) -C bpfbox/libbpfbox

.PHONY: test
test: libbpfbox
	$(MAKE) -C tests
