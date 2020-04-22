.PHONY: all
all: paper

.PHONY: paper
paper:
	$(MAKE) -C paper

.PHONY: install
install:
	echo "Not yet implemented"

.PHONY: package
package:
	pip3 install -e . -r requirements.txt
