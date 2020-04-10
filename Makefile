.PHONY: all, package, install

all: install

install:
	echo "Not yet implemented"

package:
	pip3 install -e . -r requirements.txt
