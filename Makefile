.PHONY: help install test lint demo clean

help:
	@echo "VANTA - common tasks"
	@echo "  make install   install the package (editable) + dev extras"
	@echo "  make test      run the test suite"
	@echo "  make demo      run the offline safe demo against the bundled lab"
	@echo "  make clean     remove caches and engagement output"

install:
	python3 -m pip install -e ".[dev,ui,yaml]"

test:
	python3 -m pytest

demo:
	python3 -m vanta scan --engagement examples/engagement.demo.json --allow-active

clean:
	rm -rf .pytest_cache **/__pycache__ engagements
