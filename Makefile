.PHONY: help install install-dev test clean build dist publish test-publish

help:  ## Show this help message
	@echo "🔐 OTP Encryption Suite - Development Commands"
	@echo "=============================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package
	pip install -e .

install-dev:  ## Install development dependencies
	pip install -e ".[dev]"
	pip install pytest flake8 black

test:  ## Run tests
	python test_otp.py
	python -c "from otp_encryption_suite import main; print('Import test passed')"

clean:  ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

build:  ## Build the package
	python -m build

dist: clean build  ## Clean and build the package

publish: dist  ## Publish to PyPI
	twine upload dist/*

test-publish: dist  ## Publish to TestPyPI
	twine upload --repository testpypi dist/*

format:  ## Format code with black
	black otp_encryption_suite/ *.py

lint:  ## Run linting checks
	flake8 otp_encryption_suite/ *.py

check: format lint test  ## Run all checks

run:  ## Run the OTP tool
	python otp.py

cli:  ## Test CLI commands
	otp-encrypt --help || echo "CLI not installed, run 'make install' first"
	otp --help || echo "CLI not installed, run 'make install' first"
