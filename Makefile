.PHONY: install install-dev setup run dashboard test test-cov lint format report clean help

PYTHON := python3
PIP    := $(PYTHON) -m pip

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:  ## Install production dependencies
	$(PIP) install -e .

install-dev:  ## Install development dependencies
	$(PIP) install -e ".[dev]"

setup: install-dev  ## Full setup (install + copy config + download geoip)
	@if [ ! -f config/config.yaml ]; then \
		cp config/config.example.yaml config/config.yaml; \
		echo "Created config/config.yaml — edit it before running"; \
	fi
	@bash scripts/download_geoip.sh || true

run:  ## Start monitoring (requires sudo/root for packet capture)
	@echo "Note: packet capture requires elevated privileges"
	$(PYTHON) -m homenetguard.main start

dashboard:  ## Start dashboard only (no capture)
	$(PYTHON) -m homenetguard.main dashboard

test:  ## Run all tests
	$(PYTHON) -m pytest tests/ -v

test-cov:  ## Run tests with coverage report
	$(PYTHON) -m pytest tests/ -v --cov=homenetguard --cov-report=term-missing --cov-report=html --cov-fail-under=70

lint:  ## Run ruff + mypy
	$(PYTHON) -m ruff check homenetguard/ tests/
	$(PYTHON) -m mypy homenetguard/ --ignore-missing-imports

format:  ## Format code with black
	$(PYTHON) -m black homenetguard/ tests/

report:  ## Generate daily report
	$(PYTHON) -m homenetguard.main report --type daily --format html

clean:  ## Remove build artifacts and __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf dist/ build/ *.egg-info/ .pytest_cache/ htmlcov/ .coverage 2>/dev/null || true
	@echo "Cleaned"
