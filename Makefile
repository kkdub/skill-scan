.PHONY: install sync run test lint format type-check quality check ci rules-catalog

UV ?= uv
PYTHON ?= $(UV) run python
RUFF ?= $(UV) run ruff
MYPY ?= $(UV) run mypy
PYTEST ?= $(UV) run pytest
BANDIT ?= $(UV) run bandit
RADON ?= $(UV) run radon

EXCLUDE_DIRS := .venv,.git,.agents,.github,tools
MYPY_EXCLUDE := (\.venv|\.git|\.agents|\.github|tools)

# Usage:
# make run RUN=path/to/script.py
# make run MODULE=package.module
RUN ?= main.py
MODULE ?=

install:
	$(UV) sync --group dev

sync:
	$(UV) sync

run:
	$(if $(MODULE),$(PYTHON) -m $(MODULE),$(PYTHON) $(RUN))

test:
	$(PYTEST)

lint:
	$(RUFF) check

format:
	$(RUFF) format

type-check:
	$(MYPY) . --exclude "$(MYPY_EXCLUDE)"

quality: lint type-check test
	PYTHONIOENCODING=utf-8 $(BANDIT) -r src --exclude $(EXCLUDE_DIRS)
	$(RADON) cc . -a -s --exclude $(EXCLUDE_DIRS)

check:
	$(UV) run pre-commit run --all-files

rules-catalog:
	PYTHONIOENCODING=utf-8 $(PYTHON) scripts/generate_rules_catalog.py > RULES.md

ci: check
