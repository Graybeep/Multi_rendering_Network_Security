PY ?= python
HOST := 127.0.0.1
# Every target runs inside the venv, so the tested environment is the shipped one.
ifeq ($(OS),Windows_NT)
VPY := .venv/Scripts/python
else
VPY := .venv/bin/python
endif

.PHONY: setup test lint api mock lock

# Installs the pinned versions in requirements.lock, then the project itself without re-resolving.
setup:
	$(PY) -m venv .venv
	$(VPY) -m pip install -r requirements.lock
	$(VPY) -m pip install --no-deps -e .

test:
	$(VPY) -m pytest

lint:
	$(VPY) -m ruff check src tests
	$(VPY) -m mypy src

api:
	$(VPY) -m uvicorn src.api.app:app --host $(HOST) --port 8000

# Re-resolve from pyproject.toml and rewrite the pins. Run `make test` before committing the result.
lock:
	$(VPY) -m pip install -e ".[dev]"
	$(VPY) -m pip freeze --exclude-editable > requirements.lock

# Codex builds every screen against this. Bound to loopback, never 0.0.0.0.
mock:
	npx -y @stoplight/prism-cli@5 mock docs/openapi.yaml -h $(HOST) -p 8001
