PY ?= python
HOST := 127.0.0.1

.PHONY: setup test lint api mock

setup:
	$(PY) -m venv .venv
	.venv/bin/pip install -e ".[dev]" || .venv/Scripts/pip install -e ".[dev]"

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check src tests
	$(PY) -m mypy src

api:
	$(PY) -m uvicorn src.api.app:app --host $(HOST) --port 8000

# Codex builds every screen against this. Bound to loopback, never 0.0.0.0.
mock:
	npx -y @stoplight/prism-cli@5 mock docs/openapi.yaml -h $(HOST) -p 8001
