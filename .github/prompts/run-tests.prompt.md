---
description: "Run the pytest test suite for xspct_hook. Supports optional -k filter and --cov for coverage. Shows full tracebacks on failure."
agent: agent
argument-hint: "Optional: -k <filter> or --cov"
tools: [execute, read]
---

Run the xspct_hook test suite with pytest.

## Steps

1. Build the pytest command based on any arguments provided:
   - No argument → run all tests
   - `-k <filter>` → run matching tests only: `pytest -k "<filter>"`
   - `--cov` or `coverage` → add `--cov=xspct_hook --cov-report=term-missing`
   - A file path → run that file only

2. **Run pytest** from the project root:
   ```bash
   .venv/bin/python -m pytest -v --tb=short
   ```
   Append any flags derived from the argument above.

3. **Report results**:
   - Exact command and selected scope
   - Total passed / failed / errors / skipped
   - Distinguish mocked tests from live integration checks; do not count skips as passes
   - For each failure: test name, file, line, full error message and traceback
   - For each error: same detail
   - If coverage was requested: coverage percentage per module and overall total

## Notes

- Tests use `pytest-asyncio`; async tests run without extra decorators given `asyncio_mode = "auto"`
  in `pyproject.toml`.
- `tests/integration/test_mta01_client_smoke.py` exercises the native -01 endpoint via
  `Mta01TestClient` — it is the only test path that covers discovery/registration.
- Tests against ClamAV use a fake `asyncio.start_server`-based clamd; no real clamd daemon is
  required to run the suite.
