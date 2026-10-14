---
description: "Run all code quality checks: ruff lint, pyrefly (strict preset), and REUSE/SPDX compliance. Reports issues on modified or all source files."
agent: agent
tools: [execute, search, read]
---

Run all code quality checks for xspct_hook.

## Steps

1. **Determine scope**: If the user specified files or a scope (e.g. "modified files"), use that.
   Otherwise check all source files:
   ```
   src/xspct_hook/
   tests/
   ```

2. **Ruff lint** — report every issue with file, line, and rule code:
   ```bash
   .venv/bin/ruff check src/ tests/
   ```
   If `.venv/bin/ruff` is not available try `ruff check src/ tests/`.

3. **pyrefly** — report every issue with file, line, and error code. Scope (`src/` and `tests/`),
   the `strict` preset and the baseline (`.pyrefly-baseline.json`) come from `[tool.pyrefly]` in
   `pyproject.toml`; only findings not in the baseline are reported:
   ```bash
   .venv/bin/pyrefly check
   ```
   If `.venv/bin/pyrefly` is not available try `pyrefly check`. If `VIRTUAL_ENV` points at another
   environment, run `unset VIRTUAL_ENV` first. Do not add new findings to the baseline; fix them.
   Optionally report stale baseline entries with `pyrefly check --error-stale-baseline`.

4. **REUSE / SPDX compliance** — every source file must have lines 1–2:
   ```
   # SPDX-License-Identifier: EUPL-1.2
   # SPDX-FileCopyrightText: <year> Carsten Rosenberg <c.rosenberg@heinlein-support.de>
   ```
   Run:
   ```bash
   .venv/bin/reuse lint
   ```
   If reuse is not installed, manually scan for files that are missing the SPDX header.

## Output

Summarise:
- Count of ruff issues (or "no issues")
- Count of pyrefly issues (or "no issues")
- List of REUSE violations (or "compliant")
- For each issue: file path, line number, rule / description
- Suggested fix for each issue where applicable
