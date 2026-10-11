---
description: "Generate and commit the dependency SBOM for xspct_hook (CycloneDX JSON via cyclonedx-bom)."
agent: agent
tools: [execute, read]
---

Generate the dependency SBOM for xspct_hook and commit the result.

## Prerequisites

The active virtualenv must have the full `dev` extra installed:

```bash
.venv/bin/pip install -e ".[dev]"
```

## Steps (run in order — stop and report on failure)

### 1. Generate dependency SBOM (CycloneDX JSON)

Covers the installed environment, including development dependencies. Project metadata comes
from `pyproject.toml`; this is an environment inventory, not a locked production dependency list.

```bash
.venv/bin/cyclonedx-py environment .venv/bin/python --pyproject pyproject.toml --of JSON -o bom.json
```

Report the number of components listed and confirm the root component name and version match
`pyproject.toml`.

### 2. Verify REUSE compliance still passes

```bash
.venv/bin/reuse lint
```

Stop on any violations.

### 3. Stage the file

```bash
git add bom.json
git diff --cached --stat
```

### 4. Commit

```bash
git commit -S -m "chore: update dependency SBOM"
```

Remind the user to verify their GPG key is available (`gpg --list-secret-keys`) before committing.
