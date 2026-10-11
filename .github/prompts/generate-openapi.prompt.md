---
description: "Export and commit xspct_hook's OpenAPI schema (FastAPI's native /openapi.json) for both wire-facing route sets."
agent: agent
tools: [execute, read]
---

Export the OpenAPI schema for xspct_hook and commit the result.

xspct_hook's FastAPI app generates its OpenAPI schema natively (`app.openapi()`); this just dumps it
to a committed file so it can be diffed in review and consumed by external tooling without running
the server.

## Steps (run in order — stop and report on failure)

### 1. Export the schema

```bash
.venv/bin/python -c "
import json
from xspct_hook.app import create_app
from xspct_hook.config import load_config

app = create_app(load_config('examples/config.sample.yaml'))
with open('docs/openapi.json', 'w') as f:
    json.dump(app.openapi(), f, indent=2, sort_keys=True)
    f.write('\n')
"
```

### 2. Diff and sanity-check

```bash
git diff docs/openapi.json
```

Confirm the diff only reflects intentional route/schema changes (new profile routes, new fields on
`HookContext`/`HookDecision`, etc.) — flag anything unexpected instead of committing blindly.

### 3. Stage the file

```bash
git add docs/openapi.json
git diff --cached --stat
```

### 4. Commit

```bash
git commit -S -m "docs(wire): update OpenAPI schema"
```

Remind the user to verify their GPG key is available (`gpg --list-secret-keys`) before committing.
