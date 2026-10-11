# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) and other AI coding agents when working
with code in this repository.

## Project

xspct_hook is an async Python proxy daemon implementing the IETF MTA-hooks protocol
(draft-degennaro-mta-hooks-01) against Stalwart as the reference MTA, distributing scan requests to
backend engines (PseudoScannerAdapter, ClamAVAdapter) for an IETF BOF proof-of-concept.

The full design — including the Stalwart-vs-draft-01 wire-format divergence and how it's resolved —
lives in `docs/implementation-plan.md`. Read that first for any non-trivial change; this file is the
quick-reference summary and will drift out of date if not kept in sync with the code.

## Commands

### Install (development)
```bash
pip install -e ".[dev]"
```

### Run tests
```bash
pytest                                  # all tests
pytest tests/unit                       # unit tests only
pytest tests/integration                # integration tests only
pytest -k test_stalwart_codec           # single test by name
```

### Run the daemon
```bash
xspct-hook --config examples/config.sample.yaml
# or from source:
python -m xspct_hook.cli --config examples/config.sample.yaml
```

### Send a test hook call (Stalwart wire format)
```bash
curl -s -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d @examples/stalwart-rcpt-request.json \
  http://localhost:8080/hooks/pseudo-test | python3 -m json.tool
```

## Architecture

### Two wire dialects, one canonical model

Real Stalwart does **not** speak draft -01's wire protocol (no discovery/registration, no
`X-MTA-Hooks-*` headers, no JSON-Pointer modifications, no outbound stages, no `disconnect` action —
see `docs/implementation-plan.md` for the full comparison). xspct_hook keeps an internal canonical
-01-shaped domain model and exposes it through two separate wire codecs:

| Codec | Reachable from | Wire shape |
|-------|-----------------|-----------|
| `wire/stalwart.py::StalwartCodec` | real Stalwart `MtaHook` config | Stalwart's flat `{action, response, modifications}` JSON |
| `wire/mta01.py::Mta01Codec` | `testing/mta01_client.py`, curl, the BOF demo | literal draft -01 JSON (discovery/registration/`X-MTA-Hooks-*` headers) |

Both codecs translate to/from the same `protocol/models.py::HookContext` and
`protocol/decision.py::HookDecision` — all stage/action/modification semantics live in `protocol/`,
never in a codec.

### Request flow

1. `app.py` receives the HTTP request on a profile's route and verifies the Bearer token
   (`secrets.compare_digest`) **before** touching the body.
2. The matching codec (`StalwartCodec` or `Mta01Codec`) decodes the JSON into a `HookContext`.
3. `body.py::MessageBody` wraps the message content (in-memory or spooled to a temp file above
   `body_spool_threshold_mb`).
4. `orchestrator.py::HookOrchestrator.handle()` fans the context out to every adapter configured for
   the profile's stage (`asyncio.gather` with per-adapter and overall timeouts), validates each
   adapter's output against its `supported_actions`, and asks the profile's `AggregationStrategy`
   (respecting `on_adapter_error: fail_open|fail_closed`) to produce a single `HookDecision`.
5. The same codec encodes the `HookDecision` back to the caller's wire format.
6. Every step publishes events on `events.py::EventBus`; `logging_.py::JSONLWriter` subscribes and
   appends one JSON line per event.

### Key modules

| Module | Purpose |
|--------|---------|
| `protocol/models.py` | `HookContext` + stage subclasses; `ctx.property(name)` is the fetchProperties stand-in, raises `PropertyNotProvidedError` |
| `protocol/modifications.py` | JSON-Pointer Set/Add/Delete ops; rejects top-level `/message`/`/rawMessage` body rewrites; CRLF header-injection validation |
| `protocol/canonical.py` | `parse_hook_request()`/`build_hook_response()` — the only codec that round-trips `/ext` |
| `wire/stalwart.py` | `StalwartCodec` — the only dialect real Stalwart can call |
| `wire/mta01.py` | `Mta01Codec` — literal draft -01 wire format, used for discovery/registration and the smoke-test client |
| `registration.py` | In-memory registration store for the native -01 endpoint |
| `adapters/pseudo.py` | `PseudoScannerAdapter` — scenario driven by `verdict+<scenario>@test.local` |
| `adapters/clamav.py` | `ClamAVAdapter` — INSTREAM, fresh connection per scan, no pooling |
| `aggregation.py` | `FirstRejectWins` / `ConsensusRequired` |
| `orchestrator.py` | `HookOrchestrator` — never raises; timeouts/adapter errors become `ScanVerdict(verdict="error")` |
| `testing/mta01_client.py` | `Mta01TestClient` — discovery → register → smoke hook calls → deregister, reused by both a pytest module and a CLI demo |

### Protocol conformance scope

Outbound stages (`delivery`/`defer`/`dsn`) and the -01 `disconnect` action are modeled fully but are
only reachable via the FastAPI test client and `Mta01TestClient` — real Stalwart never invokes them.
Discovery/registration beyond the slim -01 smoke-test scope, CBOR, and the full Appendix A
error-code set are out of scope for this phase.

## Commit Convention

Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
**`<type>(<scope>): <description>`**. Full rules live in `CONTRIBUTING.md` — that file is the
authoritative source; the summary below just repeats the operationally important bits.

| Type | When to use |
| --- | --- |
| `feat` | New functionality |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Restructuring without behavior change |
| `test` | Test-only change |
| `perf` | Performance improvement |
| `build` | Build system, dependencies, `pyproject.toml` |
| `ci` | CI configuration |
| `chore` | Other maintenance |

Scopes: `protocol`, `wire`, `adapter`, `orchestrator`, `config`, `cli`. Breaking changes: `!` after
the scope and/or a `BREAKING CHANGE:` footer. Description is imperative, lowercase, no trailing
period, first line ≤ 72 chars. Independent changes go in separate commits — don't mix an adapter
change with a protocol-layer change.

**ALL commits and tags must be GPG-signed:**
```bash
git commit -S -m "feat(adapter): add ClamAV INSTREAM support"
git tag -s X.Y.Z -m "Tag message"
```

**NEVER** include "generated by", "co-authored by", or any AI attribution in commit messages.

### Project-specific rules for new work

- Never add stage/action/modification semantics to a wire codec (`wire/stalwart.py`,
  `wire/mta01.py`) — those live in `protocol/` and are shared by both dialects.
- Every new adapter declares `supported_stages`/`supported_actions` explicitly; the orchestrator
  enforces them — adapters must not rely on callers filtering first.
- Body-rewrite modifications (`/message`, `/rawMessage`, Stalwart's `replaceContents`) are always
  rejected — this PoC does not implement body rewriting.
- Header names/values coming from adapters must be validated against CR/LF injection before reaching
  a codec.
- Use the EUPL-1.2 header convention in new files, consistent with the rest of the repository.
- Independent changes are committed separately.
