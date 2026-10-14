<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/_static/xspct_hook-dark.svg">
    <img src="docs/_static/xspct_hook.svg" alt="xspct_hook" width="400">
  </picture>
</p>

# xspct_hook

**xspct_hook** is an async Python proxy daemon implementing the IETF MTA-hooks protocol
([draft-degennaro-mta-hooks-01](https://datatracker.ietf.org/doc/draft-degennaro-mta-hooks/))
against [Stalwart](https://stalw.art/) as the reference MTA. It fans out hook requests (connect,
ehlo, auth, mail, rcpt, data, ...) to one or more backend scan engines, aggregates their verdicts
into a single decision, and translates between the wire format Stalwart actually speaks and the
protocol's canonical shape.

It ships with two backend adapters out of the box — `PseudoScannerAdapter` (a scripted stand-in
for demos and tests) and `ClamAVAdapter` (real ClamAV via INSTREAM) — and was built for an IETF
BOF proof-of-concept.

## Status

The Phase 0/1 implementation includes both HTTP dialects, pseudo and ClamAV scanners,
aggregation, JSONL events and a native draft smoke client. Design and review acceptance criteria
are documented in [docs/implementation-plan.md](docs/implementation-plan.md).
This is a proof-of-concept, not a production-ready or fully conformant implementation.

## Quick start

Requires Python 3.12 or newer:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/xspct-hook --config examples/config.sample.yaml
```

The daemon listens on `http://127.0.0.1:8080`. The pseudo profile works without clamd.
The optional ClamAV profile logs a connection failure if clamd is absent and applies its
fail-closed policy at scan time. `depends_on` warns about shared stages but does not establish
hook ordering or scanner-context transfer.

```bash
curl -sS -H 'Authorization: Bearer change-me-pseudo' \
  -H 'Content-Type: application/json' \
  -d @examples/stalwart-rcpt-request.json \
  http://127.0.0.1:8080/hooks/pseudo-test
```

The supplied request returns `action: reject`, SMTP status `550`, `enhanced_status: 5.7.1`
and scanner provenance. Replace sample tokens before any non-local deployment.

Run the native draft smoke client against the same daemon:

```bash
.venv/bin/python -m xspct_hook.testing.mta01_client \
  --base-url http://127.0.0.1:8080 --profile-path /hooks/pseudo-test \
  --token change-me-pseudo
```

The client discovers stages, registers, checks actions, SMTP codes and applied header changes,
then deregisters. Enable `delivery` in the pseudo profile to include the outbound smoke case.

## Stalwart configuration

Create a `MtaHook` in Stalwart's administrative configuration with these settings:

| Property | Demo value |
| --- | --- |
| `url` | `http://127.0.0.1:8080/hooks/pseudo-test` (same host only) |
| `enable` | An expression enabling this hook for the intended sessions |
| `stages` | `mail`, `rcpt`, `data` |
| `httpAuth` | Bearer authentication with the configured profile token |
| `timeout` | `35s`, greater than the profile's `overall_timeout` |
| `maxResponseSize` | `1048576` bytes |
| `tempFailOnError` | `true` |
| `allowInvalidCerts` | `false` |

Use your Stalwart version's UI/API representation of `MtaHook`, not draft registration routes.
For remote deployments use HTTPS, a trusted certificate and fresh credentials. These fields
and the wire schema were checked against local Stalwart source revision
`2f5b9f2c697ca0fb1d7f015dcdeab961cd7be893`; no released version is certified by these tests.

## Protocol conformance

- Stalwart uses object envelope addresses, body-only text contents, paired headers and flat
  response operations. MIME scanning reattaches headers, including serverHeaders, but cannot
  recover byte-exact source data. Disconnect uses reject plus the flag, as accept ignores response.
- Native draft requests use top-level properties and Base64 rawMessage; responses use
  set/add/delete arrays, action at `/action`, and SMTP code at `/response/code`.
- Root discovery selects the first configured profile; others use their own
  `<profile.path>/.well-known/mta-hooks` endpoint. Registration negotiates JSON, stages and fetch
  properties. Registration IDs are bound to profiles, and hooks require valid Request-Id headers.
- Outbound delivery/defer/dsn and continue/cancel are native-only. Stalwart's additional auth
  stage is not advertised by the literal native endpoint.
- Body rewriting, CBOR, filters, expiration/renewal, persistent state, deduplication and the full
  Appendix A error catalogue are outside this phase. Unsupported registration options are rejected.
- TLS is mandatory in the draft. Loopback HTTP examples are demos, not transport conformance.
  Production also needs request/concurrency limits, credential management and log retention.
- Logging is best-effort: queues hold 4096 events and report overflow; shutdown drains pending
  events, but process crashes do not provide durable audit delivery.

## Architecture (summary)

Real Stalwart does not speak draft -01's literal wire protocol. xspct_hook keeps one canonical
-01-shaped domain model internally and exposes it through two wire codecs:

| Codec | Reachable from | Wire shape |
|-------|-----------------|-----------|
| `StalwartCodec` | real Stalwart `MtaHook` config | Stalwart's flat `{action, response, modifications}` JSON |
| `Mta01Codec` | smoke-test client, curl, demos | literal draft -01 JSON (discovery/registration/`X-MTA-Hooks-*` headers) |

See [docs/implementation-plan.md](docs/implementation-plan.md) for the full design, including the
request flow, module layout, and protocol-conformance scope.

## Development

```bash
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/pyrefly check
```

Type checking uses [Pyrefly](https://pyrefly.org/) with the `strict` preset on `src/` and `tests/`,
configured in `[tool.pyrefly]` in [pyproject.toml](pyproject.toml). Existing findings (currently in
`tests/`) are recorded in [.pyrefly-baseline.json](.pyrefly-baseline.json) and are not reported;
new findings fail the check. Shrink the baseline with `pyrefly check --prune-baseline` after fixing
findings. In VS Code, set
`"python.analysis.diagnosticsSource": "Pylance + Pyrefly"` so Pylance shows the same diagnostics; it
picks up the `pyrefly` executable from the selected `.venv`.

## Dependency SBOM

The repository includes a CycloneDX JSON inventory in [bom.json](bom.json), following
the same checked-in SBOM workflow as xspct_scan. Regenerate it after dependency changes
and for every release:

```bash
.venv/bin/pip install -e '.[dev]'
.venv/bin/cyclonedx-py environment .venv/bin/python --pyproject pyproject.toml --of JSON -o bom.json
.venv/bin/reuse lint
```

The inventory covers the installed environment, including development tools; it is not a
production lockfile. The `generate-sbom` and `release` prompts use the same generation command.
Commit updates with GPG signing (`git commit -S`).

See [.github/copilot-instructions.md](.github/copilot-instructions.md) for the commands and
architecture quick-reference, and [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## Licence

[EUPL-1.2](LICENSE) — © 2026 Carsten Rosenberg, Heinlein Support GmbH

The xspct_hook logo (`docs/_static/xspct_hook*.svg`) is licensed under
[CC BY-ND 4.0](LICENSES/CC-BY-ND-4.0.txt): it may be shared, but only
unmodified.
