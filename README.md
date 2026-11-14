<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/_static/xspct_hook-dark.svg">
    <img src="docs/_static/xspct_hook.svg" alt="xspct_hook" width="400">
  </picture>
</p>

# xspct_hook

**xspct_hook** is an async Python proxy daemon for the IETF MTA-hooks protocol
([draft-degennaro-mta-hooks](https://datatracker.ietf.org/doc/draft-degennaro-mta-hooks/)). It fans
out hook requests (connect, ehlo, mail, rcpt, data, ...) to one or more backend scan engines,
aggregates their verdicts into a single decision, and encodes it for the calling MTA. It was built
for an IETF BOF proof-of-concept.

It ships with `PseudoScannerAdapter` (scripted demos/tests), `ClamAVAdapter`
(ClamAV INSTREAM) and `XspctScanAdapter` (decoded MIME parts via xspct_scan's HTTP API).

## Status

Two wire dialects are implemented on top of one canonical model:

| Dialect | Implemented | Used by |
| --- | --- | --- |
| **Stalwart** (`MtaHook`) | Yes, verified against Stalwart 1.0.3 | Real Stalwart installations |
| **draft-degennaro-mta-hooks-01** | Yes: discovery, registration and hook endpoints | The bundled smoke-test client, curl, demos |
| **draft-degennaro-mta-hooks-02** | **No.** The -02 specification (2026-10-28) is not implemented. Only an earlier, pre-draft-02 routing model exists, in the native dialect's outbound stages (see below). The [architecture document](docs/architecture.md#planned-work) describes the planned alignment. | - |

Stalwart does not speak draft -01's wire format, so the Stalwart dialect is a separate codec
rather than a variant of -01. See [docs/architecture.md](docs/architecture.md) for the design.

The native dialect also models outbound stages (`delivery`, `defer`, `dsn`) with `continue`/`cancel`
actions. They come from an older routing model that predates draft -02 and are not -02's
`route`/`transmit`/`delivery`/`dsn` stages with per-recipient status changes. Real Stalwart never
calls them.

The xspct_scan backend additionally scans text/HTML and attachments at DATA, rejecting confirmed
ClamAV infections while exposing other findings as context. Partial scans follow the profile's
error policy; see the [configuration guide](docs/configuration.md#xspct_scan) and the
`xspct-scan-data` profile in [the reference configuration](examples/config.reference.yaml).
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
and the wire schema were checked against Stalwart 1.0.3, source revision
`8b32686532d34623e9ce8e1237cf2bed9554af38`. An isolated native lab verifies the supported
subset, not production readiness or complete draft conformance.

## Protocol conformance

- Stalwart uses object envelope addresses, body-only text contents, paired headers and flat
  response operations. MIME scanning reattaches headers, including serverHeaders, but cannot
  recover byte-exact source data. Native header framing is removed/unfolded for canonical
  modifications, while reconstruction preserves supplied folding and adds no extra separators.
  Header-injection validation remains enabled.
- Stalwart 1.0.3 calls `connect`, `ehlo`, `mail`, `rcpt` and `data`, **not `auth`**.
  AUTH stage subscriptions are rejected at startup; SMTP authentication still appears as
  SASL context on subsequent hook requests. A `disconnect` verdict becomes a rejection with a
  logged warning, **without promising to close the SMTP session**.
- Native draft requests use top-level properties and Base64 rawMessage; responses use
  set/add/delete arrays, action at `/action`, and SMTP code at `/response/code`.
- Root discovery selects the first configured profile; others use their own
  `<profile.path>/.well-known/mta-hooks` endpoint. Registration negotiates JSON, stages and fetch
  properties. Registration IDs are bound to profiles, and hooks require valid Request-Id headers.
- Outbound delivery/defer/dsn and continue/cancel are native-only. Neither endpoint supports
  AUTH-stage subscriptions.
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

See [docs/architecture.md](docs/architecture.md) for the full design, including the
request flow, module layout, and protocol-conformance scope.

## Configuration

All options, adapters, strategies and timeout behaviour are described in
[docs/configuration.md](docs/configuration.md). [examples/config.reference.yaml](examples/config.reference.yaml)
lists every option with its default; [examples/config.sample.yaml](examples/config.sample.yaml) is the
short quick-start file.

## Development

```bash
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/pyrefly check
```

## Dependency SBOM

The repository includes a CycloneDX JSON inventory in [bom.json](bom.json).
Regenerate it after dependency changes and for every release:

```bash
.venv/bin/pip install -e '.[dev]'
.venv/bin/cyclonedx-py environment .venv/bin/python --pyproject pyproject.toml --of JSON -o bom.json
.venv/bin/reuse lint
```

The inventory covers the installed environment, including development tools; it is not a
production lockfile. Commit updates with GPG signing (`git commit -S`).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention and
[docs/index.md](docs/index.md) for all documentation.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## Licence

[EUPL-1.2](LICENSE) — © 2026 Carsten Rosenberg, Heinlein Support GmbH

The xspct_hook logo (`docs/_static/xspct_hook*.svg`) is licensed under
[CC BY-ND 4.0](LICENSES/CC-BY-ND-4.0.txt): it may be shared, but only
unmodified.
