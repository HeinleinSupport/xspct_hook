# Changelog

All commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) (see
`CONTRIBUTING.md`).

## Unreleased

### Features

- Add the async MTA-hooks proxy with YAML profiles, Bearer authentication and a daemon CLI.
- Support Stalwart hooks and native draft -01 discovery, registration and hook endpoints.
- Add pseudo-scanner scenarios, ClamAV INSTREAM scanning and configurable aggregation strategies.
- Add message-body spooling, event logging and a native protocol smoke-test client.

### Fixes

- Match Stalwart object addresses, nullable parameters, SMTP fields and header operation semantics.
- Preserve completed scan verdicts across overall timeouts and prevent action downgrades.
- Enforce registration ownership, request IDs and direction-appropriate actions.
- Validate malformed requests, adapter outputs and header modifications without losing valid verdicts.
- Bound adapter connections and uploads, drain pending log events and surface writer failures.

### Documentation

- Document setup, demo workflows, verified Stalwart configuration and protocol conformance limits.
- Update the implementation plan with review acceptance criteria and regression coverage.
- Add a configuration guide and a fully commented reference configuration.

### Build

- Add a checked-in CycloneDX dependency SBOM with generation and release prompts and EUPL metadata.
- Add package metadata, development tooling and the smoke client's runtime HTTP dependency.
- Add EUPL-1.2 REUSE annotations for examples, repository documentation and generated caches.
- Replace mypy with Pyrefly (strict preset, with a baseline for existing `tests/` findings) for type checking.

### Tests

- Add unit and integration coverage for both wire dialects, adapters and lifecycle error handling.
