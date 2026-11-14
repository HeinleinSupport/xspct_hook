# Changelog

All commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) (see
`CONTRIBUTING.md`).

## Unreleased

## 0.1.0 — 2026-11-14

### Features

- Add xspct_scan MIME-part uploads, confirmed ClamAV rejection and partial-scan error handling.
- Add the async MTA-hooks proxy with YAML profiles, Bearer authentication and a daemon CLI.
- Support Stalwart hooks and native draft -01 discovery, registration and hook endpoints.
- Add pseudo-scanner scenarios, ClamAV INSTREAM scanning and configurable aggregation strategies.
- Add message-body spooling, event logging and a native protocol smoke-test client.

### Fixes

- Return a client error for invalid Stalwart header framing instead of an internal server error.
- Exclude image EXIF metadata from xspct_scan response provenance.
- Preserve spooled-body reader positions when the xspct_scan adapter reads the full MIME message.
- Normalize native Stalwart header framing for safe modifications and preserve MIME framing.
- Reject unsupported AUTH subscriptions and warn when Stalwart disconnect becomes reject-only.
- Match Stalwart object addresses, nullable parameters, SMTP fields and header operation semantics.
- Preserve completed scan verdicts across overall timeouts and prevent action downgrades.
- Enforce registration ownership, request IDs and direction-appropriate actions.
- Validate malformed requests, adapter outputs and header modifications without losing valid verdicts.
- Bound adapter connections and uploads, drain pending log events and surface writer failures.

### Documentation

- Describe request bodies, required native headers and registration's 201 status in OpenAPI.
- Document setup, demo workflows, verified Stalwart configuration and protocol conformance limits.
- Replace the internal implementation plan with a condensed architecture document covering the
  Stalwart and draft -01 dialects, the pre-draft-02 outbound routing PoC and planned work.
- Add a documentation index, an exported OpenAPI schema and a `.reuseignore`.
- Clarify in the README that draft -02 is not implemented.
- Add a configuration guide and a fully commented reference configuration.

### Build

- Add a checked-in CycloneDX dependency SBOM with generation and release prompts and EUPL metadata.
- Add package metadata, development tooling and the smoke client's runtime HTTP dependency.
- Add EUPL-1.2 REUSE annotations for examples, repository documentation and generated caches.

### Tests

- Add unit and integration coverage for both wire dialects, adapters and lifecycle error handling.
