# xspct_hook — Implementation Plan (Phase 0 + 1)

## Implementation status (2026-10)

Phases A-I are implemented, with the review corrections included in the acceptance criteria.
This remains a JSON proof-of-concept, not full draft conformance. Stalwart behavior is checked
against the local source checkout at revision `2f5b9f2c697ca0fb1d7f015dcdeab961cd7be893`:
`crates/smtp/src/inbound/hooks/{mod,message}.rs`, the milter message implementation, and
`crates/registry/src/schema/structs.rs`. A released Stalwart version has not been certified;
live MTA interoperability is still an external integration gate.

## Overview

xspct_hook is an async Python proxy daemon implementing the IETF MTA-hooks protocol
(draft-degennaro-mta-hooks-01) against Stalwart as the reference MTA, distributing scan requests to
backend engines (`PseudoScannerAdapter`, `ClamAVAdapter`) for an IETF BOF proof-of-concept.

## Key architecture decision

Real Stalwart does **not** speak draft -01's wire protocol (verified against the
`stalwartlabs/stalwart` source). Stalwart's actual hook wire format:

- Request: `{context: {stage, client, sasl?, tls?, server, queue?, protocol}, envelope?, message?}`
  (`message.contents` is the raw body as a lossy UTF-8 string, `message.headers` as a list of pairs).
- Response: `{action: accept|discard|reject|quarantine, response?: {status, enhanced_status, message, disconnect}, modifications: [tagged flat ops]}`.
- No discovery/registration, no `X-MTA-Hooks-*` headers, only inbound stages
  (connect/ehlo/auth/mail/rcpt/data), no JSON-Pointer patches, no `disconnect` action — disconnect is
  `response.disconnect: bool`, orthogonal to `action`.
- Stalwart's runtime ignores the response for `accept`; disconnect must therefore use
  `action=reject, response.disconnect=true`, despite the misleading accept-based test fixture.
- Sender and recipients are Address objects with nullable parameter maps; normalize null maps.
  RCPT selects the last recipient (the current command), while DATA retains the full list.
- Header changes/deletions use one-based, case-insensitive name occurrences, not global indexes.
  Additions prepend. Request-aware encoding reconstructs headers to preserve canonical ordering.
- Envelope changes use `value` and `parameters`; recipient deletion uses `value`, not an index.
- `httpAuth` supports Bearer/Basic/Unauthenticated — Bearer matches the per-profile token design below.
- Stalwart's JSON deserialization has no `deny_unknown_fields`, so unknown top-level keys (like `ext`)
  are silently ignored by Stalwart — safe to include for other consumers.

**Resolution: two-layer design.**

- An internal canonical domain model (`HookContext`, `Action`, JSON-Pointer `Modification`,
  `HookDecision`, `/ext` provenance) stays fully -01-shaped, used for direct/demo callers and all
  outbound-stage / `disconnect`-action test coverage.
- `wire/stalwart.py` (`StalwartCodec`) translates Stalwart's real flat JSON into the canonical model
  on decode, and the canonical `HookDecision` into Stalwart's flat JSON (plus an extra `ext` top-level
  key) on encode. This is the only wire format actually reachable from real Stalwart.
- Outbound stages (`delivery`/`defer`/`dsn`) are native-only. Canonical `disconnect` is reachable
  from Stalwart through the reject/disconnect mapping, not as a distinct Stalwart action.
- `/ext` scannerContext + provenance appears in the literal HTTP hook response body (visible to
  curl/tests, silently ignored by Stalwart) — not only in the JSONL log.
- A second, real HTTP-reachable wire dialect speaks literal -01 (discovery, registration,
  `X-MTA-Hooks-*` headers) — see Phase I — so the full draft protocol can actually be exercised
  end-to-end by a small test client, not just by the internal canonical model. Only the scoped
  subset below is implemented, not the full draft protocol.

## Package layout (src layout, pip-installable)

```
pyproject.toml (hatchling, PEP 621, name "xspct-hook", requires-python >=3.12)
src/xspct_hook/
  cli.py                 # entrypoint xspct-hook = xspct_hook.cli:main, --config PATH, uvicorn.run
  config.py              # YAML -> Pydantic config models, profile validation, depends_on warning
  app.py                 # FastAPI app factory, routes per profile per wire dialect
  profiles.py            # HookProfile dataclass (depends_on, on_adapter_error)
  registry.py             # adapter type -> factory, strategy name -> factory
  exceptions.py           # PropertyNotProvidedError, UnsupportedActionError, BodyRewriteRejected,
                           # RegistrationNotFoundError
  body.py                 # MessageBody: in-memory/tempfile spool, async chunk iterator, .size
  protocol/
    models.py             # HookContext base + Connect/Ehlo/Auth/Mail/Rcpt/Data/Delivery/Defer/Dsn contexts
    actions.py             # Action enum (accept/reject/discard/quarantine/disconnect/continue/cancel)
    modifications.py       # SetOperation/AddOperation/DeleteOperation (JSON Pointer), apply + validation
    decision.py             # ScanVerdict (adapter-facing), HookDecision (orchestrator-facing)
    canonical.py             # parse_hook_request()/build_hook_response() - full -01 JSON shape incl. /ext read+write
  wire/
    stalwart.py             # StalwartCodec.decode_request()/encode_response() - Stalwart's real flat JSON
    mta01.py                 # Mta01Codec: native -01 wire format (thin, since canonical IS -01-shaped)
  adapters/
    base.py                 # ScanAdapter Protocol
    pseudo.py                 # PseudoScannerAdapter incl. verdict+<scenario>@test.local parsing
    clamav.py                 # ClamAVAdapter (INSTREAM, per-scan fresh connection, TCP or Unix socket)
  aggregation.py             # AggregationStrategy Protocol, FirstRejectWins, ConsensusRequired
  orchestrator.py             # HookOrchestrator
  events.py                   # Event dataclasses + EventBus (asyncio.Queue fan-out)
  logging_.py                  # JSONLWriter subscriber
  registration.py                # In-memory registration store: registrationId -> {profile, hookEndpoint, created_at}
  testing/mta01_client.py         # Mta01TestClient: discovery+register+smoke hook calls+deregister
  examples/config.sample.yaml
tests/unit/...
tests/integration/...
```

## Steps (grouped by phase, later phases depend on earlier ones)

### Phase A — Packaging & config skeleton

1. `pyproject.toml`: hatchling build-backend, PEP 621 metadata, deps (fastapi, pydantic>=2, pyyaml,
  uvicorn[standard], httpx for the bundled client), `[project.optional-dependencies].dev` (pytest, pytest-asyncio, ruff,
   pyrefly, cyclonedx-bom, reuse), console script entrypoint, ruff/pyrefly/pytest config all in this
   file,
   `[tool.hatch.build]` force-include for `examples/config.sample.yaml`.
2. `config.py` + `profiles.py`: Pydantic config models mirroring the sample YAML, plus
   `body_spool_threshold_mb` (default 10), `jsonl_log_path`, top-level `host`/`port`, per-profile
   `depends_on: list[str]` (emits a startup warning when a dependency profile shares a stage with
   this profile), and per-profile `on_adapter_error: Literal["fail_open", "fail_closed"]`
   (default `fail_open`).
3. `exceptions.py`: `PropertyNotProvidedError`, `UnsupportedActionError`, `BodyRewriteRejected`.

### Phase B — Protocol layer (canonical, -01-shaped) *depends on A*

4. `protocol/models.py`: `HookContext` base (session_id, queue_id, stage, client_info, server_info,
  timestamp, trace_id, incoming action, original document, provided_properties: frozenset[str]) + stage subclasses, including outbound
   Delivery/Defer/Dsn contexts. Access pattern: `ctx.property(name)` helper that raises
   `PropertyNotProvidedError` if `name not in provided_properties`, else returns the field — this is
  the adapter-side fetchProperties accessor; the native endpoint negotiates stages and properties.
5. `protocol/actions.py` + `protocol/modifications.py`: full -01 action set; Set/Add/Delete ops on
  JSON Pointers, applied set/add/delete in that order. Array additions use an array path plus
  optional `index`. Reject `/message`, `/rawMessage` and body descendants, allowing only
  `/message/headers` within message updates. Validate complete arrays, objects and nested header
  fields against malformed names and CR/LF injection, and check request-aware applicability.
6. `protocol/decision.py`: `ScanVerdict` (adapter output: verdict, response override, modifications,
   scanner_context dict, engine name) and `HookDecision` (orchestrator output: final action/response/
   modifications/ext block with provenance).
7. `protocol/canonical.py`: `parse_hook_request(payload, stage) -> HookContext` and
   `build_hook_response(decision) -> dict`, full -01 JSON shape (flat top-level fields, JSON-Pointer
  modifications in `set`/`add`/`delete` arrays, action via `/action`, SMTP status via
  `/response/code`, and `/ext` namespace for scannerContext+provenance). Requests use top-level
  envelope Address objects, structured messages and Base64 `rawMessage`, not a `properties`
  wrapper. Legacy wrapped inputs remain internal test helpers only. Must also be able to *read* an
   inbound `/ext` block (for the context-transfer test, see Phase H) since only this canonical codec
   round-trips `/ext`, not the Stalwart codec.

### Phase C — Stalwart wire adapter *depends on B*

8. `wire/stalwart.py`: `StalwartCodec.decode_request()` mapping Stalwart's nested `context`/
   `envelope`/`message` into canonical `HookContext` + correct `provided_properties`;
   `encode_response()` mapping `HookDecision` to Stalwart's flat `{action, response, modifications}`
  plus an extra top-level `ext` key. Action mapping: disconnect -> `{action: "reject", response:
  {disconnect: true}}` (required by runtime behavior); modifications mapped to
   Stalwart's tagged ops (`addHeader`/`insertHeader`/`changeHeader`/`deleteHeader`/`addRecipient`/
   `deleteRecipient`/`changeFrom`); body-rewrite ops (`replaceContents`) are always rejected.

### Phase D — Body handling *parallel with B/C*

9. `body.py`: `MessageBody` with in-memory bytes below `body_spool_threshold_mb`, else spooled to a
   `NamedTemporaryFile`, cleaned up via try/finally even on exception; `async def chunks(chunk_size)`
   and `.size`. Stalwart delivers the body as one already-buffered JSON string (no true streaming from
  the MTA side). JSON and decoded bytes are initially buffered; spooling does not eliminate those
  allocations. Reattach message headers and `serverHeaders` to Stalwart's body-only contents for
  MIME scanning; this is not byte-exact reconstruction, especially after lossy UTF-8 conversion.
  Native Base64 rawMessage preserves original bytes. ClamAV uses chunked INSTREAM upload.

### Phase E — Adapters & aggregation *depends on B, D*

10. `adapters/base.py`: `ScanAdapter` Protocol.
11. `adapters/pseudo.py`: scenario resolution from config default and from
    `verdict+<scenario>@test.local` recipient parsing (rcpt/data stages only, since the mail stage has
    no `to` addresses); scenarios: clean, malicious, suspicious, reject, quarantine, discard,
    header_add, header_replace, header_delete, slow, timeout, malformed, error, context_rich,
    disconnect. "malformed" is implemented by intentionally returning a value that fails
    `ScanVerdict` validation, exercising the orchestrator's own defensive validation rather than any
    JSON-serialization boundary, since this adapter is called in-process. Declares `supported_actions`
    = the full -01 set (the only adapter that does).
12. `adapters/clamav.py`: INSTREAM framing (4-byte length-prefixed chunks + zero-length terminator)
    over TCP or Unix socket, fresh connection per scan call (no pooling), `supported_actions` =
    {accept, reject} only. `connect()` = optional fail-fast startup health check; `close()` = no-op/
    resource cleanup only, since each `scan()` opens its own dedicated connection.
    Bound connection establishment, upload and response reads; drain each chunk for backpressure.
    App startup/shutdown also bound adapter lifecycle calls and isolate close failures.
13. `aggregation.py`: `FirstRejectWins` (first terminal verdict wins by severity order
    accept < quarantine < {reject, discard, disconnect}) and `ConsensusRequired` (rejects only if ALL
    non-error/non-skipped verdicts agree on a terminal action; otherwise falls back to the
    weakest/accept). Both take the profile's `on_adapter_error` setting (`fail_open`/`fail_closed`) to
    decide whether an error/timeout verdict is ignored or forces an inbound temporary reject (451).
    Outbound defaults remain continue/cancel, never accept. Outbound fail-closed unavailability
    returns HTTP 503 SCANNER_UNAVAILABLE rather than a fabricated SMTP rejection or destructive
    cancellation. Neither strategy downgrades a more restrictive incoming action.

### Phase F — Orchestration & events *depends on E*

14. `events.py` + `logging_.py`: `EventBus` (asyncio.Queue fan-out per subscriber), event dataclasses
    (RequestStarted, AdapterStarted, AdapterFinished, AdapterSkipped, ModificationRejected,
    RequestFinished) all carrying `trace_id` (uuid4, generated internally since Stalwart sends no
    request-id header), `profile_name`, `stage`; `JSONLWriter` as first subscriber.
    Native trace IDs use the required Request-Id header. Open logs before startup returns; drain
    queued events on shutdown. Queues hold at most 4096 events, with counted/logged overflow.
    Background write failures are surfaced and unsubscribe the failed writer. This is best-effort
    observability, not a durable audit queue.
15. `orchestrator.py`: `HookOrchestrator.handle(profile, ctx)`: skip unsupported-stage adapters
    (AdapterSkipped event); per-adapter `asyncio.wait_for` plus overall `asyncio.wait` on tasks.
    Preserve completed verdicts at the overall deadline, cancel pending tasks and await cleanup;
    adapter exceptions/timeouts -> `ScanVerdict(verdict="error")`,
    orchestrator itself never raises; validates each verdict's action/modifications against
    `adapter.supported_actions` — unsupported primary action downgrades the verdict to error (with a
    `ModificationRejected` event), unsupported individual modifications are dropped individually
    (with their own `ModificationRejected` event) while the verdict's action is kept; then
    `strategy.aggregate(verdicts) -> HookDecision`.
    Runtime return-type, response and JSON-serialization validation remain inside the adapter
    exception boundary; malformed adapter data follows the configured error policy, never HTTP 500.

### Phase G — FastAPI app, profiles, CLI *depends on C, F*

16. `registry.py`: `{"pseudo": ..., "clamav": ...}` and `{"first_reject_wins": ..., "consensus_required": ...}`
    factories driven by YAML `type` fields.
17. `app.py`: one POST route per `HookProfile.path`; Bearer-token dependency using
    `secrets.compare_digest` (constant-time, checked before reading/parsing the body); decode via
    `StalwartCodec.decode_request`; validate the declared `context.stage` is in `profile.stages`
    (400 otherwise); build `MessageBody`; run orchestrator; encode via
    `StalwartCodec.encode_response`; publish Request/AdapterStarted/Finished events around the call.
18. `cli.py`: `main()` parses `--config`, loads YAML via `config.py`, builds the app, starts uvicorn;
    adapter `connect()`/`close()` wired to FastAPI startup/shutdown.
    Malformed JSON/non-object payloads, invalid stages and typed schema errors return client
    errors. Body cleanup covers disabled stages, orchestration and response encoding.

### Phase H — Tests & docs *depends on all above, can start per-phase incrementally*

19. Unit tests, one file per module listed above.
20. Integration tests; the context-transfer test is explicitly documented as simulating a
    hypothetical future MTA capability (manually re-injecting profile A's `/ext` output into profile
    B's synthetic request), since neither Stalwart nor -01 itself defines any mechanism for an MTA to
    carry a scanner's custom response data into a later stage's request.
21. README: setup, sample config, curl example against `/hooks/pseudo-test`, Stalwart `MtaHook`
    config section (url/stages/httpAuth/timeout/maxResponseSize/tempFailOnError), and an explicit
    "Protocol conformance" section stating which -01 features are demonstrated only via the internal
    canonical model / test client vs. actually reachable through real Stalwart today.

### Phase I — Native -01 endpoint + slim smoke-test client *depends on B, F, G*

Rationale: testing "the full -01 draft protocol" (not just Stalwart's subset) requires a second,
real HTTP-reachable wire dialect that speaks literal -01 (discovery, registration, `X-MTA-Hooks-*`
headers). Scoped as a slim smoke-test (representative stages/actions, not full Appendix A
error-code coverage), reusing the same orchestrator/adapters/aggregation core as the Stalwart path.

`Mta01Codec` is mostly a thin pass-through of the already -01-shaped canonical model
(`protocol/canonical.py` already does the hard part) plus header validation — it does not
re-implement modification/action semantics. The bulk of genuinely new work is the registration state
machine and the two new routes; the client itself is small given the slim smoke-test scope.

22. `registration.py`: in-memory registrations with profile ownership and deregistration
  tombstones. Negotiate JSON, directional stages and supported fetch properties. Draft -01
  explicitly permits expiresAt; requested expiration and filters are rejected in this phase,
  not silently accepted. Persistence, expiry/renewal, rate limits and deduplication are future work.
23. `wire/mta01.py`: `Mta01Codec.decode_request()`/`encode_response()` — near pass-through of
    `protocol/canonical.py`, since the wire IS the canonical -01 shape; adds header extraction
    (`X-MTA-Hooks-Registration`, `X-MTA-Hooks-Request-Id`, `Authorization`) as a FastAPI dependency
    that resolves/validates against `registration.py`. Unknown IDs return 404
    REGISTRATION_NOT_FOUND; deregistered IDs return 410 REGISTRATION_DEREGISTERED. Cross-profile
    hook/status/DELETE access returns 403 REGISTRATION_MISMATCH. Require Request-Id (1-128 ASCII
    unreserved characters); errors use `{error:{code,message}}`. Full Appendix A remains out of scope.
24. `app.py` additions: `GET /.well-known/mta-hooks` (static JSON listing this profile's registration
    endpoint + supported stages/capabilities); `POST`/`DELETE` registration routes per profile
    (register validates a draft request and returns 201 with registrationId, status, UTC createdAt,
    nullable expiresAt, hookEndpoint, negotiated and management endpoints; DELETE returns 200
    confirmation); a second per-profile hook route (the native -01 `hookEndpoint`)
    that reuses the exact same `HookOrchestrator.handle()` call as the Stalwart route, differing only
    in codec (`Mta01Codec` instead of `StalwartCodec`) and the registration-header dependency.
    Registration reuses the same per-profile Bearer token already used for the Stalwart route — no
    separate registration-specific auth mechanism.
    Root discovery selects the first configured profile. Each profile also exposes discovery at
    `<profile.path>/.well-known/mta-hooks`. Advertise only stages supported by the profile and
    its adapters; Stalwart's auth-stage extension is not advertised on native -01.
25. `testing/mta01_client.py`: `Mta01TestClient` (httpx.AsyncClient-based) implementing: discovery ->
    register -> a handful of representative smoke calls (e.g. mail-stage accept, rcpt-stage reject
    with an SMTP code, data-stage quarantine with a JSON-Pointer header `add`, one outbound
    delivery-stage `continue`) asserting action + applied-modification correctness -> deregister.
    Reused both as (a) a `tests/integration/test_mta01_client_smoke.py` pytest module driving it
    against the FastAPI test client, and (b) a tiny CLI wrapper
    (`python -m xspct_hook.testing.mta01_client --base-url ...`) for live manual/demo runs against a
    running server — same client code, two entry points, no duplicated logic.
    Discover enabled stages and skip disabled representative cases (delivery is absent from the
    default sample). Apply response operations and verify action, SMTP code 550 and scan headers.

  ### Future Phase J - Two-phase scan jobs and SMTP retry correlation (proposed, not implemented)

  Goal: support backends such as Peekaboo and, subject to API verification, xspct_scan that separate
  file submission from report retrieval. A scan may outlive the synchronous hook deadline without
  requiring another upload on the next SMTP attempt. Verify each backend's submission, polling,
  expiry and idempotency contracts before implementing its adapter. ClamAV INSTREAM is synchronous
  and does not provide this job protocol.

  26. Correlation identity: use a versioned, unambiguous key containing tenant/profile scope, backend
    identity, scan-policy version and SHA-256 of the exact uploaded bytes. For file scanning, hash
    decoded attachment bytes; for whole-message scanning, define a stable message representation.
    Do not use `Message-ID`, `session_id`, `trace_id` or `queue_id` as the sole cross-retry key:
    Message-ID is sender-controlled, session/trace IDs are per-call or connection identifiers, and
    queue IDs are optional and not guaranteed stable across resubmission after SMTP 451.
    Stalwart's lossy UTF-8 message reconstruction is not a byte-exact identity; exclude locally
    generated per-attempt headers and document the remaining limitations. Native `rawMessage`
    preserves bytes but can still change between submissions. Changed content creates a new key.
    Separate reusable content scan reports from mail-specific decisions; include relevant envelope
    and other policy inputs when caching decisions. Do not reuse reports across security scopes.
  27. Persistent job store: map the correlation key to backend job ID, state, submission/update times,
    expiry and completed report. Survive proxy restarts and coordinate concurrent workers using
    atomic claims/leases. Track submitting, pending, completed and failed states; bound retention,
    report validity, maximum pending age and store size. Report expiry or policy changes invalidate
    reuse. Avoid storing message content unless necessary; protect persisted reports and IDs.
    A local atomic claim alone cannot guarantee exactly-once remote submission: handle a lost upload
    response or crash before recording the job ID through backend idempotency/content lookup where
    available, or document a bounded recovery policy that may create duplicate jobs.
  28. Adapter workflow: look up a valid job before uploading. Submit only when none exists, persist
    its returned ID promptly, and poll within the hook's remaining time budget with bounded requests
    and backoff. On a later SMTP attempt, retrieve the existing report using the stored job ID.
    Cancelling local polling at the hook deadline must not delete the mapping or cancel the remote
    job. Do not leave unowned background tasks or retain request-owned message spools after return.
    For multiple submitted files, preserve each job mapping and aggregate their reports; a required
    file without a completed report must not be treated as clean.
  29. Pending-result semantics: distinguish a valid pending job from backend errors rather than
    describing both as engine unavailability. Define an explicit profile pending policy, defaulting
    to inbound SMTP `451` with a scan-pending response even if adapter errors are configured fail-open.
    This is temporary rejection before acceptance: the sending MTA retains the mail and retries;
    xspct_hook does not queue it. Keep action and aggregation semantics in `protocol/` and the shared
    orchestration/aggregation layer, not wire codecs. Define interaction with completed terminal
    verdicts, expired/failed jobs and outbound native hooks; do not confuse pending scans with the
    draft's outbound `defer` stage. Existing timeouts produce error verdicts under `on_adapter_error`
    and cancel adapter calls; they do not yet implement this pending lifecycle.
  30. Acceptance tests: pending upload -> SMTP 451 -> completed report on retry without another upload;
    the same flow across proxy restart; concurrent attempts sharing one known job; cancellation
    preserving remote work and stored identity; ambiguous submission recovery; expiry and policy
    invalidation; changed bytes creating a new job; tenant/backend isolation; duplicate or absent
    Message-ID; multi-file pending aggregation; terminal verdict interaction; bounded polling and
    retention; backend failures following the configured error policy. Use fake two-phase backends
    first, then require live backend and Stalwart retry interoperability checks.

## Verification

1. `pip install -e .[dev]` succeeds from a clean venv; `xspct-hook --config examples/config.sample.yaml`
   starts without error (adapters may fail `connect()` gracefully if clamd is absent — should log, not
   crash, unless a profile has no working adapters at all).
2. `ruff check .` and `pyrefly check` (strict preset on `src/` and `tests/`, existing `tests/`
   findings in `.pyrefly-baseline.json`) both clean (or documented targeted exceptions).
3. `pytest` full suite green, including the fake-clamd (`asyncio.start_server`) ClamAV tests and the
   httpx-based FastAPI e2e tests per stage.
4. Manual curl against `/hooks/pseudo-test` with `verdict+malicious@test.local` recipient reproduces a
   reject decision with correct SMTP code and a populated `/ext` block in the response JSON.
5. Startup-warning test: two profiles sharing a stage where one declares `depends_on` the other logs a
   warning at boot (captured via caplog or the event bus in a test).
6. `Mta01TestClient` smoke run (both as `pytest tests/integration/test_mta01_client_smoke.py` and as a
   live CLI run against a locally started server) completes discovery -> register -> the
   representative stage/action smoke calls -> deregister, with correct actions and applied
   modifications observed.

## Decisions / scope

- Stalwart is the only wire dialect reachable from a real-world MTA in this phase; native -01
  discovery/registration (Phase I) is a second, demo/test-only dialect. CBOR and the full Appendix A
  error-code set remain out of scope.
- Outbound stages + disconnect action: modeled fully, tested only via the FastAPI test client (not
  a live MTA). Disconnect is mapped onto Stalwart's rejection flag; outbound remains native-only.
- `/ext` is visible in the literal HTTP response body (curl/tests see it; Stalwart ignores it).
- Error-verdict handling in aggregation strategies is configurable per profile via
  `on_adapter_error` (`fail_open` default / `fail_closed`).
- Config bind address keys: `host`/`port`.
- Validate finite positive timeouts, nonempty profiles/stages/adapters and unique names/routes.
- TLS is mandatory in the draft. Loopback HTTP is demo-only; production requires a TLS proxy,
  certificate validation, fresh per-MTA credentials, request/concurrency limits and log retention.
- Review regression gates include real Address objects/null parameters/current RCPT; correct
  SMTP fields/header occurrences; completed reject surviving overall timeout; malformed adapter
  data following policy; malformed HTTP returning client errors; cross-profile registration
  isolation; array/nested header injection rejection; outbound continue; log draining/open errors;
  bounded ClamAV connections; and a live local daemon smoke run.
- The native -01 registration endpoint reuses the same per-profile Bearer token as the Stalwart
  route — no separate registration-specific auth mechanism.
- JMAP-like message fragments (envelope addresses, headers, Base64 `rawMessage`) are modelled with
  local Pydantic schemas, not a JMAP library: available Python libraries are client-oriented and
  would not match the draft's field names or Stalwart's wire format. Re-check field names against
  the final draft. Use the standard `email` package (`policy=email.policy.default`) if an adapter
  needs MIME or attachment parsing from `rawMessage`.
- No fail-open/fail-closed policy for adapter unavailability beyond `on_adapter_error`; the
  orchestrator's per-adapter/overall timeout handling covers the "never hang" requirement.
