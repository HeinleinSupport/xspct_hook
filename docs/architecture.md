# Architecture

xspct_hook is an async Python proxy daemon (FastAPI/uvicorn) that sits between an MTA and one or
more scan engines. It implements two wire dialects: the one [Stalwart](https://stalw.art/) actually
speaks, and the literal
[draft-degennaro-mta-hooks-01](https://datatracker.ietf.org/doc/draft-degennaro-mta-hooks/) wire
format. Draft -02 is not implemented; see [Planned work](#planned-work). It is a proof-of-concept,
not a production-ready or fully conformant implementation.

## Two wire dialects, one canonical model

Real Stalwart does not speak draft -01's wire protocol. Its `MtaHook` sends one POST per hook:

- Request: `{context: {stage, client, sasl?, tls?, server, queue?, protocol}, envelope?, message?}`.
  `message.contents` is the body as a lossy UTF-8 string, `message.headers` a list of pairs.
- Response: `{action, response?, modifications}` with flat tagged operations
  (`addHeader`, `insertHeader`, `changeHeader`, `deleteHeader`, `addRecipient`, `deleteRecipient`,
  `changeFrom`).
- There is no discovery or registration, no `X-MTA-Hooks-*` headers, no JSON-Pointer patches, no
  outbound stages and no `disconnect` action.

xspct_hook therefore keeps an internal canonical model shaped like draft -01 and exposes it through
two codecs. All stage, action and modification semantics live in `protocol/`, never in a codec.

| Codec | Reachable from | Wire shape |
| --- | --- | --- |
| `wire/stalwart.py::StalwartCodec` | real Stalwart `MtaHook` configuration | Stalwart's flat JSON |
| `wire/mta01.py::Mta01Codec` | `testing/mta01_client.py`, curl, demos | literal draft -01 JSON with discovery, registration and `X-MTA-Hooks-*` headers |

Consequences of the divergence:

- Stalwart calls `connect`, `ehlo`, `mail`, `rcpt` and `data`, not `auth`. AUTH subscriptions are
  rejected at startup.
- A `disconnect` verdict becomes a rejection with a logged warning. The proxy does not promise to
  close the SMTP session.
- Outbound stages (`delivery`, `defer`, `dsn`) and the `continue`/`cancel` actions are native-only.
  They are an early routing model from before draft -02. Draft -02 replaces them with `route`,
  `transmit`, `delivery` and `dsn` stages and per-recipient status changes instead of actions.
- Stalwart ignores unknown response keys, so the Stalwart route adds a top-level `ext` object with
  scanner context and provenance. The native endpoint reads and writes `/ext` through the canonical
  codec.
- Stalwart's header changes use one-based, case-insensitive name occurrences, and RCPT hooks carry
  the current recipient (the last one), while DATA carries the full list.
- Body rewrites (`/message`, `/rawMessage`, `replaceContents`) are always rejected.

Behaviour was checked against Stalwart 1.0.3 (source revision
`8b32686532d34623e9ce8e1237cf2bed9554af38`).

## Request flow

1. `app.py` receives the request on a profile's route and verifies the Bearer token with
   `secrets.compare_digest` before touching the body.
2. The codec decodes the JSON into a `HookContext` and the declared stage is checked against the
   profile's stages.
3. `body.py::MessageBody` wraps the message content in memory, or in a temporary file above
   `body_spool_threshold_mb`.
4. `orchestrator.py::HookOrchestrator.handle()` fans the context out to every adapter configured
   for the stage, with per-adapter and overall timeouts. It validates each result against the
   adapter's `supported_actions` and lets the profile's aggregation strategy produce one
   `HookDecision`. It never raises: timeouts and adapter errors become error verdicts that follow
   the profile's `on_adapter_error` policy.
5. The same codec encodes the decision for the caller.
6. Every step publishes events on the `EventBus`; `JSONLWriter` appends one JSON line per event.

## Modules

| Module | Purpose |
| --- | --- |
| `protocol/models.py` | `HookContext` and stage subclasses; `ctx.property(name)` raises `PropertyNotProvidedError` for properties the caller did not provide |
| `protocol/actions.py` | Action enum and severity order |
| `protocol/modifications.py` | JSON-Pointer set/add/delete operations, body-rewrite rejection, CR/LF header-injection validation |
| `protocol/decision.py` | `ScanVerdict` (adapter output) and `HookDecision` (orchestrator output) |
| `protocol/canonical.py` | Parses and builds the draft -01 JSON shape, including `/ext` |
| `wire/stalwart.py`, `wire/mta01.py` | The two codecs |
| `registration.py` | In-memory registration store for the native endpoint |
| `body.py` | Spooled message body with an async chunk iterator |
| `adapters/` | `PseudoScannerAdapter`, `ClamAVAdapter`, `XspctScanAdapter` |
| `aggregation.py` | `FirstRejectWins` and `ConsensusRequired` |
| `orchestrator.py` | Fan-out, timeouts, validation, aggregation |
| `events.py`, `logging_.py` | Event bus and JSONL writer |
| `config.py`, `profiles.py`, `registry.py` | YAML config, profile model, adapter and strategy factories |
| `testing/mta01_client.py` | Discovery, registration, smoke hook calls and deregistration against the native endpoint |

## Adapters and aggregation

Every adapter declares `supported_stages` and `supported_actions`. The orchestrator enforces them:
unsupported stages are skipped, an unsupported primary action becomes an error verdict, and
unsupported individual modifications are dropped.

- **PseudoScannerAdapter**: scripted scenarios (clean, malicious, reject, header changes, slow,
  timeout, malformed, error, ...), chosen by config or by a `verdict+<scenario>@test.local`
  recipient. The only adapter that supports the full action set.
- **ClamAVAdapter**: INSTREAM over TCP or a Unix socket, one fresh connection per scan, bounded
  connect, upload and read times. Supports accept and reject only.
- **XspctScanAdapter**: submits decoded MIME parts to xspct_scan's HTTP API. Confirmed ClamAV
  infections reject, other findings become context, and partial or failed scans follow the profile's
  error policy.

`FirstRejectWins` picks the most severe terminal verdict (accept < quarantine < reject, discard,
disconnect). `ConsensusRequired` rejects only if all usable verdicts agree on a terminal action.
Neither downgrades a more restrictive incoming action. With `on_adapter_error: fail_closed`, inbound
stages answer `451 4.7.0` and outbound stages answer HTTP 503 `SCANNER_UNAVAILABLE`.

## Native draft -01 endpoint

Each profile also exposes `<path>/.well-known/mta-hooks`, registration and deregistration routes
and a native hook route. Registration negotiates JSON, stages and fetch properties, is bound to its
profile, and reuses the profile's Bearer token. Hook calls need a valid `X-MTA-Hooks-Registration`
and `X-MTA-Hooks-Request-Id`. Errors use `{error: {code, message}}`. Expiration, filters, CBOR and
the full Appendix A error catalogue are out of scope.

## Outbound routing PoC (implemented, pre-draft-02)

Parts of the older routing model are implemented in the canonical model and native endpoint,
not just reserved as stage names:

| Stage | Implemented context | Actions |
| --- | --- | --- |
| `delivery` | `DeliveryContext`, with recipient access through `rcpt_to` | `continue` or `cancel` |
| `defer` | `DeferContext`, with `rcpt_to` and an optional supplied `defer_reason` | `continue` or `cancel` |
| `dsn` | `DsnContext`, with an optional supplied `dsn_type` | `continue` or `cancel` |

These stages can be enabled in a profile, advertised through discovery, negotiated during
registration and invoked through `<profile.path>/mta01`. The default action is `continue`;
stage/action validation rejects inbound actions at outbound stages. The pseudo adapter produces
outbound verdicts, and orchestration and aggregation handle them with the same deadlines and
error policy as inbound calls. Fail-closed engine errors return HTTP 503 `SCANNER_UNAVAILABLE`,
not an SMTP rejection or an automatic cancellation. The bundled smoke client exercises
`delivery` when it is enabled in the profile.

This is hook-level routing experimentation, **not an MTA routing or delivery engine**: xspct_hook
does not select next hops, maintain a delivery queue, schedule retries or generate DSNs.
Real Stalwart does not invoke these stages, and the ClamAV and xspct_scan adapters do not support
them. Draft -02's `route` and `transmit` stages and per-recipient routing-status transitions are
not implemented; the existing `continue`/`cancel` model is not draft -02 conformance.

## Limits

- TLS is mandatory in the draft. Loopback HTTP examples are demos; production needs HTTPS, fresh
  credentials, request and concurrency limits and log retention.
- Logging is best-effort: each subscriber queue holds 4096 events and reports overflow.
- Stalwart delivers the body as one buffered string, so spooling does not remove the initial
  allocation, and MIME reconstruction for scanning is not byte-exact after lossy UTF-8 conversion.
- When several hooks share a stage, Stalwart sends the same serialized request to each, so a later
  hook does not see an earlier hook's changes. `depends_on` only warns about shared stages.

## Planned work

- **Draft -02 alignment (not implemented).** Draft -02 (2026-10-28) is not backward compatible:
  JSON Patch responses, per-stage action rules, grants, per-recipient routing status and a new
  session and capability model. The older outbound routing PoC above is implemented, but alignment
  with the -02 specification remains planned, with proposals and open questions for the draft
  author. Alignment needs changes to the canonical model, the native endpoint and the test client.
  The separate Stalwart codec remains necessary while Stalwart uses its own wire dialect.
- **Scan jobs across SMTP retries.** Today a timed-out scan is cancelled. A pending-result
  lifecycle (temporary reject, correlation by content hash, completed report on retry) is not
  implemented.
