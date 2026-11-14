# Configuration guide

xspct_hook reads one YAML file, passed with `--config`:

```bash
xspct-hook --config examples/config.reference.yaml
```

[examples/config.reference.yaml](../examples/config.reference.yaml) lists every option with its
default. [examples/config.sample.yaml](../examples/config.sample.yaml) is the shorter file used by
the README quick start. Invalid files, such as duplicate names or routes, non-positive timeouts or
unknown stage names, stop the daemon at startup with a validation error.

## Global options

| Option | Default | Meaning |
| --- | --- | --- |
| `host` | `127.0.0.1` | Bind address |
| `port` | `8080` | Bind port (1-65535) |
| `body_spool_threshold_mb` | `10` | Bodies above this size are spooled to a temporary file |
| `jsonl_log_path` | `xspct_hook-events.jsonl` | Event log, one JSON object per line |
| `adapter_timeout` | `10` | Seconds allowed for one scan engine call |
| `overall_timeout` | `30` | Seconds allowed for all engines of one request |
| `profiles` | required | One or more profiles |

## Profiles

Each profile exposes its own route and token:

| Option | Default | Meaning |
| --- | --- | --- |
| `name` | required | Unique name used in logs |
| `path` | required | Unique route starting with `/`, without a trailing `/` |
| `token` | required | Bearer token checked before the request body is read |
| `stages` | required | Stages handled by this profile |
| `strategy` | `first_reject_wins` | How engine verdicts are combined |
| `on_adapter_error` | `fail_open` | What to do when an engine fails or times out |
| `adapter_timeout` | global value | Per-profile override |
| `overall_timeout` | global value | Per-profile override |
| `depends_on` | `[]` | Informational only; logs a startup warning about shared stages |
| `adapters` | required | One or more scan engines |

Valid stages are `connect`, `ehlo`, `mail`, `rcpt`, `data`, `delivery`, `defer` and `dsn`.
Stalwart 1.0.3 calls only the first five. It does not invoke an AUTH hook, so `auth` subscriptions
fail configuration validation; authenticated sessions still provide SASL context at later stages.
The outbound stages can be reached only through the native draft -01 endpoint.

A profile route `P` also provides `P/mta01` (native hook endpoint), `P/register` (native
registration) and `P/.well-known/mta-hooks` (discovery). These routes must not collide with another
profile. The same token authenticates all of them.

## Adapters

### `pseudo`

A scripted scanner for demos and tests; it supports every stage and action.

| Option | Default | Meaning |
| --- | --- | --- |
| `default_scenario` | `clean` | Scenario used when the recipient does not select one |
| `slow_delay` | `2` | Seconds the `slow` scenario waits |

At the `rcpt` and `data` stages, a recipient such as `verdict+malicious@test.local` selects the
scenario named after `verdict+`. An unknown scenario name is treated as `clean`.

| Scenario | Result |
| --- | --- |
| `clean` | Accept |
| `malicious` | Reject, SMTP `550 5.7.1` |
| `reject` | Reject, SMTP `550 5.7.1` (policy) |
| `suspicious` | Quarantine; adds `X-Xspct-Scan` at the data stage |
| `quarantine`, `discard` | Quarantine, discard |
| `header_add`, `header_replace`, `header_delete` | Accept with a header change |
| `context_rich` | Accept with extra scanner context in the response |
| `disconnect` | Native draft: reject and close; Stalwart: reject only, with a warning and no close guarantee |
| `slow` | Accept after `slow_delay` seconds |
| `timeout` | Never answers; exercises the timeout handling |
| `error`, `malformed` | Engine failure; handled by `on_adapter_error` |

### `clamav`

Scans the message body at the `data` stage through ClamAV's `INSTREAM`. Each scan opens its own
connection. It can accept or reject; it does not modify messages.

| Option | Default | Meaning |
| --- | --- | --- |
| `host` | none | clamd TCP host; required unless `unix_socket` is set |
| `port` | `3310` | clamd TCP port |
| `unix_socket` | none | Path of the clamd socket, used instead of `host`/`port` |
| `timeout` | `30` | Seconds for connecting, uploading and reading the result |

### `xspct_scan`

At DATA, parses the MIME message and sends every non-empty decoded leaf part to
`POST /v1/scan`, including text/HTML alternatives, inline images, attachments and
content inside attached messages. Multipart containers are not submitted separately.
Base64 and quoted-printable content is decoded without charset conversion.
Malformed MIME is an adapter error rather than partially scanned success.

| Option | Default | Meaning |
| --- | --- | --- |
| `base_url` | required | Backend HTTP(S) base URL, e.g. `http://127.0.0.1:8081`, without `/v1/scan` |
| `api_key` | none | Optional backend `X-Api-Key`, distinct from the profile Bearer token |
| `timeout` | `30` | Total seconds for all parts of one message |
| `scan_timeout` | `10` | Per-part backend analysis budget, sent as `timeout` and `metadata.timeout_s` |

Uses structured `metadata` + `file` multipart uploads, requests JSON and validates
the v2 (`schema_version: "2.0"`) report. Metadata includes filenames, declared
content types and available queue/Message-IDs. A shared async HTTP client is
closed at shutdown; startup checks `/health`. Redirects are not followed. HTTPS
uses the normal system/environment CA trust; there is no invalid-certificate bypass.

Only a completed report with `engines.clamav.status: infected` or a `ClamAV`
finding rejects with `550 5.7.1`. The latter also covers detections propagated
from archive members. Enable ClamAV **in xspct_scan** for this protection.
Other findings, YARA matches and severity values are informational; xspct_scan
does not yet calculate an overall risk score.

HTTP 202, unfinished/dropped/error reports, pending/failed analyzers and
unavailable/skipped/failed ClamAV scans are adapter errors. HTTP failures, malformed
responses, unsupported report versions and timeouts are errors too. They follow
the profile's `on_adapter_error`; the reference profile uses `fail_closed` to
return 451. No polling occurs inside the SMTP transaction: xspct_scan may keep
working, and resubmitting content on SMTP retry uses its hash cache.

Reports for processed parts are exposed in provenance `scannerContext.parts`.
Extracted text, document metadata (including image EXIF) and decryption passwords are not copied.
Empty parts need no scan. Processing stops on the first infection or incomplete
analysis; the context lists only parts processed up to that point. Set the profile
and MTA deadlines above the adapter deadline (the reference profile needs an MTA
hook timeout above 40 seconds). Parts are uploaded sequentially; parsing and
decoding buffer message content even when the input body was spooled.

## Strategies

| Strategy | Behaviour |
| --- | --- |
| `first_reject_wins` | The most severe verdict (reject, discard or disconnect over quarantine over accept) wins |
| `consensus_required` | A non-accept action applies only if every successful engine returns the same one; otherwise the message is accepted |

Neither strategy weakens a stricter action already present in the request.

## Timeouts and engine errors

A scan runs under three limits. The smallest one that is reached ends the scan:

1. The adapter's own limit, for example ClamAV `timeout`.
2. The profile's `adapter_timeout`, which caps each engine call.
3. The profile's `overall_timeout`, which caps the whole request. Verdicts that finished before
   this deadline are kept.

Engine errors and timeouts follow `on_adapter_error`:

- `fail_open`: the failing engine is ignored; other verdicts decide, or the message is accepted.
- `fail_closed`: inbound stages answer with SMTP `451 4.7.0 scan engine unavailable`, so the
  sending MTA retries later. Outbound stages answer HTTP 503 `SCANNER_UNAVAILABLE`.

Set the MTA's hook timeout above `overall_timeout`; Stalwart's example uses `35s` for a `30s`
limit. A timed-out scan is cancelled. Scan jobs that continue across SMTP retries are not supported
yet; see "Planned work" in [architecture.md](architecture.md).

## Connecting Stalwart

Create a `MtaHook` in Stalwart with the profile's route as `url` (for example
`http://127.0.0.1:8080/hooks/pseudo-demo`), the profile's stages, Bearer authentication with the
profile token, and `tempFailOnError` enabled. The full property table is in the
[README](../README.md#stalwart-configuration).

The supported Stalwart 1.0.3 subset is `connect`, `ehlo`, `mail`, `rcpt`, `data`.
An HTTP request claiming `context.stage: auth` is rejected with 400.
The native RCPT handler ignores `response.disconnect`; xspct_hook therefore maps its canonical
disconnect verdict to an ordinary rejection, omits the misleading flag and logs the limitation.
Do not use this endpoint for policies that require a connection to be closed.

Native header values include framing whitespace and line endings. The decoder removes one
terminal line ending and unfolds legal continuations for canonical modifications; invalid
embedded newlines return HTTP 400. Raw MIME reconstruction preserves supplied header folding
without inserting extra blank lines. It still cannot recover bytes lost by Stalwart's JSON
UTF-8 conversion.

## Operating notes

- Replace all sample tokens with long random values, and use a separate token for each profile and MTA.
- Serve the daemon over HTTPS (for example behind a reverse proxy) when it is not on the same host as the MTA.
- Events go to `jsonl_log_path` on a best-effort basis; handle log rotation and retention outside
  the daemon.
- Validate a config without starting the server by loading it in Python:

  ```bash
  .venv/bin/python -c "from xspct_hook.config import build_profiles, load_config; build_profiles(load_config('examples/config.reference.yaml'))"
  ```
