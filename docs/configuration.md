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

Valid stages are `connect`, `ehlo`, `auth`, `mail`, `rcpt`, `data`, `delivery`, `defer` and `dsn`.
Stalwart only calls the inbound stages. The outbound stages can be reached only through the native
draft -01 endpoint.

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
| `disconnect` | Reject and close the session |
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
yet; see Phase J in [implementation-plan.md](implementation-plan.md).

## Connecting Stalwart

Create a `MtaHook` in Stalwart with the profile's route as `url` (for example
`http://127.0.0.1:8080/hooks/pseudo-demo`), the profile's stages, Bearer authentication with the
profile token, and `tempFailOnError` enabled. The full property table is in the
[README](../README.md#stalwart-configuration).

## Operating notes

- Replace all sample tokens with long random values, and use a separate token for each profile and MTA.
- Serve the daemon over HTTPS (for example behind a reverse proxy) when it is not on the same host as the MTA.
- Events go to `jsonl_log_path` on a best-effort basis; handle log rotation and retention outside
  the daemon.
- Validate a config without starting the server by loading it in Python:

  ```bash
  .venv/bin/python -c "from xspct_hook.config import build_profiles, load_config; build_profiles(load_config('examples/config.reference.yaml'))"
  ```
