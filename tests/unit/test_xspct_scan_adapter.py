# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""xspct_scan multipart uploads, MIME decoding and conservative report handling."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from email import policy
from email.errors import MessageDefect
from email.message import EmailMessage
from email.parser import BytesParser
from functools import partial
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from pydantic import ValidationError

from xspct_hook.adapters.xspct_scan import XspctScanAdapter
from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.canonical import parse_hook_request
from xspct_hook.protocol.decision import VerdictStatus
from xspct_hook.protocol.models import HookContext


def _report(**overrides: object) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "2.0",
        "file": {"name": "part.txt", "type": "text"},
        "scan": {"status": "finished", "analyzers": {}},
        "status": "finished",
        "verdict": {"severity": "unknown"},
    }
    result.update(overrides)
    return result


class _Backend:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.response = httpx.Response(200, json=_report())
        self.delay = 0.0
        self.error: httpx.TransportError | None = None

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/health":
            return httpx.Response(200, text="OK")
        if self.error is not None:
            raise self.error
        await asyncio.sleep(self.delay)
        return self.response


@pytest.fixture
def backend(monkeypatch: pytest.MonkeyPatch) -> _Backend:
    backend = _Backend()
    monkeypatch.setattr(
        "xspct_hook.adapters.xspct_scan.httpx.AsyncClient",
        partial(AsyncClient, transport=httpx.MockTransport(backend.handle)),
    )
    return backend


@pytest.fixture
async def adapter(backend: _Backend) -> AsyncIterator[XspctScanAdapter]:
    adapter = XspctScanAdapter(base_url="http://scanner", api_key="test-key")
    try:
        yield adapter
    finally:
        await adapter.close()


def _ctx(raw: bytes) -> HookContext:
    return parse_hook_request(
        {
            "stage": "data",
            "queue": {"id": "queue-123"},
            "rawMessage": base64.b64encode(raw).decode(),
        },
        spool_threshold_mb=0,
    )


async def test_uploads_decoded_mime_leaves_with_metadata(
    adapter: XspctScanAdapter, backend: _Backend
) -> None:
    message = EmailMessage()
    message["Message-ID"] = "<mime@example.test>"
    message.set_content("hello ü", cte="quoted-printable")
    message.add_alternative("<html>hello</html>", subtype="html")
    message.add_attachment(
        b"\x00\xffbinary", maintype="application", subtype="octet-stream", filename="résumé.bin"
    )
    forwarded = EmailMessage()
    forwarded.set_content("forwarded")
    message.add_attachment(forwarded)
    ctx = _ctx(message.as_bytes())
    try:
        verdict = await adapter.scan(ctx)
        assert verdict.action == Action.ACCEPT
        uploads = []
        for request in backend.requests:
            assert request.url.path == "/v1/scan"
            assert request.url.params["timeout"] == "10.0"
            assert request.headers["X-Api-Key"] == "test-key"
            assert request.headers["Accept"] == "application/json"
            form = BytesParser(policy=policy.default).parsebytes(
                f"Content-Type: {request.headers['Content-Type']}\r\n\r\n".encode()
                + request.content
            )
            fields = {
                part.get_param("name", header="content-disposition"): part
                for part in form.iter_parts()
            }
            raw_metadata = fields["metadata"].get_payload(decode=True)
            assert isinstance(raw_metadata, bytes)
            metadata = json.loads(raw_metadata)
            assert metadata["queue_id"] == "queue-123"
            assert metadata["message_id"] == "<mime@example.test>"
            assert metadata["timeout_s"] == 10
            uploads.append((metadata, fields["file"].get_payload(decode=True)))
        assert [data for _, data in uploads] == [
            "hello ü\n".encode(),
            b"<html>hello</html>\n",
            b"\x00\xffbinary",
            b"forwarded\n",
        ]
        assert uploads[1][0]["declared_content_type"] == "text/html"
        assert uploads[2][0]["filename"] == "résumé.bin"
        assert len(verdict.scanner_context["parts"]) == 4
        assert ctx.property("message").read_all() == message.as_bytes()
    finally:
        ctx.property("message").close()


@pytest.mark.parametrize(
    "fields",
    [
        {"engines": {"clamav": {"status": "infected", "viruses": ["Lab.Marker"]}}},
        {"findings": [{"type": "ClamAV", "keyword": "Archive.Member.Marker"}]},
    ],
)
async def test_confirmed_infections_reject(
    adapter: XspctScanAdapter, backend: _Backend, fields: dict[str, object]
) -> None:
    backend.response = httpx.Response(200, json=_report(**fields))
    ctx = _ctx(b"\r\ncontent")
    try:
        verdict = await adapter.scan(ctx)
        assert verdict.action == Action.REJECT
        assert verdict.response is not None
        assert verdict.response.status == 550
        assert verdict.response.enhanced_code == "5.7.1"
    finally:
        ctx.property("message").close()


async def test_other_findings_are_context_not_a_rejection(
    adapter: XspctScanAdapter, backend: _Backend
) -> None:
    backend.response = httpx.Response(
        200,
        json=_report(
            verdict={"severity": "critical"},
            scan={
                "status": "finished",
                "cache_hit": True,
                "analyzers": {"completed": ["office", "yara"]},
            },
            findings=[{"type": "AutoExec", "keyword": "AutoOpen", "severity": "high"}],
            flags={"macros": True, "decryption_password": "do-not-export"},
            content={"full": [{"text": "do-not-export"}]},
            engines={
                "yara": {"matches": [{"rule": "Informational"}]},
                "image": {"exif": {"Artist": "do-not-export", "GPSInfo": "do-not-export"}},
            },
        ),
    )
    ctx = _ctx(b"\r\ncontent")
    try:
        verdict = await adapter.scan(ctx)
        assert verdict.action == Action.ACCEPT
        report = verdict.scanner_context["parts"][0]["report"]
        assert report["findings"][0]["keyword"] == "AutoOpen"
        assert report["engines"]["yara"]["matches"]
        assert report["scan"]["cache_hit"] is True
        assert report["scan"]["analyzers"]["completed"] == ["office", "yara"]
        assert report["flags"] == {"macros": True}
        assert "do-not-export" not in json.dumps(verdict.scanner_context)
    finally:
        ctx.property("message").close()


@pytest.mark.parametrize(
    ("status", "fields"),
    [
        (202, {}),
        (200, {"status": "processing"}),
        (200, {"status": "dropped"}),
        (200, {"status": "error"}),
        (200, {"scan": {"status": "processing", "analyzers": {}}}),
        (200, {"scan": {"status": "finished", "analyzers": {"pending": ["yara"]}}}),
        (200, {"scan": {"status": "finished", "analyzers": {"errors": {"yara": "Error"}}}}),
        *[
            (200, {"engines": {"clamav": {"status": status}}})
            for status in ("error", "timeout", "unavailable", "skipped")
        ],
    ],
)
async def test_partial_or_failed_analysis_is_an_error_not_acceptance(
    adapter: XspctScanAdapter, backend: _Backend, status: int, fields: dict[str, object]
) -> None:
    backend.response = httpx.Response(status, json=_report(**fields))
    ctx = _ctx(b"\r\ncontent")
    try:
        verdict = await adapter.scan(ctx)
        assert verdict.status == VerdictStatus.ERROR
        assert verdict.action is None
        assert verdict.scanner_context["parts"]
    finally:
        ctx.property("message").close()


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401),
        httpx.Response(503),
        httpx.Response(302, headers={"Location": "http://other-scanner/v1/scan"}),
        httpx.Response(204),
        httpx.Response(200, text="{"),
        httpx.Response(200, json={}),
        httpx.Response(200, json=_report(schema_version="1.0")),
        httpx.Response(200, json=_report(engines={"clamav": {"status": "unexpected"}})),
    ],
)
async def test_bad_backend_responses_surface(
    adapter: XspctScanAdapter, backend: _Backend, response: httpx.Response
) -> None:
    backend.response = response
    ctx = _ctx(b"\r\ncontent")
    try:
        with pytest.raises((httpx.HTTPStatusError, ValueError, ValidationError)):
            await adapter.scan(ctx)
        assert len(backend.requests) == 1
    finally:
        ctx.property("message").close()


async def test_connection_failure_surfaces(adapter: XspctScanAdapter, backend: _Backend) -> None:
    backend.error = httpx.ConnectError("scanner unavailable")
    ctx = _ctx(b"\r\ncontent")
    try:
        with pytest.raises(httpx.ConnectError):
            await adapter.scan(ctx)
    finally:
        ctx.property("message").close()


async def test_entire_multi_part_scan_has_one_deadline(backend: _Backend) -> None:
    backend.delay = 0.03
    adapter = XspctScanAdapter(base_url="http://scanner", timeout=0.05)
    message = EmailMessage()
    message.set_content("text")
    message.add_alternative("<html>html</html>", subtype="html")
    ctx = _ctx(message.as_bytes())
    try:
        with pytest.raises(TimeoutError):
            await adapter.scan(ctx)
        assert len(backend.requests) == 2
    finally:
        ctx.property("message").close()
        await adapter.close()


async def test_invalid_mime_is_not_silently_partially_scanned(
    adapter: XspctScanAdapter, backend: _Backend
) -> None:
    ctx = _ctx(b"Content-Transfer-Encoding: base64\r\n\r\n!not-base64!")
    try:
        with pytest.raises(MessageDefect):
            await adapter.scan(ctx)
        assert not backend.requests
    finally:
        ctx.property("message").close()


async def test_empty_content_has_nothing_to_upload(
    adapter: XspctScanAdapter, backend: _Backend
) -> None:
    ctx = _ctx(b"Subject: empty\r\n\r\n")
    try:
        verdict = await adapter.scan(ctx)
        assert verdict.action == Action.ACCEPT
        assert verdict.scanner_context["parts"] == []
        assert not backend.requests
    finally:
        ctx.property("message").close()


async def test_scan_preserves_another_consumers_spooled_body_cursor(
    adapter: XspctScanAdapter,
) -> None:
    ctx = _ctx(b"\r\nabcdef")
    chunks = ctx.property("message").chunks(2)
    try:
        assert await anext(chunks) == b"\r\n"
        assert (await adapter.scan(ctx)).action == Action.ACCEPT
        assert b"".join([chunk async for chunk in chunks]) == b"abcdef"
    finally:
        await chunks.aclose()
        ctx.property("message").close()


async def test_wrong_stage_is_not_scanned(adapter: XspctScanAdapter, backend: _Backend) -> None:
    ctx = parse_hook_request({"stage": "mail", "properties": {"message_contents": "data"}})
    try:
        assert (await adapter.scan(ctx)).status == VerdictStatus.ERROR
        assert not backend.requests
    finally:
        ctx.property("message").close()


async def test_missing_body_is_an_error(adapter: XspctScanAdapter) -> None:
    assert (await adapter.scan(parse_hook_request({"stage": "data"}))).status == VerdictStatus.ERROR


async def test_health_and_client_cleanup(adapter: XspctScanAdapter, backend: _Backend) -> None:
    await adapter.connect()
    assert backend.requests[0].url.path == "/health"
    await adapter.close()
    with pytest.raises(RuntimeError, match="closed"):
        await adapter.connect()


@pytest.mark.parametrize("base_url", ["file:///tmp/scan", "http://user:secret@scanner", "http://"])
def test_invalid_backend_urls_are_refused(base_url: str) -> None:
    with pytest.raises(ValueError, match="base_url"):
        XspctScanAdapter(base_url=base_url)


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan")])
def test_invalid_deadlines_are_refused(value: float) -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        XspctScanAdapter(base_url="http://scanner", timeout=value)
