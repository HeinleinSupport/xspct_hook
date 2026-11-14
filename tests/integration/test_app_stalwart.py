# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Integration tests: the FastAPI app's Stalwart route, driven by the PseudoScannerAdapter."""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import partial
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from xspct_hook.app import create_app
from xspct_hook.config import AppConfig


def _config(tmp_path: Path, **profile_overrides: object) -> AppConfig:
    profile = {
        "name": "pseudo-test",
        "path": "/hooks/pseudo-test",
        "token": "test-token",
        "stages": ["mail", "rcpt", "data"],
        "strategy": "first_reject_wins",
        "adapters": [{"type": "pseudo", "default_scenario": "clean"}],
    }
    profile.update(profile_overrides)
    return AppConfig.model_validate(
        {"jsonl_log_path": str(tmp_path / "events.jsonl"), "profiles": [profile]}
    )


@pytest.fixture
async def client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    app: FastAPI = create_app(_config(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as async_client,
    ):
        yield async_client


def _stalwart_payload(stage: str, **props: object) -> dict[str, object]:
    envelope: dict[str, object] = {"from": {"address": "sender@example.com"}, "to": []}
    if "mail_from" in props:
        envelope["from"] = {"address": props["mail_from"]}
    if "rcpt_to" in props:
        envelope["to"] = [{"address": props["rcpt_to"]}]
    return {"context": {"stage": stage}, "envelope": envelope}


async def test_missing_bearer_token_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/hooks/pseudo-test", json=_stalwart_payload("mail", mail_from="a@example.com")
    )
    assert response.status_code == 401


async def test_wrong_bearer_token_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/hooks/pseudo-test",
        json=_stalwart_payload("mail", mail_from="a@example.com"),
        headers={"Authorization": "Bearer wrong"},
    )
    assert response.status_code == 401


async def test_clean_mail_stage_accepts(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/hooks/pseudo-test",
        json=_stalwart_payload("mail", mail_from="a@example.com"),
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    assert response.json()["action"] == "accept"


async def test_rcpt_stage_malicious_recipient_rejects(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/hooks/pseudo-test",
        json=_stalwart_payload("rcpt", rcpt_to="verdict+malicious@test.local"),
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "reject"
    assert body["response"]["status"] == 550


async def test_data_stage_header_add_modification(client: httpx.AsyncClient) -> None:
    payload = {
        "context": {"stage": "data"},
        "envelope": {
            "from": {"address": "sender@example.com"},
            "to": [{"address": "verdict+header_add@test.local"}],
        },
        "message": {"headers": [["Subject", " hi\r\n"]], "contents": "body\r\n"},
    }
    response = await client.post(
        "/hooks/pseudo-test", json=payload, headers={"Authorization": "Bearer test-token"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "accept"
    assert body["modifications"] == [
        {"type": "deleteHeader", "name": "Subject", "index": 1},
        {"type": "addHeader", "name": "X-Xspct-Scan", "value": "pseudo:clean"},
        {"type": "addHeader", "name": "Subject", "value": "hi"},
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"context": {"stage": "invalid"}},
        {"context": {"stage": "auth"}},
        {"context": {"stage": "rcpt"}, "envelope": {"from": "bad"}},
        [],
    ],
)
async def test_malformed_payload_is_client_error(
    client: httpx.AsyncClient, payload: object
) -> None:
    response = await client.post(
        "/hooks/pseudo-test", json=payload, headers={"Authorization": "Bearer test-token"}
    )
    assert response.status_code == 400


@pytest.mark.parametrize("header_field", ["headers", "serverHeaders"])
async def test_invalid_header_framing_is_client_error(
    client: httpx.AsyncClient, header_field: str
) -> None:
    response = await client.post(
        "/hooks/pseudo-test",
        headers={"Authorization": "Bearer test-token"},
        json={
            "context": {"stage": "data"},
            "message": {
                header_field: [["Subject", " hi\r\nBcc: extra\r\n"]],
                "contents": "body",
            },
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


async def test_malformed_json_is_client_error(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/hooks/pseudo-test",
        content="{",
        headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
    )
    assert response.status_code == 400


async def test_response_includes_ext_provenance(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/hooks/pseudo-test",
        json=_stalwart_payload("mail", mail_from="a@example.com"),
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.json()["ext"]["provenance"][0]["engine"] == "pseudo"


async def test_disabled_stage_returns_400(tmp_path: Path) -> None:
    app = create_app(_config(tmp_path, stages=["mail"]))
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as async_client,
    ):
        response = await async_client.post(
            "/hooks/pseudo-test",
            json=_stalwart_payload("rcpt", rcpt_to="a@example.com"),
            headers={"Authorization": "Bearer test-token"},
        )
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("backend_status", "scan_status", "clamav_status", "error_policy", "action", "smtp_status"),
    [
        (200, "finished", "clean", "fail_closed", "accept", None),
        (200, "finished", "infected", "fail_closed", "reject", 550),
        (202, "processing", "clean", "fail_closed", "reject", 451),
        (202, "processing", "clean", "fail_open", "accept", None),
        (503, "error", "clean", "fail_closed", "reject", 451),
    ],
)
async def test_xspct_scan_verdicts_reach_stalwart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend_status: int,
    scan_status: str,
    clamav_status: str,
    error_policy: str,
    action: str,
    smtp_status: int | None,
) -> None:
    def backend(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, text="OK")
        return httpx.Response(
            backend_status,
            json={
                "schema_version": "2.0",
                "file": {"name": "part.txt"},
                "status": scan_status,
                "scan": {"status": scan_status, "analyzers": {}},
                "verdict": {"severity": "unknown"},
                "engines": {"clamav": {"status": clamav_status}},
            },
        )

    with monkeypatch.context() as patch:
        patch.setattr(
            "xspct_hook.adapters.xspct_scan.httpx.AsyncClient",
            partial(AsyncClient, transport=httpx.MockTransport(backend)),
        )
        app = create_app(
            _config(
                tmp_path,
                stages=["data"],
                on_adapter_error=error_policy,
                adapters=[{"type": "xspct_scan", "base_url": "http://scanner"}],
            )
        )
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://hook") as client,
    ):
        response = await client.post(
            "/hooks/pseudo-test",
            headers={"Authorization": "Bearer test-token"},
            json={
                "context": {"stage": "data"},
                "message": {"headers": [["Content-Type", " text/plain\r\n"]], "contents": "hello"},
            },
        )
    assert response.status_code == 200
    result = response.json()
    assert result["action"] == action
    if smtp_status is not None:
        assert result["response"]["status"] == smtp_status
    assert result["ext"]["provenance"][0]["engine"] == "xspct_scan"
