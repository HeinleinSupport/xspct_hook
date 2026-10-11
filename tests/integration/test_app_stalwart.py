# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Integration tests: the FastAPI app's Stalwart route, driven by the PseudoScannerAdapter."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

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
        "message": {"headers": [["Subject", "hi"]], "contents": "body\r\n"},
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
