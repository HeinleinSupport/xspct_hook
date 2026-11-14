# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Integration tests: the native -01 discovery/registration/hook routes."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from xspct_hook.app import create_app
from xspct_hook.config import AppConfig


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "jsonl_log_path": str(tmp_path / "events.jsonl"),
            "profiles": [
                {
                    "name": "pseudo-test",
                    "path": "/hooks/pseudo-test",
                    "token": "test-token",
                    "stages": ["mail", "rcpt", "data"],
                    "adapters": [{"type": "pseudo", "default_scenario": "clean"}],
                }
            ],
        }
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


def test_openapi_describes_manually_decoded_requests(tmp_path: Path) -> None:
    schema = create_app(_config(tmp_path)).openapi()
    paths = schema["paths"]
    schemas = schema["components"]["schemas"]
    for path in ("/hooks/pseudo-test", "/hooks/pseudo-test/mta01", "/hooks/pseudo-test/register"):
        operation = paths[path]["post"]
        body = operation["requestBody"]
        assert body["required"] is True
        reference = body["content"]["application/json"]["schema"]["$ref"]
        model = schemas[reference.rsplit("/", 1)[1]]
        assert model["type"] == "object"
        assert model["required"]

    native = paths["/hooks/pseudo-test/mta01"]["post"]
    headers = {
        parameter["name"]: parameter
        for parameter in native["parameters"]
        if parameter["in"] == "header"
    }
    for name in ("X-MTA-Hooks-Registration", "X-MTA-Hooks-Request-Id"):
        assert headers[name]["required"] is True
        assert "default" not in headers[name]["schema"]
    assert "action" in schemas["HookPayload"]["required"]
    assert "properties" not in schemas["HookPayload"]["properties"]
    assert "201" in paths["/hooks/pseudo-test/register"]["post"]["responses"]
    assert "200" not in paths["/hooks/pseudo-test/register"]["post"]["responses"]


async def test_discovery_lists_endpoints(client: httpx.AsyncClient) -> None:
    response = await client.get("/hooks/pseudo-test/.well-known/mta-hooks")
    assert response.status_code == 200
    body = response.json()
    assert body["endpoints"]["registration"] == "/hooks/pseudo-test/register"
    assert body["version"] == "1.0"


async def test_register_requires_bearer_token(client: httpx.AsyncClient) -> None:
    response = await client.post("/hooks/pseudo-test/register")
    assert response.status_code == 401


async def test_register_then_call_hook_then_deregister(client: httpx.AsyncClient) -> None:
    auth = {"Authorization": "Bearer test-token"}
    register_response = await client.post(
        "/hooks/pseudo-test/register",
        headers=auth,
        json={"name": "test-mta", "serialization": "json", "inbound": {"stages": ["mail"]}},
    )
    assert register_response.status_code == 201
    registration_id = register_response.json()["registrationId"]

    hook_response = await client.post(
        "/hooks/pseudo-test/mta01",
        json={
            "stage": "mail",
            "action": "accept",
            "envelope": {"from": {"address": "a@example.com"}, "to": []},
        },
        headers={
            **auth,
            "X-MTA-Hooks-Registration": registration_id,
            "X-MTA-Hooks-Request-Id": "request-1",
        },
    )
    assert hook_response.status_code == 200
    assert hook_response.json()["set"] == [{"path": "/action", "value": "accept"}]

    deregister_response = await client.delete(
        f"/hooks/pseudo-test/register/{registration_id}", headers=auth
    )
    assert deregister_response.status_code == 200
    assert deregister_response.json()["status"] == "deregistered"
    after_delete = await client.post(
        "/hooks/pseudo-test/mta01",
        headers={**auth, "X-MTA-Hooks-Registration": registration_id},
        json={},
    )
    assert after_delete.status_code == 410
    assert after_delete.json()["error"]["code"] == "REGISTRATION_DEREGISTERED"


async def test_hook_call_without_registration_returns_404(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/hooks/pseudo-test/mta01",
        json={"stage": "mail", "properties": {}},
        headers={"Authorization": "Bearer test-token", "X-MTA-Hooks-Registration": "unknown"},
    )
    assert response.status_code == 404


async def test_deregister_unknown_id_returns_404(client: httpx.AsyncClient) -> None:
    response = await client.delete(
        "/hooks/pseudo-test/register/unknown", headers={"Authorization": "Bearer test-token"}
    )
    assert response.status_code == 404


async def test_root_discovery(client: httpx.AsyncClient) -> None:
    response = await client.get("/.well-known/mta-hooks")
    assert response.status_code == 200
    assert response.json()["capabilities"]["inbound"]["stages"] == ["data", "mail", "rcpt"]


async def test_cross_profile_registration_is_rejected(tmp_path: Path) -> None:
    config = _config(tmp_path)
    profile = config.profiles[0].model_copy(
        update={"name": "other", "path": "/hooks/other", "token": "other-token"}
    )
    config.profiles.append(profile)
    app = create_app(config)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as http_client,
    ):
        response = await http_client.post(
            "/hooks/pseudo-test/register",
            headers={"Authorization": "Bearer test-token"},
            json={"name": "test-mta", "serialization": "json", "inbound": {"stages": ["mail"]}},
        )
        registration_id = response.json()["registrationId"]
        headers = {
            "Authorization": "Bearer other-token",
            "X-MTA-Hooks-Registration": registration_id,
        }
        assert (
            await http_client.post("/hooks/other/mta01", headers=headers, json={})
        ).status_code == 403
        assert (
            await http_client.delete(f"/hooks/other/register/{registration_id}", headers=headers)
        ).status_code == 403
        assert app.state.registration_store.get(registration_id) is not None
        assert (
            await http_client.get(
                f"/hooks/other/register/{registration_id}/status", headers=headers
            )
        ).status_code == 403


@pytest.mark.parametrize("request_id", [None, "bad id", "x" * 129])
async def test_invalid_request_id_is_rejected(
    client: httpx.AsyncClient, request_id: str | None
) -> None:
    auth = {"Authorization": "Bearer test-token"}
    registered = await client.post(
        "/hooks/pseudo-test/register",
        headers=auth,
        json={"name": "test-mta", "serialization": "json", "inbound": {"stages": ["mail"]}},
    )
    headers = {**auth, "X-MTA-Hooks-Registration": registered.json()["registrationId"]}
    if request_id is not None:
        headers["X-MTA-Hooks-Request-Id"] = request_id
    response = await client.post(
        "/hooks/pseudo-test/mta01", headers=headers, json={"stage": "mail", "action": "accept"}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "MISSING_REQUEST_ID"


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "test-mta", "serialization": "json"},
        {"name": "test-mta", "serialization": "json", "outbound": {"stages": ["delivery"]}},
    ],
)
async def test_unsupported_registration_is_rejected(
    client: httpx.AsyncClient, payload: dict
) -> None:
    response = await client.post(
        "/hooks/pseudo-test/register", headers={"Authorization": "Bearer test-token"}, json=payload
    )
    assert response.status_code == 400


async def test_outbound_fail_closed_returns_unavailable(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.profiles[0] = config.profiles[0].model_copy(
        update={
            "stages": ["delivery"],
            "on_adapter_error": "fail_closed",
            "adapters": [
                config.profiles[0].adapters[0].model_copy(update={"default_scenario": "error"})
            ],
        }
    )
    app = create_app(config)
    auth = {"Authorization": "Bearer test-token"}
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        registered = await client.post(
            "/hooks/pseudo-test/register",
            headers=auth,
            json={
                "name": "test-mta",
                "serialization": "json",
                "outbound": {"stages": ["delivery"]},
            },
        )
        response = await client.post(
            "/hooks/pseudo-test/mta01",
            headers={
                **auth,
                "X-MTA-Hooks-Registration": registered.json()["registrationId"],
                "X-MTA-Hooks-Request-Id": "request-1",
            },
            json={"stage": "delivery", "action": "continue"},
        )
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "SCANNER_UNAVAILABLE"
