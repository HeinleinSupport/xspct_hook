# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Native -01 smoke-test client: discovery -> register -> representative hook calls -> deregister.

Reused both as a pytest fixture-driven integration test and as a small CLI demo against a
running server — same client code, two entry points.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import httpx

from xspct_hook.protocol.modifications import (
    AddOperation,
    DeleteOperation,
    SetOperation,
    apply_modifications,
)


def _client_server() -> tuple[dict[str, Any], dict[str, Any]]:
    return {"ip": "203.0.113.5", "port": 51234}, {"ip": "198.51.100.10", "port": 25}


def _mail_accept_payload() -> dict[str, Any]:
    client, server = _client_server()
    return {
        "stage": "mail",
        "action": "accept",
        "timestamp": datetime.now(UTC).isoformat(),
        "client": client,
        "server": server,
        "envelope": {"from": {"address": "sender@example.com"}, "to": []},
    }


def _rcpt_reject_payload() -> dict[str, Any]:
    client, server = _client_server()
    return {
        **_mail_accept_payload(),
        "stage": "rcpt",
        "client": client,
        "server": server,
        "envelope": {
            "from": {"address": "sender@example.com"},
            "to": [{"address": "verdict+reject@test.local"}],
        },
    }


def _data_quarantine_payload() -> dict[str, Any]:
    client, server = _client_server()
    return {
        **_mail_accept_payload(),
        "stage": "data",
        "client": client,
        "server": server,
        "envelope": {
            "from": {"address": "sender@example.com"},
            "to": [{"address": "verdict+suspicious@test.local"}],
        },
        "message": {"headers": [{"name": "Subject", "value": "smoke test"}]},
        "rawMessage": base64.b64encode(b"Subject: smoke test\r\n\r\nHello world.\r\n").decode(
            "ascii"
        ),
    }


def _delivery_continue_payload() -> dict[str, Any]:
    client, server = _client_server()
    return {
        **_mail_accept_payload(),
        "stage": "delivery",
        "action": "continue",
        "client": client,
        "server": server,
    }


class Mta01TestClient:
    """Drives one profile's native -01 discovery/registration/hook routes."""

    def __init__(self, client: httpx.AsyncClient, *, profile_path: str, token: str) -> None:
        self._client = client
        self._profile_path = profile_path.rstrip("/")
        self._token = token
        self.registration_id: str | None = None
        self.hook_endpoint: str | None = None
        self.discovery: dict[str, Any] = {}
        self.deregistration_endpoint: str | None = None

    @property
    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    async def discover(self) -> dict[str, Any]:
        response = await self._client.get(f"{self._profile_path}/.well-known/mta-hooks")
        response.raise_for_status()
        self.discovery = response.json()
        return self.discovery

    async def register(self) -> str:
        if not self.discovery:
            await self.discover()
        payload: dict[str, Any] = {"name": "xspct-smoke-mta", "serialization": "json"}
        for direction in ("inbound", "outbound"):
            capability = self.discovery["capabilities"].get(direction)
            if capability:
                payload[direction] = {"stages": capability["stages"]}
        response = await self._client.post(
            self.discovery["endpoints"]["registration"], headers=self._auth_headers, json=payload
        )
        response.raise_for_status()
        if response.status_code != 201:
            raise AssertionError("registration must return HTTP 201")
        data = response.json()
        self.registration_id = data["registrationId"]
        self.hook_endpoint = data["hookEndpoint"]
        self.deregistration_endpoint = data["endpoints"]["deregistration"]
        return self.registration_id

    async def deregister(self) -> None:
        if self.registration_id is None:
            return
        response = await self._client.delete(
            self.deregistration_endpoint or f"{self._profile_path}/register/{self.registration_id}",
            headers=self._auth_headers,
        )
        response.raise_for_status()
        if response.status_code != 200 or response.json()["status"] != "deregistered":
            raise AssertionError("deregistration must return a confirmation")
        self.registration_id = None

    async def call_hook(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.hook_endpoint is None or self.registration_id is None:
            raise RuntimeError("call register() before call_hook()")
        headers = {
            **self._auth_headers,
            "X-MTA-Hooks-Registration": self.registration_id,
            "X-MTA-Hooks-Request-Id": str(uuid4()),
        }
        response = await self._client.post(self.hook_endpoint, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()  # type: ignore[no-any-return]

    async def run_smoke_suite(self) -> list[dict[str, Any]]:
        """discovery -> register -> mail/rcpt/data/delivery smoke calls -> deregister."""
        await self.discover()
        await self.register()
        try:
            stages = {
                stage
                for capability in self.discovery["capabilities"].values()
                if capability
                for stage in capability["stages"]
            }
            results = []
            for payload, expected in [
                (_mail_accept_payload(), "accept"),
                (_rcpt_reject_payload(), "reject"),
                (_data_quarantine_payload(), "quarantine"),
                (_delivery_continue_payload(), "continue"),
            ]:
                if payload["stage"] not in stages:
                    continue
                result = await self.call_hook(payload)
                operations = (
                    [SetOperation(item["path"], item["value"]) for item in result["set"]]
                    + [
                        AddOperation(item["path"], item["value"], item.get("index"))
                        for item in result["add"]
                    ]
                    + [DeleteOperation(item["path"]) for item in result["delete"]]
                )
                applied = apply_modifications(payload, operations)
                if applied["action"] != expected:
                    raise AssertionError(
                        f"{payload['stage']}: expected {expected}, received {applied['action']}"
                    )
                if expected == "reject" and applied.get("response", {}).get("code") != 550:
                    raise AssertionError("reject response must contain SMTP code 550")
                if (
                    expected == "quarantine"
                    and {"name": "X-Xspct-Scan", "value": "pseudo:suspicious"}
                    not in applied["message"]["headers"]
                ):
                    raise AssertionError("quarantine response did not apply its scan header")
                results.append(result)
            if not results:
                raise AssertionError("no representative smoke stages are enabled")
            return results
        finally:
            await self.deregister()


async def _run_cli(base_url: str, profile_path: str, token: str) -> None:
    async with httpx.AsyncClient(base_url=base_url) as client:
        smoke_client = Mta01TestClient(client, profile_path=profile_path, token=token)
        results = await smoke_client.run_smoke_suite()
    print(json.dumps(results, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the native -01 smoke-test client against a live server"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--profile-path", default="/hooks/pseudo-test")
    parser.add_argument("--token", default="change-me-pseudo")
    args = parser.parse_args()
    asyncio.run(_run_cli(args.base_url, args.profile_path, args.token))


if __name__ == "__main__":
    main()
