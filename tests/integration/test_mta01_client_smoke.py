# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Integration test: Mta01TestClient's full discovery -> register -> smoke calls -> deregister run."""

from __future__ import annotations

from pathlib import Path

import httpx

from xspct_hook.app import create_app
from xspct_hook.config import AppConfig
from xspct_hook.testing.mta01_client import Mta01TestClient


def _config(tmp_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "jsonl_log_path": str(tmp_path / "events.jsonl"),
            "profiles": [
                {
                    "name": "pseudo-test",
                    "path": "/hooks/pseudo-test",
                    "token": "test-token",
                    "stages": ["mail", "rcpt", "data", "delivery"],
                    "adapters": [{"type": "pseudo", "default_scenario": "clean"}],
                }
            ],
        }
    )


async def test_mta01_smoke_suite_completes(tmp_path: Path) -> None:
    app = create_app(_config(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as http_client,
    ):
        smoke_client = Mta01TestClient(
            http_client, profile_path="/hooks/pseudo-test", token="test-token"
        )
        results = await smoke_client.run_smoke_suite()

    assert len(results) == 4
    assert [result["set"][0]["value"] for result in results] == [
        "accept",
        "reject",
        "quarantine",
        "continue",
    ]
    assert smoke_client.registration_id is None  # deregistered at the end


async def test_smoke_suite_skips_disabled_delivery(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.profiles[0].stages.remove("delivery")
    app = create_app(config)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        smoke_client = Mta01TestClient(
            client, profile_path="/hooks/pseudo-test", token="test-token"
        )
        assert len(await smoke_client.run_smoke_suite()) == 3
