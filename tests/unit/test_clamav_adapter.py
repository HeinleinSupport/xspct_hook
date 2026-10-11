# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for adapters/clamav.py against a fake asyncio clamd server (no real clamd needed)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from xspct_hook.adapters.clamav import ClamAVAdapter
from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.canonical import parse_hook_request
from xspct_hook.protocol.decision import VerdictStatus


class _FakeClamd:
    """A minimal clamd stand-in speaking just enough of the PING/INSTREAM protocol."""

    def __init__(self, *, verdict: str = "OK") -> None:
        self.verdict = verdict
        self.server: asyncio.AbstractServer | None = None
        self.port: int = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, host="127.0.0.1", port=0)
        self.port = self.server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = await reader.readline()
        command = line.strip()
        if command == b"nPING":
            writer.write(b"PONG\n")
        elif command == b"nINSTREAM":
            total = 0
            while True:
                length_bytes = await reader.readexactly(4)
                length = int.from_bytes(length_bytes, "big")
                if length == 0:
                    break
                total += len(await reader.readexactly(length))
            if self.verdict == "OK":
                writer.write(b"stream: OK\n")
            else:
                writer.write(f"stream: {self.verdict} FOUND\n".encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()


@pytest.fixture
async def fake_clamd() -> AsyncIterator[_FakeClamd]:
    server = _FakeClamd()
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


def _data_ctx(contents: str = "Subject: hi\r\n\r\nbody\r\n"):
    return parse_hook_request({"stage": "data", "properties": {"message_contents": contents}})


async def test_connect_succeeds_against_fake_server(fake_clamd: _FakeClamd) -> None:
    adapter = ClamAVAdapter(host="127.0.0.1", port=fake_clamd.port)
    await adapter.connect()


async def test_scan_clean_message_returns_accept(fake_clamd: _FakeClamd) -> None:
    adapter = ClamAVAdapter(host="127.0.0.1", port=fake_clamd.port)
    ctx = _data_ctx()
    verdict = await adapter.scan(ctx)
    ctx.property("message").close()
    assert verdict.action == Action.ACCEPT


async def test_scan_infected_message_returns_reject() -> None:
    server = _FakeClamd(verdict="Eicar-Test-Signature")
    await server.start()
    try:
        adapter = ClamAVAdapter(host="127.0.0.1", port=server.port)
        ctx = _data_ctx()
        verdict = await adapter.scan(ctx)
        ctx.property("message").close()
        assert verdict.action == Action.REJECT
        assert verdict.scanner_context["signature"] == "Eicar-Test-Signature"
    finally:
        await server.stop()


async def test_scan_without_message_body_errors(fake_clamd: _FakeClamd) -> None:
    adapter = ClamAVAdapter(host="127.0.0.1", port=fake_clamd.port)
    ctx = parse_hook_request({"stage": "mail", "properties": {"mail_from": "a@example.com"}})
    verdict = await adapter.scan(ctx)
    assert verdict.status == VerdictStatus.ERROR


def test_requires_host_or_unix_socket() -> None:
    with pytest.raises(ValueError, match="host.*unix_socket"):
        ClamAVAdapter()


def test_supported_actions_are_restricted() -> None:
    adapter = ClamAVAdapter(host="127.0.0.1")
    assert adapter.supported_actions == frozenset({Action.ACCEPT, Action.REJECT})


async def test_connection_open_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    async def stalled_connection(*args, **kwargs):
        await asyncio.Future()

    monkeypatch.setattr(asyncio, "open_connection", stalled_connection)
    adapter = ClamAVAdapter(host="127.0.0.1", timeout=0.01)
    with pytest.raises(TimeoutError):
        await adapter.connect()
    ctx = _data_ctx()
    try:
        with pytest.raises(TimeoutError):
            await adapter.scan(ctx)
    finally:
        ctx.property("message").close()
