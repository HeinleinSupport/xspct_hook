# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""ClamAV adapter: INSTREAM protocol over TCP or a Unix socket, one fresh connection per scan."""

from __future__ import annotations

import asyncio

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.decision import ResponseOverride, ScanVerdict
from xspct_hook.protocol.models import HookContext, Stage

_DEFAULT_PORT = 3310
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_CHUNK_SIZE = 64 * 1024


class ClamAVAdapter:
    """Scans the message body via clamd's INSTREAM command.

    Opens a dedicated connection per scan (no pooling), so ``connect()`` is only an
    optional fail-fast PING health check and ``close()`` is a no-op.
    """

    name = "clamav"
    supported_stages = frozenset({Stage.DATA})
    supported_actions = frozenset({Action.ACCEPT, Action.REJECT})

    def __init__(
        self,
        *,
        host: str | None = None,
        port: int = _DEFAULT_PORT,
        unix_socket: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
    ) -> None:
        if not unix_socket and not host:
            raise ValueError("ClamAVAdapter requires either 'host' or 'unix_socket'")
        if timeout <= 0 or chunk_size <= 0:
            raise ValueError("timeout and chunk_size must be positive")
        self.host = host
        self.port = port
        self.unix_socket = unix_socket
        self.timeout = timeout
        self.chunk_size = chunk_size

    async def connect(self) -> None:
        async with asyncio.timeout(self.timeout):
            await self._ping()

    async def _ping(self) -> None:
        reader, writer = await self._open_connection()
        try:
            writer.write(b"nPING\n")
            await writer.drain()
            pong = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
        finally:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=self.timeout)
        if pong.strip() != b"PONG":
            raise RuntimeError(f"clamd did not respond to PING: {pong!r}")

    async def close(self) -> None:
        return None

    async def _open_connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self.unix_socket:
            return await asyncio.open_unix_connection(self.unix_socket)
        assert self.host is not None
        return await asyncio.open_connection(self.host, self.port)

    async def scan(self, ctx: HookContext) -> ScanVerdict:
        async with asyncio.timeout(self.timeout):
            return await self._scan(ctx)

    async def _scan(self, ctx: HookContext) -> ScanVerdict:
        if "message" not in ctx.provided_properties:
            return ScanVerdict.error_result(self.name, "no message body available for this stage")
        message = ctx.property("message")
        if message is None:
            return ScanVerdict.error_result(self.name, "no message body available for this stage")

        reader, writer = await self._open_connection()
        try:
            writer.write(b"nINSTREAM\n")
            async for chunk in message.chunks(self.chunk_size):
                writer.write(len(chunk).to_bytes(4, "big") + chunk)
                await writer.drain()
            writer.write((0).to_bytes(4, "big"))
            await writer.drain()
            raw = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
        finally:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=self.timeout)
        return self._parse_result(raw)

    def _parse_result(self, raw: bytes) -> ScanVerdict:
        text = raw.decode("utf-8", errors="replace").strip()
        if text.endswith("OK"):
            return ScanVerdict.ok(self.name, Action.ACCEPT)
        if text.endswith("FOUND"):
            signature = text.removeprefix("stream:").removesuffix("FOUND").strip()
            return ScanVerdict.ok(
                self.name,
                Action.REJECT,
                response=ResponseOverride(
                    status=550, enhanced_code="5.7.1", message=f"virus detected: {signature}"
                ),
                scanner_context={"signature": signature},
            )
        return ScanVerdict.error_result(self.name, f"unexpected clamd response: {text!r}")
