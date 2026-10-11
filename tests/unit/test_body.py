# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for body.py: MessageBody in-memory vs. spooled behavior."""

from __future__ import annotations

import asyncio

from xspct_hook.body import MessageBody


def test_small_body_stays_in_memory() -> None:
    body = MessageBody.from_bytes(b"hello world", spool_threshold_mb=10.0)
    assert not body.spooled
    assert body.size == len(b"hello world")
    assert body.read_all() == b"hello world"
    body.close()


def test_large_body_is_spooled() -> None:
    data = b"x" * 2048
    body = MessageBody.from_bytes(data, spool_threshold_mb=0.001)
    try:
        assert body.spooled
        assert body.read_all() == data
    finally:
        body.close()


def test_from_text_uses_surrogateescape() -> None:
    body = MessageBody.from_text("Subject: hi\r\n\r\nbody\r\n")
    try:
        assert body.read_all() == b"Subject: hi\r\n\r\nbody\r\n"
    finally:
        body.close()


def test_chunks_reassemble_to_full_content() -> None:
    data = b"abcdefghij" * 100

    async def _collect() -> bytes:
        body = MessageBody.from_bytes(data, spool_threshold_mb=0.0001)
        try:
            collected = b""
            async for chunk in body.chunks(chunk_size=7):
                collected += chunk
            return collected
        finally:
            body.close()

    assert asyncio.run(_collect()) == data


def test_context_manager_closes_spool() -> None:
    with MessageBody.from_bytes(b"x" * 1024, spool_threshold_mb=0.0001) as body:
        assert body.spooled
    assert body._tmp is None
