# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Message body storage: in-memory for small messages, spooled to disk for large ones."""

from __future__ import annotations

import tempfile
from collections.abc import AsyncIterator
from typing import Self

DEFAULT_SPOOL_THRESHOLD_MB = 10.0
DEFAULT_CHUNK_SIZE = 64 * 1024


class MessageBody:
    """Holds a message body either in memory or spooled to a temp file.

    Always call :meth:`close` (or use as a context manager) to release the spool file.
    """

    def __init__(
        self, data: bytes, *, spool_threshold_mb: float = DEFAULT_SPOOL_THRESHOLD_MB
    ) -> None:
        self._size = len(data)
        self._data: bytes | None = None
        self._tmp: tempfile._TemporaryFileWrapper[bytes] | None = None
        if self._size > int(spool_threshold_mb * 1024 * 1024):
            tmp = tempfile.NamedTemporaryFile(prefix="xspct_hook-body-", suffix=".tmp")  # noqa: SIM115 - kept open for this object's lifetime
            tmp.write(data)
            tmp.flush()
            self._tmp = tmp
        else:
            self._data = data

    @classmethod
    def from_bytes(
        cls, data: bytes, *, spool_threshold_mb: float = DEFAULT_SPOOL_THRESHOLD_MB
    ) -> MessageBody:
        return cls(data, spool_threshold_mb=spool_threshold_mb)

    @classmethod
    def from_text(
        cls, text: str, *, spool_threshold_mb: float = DEFAULT_SPOOL_THRESHOLD_MB
    ) -> MessageBody:
        # Stalwart itself delivers message contents as a lossy-UTF-8 string, so
        # round-tripping through surrogateescape keeps us symmetric with that behavior.
        return cls.from_bytes(
            text.encode("utf-8", errors="surrogateescape"), spool_threshold_mb=spool_threshold_mb
        )

    @property
    def size(self) -> int:
        return self._size

    @property
    def spooled(self) -> bool:
        return self._tmp is not None

    async def chunks(self, chunk_size: int = DEFAULT_CHUNK_SIZE) -> AsyncIterator[bytes]:
        if self._data is not None:
            for offset in range(0, len(self._data), chunk_size):
                yield self._data[offset : offset + chunk_size]
            return
        assert self._tmp is not None
        self._tmp.seek(0)
        while True:
            chunk = self._tmp.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def read_all(self) -> bytes:
        if self._data is not None:
            return self._data
        assert self._tmp is not None
        position = self._tmp.tell()
        try:
            self._tmp.seek(0)
            return self._tmp.read()
        finally:
            self._tmp.seek(position)

    def close(self) -> None:
        if self._tmp is not None:
            self._tmp.close()
            self._tmp = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
