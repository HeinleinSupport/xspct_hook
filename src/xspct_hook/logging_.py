# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Appends one JSON line per event to a log file; the first (and in this phase, only) EventBus subscriber."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
from pathlib import Path
from typing import TextIO

from xspct_hook.events import Event, EventBus


class JSONLWriter:
    def __init__(self, bus: EventBus, path: Path) -> None:
        self._bus = bus
        self._path = path
        self._queue: asyncio.Queue[Event] | None = None
        self._handle: TextIO | None = None
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self._path.open("a", encoding="utf-8")
        self._queue = self._bus.subscribe()
        self._task = asyncio.create_task(self._run())
        self._task.add_done_callback(self._finished)

    def _finished(self, task: asyncio.Task[None]) -> None:
        if not task.cancelled() and task.exception() is not None:
            if self._queue is not None:
                self._bus.unsubscribe(self._queue)
            logging.getLogger(__name__).error("JSONL writer failed", exc_info=task.exception())

    async def stop(self) -> None:
        if self._queue is not None:
            self._bus.unsubscribe(self._queue)
        try:
            if self._task is not None:
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            if self._queue is not None and self._handle is not None:
                while not self._queue.empty():
                    self._write(self._queue.get_nowait())
        finally:
            self._task = None
            if self._handle is not None:
                self._handle.close()
                self._handle = None

    async def _run(self) -> None:
        assert self._queue is not None
        while True:
            event = await self._queue.get()
            self._write(event)

    def _write(self, event: Event) -> None:
        assert self._handle is not None
        self._handle.write(json.dumps(self._to_record(event), default=str) + "\n")
        self._handle.flush()

    @staticmethod
    def _to_record(event: Event) -> dict[str, object]:
        return {"event": type(event).__name__, **dataclasses.asdict(event)}
