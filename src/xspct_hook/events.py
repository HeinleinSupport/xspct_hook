# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""An in-process event bus (asyncio.Queue fan-out) for observability subscribers like JSONLWriter."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    trace_id: str
    profile_name: str
    stage: str


@dataclass(frozen=True)
class RequestStarted(Event):
    pass


@dataclass(frozen=True)
class AdapterStarted(Event):
    engine: str


@dataclass(frozen=True)
class AdapterFinished(Event):
    engine: str
    status: str
    action: str | None
    duration_s: float


@dataclass(frozen=True)
class AdapterSkipped(Event):
    engine: str
    reason: str


@dataclass(frozen=True)
class ModificationRejected(Event):
    engine: str
    reason: str


@dataclass(frozen=True)
class RequestFinished(Event):
    action: str
    decided_by: str
    duration_s: float


class EventBus:
    """Fans out published events to every currently-subscribed queue."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[Event]] = []
        self.dropped_events = 0

    def subscribe(self) -> asyncio.Queue[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=4096)
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    def publish(self, event: Event) -> None:
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                self.dropped_events += 1
                logging.getLogger(__name__).error(
                    "event queue full; dropped event (total=%d)", self.dropped_events
                )
