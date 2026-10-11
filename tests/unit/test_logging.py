# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Logging lifecycle regression tests."""

import asyncio
from pathlib import Path

import pytest

from xspct_hook.events import EventBus, RequestStarted
from xspct_hook.logging_ import JSONLWriter


async def test_shutdown_drains_pending_events(tmp_path: Path) -> None:
    bus = EventBus()
    path = tmp_path / "events.jsonl"
    writer = JSONLWriter(bus, path)
    await writer.start()
    for number in range(100):
        bus.publish(RequestStarted(str(number), "test", "mail"))
    await writer.stop()
    assert len(path.read_text().splitlines()) == 100


async def test_open_failure_is_reported_during_start(tmp_path: Path) -> None:
    writer = JSONLWriter(EventBus(), tmp_path)
    with pytest.raises(IsADirectoryError):
        await writer.start()


def test_event_queue_is_bounded() -> None:
    bus = EventBus()
    queue = bus.subscribe()
    for _ in range(queue.maxsize + 1):
        bus.publish(RequestStarted("trace", "test", "mail"))
    assert queue.qsize() == queue.maxsize
    assert bus.dropped_events == 1


async def test_write_failure_unsubscribes_and_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    bus = EventBus()
    writer = JSONLWriter(bus, tmp_path / "events.jsonl")
    finished = asyncio.Event()

    def fail_write(event: RequestStarted) -> None:
        raise OSError("simulated log write failure")

    monkeypatch.setattr(writer, "_write", fail_write)
    await writer.start()
    assert writer._task is not None
    writer._task.add_done_callback(lambda task: finished.set())
    bus.publish(RequestStarted("trace", "test", "mail"))
    await finished.wait()
    assert any("JSONL writer failed" in record.message for record in caplog.records)
    assert bus._subscribers == []
    with pytest.raises(OSError, match="simulated"):
        await writer.stop()
