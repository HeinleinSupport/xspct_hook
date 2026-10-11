# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for orchestrator.py: HookOrchestrator.handle()."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from xspct_hook.aggregation import FirstRejectWins
from xspct_hook.events import AdapterFinished, AdapterSkipped, Event, EventBus, ModificationRejected
from xspct_hook.orchestrator import HookOrchestrator
from xspct_hook.profiles import HookProfile
from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.canonical import parse_hook_request
from xspct_hook.protocol.decision import ScanVerdict
from xspct_hook.protocol.models import HookContext, Stage
from xspct_hook.protocol.modifications import AddOperation, SetOperation


@dataclass
class _StubAdapter:
    name: str
    supported_stages: frozenset[Stage]
    supported_actions: frozenset[Action]
    verdict: ScanVerdict | None = None
    delay: float = 0.0
    raise_exc: Exception | None = None
    calls: list[HookContext] = field(default_factory=list)

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def scan(self, ctx: HookContext) -> ScanVerdict:
        self.calls.append(ctx)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raise_exc:
            raise self.raise_exc
        assert self.verdict is not None
        return self.verdict


def _profile(adapters: list, **overrides) -> HookProfile:
    defaults = {
        "name": "test",
        "path": "/hooks/test",
        "stages": frozenset({Stage.MAIL, Stage.RCPT, Stage.DATA}),
        "token": "tok",
        "adapters": adapters,
        "strategy": FirstRejectWins(),
    }
    defaults.update(overrides)
    return HookProfile(**defaults)


def _mail_ctx() -> HookContext:
    return parse_hook_request({"stage": "mail", "properties": {"mail_from": "a@example.com"}})


async def test_handle_returns_accept_for_clean_adapter() -> None:
    adapter = _StubAdapter(
        "a", frozenset({Stage.MAIL}), frozenset({Action.ACCEPT}), ScanVerdict.ok("a", Action.ACCEPT)
    )
    orchestrator = HookOrchestrator(bus=EventBus())
    decision = await orchestrator.handle(_profile([adapter]), _mail_ctx())
    assert decision.action == Action.ACCEPT


async def test_handle_skips_adapter_not_supporting_stage() -> None:
    adapter = _StubAdapter("a", frozenset({Stage.DATA}), frozenset({Action.ACCEPT}))
    bus = EventBus()
    queue = bus.subscribe()
    orchestrator = HookOrchestrator(bus=bus)
    await orchestrator.handle(_profile([adapter]), _mail_ctx())
    assert adapter.calls == []
    events: list[Event] = []
    while not queue.empty():
        events.append(queue.get_nowait())
    assert any(isinstance(e, AdapterSkipped) for e in events)


async def test_handle_converts_adapter_exception_to_error_verdict() -> None:
    adapter = _StubAdapter(
        "a", frozenset({Stage.MAIL}), frozenset({Action.ACCEPT}), raise_exc=RuntimeError("boom")
    )
    orchestrator = HookOrchestrator(bus=EventBus())
    decision = await orchestrator.handle(
        _profile([adapter], on_adapter_error="fail_closed"), _mail_ctx()
    )
    assert decision.action == Action.REJECT


async def test_handle_times_out_slow_adapter() -> None:
    adapter = _StubAdapter("a", frozenset({Stage.MAIL}), frozenset({Action.ACCEPT}), delay=5.0)
    orchestrator = HookOrchestrator(bus=EventBus())
    profile = _profile([adapter], adapter_timeout=0.05, on_adapter_error="fail_closed")
    decision = await orchestrator.handle(profile, _mail_ctx())
    assert decision.action == Action.REJECT


async def test_unsupported_action_downgrades_to_error_and_publishes_event() -> None:
    verdict = ScanVerdict.ok("a", Action.QUARANTINE)
    adapter = _StubAdapter("a", frozenset({Stage.MAIL}), frozenset({Action.ACCEPT}), verdict)
    bus = EventBus()
    queue = bus.subscribe()
    orchestrator = HookOrchestrator(bus=bus)
    decision = await orchestrator.handle(_profile([adapter]), _mail_ctx())
    assert decision.action == Action.ACCEPT  # error verdict ignored under fail_open
    events: list[Event] = []
    while not queue.empty():
        events.append(queue.get_nowait())
    assert any(isinstance(e, ModificationRejected) for e in events)


async def test_body_rewrite_modification_is_dropped_but_action_kept() -> None:
    verdict = ScanVerdict.ok("a", Action.ACCEPT, modifications=(SetOperation("/message", "evil"),))
    adapter = _StubAdapter("a", frozenset({Stage.MAIL}), frozenset(Action), verdict)
    bus = EventBus()
    queue = bus.subscribe()
    orchestrator = HookOrchestrator(bus=bus)
    decision = await orchestrator.handle(_profile([adapter]), _mail_ctx())
    assert decision.action == Action.ACCEPT
    assert decision.modifications == ()
    events: list[Event] = []
    while not queue.empty():
        events.append(queue.get_nowait())
    assert any(isinstance(e, ModificationRejected) for e in events)


async def test_valid_modification_is_kept() -> None:
    verdict = ScanVerdict.ok(
        "a",
        Action.ACCEPT,
        modifications=(AddOperation("/message/headers/-", {"name": "X-Test", "value": "1"}),),
    )
    adapter = _StubAdapter("a", frozenset({Stage.DATA}), frozenset(Action), verdict)
    orchestrator = HookOrchestrator(bus=EventBus())
    decision = await orchestrator.handle(
        _profile([adapter]), parse_hook_request({"stage": "data", "message": {"headers": []}})
    )
    assert len(decision.modifications) == 1


async def test_invalid_header_index_drops_only_failed_modification() -> None:
    verdict = ScanVerdict.ok(
        "a",
        Action.REJECT,
        modifications=(
            SetOperation("/message/headers/999", {"name": "X-Test", "value": "bad-index"}),
            AddOperation("/message/headers", {"name": "X-Test", "value": "valid"}),
        ),
    )
    adapter = _StubAdapter("a", frozenset({Stage.DATA}), frozenset(Action), verdict)
    ctx = parse_hook_request({"stage": "data", "message": {"headers": []}})
    decision = await HookOrchestrator(bus=EventBus()).handle(_profile([adapter]), ctx)
    assert decision.action == Action.REJECT
    assert decision.modifications == (verdict.modifications[1],)


async def test_adapter_finished_event_published_with_duration() -> None:
    adapter = _StubAdapter(
        "a", frozenset({Stage.MAIL}), frozenset({Action.ACCEPT}), ScanVerdict.ok("a", Action.ACCEPT)
    )
    bus = EventBus()
    queue = bus.subscribe()
    orchestrator = HookOrchestrator(bus=bus)
    await orchestrator.handle(_profile([adapter]), _mail_ctx())
    events: list[Event] = []
    while not queue.empty():
        events.append(queue.get_nowait())
    finished = [e for e in events if isinstance(e, AdapterFinished)]
    assert len(finished) == 1
    assert finished[0].status == "ok"


async def test_overall_timeout_preserves_completed_reject() -> None:
    reject = _StubAdapter(
        "reject",
        frozenset({Stage.MAIL}),
        frozenset(Action),
        ScanVerdict.ok("reject", Action.REJECT),
    )
    slow = _StubAdapter("slow", frozenset({Stage.MAIL}), frozenset(Action), delay=1)
    decision = await HookOrchestrator(bus=EventBus()).handle(
        _profile([reject, slow], overall_timeout=0.01), _mail_ctx()
    )
    assert decision.action == Action.REJECT
    assert decision.ext["provenance"][0]["status"] == "ok"
    assert decision.ext["provenance"][1]["status"] == "error"


async def test_malformed_return_obeys_error_policy() -> None:
    adapter = _StubAdapter("bad", frozenset({Stage.MAIL}), frozenset(Action), {"action": "accept"})
    decision = await HookOrchestrator(bus=EventBus()).handle(
        _profile([adapter], on_adapter_error="fail_closed"), _mail_ctx()
    )
    assert decision.action == Action.REJECT
    assert decision.response.status == 451


async def test_outbound_continue_is_preserved() -> None:
    from xspct_hook.adapters.pseudo import PseudoScannerAdapter

    ctx = parse_hook_request({"stage": "delivery", "action": "continue"})
    decision = await HookOrchestrator(bus=EventBus()).handle(
        _profile([PseudoScannerAdapter()]), ctx
    )
    assert decision.action == Action.CONTINUE
