# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""A scripted stand-in scanner, driven by config and ``verdict+<scenario>@test.local`` recipients."""

from __future__ import annotations

import asyncio
import dataclasses

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.decision import ResponseOverride, ScanVerdict, VerdictStatus
from xspct_hook.protocol.models import OUTBOUND_STAGES, HookContext, Stage
from xspct_hook.protocol.modifications import AddOperation, DeleteOperation, SetOperation

#: Recipients local-part prefix used to pick a scenario at the rcpt/data stages.
_SCENARIO_PREFIX = "verdict+"


class PseudoScannerAdapter:
    """Scripted scanner: resolves a named scenario from config or the recipient address."""

    name = "pseudo"
    supported_stages = frozenset(Stage)
    supported_actions = frozenset(Action)

    def __init__(self, *, default_scenario: str = "clean", slow_delay: float = 2.0) -> None:
        self.default_scenario = default_scenario
        self.slow_delay = slow_delay

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def scan(self, ctx: HookContext) -> ScanVerdict:
        scenario = self._resolve_scenario(ctx)
        verdict = await self._run_scenario(scenario)
        if ctx.stage in OUTBOUND_STAGES and verdict.status == VerdictStatus.OK:
            action = (
                Action.CANCEL if scenario in {"cancel", "malicious", "reject"} else Action.CONTINUE
            )
            return dataclasses.replace(verdict, action=action, response=None)
        if ctx.stage == Stage.DATA and scenario == "suspicious":
            return dataclasses.replace(
                verdict,
                modifications=(
                    AddOperation(
                        "/message/headers", {"name": "X-Xspct-Scan", "value": "pseudo:suspicious"}
                    ),
                ),
            )
        return verdict

    def _resolve_scenario(self, ctx: HookContext) -> str:
        if ctx.stage in {Stage.RCPT, Stage.DATA} and "rcpt_to" in ctx.provided_properties:
            rcpt_to: str | None = ctx.property("rcpt_to")
            if rcpt_to:
                local_part = rcpt_to.split("@", 1)[0]
                if local_part.startswith(_SCENARIO_PREFIX):
                    return local_part[len(_SCENARIO_PREFIX) :]
        return self.default_scenario

    async def _run_scenario(self, scenario: str) -> ScanVerdict:
        if scenario == "clean":
            return ScanVerdict.ok(self.name, Action.ACCEPT)
        if scenario == "malicious":
            return ScanVerdict.ok(
                self.name,
                Action.REJECT,
                response=ResponseOverride(
                    status=550, enhanced_code="5.7.1", message="malicious content detected"
                ),
            )
        if scenario == "suspicious":
            return ScanVerdict.ok(
                self.name,
                Action.QUARANTINE,
                response=ResponseOverride(message="suspicious content detected"),
            )
        if scenario == "reject":
            return ScanVerdict.ok(
                self.name,
                Action.REJECT,
                response=ResponseOverride(
                    status=550, enhanced_code="5.7.1", message="rejected by policy"
                ),
            )
        if scenario == "quarantine":
            return ScanVerdict.ok(self.name, Action.QUARANTINE)
        if scenario == "discard":
            return ScanVerdict.ok(self.name, Action.DISCARD)
        if scenario == "header_add":
            return ScanVerdict.ok(
                self.name,
                Action.ACCEPT,
                modifications=(
                    AddOperation(
                        "/message/headers/-", {"name": "X-Xspct-Scan", "value": "pseudo:clean"}
                    ),
                ),
            )
        if scenario == "header_replace":
            return ScanVerdict.ok(
                self.name,
                Action.ACCEPT,
                modifications=(
                    SetOperation(
                        "/message/headers/0", {"name": "Subject", "value": "[SCANNED] replaced"}
                    ),
                ),
            )
        if scenario == "header_delete":
            return ScanVerdict.ok(
                self.name, Action.ACCEPT, modifications=(DeleteOperation("/message/headers/0"),)
            )
        if scenario == "slow":
            await asyncio.sleep(self.slow_delay)
            return ScanVerdict.ok(self.name, Action.ACCEPT)
        if scenario == "timeout":
            await asyncio.sleep(3600)
            return ScanVerdict.ok(self.name, Action.ACCEPT)
        if scenario == "malformed":
            # Deliberately invalid: exercises the orchestrator's own defensive handling,
            # since ScanVerdict.__post_init__ rejects status=OK with no action.
            return ScanVerdict(engine=self.name, status=VerdictStatus.OK, action=None)
        if scenario == "error":
            return ScanVerdict.error_result(self.name, "pseudo scenario: simulated engine error")
        if scenario == "context_rich":
            return ScanVerdict.ok(
                self.name,
                Action.ACCEPT,
                scanner_context={"scenario": "context_rich", "score": 0.1, "tags": ["demo"]},
            )
        if scenario == "disconnect":
            return ScanVerdict.ok(
                self.name,
                Action.DISCONNECT,
                response=ResponseOverride(status=550, message="session terminated by policy"),
            )
        return ScanVerdict.ok(self.name, Action.ACCEPT)
