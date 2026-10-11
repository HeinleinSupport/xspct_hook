# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Fans a hook context out to a profile's adapters and aggregates their verdicts.

Never raises: adapter exceptions/timeouts become ``ScanVerdict(status=error)`` instead.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import time

from xspct_hook.adapters.base import ScanAdapter
from xspct_hook.aggregation import FirstRejectWins
from xspct_hook.events import (
    AdapterFinished,
    AdapterSkipped,
    AdapterStarted,
    EventBus,
    ModificationRejected,
    RequestFinished,
    RequestStarted,
)
from xspct_hook.exceptions import UnsupportedActionError
from xspct_hook.profiles import HookProfile
from xspct_hook.protocol.actions import validate_stage_action
from xspct_hook.protocol.canonical import EnvelopePayload
from xspct_hook.protocol.decision import HookDecision, ScanVerdict, VerdictStatus
from xspct_hook.protocol.models import HookContext
from xspct_hook.protocol.modifications import (
    AddOperation,
    DeleteOperation,
    SetOperation,
    apply_modifications,
    validate_modification,
)


class HookOrchestrator:
    def __init__(self, *, bus: EventBus) -> None:
        self._bus = bus

    async def handle(self, profile: HookProfile, ctx: HookContext) -> HookDecision:
        start = time.monotonic()
        self._bus.publish(
            RequestStarted(trace_id=ctx.trace_id, profile_name=profile.name, stage=ctx.stage.value)
        )

        applicable = [
            adapter for adapter in profile.adapters if ctx.stage in adapter.supported_stages
        ]
        for adapter in profile.adapters:
            if adapter not in applicable:
                self._bus.publish(
                    AdapterSkipped(
                        trace_id=ctx.trace_id,
                        profile_name=profile.name,
                        stage=ctx.stage.value,
                        engine=adapter.name,
                        reason="stage not supported by adapter",
                    )
                )

        tasks = [
            asyncio.create_task(self._run_adapter(adapter, ctx, profile)) for adapter in applicable
        ]
        try:
            if tasks:
                _, pending = await asyncio.wait(tasks, timeout=profile.overall_timeout)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            verdicts = [
                ScanVerdict.error_result(adapter.name, "overall timeout exceeded")
                if task.cancelled()
                else task.result()
                for adapter, task in zip(applicable, tasks, strict=True)
            ]
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        try:
            decision = profile.strategy.aggregate(
                verdicts, on_adapter_error=profile.on_adapter_error, default_action=ctx.action
            )
            validate_stage_action(ctx.stage.value, decision.action)
        except Exception as exc:  # noqa: BLE001
            decision = FirstRejectWins().aggregate(
                [ScanVerdict.error_result(profile.strategy.name, f"aggregation failed: {exc}")],
                on_adapter_error=profile.on_adapter_error,
                default_action=ctx.action,
            )
        self._bus.publish(
            RequestFinished(
                trace_id=ctx.trace_id,
                profile_name=profile.name,
                stage=ctx.stage.value,
                action=decision.action.value,
                decided_by=decision.decided_by,
                duration_s=time.monotonic() - start,
            )
        )
        return decision

    async def _run_adapter(
        self, adapter: ScanAdapter, ctx: HookContext, profile: HookProfile
    ) -> ScanVerdict:
        start = time.monotonic()
        self._bus.publish(
            AdapterStarted(
                trace_id=ctx.trace_id,
                profile_name=profile.name,
                stage=ctx.stage.value,
                engine=adapter.name,
            )
        )
        try:
            verdict = await asyncio.wait_for(adapter.scan(ctx), timeout=profile.adapter_timeout)
            if not isinstance(verdict, ScanVerdict):
                raise TypeError("adapter did not return a ScanVerdict")
            verdict.__post_init__()
            json.dumps(verdict.scanner_context, allow_nan=False)
            verdict = self._validate_verdict(verdict, adapter, ctx, profile)
        except TimeoutError:
            verdict = ScanVerdict.error_result(adapter.name, "adapter timed out")
        except Exception as exc:  # noqa: BLE001 - adapter failures must never crash the orchestrator
            verdict = ScanVerdict.error_result(adapter.name, f"{type(exc).__name__}: {exc}")

        self._bus.publish(
            AdapterFinished(
                trace_id=ctx.trace_id,
                profile_name=profile.name,
                stage=ctx.stage.value,
                engine=adapter.name,
                status=verdict.status.value,
                action=verdict.action.value if verdict.action else None,
                duration_s=time.monotonic() - start,
            )
        )
        return verdict

    def _validate_verdict(
        self, verdict: ScanVerdict, adapter: ScanAdapter, ctx: HookContext, profile: HookProfile
    ) -> ScanVerdict:
        if verdict.status != VerdictStatus.OK:
            return verdict
        assert verdict.action is not None
        validate_stage_action(ctx.stage.value, verdict.action)

        if verdict.action not in adapter.supported_actions:
            reason = str(UnsupportedActionError(verdict.action.value, adapter.name))
            self._bus.publish(
                ModificationRejected(
                    trace_id=ctx.trace_id,
                    profile_name=profile.name,
                    stage=ctx.stage.value,
                    engine=adapter.name,
                    reason=reason,
                )
            )
            return ScanVerdict.error_result(adapter.name, reason)

        kept_modifications = []
        document = dict(ctx.document)
        if "message" not in document and "headers" in ctx.provided_properties:
            document["message"] = {
                "headers": [
                    {"name": name, "value": value} for name, value in ctx.property("headers")
                ]
            }
        for mod in sorted(
            verdict.modifications,
            key=lambda operation: (
                0
                if isinstance(operation, SetOperation)
                else 1
                if isinstance(operation, AddOperation)
                else 2
            ),
        ):
            try:
                validate_modification(mod)
                json.dumps(dataclasses.asdict(mod), allow_nan=False)
                if mod.path == "/action" or mod.path.startswith("/response"):
                    raise ValueError("use verdict action/response fields instead of modifications")
                if not mod.path.startswith(("/message/headers", "/envelope/", "/ext/")):
                    raise ValueError("unsupported update property")
                candidate = apply_modifications(document, [mod])
                if mod.path.startswith("/message/headers"):
                    headers = candidate.get("message", {}).get("headers")
                    if headers is not None:
                        validate_modification(SetOperation("/message/headers", headers))
                    elif isinstance(mod, DeleteOperation) and mod.path != "/message/headers":
                        raise ValueError("header operation removed a required field")
                if mod.path.startswith("/envelope/"):
                    envelope = EnvelopePayload.model_validate(candidate["envelope"])
                    if any(recipient.address is None for recipient in envelope.to):
                        raise ValueError("recipient address must not be null")
                document = candidate
            except Exception as exc:  # noqa: BLE001 - drop this one modification, keep the rest of the verdict
                self._bus.publish(
                    ModificationRejected(
                        trace_id=ctx.trace_id,
                        profile_name=profile.name,
                        stage=ctx.stage.value,
                        engine=adapter.name,
                        reason=str(exc),
                    )
                )
                continue
            kept_modifications.append(mod)

        if len(kept_modifications) != len(verdict.modifications):
            return dataclasses.replace(verdict, modifications=tuple(kept_modifications))
        return verdict
