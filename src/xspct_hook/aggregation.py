# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Aggregation strategies: combine per-adapter verdicts into one ``HookDecision``."""

from __future__ import annotations

from typing import Any, Protocol

from xspct_hook.protocol.actions import Action, action_severity
from xspct_hook.protocol.decision import HookDecision, ResponseOverride, ScanVerdict, VerdictStatus
from xspct_hook.protocol.modifications import Modification

_ENGINE_UNAVAILABLE = ResponseOverride(
    status=451, enhanced_code="4.7.0", message="scan engine unavailable"
)


class AggregationStrategy(Protocol):
    name: str

    def aggregate(
        self,
        verdicts: list[ScanVerdict],
        *,
        on_adapter_error: str,
        default_action: Action = Action.ACCEPT,
    ) -> HookDecision: ...


def _build_ext(verdicts: list[ScanVerdict]) -> dict[str, Any]:
    return {
        "provenance": [
            {
                "engine": verdict.engine,
                "status": verdict.status.value,
                "action": verdict.action.value if verdict.action else None,
                "error": verdict.error,
                "scannerContext": verdict.scanner_context,
            }
            for verdict in verdicts
        ]
    }


def _fail_closed_decision(
    strategy_name: str, ext: dict[str, Any], default_action: Action
) -> HookDecision:
    return HookDecision(
        action=default_action
        if default_action in {Action.CONTINUE, Action.CANCEL}
        else Action.REJECT,
        response=_ENGINE_UNAVAILABLE,
        modifications=(),
        decided_by=strategy_name,
        ext=ext,
    )


def _accept_decision(
    strategy_name: str, modifications: tuple[Modification, ...], ext: dict[str, Any], action: Action
) -> HookDecision:
    return HookDecision(
        action=action, response=None, modifications=modifications, decided_by=strategy_name, ext=ext
    )


class FirstRejectWins:
    """The most severe terminal verdict wins; non-terminal verdicts' modifications are merged."""

    name = "first_reject_wins"

    def aggregate(
        self,
        verdicts: list[ScanVerdict],
        *,
        on_adapter_error: str,
        default_action: Action = Action.ACCEPT,
    ) -> HookDecision:
        ext = _build_ext(verdicts)
        if on_adapter_error == "fail_closed" and any(
            v.status == VerdictStatus.ERROR for v in verdicts
        ):
            return _fail_closed_decision(self.name, ext, default_action)

        considered = [v for v in verdicts if v.status == VerdictStatus.OK]
        if not considered:
            return _accept_decision(self.name, (), ext, default_action)

        winner = max(considered, key=lambda v: action_severity(v.action))  # type: ignore[arg-type]
        assert winner.action is not None
        if action_severity(winner.action) == action_severity(Action.ACCEPT):
            merged = tuple(mod for v in considered for mod in v.modifications)
            action = (
                Action.CONTINUE
                if winner.action == Action.CONTINUE and default_action != Action.CANCEL
                else default_action
            )
            return _accept_decision(self.name, merged, ext, action)
        if action_severity(default_action) > action_severity(winner.action):
            return _accept_decision(self.name, (), ext, default_action)
        return HookDecision(
            action=winner.action,
            response=winner.response,
            modifications=winner.modifications,
            decided_by=f"{self.name}:{winner.engine}",
            ext=ext,
        )


class ConsensusRequired:
    """Rejects only if every OK verdict agrees on the same non-accept action; otherwise accepts."""

    name = "consensus_required"

    def aggregate(
        self,
        verdicts: list[ScanVerdict],
        *,
        on_adapter_error: str,
        default_action: Action = Action.ACCEPT,
    ) -> HookDecision:
        ext = _build_ext(verdicts)
        if on_adapter_error == "fail_closed" and any(
            v.status == VerdictStatus.ERROR for v in verdicts
        ):
            return _fail_closed_decision(self.name, ext, default_action)

        considered = [v for v in verdicts if v.status == VerdictStatus.OK]
        if not considered:
            return _accept_decision(self.name, (), ext, default_action)

        actions = {v.action for v in considered}
        if len(actions) == 1:
            (sole_action,) = actions
            if action_severity(sole_action) != action_severity(Action.ACCEPT):  # type: ignore[arg-type]
                winner = considered[0]
                assert winner.action is not None
                if action_severity(default_action) > action_severity(winner.action):
                    return _accept_decision(self.name, (), ext, default_action)
                return HookDecision(
                    action=winner.action,
                    response=winner.response,
                    modifications=winner.modifications,
                    decided_by=f"{self.name}:{winner.engine}",
                    ext=ext,
                )

        merged = tuple(
            mod
            for v in considered
            if v.action is not None and action_severity(v.action) == action_severity(Action.ACCEPT)
            for mod in v.modifications
        )
        action = (
            Action.CONTINUE
            if actions == {Action.CONTINUE} and default_action != Action.CANCEL
            else default_action
        )
        return _accept_decision(self.name, merged, ext, action)
