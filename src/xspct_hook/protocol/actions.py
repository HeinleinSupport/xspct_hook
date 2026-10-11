# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""The -01 action vocabulary and its severity ordering for aggregation strategies."""

from __future__ import annotations

from enum import Enum


class Action(str, Enum):
    ACCEPT = "accept"
    CONTINUE = "continue"
    REJECT = "reject"
    DISCARD = "discard"
    QUARANTINE = "quarantine"
    DISCONNECT = "disconnect"
    CANCEL = "cancel"


#: Inbound stages only ever produce these actions.
INBOUND_ACTIONS = frozenset(
    {Action.ACCEPT, Action.REJECT, Action.DISCARD, Action.QUARANTINE, Action.DISCONNECT}
)
#: Outbound stages (delivery/defer/dsn) only ever produce these actions.
OUTBOUND_ACTIONS = frozenset({Action.CONTINUE, Action.CANCEL})

_SEVERITY: dict[Action, int] = {
    Action.ACCEPT: 0,
    Action.CONTINUE: 0,
    Action.QUARANTINE: 1,
    Action.REJECT: 2,
    Action.DISCARD: 2,
    Action.DISCONNECT: 2,
    Action.CANCEL: 2,
}


def action_severity(action: Action) -> int:
    """Return the relative severity of an action, for "worst verdict wins" aggregation."""
    return _SEVERITY[action]


def default_action(stage: str) -> Action:
    return Action.CONTINUE if stage in {"delivery", "defer", "dsn"} else Action.ACCEPT


def validate_stage_action(stage: str, action: Action) -> None:
    allowed = OUTBOUND_ACTIONS if stage in {"delivery", "defer", "dsn"} else INBOUND_ACTIONS
    if action not in allowed:
        raise ValueError(f"action {action.value!r} is invalid at stage {stage!r}")
