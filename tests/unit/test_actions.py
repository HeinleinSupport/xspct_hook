# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for protocol/actions.py."""

from __future__ import annotations

from xspct_hook.protocol.actions import Action, action_severity


def test_severity_ordering_accept_lowest() -> None:
    assert action_severity(Action.ACCEPT) < action_severity(Action.QUARANTINE)
    assert action_severity(Action.QUARANTINE) < action_severity(Action.REJECT)


def test_reject_discard_disconnect_cancel_share_top_severity() -> None:
    top = action_severity(Action.REJECT)
    assert action_severity(Action.DISCARD) == top
    assert action_severity(Action.DISCONNECT) == top
    assert action_severity(Action.CANCEL) == top


def test_continue_matches_accept_severity() -> None:
    assert action_severity(Action.CONTINUE) == action_severity(Action.ACCEPT)
