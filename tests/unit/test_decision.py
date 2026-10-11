# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for protocol/decision.py."""

from __future__ import annotations

import pytest

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.decision import ScanVerdict, VerdictStatus


def test_ok_classmethod_builds_ok_verdict() -> None:
    verdict = ScanVerdict.ok("pseudo", Action.ACCEPT)
    assert verdict.status == VerdictStatus.OK
    assert verdict.action == Action.ACCEPT


def test_error_result_has_no_action() -> None:
    verdict = ScanVerdict.error_result("pseudo", "boom")
    assert verdict.status == VerdictStatus.ERROR
    assert verdict.action is None
    assert verdict.error == "boom"


def test_skipped_classmethod() -> None:
    verdict = ScanVerdict.skipped("clamav")
    assert verdict.status == VerdictStatus.SKIPPED
    assert verdict.action is None


def test_ok_status_without_action_raises() -> None:
    with pytest.raises(ValueError, match="status=OK but no action"):
        ScanVerdict(engine="pseudo", status=VerdictStatus.OK, action=None)
