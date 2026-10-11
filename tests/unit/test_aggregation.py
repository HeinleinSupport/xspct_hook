# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for aggregation.py: FirstRejectWins and ConsensusRequired."""

from __future__ import annotations

from xspct_hook.aggregation import ConsensusRequired, FirstRejectWins
from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.decision import ScanVerdict, VerdictStatus


def test_consensus_preserves_more_restrictive_default() -> None:
    decision = ConsensusRequired().aggregate(
        [ScanVerdict.ok("engine", Action.QUARANTINE)],
        on_adapter_error="fail_open",
        default_action=Action.REJECT,
    )
    assert decision.action == Action.REJECT


def test_outbound_cancel_is_not_downgraded_by_continue() -> None:
    for strategy in (FirstRejectWins(), ConsensusRequired()):
        decision = strategy.aggregate(
            [ScanVerdict.ok("engine", Action.CONTINUE)],
            on_adapter_error="fail_open",
            default_action=Action.CANCEL,
        )
        assert decision.action == Action.CANCEL


def test_first_reject_wins_picks_most_severe() -> None:
    verdicts = [ScanVerdict.ok("a", Action.ACCEPT), ScanVerdict.ok("b", Action.REJECT)]
    decision = FirstRejectWins().aggregate(verdicts, on_adapter_error="fail_open")
    assert decision.action == Action.REJECT
    assert decision.decided_by == "first_reject_wins:b"


def test_first_reject_wins_merges_modifications_when_all_accept() -> None:
    from xspct_hook.protocol.modifications import AddOperation

    verdicts = [
        ScanVerdict.ok("a", Action.ACCEPT, modifications=(AddOperation("/x", 1),)),
        ScanVerdict.ok("b", Action.ACCEPT, modifications=(AddOperation("/y", 2),)),
    ]
    decision = FirstRejectWins().aggregate(verdicts, on_adapter_error="fail_open")
    assert decision.action == Action.ACCEPT
    assert len(decision.modifications) == 2


def test_first_reject_wins_fail_open_ignores_errors() -> None:
    verdicts = [ScanVerdict.ok("a", Action.ACCEPT), ScanVerdict.error_result("b", "boom")]
    decision = FirstRejectWins().aggregate(verdicts, on_adapter_error="fail_open")
    assert decision.action == Action.ACCEPT


def test_first_reject_wins_fail_closed_rejects_on_error() -> None:
    verdicts = [ScanVerdict.ok("a", Action.ACCEPT), ScanVerdict.error_result("b", "boom")]
    decision = FirstRejectWins().aggregate(verdicts, on_adapter_error="fail_closed")
    assert decision.action == Action.REJECT
    assert decision.response is not None
    assert decision.response.status == 451


def test_first_reject_wins_no_verdicts_accepts() -> None:
    decision = FirstRejectWins().aggregate([], on_adapter_error="fail_open")
    assert decision.action == Action.ACCEPT


def test_consensus_required_accepts_on_disagreement() -> None:
    verdicts = [ScanVerdict.ok("a", Action.REJECT), ScanVerdict.ok("b", Action.ACCEPT)]
    decision = ConsensusRequired().aggregate(verdicts, on_adapter_error="fail_open")
    assert decision.action == Action.ACCEPT


def test_consensus_required_rejects_on_agreement() -> None:
    verdicts = [ScanVerdict.ok("a", Action.REJECT), ScanVerdict.ok("b", Action.REJECT)]
    decision = ConsensusRequired().aggregate(verdicts, on_adapter_error="fail_open")
    assert decision.action == Action.REJECT
    assert decision.decided_by.startswith("consensus_required:")


def test_consensus_required_fail_closed_on_error() -> None:
    verdicts = [ScanVerdict.ok("a", Action.ACCEPT), ScanVerdict.error_result("b", "boom")]
    decision = ConsensusRequired().aggregate(verdicts, on_adapter_error="fail_closed")
    assert decision.action == Action.REJECT


def test_ext_provenance_lists_every_verdict() -> None:
    verdicts = [ScanVerdict.ok("a", Action.ACCEPT), ScanVerdict.error_result("b", "boom")]
    decision = FirstRejectWins().aggregate(verdicts, on_adapter_error="fail_open")
    engines = {entry["engine"] for entry in decision.ext["provenance"]}
    assert engines == {"a", "b"}
    statuses = {entry["status"] for entry in decision.ext["provenance"]}
    assert statuses == {VerdictStatus.OK.value, VerdictStatus.ERROR.value}
