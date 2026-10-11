# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for registry.py: adapter/strategy factories."""

from __future__ import annotations

import pytest

from xspct_hook.adapters.clamav import ClamAVAdapter
from xspct_hook.adapters.pseudo import PseudoScannerAdapter
from xspct_hook.aggregation import ConsensusRequired, FirstRejectWins
from xspct_hook.registry import build_adapter, build_strategy


def test_build_pseudo_adapter() -> None:
    adapter = build_adapter("pseudo", {"default_scenario": "malicious"})
    assert isinstance(adapter, PseudoScannerAdapter)
    assert adapter.default_scenario == "malicious"


def test_build_clamav_adapter() -> None:
    adapter = build_adapter("clamav", {"host": "127.0.0.1", "port": 3310})
    assert isinstance(adapter, ClamAVAdapter)
    assert adapter.port == 3310


def test_build_unknown_adapter_raises() -> None:
    with pytest.raises(ValueError, match="unknown adapter type"):
        build_adapter("nonexistent", {})


def test_build_first_reject_wins_strategy() -> None:
    assert isinstance(build_strategy("first_reject_wins"), FirstRejectWins)


def test_build_consensus_required_strategy() -> None:
    assert isinstance(build_strategy("consensus_required"), ConsensusRequired)


def test_build_unknown_strategy_raises() -> None:
    with pytest.raises(ValueError, match="unknown aggregation strategy"):
        build_strategy("nonexistent")
