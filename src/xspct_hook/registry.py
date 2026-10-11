# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Adapter-type and strategy-name factories, driven by the YAML config's ``type`` fields."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from xspct_hook.adapters.base import ScanAdapter
from xspct_hook.adapters.clamav import ClamAVAdapter
from xspct_hook.adapters.pseudo import PseudoScannerAdapter
from xspct_hook.aggregation import AggregationStrategy, ConsensusRequired, FirstRejectWins

AdapterFactory = Callable[[dict[str, Any]], ScanAdapter]
StrategyFactory = Callable[[], AggregationStrategy]

ADAPTER_FACTORIES: dict[str, AdapterFactory] = {
    "pseudo": lambda cfg: PseudoScannerAdapter(
        default_scenario=cfg.get("default_scenario", "clean"),
        slow_delay=cfg.get("slow_delay", 2.0),
    ),
    "clamav": lambda cfg: ClamAVAdapter(
        host=cfg.get("host"),
        port=cfg.get("port", 3310),
        unix_socket=cfg.get("unix_socket"),
        timeout=cfg.get("timeout", 30.0),
    ),
}

STRATEGY_FACTORIES: dict[str, StrategyFactory] = {
    "first_reject_wins": FirstRejectWins,
    "consensus_required": ConsensusRequired,
}


def build_adapter(adapter_type: str, config: dict[str, Any]) -> ScanAdapter:
    try:
        factory = ADAPTER_FACTORIES[adapter_type]
    except KeyError:
        raise ValueError(f"unknown adapter type: {adapter_type!r}") from None
    return factory(config)


def build_strategy(strategy_type: str) -> AggregationStrategy:
    try:
        factory = STRATEGY_FACTORIES[strategy_type]
    except KeyError:
        raise ValueError(f"unknown aggregation strategy: {strategy_type!r}") from None
    return factory()
