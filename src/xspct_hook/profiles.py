# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""A single hook profile: the adapters/strategy/stages bound to one route and bearer token."""

from __future__ import annotations

from dataclasses import dataclass, field

from xspct_hook.adapters.base import ScanAdapter
from xspct_hook.aggregation import AggregationStrategy
from xspct_hook.protocol.models import Stage


@dataclass
class HookProfile:
    name: str
    path: str
    stages: frozenset[Stage]
    token: str
    adapters: list[ScanAdapter]
    strategy: AggregationStrategy
    on_adapter_error: str = "fail_open"
    adapter_timeout: float = 10.0
    overall_timeout: float = 30.0
    depends_on: tuple[str, ...] = field(default_factory=tuple)
