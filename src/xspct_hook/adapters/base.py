# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""The ``ScanAdapter`` protocol every backend engine must implement."""

from __future__ import annotations

from typing import Protocol

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.decision import ScanVerdict
from xspct_hook.protocol.models import HookContext, Stage


class ScanAdapter(Protocol):
    """A backend scan engine. Adapters must never raise out of ``scan()`` in normal use;
    the orchestrator treats any raised exception as an engine error regardless."""

    name: str
    supported_stages: frozenset[Stage]
    supported_actions: frozenset[Action]

    async def connect(self) -> None:
        """Called once at startup. May raise — a failure is logged, not fatal."""
        ...

    async def close(self) -> None:
        """Called once at shutdown to release any held resources."""
        ...

    async def scan(self, ctx: HookContext) -> ScanVerdict:
        """Scan one hook call and return this engine's verdict."""
        ...
