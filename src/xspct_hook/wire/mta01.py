# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Native draft -01 wire dialect: a thin pass-through of the canonical JSON shape.

Reachable only via the smoke-test client / demos / curl — never by real Stalwart.
"""

from __future__ import annotations

from typing import Any

from xspct_hook.protocol.canonical import build_hook_response, parse_hook_request
from xspct_hook.protocol.decision import HookDecision
from xspct_hook.protocol.models import HookContext


class Mta01Codec:
    """Decodes/encodes the literal draft -01 JSON shape (== the canonical shape)."""

    def decode_request(
        self, payload: dict[str, Any], *, spool_threshold_mb: float = 10.0
    ) -> HookContext:
        return parse_hook_request(payload, spool_threshold_mb=spool_threshold_mb)

    def encode_response(self, decision: HookDecision) -> dict[str, Any]:
        return build_hook_response(decision)
