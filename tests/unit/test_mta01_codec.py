# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for wire/mta01.py: Mta01Codec (thin pass-through of protocol/canonical.py)."""

from __future__ import annotations

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.decision import HookDecision
from xspct_hook.protocol.models import MailContext
from xspct_hook.wire.mta01 import Mta01Codec


def test_decode_request_delegates_to_canonical() -> None:
    codec = Mta01Codec()
    ctx = codec.decode_request({"stage": "mail", "properties": {"mail_from": "a@example.com"}})
    assert isinstance(ctx, MailContext)
    assert ctx.mail_from == "a@example.com"


def test_encode_response_delegates_to_canonical() -> None:
    codec = Mta01Codec()
    decision = HookDecision(
        action=Action.ACCEPT, response=None, modifications=(), decided_by="x", ext={"a": 1}
    )
    encoded = codec.encode_response(decision)
    assert encoded["set"] == [{"path": "/action", "value": "accept"}]
    assert encoded["ext"] == {"a": 1}
