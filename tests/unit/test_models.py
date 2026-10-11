# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for protocol/models.py: HookContext.property() and stage subclasses."""

from __future__ import annotations

import pytest

from tests.conftest import client_info, new_trace_id, server_info
from xspct_hook.exceptions import PropertyNotProvidedError
from xspct_hook.protocol.models import STAGE_CONTEXT_CLASSES, MailContext, RcptContext, Stage


def _make_mail_context(**properties: object) -> MailContext:
    return MailContext(
        session_id="sess-1",
        queue_id=None,
        client=client_info(),
        server=server_info(),
        trace_id=new_trace_id(),
        provided_properties=frozenset(properties),
        properties=dict(properties),
    )


def test_property_returns_provided_value() -> None:
    ctx = _make_mail_context(mail_from="sender@example.com")
    assert ctx.mail_from == "sender@example.com"


def test_property_raises_when_not_provided() -> None:
    ctx = _make_mail_context()
    with pytest.raises(PropertyNotProvidedError):
        _ = ctx.mail_from


def test_property_distinguishes_provided_empty_from_not_provided() -> None:
    ctx = _make_mail_context(mail_from="")
    assert ctx.mail_from == ""


def test_stage_context_classes_cover_every_stage() -> None:
    assert set(STAGE_CONTEXT_CLASSES) == set(Stage)


def test_rcpt_context_stage_classvar() -> None:
    ctx = RcptContext(
        session_id="s",
        queue_id=None,
        client=client_info(),
        server=server_info(),
        trace_id=new_trace_id(),
        provided_properties=frozenset({"rcpt_to"}),
        properties={"rcpt_to": "verdict+reject@test.local"},
    )
    assert ctx.stage == Stage.RCPT
    assert ctx.rcpt_to == "verdict+reject@test.local"


def test_hook_context_is_frozen() -> None:
    ctx = _make_mail_context(mail_from="a@example.com")
    with pytest.raises(AttributeError):
        ctx.session_id = "changed"  # type: ignore[misc]
