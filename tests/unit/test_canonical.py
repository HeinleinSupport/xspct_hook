# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for protocol/canonical.py (parse_hook_request/build_hook_response)."""

from __future__ import annotations

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.canonical import build_hook_response, parse_hook_request
from xspct_hook.protocol.decision import HookDecision, ResponseOverride
from xspct_hook.protocol.models import DataContext, MailContext, RcptContext, Stage
from xspct_hook.protocol.modifications import AddOperation


def test_parse_mail_stage_request() -> None:
    payload = {
        "stage": "mail",
        "client": {"ip": "203.0.113.5", "port": 51234},
        "server": {"ip": "198.51.100.10", "port": 25},
        "properties": {"mail_from": "sender@example.com"},
    }
    ctx = parse_hook_request(payload)
    assert isinstance(ctx, MailContext)
    assert ctx.stage == Stage.MAIL
    assert ctx.mail_from == "sender@example.com"
    assert ctx.client.ip == "203.0.113.5"
    assert ctx.server.port == 25


def test_parse_rcpt_stage_sets_provided_properties() -> None:
    payload = {"stage": "rcpt", "properties": {"rcpt_to": "verdict+reject@test.local"}}
    ctx = parse_hook_request(payload)
    assert isinstance(ctx, RcptContext)
    assert "rcpt_to" in ctx.provided_properties
    assert ctx.rcpt_to == "verdict+reject@test.local"


def test_parse_data_stage_builds_message_body() -> None:
    payload = {
        "stage": "data",
        "properties": {
            "headers": [["Subject", "hi"]],
            "message_contents": "Subject: hi\r\n\r\nbody\r\n",
        },
    }
    ctx = parse_hook_request(payload)
    assert isinstance(ctx, DataContext)
    assert ctx.headers == [("Subject", "hi")]
    assert ctx.message.read_all() == b"Subject: hi\r\n\r\nbody\r\n"
    ctx.message.close()


def test_parse_round_trips_ext_block() -> None:
    payload = {"stage": "mail", "properties": {}, "ext": {"provenance": [{"engine": "pseudo"}]}}
    ctx = parse_hook_request(payload)
    assert ctx.ext == {"provenance": [{"engine": "pseudo"}]}


def test_build_hook_response_includes_action_and_modifications() -> None:
    decision = HookDecision(
        action=Action.ACCEPT,
        response=None,
        modifications=(AddOperation("/message/headers/-", {"name": "X-Test", "value": "1"}),),
        decided_by="first_reject_wins",
    )
    encoded = build_hook_response(decision)
    assert encoded["set"] == [{"path": "/action", "value": "accept"}]
    assert encoded["add"] == [
        {"path": "/message/headers", "value": {"name": "X-Test", "value": "1"}}
    ]
    assert "ext" not in encoded


def test_build_hook_response_includes_response_override_and_ext() -> None:
    decision = HookDecision(
        action=Action.REJECT,
        response=ResponseOverride(status=550, enhanced_code="5.7.1", message="rejected"),
        modifications=(),
        decided_by="first_reject_wins:pseudo",
        ext={"provenance": []},
    )
    encoded = build_hook_response(decision)
    assert encoded["set"][1] == {
        "path": "/response",
        "value": {"code": 550, "enhancedCode": "5.7.1", "message": "rejected"},
    }
    assert encoded["ext"] == {"provenance": []}


def test_literal_draft_request_decodes_envelope_and_body() -> None:
    import base64

    ctx = parse_hook_request(
        {
            "stage": "data",
            "action": "accept",
            "envelope": {"from": {"address": None}, "to": [{"address": "recipient@example.com"}]},
            "rawMessage": base64.b64encode(b"Subject: test\r\n\r\nbody").decode(),
        }
    )
    assert ctx.property("mail_from") is None
    assert ctx.property("rcpt_to") == "recipient@example.com"
    with ctx.property("message") as body:
        assert body.read_all() == b"Subject: test\r\n\r\nbody"
