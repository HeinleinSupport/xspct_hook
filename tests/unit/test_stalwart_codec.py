# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for wire/stalwart.py: StalwartCodec."""

from __future__ import annotations

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.decision import HookDecision, ResponseOverride
from xspct_hook.protocol.models import MailContext, RcptContext
from xspct_hook.protocol.modifications import AddOperation, DeleteOperation, SetOperation
from xspct_hook.wire.stalwart import StalwartCodec


def test_decode_mail_stage_from_stalwart_shape() -> None:
    codec = StalwartCodec()
    payload = {
        "context": {
            "stage": "mail",
            "client": {"ip": "203.0.113.5", "port": 51234},
            "server": {"ip": "198.51.100.10", "port": 25},
        },
        "envelope": {"from": {"address": "sender@example.com"}, "to": []},
    }
    ctx = codec.decode_request(payload)
    assert isinstance(ctx, MailContext)
    assert ctx.mail_from == "sender@example.com"


def test_decode_real_null_parameters_and_server_headers() -> None:
    ctx = StalwartCodec().decode_request(
        {
            "context": {
                "stage": "data",
                "client": {
                    "ip": "192.0.2.10",
                    "port": 41000,
                    "helo": "mail.example.com",
                    "ptr": None,
                    "activeConnections": 1,
                },
                "server": {"name": "mx.example.com", "ip": "198.51.100.20", "port": 25},
                "protocol": {"version": 1},
            },
            "envelope": {
                "from": {"address": "sender@example.com", "parameters": None},
                "to": [{"address": "recipient@example.com", "parameters": None}],
            },
            "message": {
                "headers": [["Content-Type", "text/plain"]],
                "serverHeaders": [["Received", "by mx.example.com"]],
                "contents": "body\r\n",
                "size": 80,
            },
        }
    )
    try:
        assert (
            ctx.property("message").read_all()
            == b"Received: by mx.example.com\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
        )
        assert ctx.property("rcpt_to") == "recipient@example.com"
    finally:
        ctx.property("message").close()


def test_decode_rcpt_takes_current_recipient() -> None:
    codec = StalwartCodec()
    payload = {
        "context": {"stage": "rcpt"},
        "envelope": {
            "from": {"address": "sender@example.com"},
            "to": [{"address": "a@example.com"}, {"address": "b@example.com"}],
        },
    }
    ctx = codec.decode_request(payload)
    assert isinstance(ctx, RcptContext)
    assert ctx.rcpt_to == "b@example.com"


def test_decode_data_stage_with_message_contents() -> None:
    codec = StalwartCodec()
    payload = {
        "context": {"stage": "data"},
        "message": {"headers": [["Subject", "hi"]], "contents": "body\r\n"},
    }
    ctx = codec.decode_request(payload)
    assert ctx.property("headers") == [("Subject", "hi")]
    message = ctx.property("message")
    assert message.read_all() == b"Subject: hi\r\n\r\nbody\r\n"
    message.close()


def test_encode_accept_response() -> None:
    codec = StalwartCodec()
    decision = HookDecision(action=Action.ACCEPT, response=None, modifications=(), decided_by="x")
    encoded = codec.encode_response(decision)
    assert encoded == {"action": "accept", "modifications": []}


def test_encode_reject_with_response_override() -> None:
    codec = StalwartCodec()
    decision = HookDecision(
        action=Action.REJECT,
        response=ResponseOverride(status=550, enhanced_code="5.7.1", message="malicious"),
        modifications=(),
        decided_by="x",
    )
    encoded = codec.encode_response(decision)
    assert encoded["action"] == "reject"
    assert encoded["response"] == {
        "status": 550,
        "enhanced_status": "5.7.1",
        "message": "malicious",
    }


def test_encode_disconnect_maps_to_reject_with_disconnect_flag() -> None:
    codec = StalwartCodec()
    decision = HookDecision(
        action=Action.DISCONNECT,
        response=ResponseOverride(status=550),
        modifications=(),
        decided_by="x",
    )
    encoded = codec.encode_response(decision)
    assert encoded["action"] == "reject"
    assert encoded["response"]["disconnect"] is True


def test_encode_header_add_modification() -> None:
    codec = StalwartCodec()
    decision = HookDecision(
        action=Action.ACCEPT,
        response=None,
        modifications=(AddOperation("/message/headers/-", {"name": "X-Test", "value": "1"}),),
        decided_by="x",
    )
    encoded = codec.encode_response(decision)
    assert encoded["modifications"] == [{"type": "addHeader", "name": "X-Test", "value": "1"}]


def test_encode_header_delete_modification() -> None:
    codec = StalwartCodec()
    decision = HookDecision(
        action=Action.ACCEPT,
        response=None,
        modifications=(DeleteOperation("/message/headers/0"),),
        decided_by="x",
    )
    ctx = codec.decode_request(
        {"context": {"stage": "data"}, "message": {"headers": [["Subject", "test"]]}}
    )
    encoded = codec.encode_response(decision, ctx)
    assert encoded["modifications"] == [{"type": "deleteHeader", "name": "Subject", "index": 1}]


def test_encode_change_from_modification() -> None:
    codec = StalwartCodec()
    decision = HookDecision(
        action=Action.ACCEPT,
        response=None,
        modifications=(SetOperation("/envelope/from", "new@example.com"),),
        decided_by="x",
    )
    encoded = codec.encode_response(decision)
    assert encoded["modifications"] == [
        {"type": "changeFrom", "value": "new@example.com", "parameters": {}}
    ]


def test_encode_recipient_operations_use_values() -> None:
    codec = StalwartCodec()
    ctx = codec.decode_request(
        {
            "context": {"stage": "rcpt"},
            "envelope": {
                "from": {"address": "sender@example.com"},
                "to": [{"address": "recipient@example.com"}],
            },
        }
    )
    decision = HookDecision(
        Action.ACCEPT,
        None,
        (
            DeleteOperation("/envelope/to/0"),
            AddOperation("/envelope/to", {"address": "archive@example.com"}),
        ),
        "test",
    )
    encoded = codec.encode_response(decision, ctx)
    assert encoded["modifications"] == [
        {"type": "addRecipient", "value": "archive@example.com", "parameters": {}},
        {"type": "deleteRecipient", "value": "recipient@example.com"},
    ]


def test_encode_rejects_body_rewrite_modification() -> None:
    import pytest

    from xspct_hook.exceptions import BodyRewriteRejected

    codec = StalwartCodec()
    decision = HookDecision(
        action=Action.ACCEPT,
        response=None,
        modifications=(SetOperation("/message", "evil"),),
        decided_by="x",
    )
    with pytest.raises(BodyRewriteRejected):
        codec.encode_response(decision)


def test_ext_block_is_included_when_present() -> None:
    codec = StalwartCodec()
    decision = HookDecision(
        action=Action.ACCEPT,
        response=None,
        modifications=(),
        decided_by="x",
        ext={"provenance": []},
    )
    encoded = codec.encode_response(decision)
    assert encoded["ext"] == {"provenance": []}
