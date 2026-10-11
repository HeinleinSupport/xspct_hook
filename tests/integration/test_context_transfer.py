# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Integration test: simulating a hypothetical future MTA that carries a scanner's ``/ext``
output from one stage's response into the next stage's request.

Neither Stalwart nor -01 itself defines a mechanism for an MTA to do this; this test only
demonstrates that the canonical codec is capable of round-tripping ``/ext`` so such a feature
could be built on top of it in the future.
"""

from __future__ import annotations

from xspct_hook.aggregation import FirstRejectWins
from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.canonical import build_hook_response, parse_hook_request
from xspct_hook.protocol.decision import ScanVerdict


def test_ext_from_one_response_can_be_carried_into_a_later_request() -> None:
    mail_ctx = parse_hook_request({"stage": "mail", "properties": {"mail_from": "a@example.com"}})
    verdicts = [ScanVerdict.ok("pseudo", Action.ACCEPT, scanner_context={"risk_score": 0.2})]
    decision = FirstRejectWins().aggregate(verdicts, on_adapter_error="fail_open")
    response = build_hook_response(decision)
    assert response["ext"]["provenance"][0]["scannerContext"] == {"risk_score": 0.2}

    # Simulate a hypothetical MTA carrying that /ext block forward into the rcpt-stage request.
    rcpt_payload = {
        "stage": "rcpt",
        "properties": {"rcpt_to": "b@example.com"},
        "ext": response["ext"],
    }
    rcpt_ctx = parse_hook_request(rcpt_payload)
    assert rcpt_ctx.ext["provenance"][0]["scannerContext"]["risk_score"] == 0.2
    assert mail_ctx.stage.value == "mail"
