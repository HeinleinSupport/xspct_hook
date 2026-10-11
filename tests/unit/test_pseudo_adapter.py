# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for adapters/pseudo.py: scenario resolution and the full scenario catalogue."""

from __future__ import annotations

import pytest

from xspct_hook.adapters.pseudo import PseudoScannerAdapter
from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.canonical import parse_hook_request
from xspct_hook.protocol.decision import VerdictStatus


def _rcpt_ctx(local_part: str):
    return parse_hook_request(
        {"stage": "rcpt", "properties": {"rcpt_to": f"{local_part}@test.local"}}
    )


@pytest.mark.parametrize(
    ("scenario", "expected_action"),
    [
        ("clean", Action.ACCEPT),
        ("malicious", Action.REJECT),
        ("suspicious", Action.QUARANTINE),
        ("reject", Action.REJECT),
        ("quarantine", Action.QUARANTINE),
        ("discard", Action.DISCARD),
        ("header_add", Action.ACCEPT),
        ("header_replace", Action.ACCEPT),
        ("header_delete", Action.ACCEPT),
        ("context_rich", Action.ACCEPT),
        ("disconnect", Action.DISCONNECT),
        ("error", None),
    ],
)
async def test_scenario_resolution_from_recipient(
    scenario: str, expected_action: Action | None
) -> None:
    adapter = PseudoScannerAdapter()
    ctx = _rcpt_ctx(f"verdict+{scenario}")
    verdict = await adapter.scan(ctx)
    assert verdict.action == expected_action
    if expected_action is None:
        assert verdict.status == VerdictStatus.ERROR


async def test_default_scenario_used_without_recipient_hint() -> None:
    adapter = PseudoScannerAdapter(default_scenario="malicious")
    ctx = parse_hook_request({"stage": "mail", "properties": {"mail_from": "sender@example.com"}})
    verdict = await adapter.scan(ctx)
    assert verdict.action == Action.REJECT


async def test_malformed_scenario_raises_and_is_the_orchestrators_job_to_catch() -> None:
    adapter = PseudoScannerAdapter()
    ctx = _rcpt_ctx("verdict+malformed")
    with pytest.raises(ValueError, match="status=OK but no action"):
        await adapter.scan(ctx)


async def test_header_add_scenario_produces_modification() -> None:
    adapter = PseudoScannerAdapter()
    ctx = _rcpt_ctx("verdict+header_add")
    verdict = await adapter.scan(ctx)
    assert len(verdict.modifications) == 1


async def test_slow_scenario_completes_after_delay() -> None:
    adapter = PseudoScannerAdapter(slow_delay=0.01)
    ctx = _rcpt_ctx("verdict+slow")
    verdict = await adapter.scan(ctx)
    assert verdict.action == Action.ACCEPT


def test_supported_stages_and_actions_cover_everything() -> None:
    adapter = PseudoScannerAdapter()
    from xspct_hook.protocol.models import Stage

    assert adapter.supported_stages == frozenset(Stage)
    assert adapter.supported_actions == frozenset(Action)
