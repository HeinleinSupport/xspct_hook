# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Shared fixtures for unit and integration tests."""

from __future__ import annotations

from uuid import uuid4

import pytest

from xspct_hook.adapters.pseudo import PseudoScannerAdapter
from xspct_hook.aggregation import FirstRejectWins
from xspct_hook.profiles import HookProfile
from xspct_hook.protocol.models import ClientInfo, ServerInfo, Stage


@pytest.fixture
def pseudo_profile() -> HookProfile:
    return HookProfile(
        name="pseudo-test",
        path="/hooks/pseudo-test",
        stages=frozenset({Stage.MAIL, Stage.RCPT, Stage.DATA}),
        token="test-token",
        adapters=[PseudoScannerAdapter()],
        strategy=FirstRejectWins(),
    )


def make_properties(**props: object) -> tuple[dict[str, object], frozenset[str]]:
    return props, frozenset(props)


def client_info() -> ClientInfo:
    return ClientInfo(ip="203.0.113.5", port=51234)


def server_info() -> ServerInfo:
    return ServerInfo(ip="198.51.100.10", port=25)


def new_trace_id() -> str:
    return str(uuid4())
