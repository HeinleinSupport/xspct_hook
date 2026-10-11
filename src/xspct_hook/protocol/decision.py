# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Adapter-facing and orchestrator-facing verdict/decision types."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.modifications import Modification


class VerdictStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class ResponseOverride:
    status: int | None = None
    enhanced_code: str | None = None
    message: str | None = None

    def __post_init__(self) -> None:
        if self.status is not None and (
            type(self.status) is not int or not 200 <= self.status <= 599
        ):
            raise ValueError("invalid SMTP status")
        if self.enhanced_code is not None and (
            not isinstance(self.enhanced_code, str)
            or not re.fullmatch(r"[245]\.\d{1,3}\.\d{1,3}", self.enhanced_code)
        ):
            raise ValueError("invalid enhanced SMTP status")
        if self.message is not None and (
            not isinstance(self.message, str) or "\r" in self.message or "\n" in self.message
        ):
            raise ValueError("invalid SMTP response message")


@dataclass(frozen=True)
class ScanVerdict:
    """A single adapter's result for one hook call."""

    engine: str
    status: VerdictStatus = VerdictStatus.OK
    action: Action | None = None
    response: ResponseOverride | None = None
    modifications: tuple[Modification, ...] = ()
    scanner_context: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.engine, str) or not isinstance(self.status, VerdictStatus):
            raise TypeError("invalid verdict engine or status")
        if self.action is not None and not isinstance(self.action, Action):
            raise ValueError("invalid verdict action")
        if not isinstance(self.modifications, tuple) or not isinstance(self.scanner_context, dict):
            raise TypeError("invalid verdict modifications or scanner context")
        if self.response is not None and not isinstance(self.response, ResponseOverride):
            raise ValueError("invalid verdict response")
        if self.error is not None and not isinstance(self.error, str):
            raise ValueError("invalid verdict error")
        if self.response is not None:
            self.response.__post_init__()
        if self.status == VerdictStatus.OK and self.action is None:
            raise ValueError(f"ScanVerdict from {self.engine!r} has status=OK but no action")

    @classmethod
    def ok(
        cls,
        engine: str,
        action: Action,
        *,
        response: ResponseOverride | None = None,
        modifications: tuple[Modification, ...] = (),
        scanner_context: dict[str, Any] | None = None,
    ) -> ScanVerdict:
        return cls(
            engine=engine,
            status=VerdictStatus.OK,
            action=action,
            response=response,
            modifications=modifications,
            scanner_context=scanner_context or {},
        )

    @classmethod
    def error_result(cls, engine: str, error: str) -> ScanVerdict:
        return cls(engine=engine, status=VerdictStatus.ERROR, error=error)

    @classmethod
    def skipped(cls, engine: str) -> ScanVerdict:
        return cls(engine=engine, status=VerdictStatus.SKIPPED)


@dataclass(frozen=True)
class HookDecision:
    """The orchestrator's final, aggregated decision for one hook call."""

    action: Action
    response: ResponseOverride | None
    modifications: tuple[Modification, ...]
    decided_by: str
    ext: dict[str, Any] = field(default_factory=dict)
