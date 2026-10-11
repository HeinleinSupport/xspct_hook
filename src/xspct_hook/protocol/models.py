# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Stage-specific hook contexts: the ``fetchProperties`` stand-in for this phase."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, ClassVar

from xspct_hook.exceptions import PropertyNotProvidedError
from xspct_hook.protocol.actions import Action


class Stage(str, Enum):
    CONNECT = "connect"
    EHLO = "ehlo"
    AUTH = "auth"
    MAIL = "mail"
    RCPT = "rcpt"
    DATA = "data"
    DELIVERY = "delivery"
    DEFER = "defer"
    DSN = "dsn"


INBOUND_STAGES = frozenset(
    {Stage.CONNECT, Stage.EHLO, Stage.AUTH, Stage.MAIL, Stage.RCPT, Stage.DATA}
)
OUTBOUND_STAGES = frozenset({Stage.DELIVERY, Stage.DEFER, Stage.DSN})


@dataclass(frozen=True)
class ClientInfo:
    ip: str | None = None
    port: int | None = None


@dataclass(frozen=True)
class ServerInfo:
    ip: str | None = None
    port: int | None = None


@dataclass(frozen=True)
class HookContext:
    """Base canonical hook context, shared by every stage subclass below.

    ``properties`` holds the raw per-stage payload as decoded by a wire codec;
    :meth:`property` provides fetchProperties-style access that distinguishes
    "not provided by this call" from "provided but empty".
    """

    stage: ClassVar[Stage]

    session_id: str
    queue_id: str | None
    client: ClientInfo
    server: ServerInfo
    trace_id: str
    provided_properties: frozenset[str]
    properties: dict[str, Any] = field(default_factory=dict)
    ext: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    action: Action = Action.ACCEPT
    document: dict[str, Any] = field(default_factory=dict)

    def property(self, name: str) -> Any:
        if name not in self.provided_properties:
            raise PropertyNotProvidedError(name)
        return self.properties.get(name)


class ConnectContext(HookContext):
    stage = Stage.CONNECT


class EhloContext(HookContext):
    stage = Stage.EHLO

    @property
    def helo_name(self) -> str | None:
        value: str | None = self.property("helo_name")
        return value


class AuthContext(HookContext):
    stage = Stage.AUTH

    @property
    def auth_login(self) -> str | None:
        value: str | None = self.property("auth_login")
        return value


class MailContext(HookContext):
    stage = Stage.MAIL

    @property
    def mail_from(self) -> str | None:
        value: str | None = self.property("mail_from")
        return value


class RcptContext(HookContext):
    stage = Stage.RCPT

    @property
    def rcpt_to(self) -> str | None:
        value: str | None = self.property("rcpt_to")
        return value


class DataContext(HookContext):
    stage = Stage.DATA

    @property
    def headers(self) -> list[tuple[str, str]]:
        return self.property("headers") or []

    @property
    def message(self) -> Any:
        return self.property("message")


class DeliveryContext(HookContext):
    stage = Stage.DELIVERY

    @property
    def rcpt_to(self) -> str | None:
        value: str | None = self.property("rcpt_to")
        return value


class DeferContext(HookContext):
    stage = Stage.DEFER

    @property
    def rcpt_to(self) -> str | None:
        value: str | None = self.property("rcpt_to")
        return value

    @property
    def defer_reason(self) -> str | None:
        value: str | None = self.property("defer_reason")
        return value


class DsnContext(HookContext):
    stage = Stage.DSN

    @property
    def dsn_type(self) -> str | None:
        value: str | None = self.property("dsn_type")
        return value


STAGE_CONTEXT_CLASSES: dict[Stage, type[HookContext]] = {
    Stage.CONNECT: ConnectContext,
    Stage.EHLO: EhloContext,
    Stage.AUTH: AuthContext,
    Stage.MAIL: MailContext,
    Stage.RCPT: RcptContext,
    Stage.DATA: DataContext,
    Stage.DELIVERY: DeliveryContext,
    Stage.DEFER: DeferContext,
    Stage.DSN: DsnContext,
}
