# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""In-memory registration store for the native -01 discovery/registration endpoint."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from xspct_hook.profiles import HookProfile
from xspct_hook.protocol.actions import INBOUND_ACTIONS, OUTBOUND_ACTIONS
from xspct_hook.protocol.models import INBOUND_STAGES, OUTBOUND_STAGES, Stage

FETCH_PROPERTIES = frozenset(
    {
        "/stage",
        "/action",
        "/timestamp",
        "/protocol",
        "/envelope",
        "/message/headers",
        "/rawMessage",
        "/client",
        "/server",
        "/auth",
        "/queue",
        "/ext",
    }
)
UPDATE_PROPERTIES = [
    "/action",
    "/response",
    "/message/headers",
    "/envelope/from/address",
    "/envelope/to",
]


class StageSubscription(BaseModel):
    stages: list[Stage] = Field(min_length=1)
    properties: list[StrictStr] | None = None


class RegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: StrictStr = Field(min_length=1)
    version: StrictStr | None = None
    serialization: Literal["json"]
    inbound: StageSubscription | None = None
    outbound: StageSubscription | None = None
    timeoutMs: int | None = Field(default=None, gt=0)
    expiresAt: datetime | None = None
    filter: dict[str, Any] | None = None
    metadata: dict[str, StrictStr] | None = None


def discovery_capabilities(profile: HookProfile) -> dict[str, Any]:
    supported = frozenset(
        stage for adapter in profile.adapters for stage in adapter.supported_stages
    )
    actions = frozenset(
        action for adapter in profile.adapters for action in adapter.supported_actions
    )
    result: dict[str, Any] = {}
    for direction, stages, allowed in [
        ("inbound", INBOUND_STAGES - {Stage.AUTH}, INBOUND_ACTIONS),
        ("outbound", OUTBOUND_STAGES, OUTBOUND_ACTIONS),
    ]:
        enabled = profile.stages & stages & supported
        result[direction] = (
            {
                "stages": sorted(stage.value for stage in enabled),
                "actions": sorted(action.value for action in actions & allowed),
                "fetchProperties": sorted(FETCH_PROPERTIES),
                "updateProperties": UPDATE_PROPERTIES,
            }
            if enabled
            else None
        )
    return result


def negotiate(request: RegistrationRequest, profile: HookProfile) -> dict[str, Any]:
    if request.inbound is None and request.outbound is None:
        raise ValueError("at least one stage subscription is required")
    if request.expiresAt is not None or request.filter is not None:
        raise ValueError("expiration and filters are not supported in this phase")
    available = discovery_capabilities(profile)
    result: dict[str, Any] = {"serialization": "json"}
    for direction in ("inbound", "outbound"):
        subscription = getattr(request, direction)
        if subscription is None:
            result[direction] = None
            continue
        capability = available[direction]
        if capability is None or not {stage.value for stage in subscription.stages} <= set(
            capability["stages"]
        ):
            raise ValueError(f"unsupported {direction} stages")
        properties = (
            sorted(FETCH_PROPERTIES) if subscription.properties is None else subscription.properties
        )
        if not set(properties) <= FETCH_PROPERTIES:
            raise ValueError("unsupported properties")
        result[direction] = {
            "stages": sorted({stage.value for stage in subscription.stages}),
            "properties": properties,
        }
    return result


@dataclass(frozen=True)
class Registration:
    registration_id: str
    profile_name: str
    hook_endpoint: str
    capabilities: dict[str, Any]
    created_at: datetime


class RegistrationStore:
    """TTL/idle-expiry is not implemented in this slim phase — only explicit DELETE removes an entry."""

    def __init__(self) -> None:
        self._registrations: dict[str, Registration] = {}
        self._deregistered: set[str] = set()

    def register(
        self, profile_name: str, hook_endpoint: str, capabilities: dict[str, Any]
    ) -> Registration:
        registration_id = secrets.token_urlsafe(16)
        registration = Registration(
            registration_id=registration_id,
            profile_name=profile_name,
            hook_endpoint=hook_endpoint,
            capabilities=capabilities,
            created_at=datetime.now(UTC),
        )
        self._registrations[registration_id] = registration
        return registration

    def get(self, registration_id: str) -> Registration | None:
        return self._registrations.get(registration_id)

    def deregister(self, registration_id: str) -> bool:
        removed = self._registrations.pop(registration_id, None) is not None
        if removed:
            self._deregistered.add(registration_id)
        return removed

    def was_deregistered(self, registration_id: str) -> bool:
        return registration_id in self._deregistered
