# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""The literal -01 wire JSON shape: ``parse_hook_request``/``build_hook_response``.

This is the only codec that round-trips the ``/ext`` namespace (scannerContext +
provenance), since Stalwart's own flat format silently ignores unknown top-level keys.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from xspct_hook.body import MessageBody
from xspct_hook.protocol.actions import Action, default_action, validate_stage_action
from xspct_hook.protocol.decision import HookDecision, ResponseOverride
from xspct_hook.protocol.models import (
    STAGE_CONTEXT_CLASSES,
    ClientInfo,
    HookContext,
    ServerInfo,
    Stage,
)
from xspct_hook.protocol.modifications import (
    AddOperation,
    DeleteOperation,
    Modification,
    SetOperation,
    validate_modification,
)

_SIMPLE_PROPERTY_KEYS = (
    "mail_from",
    "rcpt_to",
    "auth_login",
    "helo_name",
    "defer_reason",
    "dsn_type",
)


class AddressPayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    address: StrictStr | None
    parameters: dict[str, StrictStr | None] = Field(default_factory=dict)


class EnvelopePayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    from_: AddressPayload = Field(alias="from")
    to: list[AddressPayload] = Field(default_factory=list)


class HeaderPayload(BaseModel):
    name: StrictStr
    value: StrictStr


class MessagePayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    headers: list[HeaderPayload] = Field(default_factory=list)


class PeerPayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    ip: StrictStr | None = None
    port: StrictInt | None = None
    ehlo: StrictStr | None = None


class HookPayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    stage: Stage
    action: Action | None = None
    timestamp: datetime | None = None
    client: PeerPayload | None = None
    server: PeerPayload | None = None
    envelope: EnvelopePayload | None = None
    message: MessagePayload | None = None
    rawMessage: StrictStr | None = None
    queue: dict[str, Any] | None = None
    auth: dict[str, Any] | None = None
    ext: dict[str, Any] = Field(default_factory=dict)
    properties: dict[str, Any] = Field(default_factory=dict)


def parse_hook_request(payload: dict[str, Any], *, spool_threshold_mb: float = 10.0) -> HookContext:
    parsed = HookPayload.model_validate(payload)
    stage = parsed.stage
    action = parsed.action or default_action(stage.value)
    validate_stage_action(stage.value, action)
    client = ClientInfo(
        ip=parsed.client.ip if parsed.client else None,
        port=parsed.client.port if parsed.client else None,
    )
    server = ServerInfo(
        ip=parsed.server.ip if parsed.server else None,
        port=parsed.server.port if parsed.server else None,
    )
    raw_properties = parsed.properties
    properties: dict[str, Any] = {}
    for key in _SIMPLE_PROPERTY_KEYS:
        if key in raw_properties:
            properties[key] = raw_properties[key]
    if "headers" in raw_properties:
        properties["headers"] = [tuple(h) for h in raw_properties["headers"]]
    if "message_contents" in raw_properties and not isinstance(
        raw_properties["message_contents"], str
    ):
        raise TypeError("message_contents must be a string")
    if parsed.envelope is not None:
        properties["mail_from"] = parsed.envelope.from_.address
        properties["recipients"] = [recipient.address for recipient in parsed.envelope.to]
        if any(recipient.address is None for recipient in parsed.envelope.to):
            raise ValueError("recipient address must not be null")
        if parsed.envelope.to:
            properties["rcpt_to"] = parsed.envelope.to[-1 if stage == Stage.RCPT else 0].address
    if parsed.message is not None:
        properties["headers"] = [(header.name, header.value) for header in parsed.message.headers]
    if parsed.client and parsed.client.ehlo is not None:
        properties["helo_name"] = parsed.client.ehlo
    if parsed.auth is not None and "login" in parsed.auth:
        if not isinstance(parsed.auth["login"], str):
            raise ValueError("auth.login must be a string")
        properties["auth_login"] = parsed.auth["login"]
    body = (
        base64.b64decode(parsed.rawMessage, validate=True)
        if parsed.rawMessage is not None
        else None
    )
    if body is None and "message_contents" in raw_properties:
        body = raw_properties["message_contents"].encode("utf-8", errors="surrogateescape")
    if body is not None:
        properties["message"] = MessageBody.from_bytes(body, spool_threshold_mb=spool_threshold_mb)

    context_cls = STAGE_CONTEXT_CLASSES[stage]
    return context_cls(
        session_id=payload.get("sessionId") or str(uuid4()),
        queue_id=(parsed.queue or {}).get("id", payload.get("queueId")),
        client=client,
        server=server,
        trace_id=str(uuid4()),
        provided_properties=frozenset(properties),
        properties=properties,
        ext=parsed.ext,
        timestamp=parsed.timestamp or datetime.now(UTC),
        action=action,
        document=payload,
    )


def build_hook_response(decision: HookDecision) -> dict[str, Any]:
    response: dict[str, Any] = {
        "set": [{"path": "/action", "value": decision.action.value}],
        "add": [],
        "delete": [],
    }
    if decision.response is not None:
        response["set"].append({"path": "/response", "value": _response_to_dict(decision.response)})
    for mod in decision.modifications:
        validate_modification(mod)
        group = (
            "add"
            if isinstance(mod, AddOperation)
            else "set"
            if isinstance(mod, SetOperation)
            else "delete"
        )
        response[group].append(_modification_to_dict(mod))
    if decision.ext:
        response["ext"] = decision.ext
    return response


def _response_to_dict(response: ResponseOverride) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if response.status is not None:
        result["code"] = response.status
    if response.enhanced_code is not None:
        result["enhancedCode"] = response.enhanced_code
    if response.message is not None:
        result["message"] = response.message
    return result


def _modification_to_dict(mod: Modification) -> dict[str, Any]:
    if isinstance(mod, AddOperation):
        path = mod.path
        index = mod.index
        suffix = path.rsplit("/", 1)[1]
        if path.startswith(("/message/headers/", "/envelope/to/")) and (
            suffix == "-" or suffix.isdecimal()
        ):
            path, suffix = path.rsplit("/", 1)
            index = None if suffix == "-" else int(suffix)
        result = {"path": path, "value": mod.value}
        if index is not None:
            result["index"] = index
        return result
    if isinstance(mod, SetOperation):
        return {"path": mod.path, "value": mod.value}
    if isinstance(mod, DeleteOperation):
        return {"path": mod.path}
    raise TypeError(f"unknown modification type: {type(mod)!r}")
