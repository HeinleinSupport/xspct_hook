# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""The only wire dialect real Stalwart can call: its flat ``{action, response, modifications}`` JSON.

See docs/architecture.md for the full divergence from the -01 draft that this codec resolves.
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import replace
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.canonical import PeerPayload, parse_hook_request
from xspct_hook.protocol.decision import HookDecision, ResponseOverride
from xspct_hook.protocol.models import (
    INBOUND_STAGES,
    HookContext,
    Stage,
)
from xspct_hook.protocol.modifications import (
    AddOperation,
    DeleteOperation,
    Modification,
    SetOperation,
    apply_modifications,
    validate_modification,
)

_HEADER_APPEND_PATH = "/message/headers/-"
_HEADER_INDEX_RE = re.compile(r"^/message/headers/(\d+)$")
_RECIPIENT_APPEND_PATH = "/envelope/to/-"
_RECIPIENT_INDEX_RE = re.compile(r"^/envelope/to/(\d+)$")
_SENDER_PATH = "/envelope/from"

STALWART_SCHEMA_REVISION = "8b32686532d34623e9ce8e1237cf2bed9554af38"
STALWART_STAGES = INBOUND_STAGES - {Stage.AUTH}
logger = logging.getLogger(__name__)


def _decode_headers(headers: list[tuple[str, str]]) -> list[dict[str, str]]:
    result = []
    for name, value in headers:
        value = value.removesuffix("\r\n") if value.endswith("\r\n") else value.removesuffix("\n")
        value = re.sub(r"\r?\n[ \t]+", " ", value).lstrip(" \t")
        header = {"name": name, "value": value}
        validate_modification(AddOperation(_HEADER_APPEND_PATH, header))
        result.append(header)
    return result


def _raw_header(name: str, value: str) -> str:
    separator = "" if value.startswith((" ", "\t")) else " "
    ending = "" if value.endswith("\n") else "\r\n"
    return f"{name}:{separator}{value}{ending}"


class StalwartAddressPayload(BaseModel):
    address: StrictStr
    parameters: dict[str, StrictStr] | None = None


class StalwartEnvelopePayload(BaseModel):
    from_: StalwartAddressPayload = Field(alias="from")
    to: list[StalwartAddressPayload] = Field(default_factory=list)


class StalwartContextPayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    stage: Stage
    client: PeerPayload | None = None
    server: PeerPayload | None = None
    sasl: dict[str, Any] | None = None
    queue: dict[str, Any] | None = None


class StalwartMessagePayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    headers: list[tuple[StrictStr, StrictStr]] = Field(default_factory=list)
    server_headers: list[tuple[StrictStr, StrictStr]] = Field(
        default_factory=list, alias="serverHeaders"
    )
    contents: StrictStr | None = None


class StalwartRequestPayload(BaseModel):
    context: StalwartContextPayload
    envelope: StalwartEnvelopePayload | None = None
    message: StalwartMessagePayload | None = None


_ACTION_TO_STALWART: dict[Action, str] = {
    Action.ACCEPT: "accept",
    Action.REJECT: "reject",
    Action.DISCARD: "discard",
    Action.QUARANTINE: "quarantine",
}


class StalwartCodec:
    """Decodes/encodes Stalwart's real ``MtaHook`` wire format."""

    def decode_request(
        self, payload: dict[str, Any], *, spool_threshold_mb: float = 10.0
    ) -> HookContext:
        parsed = StalwartRequestPayload.model_validate(payload)
        if parsed.context.stage not in STALWART_STAGES:
            raise ValueError("Stalwart supports connect, ehlo, mail, rcpt and data hooks")
        client = parsed.context.client.model_dump() if parsed.context.client else {}
        client["ehlo"] = (payload["context"].get("client") or {}).get("helo")
        canonical: dict[str, Any] = {
            "stage": parsed.context.stage.value,
            "client": client,
            "server": parsed.context.server.model_dump() if parsed.context.server else {},
            "queue": parsed.context.queue,
            "auth": parsed.context.sasl,
        }
        if parsed.envelope is not None:
            canonical["envelope"] = parsed.envelope.model_dump(by_alias=True)
            for address in [canonical["envelope"]["from"], *canonical["envelope"]["to"]]:
                address["parameters"] = address["parameters"] or {}
        if parsed.message is not None:
            headers = _decode_headers(parsed.message.headers)
            _decode_headers(parsed.message.server_headers)
            canonical["message"] = {"headers": headers}
            if parsed.message.contents is not None:
                contents = (
                    "".join(
                        _raw_header(name, value)
                        for name, value in [*parsed.message.server_headers, *parsed.message.headers]
                    )
                    + "\r\n"
                    + parsed.message.contents
                )
                canonical["rawMessage"] = base64.b64encode(
                    contents.encode("utf-8", errors="surrogateescape")
                ).decode("ascii")
        return parse_hook_request(canonical, spool_threshold_mb=spool_threshold_mb)

    def encode_response(
        self, decision: HookDecision, ctx: HookContext | None = None
    ) -> dict[str, Any]:
        action, response = self._map_action(decision.action, decision.response)
        headers = [mod for mod in decision.modifications if mod.path.startswith("/message/headers")]
        other = [mod for mod in decision.modifications if mod not in headers]
        modifications = []
        working = ctx
        for mod in sorted(
            other,
            key=lambda operation: (
                0
                if isinstance(operation, SetOperation)
                else 1
                if isinstance(operation, AddOperation)
                else 2
            ),
        ):
            modifications.append(self._map_modification(mod, working))
            if working is not None:
                working = replace(working, document=apply_modifications(working.document, [mod]))
        if headers and ctx is not None:
            original = ctx.document.get("message", {}).get("headers", [])
            modified = apply_modifications({"message": {"headers": original}}, headers)["message"][
                "headers"
            ]
            for position in range(len(original) - 1, -1, -1):
                name = original[position]["name"]
                occurrence = sum(
                    header["name"].lower() == name.lower() for header in original[: position + 1]
                )
                modifications.append({"type": "deleteHeader", "name": name, "index": occurrence})
            for header in reversed(modified):
                modifications.append({"type": "addHeader", **header})
        else:
            modifications.extend(self._map_modification(mod, ctx) for mod in headers)
        result: dict[str, Any] = {"action": action, "modifications": modifications}
        if response:
            result["response"] = response
        if decision.ext:
            result["ext"] = decision.ext
        return result

    @staticmethod
    def _map_action(
        action: Action, response: ResponseOverride | None
    ) -> tuple[str, dict[str, Any]]:
        resp: dict[str, Any] = {}
        if response is not None:
            if response.status is not None:
                resp["status"] = response.status
            if response.enhanced_code is not None:
                resp["enhanced_status"] = response.enhanced_code
            if response.message is not None:
                resp["message"] = response.message
        if action == Action.DISCONNECT:
            logger.warning(
                "Stalwart does not reliably honour disconnect; returning reject without closing "
                "the SMTP session"
            )
            return "reject", resp
        return _ACTION_TO_STALWART[action], resp

    @staticmethod
    def _map_modification(mod: Modification, ctx: HookContext | None = None) -> dict[str, Any]:
        validate_modification(mod)
        if isinstance(mod, AddOperation):
            if mod.path == _HEADER_APPEND_PATH:
                return {"type": "addHeader", "name": mod.value["name"], "value": mod.value["value"]}
            if mod.path == "/message/headers" or _HEADER_INDEX_RE.fullmatch(mod.path):
                index = (
                    mod.index if mod.path == "/message/headers" else int(mod.path.rsplit("/", 1)[1])
                )
                return {
                    "type": "insertHeader" if index is not None else "addHeader",
                    **({"index": index} if index is not None else {}),
                    **mod.value,
                }
            if mod.path in {_RECIPIENT_APPEND_PATH, "/envelope/to"}:
                if mod.index is not None:
                    raise ValueError("Stalwart cannot represent recipient insertion indexes")
                value = mod.value if isinstance(mod.value, dict) else {"address": mod.value}
                return {
                    "type": "addRecipient",
                    "value": value["address"],
                    "parameters": value.get("parameters", {}),
                }
        if isinstance(mod, SetOperation):
            header_match = _HEADER_INDEX_RE.match(mod.path)
            if header_match:
                if ctx is None:
                    raise ValueError("header replacement requires request context")
                headers = ctx.document["message"]["headers"]
                position = int(header_match.group(1))
                name = headers[position]["name"]
                value = mod.value
                if value["name"].lower() != name.lower():
                    raise ValueError("header renaming requires header reconstruction")
                return {
                    "type": "changeHeader",
                    "index": sum(
                        header["name"].lower() == name.lower() for header in headers[: position + 1]
                    ),
                    "name": name,
                    "value": value["value"],
                }
            if mod.path in {_SENDER_PATH, "/envelope/from/address"}:
                value = mod.value if isinstance(mod.value, dict) else {"address": mod.value}
                parameters = (
                    value.get("parameters", {})
                    if mod.path == _SENDER_PATH or ctx is None
                    else ctx.document.get("envelope", {}).get("from", {}).get("parameters", {})
                )
                return {
                    "type": "changeFrom",
                    "value": value["address"] or "",
                    "parameters": parameters,
                }
        if isinstance(mod, DeleteOperation):
            header_match = _HEADER_INDEX_RE.match(mod.path)
            if header_match:
                if ctx is None:
                    raise ValueError("header deletion requires request context")
                headers = ctx.document["message"]["headers"]
                position = int(header_match.group(1))
                name = headers[position]["name"]
                return {
                    "type": "deleteHeader",
                    "name": name,
                    "index": sum(
                        header["name"].lower() == name.lower() for header in headers[: position + 1]
                    ),
                }
            recipient_match = _RECIPIENT_INDEX_RE.match(mod.path)
            if recipient_match:
                if ctx is None:
                    raise ValueError("recipient deletion requires request context")
                value = ctx.document["envelope"]["to"][int(recipient_match.group(1))]["address"]
                return {"type": "deleteRecipient", "value": value}
        raise ValueError(f"modification cannot be represented by Stalwart: {mod.path}")
