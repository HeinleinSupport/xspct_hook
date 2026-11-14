# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Scan decoded MIME content parts through xspct_scan's v2 report API."""

from __future__ import annotations

import asyncio
import json
import math
import mimetypes
from email import policy
from email.parser import BytesParser
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from xspct_hook.protocol.actions import Action
from xspct_hook.protocol.decision import ResponseOverride, ScanVerdict, VerdictStatus
from xspct_hook.protocol.models import HookContext, Stage


class _Analyzers(BaseModel):
    model_config = ConfigDict(extra="allow")

    pending: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


class _ScanState(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: Literal["finished", "processing", "dropped", "error"]
    analyzers: _Analyzers


class _ClamAVResult(BaseModel):
    status: Literal["clean", "infected", "skipped", "unavailable", "error", "timeout"]


class _Report(BaseModel):
    model_config = ConfigDict(strict=True)

    schema_version: Literal["2.0"]
    status: Literal["finished", "processing", "dropped", "error"]
    file: dict[str, object]
    scan: _ScanState
    verdict: dict[str, object]
    findings: list[dict[str, object]] = Field(default_factory=list)
    flags: dict[str, object] = Field(default_factory=dict)
    iocs: dict[str, object] = Field(default_factory=dict)
    engines: dict[str, object] = Field(default_factory=dict)


class XspctScanAdapter:
    """Scan all non-empty MIME leaves; only confirmed ClamAV detections reject."""

    name = "xspct_scan"
    supported_stages = frozenset({Stage.DATA})
    supported_actions = frozenset({Action.ACCEPT, Action.REJECT})

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 30.0,
        scan_timeout: float = 10.0,
    ) -> None:
        url = httpx.URL(base_url)
        if (
            url.scheme not in {"http", "https"}
            or not url.host
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError(
                "base_url must be an HTTP(S) URL without credentials, query or fragment"
            )
        if any(not math.isfinite(value) or value <= 0 for value in (timeout, scan_timeout)):
            raise ValueError("timeout and scan_timeout must be finite and positive")
        self.timeout = timeout
        self.scan_timeout = scan_timeout
        headers = {"Accept": "application/json"}
        if api_key:
            headers["X-Api-Key"] = api_key
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/",
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
        )

    async def connect(self) -> None:
        async with asyncio.timeout(self.timeout):
            response = await self._client.get("health")
            response.raise_for_status()

    async def close(self) -> None:
        await self._client.aclose()

    async def scan(self, ctx: HookContext) -> ScanVerdict:
        if ctx.stage not in self.supported_stages or "message" not in ctx.provided_properties:
            return ScanVerdict.error_result(self.name, "xspct_scan requires a DATA message")
        body = ctx.property("message")
        if body is None:
            return ScanVerdict.error_result(self.name, "no message body available")
        async with asyncio.timeout(self.timeout):
            message = BytesParser(policy=policy.default.clone(raise_on_defect=True)).parsebytes(
                body.read_all()
            )
            parts: list[dict[str, object]] = []
            context = {"parts": parts}
            for index, part in enumerate(message.walk()):
                if part.is_multipart():
                    continue
                data = part.get_payload(decode=True)
                if not isinstance(data, bytes):
                    raise TypeError("cannot decode MIME content part")
                if not data:
                    continue
                content_type = part.get_content_type()
                filename = part.get_filename() or (
                    f"part-{index}{mimetypes.guess_extension(content_type) or '.bin'}"
                )
                metadata: dict[str, object] = {
                    "filename": filename,
                    "declared_content_type": content_type,
                    "timeout_s": self.scan_timeout,
                }
                if ctx.queue_id:
                    metadata["queue_id"] = ctx.queue_id
                if message_id := message.get("Message-ID"):
                    metadata["message_id"] = str(message_id)
                response = await self._client.post(
                    "v1/scan",
                    params={"timeout": self.scan_timeout},
                    files={
                        "metadata": (None, json.dumps(metadata), "application/json"),
                        "file": (filename, data, content_type),
                    },
                )
                response.raise_for_status()
                if response.status_code not in {200, 202}:
                    raise ValueError(f"unexpected xspct_scan HTTP status: {response.status_code}")
                report = _Report.model_validate(response.json())
                # Keep passwords, extracted content and image metadata out of provenance.
                summary = report.model_dump(exclude={"flags": True, "engines": {"image": {"exif"}}})
                summary["flags"] = {
                    key: value for key, value in report.flags.items() if isinstance(value, bool)
                }
                parts.append({"index": index, "filename": filename, "report": summary})
                clamav = (
                    _ClamAVResult.model_validate(report.engines["clamav"])
                    if "clamav" in report.engines
                    else None
                )
                if (
                    response.status_code != 200
                    or report.status != "finished"
                    or report.scan.status != "finished"
                    or report.scan.analyzers.pending
                    or report.scan.analyzers.errors
                    or (clamav is not None and clamav.status not in {"clean", "infected"})
                ):
                    return ScanVerdict(
                        engine=self.name,
                        status=VerdictStatus.ERROR,
                        error="xspct_scan returned an incomplete or failed analysis",
                        scanner_context=context,
                    )
                if (clamav is not None and clamav.status == "infected") or any(
                    finding.get("type") == "ClamAV" for finding in report.findings
                ):
                    return ScanVerdict.ok(
                        self.name,
                        Action.REJECT,
                        response=ResponseOverride(
                            status=550,
                            enhanced_code="5.7.1",
                            message="malware detected by xspct_scan",
                        ),
                        scanner_context=context,
                    )
            return ScanVerdict.ok(self.name, Action.ACCEPT, scanner_context=context)
