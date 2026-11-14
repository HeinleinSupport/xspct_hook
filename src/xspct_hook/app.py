# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""FastAPI app factory: one Stalwart route plus one native -01 discovery/registration/hook
route set per configured profile."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from pydantic.json_schema import models_json_schema

from xspct_hook.body import MessageBody
from xspct_hook.config import AppConfig, build_profiles
from xspct_hook.events import EventBus, ModificationRejected
from xspct_hook.exceptions import HeaderInjectionRejected, RegistrationNotFoundError
from xspct_hook.logging_ import JSONLWriter
from xspct_hook.orchestrator import HookOrchestrator
from xspct_hook.profiles import HookProfile
from xspct_hook.protocol.canonical import HookPayload
from xspct_hook.protocol.models import OUTBOUND_STAGES
from xspct_hook.registration import (
    Registration,
    RegistrationRequest,
    RegistrationStore,
    discovery_capabilities,
    negotiate,
)
from xspct_hook.wire.mta01 import Mta01Codec
from xspct_hook.wire.stalwart import STALWART_STAGES, StalwartCodec, StalwartRequestPayload

logger = logging.getLogger(__name__)


def create_app(config: AppConfig) -> FastAPI:
    profiles = build_profiles(config)
    bus = EventBus()
    jsonl_writer = JSONLWriter(bus, Path(config.jsonl_log_path))
    orchestrator = HookOrchestrator(bus=bus)
    registration_store = RegistrationStore()
    stalwart_codec = StalwartCodec()
    mta01_codec = Mta01Codec()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await jsonl_writer.start()
        for profile in profiles:
            for adapter in profile.adapters:
                try:
                    await asyncio.wait_for(adapter.connect(), timeout=profile.adapter_timeout)
                except Exception:
                    logger.exception(
                        "adapter %r failed to connect for profile %r; it will error at scan time",
                        adapter.name,
                        profile.name,
                    )
        try:
            yield
        finally:
            for profile in profiles:
                for adapter in profile.adapters:
                    try:
                        await asyncio.wait_for(adapter.close(), timeout=profile.adapter_timeout)
                    except Exception:
                        logger.exception("adapter %r failed to close", adapter.name)
            await jsonl_writer.stop()

    app = FastAPI(title="xspct_hook", lifespan=lifespan)
    app.state.profiles = {profile.name: profile for profile in profiles}
    app.state.bus = bus
    app.state.registration_store = registration_store

    @app.exception_handler(RegistrationNotFoundError)
    async def _handle_registration_not_found(
        _request: Request, exc: RegistrationNotFoundError
    ) -> JSONResponse:
        deregistered = registration_store.was_deregistered(exc.registration_id)
        return JSONResponse(
            status_code=410 if deregistered else 404,
            content={
                "error": {
                    "code": "REGISTRATION_DEREGISTERED"
                    if deregistered
                    else "REGISTRATION_NOT_FOUND",
                    "message": str(exc),
                }
            },
        )

    @app.exception_handler(HTTPException)
    async def _handle_http_error(_request: Request, exc: HTTPException) -> JSONResponse:
        detail = (
            exc.detail
            if isinstance(exc.detail, dict)
            else {"code": "INVALID_REQUEST", "message": str(exc.detail)}
        )
        return JSONResponse(
            status_code=exc.status_code, content={"error": detail}, headers=exc.headers
        )

    for profile in profiles:
        _register_stalwart_route(app, profile, orchestrator, stalwart_codec, config)
        _register_mta01_routes(app, profile, orchestrator, mta01_codec, registration_store, config)

    async def _root_discovery() -> Response:
        return _dump_json(_discovery(profiles[0]))

    app.add_api_route("/.well-known/mta-hooks", _root_discovery, methods=["GET"])

    def _openapi() -> dict[str, Any]:
        if app.openapi_schema is not None:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            openapi_version=app.openapi_version,
            routes=app.routes,
        )
        # Document manual decoding without moving body parsing ahead of authentication.
        _, definitions = models_json_schema(
            [
                (StalwartRequestPayload, "validation"),
                (HookPayload, "validation"),
                (RegistrationRequest, "validation"),
            ],
            ref_template="#/components/schemas/{model}",
        )
        schemas = schema.setdefault("components", {}).setdefault("schemas", {})
        schemas.update(definitions["$defs"])
        schemas["StalwartContextPayload"]["properties"]["stage"] = {
            "type": "string",
            "enum": sorted(stage.value for stage in STALWART_STAGES),
        }
        schemas["HookPayload"]["required"].append("action")
        del schemas["HookPayload"]["properties"]["properties"]
        schemas["HookPayload"]["not"] = {"required": ["properties"]}
        for profile in profiles:
            for suffix, model in (
                ("", "StalwartRequestPayload"),
                ("/mta01", "HookPayload"),
                ("/register", "RegistrationRequest"),
            ):
                operation = schema["paths"][profile.path + suffix]["post"]
                operation["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {"schema": {"$ref": f"#/components/schemas/{model}"}}
                    },
                }
            for parameter in schema["paths"][f"{profile.path}/mta01"]["post"]["parameters"]:
                if parameter["in"] == "header":
                    parameter["required"] = True
                    parameter["schema"].pop("default", None)
        app.openapi_schema = schema
        return schema

    app.openapi = _openapi
    return app


def _dump_json(
    data: dict[str, Any], *, status_code: int = 200, headers: dict[str, str] | None = None
) -> Response:
    return Response(
        content=json.dumps(data, allow_nan=False).encode("utf-8"),
        media_type="application/json",
        status_code=status_code,
        headers=headers,
    )


def _error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


async def _read_payload(request: Request) -> dict[str, Any]:
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
        raise _error(415, "INVALID_REQUEST", "Content-Type must be application/json")
    try:
        data = await request.json()
    except (ValueError, UnicodeError) as exc:
        raise _error(400, "INVALID_REQUEST", "malformed JSON") from exc
    if not isinstance(data, dict):
        raise _error(400, "INVALID_REQUEST", "request must be a JSON object")
    try:
        json.dumps(data, allow_nan=False)
    except (ValueError, UnicodeError) as exc:
        raise _error(400, "INVALID_REQUEST", "request must contain valid JSON values") from exc
    return data


def _discovery(profile: HookProfile) -> dict[str, Any]:
    return {
        "version": "1.0",
        "endpoints": {
            "registration": f"{profile.path}/register",
            "deregistration": f"{profile.path}/register/{{registration_id}}",
        },
        "serialization": ["json"],
        "capabilities": discovery_capabilities(profile),
        "limits": {"timeoutMs": int(profile.overall_timeout * 1000)},
        "extensions": ["de.heinlein-support.xspct.provenance"],
    }


def _registration_for_profile(
    store: RegistrationStore, registration_id: str, profile: HookProfile
) -> Registration:
    registration = store.get(registration_id)
    if registration is None:
        raise RegistrationNotFoundError(registration_id)
    if registration.profile_name != profile.name:
        raise _error(403, "REGISTRATION_MISMATCH", "registration belongs to another profile")
    return registration


def _check_bearer_token(credentials: HTTPAuthorizationCredentials | None, token: str) -> None:
    if credentials is None or not secrets.compare_digest(
        credentials.credentials.encode("utf-8"), token.encode("utf-8")
    ):
        raise _error(401, "INVALID_CREDENTIALS", "invalid or missing bearer token")


def _register_stalwart_route(
    app: FastAPI,
    profile: HookProfile,
    orchestrator: HookOrchestrator,
    codec: StalwartCodec,
    config: AppConfig,
) -> None:
    security = HTTPBearer(auto_error=False)

    async def _handler(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(security),
    ) -> Response:
        _check_bearer_token(credentials, profile.token)

        payload = await _read_payload(request)
        try:
            ctx = codec.decode_request(payload, spool_threshold_mb=config.body_spool_threshold_mb)
        except (ValueError, TypeError, KeyError, HeaderInjectionRejected) as exc:
            raise _error(400, "INVALID_REQUEST", "invalid Stalwart hook payload") from exc

        message = ctx.properties.get("message")
        try:
            if ctx.stage not in profile.stages:
                raise _error(400, "INVALID_STAGE", "stage not enabled for this profile")
            decision = await orchestrator.handle(profile, ctx)
            kept = []
            for mod in decision.modifications:
                try:
                    codec.encode_response(replace(decision, modifications=(mod,)), ctx)
                except (ValueError, KeyError, IndexError, TypeError) as exc:
                    app.state.bus.publish(
                        ModificationRejected(
                            ctx.trace_id, profile.name, ctx.stage.value, "stalwart", str(exc)
                        )
                    )
                else:
                    kept.append(mod)
            try:
                encoded = codec.encode_response(replace(decision, modifications=tuple(kept)), ctx)
            except (ValueError, KeyError, IndexError, TypeError):
                encoded = codec.encode_response(replace(decision, modifications=()), ctx)
            return _dump_json(encoded)
        finally:
            if isinstance(message, MessageBody):
                message.close()

    app.add_api_route(
        profile.path, _handler, methods=["POST"], name=f"stalwart-hook-{profile.name}"
    )


def _register_mta01_routes(
    app: FastAPI,
    profile: HookProfile,
    orchestrator: HookOrchestrator,
    codec: Mta01Codec,
    registration_store: RegistrationStore,
    config: AppConfig,
) -> None:
    security = HTTPBearer(auto_error=False)
    discovery_path = f"{profile.path}/.well-known/mta-hooks"
    register_path = f"{profile.path}/register"
    hook_path = f"{profile.path}/mta01"

    async def _discover() -> Response:
        return _dump_json(_discovery(profile))

    async def _register(
        request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(security)
    ) -> Response:
        _check_bearer_token(credentials, profile.token)
        payload = await _read_payload(request)
        try:
            registration_request = RegistrationRequest.model_validate(payload)
            capabilities = negotiate(registration_request, profile)
        except (ValidationError, ValueError) as exc:
            raise _error(400, "CAPABILITY_MISMATCH", "unsupported or invalid registration") from exc
        registration = registration_store.register(profile.name, hook_path, capabilities)
        return _dump_json(
            {
                "registrationId": registration.registration_id,
                "hookEndpoint": registration.hook_endpoint,
                "status": "active",
                "createdAt": registration.created_at.isoformat().replace("+00:00", "Z"),
                "expiresAt": None,
                "negotiated": registration.capabilities,
                "endpoints": {
                    "deregistration": f"{register_path}/{registration.registration_id}",
                    "status": f"{register_path}/{registration.registration_id}/status",
                },
            },
            status_code=201,
            headers={"Location": f"{register_path}/{registration.registration_id}"},
        )

    async def _deregister(
        registration_id: str, credentials: HTTPAuthorizationCredentials | None = Depends(security)
    ) -> Response:
        _check_bearer_token(credentials, profile.token)
        _registration_for_profile(registration_store, registration_id, profile)
        if not registration_store.deregister(registration_id):
            raise RegistrationNotFoundError(registration_id)
        return _dump_json(
            {
                "registrationId": registration_id,
                "status": "deregistered",
                "deregisteredAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        )

    async def _status(
        registration_id: str, credentials: HTTPAuthorizationCredentials | None = Depends(security)
    ) -> Response:
        _check_bearer_token(credentials, profile.token)
        registration = _registration_for_profile(registration_store, registration_id, profile)
        return _dump_json(
            {
                "registrationId": registration_id,
                "status": "active",
                "createdAt": registration.created_at.isoformat().replace("+00:00", "Z"),
                "expiresAt": None,
                "lastInvocation": None,
            }
        )

    async def _hook(
        request: Request,
        x_mta_hooks_registration: str = Header(default="", alias="X-MTA-Hooks-Registration"),
        x_mta_hooks_request_id: str = Header(default="", alias="X-MTA-Hooks-Request-Id"),
        credentials: HTTPAuthorizationCredentials | None = Depends(security),
    ) -> Response:
        _check_bearer_token(credentials, profile.token)
        registration = _registration_for_profile(
            registration_store, x_mta_hooks_registration, profile
        )
        if not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", x_mta_hooks_request_id):
            raise _error(400, "MISSING_REQUEST_ID", "a valid X-MTA-Hooks-Request-Id is required")
        payload = await _read_payload(request)
        if "properties" in payload or "action" not in payload:
            raise _error(400, "INVALID_REQUEST", "use the literal draft hook structure")
        try:
            ctx = codec.decode_request(payload, spool_threshold_mb=config.body_spool_threshold_mb)
        except (ValueError, KeyError, TypeError) as exc:
            raise _error(400, "INVALID_REQUEST", "invalid draft hook payload") from exc

        message = ctx.properties.get("message")
        try:
            stages = {
                stage
                for direction in ("inbound", "outbound")
                for stage in (registration.capabilities.get(direction) or {}).get("stages", [])
            }
            if ctx.stage.value not in stages:
                raise _error(400, "INVALID_STAGE", "stage was not negotiated")
            ctx = replace(ctx, trace_id=x_mta_hooks_request_id)
            decision = await orchestrator.handle(profile, ctx)
            if ctx.stage in OUTBOUND_STAGES and decision.response is not None:
                raise _error(503, "SCANNER_UNAVAILABLE", "scan engine unavailable")
            return _dump_json(codec.encode_response(decision))
        finally:
            if isinstance(message, MessageBody):
                message.close()

    app.add_api_route(
        discovery_path, _discover, methods=["GET"], name=f"mta01-discovery-{profile.name}"
    )
    app.add_api_route(
        register_path,
        _register,
        methods=["POST"],
        status_code=201,
        name=f"mta01-register-{profile.name}",
    )
    app.add_api_route(
        register_path + "/{registration_id}",
        _deregister,
        methods=["DELETE"],
        name=f"mta01-deregister-{profile.name}",
    )
    app.add_api_route(hook_path, _hook, methods=["POST"], name=f"mta01-hook-{profile.name}")
    app.add_api_route(
        register_path + "/{registration_id}/status",
        _status,
        methods=["GET"],
        name=f"mta01-status-{profile.name}",
    )
