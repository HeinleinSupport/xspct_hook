# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""YAML -> Pydantic config models, profile construction, and ``depends_on`` validation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from xspct_hook.profiles import HookProfile
from xspct_hook.protocol.models import Stage
from xspct_hook.registry import build_adapter, build_strategy

logger = logging.getLogger(__name__)


class AdapterConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str


class ProfileConfig(BaseModel):
    name: str = Field(min_length=1)
    path: str = Field(pattern=r"^/[^{}?#]*[^/]$")
    token: str = Field(min_length=1)
    stages: list[str] = Field(min_length=1)
    strategy: str = "first_reject_wins"
    on_adapter_error: Literal["fail_open", "fail_closed"] = "fail_open"
    adapter_timeout: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    overall_timeout: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    depends_on: list[str] = Field(default_factory=list)
    adapters: list[AdapterConfig] = Field(min_length=1)

    @field_validator("stages")
    @classmethod
    def _validate_stages(cls, value: list[str]) -> list[str]:
        for stage in value:
            Stage(stage)
        return value


class AppConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    body_spool_threshold_mb: float = Field(default=10.0, ge=0, allow_inf_nan=False)
    jsonl_log_path: str = "xspct_hook-events.jsonl"
    adapter_timeout: float = Field(default=10.0, gt=0, allow_inf_nan=False)
    overall_timeout: float = Field(default=30.0, gt=0, allow_inf_nan=False)
    profiles: list[ProfileConfig] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_routes(self) -> AppConfig:
        names = [profile.name for profile in self.profiles]
        if len(set(names)) != len(names):
            raise ValueError("profile names must be unique")
        routes = {"/.well-known/mta-hooks"}
        for profile in self.profiles:
            paths = {
                profile.path,
                f"{profile.path}/register",
                f"{profile.path}/mta01",
                f"{profile.path}/.well-known/mta-hooks",
            }
            if routes & paths or any(
                profile.path.startswith(f"{other.path}/register/")
                for other in self.profiles
                if other is not profile
            ):
                raise ValueError("profile routes must not collide")
            routes.update(paths)
        return self


def load_config(path: str | Path) -> AppConfig:
    with open(path, encoding="utf-8") as handle:
        data: dict[str, Any] = yaml.safe_load(handle) or {}
    return AppConfig.model_validate(data)


def build_profiles(config: AppConfig) -> list[HookProfile]:
    profiles = [_build_profile(profile_cfg, config) for profile_cfg in config.profiles]
    _warn_on_stage_overlaps(profiles)
    return profiles


def _build_profile(profile_cfg: ProfileConfig, config: AppConfig) -> HookProfile:
    return HookProfile(
        name=profile_cfg.name,
        path=profile_cfg.path,
        stages=frozenset(Stage(s) for s in profile_cfg.stages),
        token=profile_cfg.token,
        adapters=[
            build_adapter(a.type, a.model_dump(exclude={"type"})) for a in profile_cfg.adapters
        ],
        strategy=build_strategy(profile_cfg.strategy),
        on_adapter_error=profile_cfg.on_adapter_error,
        adapter_timeout=profile_cfg.adapter_timeout or config.adapter_timeout,
        overall_timeout=profile_cfg.overall_timeout or config.overall_timeout,
        depends_on=tuple(profile_cfg.depends_on),
    )


def _warn_on_stage_overlaps(profiles: list[HookProfile]) -> None:
    by_name = {profile.name: profile for profile in profiles}
    for profile in profiles:
        for dep_name in profile.depends_on:
            dependency = by_name.get(dep_name)
            if dependency is None:
                logger.warning(
                    "profile %r declares depends_on %r, which does not exist",
                    profile.name,
                    dep_name,
                )
                continue
            if not (profile.stages & dependency.stages):
                logger.warning(
                    "profile %r declares depends_on %r, but they share no stages (dependency has no effect)",
                    profile.name,
                    dep_name,
                )
            else:
                logger.warning(
                    "profile %r depends on %r at shared stages; independent HTTP hooks have no guaranteed order or context transfer",
                    profile.name,
                    dep_name,
                )
