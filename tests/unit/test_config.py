# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for config.py: load_config/build_profiles/_warn_on_stage_overlaps."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from xspct_hook.adapters.pseudo import PseudoScannerAdapter
from xspct_hook.aggregation import FirstRejectWins
from xspct_hook.config import AppConfig, build_profiles, load_config
from xspct_hook.protocol.models import Stage

_SAMPLE_CONFIG = """
host: 127.0.0.1
port: 9000
profiles:
  - name: pseudo-test
    path: /hooks/pseudo-test
    token: tok
    stages: [mail, rcpt]
    strategy: first_reject_wins
    adapters:
      - type: pseudo
        default_scenario: clean
"""


def test_load_config_parses_yaml(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(_SAMPLE_CONFIG)
    config = load_config(config_path)
    assert config.port == 9000
    assert len(config.profiles) == 1
    assert config.profiles[0].name == "pseudo-test"


def test_config_refuses_unreachable_auth_subscription(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(_SAMPLE_CONFIG.replace("[mail, rcpt]", "[auth]"))
    with pytest.raises(ValueError, match="auth is not supported"):
        load_config(config_path)


def test_build_profiles_constructs_hook_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(_SAMPLE_CONFIG)
    config = load_config(config_path)
    profiles = build_profiles(config)
    assert len(profiles) == 1
    profile = profiles[0]
    assert profile.name == "pseudo-test"
    assert profile.stages == frozenset({Stage.MAIL, Stage.RCPT})
    assert isinstance(profile.adapters[0], PseudoScannerAdapter)
    assert isinstance(profile.strategy, FirstRejectWins)


def test_build_profiles_uses_config_level_timeouts_as_default() -> None:
    config = AppConfig.model_validate(
        {
            "adapter_timeout": 7,
            "overall_timeout": 21,
            "profiles": [
                {
                    "name": "p",
                    "path": "/hooks/p",
                    "token": "t",
                    "stages": ["mail"],
                    "adapters": [{"type": "pseudo"}],
                }
            ],
        }
    )
    profile = build_profiles(config)[0]
    assert profile.adapter_timeout == 7
    assert profile.overall_timeout == 21


def test_warn_on_stage_overlaps_logs_when_depends_on_missing(caplog) -> None:
    config = AppConfig.model_validate(
        {
            "profiles": [
                {
                    "name": "p",
                    "path": "/hooks/p",
                    "token": "t",
                    "stages": ["mail"],
                    "depends_on": ["nonexistent"],
                    "adapters": [{"type": "pseudo"}],
                }
            ],
        }
    )
    with caplog.at_level(logging.WARNING):
        build_profiles(config)
    assert any("does not exist" in record.message for record in caplog.records)


def test_warn_on_stage_overlaps_logs_when_stages_disjoint(caplog) -> None:
    config = AppConfig.model_validate(
        {
            "profiles": [
                {
                    "name": "a",
                    "path": "/hooks/a",
                    "token": "t",
                    "stages": ["mail"],
                    "depends_on": ["b"],
                    "adapters": [{"type": "pseudo"}],
                },
                {
                    "name": "b",
                    "path": "/hooks/b",
                    "token": "t",
                    "stages": ["data"],
                    "adapters": [{"type": "pseudo"}],
                },
            ],
        }
    )
    with caplog.at_level(logging.WARNING):
        build_profiles(config)
    assert any("share no stages" in record.message for record in caplog.records)


def test_shared_stage_dependency_warns_about_order(caplog) -> None:
    config = AppConfig.model_validate(
        {
            "profiles": [
                {
                    "name": "a",
                    "path": "/hooks/a",
                    "token": "t",
                    "stages": ["data"],
                    "depends_on": ["b"],
                    "adapters": [{"type": "pseudo"}],
                },
                {
                    "name": "b",
                    "path": "/hooks/b",
                    "token": "t",
                    "stages": ["data"],
                    "adapters": [{"type": "pseudo"}],
                },
            ]
        }
    )
    with caplog.at_level(logging.WARNING):
        build_profiles(config)
    assert any("no guaranteed order" in record.message for record in caplog.records)
