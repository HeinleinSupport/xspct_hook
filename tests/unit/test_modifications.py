# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for protocol/modifications.py."""

from __future__ import annotations

import pytest

from xspct_hook.exceptions import BodyRewriteRejected, HeaderInjectionRejected
from xspct_hook.protocol.modifications import (
    AddOperation,
    DeleteOperation,
    SetOperation,
    apply_modifications,
    validate_modification,
)


def test_body_rewrite_rejected_for_message_path() -> None:
    with pytest.raises(BodyRewriteRejected):
        validate_modification(SetOperation("/message", "new body"))


def test_body_rewrite_rejected_for_raw_message_path() -> None:
    with pytest.raises(BodyRewriteRejected):
        validate_modification(SetOperation("/rawMessage", "new body"))


def test_header_add_is_allowed() -> None:
    validate_modification(AddOperation("/message/headers/-", {"name": "X-Test", "value": "ok"}))


def test_header_injection_rejected_in_name() -> None:
    with pytest.raises(HeaderInjectionRejected):
        validate_modification(
            AddOperation("/message/headers/-", {"name": "X-Test\r\nEvil: 1", "value": "ok"})
        )


def test_header_injection_rejected_in_value() -> None:
    with pytest.raises(HeaderInjectionRejected):
        validate_modification(
            AddOperation("/message/headers/-", {"name": "X-Test", "value": "ok\r\nEvil: 1"})
        )


def test_delete_operation_skips_value_validation() -> None:
    validate_modification(DeleteOperation("/message/headers/0"))


def test_apply_add_append() -> None:
    doc = {"headers": [["Subject", "hi"]]}
    result = apply_modifications(doc, [AddOperation("/headers/-", ["X-New", "v"])])
    assert result["headers"] == [["Subject", "hi"], ["X-New", "v"]]
    assert doc["headers"] == [["Subject", "hi"]]  # original untouched


def test_apply_add_insert_at_index() -> None:
    doc = {"headers": [["A", "1"], ["B", "2"]]}
    result = apply_modifications(doc, [AddOperation("/headers/0", ["X", "0"])])
    assert result["headers"] == [["X", "0"], ["A", "1"], ["B", "2"]]


def test_apply_set_replaces_value() -> None:
    doc = {"headers": [["Subject", "old"]]}
    result = apply_modifications(doc, [SetOperation("/headers/0", ["Subject", "new"])])
    assert result["headers"] == [["Subject", "new"]]


def test_apply_delete_removes_entry() -> None:
    doc = {"headers": [["A", "1"], ["B", "2"]]}
    result = apply_modifications(doc, [DeleteOperation("/headers/0")])
    assert result["headers"] == [["B", "2"]]


def test_apply_modifications_rejects_body_rewrite() -> None:
    with pytest.raises(BodyRewriteRejected):
        apply_modifications({"message": "x"}, [SetOperation("/message", "y")])


@pytest.mark.parametrize("path", ["/message/headers/0/value", "/message/headers/0/name"])
def test_nested_header_injection_rejected(path: str) -> None:
    with pytest.raises(HeaderInjectionRejected):
        validate_modification(SetOperation(path, "bad\r\nInjected: yes"))


def test_array_header_injection_rejected() -> None:
    with pytest.raises(HeaderInjectionRejected):
        validate_modification(
            AddOperation("/message/headers", {"name": "X-Test", "value": "bad\nInjected: yes"})
        )


@pytest.mark.parametrize(
    "value",
    [{"name": "X-Test"}, {"name": "X-Test", "value": 3}, {"name": "Bad:Name", "value": "ok"}],
)
def test_malformed_header_rejected(value: object) -> None:
    with pytest.raises((ValueError, TypeError)):
        validate_modification(AddOperation("/message/headers/-", value))


def test_draft_array_insertion() -> None:
    header = {"name": "X-Test", "value": "ok"}
    document = {"message": {"headers": []}}
    result = apply_modifications(document, [AddOperation("/message/headers", header, index=0)])
    assert result["message"]["headers"] == [header]
