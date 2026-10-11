# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Unit tests for registration.py: RegistrationStore."""

from __future__ import annotations

from xspct_hook.registration import RegistrationStore


def test_register_returns_registration_with_fields() -> None:
    store = RegistrationStore()
    registration = store.register("pseudo-test", "/hooks/pseudo-test/mta01", {"stages": ["mail"]})
    assert registration.profile_name == "pseudo-test"
    assert registration.hook_endpoint == "/hooks/pseudo-test/mta01"
    assert registration.capabilities == {"stages": ["mail"]}
    assert registration.registration_id


def test_get_returns_registered_entry() -> None:
    store = RegistrationStore()
    registration = store.register("p", "/h", {})
    assert store.get(registration.registration_id) is registration


def test_get_returns_none_for_unknown_id() -> None:
    store = RegistrationStore()
    assert store.get("nope") is None


def test_deregister_removes_entry_and_returns_true() -> None:
    store = RegistrationStore()
    registration = store.register("p", "/h", {})
    assert store.deregister(registration.registration_id) is True
    assert store.get(registration.registration_id) is None


def test_deregister_unknown_id_returns_false() -> None:
    store = RegistrationStore()
    assert store.deregister("nope") is False


def test_registration_ids_are_unique() -> None:
    store = RegistrationStore()
    first = store.register("p", "/h", {})
    second = store.register("p", "/h", {})
    assert first.registration_id != second.registration_id
