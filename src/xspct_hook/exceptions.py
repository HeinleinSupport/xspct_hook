# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Domain-specific exceptions shared across the protocol, wire, and adapter layers."""

from __future__ import annotations


class XspctHookError(Exception):
    """Base class for all xspct_hook domain errors."""


class PropertyNotProvidedError(XspctHookError):
    """Raised by ``HookContext.property()`` when the named property was not supplied."""

    def __init__(self, name: str) -> None:
        super().__init__(f"property {name!r} was not provided for this hook context")
        self.name = name


class UnsupportedActionError(XspctHookError):
    """Raised when an adapter returns an action outside its declared ``supported_actions``."""

    def __init__(self, action: str, adapter: str) -> None:
        super().__init__(f"action {action!r} is not supported by adapter {adapter!r}")
        self.action = action
        self.adapter = adapter


class BodyRewriteRejected(XspctHookError):
    """Raised when a modification targets the full message body, which this PoC never rewrites."""

    def __init__(self, path: str) -> None:
        super().__init__(
            f"modification targeting {path!r} would rewrite the message body; rejected"
        )
        self.path = path


class HeaderInjectionRejected(XspctHookError):
    """Raised when a header name/value modification contains a raw CR or LF."""

    def __init__(self, value: str) -> None:
        super().__init__(f"header name/value {value!r} contains CR/LF and was rejected")
        self.value = value


class RegistrationNotFoundError(XspctHookError):
    """Raised when a native -01 request references an unknown registration id."""

    def __init__(self, registration_id: str) -> None:
        super().__init__(f"registration {registration_id!r} not found")
        self.registration_id = registration_id
