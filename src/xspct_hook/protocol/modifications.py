# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""JSON-Pointer based message/envelope modifications, with body-rewrite and header-injection guards."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

from xspct_hook.exceptions import BodyRewriteRejected, HeaderInjectionRejected


@dataclass(frozen=True)
class SetOperation:
    path: str
    value: Any


@dataclass(frozen=True)
class AddOperation:
    path: str
    value: Any
    index: int | None = None


@dataclass(frozen=True)
class DeleteOperation:
    path: str


Modification = SetOperation | AddOperation | DeleteOperation

#: Modifying the whole message body is never allowed — this PoC does not rewrite content.
_BODY_PATHS = frozenset({"/message", "/rawMessage"})
_HEADER_PATH_RE = re.compile(r"^/message/headers(?:/(-|\d+)(?:/(name|value))?)?$")
_CRLF_RE = re.compile(r"[\r\n]")


def validate_modification(mod: Modification) -> None:
    """Raise if ``mod`` would rewrite the message body or inject a header CR/LF."""
    if not isinstance(mod, (SetOperation, AddOperation, DeleteOperation)):
        raise TypeError("unknown modification type")
    _split_pointer(mod.path)
    if mod.path in _BODY_PATHS or mod.path.startswith("/rawMessage/"):
        raise BodyRewriteRejected(mod.path)
    if mod.path.startswith("/message/") and not _HEADER_PATH_RE.fullmatch(mod.path):
        raise BodyRewriteRejected(mod.path)
    if (
        isinstance(mod, AddOperation)
        and mod.index is not None
        and (type(mod.index) is not int or mod.index < 0)
    ):
        raise ValueError("array insertion index must be a nonnegative integer")
    if isinstance(mod, DeleteOperation):
        return
    match = _HEADER_PATH_RE.fullmatch(mod.path)
    if match:
        if match.group(2):
            _validate_header_text(mod.value, name=match.group(2) == "name")
        elif mod.path == "/message/headers" and isinstance(mod, SetOperation):
            if not isinstance(mod.value, list):
                raise ValueError("headers must be an array")
            for header in mod.value:
                _validate_header_value(header)
        else:
            _validate_header_value(mod.value)


def _validate_header_value(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"name", "value"}:
        raise ValueError("header must contain string name and value fields")
    _validate_header_text(value["name"], name=True)
    _validate_header_text(value["value"], name=False)


def _validate_header_text(value: Any, *, name: bool) -> None:
    if not isinstance(value, str):
        raise TypeError("header fields must be strings")
    if _CRLF_RE.search(value):
        raise HeaderInjectionRejected(value)
    if name and not re.fullmatch(r"[!-9;-~]+", value):
        raise ValueError("invalid header name")


def apply_modifications(
    document: dict[str, Any], modifications: list[Modification]
) -> dict[str, Any]:
    """Apply a sequence of JSON-Pointer modifications to a deep copy of ``document``."""
    result = copy.deepcopy(document)
    ordered = sorted(
        modifications,
        key=lambda mod: (
            0 if isinstance(mod, SetOperation) else 1 if isinstance(mod, AddOperation) else 2
        ),
    )
    for mod in ordered:
        validate_modification(mod)
        if isinstance(mod, AddOperation):
            _add(result, mod.path, mod.value, mod.index)
        elif isinstance(mod, SetOperation):
            _set(result, mod.path, mod.value)
        elif isinstance(mod, DeleteOperation):
            _delete(result, mod.path)
    return result


def _split_pointer(path: str) -> list[str]:
    if not isinstance(path, str) or not path.startswith("/") or re.search(r"~(?:[^01]|$)", path):
        raise ValueError(f"invalid JSON pointer: {path!r}")
    return [token.replace("~1", "/").replace("~0", "~") for token in path.split("/")[1:]]


def _resolve_parent(document: dict[str, Any], tokens: list[str]) -> tuple[Any, str]:
    node: Any = document
    for token in tokens[:-1]:
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node, tokens[-1]


def _add(document: dict[str, Any], path: str, value: Any, index: int | None = None) -> None:
    parent, last = _resolve_parent(document, _split_pointer(path))
    if isinstance(parent, dict) and isinstance(parent.get(last), list):
        target = parent[last]
        position = len(target) if index is None else index
        if position > len(target):
            raise ValueError("array insertion index out of range")
        target.insert(position, value)
        return
    if isinstance(parent, list):
        position = len(parent) if last == "-" else int(last)
        if position < 0 or position > len(parent):
            raise ValueError("array insertion index out of range")
        parent.insert(position, value)
    else:
        parent[last] = value


def _set(document: dict[str, Any], path: str, value: Any) -> None:
    parent, last = _resolve_parent(document, _split_pointer(path))
    if isinstance(parent, list):
        parent[int(last)] = value
    else:
        parent[last] = value


def _delete(document: dict[str, Any], path: str) -> None:
    parent, last = _resolve_parent(document, _split_pointer(path))
    if isinstance(parent, list):
        del parent[int(last)]
    else:
        del parent[last]
