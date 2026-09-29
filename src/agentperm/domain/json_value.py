"""Typed JSON values shared across agentperm's system boundaries."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TypeGuard

from ..errors import PolicyError

type JsonScalar = str | int | float | bool | None
# Sequence/Mapping (covariant) — so list[str] ⊆ JsonValue without dict-invariance grief.
type JsonValue = JsonScalar | Sequence["JsonValue"] | Mapping[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]
type JsonArray = list[JsonValue]


def object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def object_dict(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def narrow_json(value: object) -> JsonValue:
    """Convert decoded JSON into a typed value, rejecting non-JSON objects."""
    if value is None:
        return None
    if isinstance(value, bool):  # check before int — bool is a subclass of int
        return value
    if isinstance(value, (str, int, float)):
        return value
    if object_list(value):
        return [narrow_json(item) for item in value]
    if object_dict(value):
        result: JsonObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise PolicyError(f"non-string JSON key: {key!r}")
            result[key] = narrow_json(item)
        return result
    raise PolicyError(f"unsupported JSON value: {type(value).__name__}")
