"""Checked JSON traversal for assertions against external hook contracts."""

from collections.abc import Mapping, Sequence

from agentperm.domain import JsonObject, JsonValue
from agentperm.json_boundary import decode_json


def decode_object(source: str) -> JsonObject:
    value = decode_json(source)
    assert isinstance(value, dict), "expected a JSON object"
    return value


def object_at(value: JsonValue, *path: str | int) -> JsonObject:
    found = json_at(value, *path)
    assert isinstance(found, dict), f"expected an object at {path!r}"
    return found


def array_at(value: JsonValue, *path: str | int) -> list[JsonValue]:
    found = json_at(value, *path)
    assert isinstance(found, list), f"expected an array at {path!r}"
    return found


def text_at(value: JsonValue, *path: str | int) -> str:
    found = json_at(value, *path)
    assert isinstance(found, str), f"expected text at {path!r}"
    return found


def json_at(value: JsonValue, *path: str | int) -> JsonValue:
    for key in path:
        if isinstance(key, str):
            assert isinstance(value, Mapping), f"expected an object at {key!r}"
            value = value[key]
        else:
            assert isinstance(value, Sequence) and not isinstance(value, str), "expected an array"
            value = value[key]
    return value
