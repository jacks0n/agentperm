"""Validate unknown decoder output before exposing the JSON value model."""

import json
from collections.abc import Callable

import pyjson5

from .domain import JsonValue, narrow_json

# Decoder libraries accept richer options, but this boundary only accepts text.
# Their output is deliberately unknown until recursively validated below.
_json_decoder: Callable[[str], object] = json.loads
_jsonc_decoder: Callable[[str], object] = pyjson5.decode


def decode_json(source: str) -> JsonValue:
    return narrow_json(_json_decoder(source))


def decode_jsonc(source: str) -> JsonValue:
    return narrow_json(_jsonc_decoder(source))
