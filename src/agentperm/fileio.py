"""Shared JSON/JSONC and atomic file-writing helpers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pyjson5

from .domain import JsonObject, narrow_json
from .errors import PolicyError


def read_json(path: Path) -> JsonObject:
    if not path.exists():
        return {}
    try:
        decoded: object = pyjson5.decode(path.read_text())
    except Exception as error:
        raise PolicyError(f"{path}: {error}") from error
    narrowed = narrow_json(decoded)
    return narrowed if isinstance(narrowed, dict) else {}


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent)) as handle:
        handle.write(text)
        tmp_path = Path(handle.name)
    os.chmod(tmp_path, 0o600)
    tmp_path.replace(path)
