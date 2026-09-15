"""Shared JSON/JSONC and atomic file-writing helpers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .domain import JsonObject
from .errors import PolicyError
from .json_boundary import decode_jsonc


def read_json(path: Path) -> JsonObject:
    if not path.exists():
        return {}
    try:
        narrowed = decode_jsonc(path.read_text())
    except Exception as error:
        raise PolicyError(f"{path}: {error}") from error
    return narrowed if isinstance(narrowed, dict) else {}


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent)) as handle:
        handle.write(text)
        tmp_path = Path(handle.name)
    os.chmod(tmp_path, 0o600)
    tmp_path.replace(path)
