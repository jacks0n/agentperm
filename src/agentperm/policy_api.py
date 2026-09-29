"""Reviewable, compare-and-swap policy changes for JSON API clients."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import secrets
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .config import POLICY_FILENAME, POLICY_VERSION
from .domain import JsonObject, JsonValue
from .errors import PolicyError
from .fileio import atomic_write
from .json_boundary import decode_json
from .policy import git_toplevel, policy_layers
from .policy_edit import (
    AddPermissionRule,
    PermissionDecision,
    PermissionEdit,
    RemovePermissionRule,
    ReplacePermissionRule,
    edit_permission_rules,
)
from .validate import validate_policy_text

_PLAN_VERSION = 1
_PLAN_TTL_SECONDS = 60 * 60


@dataclass(frozen=True)
class PolicyTarget:
    id: str
    path: Path
    scope: Literal["global", "project"]
    contexts: tuple[Path, ...]
    exists: bool

    def to_json(self) -> JsonObject:
        return {
            "id": self.id,
            "path": str(self.path),
            "scope": self.scope,
            "contexts": [str(context) for context in self.contexts],
            "exists": self.exists,
        }


def policy_source_id(path: Path) -> str:
    identity = path.expanduser().absolute().resolve(strict=False)
    digest = hashlib.sha256(str(identity).encode()).hexdigest()
    return f"policy-source-v1-{digest}"


def discover_policy_targets(contexts: list[Path]) -> tuple[PolicyTarget, ...]:
    """Return backend-issued editable targets for supplied runtime contexts."""
    home = Path.home().resolve()
    global_root = home / POLICY_FILENAME
    by_path: dict[Path, PolicyTarget] = {}

    def add(path: Path, scope: Literal["global", "project"], context: Path) -> None:
        absolute = path.expanduser().absolute()
        identity = absolute.resolve(strict=False)
        existing = by_path.get(identity)
        if existing is None:
            by_path[identity] = PolicyTarget(
                id=policy_source_id(identity),
                path=identity,
                scope=scope,
                contexts=(context,),
                exists=absolute.exists(),
            )
        else:
            contexts = tuple(dict.fromkeys((*existing.contexts, context)))
            by_path[identity] = PolicyTarget(
                id=existing.id,
                path=existing.path,
                scope="global" if existing.scope == "global" or scope == "global" else "project",
                contexts=contexts,
                exists=existing.exists,
            )

    add(global_root, "global", home)
    for context in contexts:
        resolved = context.expanduser().resolve()
        if not resolved.is_dir():
            raise PolicyError(f"context is not a directory: {context}")
        project_root = git_toplevel(resolved)
        if project_root is not None:
            add(project_root / POLICY_FILENAME, "project", project_root)
        for layer in policy_layers(cwd=resolved):
            is_global = layer.root.resolve(strict=False) == global_root.resolve(strict=False)
            scope: Literal["global", "project"] = "global" if is_global else "project"
            for source in layer.sources:
                add(source, scope, resolved)
    return tuple(sorted(by_path.values(), key=lambda target: (target.scope, str(target.path))))


def create_policy_plan(contexts: list[Path], files: JsonValue) -> JsonObject:
    """Build and persist an exact-byte plan without modifying a policy file."""
    if not isinstance(files, list) or not files:
        raise PolicyError("files must be a non-empty array")
    targets = {target.id: target for target in discover_policy_targets(contexts)}
    planned_files: list[JsonObject] = []
    seen: set[str] = set()
    for raw_file in files:
        if not isinstance(raw_file, dict):
            raise PolicyError("each files entry must be an object")
        target_id = raw_file.get("target_id")
        raw_edits = raw_file.get("edits")
        if not isinstance(target_id, str) or target_id not in targets:
            raise PolicyError("target_id is not editable for the supplied contexts")
        if target_id in seen:
            raise PolicyError(f"duplicate target_id: {target_id}")
        seen.add(target_id)
        if not isinstance(raw_edits, list) or not raw_edits:
            raise PolicyError("edits must be a non-empty array")
        target = targets[target_id]
        before = _read_text_exact(target.path) if target.path.exists() else None
        source = before if before is not None else _new_policy_text()
        edits = [_parse_edit(edit) for edit in raw_edits]
        after = edit_permission_rules(source, edits)
        _validate_planned_policy(after, str(target.path))
        if after == source and before is not None:
            continue
        planned_files.append(
            {
                "target_id": target.id,
                "path": str(target.path),
                "before": before,
                "after": after,
                "before_hash": _text_hash(before),
                "after_hash": _text_hash(after),
                "diff": _unified_diff(before or "", after, str(target.path)),
            }
        )
    if not planned_files:
        raise PolicyError("the requested edits do not change any policy file")

    plan_id = secrets.token_urlsafe(24)
    created_at = int(time.time())
    document: JsonObject = {
        "plan_version": _PLAN_VERSION,
        "kind": "apply",
        "plan_id": plan_id,
        "created_at": created_at,
        "expires_at": created_at + _PLAN_TTL_SECONDS,
        "files": planned_files,
    }
    _write_plan(document)
    return _public_plan(document)


def apply_policy_plan(plan_id: str) -> JsonObject:
    """Apply one reviewed plan exactly, or leave every target unchanged."""
    plan = _read_plan(plan_id, expected_kind="apply")
    files = _plan_files(plan)
    _assert_current(files, side="before")
    undo_id = secrets.token_urlsafe(24)
    created_at = int(time.time())
    undo: JsonObject = {
        "plan_version": _PLAN_VERSION,
        "kind": "undo",
        "plan_id": undo_id,
        "created_at": created_at,
        "expires_at": created_at + _PLAN_TTL_SECONDS,
        "files": files,
    }
    # Persist recovery metadata before touching any policy. A cache failure must
    # never apply changes without giving the client a usable undo identity.
    _write_plan(undo)
    written: list[JsonObject] = []
    try:
        for item in files:
            path = Path(_required_string(item, "path"))
            atomic_write(path, _required_string(item, "after"))
            written.append(item)
        for item in files:
            path = Path(_required_string(item, "path"))
            _validate_planned_policy(_read_text_exact(path), str(path))
    except Exception as apply_error:
        try:
            _restore_before(written)
        except Exception as rollback_error:
            raise PolicyError(
                f"policy apply failed ({apply_error}) and rollback also failed ({rollback_error}); "
                f"recovery plan retained as {undo_id}"
            ) from rollback_error
        with suppress(OSError):
            _delete_plan(undo_id)
        raise
    with suppress(OSError):
        _delete_plan(plan_id)
    return {"applied_files": len(files), "undo_id": undo_id}


def undo_policy_plan(plan_id: str) -> JsonObject:
    """Restore exact pre-apply bytes if files still match the applied plan."""
    plan = _read_plan(plan_id, expected_kind="undo")
    files = _plan_files(plan)
    _assert_current(files, side="after")
    _restore_before(files)
    with suppress(OSError):
        _delete_plan(plan_id)
    return {"restored_files": len(files)}


def _parse_edit(value: JsonValue) -> PermissionEdit:
    if not isinstance(value, dict):
        raise PolicyError("each edit must be an object")
    action = value.get("action")
    decision = _decision(value.get("decision"))
    if "rule" not in value:
        raise PolicyError("edit rule is required")
    rule = value["rule"]
    if action == "add" and set(value) == {"action", "decision", "rule"}:
        return AddPermissionRule(decision, rule)
    if action == "remove" and set(value) == {"action", "decision", "rule"}:
        return RemovePermissionRule(decision, rule)
    if action == "replace" and set(value) == {"action", "decision", "rule", "old_rule"}:
        return ReplacePermissionRule(decision, value["old_rule"], rule)
    raise PolicyError(f"invalid {action!r} edit fields")


def _decision(value: JsonValue | None) -> PermissionDecision:
    if value == "allow":
        return "allow"
    if value == "ask":
        return "ask"
    if value == "deny":
        return "deny"
    raise PolicyError("edit decision must be allow, ask, or deny")


def _validate_planned_policy(text: str, path: str) -> None:
    findings = validate_policy_text(text)
    blocking = [
        finding
        for finding in findings
        if finding.severity == "error" or finding.message.startswith("unsupported version ")
    ]
    if blocking:
        detail = "; ".join(finding.message for finding in blocking)
        raise PolicyError(f"{path}: proposed policy is invalid: {detail}")


def _new_policy_text() -> str:
    return json.dumps({"version": POLICY_VERSION, "permissions": {}}, indent=2) + "\n"


def _unified_diff(before: str, after: str, path: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=path,
            tofile=path,
        )
    )


def _text_hash(value: str | None) -> str | None:
    return None if value is None else hashlib.sha256(value.encode()).hexdigest()


def _read_text_exact(path: Path) -> str:
    """Decode UTF-8 without universal-newline normalization."""
    return path.read_bytes().decode("utf-8")


def _plan_directory() -> Path:
    override = os.environ.get("AGENTPERM_PLAN_DIR")
    if override:
        return Path(override).expanduser().absolute()
    cache = os.environ.get("XDG_CACHE_HOME")
    root = Path(cache).expanduser() if cache else Path.home() / ".cache"
    return root / "agentperm" / "plans"


def _plan_path(plan_id: str) -> Path:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if not plan_id or any(character not in allowed for character in plan_id):
        raise PolicyError("invalid plan_id")
    return _plan_directory() / f"{plan_id}.json"


def _write_plan(plan: JsonObject) -> None:
    directory = _plan_directory()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    _remove_expired_plans(directory)
    path = _plan_path(_required_string(plan, "plan_id"))
    atomic_write(path, json.dumps(plan, separators=(",", ":")))


def _remove_expired_plans(directory: Path) -> None:
    now = int(time.time())
    for path in directory.glob("*.json"):
        try:
            value = decode_json(_read_text_exact(path))
            if isinstance(value, dict):
                expires_at = value.get("expires_at")
                if type(expires_at) is int and expires_at < now:
                    path.unlink()
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
            continue


def _read_plan(plan_id: str, *, expected_kind: str) -> JsonObject:
    try:
        value = decode_json(_plan_path(plan_id).read_text())
    except FileNotFoundError as error:
        raise PolicyError("plan not found or already used") from error
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"could not read plan: {error}") from error
    if not isinstance(value, dict) or value.get("plan_version") != _PLAN_VERSION:
        raise PolicyError("unsupported or corrupt plan")
    if value.get("kind") != expected_kind:
        raise PolicyError(f"plan cannot be used for {expected_kind}")
    expires_at = _required_integer(value, "expires_at")
    if expires_at < int(time.time()):
        _delete_plan(plan_id)
        raise PolicyError("plan expired")
    return dict(value)


def _public_plan(plan: JsonObject) -> JsonObject:
    files = _plan_files(plan)
    return {
        "plan_id": _required_string(plan, "plan_id"),
        "expires_at": _required_integer(plan, "expires_at"),
        "files": [
            {
                "target_id": _required_string(item, "target_id"),
                "path": _required_string(item, "path"),
                "diff": _required_string(item, "diff"),
            }
            for item in files
        ],
    }


def _plan_files(plan: JsonObject) -> list[JsonObject]:
    files = plan.get("files")
    if not isinstance(files, list) or not files:
        raise PolicyError("corrupt plan files")
    result: list[JsonObject] = []
    for item in files:
        if not isinstance(item, dict):
            raise PolicyError("corrupt plan files")
        result.append(dict(item))
    return result


def _required_string(value: JsonObject, key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise PolicyError(f"corrupt plan field: {key}")
    return item


def _required_integer(value: JsonObject, key: str) -> int:
    item = value.get(key)
    if type(item) is not int:
        raise PolicyError(f"corrupt plan field: {key}")
    return item


def _assert_current(files: list[JsonObject], *, side: Literal["before", "after"]) -> None:
    for item in files:
        path = Path(_required_string(item, "path"))
        current = _read_text_exact(path) if path.exists() else None
        expected = item.get(f"{side}_hash")
        if expected is not None and not isinstance(expected, str):
            raise PolicyError(f"corrupt plan {side}_hash")
        if _text_hash(current) != expected:
            raise PolicyError(f"{path} changed after review; create a new plan")


def _restore_before(files: list[JsonObject]) -> None:
    for item in reversed(files):
        path = Path(_required_string(item, "path"))
        before = item.get("before")
        if before is None:
            with suppress(FileNotFoundError):
                path.unlink()
        elif isinstance(before, str):
            atomic_write(path, before)
        else:
            raise PolicyError("corrupt plan before value")


def _delete_plan(plan_id: str) -> None:
    with suppress(FileNotFoundError):
        _plan_path(plan_id).unlink()
