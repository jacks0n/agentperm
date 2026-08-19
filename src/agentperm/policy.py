"""Policy file I/O: load, save, merge."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pyjson5

from .domain import (
    POLICY_FILENAME,
    Decision,
    JsonObject,
    JsonValue,
    Policy,
    PythonCallPolicy,
    RedirectionPolicy,
    Rule,
    narrow_json,
)
from .errors import PolicyError
from .fileio import atomic_write
from .rules import parse_rule

_REDIRECT_DECISION_VALUES = frozenset({Decision.Allow.value, Decision.Ask.value, Decision.Deny.value})


@dataclass(frozen=True)
class PolicyFile:
    """Round-trips ``.agent-permissions.jsonc`` data, preserving fields we don't model."""

    policy: Policy
    raw: JsonObject = field(default_factory=dict)


def load_policy_file(path: Path) -> PolicyFile:
    text = path.read_text()
    try:
        decoded: object = pyjson5.decode(text)
    except Exception as error:
        raise PolicyError(f"{path}: invalid JSON/JSONC ({error})") from error
    data = narrow_json(decoded)
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: top-level must be an object")
    return PolicyFile(policy=_policy_from_dict(data), raw=data)


def _policy_from_dict(data: JsonObject) -> Policy:
    redirection = _redirection_from_dict(data)
    python_calls = _python_calls_from_dict(data)
    permissions = data.get("permissions")
    if not isinstance(permissions, dict):
        return Policy(redirection=redirection, python_calls=python_calls)
    deny = tuple(_rules_from_list(permissions.get("deny")))
    ask = tuple(_rules_from_list(permissions.get("ask")))
    allow = tuple(_rules_from_list(permissions.get("allow")))
    return Policy(deny=deny, ask=ask, allow=allow, redirection=redirection, python_calls=python_calls)


def _python_calls_from_dict(data: JsonObject) -> PythonCallPolicy:
    python = data.get("python")
    if not isinstance(python, dict):
        return PythonCallPolicy()
    calls = python.get("calls")
    if not isinstance(calls, dict):
        return PythonCallPolicy()

    def names(key: str) -> frozenset[str]:
        raw = calls.get(key)
        if raw is None:
            return frozenset()
        if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
            raise PolicyError(f"python.calls.{key} must be an array of non-empty strings")
        return frozenset(item.strip() for item in raw if isinstance(item, str))

    return PythonCallPolicy(deny=names("deny"), ask=names("ask"), allow=names("allow"))


def _redirection_from_dict(data: JsonObject) -> RedirectionPolicy:
    shell = data.get("shell")
    if not isinstance(shell, dict):
        return RedirectionPolicy()
    redirection = shell.get("redirection")
    if not isinstance(redirection, dict):
        return RedirectionPolicy()
    allow_paths_raw = redirection.get("allowPaths")
    allow_paths: tuple[str, ...] = ()
    if isinstance(allow_paths_raw, list):
        allow_paths = tuple(p for p in allow_paths_raw if isinstance(p, str) and p)
    return RedirectionPolicy(
        stderr_to_dev_null=_parse_redirect_decision(redirection.get("stderrToDevNull")),
        stdout_to_dev_null=_parse_redirect_decision(redirection.get("stdoutToDevNull")),
        stdout_to_file=_parse_redirect_decision(redirection.get("stdoutToFile")),
        append_to_file=_parse_redirect_decision(redirection.get("appendToFile")),
        allow_paths=allow_paths,
    )


def _parse_redirect_decision(value: JsonValue) -> Decision | None:
    return Decision(value) if isinstance(value, str) and value in _REDIRECT_DECISION_VALUES else None


def _rules_from_list(raw: JsonValue) -> Iterator[Rule]:
    if not isinstance(raw, list):
        return
    for item in raw:
        rule = parse_rule(item)
        if rule is not None:
            yield rule


def save_policy_file(path: Path, policy_file: PolicyFile) -> None:
    raw: JsonObject = dict(policy_file.raw)
    raw.setdefault("version", 1)
    raw["permissions"] = {
        "allow": [r.serialize() for r in policy_file.policy.allow],
        "ask": [r.serialize() for r in policy_file.policy.ask],
        "deny": [r.serialize() for r in policy_file.policy.deny],
    }
    calls = policy_file.policy.python_calls
    python_raw = raw.get("python")
    existing_calls = python_raw.get("calls") if isinstance(python_raw, dict) else None
    if calls.deny or calls.ask or calls.allow or isinstance(existing_calls, dict):
        python: JsonObject = dict(python_raw) if isinstance(python_raw, dict) else {}
        serialized: JsonObject = dict(existing_calls) if isinstance(existing_calls, dict) else {}
        serialized.update({
            "allow": sorted(calls.allow),
            "ask": sorted(calls.ask),
            "deny": sorted(calls.deny),
        })
        python["calls"] = serialized
        raw["python"] = python

    redirect_fields = {
        "stderrToDevNull": policy_file.policy.redirection.stderr_to_dev_null,
        "stdoutToDevNull": policy_file.policy.redirection.stdout_to_dev_null,
        "stdoutToFile": policy_file.policy.redirection.stdout_to_file,
        "appendToFile": policy_file.policy.redirection.append_to_file,
    }
    shell_raw = raw.get("shell")
    existing_redirection = shell_raw.get("redirection") if isinstance(shell_raw, dict) else None
    allow_paths = policy_file.policy.redirection.allow_paths
    has_redirection = (
        any(value is not None for value in redirect_fields.values())
        or bool(allow_paths)
        or isinstance(existing_redirection, dict)
    )
    if has_redirection:
        shell: JsonObject = dict(shell_raw) if isinstance(shell_raw, dict) else {}
        redirection: JsonObject = dict(existing_redirection) if isinstance(existing_redirection, dict) else {}
        for key, decision in redirect_fields.items():
            if decision is None:
                redirection.pop(key, None)
            else:
                redirection[key] = decision.value
        if allow_paths:
            redirection["allowPaths"] = list(allow_paths)
        else:
            redirection.pop("allowPaths", None)
        shell["redirection"] = redirection
        raw["shell"] = shell
    atomic_write(path, json.dumps(raw, indent=2) + "\n")


def _policy_paths(cwd: Path | None) -> tuple[Path, ...]:
    """Policy files in merge order: global, then filesystem root through ``cwd``."""
    global_path = Path.home() / POLICY_FILENAME
    paths = [global_path]
    seen = {global_path.resolve()}
    if cwd is None:
        return tuple(paths)

    resolved_cwd = cwd.resolve()
    for directory in reversed((resolved_cwd, *resolved_cwd.parents)):
        candidate = directory / POLICY_FILENAME
        identity = candidate.resolve()
        if identity in seen:
            continue
        paths.append(candidate)
        seen.add(identity)
    return tuple(paths)


def merged_policy(cwd: Path | None = None, *, local_root: Path | None = None) -> Policy:
    """Merge global policy with every policy from the filesystem root through ``cwd``.

    ``local_root`` is retained as a compatibility alias for callers of the previous
    Git-root-only API. Supplying both names is ambiguous and therefore rejected.
    """
    if cwd is not None and local_root is not None:
        raise TypeError("merged_policy accepts either cwd or local_root, not both")
    search_from = cwd if cwd is not None else local_root
    policy = Policy()
    for path in _policy_paths(search_from):
        if not path.exists():
            continue
        policy = policy.merged_with(load_policy_file(path).policy)
    return policy


def git_toplevel(cwd: Path) -> Path | None:
    """The git worktree root containing ``cwd``, or ``None`` if there isn't one."""
    try:
        output = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(cwd),
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return Path(output) if output else None


def write_default_policy(path: Path) -> None:
    default: JsonObject = {
        "version": 1,
        "permissions": {
            "allow": [],
            "ask": [],
            "deny": [],
        },
    }
    atomic_write(path, json.dumps(default, indent=2) + "\n")
