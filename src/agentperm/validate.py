"""Policy file validation: surface silently-dropped rules and typo'd settings.

The runtime loader is deliberately tolerant in places — an entry ``parse_rule``
can't understand is skipped, and an unknown redirect decision is ignored — so a
typo can leave you with less protection than you wrote, without an error.
``agentperm validate`` walks the raw file and reports exactly those cases.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pyjson5

from .domain import JsonObject, JsonValue, NamedTool, narrow_json
from .errors import PolicyError
from .rules import parse_rule

_TOP_LEVEL_KEYS = frozenset({"version", "permissions", "shell", "python"})
_PERMISSION_KEYS = ("allow", "ask", "deny")
_REDIRECTION_DECISION_KEYS = frozenset(
    {"stderrToDevNull", "stdoutToDevNull", "stdoutToFile", "appendToFile"}
)
_REDIRECTION_KEYS = _REDIRECTION_DECISION_KEYS | {"allowPaths"}
_DECISION_VALUES = frozenset({"allow", "ask", "deny"})


@dataclass(frozen=True)
class Finding:
    severity: str  # "error" | "warning"
    message: str


def validate_policy_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text()
    except OSError as error:
        return [Finding("error", f"unreadable: {error}")]
    return validate_policy_text(text)


def validate_policy_text(text: str) -> list[Finding]:
    try:
        decoded: object = pyjson5.decode(text)
    except Exception as error:
        return [Finding("error", f"invalid JSON/JSONC: {error}")]
    data = narrow_json(decoded)
    if not isinstance(data, dict):
        return [Finding("error", "top-level must be an object")]

    findings: list[Finding] = []
    for key in data:
        if key not in _TOP_LEVEL_KEYS:
            findings.append(Finding("warning", f"unknown top-level key {key!r}"))
    version = data.get("version")
    if version is not None and version != 1:
        findings.append(Finding("warning", f"unsupported version {version!r} (expected 1)"))

    findings.extend(_validate_permissions(data))
    findings.extend(_validate_redirection(data))
    findings.extend(_validate_python_calls(data))
    return findings


def _validate_permissions(data: JsonObject) -> list[Finding]:
    findings: list[Finding] = []
    permissions = data.get("permissions")
    if permissions is None:
        return findings
    if not isinstance(permissions, dict):
        return [Finding("error", "'permissions' must be an object")]
    for key in permissions:
        if key not in _PERMISSION_KEYS:
            findings.append(Finding("warning", f"unknown permissions key {key!r}"))
    for decision in _PERMISSION_KEYS:
        entries = permissions.get(decision)
        if entries is None:
            continue
        if not isinstance(entries, list):
            findings.append(Finding("error", f"permissions.{decision} must be an array"))
            continue
        for index, entry in enumerate(entries):
            findings.extend(_validate_rule(entry, f"{decision}[{index}]"))
    return findings


def _validate_rule(entry: JsonValue, where: str) -> list[Finding]:
    try:
        rule = parse_rule(entry)
    except PolicyError as error:
        return [Finding("error", f"{where}: {error}")]
    if rule is None:
        # The loader would skip this entry without a sound — the rule you wrote
        # protects (or allows) nothing.
        return [Finding("error", f"{where}: unparseable rule {_show(entry)} (silently ignored at runtime)")]
    if isinstance(rule, NamedTool) and rule.specifier is not None and " " in rule.specifier:
        # ``Shel(git status)`` parses as NamedTool("Shel", "git status") — a real
        # tool specifier never contains a space, so this is almost surely a typo.
        return [
            Finding(
                "warning",
                f"{where}: {_show(entry)} matches a tool literally named {rule.name!r} — "
                f"did you mean Shell(...) or Bash(...)?",
            )
        ]
    return []


def _validate_redirection(data: JsonObject) -> list[Finding]:
    shell = data.get("shell")
    if shell is None:
        return []
    if not isinstance(shell, dict):
        return [Finding("error", "'shell' must be an object")]
    findings: list[Finding] = []
    for key in shell:
        if key != "redirection":
            findings.append(Finding("warning", f"unknown shell key {key!r}"))
    redirection = shell.get("redirection")
    if redirection is None:
        return findings
    if not isinstance(redirection, dict):
        return [*findings, Finding("error", "'shell.redirection' must be an object")]
    for key, value in redirection.items():
        if key not in _REDIRECTION_KEYS:
            findings.append(Finding("warning", f"unknown shell.redirection key {key!r}"))
            continue
        if key in _REDIRECTION_DECISION_KEYS and (not isinstance(value, str) or value not in _DECISION_VALUES):
            # The loader ignores an unrecognized decision, so the default applies
            # silently — worth an error, not a warning.
            findings.append(
                Finding(
                    "error",
                    f"shell.redirection.{key}: {_show(value)} is not one of allow/ask/deny "
                    f"(silently ignored at runtime)",
                )
            )
    allow_paths = redirection.get("allowPaths")
    if allow_paths is not None:
        if not isinstance(allow_paths, list):
            findings.append(Finding("error", "shell.redirection.allowPaths must be an array of paths"))
        else:
            for index, item in enumerate(allow_paths):
                if not isinstance(item, str) or not item:
                    findings.append(
                        Finding(
                            "error",
                            f"shell.redirection.allowPaths[{index}]: {_show(item)} is not a non-empty string "
                            f"(silently ignored at runtime)",
                        )
                    )
    return findings


def _validate_python_calls(data: JsonObject) -> list[Finding]:
    python = data.get("python")
    if python is None:
        return []
    if not isinstance(python, dict):
        return [Finding("error", "'python' must be an object")]
    findings: list[Finding] = []
    for key in python:
        if key != "calls":
            findings.append(Finding("warning", f"unknown python key {key!r}"))
    calls = python.get("calls")
    if calls is None:
        return findings
    if not isinstance(calls, dict):
        return [*findings, Finding("error", "'python.calls' must be an object")]
    for key, value in calls.items():
        if key not in _DECISION_VALUES:
            findings.append(Finding("warning", f"unknown python.calls key {key!r}"))
            continue
        if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
            findings.append(Finding("error", f"python.calls.{key} must be an array of non-empty strings"))
    return findings


def _show(value: JsonValue) -> str:
    return json.dumps(value)
