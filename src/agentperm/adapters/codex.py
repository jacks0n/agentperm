"""Codex CLI adapter."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

import tomlkit

from ..domain import (
    AgentName,
    BashCommand,
    Decision,
    InstallMode,
    JsonObject,
    Request,
    Rule,
    ShellRequest,
    ToolRequest,
    Verdict,
    tool_arguments,
)
from ..errors import PolicyError
from ..fileio import atomic_write
from ..shell import parse_pipeline
from .base import (
    AgentAdapter,
    merge_nested_hooks,
    merge_rulesync_hooks,
    permission_request_output,
    pretooluse_output,
    strip_nested_hooks,
    strip_rulesync_hooks,
)
from .claude import ClaudeAdapter


class CodexAdapter(AgentAdapter):
    name = AgentName.Codex
    config_path: ClassVar[Path] = Path.home() / ".codex/config.toml"
    hooks_path: ClassVar[Path] = Path.home() / ".codex/hooks.json"

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        rules_dir = self.config_path.parent / "rules"
        if not rules_dir.exists():
            return
        for rules_file in sorted(rules_dir.glob("*.rules")):
            for tokens, decision_text in _parse_codex_prefix_rules(rules_file.read_text()):
                decision = {"allow": Decision.Allow, "prompt": Decision.Ask, "forbidden": Decision.Deny}.get(
                    decision_text
                )
                if decision is None or not tokens:
                    continue
                yield decision, BashCommand(tuple(tokens))

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        if event_name == "PermissionRequest":
            # Codex 0.128+ ships a Claude-shaped envelope at top level
            # (``tool_name`` + ``tool_input``). Earlier builds wrapped the
            # command in ``permission.metadata.command``; we still accept it
            # for back-compat.
            permission = payload.get("permission")
            if isinstance(permission, dict):
                permission_type = permission.get("type")
                metadata = permission.get("metadata")
                if permission_type == "Bash":
                    command = metadata.get("command") if isinstance(metadata, dict) else None
                    return ShellRequest(parse_pipeline(command if isinstance(command, str) else ""))
                if isinstance(permission_type, str):
                    return ToolRequest(permission_type, tool_arguments(metadata))
                return None
        return ClaudeAdapter().parse_event(payload, event_name)

    def write_verdict(self, verdict: Verdict, event_name: str) -> int:
        # Codex's two events split responsibilities: PreToolUse is the fast-path
        # veto (Deny only), PermissionRequest is where we may pre-approve. Allow
        # / Ask on PreToolUse fall through to Codex's normal flow so the user
        # still sees a prompt for anything not explicitly denied.
        if event_name == "PreToolUse":
            if verdict.decision is Decision.Deny:
                json.dump(pretooluse_output(Decision.Deny, verdict.rationale), sys.stdout)
                return 0
            json.dump({}, sys.stdout)
            return 0
        if event_name == "PermissionRequest":
            if verdict.decision is Decision.Allow:
                json.dump(permission_request_output(Decision.Allow, verdict.rationale), sys.stdout)
                return 0
            if verdict.decision is Decision.Deny:
                json.dump(permission_request_output(Decision.Deny, verdict.rationale), sys.stdout)
                return 0
        json.dump({}, sys.stdout)
        return 0

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        if mode is InstallMode.Rulesync:
            # rulesync owns enabling Codex's hook feature flag; we only emit hook entries.
            return merge_rulesync_hooks(
                block="codexcli",
                add=[
                    ("preToolUse", "PreToolUse", ".*"),
                    ("permissionRequest", "PermissionRequest", ".*"),
                ],
                strip=[],
                agent_name="codex",
                dry_run=dry_run,
            )
        touched = merge_nested_hooks(
            self.hooks_path,
            add=[("PreToolUse", "Bash"), ("PermissionRequest", "Bash|apply_patch|mcp__.*")],
            strip=[],
            agent_name="codex",
            dry_run=dry_run,
        )
        touched.extend(_enable_codex_hooks_feature(self.config_path, dry_run=dry_run))
        return touched

    def uninstall(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        # ``[features] hooks = true`` in config.toml is deliberately left alone:
        # other tools may rely on it, and it is inert without hook entries.
        if mode is InstallMode.Rulesync:
            return strip_rulesync_hooks(
                block="codexcli",
                keys=["preToolUse", "permissionRequest"],
                dry_run=dry_run,
            )
        return strip_nested_hooks(
            self.hooks_path,
            events=["PreToolUse", "PermissionRequest"],
            dry_run=dry_run,
        )


def _enable_codex_hooks_feature(path: Path, *, dry_run: bool) -> list[Path]:
    """Ensure ``[features] hooks = true`` in ``~/.codex/config.toml``.

    Codex gates hook execution behind this feature flag; the hook entries in
    ``hooks.json`` are inert until it is set. Older Codex versions used
    ``codex_hooks``; migrate that deprecated key away when it is present.
    """
    if path.exists():
        try:
            doc = tomlkit.parse(path.read_text())
        except Exception as error:
            raise PolicyError(f"{path}: {error}") from error
    else:
        doc = tomlkit.document()
    features = doc.get("features")
    if not isinstance(features, dict):
        features = tomlkit.table()
        doc["features"] = features

    changed = False
    if features.get("hooks") is not True:
        features["hooks"] = True
        changed = True
    if "codex_hooks" in features:
        del features["codex_hooks"]
        changed = True
    if not changed:
        return []
    if not dry_run:
        atomic_write(path, tomlkit.dumps(doc))
    return [path]


def _parse_codex_prefix_rules(text: str) -> Iterator[tuple[list[str], str]]:
    for match in re.finditer(r"prefix_rule\((.*?)\)", text, flags=re.DOTALL):
        body = match.group(1)
        pattern_match = re.search(r"pattern\s*=\s*\[(.*?)\]", body, flags=re.DOTALL)
        decision_match = re.search(r"decision\s*=\s*['\"]([^'\"]+)['\"]", body)
        if pattern_match is None or decision_match is None:
            continue
        tokens = re.findall(r"['\"]([^'\"]+)['\"]", pattern_match.group(1))
        if tokens:
            yield tokens, decision_match.group(1)
