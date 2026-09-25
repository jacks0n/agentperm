"""Claude Code adapter."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from ..config import CLAUDE_SETTINGS_PATH
from ..domain import (
    AgentName,
    Decision,
    InstallMode,
    JsonObject,
    McpToolRequest,
    McpToolRule,
    NamedTool,
    Request,
    Rule,
    ShellRequest,
    Verdict,
    native_tool,
    powershell_request,
    tool_arguments,
    tool_request,
)
from ..fileio import read_json
from ..rules import parse_rule
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


class ClaudeAdapter(AgentAdapter):
    name = AgentName.Claude
    settings_path: ClassVar[Path] = Path.home() / CLAUDE_SETTINGS_PATH

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        for path in (self.settings_path, self.settings_path.with_name("settings.local.json")):
            if not path.exists():
                continue
            settings = read_json(path)
            permissions = settings.get("permissions")
            if not isinstance(permissions, dict):
                continue
            for decision_key, target_decision in (
                ("deny", Decision.Deny),
                ("ask", Decision.Ask),
                ("allow", Decision.Allow),
            ):
                raw_list = permissions.get(decision_key)
                if not isinstance(raw_list, list):
                    continue
                for raw in raw_list:
                    if raw == "Bash":
                        continue
                    if isinstance(raw, str) and (identity := _claude_mcp_identity(raw)) is not None:
                        yield target_decision, McpToolRule(*identity)
                        continue
                    rule = parse_rule(raw)
                    if isinstance(rule, NamedTool):
                        tool = native_tool(AgentName.Claude, rule.name)
                        if tool is None:
                            continue
                        rule = NamedTool(tool.capability, rule.specifier, rule.rationale)
                    if rule is not None:
                        yield target_decision, rule

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        return parse_claude_shaped_event(payload, AgentName.Claude)

    def write_verdict(
        self,
        verdict: Verdict,
        event_name: str,
        *,
        updated_input: JsonObject | None = None,
    ) -> int:
        if verdict.decision is Decision.NoOpinion:
            if event_name == "PreToolUse" and updated_input is not None:
                json.dump(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "updatedInput": updated_input,
                        }
                    },
                    sys.stdout,
                )
                return 0
            json.dump({}, sys.stdout)
            return 0
        if event_name == "PreToolUse":
            if verdict.decision is Decision.Deny:
                json.dump(pretooluse_output(Decision.Deny, verdict.rationale), sys.stdout)
                return 0
            hook_output: JsonObject = {
                "hookEventName": "PreToolUse",
                "permissionDecision": verdict.decision.value,
                "permissionDecisionReason": verdict.rationale,
            }
            if updated_input is not None:
                hook_output["updatedInput"] = updated_input
            json.dump({"hookSpecificOutput": hook_output}, sys.stdout)
            return 0
        if event_name == "PermissionRequest":
            json.dump(permission_request_output(verdict.decision, verdict.rationale), sys.stdout)
            return 0
        json.dump({}, sys.stdout)
        return 0

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        # Claude doesn't fire ``PermissionRequest`` — strip any bridge entry that
        # made it there from an older or third-party installer.
        if mode is InstallMode.Rulesync:
            return merge_rulesync_hooks(
                block="claudecode",
                add=[("preToolUse", "PreToolUse", "*")],
                strip=["permissionRequest"],
                agent_name="claude",
                dry_run=dry_run,
            )
        return merge_nested_hooks(
            self.settings_path,
            add=[("PreToolUse", "*")],
            strip=["PermissionRequest"],
            agent_name="claude",
            dry_run=dry_run,
        )

    def uninstall(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        if mode is InstallMode.Rulesync:
            return strip_rulesync_hooks(
                block="claudecode",
                keys=["preToolUse", "permissionRequest"],
                dry_run=dry_run,
            )
        return strip_nested_hooks(
            self.settings_path,
            events=["PreToolUse", "PermissionRequest"],
            dry_run=dry_run,
        )


def parse_claude_shaped_event(payload: JsonObject, agent: AgentName) -> Request | None:
    """Parse a ``tool_name``/``tool_input`` hook payload, as Claude and Codex send it."""
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str):
        return None
    cwd_raw = payload.get("cwd")
    cwd = Path(cwd_raw) if isinstance(cwd_raw, str) else None
    tool_input = payload.get("tool_input")
    if tool_name == "Bash":
        command = tool_input.get("command") if isinstance(tool_input, dict) else None
        return ShellRequest(parse_pipeline(command if isinstance(command, str) else ""), cwd=cwd)
    if tool_name == "PowerShell":
        return powershell_request(cwd)
    identity = _claude_mcp_identity(tool_name)
    if identity is not None:
        return McpToolRequest(*identity, tool_arguments(tool_input), cwd)
    return tool_request(agent, tool_name, tool_input, cwd)


def _claude_mcp_identity(tool_name: str) -> tuple[str, str] | None:
    if not tool_name.startswith("mcp__"):
        return None
    server, separator, tool = tool_name[5:].partition("__")
    if not server or not separator or not tool:
        return None
    return server, tool
