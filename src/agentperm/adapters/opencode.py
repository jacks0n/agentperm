"""OpenCode adapter."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from ..domain import (
    AgentName,
    BashCommand,
    Decision,
    InstallMode,
    JsonObject,
    NamedTool,
    Request,
    Rule,
    ShellRequest,
    ToolRequest,
    Verdict,
    tool_arguments,
)
from ..fileio import atomic_write, read_json
from ..shell import parse_pipeline
from .apply_patch import parse_apply_patch_request
from .base import (
    AgentAdapter,
    resolve_bridge_command,
)

_OPENCODE_PLUGIN_TEMPLATE = """import {{ spawnSync }} from "node:child_process";

const bridge = {bridge};

function bridgeDecision(event, payload) {{
  const proc = spawnSync(
    bridge,
    ["check", "--agent", "opencode", "--event", event],
    {{ input: JSON.stringify(payload), encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] }},
  );
  if (proc.status !== 0 || !proc.stdout.trim()) return null;
  try {{ return JSON.parse(proc.stdout); }} catch {{ return null; }}
}}

export const AgentBridgePlugin = async (input) => ({{
  "tool.execute.before": async (tool, output) => {{
    const decision = bridgeDecision("tool.execute.before", {{
      cwd: input.directory,
      hook_event_name: "tool.execute.before",
      tool_name: tool.tool,
      tool_input: output.args,
    }});
    if (decision?.status === "deny") {{
      throw new Error(decision.reason || "Blocked by agentperm policy");
    }}
  }},
  "permission.ask": async (permission, output) => {{
    const decision = bridgeDecision("permission.ask", {{
      cwd: input.directory,
      hook_event_name: "permission.ask",
      permission,
      tool_name: permission.type,
      tool_input: permission.metadata ?? permission,
    }});
    if (decision?.status === "allow" || decision?.status === "deny" || decision?.status === "ask") {{
      output.status = decision.status;
    }}
  }},
}});
"""


class OpencodeAdapter(AgentAdapter):
    name = AgentName.Opencode
    config_path: ClassVar[Path] = Path.home() / ".config/opencode/opencode.json"
    plugin_path: ClassVar[Path] = Path.home() / ".config/opencode/plugins/agentperm.js"

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        for path in (self.config_path, self.config_path.with_suffix(".jsonc")):
            if not path.exists():
                continue
            data = read_json(path)
            permissions = data.get("permission")
            if not isinstance(permissions, dict):
                continue
            for tool_name, raw_rules in permissions.items():
                if isinstance(raw_rules, str):
                    rule = _opencode_rule(tool_name, "*")
                    if rule is None:
                        continue
                    decision = _opencode_decision(raw_rules)
                    if decision is not None:
                        yield decision, rule
                    continue
                if not isinstance(raw_rules, dict):
                    continue
                for pattern, action in raw_rules.items():
                    if not isinstance(action, str):
                        continue
                    decision = _opencode_decision(action)
                    if decision is None:
                        continue
                    rule = _opencode_rule(tool_name, pattern)
                    if rule is not None:
                        yield decision, rule

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        if event_name == "tool.execute.before":
            tool_name = payload.get("tool_name")
            if not isinstance(tool_name, str):
                return None
            tool_input_raw = payload.get("tool_input")
            tool_input: JsonObject = tool_input_raw if isinstance(tool_input_raw, dict) else {}
            cwd_raw = payload.get("cwd")
            cwd = Path(cwd_raw) if isinstance(cwd_raw, str) else None
            if tool_name == "bash":
                command = tool_input.get("command")
                return ShellRequest(
                    parse_pipeline(command if isinstance(command, str) else ""),
                    cwd=cwd,
                )
            if tool_name == "apply_patch":
                patch = tool_input.get("patchText")
                return parse_apply_patch_request(patch if isinstance(patch, str) else "", cwd)
            return ToolRequest(_opencode_tool_name(tool_name), tool_arguments(tool_input), cwd=cwd)

        permission = payload.get("permission")
        if not isinstance(permission, dict):
            return None
        permission_type = permission.get("type")
        metadata_raw = permission.get("metadata")
        metadata: JsonObject = metadata_raw if isinstance(metadata_raw, dict) else permission
        cwd_raw = payload.get("cwd")
        cwd = Path(cwd_raw) if isinstance(cwd_raw, str) else None
        if permission_type == "bash":
            command = metadata.get("command")
            return ShellRequest(parse_pipeline(command if isinstance(command, str) else ""), cwd=cwd)
        if permission_type == "apply_patch":
            patch = metadata.get("patchText")
            if isinstance(patch, str):
                return parse_apply_patch_request(patch, cwd)
        if isinstance(permission_type, str):
            return ToolRequest(_opencode_tool_name(permission_type), tool_arguments(metadata), cwd=cwd)
        return None

    def write_verdict(self, verdict: Verdict, event_name: str) -> int:
        if verdict.decision is Decision.NoOpinion:
            json.dump({}, sys.stdout)
            return 0
        json.dump({"status": verdict.decision.value, "reason": verdict.rationale}, sys.stdout)
        return 0

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        """Always writes the OpenCode plugin shim regardless of ``mode``.

        rulesync has no ``permission.ask`` plugin emitter — there is no schema for
        it — so the plugin is always installed directly. The plugin embeds the
        absolute path to ``agentperm`` resolved at install time, JSON-quoted
        so paths containing backslashes or quotes survive interpolation into a JS
        string literal.
        """
        bridge_literal = json.dumps(resolve_bridge_command())
        contents = _OPENCODE_PLUGIN_TEMPLATE.format(bridge=bridge_literal)
        if self.plugin_path.exists() and self.plugin_path.read_text() == contents:
            return []
        if not dry_run:
            atomic_write(self.plugin_path, contents)
        return [self.plugin_path]

    def uninstall(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        """Delete the plugin shim, but only when it is recognizably ours.

        Exact-template matching would be too brittle (the file embeds an
        absolute path and changes across versions), so match on the plugin's
        own identifiers instead. Anything else stays put with a warning.
        """
        if not self.plugin_path.exists():
            return []
        text = self.plugin_path.read_text()
        if "AgentBridgePlugin" not in text or '"--agent", "opencode"' not in text:
            print(
                f"warning: {self.plugin_path} does not look like the agentperm plugin; leaving it in place",
                file=sys.stderr,
            )
            return []
        if not dry_run:
            self.plugin_path.unlink()
        return [self.plugin_path]


def _opencode_rule(tool: str, pattern: str) -> Rule | None:
    if tool == "bash":
        if pattern == "*":
            return BashCommand(("**",), trailing_wildcard=True)
        return BashCommand(tuple(pattern.split()))
    specifier = None if pattern == "*" else pattern
    return NamedTool(_opencode_tool_name(tool), specifier)


_OPENCODE_TOOL_NAMES = {
    "read": "Read",
    "grep": "Grep",
    "glob": "Glob",
    "edit": "Edit",
    "write": "Write",
    "webfetch": "WebFetch",
    "websearch": "WebSearch",
    "task": "Task",
    "skill": "Skill",
}


def _opencode_tool_name(tool: str) -> str:
    """Canonicalize an OpenCode tool key (``webfetch``) to the policy name (``WebFetch``)."""
    return _OPENCODE_TOOL_NAMES.get(tool, tool)


def _opencode_decision(action: str) -> Decision | None:
    return {"allow": Decision.Allow, "ask": Decision.Ask, "deny": Decision.Deny}.get(action)
