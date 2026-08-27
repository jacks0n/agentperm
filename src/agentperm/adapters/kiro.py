"""Kiro adapter."""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from ..domain import (
    AgentName,
    BashCommand,
    CompoundRequest,
    Decision,
    InstallMode,
    JsonArray,
    JsonObject,
    JsonValue,
    NamedTool,
    Pipeline,
    Request,
    Rule,
    ShellRequest,
    ToolRequest,
    Verdict,
    tool_arguments,
)
from ..fileio import atomic_write, read_json
from ..policy import git_toplevel
from ..shell import parse_pipeline
from .base import (
    AgentAdapter,
    is_bridge_hook,
    resolve_bridge_command,
)


class KiroAdapter(AgentAdapter):
    name = AgentName.Kiro
    # Tests and embedders may override these. ``None`` follows Kiro's runtime
    # home selection, including its supported KIRO_HOME profile override.
    hooks_path: ClassVar[Path | None] = None
    agents_path: ClassVar[Path | None] = None
    workspace_root: ClassVar[Path | None] = None

    def _kiro_home(self) -> Path:
        configured = os.environ.get("KIRO_HOME")
        return Path(configured).expanduser() if configured else Path.home() / ".kiro"

    def _hooks_path(self) -> Path:
        return self.hooks_path if self.hooks_path is not None else self._kiro_home() / "hooks/agentperm.json"

    def _agents_path(self) -> Path:
        return self.agents_path if self.agents_path is not None else self._kiro_home() / "agents"

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str):
            return None
        cwd_raw = payload.get("cwd")
        cwd = Path(cwd_raw) if isinstance(cwd_raw, str) else None
        tool_input = payload.get("tool_input")
        if tool_name in ("shell", "execute_bash", "execute_cmd"):
            command = tool_input.get("command") if isinstance(tool_input, dict) else None
            if not isinstance(command, str) or not command:
                return ShellRequest(
                    Pipeline((), parseable=False, unparseable_reason="no command in tool_input"),
                    cwd=cwd,
                )
            return ShellRequest(parse_pipeline(command), cwd=cwd)
        arguments = tool_arguments(tool_input)
        if tool_name in _KIRO_WRITE_TOOL_NAMES:
            # Kiro exposes creation and modification through one native write
            # tool. Evaluate both semantic capabilities so either policy can
            # guard the operation without exposing Kiro's implementation detail.
            return CompoundRequest(
                (
                    ToolRequest("Edit", arguments, cwd=cwd),
                    ToolRequest("Write", arguments, cwd=cwd),
                )
            )
        return ToolRequest(kiro_tool_name(tool_name), arguments, cwd=cwd)

    def write_verdict(self, verdict: Verdict, event_name: str) -> int:
        if verdict.decision == Decision.Deny:
            print(f"denied: {verdict.rationale}", file=sys.stderr)
            return 2
        if verdict.decision == Decision.Ask:
            print(f"blocked: {verdict.rationale}", file=sys.stderr)
            return 2
        if verdict.decision == Decision.Allow:
            return 0
        # NoOpinion defers to Kiro's native permission handling.
        return 0

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        bridge = resolve_bridge_command()
        command = f"{shlex.quote(bridge)} check --agent kiro --event preToolUse"
        # Kiro v2 uses glob-style tool matchers; v3/IDE standalone hooks use regex.
        hook_entry: JsonObject = {"matcher": "*", "command": command}
        touched: list[Path] = []
        # CLI hooks are embedded in custom-agent files. The built-in
        # ``kiro_default`` agent is held in memory and cannot be edited, so do not
        # create a misleading reserved-name file for it. The standalone global
        # hook below covers current Kiro/IDE releases. For custom agents, merge
        # into both the global profile and the current workspace so selecting a
        # project-scoped agent cannot silently bypass agentperm.
        agent_paths = self._custom_agent_paths()
        for agent_path in sorted(agent_paths):
            touched.extend(self._install_v2_agent_hook(agent_path, hook_entry, dry_run=dry_run))
        # v3 CLI / IDE: standalone global hook file.
        hook_file: JsonObject = {
            "version": "v1",
            "hooks": [
                {
                    "name": "agentperm",
                    "trigger": "PreToolUse",
                    "matcher": ".*",
                    "action": {"type": "command", "command": command},
                    "timeout": 30,
                    "enabled": True,
                }
            ],
        }
        hook_contents = json.dumps(hook_file, indent=2) + "\n"
        hooks_path = self._hooks_path()
        if not hooks_path.exists() or hooks_path.read_text() != hook_contents:
            if not dry_run:
                atomic_write(hooks_path, hook_contents)
            touched.append(hooks_path)
        return touched

    def uninstall(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        touched: list[Path] = []
        for agent_path in sorted(self._custom_agent_paths()):
            touched.extend(self._uninstall_v2_agent_hook(agent_path, dry_run=dry_run))
        touched.extend(self._uninstall_standalone_hooks(dry_run=dry_run))
        return touched

    def _uninstall_v2_agent_hook(self, agent_path: Path, *, dry_run: bool) -> list[Path]:
        before = read_json(agent_path)
        after: JsonObject = json.loads(json.dumps(before))
        hooks = after.get("hooks")
        if not isinstance(hooks, dict):
            return []
        pre_tool = hooks.get("preToolUse")
        if not isinstance(pre_tool, list):
            return []
        remaining: JsonArray = [hook for hook in pre_tool if not is_bridge_hook(hook)]
        if len(remaining) == len(pre_tool):
            return []
        if remaining:
            hooks["preToolUse"] = remaining
        else:
            del hooks["preToolUse"]
            if not hooks:
                del after["hooks"]
        if not dry_run:
            atomic_write(agent_path, json.dumps(after, indent=2) + "\n")
        return [agent_path]

    def _uninstall_standalone_hooks(self, *, dry_run: bool) -> list[Path]:
        """Remove the standalone hook file, or just our entries if it holds others."""
        hooks_path = self._hooks_path()
        if not hooks_path.exists():
            return []
        data = read_json(hooks_path)
        entries = data.get("hooks")
        entry_list: JsonArray = entries if isinstance(entries, list) else []
        others: JsonArray = [entry for entry in entry_list if not _kiro_standalone_is_bridge(entry)]
        if len(others) == len(entry_list):
            return []
        if others:
            updated: JsonObject = json.loads(json.dumps(data))
            updated["hooks"] = others
            if not dry_run:
                atomic_write(hooks_path, json.dumps(updated, indent=2) + "\n")
        elif not dry_run:
            hooks_path.unlink()
        return [hooks_path]

    def _custom_agent_paths(self) -> set[Path]:
        paths: set[Path] = set()
        global_agents = self._agents_path()
        if global_agents.is_dir():
            paths.update(global_agents.glob("*.json"))

        root = self.workspace_root
        if root is None:
            root = git_toplevel(Path.cwd())
        if root is not None:
            workspace_agents = root / ".kiro/agents"
            if workspace_agents.is_dir() and workspace_agents != global_agents:
                paths.update(workspace_agents.glob("*.json"))
        return paths

    def _install_v2_agent_hook(
        self,
        agent_path: Path,
        hook_entry: JsonObject,
        *,
        dry_run: bool,
    ) -> list[Path]:
        before = read_json(agent_path)
        default_name = agent_path.stem
        after: JsonObject = json.loads(json.dumps(before)) if before else {"name": default_name}
        if "name" not in after:
            after = {"name": default_name, **after}
        hooks = after.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            hooks = {}
            after["hooks"] = hooks
        pre_tool_raw = hooks.get("preToolUse")
        pre_tool: JsonArray = list(pre_tool_raw) if isinstance(pre_tool_raw, list) else []
        pre_tool = [h for h in pre_tool if not is_bridge_hook(h)]
        pre_tool.append(hook_entry)
        hooks["preToolUse"] = pre_tool
        after["hooks"] = hooks
        agent_contents = json.dumps(after, indent=2) + "\n"
        before_text = agent_path.read_text() if agent_path.exists() else ""
        if before_text != agent_contents:
            if not dry_run:
                atomic_write(agent_path, agent_contents)
            return [agent_path]
        return []

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        agents_path = self._agents_path()
        if not agents_path.is_dir():
            return
        for agent_file in agents_path.glob("*.json"):
            try:
                data = read_json(agent_file)
            except Exception:
                continue
            allowed_tools = data.get("allowedTools")
            if isinstance(allowed_tools, list):
                for entry in allowed_tools:
                    if not isinstance(entry, str):
                        continue
                    if entry in ("shell", "execute_bash", "execute_cmd"):
                        continue
                    for rule in _kiro_allowed_tool_rules(entry):
                        yield Decision.Allow, rule
            tools_settings = data.get("toolsSettings")
            if not isinstance(tools_settings, dict):
                continue
            shell_settings = tools_settings.get("shell")
            if not isinstance(shell_settings, dict):
                continue
            allowed_commands = shell_settings.get("allowedCommands")
            if isinstance(allowed_commands, list):
                for cmd in allowed_commands:
                    if isinstance(cmd, str) and cmd:
                        rule = _kiro_command_rule(cmd)
                        if rule is not None:
                            yield Decision.Allow, rule
            denied_commands = shell_settings.get("deniedCommands")
            if isinstance(denied_commands, list):
                for cmd in denied_commands:
                    if isinstance(cmd, str) and cmd:
                        rule = _kiro_command_rule(cmd)
                        if rule is not None:
                            yield Decision.Deny, rule


def _kiro_standalone_is_bridge(entry: JsonValue) -> bool:
    """Bridge detection for standalone hook entries, whose command nests under ``action``."""
    if not isinstance(entry, dict):
        return False
    action = entry.get("action")
    return is_bridge_hook(action if isinstance(action, dict) else entry)


def kiro_tool_name(name: str) -> str:
    return {
        "shell": "Bash",
        "execute_bash": "Bash",
        "execute_cmd": "Bash",
        "read": "Read",
        "fs_read": "Read",
        "fsRead": "Read",
        "write": "Write",
        "fs_write": "Write",
        "fsWrite": "Write",
        "glob": "Glob",
        "grep": "Grep",
        "web_search": "WebSearch",
        "web_fetch": "WebFetch",
        "aws": "AWS",
        "use_aws": "AWS",
        "code": "Code",
        "knowledge": "Knowledge",
        "delegate": "Delegate",
        "subagent": "Subagent",
        "use_subagent": "Subagent",
    }.get(name, name)


_KIRO_WRITE_TOOL_NAMES = frozenset({"write", "fs_write", "fsWrite"})


KIRO_TOOL_NAMES = frozenset(
    {
        "shell",
        "execute_bash",
        "execute_cmd",
        "read",
        "fs_read",
        "fsRead",
        "write",
        "fs_write",
        "fsWrite",
        "glob",
        "grep",
        "web_search",
        "web_fetch",
        "aws",
        "use_aws",
        "code",
        "knowledge",
        "delegate",
        "subagent",
        "use_subagent",
    }
)


def _kiro_allowed_tool_rules(pattern: str) -> list[NamedTool]:
    """Convert Kiro tool patterns to canonical NamedTool rules.

    Wildcards are expanded against known Kiro tool names so the resulting rules
    use agentperm's canonical namespace (``Read``, ``Write``, …), not Kiro's
    native aliases (``fs_read``, ``fs_write``, …).  Unknown wildcards that
    don't match any known alias are passed through for custom/MCP tools.
    """
    if "?" in pattern or pattern.count("*") > 1 or ("*" in pattern and not pattern.endswith("*")):
        return []
    if "*" not in pattern:
        canonical = kiro_tool_name(pattern)
        return [] if canonical == "Bash" else [NamedTool(canonical)]
    prefix = pattern[:-1]
    seen: set[str] = set()
    result: list[NamedTool] = []
    for kiro_name in sorted(KIRO_TOOL_NAMES):
        if not kiro_name.startswith(prefix):
            continue
        canonical = kiro_tool_name(kiro_name)
        if canonical == "Bash" or canonical in seen:
            continue
        seen.add(canonical)
        result.append(NamedTool(canonical))
    if not result:
        return [NamedTool(pattern)]
    return result


def _kiro_command_rule(pattern: str) -> BashCommand | None:
    """Convert a Kiro allowedCommands/deniedCommands pattern to a BashCommand.

    Kiro uses anchored regex. Only the losslessly representable subset is
    imported: optional outer anchors, a literal command, and an optional trailing
    ``.*`` prefix wildcard. Other regex syntax is skipped rather than silently
    changing the rule's meaning.
    """
    cleaned = pattern
    if cleaned.startswith("\\A"):
        cleaned = cleaned[2:]
    elif cleaned.startswith("^"):
        cleaned = cleaned[1:]
    if cleaned.endswith("\\z"):
        cleaned = cleaned[:-2]
    elif cleaned.endswith("$"):
        cleaned = cleaned[:-1]
    trailing_wild = cleaned.endswith(".*")
    if trailing_wild:
        cleaned = cleaned[:-2]
    # Any remaining regex metacharacter can make the Kiro match broader than the
    # literal BashCommand we would create, which is especially unsafe for denies.
    if not cleaned.strip() or re.search(r"[\\\\.^$*+?()[\]{}|]", cleaned):
        return None
    pipeline = parse_pipeline(cleaned)
    if not pipeline.parseable or len(pipeline.segments) != 1:
        return None
    seg = pipeline.segments[0]
    if not seg.argv or seg.redirects:
        return None
    return BashCommand(seg.argv, trailing_wildcard=trailing_wild)
