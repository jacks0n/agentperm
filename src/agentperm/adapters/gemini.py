"""Gemini CLI adapter."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import ClassVar

from ..domain import (
    AgentName,
    Decision,
    InstallMode,
    JsonObject,
    Request,
    ShellRequest,
    ToolRequest,
    Verdict,
    tool_arguments,
)
from ..shell import parse_pipeline
from .base import (
    AgentAdapter,
    merge_nested_hooks,
    merge_rulesync_hooks,
)


class GeminiAdapter(AgentAdapter):
    name = AgentName.Gemini
    settings_path: ClassVar[Path] = Path.home() / ".gemini/settings.json"

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str):
            return None
        tool_input = payload.get("tool_input")
        if tool_name == "run_shell_command":
            command = tool_input.get("command") if isinstance(tool_input, dict) else None
            return ShellRequest(parse_pipeline(command if isinstance(command, str) else ""))
        return ToolRequest(_gemini_tool_name(tool_name), tool_arguments(tool_input))

    def write_verdict(self, verdict: Verdict, event_name: str) -> int:
        if verdict.decision is Decision.NoOpinion:
            json.dump({}, sys.stdout)
            return 0
        if verdict.decision is Decision.Ask:
            json.dump({"decision": "deny", "reason": f"approval required: {verdict.rationale}"}, sys.stdout)
            return 0
        json.dump({"decision": verdict.decision.value, "reason": verdict.rationale}, sys.stdout)
        return 0

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        # rulesync's ``geminicli.preToolUse`` block is materialised as Gemini's
        # ``BeforeTool`` hook by rulesync itself; the bridge command embedded in
        # the entry uses ``--event BeforeTool`` since that's what Gemini fires
        # at runtime. Direct mode writes the same nested-group shape into
        # ``hooks.BeforeTool`` of ``settings.json`` with the same event arg.
        if mode is InstallMode.Rulesync:
            return merge_rulesync_hooks(
                block="geminicli",
                add=[("preToolUse", "BeforeTool", ".*")],
                strip=[],
                agent_name="gemini",
                dry_run=dry_run,
            )
        return merge_nested_hooks(
            self.settings_path,
            add=[("BeforeTool", ".*")],
            strip=[],
            agent_name="gemini",
            dry_run=dry_run,
        )


def _gemini_tool_name(name: str) -> str:
    return {
        "glob": "Glob",
        "grep_search": "Grep",
        "read_file": "Read",
        "read_many_files": "Read",
        "list_directory": "LS",
        "web_fetch": "WebFetch",
        "google_web_search": "WebSearch",
        "replace": "Edit",
        "write_file": "Write",
    }.get(name, name)


GEMINI_TOOL_NAMES = frozenset(
    {
        "run_shell_command",
        "glob",
        "grep_search",
        "read_file",
        "read_many_files",
        "list_directory",
        "web_fetch",
        "google_web_search",
        "replace",
        "write_file",
    }
)
