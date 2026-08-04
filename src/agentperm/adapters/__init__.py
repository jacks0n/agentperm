"""Public adapter registry and automatic adapter selection."""

from __future__ import annotations

from ..domain import AgentName, JsonObject
from .base import AgentAdapter
from .claude import ClaudeAdapter
from .codex import CodexAdapter
from .gemini import GEMINI_TOOL_NAMES, GeminiAdapter
from .kiro import KIRO_TOOL_NAMES, KiroAdapter
from .opencode import OpencodeAdapter

ADAPTERS: dict[AgentName, AgentAdapter] = {
    AgentName.Claude: ClaudeAdapter(),
    AgentName.Codex: CodexAdapter(),
    AgentName.Opencode: OpencodeAdapter(),
    AgentName.Gemini: GeminiAdapter(),
    AgentName.Kiro: KiroAdapter(),
}


def select_adapter(agent: AgentName, event: str, payload: JsonObject) -> AgentAdapter:
    if agent is not AgentName.Auto:
        return ADAPTERS[agent]
    # Kiro's hook event names are lower camel case. Prefer this unambiguous
    # signal before inspecting tool names shared with Gemini (for example
    # ``glob`` and ``web_fetch``).
    if event in ("preToolUse", "postToolUse"):
        return ADAPTERS[AgentName.Kiro]
    if event in ("BeforeTool", "AfterTool"):
        return ADAPTERS[AgentName.Gemini]
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name in GEMINI_TOOL_NAMES:
        return ADAPTERS[AgentName.Gemini]
    if isinstance(tool_name, str) and tool_name in KIRO_TOOL_NAMES:
        return ADAPTERS[AgentName.Kiro]
    if event == "PermissionRequest" and isinstance(payload.get("permission"), dict):
        return ADAPTERS[AgentName.Codex]
    if event == "PermissionRequest":
        return ADAPTERS[AgentName.Claude]
    if event in ("permission.ask", "permission.asked"):
        return ADAPTERS[AgentName.Opencode]
    return ADAPTERS[AgentName.Claude]


__all__ = [
    "ADAPTERS",
    "AgentAdapter",
    "ClaudeAdapter",
    "CodexAdapter",
    "GeminiAdapter",
    "KiroAdapter",
    "OpencodeAdapter",
    "select_adapter",
]
