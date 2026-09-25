"""Public adapter registry and automatic adapter selection."""

from __future__ import annotations

from ..domain import AgentName, JsonObject, agent_tool_names
from .base import AgentAdapter
from .claude import ClaudeAdapter
from .codex import CodexAdapter
from .gemini import GeminiAdapter
from .kiro import KiroAdapter
from .opencode import OpencodeAdapter

_GEMINI_TOOL_NAMES = agent_tool_names(AgentName.Gemini)
_KIRO_TOOL_NAMES = agent_tool_names(AgentName.Kiro)

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
    # ``glob`` and ``web_fetch``). Shared names resolve identically either way.
    if event in ("preToolUse", "postToolUse"):
        return ADAPTERS[AgentName.Kiro]
    if event in ("BeforeTool", "AfterTool"):
        return ADAPTERS[AgentName.Gemini]
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name in _GEMINI_TOOL_NAMES:
        return ADAPTERS[AgentName.Gemini]
    if isinstance(tool_name, str) and tool_name in _KIRO_TOOL_NAMES:
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
