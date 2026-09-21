"""Host-independent MCP permission requests and rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .model import JsonObject, Request, Rule, ToolArguments, serialize_rule_metadata


@dataclass(frozen=True)
class McpToolRequest(Request):
    """An MCP tool invocation after adapter-specific name decoding."""

    server: str
    tool: str
    arguments: ToolArguments = ()
    cwd: Path | None = None


@dataclass(frozen=True)
class McpToolRule(Rule):
    """A glob over the two components of a canonical MCP identity."""

    server_pattern: str
    tool_pattern: str
    rationale: str = field(default="", compare=False)

    def matches(self, server: str, tool: str) -> bool:
        from ..mcppattern import matches_identifier_pattern

        return matches_identifier_pattern(self.server_pattern, server) and matches_identifier_pattern(
            self.tool_pattern, tool
        )

    def serialize(self) -> str | JsonObject:
        target = "*" if self.server_pattern == self.tool_pattern == "*" else (
            f"{self.server_pattern}.{self.tool_pattern}"
        )
        return serialize_rule_metadata(f"MCP({target})", self.rationale)
