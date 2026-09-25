"""Parsing and matching for canonical ``MCP(server.tool)`` policy rules."""

from __future__ import annotations

import re
from functools import lru_cache

from .config import MCP_PATTERN_CACHE_SIZE
from .domain.mcp import McpToolRule
from .errors import PolicyError


def parse_mcp_rule(text: str) -> McpToolRule:
    if not text.endswith(")"):
        raise PolicyError(f"malformed MCP rule (missing closing parenthesis): {text!r}")
    target = text[4:-1]
    if target == "*":
        return McpToolRule("*", "*")
    boundary = _identity_boundary(target)
    if boundary is None:
        raise PolicyError("MCP rules must be MCP(*), MCP(server.*), or MCP(server.tool-pattern)")
    server_pattern = target[:boundary]
    tool_pattern = target[boundary + 1 :]
    if not server_pattern or not tool_pattern:
        raise PolicyError("MCP server and tool patterns must both be non-empty")
    _compile_identifier_pattern(server_pattern)
    _compile_identifier_pattern(tool_pattern)
    return McpToolRule(server_pattern, tool_pattern)


def matches_identifier_pattern(pattern: str, value: str) -> bool:
    return _compile_identifier_pattern(pattern).fullmatch(value) is not None


def _identity_boundary(target: str) -> int | None:
    escaped = False
    depth = 0
    for index, character in enumerate(target):
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                raise PolicyError("unmatched '}' in MCP pattern")
        elif character == "." and depth == 0:
            return index
    if escaped:
        raise PolicyError("trailing escape in MCP pattern")
    if depth:
        raise PolicyError("unclosed '{' in MCP pattern")
    return None


@lru_cache(maxsize=MCP_PATTERN_CACHE_SIZE)
def _compile_identifier_pattern(pattern: str) -> re.Pattern[str]:
    regex, index = _compile_sequence(pattern, 0, stop=frozenset())
    if index != len(pattern):
        raise PolicyError(f"unexpected {pattern[index]!r} in MCP pattern")
    return re.compile(regex)


def _compile_sequence(pattern: str, index: int, *, stop: frozenset[str]) -> tuple[str, int]:
    parts: list[str] = []
    while index < len(pattern):
        character = pattern[index]
        if character in stop:
            break
        if character == "\\":
            index += 1
            if index >= len(pattern):
                raise PolicyError("trailing escape in MCP pattern")
            if pattern[index] not in r".*{},\\":
                raise PolicyError(f"unsupported escape \\{pattern[index]} in MCP pattern")
            parts.append(re.escape(pattern[index]))
        elif character == "*":
            parts.append(".*")
        elif character == "{":
            alternative, index = _compile_alternatives(pattern, index + 1)
            parts.append(alternative)
            continue
        elif character == "}":
            raise PolicyError("unmatched '}' in MCP pattern")
        else:
            parts.append(re.escape(character))
        index += 1
    return "".join(parts), index


def _compile_alternatives(pattern: str, index: int) -> tuple[str, int]:
    alternatives: list[str] = []
    while True:
        alternative, index = _compile_sequence(pattern, index, stop=frozenset({",", "}"}))
        if not alternative:
            raise PolicyError("empty alternative in MCP pattern")
        alternatives.append(alternative)
        if index >= len(pattern):
            raise PolicyError("unclosed '{' in MCP pattern")
        if pattern[index] == "}":
            if len(alternatives) < 2:
                raise PolicyError("MCP alternatives require at least two choices")
            return f"(?:{'|'.join(alternatives)})", index + 1
        index += 1
