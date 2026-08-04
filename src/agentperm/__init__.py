"""Permission policy mediator for Claude Code, Codex, OpenCode, Gemini CLI, and Kiro.

Package layout:
    agentperm.domain    — Decision, Verdict, Rule, Request, Pipeline, Segment, Policy
    agentperm.shell     — Tree-sitter Bash → Pipeline
    agentperm.pythoncode — shallow AST analysis for inline Python
    agentperm.rules     — string/dict ↔ Rule
    agentperm.policy    — file ↔ Policy
    agentperm.adapters  — AgentAdapter ABC + Claude/Codex/Opencode/Gemini/Kiro
    agentperm.cli       — import, check, edit, install
"""

from __future__ import annotations

from .adapters import ADAPTERS, ClaudeAdapter, CodexAdapter, GeminiAdapter, KiroAdapter, OpencodeAdapter
from .adapters.base import AgentAdapter
from .cli import agentperm_bypass_dir, coerce_for_pane_bypass, coerce_for_permission_mode, main
from .domain import (
    POLICY_FILENAME,
    AgentName,
    BashCommand,
    BashOption,
    Decision,
    InstallMode,
    JsonArray,
    JsonObject,
    JsonValue,
    NamedTool,
    Pipeline,
    Policy,
    PythonCallPolicy,
    PythonReadonly,
    RedirectionPolicy,
    Request,
    Rule,
    Segment,
    ShellPattern,
    ShellRequest,
    ToolRequest,
    Verdict,
    aggregate,
    narrow_json,
)
from .errors import PolicyError
from .policy import PolicyFile, git_toplevel, load_policy_file, merged_policy, save_policy_file, write_default_policy
from .rules import parse_rule
from .shell import parse_pipeline

__all__ = [
    "ADAPTERS",
    "POLICY_FILENAME",
    "AgentAdapter",
    "AgentName",
    "BashCommand",
    "BashOption",
    "ClaudeAdapter",
    "CodexAdapter",
    "Decision",
    "GeminiAdapter",
    "InstallMode",
    "JsonArray",
    "JsonObject",
    "JsonValue",
    "KiroAdapter",
    "NamedTool",
    "OpencodeAdapter",
    "Pipeline",
    "Policy",
    "PolicyError",
    "PolicyFile",
    "PythonCallPolicy",
    "PythonReadonly",
    "RedirectionPolicy",
    "Request",
    "Rule",
    "Segment",
    "ShellPattern",
    "ShellRequest",
    "ToolRequest",
    "Verdict",
    "agentperm_bypass_dir",
    "aggregate",
    "coerce_for_pane_bypass",
    "coerce_for_permission_mode",
    "git_toplevel",
    "load_policy_file",
    "main",
    "merged_policy",
    "narrow_json",
    "parse_pipeline",
    "parse_rule",
    "save_policy_file",
    "write_default_policy",
]
