"""Permission policy mediator for Claude Code, Codex, OpenCode, Gemini CLI, and Kiro.

Package layout:
    agentperm.domain    — Decision, Verdict, Rule, Request, Pipeline, Segment, Policy
    agentperm.shell     — Tree-sitter Bash → Pipeline
    agentperm.pythoncode — shallow AST analysis for inline Python
    agentperm.rules     — string/dict ↔ Rule
    agentperm.policy    — file ↔ Policy, bundled templates
    agentperm.validate  — policy linting
    agentperm.adapters  — AgentAdapter ABC + Claude/Codex/Opencode/Gemini/Kiro
    agentperm.cli       — install, uninstall, import, init, validate, why, check, edit
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
    CompoundRequest,
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
    PythonSqlPattern,
    RedirectionPolicy,
    RejectedRequest,
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
from .policy import (
    DEFAULT_TEMPLATES,
    PolicyFile,
    Template,
    TemplateMerge,
    available_templates,
    existing_policy_paths,
    git_toplevel,
    load_policy_file,
    load_policy_layer,
    load_template,
    merge_templates_into,
    merged_policy,
    parse_policy_text,
    render_templates,
    resolve_policy_paths,
    save_policy_file,
    write_default_policy,
)
from .rules import parse_rule
from .shell import parse_pipeline
from .sql import CapturedSql, SqlDialect, SqlDocumentFormat, SqlEffect, SqlPolicyService, SqlRequest, SqlRule
from .validate import Finding, validate_policy_file, validate_policy_text

__all__ = [
    "ADAPTERS",
    "DEFAULT_TEMPLATES",
    "POLICY_FILENAME",
    "AgentAdapter",
    "AgentName",
    "BashCommand",
    "BashOption",
    "CapturedSql",
    "ClaudeAdapter",
    "CodexAdapter",
    "CompoundRequest",
    "Decision",
    "Finding",
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
    "PythonSqlPattern",
    "RedirectionPolicy",
    "RejectedRequest",
    "Request",
    "Rule",
    "Segment",
    "ShellPattern",
    "ShellRequest",
    "SqlDialect",
    "SqlDocumentFormat",
    "SqlEffect",
    "SqlPolicyService",
    "SqlRequest",
    "SqlRule",
    "Template",
    "TemplateMerge",
    "ToolRequest",
    "Verdict",
    "agentperm_bypass_dir",
    "aggregate",
    "available_templates",
    "coerce_for_pane_bypass",
    "coerce_for_permission_mode",
    "existing_policy_paths",
    "git_toplevel",
    "load_policy_file",
    "load_policy_layer",
    "load_template",
    "main",
    "merge_templates_into",
    "merged_policy",
    "narrow_json",
    "parse_pipeline",
    "parse_policy_text",
    "parse_rule",
    "render_templates",
    "resolve_policy_paths",
    "save_policy_file",
    "validate_policy_file",
    "validate_policy_text",
    "write_default_policy",
]
