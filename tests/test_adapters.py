"""Adapter tests — parse_event / write_verdict round-trips, rule round-tripping."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

from llm_agent_bridge import (
    BashCommand,
    BashOption,
    ClaudeAdapter,
    CodexAdapter,
    Decision,
    OpencodeAdapter,
    ShellRequest,
    ToolRequest,
    Verdict,
    parse_rule,
)

# ---- Rule round-trip ------------------------------------------------------


def test_string_rule_round_trip():
    rule = parse_rule("Bash(git status:*)")
    assert isinstance(rule, BashCommand)
    assert rule.prefix == ("git", "status")
    assert rule.serialize() == "Bash(git status:*)"


def test_dict_rule_round_trip():
    raw = {
        "tool": "Bash",
        "command": ["sed", "gsed"],
        "when": {"hasOption": ["-i", "--in-place"]},
        "reason": "sed in-place editing",
    }
    rule = parse_rule(raw)
    assert isinstance(rule, BashOption)
    assert rule.commands == frozenset({"sed", "gsed"})
    assert rule.options == frozenset({"-i", "--in-place"})
    assert rule.rationale == "sed in-place editing"
    serialized = rule.serialize()
    assert isinstance(serialized, dict)
    assert serialized["tool"] == "Bash"
    commands = serialized["command"]
    assert isinstance(commands, list)
    assert sorted(str(c) for c in commands) == ["gsed", "sed"]


def test_named_tool_rule_round_trip():
    rule = parse_rule("Read")
    assert rule is not None
    assert rule.serialize() == "Read"


# ---- Claude adapter -------------------------------------------------------


def test_claude_parse_bash_event():
    adapter = ClaudeAdapter()
    request = adapter.parse_event(
        {"tool_name": "Bash", "tool_input": {"command": "ls -la"}},
        "PreToolUse",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("ls", "-la")


def test_claude_parse_non_bash_tool_event():
    adapter = ClaudeAdapter()
    request = adapter.parse_event({"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"}}, "PreToolUse")
    assert isinstance(request, ToolRequest)
    assert request.tool == "Read"


def test_claude_write_verdict_no_opinion_emits_empty():
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.NoOpinion, ""), "PreToolUse")
    assert json.loads(buf.getvalue()) == {}


def test_claude_write_verdict_deny_emits_hook_specific_output():
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Deny, "no sudo"), "PreToolUse")
    payload = json.loads(buf.getvalue())
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert payload["hookSpecificOutput"]["permissionDecisionReason"] == "no sudo"


def test_claude_write_verdict_allow_emits_allow():
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "by rule"), "PreToolUse")
    payload = json.loads(buf.getvalue())
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"


# ---- Codex adapter --------------------------------------------------------


def test_codex_parse_permission_request_bash():
    adapter = CodexAdapter()
    request = adapter.parse_event(
        {"permission": {"type": "Bash", "metadata": {"command": "git push"}}},
        "PermissionRequest",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("git", "push")


def test_codex_parse_permission_request_other_tool():
    adapter = CodexAdapter()
    request = adapter.parse_event(
        {"permission": {"type": "apply_patch"}},
        "PermissionRequest",
    )
    assert isinstance(request, ToolRequest)
    assert request.tool == "apply_patch"


def test_codex_pretooluse_emits_only_deny():
    adapter = CodexAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "ok"), "PreToolUse")
    # Allow on PreToolUse should be a no-op; user gets the standard prompt path.
    assert json.loads(buf.getvalue()) == {}


def test_codex_pretooluse_emits_deny():
    adapter = CodexAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Deny, "blocked"), "PreToolUse")
    payload = json.loads(buf.getvalue())
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_permission_request_emits_allow_behavior():
    adapter = CodexAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "approved"), "PermissionRequest")
    payload = json.loads(buf.getvalue())
    assert payload["hookSpecificOutput"]["decision"]["behavior"] == "allow"


def test_codex_permission_request_emits_deny_with_message():
    adapter = CodexAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Deny, "policy says no"), "PermissionRequest")
    payload = json.loads(buf.getvalue())
    assert payload["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    assert payload["hookSpecificOutput"]["decision"]["message"] == "policy says no"


# ---- OpenCode adapter -----------------------------------------------------


def test_opencode_parse_bash_event():
    adapter = OpencodeAdapter()
    request = adapter.parse_event(
        {"permission": {"type": "bash", "metadata": {"command": "rm -rf /"}}},
        "permission.ask",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("rm", "-rf", "/")


def test_opencode_write_verdict_emits_status():
    adapter = OpencodeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Deny, "policy"), "permission.ask")
    payload = json.loads(buf.getvalue())
    assert payload["status"] == "deny"
    assert payload["reason"] == "policy"


def test_opencode_no_opinion_emits_empty():
    adapter = OpencodeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.NoOpinion, ""), "permission.ask")
    assert json.loads(buf.getvalue()) == {}
