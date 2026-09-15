"""Adapter tests — parse_event / write_verdict round-trips, rule round-tripping."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agentperm import (
    AgentName,
    BashCommand,
    BashOption,
    ClaudeAdapter,
    CodexAdapter,
    Decision,
    GeminiAdapter,
    JsonObject,
    NamedTool,
    OpencodeAdapter,
    Policy,
    Segment,
    ShellRequest,
    ToolRequest,
    Verdict,
    parse_rule,
)
from agentperm.adapters import select_adapter
from agentperm.cli import cmd_check, effective_event
from tests.json_support import decode_object, json_at, object_at

# ---- Rule round-trip ------------------------------------------------------


def test_string_rule_round_trip() -> None:
    rule = parse_rule("Bash(git status:*)")
    assert isinstance(rule, BashCommand)
    assert rule.prefix == ("git", "status")
    assert rule.trailing_wildcard is True
    assert rule.serialize() == "Bash(git status:*)"


def test_string_rule_round_trip_with_glob() -> None:
    rule = parse_rule("Bash(pnpm * build:*)")
    assert isinstance(rule, BashCommand)
    assert rule.prefix == ("pnpm", "*", "build")
    assert rule.trailing_wildcard is True
    assert rule.serialize() == "Bash(pnpm * build:*)"


def test_string_rule_round_trip_exact() -> None:
    rule = parse_rule("Bash(git status)")
    assert isinstance(rule, BashCommand)
    assert rule.prefix == ("git", "status")
    assert rule.trailing_wildcard is False
    assert rule.serialize() == "Bash(git status)"


def test_dict_rule_round_trip() -> None:
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


def test_named_tool_rule_round_trip() -> None:
    rule = parse_rule("Read")
    assert rule is not None
    assert rule.serialize() == "Read"


# ---- Claude adapter -------------------------------------------------------


def test_claude_parse_bash_event() -> None:
    adapter = ClaudeAdapter()
    request = adapter.parse_event(
        {"tool_name": "Bash", "tool_input": {"command": "ls -la"}},
        "PreToolUse",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("ls", "-la")


def test_claude_parse_non_bash_tool_event() -> None:
    adapter = ClaudeAdapter()
    request = adapter.parse_event({"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"}}, "PreToolUse")
    assert isinstance(request, ToolRequest)
    assert request.tool == "Read"
    assert ("file_path", "/tmp/x") in request.arguments  # input threaded through for scoping


def test_claude_write_verdict_no_opinion_emits_empty() -> None:
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.NoOpinion, ""), "PreToolUse")
    assert decode_object(buf.getvalue()) == {}


def test_claude_write_verdict_deny_emits_hook_specific_output() -> None:
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Deny, "no sudo"), "PreToolUse")
    payload = decode_object(buf.getvalue())
    assert json_at(payload, "hookSpecificOutput", "permissionDecision") == "deny"
    assert json_at(payload, "hookSpecificOutput", "permissionDecisionReason") == "no sudo"


def test_claude_pretooluse_allow_emits_allow_decision() -> None:
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "by rule"), "PreToolUse")
    payload = decode_object(buf.getvalue())
    assert json_at(payload, "hookSpecificOutput", "permissionDecision") == "allow"
    assert json_at(payload, "hookSpecificOutput", "permissionDecisionReason") == "by rule"


def test_claude_permission_request_emits_allow_behavior() -> None:
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "by rule"), "PermissionRequest")
    payload = decode_object(buf.getvalue())
    assert json_at(payload, "hookSpecificOutput", "decision", "behavior") == "allow"


def test_claude_import_native_rules_skips_bare_bash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "permissions": {
                    "allow": ["Bash", "Read"],
                    "deny": ["Bash"],
                }
            }
        )
    )
    monkeypatch.setattr(ClaudeAdapter, "settings_path", settings)
    rules = list(ClaudeAdapter().import_native_rules())
    names = [(d.value, r.serialize()) for d, r in rules]
    assert ("allow", "Read") in names
    assert not any(s == "Bash" for _, s in names)


# ---- Claude MCP bypass (updatedInput injection) --------------------------


def test_claude_pretooluse_mcp_bypass_injects_approval_policy() -> None:
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    updated: JsonObject = {"prompt": "do stuff", "approval-policy": "never"}
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "bypass"), "PreToolUse", updated_input=updated)
    payload = decode_object(buf.getvalue())
    assert json_at(payload, "hookSpecificOutput", "permissionDecision") == "allow"
    assert json_at(payload, "hookSpecificOutput", "updatedInput") == updated


def test_claude_pretooluse_no_updated_input_omits_key() -> None:
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "ok"), "PreToolUse")
    payload = decode_object(buf.getvalue())
    assert "updatedInput" not in object_at(payload, "hookSpecificOutput")


def test_claude_pretooluse_updated_input_preserves_original_fields() -> None:
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    updated: JsonObject = {"prompt": "hello", "cwd": "/tmp", "approval-policy": "never"}
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "bypass"), "PreToolUse", updated_input=updated)
    payload = decode_object(buf.getvalue())
    ui = json_at(payload, "hookSpecificOutput", "updatedInput")
    assert json_at(ui, "prompt") == "hello"
    assert json_at(ui, "cwd") == "/tmp"
    assert json_at(ui, "approval-policy") == "never"


def test_claude_pretooluse_deny_omits_updated_input() -> None:
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    updated: JsonObject = {"prompt": "hello", "approval-policy": "never"}
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Deny, "blocked"), "PreToolUse", updated_input=updated)
    payload = decode_object(buf.getvalue())
    hook_output = object_at(payload, "hookSpecificOutput")
    assert json_at(hook_output, "permissionDecision") == "deny"
    assert "updatedInput" not in hook_output


def _mcp_bypass_payload(
    *,
    permission_mode: str = "bypassPermissions",
    tool_name: str = "mcp__codex__codex",
) -> JsonObject:
    return {
        "permission_mode": permission_mode,
        "tool_name": tool_name,
        "tool_input": {"prompt": "do stuff", "cwd": "/tmp"},
    }


def test_claude_mcp_bypass_injects_approval_policy_without_policy_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AGENTPERM_TRACE", raising=False)
    monkeypatch.delenv("ZELLIJ_PANE_ID", raising=False)
    monkeypatch.delenv("ZELLIJ_SESSION_NAME", raising=False)
    payload = _mcp_bypass_payload()
    payload["hook_event_name"] = "PreToolUse"
    payload["cwd"] = str(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cmd_check(AgentName.Claude, "PreToolUse")
    assert rc == 0
    output = decode_object(buf.getvalue())
    hook_output = object_at(output, "hookSpecificOutput")
    updated_input = json_at(hook_output, "updatedInput")
    assert json_at(hook_output, "hookEventName") == "PreToolUse"
    assert "permissionDecision" not in hook_output
    assert json_at(updated_input, "approval-policy") == "never"
    assert json_at(updated_input, "prompt") == "do stuff"


def test_claude_mcp_bypass_skips_non_codex_mcp_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-codex MCP tools must not receive approval-policy injection."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AGENTPERM_TRACE", raising=False)
    monkeypatch.delenv("ZELLIJ_PANE_ID", raising=False)
    monkeypatch.delenv("ZELLIJ_SESSION_NAME", raising=False)

    for tool in (
        "mcp__google_workspace__search_gmail_messages",
        "mcp__todoist__find-tasks",
        "mcp__notion__notion-fetch",
    ):
        payload = _mcp_bypass_payload(tool_name=tool)
        payload["hook_event_name"] = "PreToolUse"
        payload["cwd"] = str(tmp_path)
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cmd_check(AgentName.Claude, "PreToolUse")
        assert rc == 0
        assert decode_object(buf.getvalue()) == {}


def test_claude_bypass_defers_entirely(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Under bypassPermissions agentperm does nothing — emits {} so Claude proceeds —
    even for a command that would otherwise prompt (regression: it used to return
    'ask' on unanalyzable wrappers, forcing a prompt in bypass mode)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AGENTPERM_TRACE", raising=False)
    monkeypatch.delenv("ZELLIJ_PANE_ID", raising=False)
    monkeypatch.delenv("ZELLIJ_SESSION_NAME", raising=False)
    base = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "timeout 30 npm test"},
        "cwd": str(tmp_path),
    }

    # bypass → empty {} (defer to Claude)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({**base, "permission_mode": "bypassPermissions"})))
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert cmd_check(AgentName.Claude, "PreToolUse") == 0
    assert decode_object(buf.getvalue()) == {}

    # default mode → still evaluated (the unanalyzable wrapper asks)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({**base, "permission_mode": "default"})))
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert cmd_check(AgentName.Claude, "PreToolUse") == 0
    assert json_at(decode_object(buf.getvalue()), "hookSpecificOutput", "permissionDecision") == "ask"


# ---- Codex adapter --------------------------------------------------------


def test_codex_parse_permission_request_bash() -> None:
    adapter = CodexAdapter()
    request = adapter.parse_event(
        {"permission": {"type": "Bash", "metadata": {"command": "git push"}}},
        "PermissionRequest",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("git", "push")


def test_codex_parse_permission_request_bash_modern_envelope() -> None:
    # Codex CLI 0.128+ delivers PermissionRequest payloads in the same shape as
    # Claude's PreToolUse — ``tool_name`` + ``tool_input.command`` at the top
    # level — rather than the legacy ``permission.metadata.command`` wrapper.
    adapter = CodexAdapter()
    request = adapter.parse_event(
        {
            "session_id": "019dcdb6-2e0a-7982-afda-8717d6346018",
            "turn_id": "019de0dd-f03f-7771-a3eb-a91d169c1793",
            "transcript_path": "/tmp/rollout.jsonl",
            "cwd": "/Users/dev/Code/webapp",
            "hook_event_name": "PermissionRequest",
            "model": "gpt-5.5",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": "git push"},
        },
        "PermissionRequest",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("git", "push")


def test_codex_parse_permission_request_other_tool() -> None:
    adapter = CodexAdapter()
    request = adapter.parse_event(
        {"permission": {"type": "apply_patch", "metadata": {"file_path": "/tmp/x"}}},
        "PermissionRequest",
    )
    assert isinstance(request, ToolRequest)
    assert request.tool == "apply_patch"
    assert ("file_path", "/tmp/x") in request.arguments  # metadata threaded through for scoping


def test_codex_pretooluse_passes_allow_through() -> None:
    # PreToolUse is the deny-fast-path; Allow falls through so PermissionRequest
    # gets the chance to silently approve. Anything other than Deny → empty {}.
    adapter = CodexAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "ok"), "PreToolUse")
    assert decode_object(buf.getvalue()) == {}


def test_codex_pretooluse_emits_deny() -> None:
    adapter = CodexAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Deny, "blocked"), "PreToolUse")
    payload = decode_object(buf.getvalue())
    assert json_at(payload, "hookSpecificOutput", "permissionDecision") == "deny"


def test_codex_yolo_mode_still_blocks_denied_apply_patch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codex code-mode nested tools traverse this same PreToolUse boundary."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AGENTPERM_TRACE", raising=False)
    monkeypatch.delenv("ZELLIJ_PANE_ID", raising=False)
    monkeypatch.delenv("ZELLIJ_SESSION_NAME", raising=False)
    (tmp_path / ".agent-permissions.jsonc").write_text(
        json.dumps(
            {
                "version": 1,
                "permissions": {
                    "deny": [
                        {
                            "Write(generated/**)": {
                                "reason": "Regenerate this file instead of editing it directly."
                            }
                        }
                    ]
                },
            }
        )
    )
    payload = {
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
        "permission_mode": "bypassPermissions",
        "tool_name": "apply_patch",
        "tool_input": {
            "command": "*** Begin Patch\n*** Update File: generated/snapshot.txt\n@@\n-old\n+new\n*** End Patch"
        },
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    buf = io.StringIO()

    with redirect_stdout(buf):
        assert cmd_check(AgentName.Codex, "PreToolUse") == 0

    output = decode_object(buf.getvalue())
    assert json_at(output, "hookSpecificOutput", "permissionDecision") == "deny"
    assert (
        json_at(output, "hookSpecificOutput", "permissionDecisionReason")
        == "Regenerate this file instead of editing it directly."
    )


def test_codex_permission_request_emits_allow_behavior() -> None:
    adapter = CodexAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "approved"), "PermissionRequest")
    payload = decode_object(buf.getvalue())
    assert json_at(payload, "hookSpecificOutput", "decision", "behavior") == "allow"


def test_codex_permission_request_emits_deny_with_message() -> None:
    adapter = CodexAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Deny, "policy says no"), "PermissionRequest")
    payload = decode_object(buf.getvalue())
    assert json_at(payload, "hookSpecificOutput", "decision", "behavior") == "deny"
    assert json_at(payload, "hookSpecificOutput", "decision", "message") == "policy says no"


def test_codex_permission_request_under_pane_bypass_allows_unknown_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end regression: NoOpinion (no policy match) must be coerced to Allow under bypass.

    Codex's ``PermissionRequest.write_verdict`` falls through to ``{}`` on NoOpinion,
    which makes codex prompt — defeating the user's "approve everything" intent. The
    pane-bypass coercion fixes this by lifting both Ask and NoOpinion to Allow.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("ZELLIJ_PANE_ID", "7")
    monkeypatch.setenv("ZELLIJ_SESSION_NAME", "main")
    monkeypatch.delenv("AGENTPERM_TRACE", raising=False)
    bypass = tmp_path / "cache" / "agentperm" / "bypass"
    (bypass / "main").mkdir(parents=True)
    bypass.chmod(0o700)
    (bypass / "main").chmod(0o700)
    (bypass / "main" / "7").touch(mode=0o600)
    payload = {
        "hook_event_name": "PermissionRequest",
        "cwd": str(tmp_path),
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {"command": "totally-unknown-command --flag"},
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cmd_check(AgentName.Codex, "PermissionRequest")
    assert rc == 0
    out = decode_object(buf.getvalue())
    # Codex's PermissionRequest Allow envelope intentionally omits a message;
    # behavior=="allow" is sufficient proof that NoOpinion was coerced (NoOpinion
    # would have produced ``{}`` here, which would make codex prompt).
    assert json_at(out, "hookSpecificOutput", "decision", "behavior") == "allow"


# ---- OpenCode adapter -----------------------------------------------------


def test_opencode_parse_bash_event() -> None:
    adapter = OpencodeAdapter()
    request = adapter.parse_event(
        {"permission": {"type": "bash", "metadata": {"command": "rm -rf /"}}},
        "permission.ask",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("rm", "-rf", "/")


def test_opencode_parse_non_bash_event_threads_arguments() -> None:
    adapter = OpencodeAdapter()
    request = adapter.parse_event(
        {"permission": {"type": "webfetch", "metadata": {"url": "https://github.com/x"}}},
        "permission.ask",
    )
    assert isinstance(request, ToolRequest)
    assert request.tool == "WebFetch"  # canonicalized to match imported/written rule names
    assert ("url", "https://github.com/x") in request.arguments  # metadata threaded through


def test_opencode_write_verdict_emits_status() -> None:
    adapter = OpencodeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Deny, "policy"), "permission.ask")
    payload = decode_object(buf.getvalue())
    assert json_at(payload, "status") == "deny"
    assert json_at(payload, "reason") == "policy"


def test_opencode_no_opinion_emits_empty() -> None:
    adapter = OpencodeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.NoOpinion, ""), "permission.ask")
    assert decode_object(buf.getvalue()) == {}


@pytest.mark.parametrize("action,expected", [("deny", Decision.Deny), ("ask", Decision.Ask), ("allow", Decision.Allow)])
def test_opencode_import_blanket_bash(
    action: str,
    expected: Decision,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "opencode.json"
    config.write_text(json.dumps({"permission": {"bash": action}}))
    monkeypatch.setattr(OpencodeAdapter, "config_path", config)
    rules = list(OpencodeAdapter().import_native_rules())
    assert len(rules) == 1
    decision, rule = rules[0]
    assert decision is expected
    assert isinstance(rule, BashCommand)
    assert rule.matches(Segment(argv=("rm", "-rf", "/"), redirects=()))


def test_opencode_import_preserves_scoped_non_bash_patterns(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Path("/mock/opencode.json")

    def mock_exists(path: Path) -> bool:
        return path == config

    def mock_read_json(_path: Path) -> JsonObject:
        return {
            "permission": {
                "read": {"src/**": "allow"},
                "webfetch": {"domain:github.com": "ask"},
            }
        }

    monkeypatch.setattr(OpencodeAdapter, "config_path", config)
    monkeypatch.setattr(Path, "exists", mock_exists)
    monkeypatch.setattr("agentperm.adapters.opencode.read_json", mock_read_json)

    rules = list(OpencodeAdapter().import_native_rules())

    assert rules == [
        (Decision.Allow, NamedTool("Read", "src/**")),
        (Decision.Ask, NamedTool("WebFetch", "domain:github.com")),
    ]
    policy = Policy(allow=(rules[0][1],), ask=(rules[1][1],))
    assert policy.decide(ToolRequest("Read", (("file_path", "src/main.py"),))).decision is Decision.Allow
    assert policy.decide(ToolRequest("Read", (("file_path", "README.md"),))).decision is Decision.NoOpinion
    assert (
        policy.decide(ToolRequest("WebFetch", (("url", "https://github.com/jacks0n/agentperm"),))).decision
        is Decision.Ask
    )
    assert policy.decide(ToolRequest("WebFetch", (("url", "https://example.com"),))).decision is Decision.NoOpinion


# ---- Gemini adapter -------------------------------------------------------


def test_gemini_parse_shell_event() -> None:
    adapter = GeminiAdapter()
    request = adapter.parse_event(
        {"tool_name": "run_shell_command", "tool_input": {"command": "ls -la"}},
        "BeforeTool",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("ls", "-la")


def test_gemini_parse_read_tool_event() -> None:
    adapter = GeminiAdapter()
    request = adapter.parse_event(
        {"tool_name": "read_file", "tool_input": {"absolute_path": "/tmp/x"}},
        "BeforeTool",
    )
    assert isinstance(request, ToolRequest)
    assert request.tool == "Read"
    assert ("absolute_path", "/tmp/x") in request.arguments  # input threaded through for scoping


def test_gemini_ask_blocks_because_beforetool_cannot_prompt() -> None:
    adapter = GeminiAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Ask, "needs review"), "BeforeTool")
    payload = decode_object(buf.getvalue())
    assert json_at(payload, "decision") == "deny"
    assert json_at(payload, "reason") == "approval required: needs review"


def test_auto_adapter_selects_gemini_from_beforetool_event() -> None:
    payload: JsonObject = {
        "hook_event_name": "BeforeTool",
        "tool_name": "run_shell_command",
        "tool_input": {"command": "ls"},
    }
    event = effective_event("auto", payload)
    adapter = select_adapter(AgentName.Auto, event, payload)
    assert isinstance(adapter, GeminiAdapter)


def test_auto_adapter_selects_claude_permission_request_from_claude_payload() -> None:
    payload: JsonObject = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
    }
    event = effective_event("auto", payload)
    adapter = select_adapter(AgentName.Auto, event, payload)
    assert isinstance(adapter, ClaudeAdapter)


def test_auto_adapter_selects_codex_permission_request_from_codex_payload() -> None:
    payload: JsonObject = {
        "hook_event_name": "PermissionRequest",
        "permission": {"type": "Bash", "metadata": {"command": "ls"}},
    }
    event = effective_event("auto", payload)
    adapter = select_adapter(AgentName.Auto, event, payload)
    assert isinstance(adapter, CodexAdapter)
