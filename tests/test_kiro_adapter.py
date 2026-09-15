"""Adapter tests — parse_event / write_verdict round-trips, rule round-tripping."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import agentperm
from agentperm import (
    AgentName,
    BashCommand,
    ClaudeAdapter,
    Decision,
    InstallMode,
    JsonObject,
    JsonValue,
    KiroAdapter,
    NamedTool,
    Policy,
    ShellRequest,
    ToolRequest,
    Verdict,
    parse_rule,
)
from agentperm.adapters import select_adapter
from agentperm.adapters.kiro import kiro_tool_name
from agentperm.cli import cmd_check, effective_event
from tests.json_support import array_at, decode_object, json_at, text_at

# ---- End-to-end glob matching through Claude PreToolUse ------------------


def test_claude_pretooluse_allows_pnpm_dir_build_via_glob() -> None:
    rule = parse_rule("Bash(pnpm --dir * build:*)")
    assert isinstance(rule, BashCommand)
    policy = Policy(allow=(rule,))
    request = ClaudeAdapter().parse_event(
        {"tool_name": "Bash", "tool_input": {"command": "pnpm --dir web-overlay/client build"}},
        "PreToolUse",
    )
    assert isinstance(request, ShellRequest)
    assert policy.decide(request).decision is Decision.Allow


def test_claude_pretooluse_no_match_when_subcommand_differs() -> None:
    rule = parse_rule("Bash(pnpm --dir * build:*)")
    assert isinstance(rule, BashCommand)
    policy = Policy(allow=(rule,))
    request = ClaudeAdapter().parse_event(
        {"tool_name": "Bash", "tool_input": {"command": "pnpm --dir web-overlay/client install"}},
        "PreToolUse",
    )
    assert isinstance(request, ShellRequest)
    assert policy.decide(request).decision is Decision.NoOpinion


# ---- Kiro adapter ---------------------------------------------------------


def test_kiro_parse_shell_event() -> None:
    adapter = KiroAdapter()
    request = adapter.parse_event(
        {"tool_name": "shell", "tool_input": {"command": "ls -la"}},
        "preToolUse",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("ls", "-la")


def test_kiro_parse_execute_bash_alias() -> None:
    adapter = KiroAdapter()
    request = adapter.parse_event(
        {"tool_name": "execute_bash", "tool_input": {"command": "git status"}},
        "preToolUse",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("git", "status")


def test_kiro_parse_execute_cmd_alias() -> None:
    adapter = KiroAdapter()
    request = adapter.parse_event(
        {"tool_name": "execute_cmd", "tool_input": {"command": "npm test"}},
        "preToolUse",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("npm", "test")


def test_kiro_parse_read_tool() -> None:
    adapter = KiroAdapter()
    request = adapter.parse_event(
        {"tool_name": "read", "tool_input": {"operations": [{"mode": "Line", "path": "/tmp/x"}]}},
        "preToolUse",
    )
    assert isinstance(request, ToolRequest)
    assert request.tool == "Read"
    assert ("path", "/tmp/x") in request.arguments


def test_kiro_parse_grep_tool() -> None:
    adapter = KiroAdapter()
    request = adapter.parse_event(
        {"tool_name": "grep", "tool_input": {"pattern": "TODO", "path": "/src"}},
        "preToolUse",
    )
    assert isinstance(request, ToolRequest)
    assert request.tool == "Grep"


def test_kiro_parse_web_fetch_tool() -> None:
    adapter = KiroAdapter()
    request = adapter.parse_event(
        {"tool_name": "web_fetch", "tool_input": {"url": "https://example.com"}},
        "preToolUse",
    )
    assert isinstance(request, ToolRequest)
    assert request.tool == "WebFetch"
    assert ("url", "https://example.com") in request.arguments


def test_kiro_parse_mcp_tool_passthrough() -> None:
    adapter = KiroAdapter()
    request = adapter.parse_event(
        {"tool_name": "@git/git_status", "tool_input": {}},
        "preToolUse",
    )
    assert isinstance(request, ToolRequest)
    assert request.tool == "@git/git_status"


def test_kiro_parse_missing_tool_name() -> None:
    adapter = KiroAdapter()
    assert adapter.parse_event({"tool_input": {"command": "ls"}}, "preToolUse") is None


@pytest.mark.parametrize(
    "tool_input",
    [
        None,
        "not a dict",
        {"other_key": "value"},
        {"command": ""},
        {"command": 42},
    ],
)
def test_kiro_shell_with_missing_or_bad_command_is_unparseable(tool_input: JsonValue) -> None:
    adapter = KiroAdapter()
    request = adapter.parse_event({"tool_name": "shell", "tool_input": tool_input}, "preToolUse")
    assert isinstance(request, ShellRequest)
    assert not request.pipeline.parseable


def test_kiro_write_verdict_allow(capsys: pytest.CaptureFixture[str]) -> None:
    adapter = KiroAdapter()
    rc = adapter.write_verdict(Verdict(Decision.Allow, "allowed by rule"), "preToolUse")
    assert rc == 0
    out = decode_object(capsys.readouterr().out)
    assert text_at(out, "hookSpecificOutput", "permissionDecision") == "allow"
    assert text_at(out, "hookSpecificOutput", "permissionDecisionReason") == "allowed by rule"


def test_kiro_write_verdict_no_opinion(capsys: pytest.CaptureFixture[str]) -> None:
    adapter = KiroAdapter()
    rc = adapter.write_verdict(Verdict(Decision.NoOpinion, ""), "preToolUse")
    assert rc == 0
    out = decode_object(capsys.readouterr().out)
    assert out == {}


def test_kiro_write_verdict_deny(capsys: pytest.CaptureFixture[str]) -> None:
    adapter = KiroAdapter()
    rc = adapter.write_verdict(
        Verdict(Decision.Deny, "deny by rule 'Bash(rm -rf:*)'"),
        "preToolUse",
    )
    assert rc == 0
    out = decode_object(capsys.readouterr().out)
    assert text_at(out, "hookSpecificOutput", "permissionDecision") == "deny"
    assert "deny by rule" in text_at(out, "hookSpecificOutput", "permissionDecisionReason")


def test_kiro_write_verdict_ask(capsys: pytest.CaptureFixture[str]) -> None:
    adapter = KiroAdapter()
    rc = adapter.write_verdict(Verdict(Decision.Ask, "needs approval"), "preToolUse")
    assert rc == 0
    out = decode_object(capsys.readouterr().out)
    assert text_at(out, "hookSpecificOutput", "permissionDecision") == "ask"
    assert "needs approval" in text_at(out, "hookSpecificOutput", "permissionDecisionReason")


def test_kiro_tool_name_mapping() -> None:
    assert kiro_tool_name("shell") == "Bash"
    assert kiro_tool_name("execute_bash") == "Bash"
    assert kiro_tool_name("execute_cmd") == "Bash"
    assert kiro_tool_name("read") == "Read"
    assert kiro_tool_name("fs_read") == "Read"
    assert kiro_tool_name("fsRead") == "Read"
    assert kiro_tool_name("write") == "Write"
    assert kiro_tool_name("fs_write") == "Write"
    assert kiro_tool_name("fsWrite") == "Write"
    assert kiro_tool_name("glob") == "Glob"
    assert kiro_tool_name("grep") == "Grep"
    assert kiro_tool_name("web_search") == "WebSearch"
    assert kiro_tool_name("web_fetch") == "WebFetch"
    assert kiro_tool_name("aws") == "AWS"
    assert kiro_tool_name("use_aws") == "AWS"
    assert kiro_tool_name("code") == "Code"
    assert kiro_tool_name("knowledge") == "Knowledge"
    assert kiro_tool_name("delegate") == "Delegate"
    assert kiro_tool_name("subagent") == "Subagent"
    assert kiro_tool_name("use_subagent") == "Subagent"
    assert kiro_tool_name("@git/status") == "@git/status"  # MCP passthrough
    assert kiro_tool_name("unknown_tool") == "unknown_tool"  # unknown passthrough


def test_auto_adapter_selects_kiro_from_kiro_tool_names() -> None:
    payload: JsonObject = {
        "hook_event_name": "preToolUse",
        "tool_name": "shell",
        "tool_input": {"command": "ls"},
    }
    event = effective_event("auto", payload)
    adapter = select_adapter(AgentName.Auto, event, payload)
    assert isinstance(adapter, KiroAdapter)


def test_auto_adapter_selects_kiro_for_read_tool() -> None:
    payload: JsonObject = {
        "hook_event_name": "preToolUse",
        "tool_name": "read",
        "tool_input": {"path": "/tmp/x"},
    }
    event = effective_event("auto", payload)
    adapter = select_adapter(AgentName.Auto, event, payload)
    assert isinstance(adapter, KiroAdapter)


@pytest.mark.parametrize("tool_name", ["glob", "web_fetch"])
def test_auto_adapter_prefers_kiro_event_for_shared_tool_names(tool_name: str) -> None:
    payload: JsonObject = {
        "hook_event_name": "preToolUse",
        "tool_name": tool_name,
        "tool_input": {},
    }
    event = effective_event("auto", payload)
    adapter = select_adapter(AgentName.Auto, event, payload)
    assert isinstance(adapter, KiroAdapter)


# ---- Install: Kiro --------------------------------------------------------


def test_kiro_install_writes_hook_file(fake_home: Path) -> None:
    paths = KiroAdapter().install(InstallMode.Direct)
    hook_path = fake_home / ".kiro/hooks/agentperm.json"
    assert paths == [hook_path]
    assert not (fake_home / ".kiro/agents/kiro_default.json").exists()
    # v3/IDE standalone hook file
    data = decode_object(hook_path.read_text())
    assert json_at(data, "version") == "v1"
    assert len(array_at(data, "hooks")) == 1
    hook = json_at(data, "hooks", 0)
    assert json_at(hook, "name") == "agentperm"
    assert json_at(hook, "trigger") == "PreToolUse"
    assert json_at(hook, "matcher") == ".*"
    assert "--agent kiro" in text_at(hook, "action", "command")
    assert "--event preToolUse" in text_at(hook, "action", "command")
    assert json_at(hook, "timeout") == 30
    assert json_at(hook, "enabled") is True


def test_kiro_install_idempotent(fake_home: Path) -> None:
    assert KiroAdapter().install(InstallMode.Direct) != []
    assert KiroAdapter().install(InstallMode.Direct) == []


def test_kiro_install_updates_all_existing_v2_agents(fake_home: Path) -> None:
    agents_dir = fake_home / ".kiro/agents"
    agents_dir.mkdir(parents=True)
    custom = agents_dir / "reviewer.json"
    custom.write_text(json.dumps({"name": "reviewer", "description": "Review agent"}))

    paths = KiroAdapter().install(InstallMode.Direct)

    assert custom in paths
    data = decode_object(custom.read_text())
    [hook] = array_at(data, "hooks", "preToolUse")
    assert json_at(hook, "matcher") == "*"
    assert "--agent kiro" in text_at(hook, "command")


def test_kiro_install_updates_current_workspace_agents(fake_home: Path) -> None:
    workspace_agent = fake_home / "workspace/.kiro/agents/reviewer.json"
    workspace_agent.parent.mkdir(parents=True)
    workspace_agent.write_text(json.dumps({"name": "reviewer"}))

    paths = KiroAdapter().install(InstallMode.Direct)

    assert workspace_agent in paths
    [hook] = array_at(decode_object(workspace_agent.read_text()), "hooks", "preToolUse")
    assert json_at(hook, "matcher") == "*"
    assert "--agent kiro" in text_at(hook, "command")


def test_kiro_install_does_not_create_reserved_builtin_agent(fake_home: Path) -> None:
    KiroAdapter().install(InstallMode.Direct)
    assert not (fake_home / ".kiro/agents/kiro_default.json").exists()


def test_kiro_install_and_import_honor_kiro_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    kiro_home = tmp_path / "profile"
    monkeypatch.setenv("KIRO_HOME", str(kiro_home))
    monkeypatch.setattr(KiroAdapter, "hooks_path", None)
    monkeypatch.setattr(KiroAdapter, "agents_path", None)
    agents_dir = kiro_home / "agents"
    agents_dir.mkdir(parents=True)
    agent_path = agents_dir / "custom.json"
    agent_path.write_text(json.dumps({"allowedTools": ["read"]}))

    paths = KiroAdapter().install(InstallMode.Direct)
    rules = list(KiroAdapter().import_native_rules())

    assert kiro_home / "hooks/agentperm.json" in paths
    assert agent_path in paths
    assert any(isinstance(rule, NamedTool) and rule.name == "Read" for _, rule in rules)


def test_kiro_install_works_in_rulesync_mode(fake_home: Path) -> None:
    # Kiro always installs directly (no rulesync schema), same as OpenCode.
    paths = KiroAdapter().install(InstallMode.Rulesync)
    assert (fake_home / ".kiro/hooks/agentperm.json") in paths


def test_kiro_install_dry_run_writes_nothing(fake_home: Path) -> None:
    KiroAdapter().install(InstallMode.Direct, dry_run=True)
    assert not (fake_home / ".kiro/hooks/agentperm.json").exists()
    assert not (fake_home / ".kiro/agents/kiro_default.json").exists()


# ---- Import: Kiro ---------------------------------------------------------


def test_kiro_import_allowed_tools(fake_home: Path) -> None:
    agents_dir = fake_home / ".kiro/agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "default.json").write_text(json.dumps({"allowedTools": ["read", "grep", "@git/git_status"]}))
    rules = list(KiroAdapter().import_native_rules())
    decisions = {(d.value, r.name) for d, r in rules if isinstance(r, NamedTool)}
    assert ("allow", "Read") in decisions
    assert ("allow", "Grep") in decisions
    assert ("allow", "@git/git_status") in decisions


def test_kiro_import_skips_shell_in_allowed_tools(fake_home: Path) -> None:
    agents_dir = fake_home / ".kiro/agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "default.json").write_text(json.dumps({"allowedTools": ["shell", "execute_bash", "read"]}))
    rules = list(KiroAdapter().import_native_rules())
    # shell/execute_bash should be skipped (too broad)
    tools = [r.name for _, r in rules if isinstance(r, NamedTool)]
    assert "Bash" not in tools
    assert "Read" in tools


def test_kiro_import_skips_unrepresentable_allowed_tool_wildcards(fake_home: Path) -> None:
    agents_dir = fake_home / ".kiro/agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "default.json").write_text(json.dumps({"allowedTools": ["code_*", "*_bash", "?ead", "@git/read_*"]}))
    tools = [r.name for _, r in KiroAdapter().import_native_rules() if isinstance(r, NamedTool)]
    assert tools == ["code_*", "@git/read_*"]


def test_kiro_import_expands_known_wildcard_aliases(fake_home: Path) -> None:
    agents_dir = fake_home / ".kiro/agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "default.json").write_text(json.dumps({"allowedTools": ["fs_*"]}))
    rules = list(KiroAdapter().import_native_rules())
    tools = sorted(r.name for _, r in rules if isinstance(r, NamedTool))
    assert tools == ["Read", "Write"]


def test_kiro_import_shell_commands(fake_home: Path) -> None:
    agents_dir = fake_home / ".kiro/agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "default.json").write_text(
        json.dumps(
            {
                "toolsSettings": {
                    "shell": {
                        "allowedCommands": ["git status", "git fetch"],
                        "deniedCommands": ["git push.*"],
                    }
                }
            }
        )
    )
    rules = list(KiroAdapter().import_native_rules())
    allow_rules = [(d, r) for d, r in rules if d is Decision.Allow]
    deny_rules = [(d, r) for d, r in rules if d is Decision.Deny]
    assert len(allow_rules) == 2
    assert all(isinstance(r, BashCommand) for _, r in allow_rules)
    assert len(deny_rules) == 1
    assert isinstance(deny_rules[0][1], BashCommand)
    assert deny_rules[0][1].prefix == ("git", "push")
    assert deny_rules[0][1].trailing_wildcard is True


def test_kiro_import_keeps_single_command_regex_exact(fake_home: Path) -> None:
    agents_dir = fake_home / ".kiro/agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "default.json").write_text(json.dumps({"toolsSettings": {"shell": {"allowedCommands": ["pytest"]}}}))
    [(_, rule)] = list(KiroAdapter().import_native_rules())
    assert isinstance(rule, BashCommand)
    assert rule.prefix == ("pytest",)
    assert rule.trailing_wildcard is False


def test_kiro_import_skips_complex_regex(fake_home: Path) -> None:
    agents_dir = fake_home / ".kiro/agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "default.json").write_text(
        json.dumps(
            {
                "toolsSettings": {
                    "shell": {
                        "allowedCommands": ["git (commit|push).*"],
                    }
                }
            }
        )
    )
    rules = list(KiroAdapter().import_native_rules())
    assert rules == []


@pytest.mark.parametrize(
    "pattern",
    [r"\Agit\s+push.*\z", "git status.?", r"rm\s+-rf.*", "git [a-z]+.*"],
)
def test_kiro_import_skips_complex_regex_that_is_valid_shell_syntax(
    fake_home: Path,
    pattern: str,
) -> None:
    agents_dir = fake_home / ".kiro/agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "default.json").write_text(json.dumps({"toolsSettings": {"shell": {"deniedCommands": [pattern]}}}))
    assert list(KiroAdapter().import_native_rules()) == []


# ---- End-to-end: Kiro check with structured verdicts ---------------------


def test_kiro_check_deny_outputs_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """agentperm check --agent kiro outputs deny verdict as JSON on stdout."""
    policy_path = tmp_path / ".agent-permissions.jsonc"
    policy_path.write_text(json.dumps({"version": 1, "permissions": {"deny": ["Bash(rm -rf:*)"]}}))
    monkeypatch.setattr(agentperm, "POLICY_FILENAME", ".agent-permissions.jsonc")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    payload = json.dumps({"tool_name": "shell", "tool_input": {"command": "rm -rf /"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    rc = cmd_check(AgentName.Kiro, "preToolUse")
    assert rc == 0
    out = decode_object(capsys.readouterr().out)
    assert text_at(out, "hookSpecificOutput", "permissionDecision") == "deny"


def test_kiro_check_allow_returns_exit_code_0(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """agentperm check --agent kiro returns exit code 0 for allowed commands."""
    policy_path = tmp_path / ".agent-permissions.jsonc"
    policy_path.write_text(json.dumps({"version": 1, "permissions": {"allow": ["Bash(cat:*)"]}}))
    monkeypatch.setattr(agentperm, "POLICY_FILENAME", ".agent-permissions.jsonc")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    payload = json.dumps({"tool_name": "shell", "tool_input": {"command": "cat foo.txt"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    rc = cmd_check(AgentName.Kiro, "preToolUse")
    assert rc == 0
