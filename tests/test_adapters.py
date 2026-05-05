"""Adapter tests — parse_event / write_verdict round-trips, rule round-tripping."""

from __future__ import annotations

import io
import json
import shutil
from contextlib import redirect_stdout
from pathlib import Path

import pytest
import tomlkit

import agentperms
from agentperms import (
    AgentName,
    BashCommand,
    BashOption,
    ClaudeAdapter,
    CodexAdapter,
    Decision,
    GeminiAdapter,
    InstallMode,
    JsonObject,
    OpencodeAdapter,
    ShellRequest,
    ToolRequest,
    Verdict,
    _effective_event,  # pyright: ignore[reportPrivateUsage]
    _is_bridge_hook,  # pyright: ignore[reportPrivateUsage]
    _resolve_install_mode,  # pyright: ignore[reportPrivateUsage]
    _select_adapter,  # pyright: ignore[reportPrivateUsage]
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


def test_claude_pretooluse_allow_emits_allow_decision():
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "by rule"), "PreToolUse")
    payload = json.loads(buf.getvalue())
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert payload["hookSpecificOutput"]["permissionDecisionReason"] == "by rule"


def test_claude_permission_request_emits_allow_behavior():
    adapter = ClaudeAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "by rule"), "PermissionRequest")
    payload = json.loads(buf.getvalue())
    assert payload["hookSpecificOutput"]["decision"]["behavior"] == "allow"


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


def test_codex_pretooluse_passes_allow_through():
    # PreToolUse is the deny-fast-path; Allow falls through so PermissionRequest
    # gets the chance to silently approve. Anything other than Deny → empty {}.
    adapter = CodexAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Allow, "ok"), "PreToolUse")
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


# ---- Gemini adapter -------------------------------------------------------


def test_gemini_parse_shell_event():
    adapter = GeminiAdapter()
    request = adapter.parse_event(
        {"tool_name": "run_shell_command", "tool_input": {"command": "ls -la"}},
        "BeforeTool",
    )
    assert isinstance(request, ShellRequest)
    assert request.pipeline.segments[0].argv == ("ls", "-la")


def test_gemini_parse_read_tool_event():
    adapter = GeminiAdapter()
    request = adapter.parse_event(
        {"tool_name": "read_file", "tool_input": {"absolute_path": "/tmp/x"}},
        "BeforeTool",
    )
    assert isinstance(request, ToolRequest)
    assert request.tool == "Read"


def test_gemini_ask_blocks_because_beforetool_cannot_prompt():
    adapter = GeminiAdapter()
    buf = io.StringIO()
    with redirect_stdout(buf):
        adapter.write_verdict(Verdict(Decision.Ask, "needs review"), "BeforeTool")
    payload = json.loads(buf.getvalue())
    assert payload["decision"] == "deny"
    assert payload["reason"] == "approval required: needs review"


def test_auto_adapter_selects_gemini_from_beforetool_event():
    payload: JsonObject = {
        "hook_event_name": "BeforeTool",
        "tool_name": "run_shell_command",
        "tool_input": {"command": "ls"},
    }
    event = _effective_event("auto", payload)
    adapter = _select_adapter(AgentName.Auto, event, payload)
    assert isinstance(adapter, GeminiAdapter)


def test_auto_adapter_selects_claude_permission_request_from_claude_payload():
    payload: JsonObject = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
    }
    event = _effective_event("auto", payload)
    adapter = _select_adapter(AgentName.Auto, event, payload)
    assert isinstance(adapter, ClaudeAdapter)


def test_auto_adapter_selects_codex_permission_request_from_codex_payload():
    payload: JsonObject = {
        "hook_event_name": "PermissionRequest",
        "permission": {"type": "Bash", "metadata": {"command": "ls"}},
    }
    event = _effective_event("auto", payload)
    adapter = _select_adapter(AgentName.Auto, event, payload)
    assert isinstance(adapter, CodexAdapter)


# ---- Install: shared fixture ---------------------------------------------


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect every adapter's hook-config path under ``tmp_path``.

    Also stubs ``shutil.which`` so the bridge command embedded in hook entries
    is deterministic across machines.
    """
    monkeypatch.setattr(ClaudeAdapter, "settings_path", tmp_path / ".claude/settings.json")
    monkeypatch.setattr(CodexAdapter, "hooks_path", tmp_path / ".codex/hooks.json")
    monkeypatch.setattr(CodexAdapter, "config_path", tmp_path / ".codex/config.toml")
    monkeypatch.setattr(GeminiAdapter, "settings_path", tmp_path / ".gemini/settings.json")
    monkeypatch.setattr(OpencodeAdapter, "plugin_path", tmp_path / ".config/opencode/plugins/agentperms.js")
    monkeypatch.setattr(
        agentperms,
        "_rulesync_hooks_path",
        lambda: tmp_path / ".rulesync/hooks.json",
    )
    def _stub_which(_name: str, *_args: object, **_kwargs: object) -> str:
        return "/abs/agentperms"
    monkeypatch.setattr(shutil, "which", _stub_which)
    return tmp_path


# ---- Install: Claude ------------------------------------------------------


def test_claude_install_direct_writes_pretooluse(fake_home: Path):
    paths = ClaudeAdapter().install(InstallMode.Direct)
    assert paths == [fake_home / ".claude/settings.json"]
    data = json.loads(paths[0].read_text())
    groups = data["hooks"]["PreToolUse"]
    assert len(groups) == 1
    assert groups[0]["matcher"] == "*"
    hook = groups[0]["hooks"][0]
    assert "agentperms" in hook["command"]
    assert "--agent claude" in hook["command"]
    # Explicit event so the bridge doesn't have to guess from payload shape
    assert "--event PreToolUse" in hook["command"]
    # Claude timeout is in seconds.
    assert hook["timeout"] == 30


def test_claude_install_direct_preserves_other_hooks(fake_home: Path):
    settings = fake_home / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    notify_group = {"matcher": "*", "hooks": [{"type": "command", "command": "/bin/notify"}]}
    settings.write_text(json.dumps({"hooks": {"Notification": [notify_group]}}))
    ClaudeAdapter().install(InstallMode.Direct)
    data = json.loads(settings.read_text())
    assert data["hooks"]["Notification"][0]["hooks"][0]["command"] == "/bin/notify"
    assert "PreToolUse" in data["hooks"]


def test_claude_install_direct_replaces_stale_bridge_entry(fake_home: Path):
    settings = fake_home / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    stale_cmd = "/old/path/agentperms check --agent claude --event PreToolUse"
    stale = {"matcher": "*", "hooks": [{"type": "command", "command": stale_cmd}]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [stale]}}))
    ClaudeAdapter().install(InstallMode.Direct)
    data = json.loads(settings.read_text())
    groups = data["hooks"]["PreToolUse"]
    assert len(groups) == 1
    assert (
        groups[0]["hooks"][0]["command"]
        == "/abs/agentperms check --agent claude --event PreToolUse"
    )


def test_claude_install_direct_strips_spurious_permissionrequest(fake_home: Path):
    settings = fake_home / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "PermissionRequest": [
                        {
                            "matcher": "*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "/bin/agentperms check --agent claude --event PreToolUse",
                                }
                            ],
                        },
                    ]
                }
            }
        )
    )
    ClaudeAdapter().install(InstallMode.Direct)
    data = json.loads(settings.read_text())
    assert "PermissionRequest" not in data["hooks"]


def test_claude_install_rulesync_merges_into_hooks_json(fake_home: Path):
    paths = ClaudeAdapter().install(InstallMode.Rulesync)
    assert paths == [fake_home / ".rulesync/hooks.json"]
    data = json.loads(paths[0].read_text())
    # Fresh rulesync files must include the schema version, else `rulesync`
    # rejects them.
    assert data["version"] == 1
    entries = data["claudecode"]["hooks"]["preToolUse"]
    assert len(entries) == 1
    assert entries[0]["matcher"] == "*"
    assert "--agent claude" in entries[0]["command"]
    assert "--event PreToolUse" in entries[0]["command"]


def test_claude_install_rulesync_strips_spurious_permissionrequest(fake_home: Path):
    rulesync = fake_home / ".rulesync/hooks.json"
    rulesync.parent.mkdir(parents=True)
    rulesync.write_text(
        json.dumps(
            {
                "claudecode": {
                    "hooks": {
                        "permissionRequest": [
                            {
                                "type": "command",
                                "command": "/bin/agentperms check --agent claude --event PreToolUse",
                                "matcher": "*",
                            },
                            {"type": "command", "command": "/bin/beckon enqueue --permission"},
                        ]
                    }
                }
            }
        )
    )
    ClaudeAdapter().install(InstallMode.Rulesync)
    data = json.loads(rulesync.read_text())
    pr_entries = data["claudecode"]["hooks"]["permissionRequest"]
    assert len(pr_entries) == 1
    assert "beckon" in pr_entries[0]["command"]


def test_claude_install_idempotent(fake_home: Path):
    assert ClaudeAdapter().install(InstallMode.Direct) != []
    assert ClaudeAdapter().install(InstallMode.Direct) == []


# ---- Install: Codex -------------------------------------------------------


def test_codex_install_direct_writes_both_files(fake_home: Path):
    paths = CodexAdapter().install(InstallMode.Direct)
    assert (fake_home / ".codex/hooks.json") in paths
    assert (fake_home / ".codex/config.toml") in paths
    hooks = json.loads((fake_home / ".codex/hooks.json").read_text())
    pre = hooks["hooks"]["PreToolUse"]
    perm = hooks["hooks"]["PermissionRequest"]
    assert pre[0]["matcher"] == "Bash"
    assert perm[0]["matcher"] == "Bash|apply_patch|mcp__.*"
    # Each entry embeds its own --event arg so the bridge doesn't have to infer.
    assert "--event PreToolUse" in pre[0]["hooks"][0]["command"]
    assert "--event PermissionRequest" in perm[0]["hooks"][0]["command"]


def test_codex_install_direct_enables_codex_hooks_feature(fake_home: Path):
    CodexAdapter().install(InstallMode.Direct)
    config = tomlkit.parse((fake_home / ".codex/config.toml").read_text())
    features = config.get("features")
    assert isinstance(features, dict)
    assert features.get("codex_hooks") is True


def test_codex_install_direct_preserves_existing_toml(fake_home: Path):
    config = fake_home / ".codex/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[approval]\npolicy = "untrusted"\n')
    CodexAdapter().install(InstallMode.Direct)
    parsed = tomlkit.parse(config.read_text())
    approval = parsed.get("approval")
    features = parsed.get("features")
    assert isinstance(approval, dict)
    assert isinstance(features, dict)
    assert approval.get("policy") == "untrusted"
    assert features.get("codex_hooks") is True


def test_codex_install_rulesync_writes_both_events(fake_home: Path):
    CodexAdapter().install(InstallMode.Rulesync)
    data = json.loads((fake_home / ".rulesync/hooks.json").read_text())
    assert data["codexcli"]["hooks"]["preToolUse"][0]["matcher"] == ".*"
    assert data["codexcli"]["hooks"]["permissionRequest"][0]["matcher"] == ".*"


def test_codex_install_rulesync_does_not_touch_config_toml(fake_home: Path):
    CodexAdapter().install(InstallMode.Rulesync)
    assert not (fake_home / ".codex/config.toml").exists()


# ---- Install: Gemini ------------------------------------------------------


def test_gemini_install_direct_writes_beforetool(fake_home: Path):
    paths = GeminiAdapter().install(InstallMode.Direct)
    assert paths == [fake_home / ".gemini/settings.json"]
    data = json.loads(paths[0].read_text())
    groups = data["hooks"]["BeforeTool"]
    assert groups[0]["matcher"] == ".*"
    assert "--agent gemini" in groups[0]["hooks"][0]["command"]


def test_gemini_install_rulesync_uses_geminicli_block(fake_home: Path):
    GeminiAdapter().install(InstallMode.Rulesync)
    data = json.loads((fake_home / ".rulesync/hooks.json").read_text())
    entries = data["geminicli"]["hooks"]["preToolUse"]
    assert entries[0]["matcher"] == ".*"


# ---- Install: OpenCode ----------------------------------------------------


def test_opencode_install_writes_plugin_with_resolved_path(fake_home: Path):
    paths = OpencodeAdapter().install(InstallMode.Direct)
    plugin_path = fake_home / ".config/opencode/plugins/agentperms.js"
    assert paths == [plugin_path]
    text = plugin_path.read_text()
    assert 'const bridge = "/abs/agentperms";' in text
    assert "AgentBridgePlugin" in text


def test_opencode_install_idempotent(fake_home: Path):
    assert OpencodeAdapter().install(InstallMode.Direct) != []
    assert OpencodeAdapter().install(InstallMode.Direct) == []


def test_opencode_install_runs_in_rulesync_mode_too(fake_home: Path):
    # OpenCode plugin is always installed directly even when mode is Rulesync,
    # because rulesync has no schema for permission.ask plugins.
    paths = OpencodeAdapter().install(InstallMode.Rulesync)
    assert paths == [fake_home / ".config/opencode/plugins/agentperms.js"]


# ---- Install: dry-run + mode resolution ----------------------------------


def test_install_dry_run_writes_nothing(fake_home: Path):
    ClaudeAdapter().install(InstallMode.Direct, dry_run=True)
    CodexAdapter().install(InstallMode.Direct, dry_run=True)
    GeminiAdapter().install(InstallMode.Direct, dry_run=True)
    OpencodeAdapter().install(InstallMode.Direct, dry_run=True)
    assert not (fake_home / ".claude/settings.json").exists()
    assert not (fake_home / ".codex/hooks.json").exists()
    assert not (fake_home / ".codex/config.toml").exists()
    assert not (fake_home / ".gemini/settings.json").exists()
    assert not (fake_home / ".config/opencode/plugins/agentperms.js").exists()


def test_resolve_install_mode_picks_rulesync_when_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".rulesync").mkdir()
    assert _resolve_install_mode("auto") is InstallMode.Rulesync


def test_resolve_install_mode_picks_direct_when_no_rulesync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert _resolve_install_mode("auto") is InstallMode.Direct


def test_resolve_install_mode_explicit_rulesync_requires_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(agentperms.PolicyError):
        _resolve_install_mode("rulesync")


# ---- _is_bridge_hook ownership ------------------------------------------


def test_is_bridge_hook_matches_bridge_command():
    assert _is_bridge_hook(
        {"type": "command", "command": "/abs/agentperms check --agent claude --event PreToolUse"}
    )


def test_is_bridge_hook_rejects_unrelated_wrapper_with_substring():
    """Substring-match would falsely strip a sibling tool whose name contains
    ``agentperms`` (e.g. ``agentperms-debug``). Strict basename +
    second-arg ``check`` is required to identify our own entries.
    """
    assert not _is_bridge_hook(
        {"type": "command", "command": "/usr/local/bin/agentperms-debug trace"}
    )


def test_is_bridge_hook_rejects_bridge_with_other_subcommand():
    """A user's manual ``agentperms edit`` should not be treated as installer-owned."""
    assert not _is_bridge_hook(
        {"type": "command", "command": "/abs/agentperms edit"}
    )


def test_is_bridge_hook_rejects_non_dict():
    assert not _is_bridge_hook("not a dict")
    assert not _is_bridge_hook(None)


def test_is_bridge_hook_rejects_empty_command():
    assert not _is_bridge_hook({"type": "command", "command": "   "})


# ---- shell-safe path embedding -------------------------------------------


def test_install_quotes_paths_with_spaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A user's bridge installed under e.g. ``/Users/jane doe/.local/bin/`` must
    survive interpolation into a hook command — without ``shlex.quote`` the path
    splits on the space and the hook silently fails. Regression guard for M1.
    """
    monkeypatch.setattr(ClaudeAdapter, "settings_path", tmp_path / ".claude/settings.json")
    def _spaced_which(_name: str, *_args: object, **_kwargs: object) -> str:
        return "/Users/jane doe/bin/agentperms"
    monkeypatch.setattr(shutil, "which", _spaced_which)
    paths = ClaudeAdapter().install(InstallMode.Direct)
    data = json.loads(paths[0].read_text())
    command = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    # The space-bearing path must be quoted; otherwise the shell sees three argv.
    assert "'/Users/jane doe/bin/agentperms'" in command
    # And the resulting command round-trips through shlex back to the original argv.
    import shlex as _shlex

    parts = _shlex.split(command)
    assert parts[0] == "/Users/jane doe/bin/agentperms"
    assert parts[1] == "check"


def test_opencode_plugin_json_escapes_special_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The plugin embeds the bridge path as a JS string literal; ``json.dumps``
    correctly handles backslashes and quotes. A path with a backslash must
    survive interpolation as a valid JS literal.
    """
    monkeypatch.setattr(OpencodeAdapter, "plugin_path", tmp_path / "agentperms.js")
    def _windows_which(_name: str, *_args: object, **_kwargs: object) -> str:
        return "C:\\Program Files\\agentperms"
    monkeypatch.setattr(shutil, "which", _windows_which)
    paths = OpencodeAdapter().install(InstallMode.Direct)
    text = paths[0].read_text()
    # ``json.dumps`` wraps in double quotes and escapes backslashes; the literal
    # must appear as a valid JS string.
    assert 'const bridge = "C:\\\\Program Files\\\\agentperms";' in text
