"""Adapter tests — parse_event / write_verdict round-trips, rule round-tripping."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import tomlkit
from tomlkit.items import Table

import agentperm
from agentperm import (
    ClaudeAdapter,
    CodexAdapter,
    GeminiAdapter,
    InstallMode,
    OpencodeAdapter,
)
from agentperm.adapters.base import is_bridge_hook
from agentperm.cli import resolve_install_mode
from tests.json_support import array_at, decode_object, json_at, object_at, text_at

# ---- Install: Claude ------------------------------------------------------


def test_claude_install_direct_writes_pretooluse(fake_home: Path) -> None:
    paths = ClaudeAdapter().install(InstallMode.Direct)
    assert paths == [fake_home / ".claude/settings.json"]
    data = decode_object(paths[0].read_text())
    groups = array_at(data, "hooks", "PreToolUse")
    assert len(groups) == 1
    assert json_at(groups, 0, "matcher") == "*"
    hook = json_at(groups, 0, "hooks", 0)
    assert "agentperm" in text_at(hook, "command")
    assert "--agent claude" in text_at(hook, "command")
    # Explicit event so the bridge doesn't have to guess from payload shape
    assert "--event PreToolUse" in text_at(hook, "command")
    # Claude timeout is in seconds.
    assert json_at(hook, "timeout") == 30


def test_claude_install_direct_preserves_other_hooks(fake_home: Path) -> None:
    settings = fake_home / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    notify_group = {"matcher": "*", "hooks": [{"type": "command", "command": "/bin/notify"}]}
    settings.write_text(json.dumps({"hooks": {"Notification": [notify_group]}}))
    ClaudeAdapter().install(InstallMode.Direct)
    data = decode_object(settings.read_text())
    assert text_at(data, "hooks", "Notification", 0, "hooks", 0, "command") == "/bin/notify"
    assert "PreToolUse" in object_at(data, "hooks")


def test_claude_install_direct_replaces_stale_bridge_entry(fake_home: Path) -> None:
    settings = fake_home / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    stale_cmd = "/old/path/agentperm check --agent claude --event PreToolUse"
    stale = {"matcher": "*", "hooks": [{"type": "command", "command": stale_cmd}]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [stale]}}))
    ClaudeAdapter().install(InstallMode.Direct)
    data = decode_object(settings.read_text())
    groups = array_at(data, "hooks", "PreToolUse")
    assert len(groups) == 1
    assert text_at(groups, 0, "hooks", 0, "command") == "/abs/agentperm check --agent claude --event PreToolUse"


def test_claude_install_direct_strips_spurious_permissionrequest(fake_home: Path) -> None:
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
                                    "command": "/bin/agentperm check --agent claude --event PreToolUse",
                                }
                            ],
                        },
                    ]
                }
            }
        )
    )
    ClaudeAdapter().install(InstallMode.Direct)
    data = decode_object(settings.read_text())
    assert "PermissionRequest" not in object_at(data, "hooks")


def test_claude_install_rulesync_merges_into_hooks_json(fake_home: Path) -> None:
    paths = ClaudeAdapter().install(InstallMode.Rulesync)
    assert paths == [fake_home / ".rulesync/hooks.json"]
    data = decode_object(paths[0].read_text())
    # Fresh rulesync files must include the schema version, else `rulesync`
    # rejects them.
    assert json_at(data, "version") == 1
    entries = array_at(data, "claudecode", "hooks", "preToolUse")
    assert len(entries) == 1
    assert json_at(entries, 0, "matcher") == "*"
    assert "--agent claude" in text_at(entries, 0, "command")
    assert "--event PreToolUse" in text_at(entries, 0, "command")


def test_claude_install_rulesync_strips_spurious_permissionrequest(fake_home: Path) -> None:
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
                                "command": "/bin/agentperm check --agent claude --event PreToolUse",
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
    data = decode_object(rulesync.read_text())
    pr_entries = array_at(data, "claudecode", "hooks", "permissionRequest")
    assert len(pr_entries) == 1
    assert "beckon" in text_at(pr_entries, 0, "command")


def test_claude_install_idempotent(fake_home: Path) -> None:
    assert ClaudeAdapter().install(InstallMode.Direct) != []
    assert ClaudeAdapter().install(InstallMode.Direct) == []


# ---- Install: Codex -------------------------------------------------------


def test_codex_install_direct_writes_both_files(fake_home: Path) -> None:
    paths = CodexAdapter().install(InstallMode.Direct)
    assert (fake_home / ".codex/hooks.json") in paths
    assert (fake_home / ".codex/config.toml") in paths
    hooks = decode_object((fake_home / ".codex/hooks.json").read_text())
    pre = json_at(hooks, "hooks", "PreToolUse")
    perm = json_at(hooks, "hooks", "PermissionRequest")
    assert json_at(pre, 0, "matcher") == ".*"
    assert json_at(perm, 0, "matcher") == ".*"
    # Each entry embeds its own --event arg so the bridge doesn't have to infer.
    assert "--event PreToolUse" in text_at(pre, 0, "hooks", 0, "command")
    assert "--event PermissionRequest" in text_at(perm, 0, "hooks", 0, "command")


def test_codex_reinstall_preserves_configured_passthrough(fake_home: Path) -> None:
    CodexAdapter().install(InstallMode.Direct)
    hooks_path = fake_home / ".codex/hooks.json"
    hooks = decode_object(hooks_path.read_text())
    command = text_at(hooks, "hooks", "PermissionRequest", 0, "hooks", 0, "command")
    permission_hook = object_at(hooks, "hooks", "PermissionRequest", 0, "hooks", 0)
    permission_hook["command"] = command + " --passthrough /bin/notifier hook"
    hooks_path.write_text(json.dumps(hooks))

    CodexAdapter().install(InstallMode.Direct)

    updated = decode_object(hooks_path.read_text())
    assert text_at(updated, "hooks", "PermissionRequest", 0, "hooks", 0, "command").endswith(
        "--passthrough /bin/notifier hook"
    )


def test_codex_install_direct_enables_hooks_feature(fake_home: Path) -> None:
    CodexAdapter().install(InstallMode.Direct)
    config = tomlkit.parse((fake_home / ".codex/config.toml").read_text())
    features = config["features"]
    assert isinstance(features, Table)
    assert features["hooks"] is True
    assert "codex_hooks" not in features


def test_codex_install_direct_migrates_deprecated_codex_hooks_feature(fake_home: Path) -> None:
    config = fake_home / ".codex/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text("[features]\ncodex_hooks = true\n")
    CodexAdapter().install(InstallMode.Direct)
    parsed = tomlkit.parse(config.read_text())
    features = parsed["features"]
    assert isinstance(features, Table)
    assert features["hooks"] is True
    assert "codex_hooks" not in features


def test_codex_install_direct_preserves_existing_toml(fake_home: Path) -> None:
    config = fake_home / ".codex/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[approval]\npolicy = "untrusted"\n')
    CodexAdapter().install(InstallMode.Direct)
    parsed = tomlkit.parse(config.read_text())
    approval = parsed["approval"]
    features = parsed["features"]
    assert isinstance(approval, Table)
    assert isinstance(features, Table)
    assert approval["policy"] == "untrusted"
    assert features["hooks"] is True


def test_codex_install_rulesync_writes_both_events(fake_home: Path) -> None:
    CodexAdapter().install(InstallMode.Rulesync)
    data = decode_object((fake_home / ".rulesync/hooks.json").read_text())
    assert json_at(data, "codexcli", "hooks", "preToolUse", 0, "matcher") == ".*"
    assert json_at(data, "codexcli", "hooks", "permissionRequest", 0, "matcher") == ".*"


def test_codex_install_rulesync_does_not_touch_config_toml(fake_home: Path) -> None:
    CodexAdapter().install(InstallMode.Rulesync)
    assert not (fake_home / ".codex/config.toml").exists()


# ---- Install: Gemini ------------------------------------------------------


def test_gemini_install_direct_writes_beforetool(fake_home: Path) -> None:
    paths = GeminiAdapter().install(InstallMode.Direct)
    assert paths == [fake_home / ".gemini/settings.json"]
    data = decode_object(paths[0].read_text())
    groups = array_at(data, "hooks", "BeforeTool")
    assert json_at(groups, 0, "matcher") == ".*"
    assert "--agent gemini" in text_at(groups, 0, "hooks", 0, "command")


def test_gemini_install_rulesync_uses_geminicli_block(fake_home: Path) -> None:
    GeminiAdapter().install(InstallMode.Rulesync)
    data = decode_object((fake_home / ".rulesync/hooks.json").read_text())
    entries = array_at(data, "geminicli", "hooks", "preToolUse")
    assert json_at(entries, 0, "matcher") == ".*"


# ---- Install: OpenCode ----------------------------------------------------


def test_opencode_install_writes_plugin_with_resolved_path(fake_home: Path) -> None:
    paths = OpencodeAdapter().install(InstallMode.Direct)
    plugin_path = fake_home / ".config/opencode/plugins/agentperm.js"
    assert paths == [plugin_path]
    text = plugin_path.read_text()
    assert 'const bridge = "/abs/agentperm";' in text
    assert "AgentBridgePlugin" in text


def test_opencode_install_idempotent(fake_home: Path) -> None:
    assert OpencodeAdapter().install(InstallMode.Direct) != []
    assert OpencodeAdapter().install(InstallMode.Direct) == []


def test_opencode_install_runs_in_rulesync_mode_too(fake_home: Path) -> None:
    # OpenCode plugin is always installed directly even when mode is Rulesync,
    # because rulesync has no schema for permission.ask plugins.
    paths = OpencodeAdapter().install(InstallMode.Rulesync)
    assert paths == [fake_home / ".config/opencode/plugins/agentperm.js"]


# ---- Install: dry-run + mode resolution ----------------------------------


def test_install_dry_run_writes_nothing(fake_home: Path) -> None:
    ClaudeAdapter().install(InstallMode.Direct, dry_run=True)
    CodexAdapter().install(InstallMode.Direct, dry_run=True)
    GeminiAdapter().install(InstallMode.Direct, dry_run=True)
    OpencodeAdapter().install(InstallMode.Direct, dry_run=True)
    assert not (fake_home / ".claude/settings.json").exists()
    assert not (fake_home / ".codex/hooks.json").exists()
    assert not (fake_home / ".codex/config.toml").exists()
    assert not (fake_home / ".gemini/settings.json").exists()
    assert not (fake_home / ".config/opencode/plugins/agentperm.js").exists()


def test_resolve_install_mode_picks_rulesync_when_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".rulesync").mkdir()
    assert resolve_install_mode("auto") is InstallMode.Rulesync


def test_resolve_install_mode_picks_direct_when_no_rulesync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert resolve_install_mode("auto") is InstallMode.Direct


def test_resolve_install_mode_explicit_rulesync_requires_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(agentperm.PolicyError):
        resolve_install_mode("rulesync")


# ---- is_bridge_hook ownership ------------------------------------------


def test_is_bridge_hook_matches_bridge_command() -> None:
    assert is_bridge_hook({"type": "command", "command": "/abs/agentperm check --agent claude --event PreToolUse"})


def test_is_bridge_hook_rejects_unrelated_wrapper_with_substring() -> None:
    """Substring-match would falsely strip a sibling tool whose name contains
    ``agentperm`` (e.g. ``agentperm-debug``). Strict basename +
    second-arg ``check`` is required to identify our own entries.
    """
    assert not is_bridge_hook({"type": "command", "command": "/usr/local/bin/agentperm-debug trace"})


def test_is_bridge_hook_rejects_bridge_with_other_subcommand() -> None:
    """A user's manual ``agentperm edit`` should not be treated as installer-owned."""
    assert not is_bridge_hook({"type": "command", "command": "/abs/agentperm edit"})


def test_is_bridge_hook_rejects_non_dict() -> None:
    assert not is_bridge_hook("not a dict")
    assert not is_bridge_hook(None)


def test_is_bridge_hook_rejects_empty_command() -> None:
    assert not is_bridge_hook({"type": "command", "command": "   "})


# ---- shell-safe path embedding -------------------------------------------


def test_install_quotes_paths_with_spaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A user's bridge installed under e.g. ``/Users/jane doe/.local/bin/`` must
    survive interpolation into a hook command — without ``shlex.quote`` the path
    splits on the space and the hook silently fails. Regression guard for M1.
    """
    monkeypatch.setattr(ClaudeAdapter, "settings_path", tmp_path / ".claude/settings.json")

    def _spaced_which(_name: str, *_args: object, **_kwargs: object) -> str:
        return "/Users/jane doe/bin/agentperm"

    monkeypatch.setattr(shutil, "which", _spaced_which)
    paths = ClaudeAdapter().install(InstallMode.Direct)
    data = decode_object(paths[0].read_text())
    command = text_at(data, "hooks", "PreToolUse", 0, "hooks", 0, "command")
    # The space-bearing path must be quoted; otherwise the shell sees three argv.
    assert "'/Users/jane doe/bin/agentperm'" in command
    # And the resulting command round-trips through shlex back to the original argv.
    import shlex as _shlex

    parts = _shlex.split(command)
    assert parts[0] == "/Users/jane doe/bin/agentperm"
    assert parts[1] == "check"


def test_opencode_plugin_json_escapes_special_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The plugin embeds the bridge path as a JS string literal; ``json.dumps``
    correctly handles backslashes and quotes. A path with a backslash must
    survive interpolation as a valid JS literal.
    """
    monkeypatch.setattr(OpencodeAdapter, "plugin_path", tmp_path / "agentperm.js")

    def _windows_which(_name: str, *_args: object, **_kwargs: object) -> str:
        return "C:\\Program Files\\agentperm"

    monkeypatch.setattr(shutil, "which", _windows_which)
    paths = OpencodeAdapter().install(InstallMode.Direct)
    text = paths[0].read_text()
    # ``json.dumps`` wraps in double quotes and escapes backslashes; the literal
    # must appear as a valid JS string.
    assert 'const bridge = "C:\\\\Program Files\\\\agentperm";' in text
