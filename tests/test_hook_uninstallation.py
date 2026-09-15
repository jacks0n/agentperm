"""Adapter tests — parse_event / write_verdict round-trips, rule round-tripping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import tomlkit
from tomlkit.items import Table

from agentperm import (
    ClaudeAdapter,
    CodexAdapter,
    GeminiAdapter,
    InstallMode,
    KiroAdapter,
    OpencodeAdapter,
)
from tests.json_support import array_at, decode_object, json_at, object_at

# ---- Uninstall -------------------------------------------------------------


def test_uninstall_restores_preexisting_claude_settings(fake_home: Path) -> None:
    settings = fake_home / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    notify_group = {"matcher": "*", "hooks": [{"type": "command", "command": "/bin/notify"}]}
    original = json.dumps({"hooks": {"Notification": [notify_group]}}, indent=2) + "\n"
    settings.write_text(original)

    ClaudeAdapter().install(InstallMode.Direct)
    assert "PreToolUse" in object_at(decode_object(settings.read_text()), "hooks")
    paths = ClaudeAdapter().uninstall(InstallMode.Direct)

    assert paths == [settings]
    assert settings.read_text() == original  # byte-for-byte round trip


def test_uninstall_on_fresh_install_leaves_empty_config(fake_home: Path) -> None:
    ClaudeAdapter().install(InstallMode.Direct)
    ClaudeAdapter().uninstall(InstallMode.Direct)
    assert decode_object((fake_home / ".claude/settings.json").read_text()) == {}


def test_uninstall_is_idempotent(fake_home: Path) -> None:
    ClaudeAdapter().install(InstallMode.Direct)
    assert ClaudeAdapter().uninstall(InstallMode.Direct)
    assert ClaudeAdapter().uninstall(InstallMode.Direct) == []


def test_uninstall_missing_config_is_a_noop(fake_home: Path) -> None:
    assert ClaudeAdapter().uninstall(InstallMode.Direct) == []
    assert not (fake_home / ".claude/settings.json").exists()


def test_uninstall_codex_strips_hooks_but_keeps_feature_flag(fake_home: Path) -> None:
    CodexAdapter().install(InstallMode.Direct)
    config = fake_home / ".codex/config.toml"
    config_before = config.read_text()

    paths = CodexAdapter().uninstall(InstallMode.Direct)

    assert paths == [fake_home / ".codex/hooks.json"]
    assert decode_object((fake_home / ".codex/hooks.json").read_text()) == {}
    assert config.read_text() == config_before
    features = tomlkit.parse(config_before)["features"]
    assert isinstance(features, Table)
    assert features["hooks"] is True


def test_uninstall_codex_restores_configured_passthrough_hook(fake_home: Path) -> None:
    hooks = fake_home / ".codex/hooks.json"
    hooks.parent.mkdir(parents=True)
    hooks.write_text(
        json.dumps(
            {
                "hooks": {
                    "PermissionRequest": [
                        {
                            "matcher": ".*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": (
                                        "/bin/agentperm check --agent codex --event PermissionRequest "
                                        "--passthrough /bin/notifier hook --agent codex PermissionRequest"
                                    ),
                                    "timeout": 30,
                                }
                            ],
                        }
                    ]
                }
            }
        )
    )

    CodexAdapter().uninstall(InstallMode.Direct)

    data = decode_object(hooks.read_text())
    restored = object_at(data, "hooks", "PermissionRequest", 0, "hooks", 0)
    assert restored == {
        "type": "command",
        "command": "/bin/notifier hook --agent codex PermissionRequest",
        "timeout": 30,
    }


def test_uninstall_gemini_strips_beforetool(fake_home: Path) -> None:
    GeminiAdapter().install(InstallMode.Direct)
    GeminiAdapter().uninstall(InstallMode.Direct)
    assert decode_object((fake_home / ".gemini/settings.json").read_text()) == {}


def test_uninstall_opencode_deletes_our_plugin(fake_home: Path) -> None:
    OpencodeAdapter().install(InstallMode.Direct)
    plugin = fake_home / ".config/opencode/plugins/agentperm.js"
    assert plugin.exists()
    paths = OpencodeAdapter().uninstall(InstallMode.Direct)
    assert paths == [plugin]
    assert not plugin.exists()


def test_uninstall_opencode_keeps_foreign_plugin(fake_home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plugin = fake_home / ".config/opencode/plugins/agentperm.js"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("export const SomethingElse = 1;\n")
    assert OpencodeAdapter().uninstall(InstallMode.Direct) == []
    assert plugin.exists()
    assert "does not look like the agentperm plugin" in capsys.readouterr().err


def test_uninstall_kiro_strips_agent_hooks_and_removes_standalone_file(fake_home: Path) -> None:
    agents = fake_home / ".kiro/agents"
    agents.mkdir(parents=True)
    agent = agents / "reviewer.json"
    agent.write_text(json.dumps({"name": "reviewer", "allowedTools": ["read"]}, indent=2) + "\n")

    KiroAdapter().install(InstallMode.Direct)
    assert "hooks" in decode_object(agent.read_text())
    standalone = fake_home / ".kiro/hooks/agentperm.json"
    assert standalone.exists()

    KiroAdapter().uninstall(InstallMode.Direct)

    data = decode_object(agent.read_text())
    assert data == {"name": "reviewer", "allowedTools": ["read"]}
    assert not standalone.exists()


def test_uninstall_kiro_keeps_foreign_hooks_in_standalone_file(fake_home: Path) -> None:
    KiroAdapter().install(InstallMode.Direct)
    standalone = fake_home / ".kiro/hooks/agentperm.json"
    data = decode_object(standalone.read_text())
    foreign = {
        "name": "linter",
        "trigger": "PreToolUse",
        "matcher": ".*",
        "action": {"type": "command", "command": "/bin/lint"},
    }
    array_at(data, "hooks").append(foreign)
    standalone.write_text(json.dumps(data, indent=2) + "\n")

    KiroAdapter().uninstall(InstallMode.Direct)

    remaining = decode_object(standalone.read_text())["hooks"]
    assert remaining == [foreign]


def test_uninstall_rulesync_strips_bridge_blocks(fake_home: Path) -> None:
    rulesync = fake_home / ".rulesync/hooks.json"
    ClaudeAdapter().install(InstallMode.Rulesync)
    CodexAdapter().install(InstallMode.Rulesync)
    assert "claudecode" in decode_object(rulesync.read_text())

    ClaudeAdapter().uninstall(InstallMode.Rulesync)
    CodexAdapter().uninstall(InstallMode.Rulesync)

    assert decode_object(rulesync.read_text()) == {"version": 1}


def test_uninstall_rulesync_keeps_foreign_entries(fake_home: Path) -> None:
    rulesync = fake_home / ".rulesync/hooks.json"
    rulesync.parent.mkdir(parents=True)
    foreign = {"type": "command", "command": "/bin/audit", "matcher": "*"}
    rulesync.write_text(json.dumps({"version": 1, "claudecode": {"hooks": {"preToolUse": [foreign]}}}, indent=2) + "\n")
    ClaudeAdapter().install(InstallMode.Rulesync)
    ClaudeAdapter().uninstall(InstallMode.Rulesync)
    data = decode_object(rulesync.read_text())
    assert json_at(data, "claudecode", "hooks", "preToolUse") == [foreign]


def test_uninstall_dry_run_reports_but_writes_nothing(fake_home: Path) -> None:
    ClaudeAdapter().install(InstallMode.Direct)
    OpencodeAdapter().install(InstallMode.Direct)
    settings = fake_home / ".claude/settings.json"
    plugin = fake_home / ".config/opencode/plugins/agentperm.js"
    settings_before = settings.read_bytes()

    assert ClaudeAdapter().uninstall(InstallMode.Direct, dry_run=True) == [settings]
    assert OpencodeAdapter().uninstall(InstallMode.Direct, dry_run=True) == [plugin]

    assert settings.read_bytes() == settings_before
    assert plugin.exists()


def test_cli_uninstall_auto_strips_direct_and_rulesync(fake_home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agentperm import main

    ClaudeAdapter().install(InstallMode.Direct)
    ClaudeAdapter().install(InstallMode.Rulesync)
    assert main(["uninstall"]) == 0
    out = capsys.readouterr().out
    assert "claude: removed hooks from" in out
    assert "policy files are left in place" in out
    assert decode_object((fake_home / ".claude/settings.json").read_text()) == {}
    assert decode_object((fake_home / ".rulesync/hooks.json").read_text()) == {"version": 1}
