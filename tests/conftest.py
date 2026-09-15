"""Adapter tests — parse_event / write_verdict round-trips, rule round-tripping."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import agentperm
import agentperm.adapters.base
from agentperm import (
    ClaudeAdapter,
    CodexAdapter,
    GeminiAdapter,
    KiroAdapter,
    OpencodeAdapter,
)


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
    monkeypatch.setattr(OpencodeAdapter, "plugin_path", tmp_path / ".config/opencode/plugins/agentperm.js")
    monkeypatch.setattr(KiroAdapter, "hooks_path", tmp_path / ".kiro/hooks/agentperm.json")
    monkeypatch.setattr(KiroAdapter, "agents_path", tmp_path / ".kiro/agents")
    monkeypatch.setattr(KiroAdapter, "workspace_root", tmp_path / "workspace")
    monkeypatch.setattr(
        agentperm.adapters.base,
        "_rulesync_hooks_path",
        lambda: tmp_path / ".rulesync/hooks.json",
    )

    def _stub_which(_name: str, *_args: object, **_kwargs: object) -> str:
        return "/abs/agentperm"

    monkeypatch.setattr(shutil, "which", _stub_which)
    return tmp_path
