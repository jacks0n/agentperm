"""Focused coverage for OpenCode's pre-execution policy bridge."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentperm.adapters.opencode import OpencodeAdapter
from agentperm.domain import CompoundRequest, InstallMode, RejectedRequest, ShellRequest, ToolRequest


def test_tool_execute_before_parses_tool_name_and_input() -> None:
    request = OpencodeAdapter().parse_event(
        {
            "cwd": "/workspace",
            "tool_name": "edit",
            "tool_input": {"filePath": "generated/client.ts", "oldString": "old", "newString": "new"},
        },
        "tool.execute.before",
    )

    assert request == ToolRequest(
        "Edit",
        (
            ("filePath", "generated/client.ts"),
            ("oldString", "old"),
            ("newString", "new"),
        ),
        cwd=Path("/workspace"),
    )


def test_tool_execute_before_parses_bash_with_cwd() -> None:
    request = OpencodeAdapter().parse_event(
        {"cwd": "/workspace", "tool_name": "bash", "tool_input": {"command": "rm generated/client.ts"}},
        "tool.execute.before",
    )

    assert isinstance(request, ShellRequest)
    assert request.cwd == Path("/workspace")
    assert request.pipeline.segments[0].argv == ("rm", "generated/client.ts")


def test_tool_execute_before_translates_apply_patch_semantics() -> None:
    request = OpencodeAdapter().parse_event(
        {
            "cwd": "/workspace",
            "tool_name": "apply_patch",
            "tool_input": {
                "patchText": """*** Begin Patch
*** Update File: generated/old.ts
@@
-old
+new
*** Move to: generated/new.ts
*** Add File: generated/manifest.json
+{}
*** End Patch"""
            },
        },
        "tool.execute.before",
    )

    assert isinstance(request, CompoundRequest)
    assert request.requests == (
        ToolRequest("Edit", (("file_path", "generated/old.ts"),), cwd=Path("/workspace")),
        ToolRequest("Write", (("file_path", "generated/new.ts"),), cwd=Path("/workspace")),
        ToolRequest("Write", (("file_path", "generated/manifest.json"),), cwd=Path("/workspace")),
    )


def test_legacy_permission_hook_translates_apply_patch_when_patch_text_is_available() -> None:
    request = OpencodeAdapter().parse_event(
        {
            "cwd": "/workspace",
            "permission": {
                "type": "apply_patch",
                "metadata": {
                    "patchText": """*** Begin Patch
*** Delete File: generated/client.ts
*** End Patch"""
                },
            },
        },
        "permission.ask",
    )

    assert isinstance(request, CompoundRequest)
    assert request.requests == (ToolRequest("Edit", (("file_path", "generated/client.ts"),), cwd=Path("/workspace")),)


@pytest.mark.parametrize("tool_input", [{}, {"patchText": "not a patch"}])
def test_tool_execute_before_rejects_unparseable_apply_patch(tool_input: dict[str, str]) -> None:
    request = OpencodeAdapter().parse_event(
        {"tool_name": "apply_patch", "tool_input": tool_input},
        "tool.execute.before",
    )

    assert isinstance(request, RejectedRequest)


def test_install_includes_hard_deny_bridge_and_legacy_permission_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin_path = tmp_path / "agentperm.js"
    monkeypatch.setattr(OpencodeAdapter, "plugin_path", plugin_path)
    monkeypatch.setattr("agentperm.adapters.opencode.resolve_bridge_command", lambda: "/opt/agentperm")

    assert OpencodeAdapter().install(InstallMode.Direct) == [plugin_path]
    source = plugin_path.read_text()

    assert '"tool.execute.before": async (tool, output)' in source
    assert 'bridgeDecision("tool.execute.before"' in source
    assert "tool_name: tool.tool" in source
    assert "tool_input: output.args" in source
    assert 'decision?.status === "deny"' in source
    assert 'throw new Error(decision.reason || "Blocked by agentperm policy")' in source
    assert '"permission.ask": async (permission, output)' in source
    assert 'bridgeDecision("permission.ask"' in source


def test_uninstall_still_recognizes_updated_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plugin_path = tmp_path / "agentperm.js"
    monkeypatch.setattr(OpencodeAdapter, "plugin_path", plugin_path)
    monkeypatch.setattr("agentperm.adapters.opencode.resolve_bridge_command", lambda: "/opt/agentperm")
    OpencodeAdapter().install(InstallMode.Direct)

    assert OpencodeAdapter().uninstall(InstallMode.Direct) == [plugin_path]
    assert not plugin_path.exists()
