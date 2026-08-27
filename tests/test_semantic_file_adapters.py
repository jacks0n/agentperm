"""Semantic file-operation mappings at native adapter boundaries."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentperm import (
    ClaudeAdapter,
    CodexAdapter,
    CompoundRequest,
    GeminiAdapter,
    KiroAdapter,
    RejectedRequest,
    ToolRequest,
)


@pytest.mark.parametrize("tool_name", ["Edit", "Write"])
def test_claude_preserves_semantic_file_tool_names(tool_name: str) -> None:
    request = ClaudeAdapter().parse_event(
        {
            "tool_name": tool_name,
            "tool_input": {"file_path": "/workspace/generated.py"},
            "cwd": "/workspace",
        },
        "PreToolUse",
    )

    assert isinstance(request, ToolRequest)
    assert request.tool == tool_name
    assert ("file_path", "/workspace/generated.py") in request.arguments
    assert request.cwd == Path("/workspace")


def test_claude_maps_notebook_edit_to_semantic_edit() -> None:
    request = ClaudeAdapter().parse_event(
        {
            "tool_name": "NotebookEdit",
            "tool_input": {"notebook_path": "/workspace/generated.ipynb", "new_source": "x = 1"},
        },
        "PreToolUse",
    )

    assert isinstance(request, ToolRequest)
    assert request.tool == "Edit"
    assert ("notebook_path", "/workspace/generated.ipynb") in request.arguments


@pytest.mark.parametrize(
    ("native_name", "semantic_name", "path_field"),
    [
        ("replace", "Edit", "file_path"),
        ("write_file", "Write", "file_path"),
    ],
)
def test_gemini_maps_file_tools_to_semantic_operations(
    native_name: str,
    semantic_name: str,
    path_field: str,
) -> None:
    request = GeminiAdapter().parse_event(
        {
            "tool_name": native_name,
            "tool_input": {path_field: "/workspace/generated.py"},
            "cwd": "/workspace",
        },
        "BeforeTool",
    )

    assert isinstance(request, ToolRequest)
    assert request.tool == semantic_name
    assert (path_field, "/workspace/generated.py") in request.arguments
    assert request.cwd == Path("/workspace")


@pytest.mark.parametrize("native_name", ["write", "fs_write", "fsWrite"])
def test_kiro_combined_write_requires_edit_and_write_capabilities(native_name: str) -> None:
    request = KiroAdapter().parse_event(
        {
            "tool_name": native_name,
            "tool_input": {"path": "generated/client.py", "content": "generated"},
            "cwd": "/workspace",
        },
        "preToolUse",
    )

    assert isinstance(request, CompoundRequest)
    assert len(request.requests) == 2
    edit, write = request.requests
    assert isinstance(edit, ToolRequest)
    assert isinstance(write, ToolRequest)
    assert edit.tool == "Edit"
    assert write.tool == "Write"
    assert edit.arguments == write.arguments
    assert ("path", "generated/client.py") in edit.arguments
    assert edit.cwd == Path("/workspace")
    assert write.cwd == Path("/workspace")


def test_codex_apply_patch_maps_each_mutation_to_semantic_operations() -> None:
    request = CodexAdapter().parse_event(
        {
            "tool_name": "apply_patch",
            "tool_input": {
                "command": """*** Begin Patch
*** Environment ID: 123
*** Update File: generated/old.py
@@
-old
+new
*** Move to: generated/new.py
*** Delete File: generated/stale.py
*** Add File: generated/index.py
+content
*** End Patch"""
            },
        },
        "PreToolUse",
    )

    assert isinstance(request, CompoundRequest)
    assert request.requests == (
        ToolRequest("Edit", (("file_path", "generated/old.py"),)),
        ToolRequest("Write", (("file_path", "generated/new.py"),)),
        ToolRequest("Edit", (("file_path", "generated/stale.py"),)),
        ToolRequest("Write", (("file_path", "generated/index.py"),)),
    )


@pytest.mark.parametrize(
    "command",
    [
        "not a patch",
        "*** Begin Patch\n*** Unknown File: generated/x.py\n*** End Patch",
        "*** Begin Patch\n*** Move to: generated/x.py\n*** End Patch",
    ],
)
def test_codex_apply_patch_fails_closed_when_targets_are_not_parseable(command: str) -> None:
    request = CodexAdapter().parse_event(
        {"tool_name": "apply_patch", "tool_input": {"command": command}},
        "PreToolUse",
    )

    assert isinstance(request, RejectedRequest)
