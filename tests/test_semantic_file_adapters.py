"""Semantic file-operation mappings at native adapter boundaries.

Every native file mutation is one capability, ``Write``: creating, overwriting, and editing a
file are not separable permissions, because a write to an existing path overwrites it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentperm import (
    ClaudeAdapter,
    CodexAdapter,
    CompoundRequest,
    GeminiAdapter,
    JsonObject,
    KiroAdapter,
    RejectedRequest,
    ToolRequest,
)


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("Write", {"file_path": "/workspace/generated.py", "content": "new"}),
        ("Edit", {"file_path": "/workspace/generated.py", "old_string": "old", "new_string": "new"}),
        (
            "MultiEdit",
            {"file_path": "/workspace/generated.py", "edits": [{"old_string": "old", "new_string": "new"}]},
        ),
    ],
)
def test_claude_maps_every_file_mutation_tool_to_write(tool_name: str, tool_input: JsonObject) -> None:
    request = ClaudeAdapter().parse_event(
        {"tool_name": tool_name, "tool_input": tool_input, "cwd": "/workspace"},
        "PreToolUse",
    )

    assert isinstance(request, ToolRequest)
    assert request.tool == "Write"
    assert ("file_path", "/workspace/generated.py") in request.arguments
    assert request.cwd == Path("/workspace")


def test_claude_maps_notebook_edit_to_write() -> None:
    request = ClaudeAdapter().parse_event(
        {
            "tool_name": "NotebookEdit",
            "tool_input": {"notebook_path": "/workspace/generated.ipynb", "new_source": "x = 1"},
        },
        "PreToolUse",
    )

    assert isinstance(request, ToolRequest)
    assert request.tool == "Write"
    assert ("notebook_path", "/workspace/generated.ipynb") in request.arguments


def test_claude_leaves_non_mutating_tools_untouched() -> None:
    request = ClaudeAdapter().parse_event(
        {"tool_name": "Read", "tool_input": {"file_path": "/workspace/generated.py"}},
        "PreToolUse",
    )

    assert isinstance(request, ToolRequest)
    assert request.tool == "Read"


@pytest.mark.parametrize(
    ("native_name", "path_field"),
    [
        ("replace", "file_path"),
        ("write_file", "file_path"),
    ],
)
def test_gemini_maps_file_tools_to_write(native_name: str, path_field: str) -> None:
    request = GeminiAdapter().parse_event(
        {
            "tool_name": native_name,
            "tool_input": {path_field: "/workspace/generated.py"},
            "cwd": "/workspace",
        },
        "BeforeTool",
    )

    assert isinstance(request, ToolRequest)
    assert request.tool == "Write"
    assert (path_field, "/workspace/generated.py") in request.arguments
    assert request.cwd == Path("/workspace")


@pytest.mark.parametrize("native_name", ["write", "fs_write", "fsWrite"])
def test_kiro_write_aliases_map_to_write(native_name: str) -> None:
    request = KiroAdapter().parse_event(
        {
            "tool_name": native_name,
            "tool_input": {"path": "generated/client.py", "content": "generated"},
            "cwd": "/workspace",
        },
        "preToolUse",
    )

    assert isinstance(request, ToolRequest)
    assert request.tool == "Write"
    assert ("path", "generated/client.py") in request.arguments
    assert request.cwd == Path("/workspace")


def test_codex_apply_patch_maps_every_mutation_to_write() -> None:
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

    # A move contributes both its source and its destination.
    assert isinstance(request, CompoundRequest)
    assert request.requests == (
        ToolRequest("Write", (("file_path", "generated/old.py"),)),
        ToolRequest("Write", (("file_path", "generated/new.py"),)),
        ToolRequest("Write", (("file_path", "generated/stale.py"),)),
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
