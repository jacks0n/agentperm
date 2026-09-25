"""One policy vocabulary for every host: each agent's native tools resolve to the same capability."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentperm import (
    AgentAdapter,
    ClaudeAdapter,
    CodexAdapter,
    Decision,
    GeminiAdapter,
    JsonObject,
    KiroAdapter,
    NamedTool,
    OpencodeAdapter,
    Policy,
    ShellRequest,
    parse_rule,
)
from agentperm.domain import agent_tool_names
from agentperm.domain.tools import NATIVE_TOOLS

_EVENTS: dict[str, tuple[AgentAdapter, str]] = {
    "claude": (ClaudeAdapter(), "PreToolUse"),
    "codex": (CodexAdapter(), "PreToolUse"),
    "gemini": (GeminiAdapter(), "BeforeTool"),
    "opencode": (OpencodeAdapter(), "tool.execute.before"),
    "kiro": (KiroAdapter(), "preToolUse"),
}
_CAPABILITIES = ("Read", "Write", "WebFetch", "WebSearch", "Skill", "AWS", "Code", "Knowledge")


def _decide(agent: str, tool: str, tool_input: JsonObject, rule: str, decision: Decision = Decision.Allow) -> Decision:
    adapter, event = _EVENTS[agent]
    request = adapter.parse_event({"cwd": "/repo", "tool_name": tool, "tool_input": tool_input}, event)
    assert request is not None
    parsed = parse_rule(rule)
    assert parsed is not None
    policy = Policy(deny=(parsed,)) if decision is Decision.Deny else Policy(allow=(parsed,))
    return policy.decide(request).decision


# Current and legacy native names. Inputs target /repo/src so scoped rules can be checked too.
_READ_TOOLS: list[tuple[str, str, JsonObject]] = [
    ("claude", "Read", {"file_path": "src/a.py"}),
    ("claude", "Glob", {"pattern": "src/**/*.py"}),
    ("claude", "Grep", {"pattern": "TODO", "path": "src/pkg"}),
    ("claude", "LS", {"path": "src/pkg"}),
    ("claude", "NotebookRead", {"notebook_path": "src/a.ipynb"}),
    ("codex", "view_image", {"path": "src/a.png"}),
    ("codex", "read_file", {"file_path": "src/a.py"}),
    ("codex", "list_dir", {"dir_path": "src/pkg"}),
    ("codex", "grep_files", {"pattern": "TODO", "path": "src/pkg"}),
    ("gemini", "read_file", {"file_path": "src/a.py"}),
    ("gemini", "read_file", {"absolute_path": "/repo/src/a.py"}),
    ("gemini", "read_many_files", {"include": ["src/**/*.py"]}),
    ("gemini", "list_directory", {"dir_path": "src/pkg"}),
    ("gemini", "glob", {"pattern": "**/*.py", "dir_path": "src/pkg"}),
    ("gemini", "grep_search", {"pattern": "TODO", "dir_path": "src/pkg"}),
    ("gemini", "search_file_content", {"pattern": "TODO", "dir_path": "src/pkg"}),
    ("opencode", "read", {"filePath": "/repo/src/a.py"}),
    ("opencode", "list", {"path": "/repo/src/pkg"}),
    ("opencode", "glob", {"pattern": "src/*.ts"}),
    ("opencode", "grep", {"pattern": "TODO", "path": "/repo/src/pkg"}),
    ("kiro", "read", {"path": "src/a.py"}),
    ("kiro", "fs_read", {"operations": [{"mode": "Line", "path": "src/a.py"}]}),
    ("kiro", "fs_read", {"operations": [{"mode": "Image", "image_paths": ["src/a.png"]}]}),
    ("kiro", "fsRead", {"path": "src/a.py"}),
    ("kiro", "glob", {"pattern": "**/*.py", "path": "src/pkg"}),
    ("kiro", "grep", {"pattern": "TODO", "path": "src/pkg"}),
    ("kiro", "read_file", {"path": "src/a.py"}),
    ("kiro", "readFile", {"path": "src/a.py"}),
    ("kiro", "read_files", {"paths": ["src/a.py", "src/b.py"]}),
    ("kiro", "readMultipleFiles", {"paths": ["src/a.py"]}),
    ("kiro", "list_directory", {"path": "src/pkg"}),
    ("kiro", "listDirectory", {"path": "src/pkg"}),
    ("kiro", "read_code", {"path": "src/a.py"}),
    ("kiro", "readCode", {"path": "src/a.py"}),
]


@pytest.mark.parametrize(("agent", "tool", "tool_input"), _READ_TOOLS)
def test_every_native_read_tool_is_read(agent: str, tool: str, tool_input: JsonObject) -> None:
    assert _decide(agent, tool, tool_input, "Read") is Decision.Allow
    assert _decide(agent, tool, tool_input, "Write") is Decision.NoOpinion


@pytest.mark.parametrize(("agent", "tool", "tool_input"), _READ_TOOLS)
def test_scoped_read_rule_matches_each_tools_own_target(agent: str, tool: str, tool_input: JsonObject) -> None:
    assert _decide(agent, tool, tool_input, "Read(src/**)") is Decision.Allow
    assert _decide(agent, tool, tool_input, "Read(src/**)", Decision.Deny) is Decision.Deny
    assert _decide(agent, tool, tool_input, "Read(docs/**)", Decision.Deny) is Decision.NoOpinion


@pytest.mark.parametrize(
    ("agent", "tool", "tool_input"),
    [
        ("claude", "Glob", {"pattern": "**/*.py"}),
        ("claude", "Grep", {"pattern": "TODO"}),
        ("gemini", "glob", {"pattern": "**/*.py"}),
        ("opencode", "grep", {"pattern": "TODO"}),
        ("kiro", "file_search", {"query": "a.py"}),
        ("kiro", "fileSearch", {"query": "a.py"}),
        ("kiro", "grep_search", {"query": "TODO"}),
        ("kiro", "grepSearch", {"query": "TODO"}),
    ],
)
def test_search_without_a_narrower_root_targets_the_working_directory(
    agent: str, tool: str, tool_input: JsonObject
) -> None:
    assert _decide(agent, tool, tool_input, "Read") is Decision.Allow
    assert _decide(agent, tool, tool_input, "Read(src/**)") is Decision.NoOpinion
    assert _decide(agent, tool, tool_input, "Read(/repo/**)", Decision.Deny) is Decision.Deny


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Glob", {"pattern": "src/**"}),
        ("Grep", {"pattern": "TODO", "path": "src"}),
        ("LS", {"path": "src/pkg"}),
    ],
)
def test_single_segment_scope_does_not_cover_a_recursive_target(tool: str, tool_input: JsonObject) -> None:
    assert _decide("claude", tool, tool_input, "Read(src/*)") is Decision.NoOpinion
    assert _decide("claude", tool, tool_input, "Read(src/**)") is Decision.Allow


def test_glob_pattern_cannot_escape_a_scoped_allow() -> None:
    assert _decide("claude", "Glob", {"pattern": "src/../../etc/*"}, "Read(src/**)") is Decision.NoOpinion
    assert _decide("claude", "Glob", {"pattern": "/etc/*"}, "Read(/etc/**)", Decision.Deny) is Decision.Deny
    assert _decide("claude", "Glob", {"pattern": "src/*.py", "path": "/tmp"}, "Read(src/**)") is Decision.NoOpinion


_WRITE_TOOLS: list[tuple[str, str, JsonObject]] = [
    ("claude", "Write", {"file_path": "src/a.py", "content": "x"}),
    ("claude", "Edit", {"file_path": "src/a.py", "old_string": "a", "new_string": "b"}),
    ("claude", "MultiEdit", {"file_path": "src/a.py", "edits": []}),
    ("claude", "NotebookEdit", {"notebook_path": "src/a.ipynb", "new_source": "x"}),
    ("codex", "apply_patch", {"command": "*** Begin Patch\n*** Add File: src/a.py\n+x\n*** End Patch\n"}),
    ("gemini", "write_file", {"file_path": "src/a.py", "content": "x"}),
    ("gemini", "replace", {"file_path": "src/a.py", "old_string": "a", "new_string": "b"}),
    ("opencode", "edit", {"filePath": "/repo/src/a.py", "oldString": "a", "newString": "b"}),
    ("opencode", "write", {"filePath": "/repo/src/a.py", "content": "x"}),
    ("opencode", "multiedit", {"filePath": "/repo/src/a.py", "edits": []}),
    ("opencode", "apply_patch", {"patchText": "*** Begin Patch\n*** Add File: src/a.py\n+x\n*** End Patch\n"}),
    ("opencode", "patch", {"patchText": "*** Begin Patch\n*** Add File: src/a.py\n+x\n*** End Patch\n"}),
    ("kiro", "write", {"path": "src/a.py", "command": "create", "file_text": "x"}),
    ("kiro", "fs_write", {"path": "src/a.py", "command": "create", "file_text": "x"}),
    ("kiro", "fsWrite", {"path": "src/a.py", "text": "x"}),
    ("kiro", "fs_append", {"path": "src/a.py", "text": "x"}),
    ("kiro", "fsAppend", {"path": "src/a.py", "text": "x"}),
    ("kiro", "str_replace", {"path": "src/a.py", "oldStr": "a", "newStr": "b"}),
    ("kiro", "strReplace", {"path": "src/a.py", "oldStr": "a", "newStr": "b"}),
    ("kiro", "delete_file", {"targetFile": "src/a.py"}),
    ("kiro", "deleteFile", {"targetFile": "src/a.py"}),
    ("kiro", "edit_code", {"path": "src/a.py"}),
    ("kiro", "editCode", {"path": "src/a.py"}),
]


@pytest.mark.parametrize(("agent", "tool", "tool_input"), _WRITE_TOOLS)
def test_every_native_write_tool_is_governed_by_write(agent: str, tool: str, tool_input: JsonObject) -> None:
    assert _decide(agent, tool, tool_input, "Write(src/**)", Decision.Deny) is Decision.Deny
    assert _decide(agent, tool, tool_input, "Read", Decision.Deny) is Decision.NoOpinion


@pytest.mark.parametrize(
    ("agent", "tool", "tool_input", "capability"),
    [
        ("claude", "WebFetch", {"url": "https://github.com/x"}, "WebFetch"),
        ("gemini", "web_fetch", {"url": "https://github.com/x"}, "WebFetch"),
        ("opencode", "webfetch", {"url": "https://github.com/x"}, "WebFetch"),
        ("kiro", "web_fetch", {"url": "https://github.com/x"}, "WebFetch"),
        ("kiro", "webFetch", {"url": "https://github.com/x"}, "WebFetch"),
        ("claude", "WebSearch", {"query": "x"}, "WebSearch"),
        ("gemini", "google_web_search", {"query": "x"}, "WebSearch"),
        ("opencode", "websearch", {"query": "x"}, "WebSearch"),
        ("kiro", "web_search", {"query": "x"}, "WebSearch"),
        ("kiro", "remote_web_search", {"query": "x"}, "WebSearch"),
        ("kiro", "webSearch", {"query": "x"}, "WebSearch"),
        ("claude", "Skill", {"skill": "x"}, "Skill"),
        ("gemini", "activate_skill", {"name": "x"}, "Skill"),
        ("opencode", "skill", {"name": "x"}, "Skill"),
        ("kiro", "aws", {"service_name": "s3"}, "AWS"),
        ("kiro", "use_aws", {"service_name": "s3"}, "AWS"),
        ("kiro", "useAws", {"service_name": "s3"}, "AWS"),
        ("kiro", "code", {"operation": "search_symbols"}, "Code"),
        ("kiro", "knowledge", {"command": "search"}, "Knowledge"),
    ],
)
def test_other_native_tools_resolve_to_one_capability(
    agent: str, tool: str, tool_input: JsonObject, capability: str
) -> None:
    for candidate in _CAPABILITIES:
        expected = Decision.Allow if candidate == capability else Decision.NoOpinion
        assert _decide(agent, tool, tool_input, candidate) is expected


@pytest.mark.parametrize(
    ("agent", "tool"),
    [
        ("claude", "Agent"),
        ("claude", "Task"),
        ("claude", "TodoWrite"),
        ("codex", "spawn_agent"),
        ("codex", "update_plan"),
        ("gemini", "invoke_agent"),
        ("gemini", "write_todos"),
        ("opencode", "task"),
        ("opencode", "todowrite"),
        ("kiro", "subagent"),
        ("kiro", "use_subagent"),
        ("kiro", "delegate"),
        ("kiro", "todo"),
    ],
)
def test_unmapped_native_tools_defer_to_the_host(agent: str, tool: str) -> None:
    for capability in _CAPABILITIES:
        assert _decide(agent, tool, {"prompt": "x", "path": "src/a.py"}, capability) is Decision.NoOpinion


@pytest.mark.parametrize(
    ("agent", "tool"),
    [
        ("kiro", "shell"),
        ("kiro", "execute_bash"),
        ("kiro", "execute_cmd"),
        ("kiro", "executeBash"),
        ("kiro", "executeCmd"),
        ("kiro", "run_command"),
        ("kiro", "runCommand"),
    ],
)
def test_every_native_shell_tool_is_a_shell_request(agent: str, tool: str) -> None:
    assert _decide(agent, tool, {"command": "git status"}, "Shell(git status)") is Decision.Allow
    assert _decide(agent, tool, {"command": "git status"}, "Read") is Decision.NoOpinion


@pytest.mark.parametrize(
    ("agent", "tool"),
    [("claude", "PowerShell"), ("kiro", "execute_pwsh"), ("kiro", "executePwsh")],
)
def test_powershell_is_never_approved_as_posix_shell(agent: str, tool: str) -> None:
    adapter, event = _EVENTS[agent]
    request = adapter.parse_event({"cwd": "/repo", "tool_name": tool, "tool_input": {"command": "ls"}}, event)
    assert isinstance(request, ShellRequest)
    assert _decide(agent, tool, {"command": "ls"}, "Shell(ls)") is Decision.Ask


@pytest.mark.parametrize("tool", ["glob", "web_fetch", "read_file", "list_directory", "grep_search"])
def test_names_shared_by_gemini_and_kiro_decide_the_same_either_way(tool: str) -> None:
    tool_input: JsonObject = {"pattern": "src/*", "path": "src/a", "dir_path": "src/a", "url": "https://x.dev"}
    for capability in _CAPABILITIES:
        assert _decide("gemini", tool, tool_input, capability) is _decide("kiro", tool, tool_input, capability)


def test_rule_names_are_exact_capabilities() -> None:
    assert parse_rule("Edit") == NamedTool("Edit")
    assert parse_rule("Glob(src/**)") == NamedTool("Glob", "src/**")
    assert _decide("claude", "Edit", {"file_path": "src/a.py"}, "Edit", Decision.Deny) is Decision.NoOpinion
    assert _decide("claude", "Glob", {"pattern": "src/*"}, "Glob", Decision.Deny) is Decision.NoOpinion


def _imported(adapter: AgentAdapter) -> set[tuple[str, object]]:
    return {(decision.value, rule.serialize()) for decision, rule in adapter.import_native_rules()}


def test_claude_import_writes_capabilities_and_skips_other_tools(fake_home: Path) -> None:
    settings = fake_home / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps({"permissions": {"allow": ["Glob", "Grep(src/**)", "Read", "Task", "LS"], "deny": ["Edit(gen/**)"]}})
    )
    assert _imported(ClaudeAdapter()) == {("allow", "Read"), ("allow", "Read(src/**)"), ("deny", "Write(gen/**)")}


def test_opencode_import_writes_capabilities_and_skips_other_keys(fake_home: Path) -> None:
    config = fake_home / ".config/opencode/opencode.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "permission": {
                    "list": "allow",
                    "grep": {"src/**": "allow"},
                    "task": "allow",
                    "todowrite": "allow",
                    "external_directory": "ask",
                    "edit": "deny",
                }
            }
        )
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(OpencodeAdapter, "config_path", config)
        assert _imported(OpencodeAdapter()) == {("allow", "Read"), ("allow", "Read(src/**)"), ("deny", "Write")}


def test_kiro_import_writes_capabilities_and_skips_other_tools(fake_home: Path) -> None:
    agents = fake_home / ".kiro/agents"
    agents.mkdir(parents=True)
    (agents / "default.json").write_text(
        json.dumps({"allowedTools": ["fs_*", "grep", "subagent", "delegate", "code_*", "use_aws"]})
    )
    assert _imported(KiroAdapter()) == {("allow", "Read"), ("allow", "Write"), ("allow", "AWS")}


def test_capabilities_page_lists_every_native_tool() -> None:
    page = (Path(__file__).parents[1] / "docs/capabilities.md").read_text()
    table = page.split("## Tool capabilities", 1)[1].split("\n## ", 1)[0]
    for agent in NATIVE_TOOLS:
        for name in agent_tool_names(agent):
            assert f"`{name}`" in table, f"{agent} {name}"
