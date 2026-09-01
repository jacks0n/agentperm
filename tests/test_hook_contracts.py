"""Black-box acceptance tests for the hook CLI contracts.

These tests execute the installed ``agentperm`` console script and pipe the same
JSON documents that agent hooks send at runtime. Policy selection is performed
through fixture HOME directories; no policy files are created or modified by the
tests.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

AGENTPERM = Path(sys.executable).with_name("agentperm")
FIXTURES = Path(__file__).parent / "fixtures" / "hook_contracts"
REQUEST_CWD = "/agentperm-black-box/workspace"


@dataclass(frozen=True)
class Hook:
    agent: str
    event: str
    tool_name: str


@dataclass(frozen=True)
class HookResult:
    hook: Hook
    returncode: int
    stdout: str
    stderr: str

    def output(self) -> object:
        return json.loads(self.stdout) if self.stdout else None


HOOKS = (
    Hook("claude", "PreToolUse", "Bash"),
    Hook("codex", "PermissionRequest", "Bash"),
    Hook("gemini", "BeforeTool", "run_shell_command"),
    Hook("kiro", "preToolUse", "shell"),
    Hook("opencode", "tool.execute.before", "bash"),
)

REPORTED_READ_COMMANDS = (
    (
        "sed-and-rg",
        "sed -n '540,595p' Cargo.toml; "
        'rg -n "dev-small|CARGO_PROFILE_DEV_INCREMENTAL|incremental" '
        "Justfile justfile .config .cargo -g '*' 2>/dev/null || true",
    ),
    (
        "repo-health",
        "rg -n '^codex|cargo run|profile' Justfile | head -80; "
        "sed -n '1,35p' Justfile; df -h /Users/jackson/Code/vendor/codex; "
        "pgrep -fl '/cargo clean' || true",
    ),
    (
        "seed-discovery",
        "git status --short; test -e scripts/shared_seed.sh && echo shared-script-exists || true; "
        'rg -n "shared_seed|_db-share-seed|NAPI_SEED_DIR" . || true; ls db | head -n 30',
    ),
    (
        "source-inspection",
        "sed -n '1,80p' db/restore/load_nap_data.py; "
        "sed -n '1,60p' db/restore/load_snap_data.py; "
        "sed -n '1,100p' db/restore/verify_search_data.py; "
        "sed -n '1,230p' db/seed_topology/__main__.py | tail -n 80; "
        "sed -n '1,45p' db/dump/lv_derms_data.py; sed -n '1,120p' .env.example",
    ),
    (
        "justfile-search",
        "rg -n '^codex|cargo run' justfile Justfile 2>/dev/null | head -80",
    ),
    (
        "path-and-docs-inspection",
        'rg -n "\\bPath\\b|\\bpathlib\\b|_HERE" '
        "db/restore/lv_derms_data.py db/restore/verify_search_data.py db/seed_topology/__main__.py; "
        'rg -n "OUTPUT_DIR / \\"seed\\"|parent\\.parent / \\"seed\\"|'
        'seed_topology/report\\.json|db/seed_topology/report" '
        "db tests scripts justfile .gitignore || true; "
        "sed -n '1,85p' db/README.md; sed -n '1,75p' db/seed_topology/README.md",
    ),
)

SQL_SCENARIOS = (
    (
        "postgres-read",
        "allow",
        "source /project/runtime.env && PGPASSWORD=\"$DATABASE_PASSWORD\" /opt/tools/bin/psql -X "
        "-h \"$DATABASE_HOST\" -p \"$DATABASE_PORT\" -U \"$DATABASE_USER\" -d \"$DATABASE_NAME\" "
        "-v ON_ERROR_STOP=1 -P pager=off "
        "-c \"with totals as (select meter_id,count(*) channels from process.channel group by meter_id) "
        "select meter_id,channels from totals order by meter_id\" "
        "-c \"select meter_id from process.meter order by meter_id fetch first 20 rows only\"",
    ),
    (
        "postgres-write",
        "ask",
        "psql -c \"with changed as (delete from process.meter returning *) select * from changed\"",
    ),
    (
        "postgres-denied-function",
        "deny",
        'psql -c "select dangerous_extension_function()"',
    ),
    (
        "oracle-sqlplus-read",
        "allow",
        "docker exec arbitrary-container bash -lc \"printf '%s\\n' 'set pagesize 100 feedback off' "
        "'column meter_id format a12' 'select meter_id from process.meter order by meter_id;' 'exit' "
        "| sqlplus -s process/example@DATABASE\"",
    ),
    (
        "oracle-sqlplus-write",
        "ask",
        "docker exec arbitrary-container bash -lc \"printf '%s\\n' "
        "'delete from process.meter where meter_id = 1;' 'exit' | sqlplus -s process/example@DATABASE\"",
    ),
    (
        "python-heredoc-read",
        "allow",
        "python <<'EOL'\nquery_db('select meter_id from process.meter order by meter_id')\nEOL",
    ),
    (
        "python-heredoc-write",
        "ask",
        "python <<'EOL'\nquery_db('update process.meter set active = false')\nEOL",
    ),
)

FILE_DENY_REASON = "Generated file; run the generator instead."

# (policy fixture, cwd-relative path, expected decision). ``files-alias`` spells the same
# policy with the deprecated ``Edit(...)`` alias and must decide identically.
FILE_SCENARIOS = (
    ("files", "generated/client.py", "deny"),
    ("files", "src/app.py", "allow"),
    ("files-alias", "generated/client.py", "deny"),
    ("files-alias", "src/app.py", "allow"),
)


@dataclass(frozen=True)
class FileCase:
    hook: Hook
    tool_input: dict[str, object]


def _patch_text(relative_path: str) -> str:
    return f"*** Begin Patch\n*** Update File: {relative_path}\n@@\n-old\n+new\n*** End Patch"


def _file_cases(relative_path: str) -> tuple[FileCase, ...]:
    """Every native create/overwrite/edit/patch tool, with the payload shape its host sends."""
    absolute = f"{REQUEST_CWD}/{relative_path}"
    patch = _patch_text(relative_path)
    edit = {"file_path": absolute, "old_string": "old", "new_string": "new"}
    return (
        FileCase(Hook("claude", "PreToolUse", "Write"), {"file_path": absolute, "content": "new"}),
        FileCase(Hook("claude", "PreToolUse", "Edit"), dict(edit)),
        FileCase(
            Hook("claude", "PreToolUse", "MultiEdit"),
            {"file_path": absolute, "edits": [{"old_string": "old", "new_string": "new"}]},
        ),
        FileCase(Hook("claude", "PreToolUse", "NotebookEdit"), {"notebook_path": absolute, "new_source": "x"}),
        FileCase(Hook("codex", "PermissionRequest", "apply_patch"), {"command": patch}),
        FileCase(Hook("gemini", "BeforeTool", "write_file"), {"file_path": absolute, "content": "new"}),
        FileCase(Hook("gemini", "BeforeTool", "replace"), dict(edit)),
        FileCase(Hook("kiro", "preToolUse", "fs_write"), {"command": "create", "path": absolute, "file_text": "new"}),
        FileCase(Hook("opencode", "tool.execute.before", "write"), {"filePath": absolute, "content": "new"}),
        FileCase(
            Hook("opencode", "tool.execute.before", "edit"),
            {"filePath": absolute, "oldString": "old", "newString": "new"},
        ),
        FileCase(Hook("opencode", "tool.execute.before", "apply_patch"), {"patchText": patch}),
    )


def _run_tool_hook(policy: str, hook: Hook, tool_input: dict[str, object]) -> HookResult:
    payload = {
        "cwd": REQUEST_CWD,
        "hook_event_name": hook.event,
        "tool_name": hook.tool_name,
        "tool_input": tool_input,
    }
    env = dict(os.environ)
    env.update(
        {
            "HOME": str((FIXTURES / policy).resolve()),
            "XDG_CACHE_HOME": "/agentperm-black-box/cache",
            # Prevent the repository's development .env from enabling trace writes.
            "AGENTPERM_TRACE": "",
            "ZELLIJ_PANE_ID": "",
            "ZELLIJ_SESSION_NAME": "",
        }
    )
    completed = subprocess.run(
        [str(AGENTPERM), "check", "--agent", hook.agent, "--event", hook.event],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    return HookResult(hook, completed.returncode, completed.stdout, completed.stderr)


def _run_hook(policy: str, hook: Hook, command: str) -> HookResult:
    return _run_tool_hook(policy, hook, {"command": command})


def _run_every_hook(policy: str, command: str) -> tuple[HookResult, ...]:
    with ThreadPoolExecutor(max_workers=len(HOOKS)) as executor:
        futures = tuple(executor.submit(_run_hook, policy, hook, command) for hook in HOOKS)
        return tuple(future.result() for future in futures)


def _run_every_file_hook(policy: str, relative_path: str) -> tuple[HookResult, ...]:
    cases = _file_cases(relative_path)
    with ThreadPoolExecutor(max_workers=len(cases)) as executor:
        futures = tuple(executor.submit(_run_tool_hook, policy, case.hook, case.tool_input) for case in cases)
        return tuple(future.result() for future in futures)


def _assert_external_decision(result: HookResult, decision: str) -> None:
    agent = result.hook.agent
    output = result.output()

    if agent == "claude":
        assert result.returncode == 0, result.stderr
        assert isinstance(output, dict)
        hook_output = output.get("hookSpecificOutput")
        assert isinstance(hook_output, dict)
        assert hook_output.get("permissionDecision") == decision
        return

    if agent == "codex":
        assert result.returncode == 0, result.stderr
        if decision == "ask":
            assert output == {}
            return
        assert isinstance(output, dict)
        hook_output = output.get("hookSpecificOutput")
        assert isinstance(hook_output, dict)
        codex_decision = hook_output.get("decision")
        assert isinstance(codex_decision, dict)
        assert codex_decision.get("behavior") == decision
        return

    if agent == "gemini":
        assert result.returncode == 0, result.stderr
        assert isinstance(output, dict)
        expected = "deny" if decision == "ask" else decision
        assert output.get("decision") == expected
        if decision == "ask":
            assert str(output.get("reason", "")).startswith("approval required:")
        return

    if agent == "kiro":
        assert output is None
        if decision == "allow":
            assert result.returncode == 0, result.stderr
            assert result.stderr == ""
        else:
            assert result.returncode == 2
            prefix = "blocked:" if decision == "ask" else "denied:"
            assert result.stderr.startswith(prefix)
        return

    assert agent == "opencode"
    assert result.returncode == 0, result.stderr
    assert isinstance(output, dict)
    assert output.get("status") == decision


def _external_reason(result: HookResult) -> str:
    agent = result.hook.agent
    if agent == "kiro":
        return result.stderr.strip()
    output = result.output()
    assert isinstance(output, dict)
    if agent == "claude":
        hook_output = output.get("hookSpecificOutput")
        assert isinstance(hook_output, dict)
        return str(hook_output.get("permissionDecisionReason", ""))
    if agent == "codex":
        hook_output = output.get("hookSpecificOutput")
        assert isinstance(hook_output, dict)
        codex_decision = hook_output.get("decision")
        assert isinstance(codex_decision, dict)
        return str(codex_decision.get("message", ""))
    return str(output.get("reason", ""))


@pytest.mark.parametrize(("_name", "command"), REPORTED_READ_COMMANDS, ids=[case[0] for case in REPORTED_READ_COMMANDS])
def test_reported_whitelisted_commands_are_allowed_by_every_agent(_name: str, command: str) -> None:
    """Every reported regression traverses the real executable and each agent protocol."""
    assert AGENTPERM.is_file(), f"console script is missing beside the test interpreter: {AGENTPERM}"
    for result in _run_every_hook("allow", command):
        _assert_external_decision(result, "allow")


@pytest.mark.parametrize("decision", ("allow", "ask", "deny"))
def test_policy_decisions_are_translated_for_every_agent(decision: str) -> None:
    """The CLI honors each policy disposition through every supported hook contract."""
    assert AGENTPERM.is_file(), f"console script is missing beside the test interpreter: {AGENTPERM}"
    for result in _run_every_hook(decision, "echo regression-check"):
        _assert_external_decision(result, decision)


@pytest.mark.parametrize(
    ("_name", "decision", "command"),
    SQL_SCENARIOS,
    ids=[case[0] for case in SQL_SCENARIOS],
)
def test_sql_commands_are_decided_through_every_agent_cli(
    _name: str,
    decision: str,
    command: str,
) -> None:
    """SQL semantics are acceptance-tested at the executable boundary, not through internals."""
    assert AGENTPERM.is_file(), f"console script is missing beside the test interpreter: {AGENTPERM}"
    for result in _run_every_hook("sql", command):
        _assert_external_decision(result, decision)


@pytest.mark.parametrize(
    ("policy", "relative_path", "decision"),
    FILE_SCENARIOS,
    ids=[f"{policy}-{decision}" for policy, _, decision in FILE_SCENARIOS],
)
def test_native_file_mutations_are_decided_through_every_agent_cli(
    policy: str,
    relative_path: str,
    decision: str,
) -> None:
    """Every native create/overwrite/edit/patch tool is one ``Write`` at the executable boundary."""
    assert AGENTPERM.is_file(), f"console script is missing beside the test interpreter: {AGENTPERM}"
    for result in _run_every_file_hook(policy, relative_path):
        _assert_external_decision(result, decision)
        if decision == "deny":
            assert FILE_DENY_REASON in _external_reason(result), result.hook


def test_mixed_patch_is_denied_by_its_strictest_target() -> None:
    """A move into a denied directory denies the whole patch, even when every other target is allowed."""
    assert AGENTPERM.is_file(), f"console script is missing beside the test interpreter: {AGENTPERM}"
    patch = (
        "*** Begin Patch\n*** Update File: src/app.py\n@@\n-old\n+new\n*** Move to: generated/app.py\n"
        "*** Add File: src/new.py\n+content\n*** End Patch"
    )
    cases = (
        FileCase(Hook("codex", "PermissionRequest", "apply_patch"), {"command": patch}),
        FileCase(Hook("opencode", "tool.execute.before", "apply_patch"), {"patchText": patch}),
    )
    for case in cases:
        result = _run_tool_hook("files", case.hook, case.tool_input)
        _assert_external_decision(result, "deny")
        assert FILE_DENY_REASON in _external_reason(result), result.hook
