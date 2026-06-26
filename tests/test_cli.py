"""CLI tests — `edit` scope/editor handling and `check` project-policy resolution."""

from __future__ import annotations

import io
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from agentperm import POLICY_FILENAME, main

EMPTY_DEFAULT = {"version": 1, "permissions": {"allow": [], "ask": [], "deny": []}}
DENY_RM = '{"version":1,"permissions":{"deny":["Bash(rm:*)"]}}'


def _recording_editor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, env_var: str = "VISUAL", prefix_args: str = ""
) -> Path:
    """Install a fake editor (via $VISUAL or $EDITOR) that appends each argv to a record file."""
    record = tmp_path / "opened_paths.txt"
    script = tmp_path / "fake_editor.sh"
    script.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> ' + shlex.quote(str(record)) + "\n")
    script.chmod(0o755)
    value = shlex.quote(str(script))
    if prefix_args:
        value = f"{value} {prefix_args}"
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.delenv("EDITOR", raising=False)
    monkeypatch.setenv(env_var, value)
    return record


def _opened_path(record: Path) -> Path:
    # The policy path is the last argv the editor received.
    return Path(record.read_text().splitlines()[-1])


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)


def _run_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], command: str, cwd: Path
) -> dict[str, object]:
    # Mirrors a real hook: the command's cwd travels in the payload, not the bridge process's cwd.
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(cwd)})
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    assert main(["check", "--agent", "claude", "--event", "PreToolUse"]) == 0
    out = capsys.readouterr().out.strip()
    return json.loads(out) if out else {}


def _decision(verdict: dict[str, object]) -> str | None:
    hook = verdict.get("hookSpecificOutput")
    return hook.get("permissionDecision") if isinstance(hook, dict) else None


# --- edit: scope routing ----------------------------------------------------


def test_edit_global_creates_default_and_opens_home_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    record = _recording_editor(tmp_path, monkeypatch)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    assert main(["edit"]) == 0

    global_file = home / POLICY_FILENAME
    assert json.loads(global_file.read_text()) == EMPTY_DEFAULT  # fresh default content, exactly
    assert _opened_path(record).resolve() == global_file.resolve()  # editor opened that file


def test_edit_global_explicit_opens_home_even_inside_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    record = _recording_editor(tmp_path, monkeypatch)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(repo)

    assert main(["edit", "--global"]) == 0

    assert _opened_path(record).resolve() == (home / POLICY_FILENAME).resolve()
    assert not (repo / POLICY_FILENAME).exists()


def test_edit_local_opens_repo_root_not_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    sub = repo / "pkg" / "nested"
    sub.mkdir(parents=True)
    _init_repo(repo)
    record = _recording_editor(tmp_path, monkeypatch)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(sub)

    assert main(["edit", "--local"]) == 0

    repo_file = repo / POLICY_FILENAME
    assert json.loads(repo_file.read_text()) == EMPTY_DEFAULT
    assert _opened_path(record).resolve() == repo_file.resolve()  # opened the repo-root file
    assert not (sub / POLICY_FILENAME).exists()
    assert not (home / POLICY_FILENAME).exists()


def test_edit_local_outside_git_repo_errors_and_launches_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    loose = tmp_path / "loose"
    loose.mkdir()
    record = _recording_editor(tmp_path, monkeypatch)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))  # don't discover a parent repo
    monkeypatch.chdir(loose)

    assert main(["edit", "--local"]) == 2
    assert not (loose / POLICY_FILENAME).exists()  # no stray file
    assert not (home / POLICY_FILENAME).exists()
    assert not record.exists()  # editor was never launched


# --- edit: file + editor handling ------------------------------------------


def test_edit_does_not_overwrite_existing_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    existing = home / POLICY_FILENAME
    original = '{ "version": 1, "permissions": { "allow": ["Read"] } }'
    existing.write_text(original)
    _recording_editor(tmp_path, monkeypatch)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    assert main(["edit"]) == 0
    assert existing.read_text() == original  # byte-for-byte unchanged, not reset to default


def test_edit_propagates_editor_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("VISUAL", "false")  # editor exits 1
    monkeypatch.delenv("EDITOR", raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    assert main(["edit"]) == 1


@pytest.mark.parametrize("env_var", ["VISUAL", "EDITOR"])
def test_edit_handles_editor_command_with_arguments(
    env_var: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    record = _recording_editor(tmp_path, monkeypatch, env_var=env_var, prefix_args="--wait")  # e.g. "code --wait"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    assert main(["edit"]) == 0  # shlex.split, not a literal "fake_editor.sh --wait" executable

    args = record.read_text().splitlines()
    assert args[0] == "--wait"  # the editor's own arg survived
    assert Path(args[-1]).resolve() == (home / POLICY_FILENAME).resolve()  # plus the policy path


def test_edit_global_and_local_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["edit", "--global", "--local"])
    assert exit_info.value.code == 2  # argparse usage error


# --- check: project-local policy is git-root-only, keyed off the payload cwd --


def test_check_resolves_payload_cwd_to_git_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()  # no global policy
    repo = tmp_path / "repo"
    nested = repo / "pkg" / "nested"
    nested.mkdir(parents=True)
    _init_repo(repo)
    (repo / POLICY_FILENAME).write_text(DENY_RM)
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    monkeypatch.chdir(neutral)  # bridge process runs OUTSIDE the repo

    # payload cwd is deep inside the repo -> must resolve up to the repo-root policy
    assert _decision(_run_check(monkeypatch, capsys, "rm foo", cwd=nested)) == "deny"


def test_check_ignores_local_policy_outside_git_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()  # no global policy
    loose = tmp_path / "loose"
    loose.mkdir()
    (loose / POLICY_FILENAME).write_text(DENY_RM)  # same rule, but NOT in a git repo
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    monkeypatch.chdir(neutral)

    assert _decision(_run_check(monkeypatch, capsys, "rm foo", cwd=loose)) != "deny"
