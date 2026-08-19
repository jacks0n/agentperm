"""CLI tests — `edit` scope/editor handling and `check` project-policy resolution."""

from __future__ import annotations

import io
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

import agentperm.cli as cli_module
from agentperm import POLICY_FILENAME, BashCommand, Policy, PolicyError, main

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


# --- check: ancestor policies are keyed off the payload cwd ----------------


def test_check_passes_payload_cwd_to_public_policy_loader(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload_cwd = Path("/workspace/project/src")
    received: list[Path | None] = []

    def fake_merged_policy(cwd: Path | None = None, *, local_root: Path | None = None) -> Policy:
        assert local_root is None
        received.append(cwd)
        return Policy(deny=(BashCommand(("rm",)),))

    monkeypatch.setattr(cli_module, "merged_policy", fake_merged_policy)

    assert _decision(_run_check(monkeypatch, capsys, "rm foo", cwd=payload_cwd)) == "deny"
    assert received == [payload_cwd]


def test_check_asks_and_names_malformed_ancestor_policy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cwd = Path("/workspace/project/src")
    policy_path = Path("/workspace/project") / POLICY_FILENAME

    def failing_merged_policy(cwd: Path | None = None, *, local_root: Path | None = None) -> Policy:
        raise PolicyError(f"{policy_path}: invalid JSON/JSONC")

    monkeypatch.setattr(cli_module, "merged_policy", failing_merged_policy)

    verdict = _run_check(monkeypatch, capsys, "cat README.md", cwd=cwd)

    assert _decision(verdict) == "ask"
    hook = verdict.get("hookSpecificOutput")
    assert isinstance(hook, dict)
    reason = hook.get("permissionDecisionReason")
    assert isinstance(reason, str)
    assert str(policy_path) in reason


def test_check_applies_python_readonly_ast_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / POLICY_FILENAME).write_text(
        '{"version":1,"permissions":{"allow":["Python(readonly)"]}}'
    )
    monkeypatch.setenv("HOME", str(home))

    readonly = _run_check(
        monkeypatch,
        capsys,
        'python -c "import agentperm; print(len(agentperm.__all__))"',
        cwd=tmp_path,
    )
    mutation = _run_check(
        monkeypatch,
        capsys,
        'python -c "open(\'out\', \'w\')"',
        cwd=tmp_path,
    )
    assert _decision(readonly) == "allow"
    assert _decision(mutation) == "ask"


# --- why: human-readable decision explanations --------------------------------


def _why_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    return home


def test_why_explains_each_segment_of_a_compound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _why_home(tmp_path, monkeypatch)
    (home / POLICY_FILENAME).write_text(
        '{"version":1,"permissions":{"allow":["Shell({cat,head})"],"deny":["Shell(sudo)"]}}'
    )

    assert main(["why", "cat foo | ./deploy.sh"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("ask")
    assert "cat foo  → allow" in out
    assert "./deploy.sh  → no-opinion" in out
    assert str(home / POLICY_FILENAME) in out

    assert main(["why", "sudo ls"]) == 0
    assert capsys.readouterr().out.startswith("deny — deny by rule")


def test_why_with_no_policy_files_points_at_init(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _why_home(tmp_path, monkeypatch)
    assert main(["why", "ls"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("no-opinion")
    assert "agentperm init" in out


def test_why_broken_policy_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _why_home(tmp_path, monkeypatch)
    (home / POLICY_FILENAME).write_text("not jsonc")
    assert main(["why", "ls"]) == 2
    assert "policy load failed" in capsys.readouterr().err
