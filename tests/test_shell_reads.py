"""Scoped Read denies and asks also govern files that shell commands name."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentperm import POLICY_FILENAME, Decision, ShellRequest, main, parse_pipeline
from agentperm.scoped_policy import decide_with_discovered_policy

_SHELL = "Shell({cat,cd,find,git,grep,head,ls,rg,sed,xargs,echo,bash})"


@pytest.fixture
def project(isolated_policy_home: Path) -> Path:
    root = isolated_policy_home / "project"
    (root / "secret").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "secret/key.txt").write_text("hunter2\n")
    (root / "src/a.txt").write_text("TODO\n")
    (root / ".env").write_text("TOKEN=x\n")
    _policy(
        root,
        allow=[_SHELL, "Read(src/**)"],
        ask=["Read(**/.env)"],
        deny=[{"Read(secret/**)": {"reason": "secret is off limits"}}],
    )
    return root


def _policy(root: Path, **permissions: object) -> None:
    (root / POLICY_FILENAME).write_text(json.dumps({"version": 1, "permissions": permissions}))


def _decide(command: str, cwd: Path) -> Decision:
    return decide_with_discovered_policy(ShellRequest(parse_pipeline(command), cwd=cwd), cwd).decision


@pytest.mark.parametrize(
    "command",
    [
        "cat secret/key.txt",
        "sed -n 1p secret/key.txt",
        "cat < secret/key.txt",
        "grep -r TODO secret",
        "find secret -type f | xargs cat",
        "cd secret && cat key.txt",
        "cd missing || cat secret/key.txt",
        "./secret/key.txt",
        "cat secret/*",
        "bash -c 'cat secret/key.txt'",
        "git diff -- secret/key.txt",
        "cat ~/project/secret/key.txt",
        "cat $HOME/project/secret/key.txt",
        "grep --file=secret/key.txt src/a.txt",
        "ls secret",
        "python3 -c \"print(open('secret/key.txt').read())\"",
        "node -e 'require(\"fs\").readFileSync(\"secret/key.txt\")'",
    ],
)
def test_shell_command_naming_a_denied_path_is_denied(project: Path, command: str) -> None:
    assert _decide(command, project) is Decision.Deny


def test_shell_read_restrictions_require_approval(project: Path) -> None:
    assert _decide("cat .env", project) is Decision.Ask
    directory_changes = "; ".join(f"cd path{index}" for index in range(7))
    assert _decide(f"{directory_changes}; cat src/a.txt", project) is Decision.Ask


@pytest.mark.parametrize("command", ["cat src/a.txt", "rg TODO", "grep -r TODO .", "echo secret-free"])
def test_shell_command_outside_read_denies_keeps_its_shell_verdict(project: Path, command: str) -> None:
    assert _decide(command, project) is Decision.Allow


def test_read_allow_never_approves_a_shell_command(isolated_policy_home: Path) -> None:
    root = isolated_policy_home / "readonly"
    (root / "src").mkdir(parents=True)
    _policy(root, allow=["Read(src/**)"])
    assert _decide("cat src/a.txt", root) is Decision.NoOpinion


def test_read_deny_in_the_target_projects_policy_applies_from_elsewhere(project: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _policy(elsewhere, allow=[_SHELL])
    assert _decide(f"cat {project}/secret/key.txt", elsewhere) is Decision.Deny


def test_why_reports_the_read_restriction(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(project)
    assert main(["why", "cat secret/key.txt"]) == 0
    assert capsys.readouterr().out.startswith("deny — secret is off limits")
