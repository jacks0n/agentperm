"""Bundled rule templates and the `init` command that copies and merges them."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agentperm import (
    DEFAULT_TEMPLATES,
    POLICY_FILENAME,
    Decision,
    ShellRequest,
    available_templates,
    load_policy_file,
    load_template,
    main,
    merge_templates_into,
    parse_pipeline,
    parse_policy_text,
    render_templates,
)
from agentperm.errors import PolicyError
from agentperm.rules import parse_rule

TEMPLATE_NAMES = [name for name, _ in available_templates()]


def _decide(policy_text: str, command: str, tmp_path: Path) -> str:
    policy = parse_policy_text(policy_text, "test").policy
    return policy.decide(ShellRequest(parse_pipeline(command), cwd=tmp_path)).decision.value


# --- template integrity -------------------------------------------------------


def test_default_templates_are_all_available() -> None:
    assert set(DEFAULT_TEMPLATES) <= set(TEMPLATE_NAMES)


def test_every_template_has_a_description() -> None:
    for name, description in available_templates():
        assert description, f"template {name} is missing its leading // description line"


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_every_template_rule_parses(name: str) -> None:
    # parse_rule returning None means the rule would be silently dropped at load —
    # a template typo must fail this test, not ship as a dead rule.
    template = load_template(name)
    permissions = template.file.raw.get("permissions")
    assert isinstance(permissions, dict)
    for decision in ("allow", "ask", "deny"):
        entries = permissions.get(decision)
        assert isinstance(entries, list)
        for index, entry in enumerate(entries):
            assert parse_rule(entry) is not None, f"{name} {decision}[{index}]: {entry!r}"


def test_unknown_template_raises() -> None:
    with pytest.raises(PolicyError, match="unknown template"):
        load_template("no-such-template")


# --- render (fresh file) ------------------------------------------------------


def test_render_defaults_parses_and_decides(tmp_path: Path) -> None:
    text = render_templates([load_template(name) for name in DEFAULT_TEMPLATES])
    assert "// --- file-inspection ---" in text
    assert _decide(text, "git status | head -5", tmp_path) == "allow"
    assert _decide(text, "sudo ls", tmp_path) == "deny"
    assert _decide(text, "sed -i s/a/b/ f.txt", tmp_path) == "ask"


def test_render_dedups_rules_shared_between_templates(tmp_path: Path) -> None:
    template = load_template("git-read-only")
    text = render_templates([template, template])
    assert text.count("Shell(git fetch values(-C))") == 1


def test_rendered_templates_close_the_documented_holes(tmp_path: Path) -> None:
    names = ["git-read-only", "gh-read-only", "aws-read-only", "packages-read-only"]
    text = render_templates([load_template(name) for name in names])
    for command in (
        "git branch -D main",
        "git remote add origin http://evil",
        "gh api graphql -f query=x",
        "gh api -X DELETE repos/o/r",
        "aws secretsmanager get-secret-value --secret-id x",
        "npm audit fix",
    ):
        assert _decide(text, command, tmp_path) != "allow", command


# --- merge into an existing policy --------------------------------------------


def test_merge_appends_only_missing_rules() -> None:
    existing = parse_policy_text(
        '{"version":1,"permissions":{"allow":["Shell(git fetch values(-C))"]}}', "test"
    )
    merge = merge_templates_into(existing, [load_template("git-read-only")])
    added_rules = [rule.serialize() for _, rule, _ in merge.added]
    assert "Shell(git fetch values(-C))" not in added_rules
    assert "Shell(git stash {list,show} values(-C))" in added_rules
    assert all(name == "git-read-only" for _, _, name in merge.added)


def test_merge_never_overrides_existing_redirection_decisions() -> None:
    existing = parse_policy_text(
        '{"version":1,"permissions":{},"shell":{"redirection":'
        '{"stdoutToFile":"allow","allowPaths":["/scratch"]}}}',
        "test",
    )
    merge = merge_templates_into(existing, [load_template("safety-baseline")])
    redirection = merge.file.policy.redirection
    assert redirection.stdout_to_file is Decision.Allow  # kept, not template's "ask"
    assert redirection.append_to_file is Decision.Ask  # gap filled from the template
    assert redirection.allow_paths == ("/scratch", "/tmp")
    assert merge.redirection_changed


def test_merge_is_a_noop_when_everything_is_present() -> None:
    template = load_template("docker-read-only")
    text = render_templates([template])
    merge = merge_templates_into(parse_policy_text(text, "test"), [template])
    assert not merge.added
    assert not merge.redirection_changed


# --- the init command ---------------------------------------------------------


def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


def test_init_list_names_every_template(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["init", "--list"]) == 0
    out = capsys.readouterr().out
    for name in TEMPLATE_NAMES:
        assert name in out


def test_init_creates_global_policy_from_default_templates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _home(tmp_path, monkeypatch)
    assert main(["init"]) == 0
    path = home / POLICY_FILENAME
    assert f"wrote {path}" in capsys.readouterr().out
    policy = load_policy_file(path).policy
    verdict = policy.decide(ShellRequest(parse_pipeline("cat x | head -2"), cwd=tmp_path))
    assert verdict.decision is Decision.Allow


def test_init_rerun_changes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path, monkeypatch)
    assert main(["init"]) == 0
    before = (home / POLICY_FILENAME).read_bytes()
    assert main(["init"]) == 0
    assert (home / POLICY_FILENAME).read_bytes() == before


def test_init_merges_additional_template_into_existing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _home(tmp_path, monkeypatch)
    assert main(["init"]) == 0
    capsys.readouterr()
    assert main(["init", "aws-read-only"]) == 0
    out = capsys.readouterr().out
    assert "+allow" in out and "[aws-read-only]" in out
    policy = load_policy_file(home / POLICY_FILENAME).policy
    verdict = policy.decide(ShellRequest(parse_pipeline("aws s3 ls"), cwd=tmp_path))
    assert verdict.decision is Decision.Allow
    # rules from the original init survive the merge
    verdict = policy.decide(ShellRequest(parse_pipeline("sudo ls"), cwd=tmp_path))
    assert verdict.decision is Decision.Deny


def test_init_local_requires_a_git_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _home(tmp_path, monkeypatch)
    outside = tmp_path / "plain"
    outside.mkdir()
    monkeypatch.chdir(outside)
    assert main(["init", "--local"]) == 2


def test_init_local_writes_to_repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _home(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    monkeypatch.chdir(repo / "sub")
    assert main(["init", "--local", "python-checks"]) == 0
    assert (repo / POLICY_FILENAME).exists()


def test_init_output_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _home(tmp_path, monkeypatch)
    target = tmp_path / "elsewhere" / "policy.jsonc"
    assert main(["init", "gh-read-only", "-o", str(target)]) == 0
    raw = load_policy_file(target).raw
    assert isinstance(raw.get("permissions"), dict)


def test_init_unknown_template_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _home(tmp_path, monkeypatch)
    assert main(["init", "nope"]) == 2
    assert "--list" in capsys.readouterr().err


def test_init_warns_when_merging_discards_comments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _home(tmp_path, monkeypatch)
    path = home / POLICY_FILENAME
    path.write_text('// hand-written note\n{"version":1,"permissions":{"allow":["Read"]}}\n')
    assert main(["init", "docker-read-only"]) == 0
    captured = capsys.readouterr()
    assert "not preserved" in captured.err
    saved = load_policy_file(path)
    assert "// hand-written note" not in path.read_text()
    serialized = [rule.serialize() for _, rule in saved.policy.all_rules()]
    assert "Read" in serialized  # the hand-written rule survives
    assert json.loads(path.read_text())  # merged output is plain JSON
