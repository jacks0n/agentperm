"""Behavioral tests for target discovery and config-relative path rules."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from agentperm import POLICY_FILENAME, CompoundRequest, Decision, ShellRequest, ToolRequest, parse_pipeline
from agentperm.scoped_policy import decide_with_discovered_policy


def _write_policy(
    root: Path,
    *,
    deny: Sequence[object] = (),
    allow: Sequence[object] = (),
    include: Sequence[str] = (),
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / POLICY_FILENAME).write_text(
        json.dumps(
            {
                "version": 1,
                "include": include,
                "permissions": {"deny": deny, "allow": allow},
            }
        )
    )


def _write_request(target: Path, cwd: Path) -> ToolRequest:
    return ToolRequest("Write", (("file_path", str(target)),), cwd=cwd)


def test_parent_policy_double_star_covers_child_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    worktrees = home / "Code" / "network-api-worktrees"
    target = worktrees / "mir-281" / "db" / "schema" / "nap.sql"
    cwd = home / "Code" / "network-api"
    cwd.mkdir(parents=True)
    target.parent.mkdir(parents=True)
    _write_policy(worktrees, deny=["Write(**/db/schema/nap.sql)"])

    verdict = decide_with_discovered_policy(_write_request(target, cwd), cwd)

    assert verdict.decision is Decision.Deny


def test_relative_rule_does_not_gain_implicit_child_worktree_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    worktrees = home / "Code" / "network-api-worktrees"
    target = worktrees / "mir-281" / "db" / "schema" / "nap.sql"
    target.parent.mkdir(parents=True)
    _write_policy(worktrees, deny=["Write(db/schema/nap.sql)"])

    verdict = decide_with_discovered_policy(_write_request(target, home), home)

    assert verdict.decision is Decision.NoOpinion


def test_included_fragment_uses_including_root_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    fragment = home / ".agent-permissions.d" / "default.jsonc"
    fragment.parent.mkdir(parents=True)
    fragment.write_text('{"permissions":{"deny":["Write(foo/bar)"]}}')
    _write_policy(home, include=[".agent-permissions.d/default.jsonc"])
    cwd = home / "Code" / "project"
    target = home / "foo" / "bar"

    verdict = decide_with_discovered_policy(_write_request(target, cwd), cwd)

    assert verdict.decision is Decision.Deny


def test_global_relative_and_absolute_patterns_have_explicit_scopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    outside = tmp_path / "outside" / "generated" / "client.py"
    inside = home / "Code" / "project" / "generated" / "client.py"
    directly_inside = home / "generated" / "client.py"
    _write_policy(
        home,
        deny=["Write(**/generated/**)", f"Write({outside.parent.as_posix()}/**)"]
    )

    assert decide_with_discovered_policy(_write_request(inside, home), home).decision is Decision.Deny
    assert decide_with_discovered_policy(_write_request(directly_inside, home), home).decision is Decision.Deny
    assert decide_with_discovered_policy(_write_request(outside, home), home).decision is Decision.Deny


def test_relative_redirect_allow_path_uses_policy_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    parent = home / "Code"
    project = parent / "project"
    project.mkdir(parents=True)
    (parent / POLICY_FILENAME).write_text(
        json.dumps(
            {
                "version": 1,
                "shell": {"redirection": {"allowPaths": ["scratch"]}},
            }
        )
    )
    request = ShellRequest(parse_pipeline(f"echo ok > {parent / 'scratch' / 'out.txt'}"), cwd=project)

    verdict = decide_with_discovered_policy(request, project)

    assert verdict.decision is Decision.Allow


def test_same_relative_rule_in_different_layers_keeps_each_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    parent = home / "Code"
    project = parent / "project"
    target = project / "generated" / "client.py"
    _write_policy(parent, allow=["Write(generated/**)"])
    _write_policy(project, deny=["Write(generated/**)"])

    verdict = decide_with_discovered_policy(_write_request(target, project), project)

    assert verdict.decision is Decision.Deny


def test_compound_write_uses_strictest_target_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    project = home / "Code" / "project"
    denied = project / "generated" / "client.py"
    allowed = project / "src" / "client.py"
    _write_policy(project, deny=["Write(generated/**)"], allow=["Write(src/**)"])
    request = CompoundRequest((_write_request(allowed, project), _write_request(denied, project)))

    verdict = decide_with_discovered_policy(request, project)

    assert verdict.decision is Decision.Deny


def test_symlink_target_consults_lexical_and_resolved_ancestry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    project = home / "Code" / "project"
    external = home / "external"
    project.mkdir(parents=True)
    external.mkdir(parents=True)
    (project / "link").symlink_to(external, target_is_directory=True)
    _write_policy(project, deny=["Write(link/**)"])
    _write_policy(external, deny=["Write(protected.txt)"])

    lexical = project / "link" / "protected.txt"
    verdict = decide_with_discovered_policy(_write_request(lexical, project), project)

    assert verdict.decision is Decision.Deny
