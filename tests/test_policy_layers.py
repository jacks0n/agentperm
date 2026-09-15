"""Policy decision tests — strictness, aggregation, rule matching, bypass coercion."""

from __future__ import annotations

from pathlib import Path

import pytest

import agentperm.policy as policy_module
from agentperm import (
    POLICY_FILENAME,
    BashCommand,
    Decision,
    NamedTool,
    Policy,
    PolicyError,
    PolicyFile,
    PythonCallPolicy,
    RedirectionPolicy,
    ShellRequest,
    ToolRequest,
    load_policy_layer,
    merged_policy,
    parse_pipeline,
    resolve_policy_paths,
)
from tests.policy_support import decide as _decide

# ---- Policy merging -------------------------------------------------------


def test_merged_policies_union_rules_without_duplicates() -> None:
    a = Policy(allow=(BashCommand(("ls",)), BashCommand(("cat",))))
    b = Policy(allow=(BashCommand(("ls",)), BashCommand(("rg",))))
    merged = a.merged_with(b)
    prefixes = {r.prefix for r in merged.allow if isinstance(r, BashCommand)}
    assert prefixes == {("ls",), ("cat",), ("rg",)}


def test_policy_layer_recursively_merges_globs_in_lexical_order(tmp_path: Path) -> None:
    parts = tmp_path / "parts"
    nested = parts / "nested"
    nested.mkdir(parents=True)
    (nested / "tools.jsonc").write_text('{"permissions":{"allow":["Shell(git push origin)"]}}')
    (parts / "10-base.jsonc").write_text(
        """{
            "include": ["nested/*.jsonc"],
            "permissions": {"allow": ["Read"]},
            "shell": {"redirection": {"stdoutToFile": "deny"}}
        }"""
    )
    (parts / "20-prompts.jsonc").write_text(
        """{
            "permissions": {"ask": ["Shell(git push)"]},
            "shell": {"redirection": {"stdoutToFile": "ask"}}
        }"""
    )
    root = tmp_path / POLICY_FILENAME
    root.write_text(
        """{
            "version": 1,
            "include": ["parts/**/*.jsonc"],
            "shell": {"redirection": {"stdoutToFile": "allow"}}
        }"""
    )

    assert resolve_policy_paths(root) == (
        nested / "tools.jsonc",
        parts / "10-base.jsonc",
        parts / "20-prompts.jsonc",
        root,
    )
    policy = load_policy_layer(root).policy
    assert policy.decide(ShellRequest(parse_pipeline("git push origin main"))).decision is Decision.Ask
    assert policy.decide(ToolRequest("Read")).decision is Decision.Allow
    assert policy.redirection.stdout_to_file is Decision.Allow


def test_policy_layer_deduplicates_files_matched_by_overlapping_globs(tmp_path: Path) -> None:
    parts = tmp_path / "parts"
    parts.mkdir()
    shared = parts / "shared.jsonc"
    shared.write_text('{"permissions":{"allow":["Read"]}}')
    root = tmp_path / POLICY_FILENAME
    root.write_text('{"include":["parts/*.jsonc","parts/shared.jsonc"]}')

    assert resolve_policy_paths(root) == (shared, root)
    assert load_policy_layer(root).policy.allow == (NamedTool("Read"),)


def test_policy_layer_rejects_unmatched_include_glob(tmp_path: Path) -> None:
    root = tmp_path / POLICY_FILENAME
    root.write_text('{"include":["parts/*.jsonc"]}')

    with pytest.raises(PolicyError, match="matched no files"):
        load_policy_layer(root)


def test_policy_layer_rejects_recursive_include_cycle(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonc"
    second = tmp_path / "second.jsonc"
    first.write_text('{"include":["second.jsonc"]}')
    second.write_text('{"include":["first.jsonc"]}')

    with pytest.raises(PolicyError, match=r"include cycle:.*first\.jsonc.*second\.jsonc.*first\.jsonc"):
        load_policy_layer(first)


def test_more_specific_allow_overrides_ancestor_ask() -> None:
    global_policy = Policy(ask=(BashCommand(("git", "push")),))
    project_policy = Policy(allow=(BashCommand(("git", "push", "origin")),))

    verdict = _decide(global_policy.merged_with(project_policy), "git push origin main")

    assert verdict.decision is Decision.Allow


def test_more_specific_ask_overrides_ancestor_allow() -> None:
    global_policy = Policy(allow=(BashCommand(("git", "push")),))
    project_policy = Policy(ask=(BashCommand(("git", "push", "origin")),))

    verdict = _decide(global_policy.merged_with(project_policy), "git push origin main")

    assert verdict.decision is Decision.Ask


def test_ancestor_deny_cannot_be_overridden_by_more_specific_allow() -> None:
    global_policy = Policy(deny=(BashCommand(("git", "push")),))
    project_policy = Policy(allow=(BashCommand(("git", "push", "origin")),))

    verdict = _decide(global_policy.merged_with(project_policy), "git push origin main")

    assert verdict.decision is Decision.Deny


def test_ask_still_overrides_allow_within_one_policy_file() -> None:
    policy = Policy(
        ask=(BashCommand(("git", "push")),),
        allow=(BashCommand(("git", "push", "origin")),),
    )

    assert _decide(policy, "git push origin main").decision is Decision.Ask


def test_merged_policy_loads_global_and_all_ancestors_with_nearest_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Path("/home/example")
    cwd = Path("/workspace/project/src")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    policy_files = {
        home / POLICY_FILENAME: PolicyFile(
            policy=Policy(
                allow=(BashCommand(("cat",)),),
                redirection=RedirectionPolicy(stdout_to_file=Decision.Deny, allow_paths=("/global",)),
                python_calls=PythonCallPolicy(allow=frozenset({"package.read"})),
            )
        ),
        Path("/") / POLICY_FILENAME: PolicyFile(policy=Policy(allow=(BashCommand(("echo",)),))),
        Path("/workspace") / POLICY_FILENAME: PolicyFile(
            policy=Policy(
                ask=(BashCommand(("curl",)),),
                redirection=RedirectionPolicy(
                    stdout_to_file=Decision.Ask,
                    append_to_file=Decision.Deny,
                    allow_paths=("/workspace",),
                ),
                python_calls=PythonCallPolicy(ask=frozenset({"package.inspect"})),
            )
        ),
        Path("/workspace/project") / POLICY_FILENAME: PolicyFile(
            policy=Policy(
                deny=(BashCommand(("rm",)),),
                redirection=RedirectionPolicy(stdout_to_file=Decision.Ask, allow_paths=("/project",)),
                python_calls=PythonCallPolicy(deny=frozenset({"package.delete"})),
            )
        ),
        cwd / POLICY_FILENAME: PolicyFile(
            policy=Policy(
                allow=(BashCommand(("pwd",)), BashCommand(("curl", "https://approved.example"))),
                redirection=RedirectionPolicy(stdout_to_file=Decision.Allow, allow_paths=("/cwd",)),
            )
        ),
    }
    loaded: list[Path] = []

    def policy_exists(path: Path) -> bool:
        return path in policy_files

    def fake_load_policy_file(path: Path) -> PolicyFile:
        loaded.append(path)
        return policy_files[path]

    monkeypatch.setattr(Path, "exists", policy_exists)
    monkeypatch.setattr(policy_module, "load_policy_file", fake_load_policy_file)

    policy = merged_policy(cwd=cwd)

    assert loaded == list(policy_files)
    assert tuple(rule.prefix for rule in policy.allow if isinstance(rule, BashCommand)) == (
        ("cat",),
        ("echo",),
        ("pwd",),
        ("curl", "https://approved.example"),
    )
    assert tuple(rule.prefix for rule in policy.ask if isinstance(rule, BashCommand)) == (("curl",),)
    assert tuple(rule.prefix for rule in policy.deny if isinstance(rule, BashCommand)) == (("rm",),)
    assert policy.redirection.stdout_to_file is Decision.Allow
    assert policy.redirection.append_to_file is Decision.Deny
    assert policy.redirection.allow_paths == ("/global", "/workspace", "/project", "/cwd")
    assert policy.python_calls.allow == frozenset({"package.read"})
    assert policy.python_calls.ask == frozenset({"package.inspect"})
    assert policy.python_calls.deny == frozenset({"package.delete"})
    assert _decide(policy, "curl https://approved.example").decision is Decision.Allow


def test_merged_policy_loads_global_only_once_when_cwd_is_below_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = Path("/home/example")
    cwd = home / "project"
    global_path = home / POLICY_FILENAME
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    loaded: list[Path] = []

    def global_policy_exists(path: Path) -> bool:
        return path == global_path

    def recording_load(path: Path) -> PolicyFile:
        loaded.append(path)
        return PolicyFile(policy=Policy(allow=(BashCommand(("cat",)),)))

    monkeypatch.setattr(Path, "exists", global_policy_exists)
    monkeypatch.setattr(policy_module, "load_policy_file", recording_load)

    merged_policy(cwd=cwd)

    assert loaded.count(global_path) == 1


def test_merged_policy_accepts_legacy_local_root_keyword(monkeypatch: pytest.MonkeyPatch) -> None:
    home = Path("/home/example")
    local_root = Path("/workspace/project")
    policy_path = local_root / POLICY_FILENAME
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))

    def local_policy_exists(path: Path) -> bool:
        return path == policy_path

    def load_local_policy(path: Path) -> PolicyFile:
        assert path == policy_path
        return PolicyFile(policy=Policy(deny=(BashCommand(("rm",)),)))

    monkeypatch.setattr(Path, "exists", local_policy_exists)
    monkeypatch.setattr(policy_module, "load_policy_file", load_local_policy)

    policy = merged_policy(local_root=local_root)

    assert tuple(rule.prefix for rule in policy.deny if isinstance(rule, BashCommand)) == (("rm",),)


def test_merged_policy_rejects_cwd_and_legacy_local_root_together() -> None:
    with pytest.raises(TypeError, match="either cwd or local_root"):
        merged_policy(cwd=Path("/workspace"), local_root=Path("/workspace"))
