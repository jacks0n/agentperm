"""Policy decision tests — strictness, aggregation, rule matching, bypass coercion."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from agentperm import (
    BashCommand,
    Decision,
    JsonObject,
    NamedTool,
    Policy,
    PolicyFile,
    PythonCallPolicy,
    RedirectionPolicy,
    ShellPattern,
    load_policy_file,
    parse_rule,
    save_policy_file,
)
from tests.json_support import decode_object, json_at
from tests.policy_support import decide as _decide

# ---- Redirect policy configuration (shell.redirection) ---------------------


def test_stdout_to_file_configured_allow_defers_to_command_rule() -> None:
    """``stdoutToFile: allow`` means the redirect shape alone no longer forces Ask —
    the segment's own command rule decides, same as if there were no redirect."""
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Allow),
    )
    assert _decide(policy, "echo hi > out.txt").decision is Decision.Allow


def test_stdout_to_file_configured_allow_does_not_grant_unmatched_command() -> None:
    """Configuring the redirect shape to ``allow`` must not itself grant permission —
    an unmatched command still falls through to NoOpinion, same as without a redirect."""
    policy = Policy(redirection=RedirectionPolicy(stdout_to_file=Decision.Allow))
    assert _decide(policy, "weird_cmd > out.txt").decision is Decision.NoOpinion


def test_stdout_to_file_configured_deny_overrides_allowed_command() -> None:
    """``stdoutToFile: deny`` forces Deny even though the base command is allow-listed."""
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Deny),
    )
    assert _decide(policy, "echo hi > out.txt").decision is Decision.Deny


def test_strictest_redirect_wins_regardless_of_source_order() -> None:
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(
            stdout_to_file=Decision.Ask,
            append_to_file=Decision.Deny,
        ),
    )
    for command in (
        "echo hi > ask.txt >> denied.txt",
        "echo hi >> denied.txt > ask.txt",
    ):
        assert _decide(policy, command).decision is Decision.Deny, command


def test_append_to_file_is_configured_independently_of_stdout_to_file() -> None:
    """``>>`` (append) is governed by ``appendToFile``, not ``stdoutToFile`` — allowing
    one must not silently allow the other."""
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Allow),
    )
    assert _decide(policy, "echo hi > out.txt").decision is Decision.Allow
    verdict = _decide(policy, "echo hi >> out.txt")
    assert verdict.decision is Decision.Ask
    assert "out.txt" in verdict.rationale


def test_stderr_to_dev_null_configured_ask_overrides_default_no_opinion() -> None:
    """Default treats ``2>/dev/null`` as no-opinion; configuring ``ask`` forces a prompt."""
    policy = Policy(
        allow=(BashCommand(("cat",)),),
        redirection=RedirectionPolicy(stderr_to_dev_null=Decision.Ask),
    )
    assert _decide(policy, "cat foo 2>/dev/null").decision is Decision.Ask


def test_stdout_to_dev_null_configured_ask_overrides_default_no_opinion() -> None:
    """Same override, mirrored for the stdout-to-devnull bucket (bare ``>``/``1>``)."""
    policy = Policy(
        allow=(BashCommand(("cat",)),),
        redirection=RedirectionPolicy(stdout_to_dev_null=Decision.Ask),
    )
    assert _decide(policy, "cat foo > /dev/null").decision is Decision.Ask
    assert _decide(policy, "cat foo 1> /dev/null").decision is Decision.Ask


def test_stdout_and_stderr_to_dev_null_are_configured_independently() -> None:
    """Configuring one devnull bucket must not affect the other."""
    policy = Policy(
        allow=(BashCommand(("cat",)),),
        redirection=RedirectionPolicy(stdout_to_dev_null=Decision.Ask),
    )
    assert _decide(policy, "cat foo > /dev/null").decision is Decision.Ask
    assert _decide(policy, "cat foo 2>/dev/null").decision is Decision.Allow


def test_fd_dup_redirect_unaffected_by_redirect_config() -> None:
    """``2>&1`` never touches the filesystem — it stays no-opinion regardless of config."""
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Deny, append_to_file=Decision.Deny),
    )
    assert _decide(policy, "echo hi 2>&1").decision is Decision.Allow


def test_stderr_to_file_uses_stdout_to_file_config() -> None:
    """``2>file`` (stderr redirected to a file) is governed by ``stdoutToFile`` —
    there is no separate ``stderrToFile`` knob.  The fd distinction only applies
    to the ``/dev/null`` buckets."""
    policy = Policy(
        allow=(BashCommand(("make",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Allow),
    )
    assert _decide(policy, "make 2>errors.log").decision is Decision.Allow
    deny_policy = Policy(
        allow=(BashCommand(("make",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Deny),
    )
    assert _decide(deny_policy, "make 2>errors.log").decision is Decision.Deny


def test_redirection_policy_merge_keeps_unset_keys_from_base() -> None:
    """A local file that only sets ``appendToFile`` must not reset an unrelated
    ``stdoutToFile`` customization from the global file."""
    base = RedirectionPolicy(stdout_to_file=Decision.Allow)
    override = RedirectionPolicy(append_to_file=Decision.Deny)
    merged = base.merged_with(override)
    assert merged.stdout_to_file is Decision.Allow
    assert merged.append_to_file is Decision.Deny
    assert merged.stderr_to_dev_null is None


def test_redirection_policy_merge_lets_override_win_on_shared_key() -> None:
    base = RedirectionPolicy(stdout_to_file=Decision.Allow)
    override = RedirectionPolicy(stdout_to_file=Decision.Deny)
    assert base.merged_with(override).stdout_to_file is Decision.Deny


def test_policy_merged_with_combines_redirection_config() -> None:
    global_policy = Policy(redirection=RedirectionPolicy(stdout_to_file=Decision.Allow))
    local_policy = Policy(redirection=RedirectionPolicy(append_to_file=Decision.Deny))
    merged = global_policy.merged_with(local_policy)
    assert merged.redirection.stdout_to_file is Decision.Allow
    assert merged.redirection.append_to_file is Decision.Deny


def test_load_policy_file_parses_shell_redirection_block(tmp_path: Path) -> None:
    path = tmp_path / ".agent-permissions.jsonc"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "permissions": {"allow": ["Bash(echo:*)"]},
                "shell": {
                    "redirection": {
                        "stdoutToFile": "allow",
                        "appendToFile": "deny",
                        "stdoutToDevNull": "ask",
                    }
                },
            }
        )
    )
    policy = load_policy_file(path).policy
    assert policy.redirection.stdout_to_file is Decision.Allow
    assert policy.redirection.append_to_file is Decision.Deny
    assert policy.redirection.stdout_to_dev_null is Decision.Ask
    assert policy.redirection.stderr_to_dev_null is None


def test_load_policy_file_ignores_invalid_redirection_value(tmp_path: Path) -> None:
    path = tmp_path / ".agent-permissions.jsonc"
    path.write_text(
        json.dumps({"version": 1, "permissions": {}, "shell": {"redirection": {"stdoutToFile": "sometimes"}}})
    )
    policy = load_policy_file(path).policy
    assert policy.redirection.stdout_to_file is None


def test_load_policy_file_parses_python_call_decisions(tmp_path: Path) -> None:
    path = tmp_path / ".agent-permissions.jsonc"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "permissions": {"allow": ["Python(readonly)"]},
                "python": {
                    "calls": {
                        "allow": ["project.allowed"],
                        "ask": ["project.ambiguous"],
                        "deny": ["project.forbidden"],
                    }
                },
            }
        )
    )
    policy = load_policy_file(path).policy
    assert policy.python_calls == PythonCallPolicy(
        allow=frozenset({"project.allowed"}),
        ask=frozenset({"project.ambiguous"}),
        deny=frozenset({"project.forbidden"}),
    )


def test_python_call_policy_merge_unions_each_decision() -> None:
    base = Policy(python_calls=PythonCallPolicy(allow=frozenset({"a"}), deny=frozenset({"blocked"})))
    local = Policy(python_calls=PythonCallPolicy(ask=frozenset({"review"}), deny=frozenset({"a"})))
    merged = base.merged_with(local)
    assert merged.python_calls.allow == frozenset({"a"})
    assert merged.python_calls.ask == frozenset({"review"})
    assert merged.python_calls.deny == frozenset({"blocked", "a"})


def test_more_specific_python_call_allow_overrides_ancestor_ask() -> None:
    base = PythonCallPolicy(ask=frozenset({"project.inspect"}))
    local = PythonCallPolicy(allow=frozenset({"project.inspect"}))

    assert base.merged_with(local).decision_for("project.inspect") is Decision.Allow


def test_ancestor_python_call_deny_cannot_be_overridden() -> None:
    base = PythonCallPolicy(deny=frozenset({"project.mutate"}))
    local = PythonCallPolicy(allow=frozenset({"project.mutate"}))

    assert base.merged_with(local).decision_for("project.mutate") is Decision.Deny


def test_save_policy_file_serializes_python_call_decisions(tmp_path: Path) -> None:
    path = tmp_path / ".agent-permissions.jsonc"
    policy_file = PolicyFile(
        policy=Policy(
            python_calls=PythonCallPolicy(
                allow=frozenset({"project.allowed"}),
                ask=frozenset({"project.review"}),
                deny=frozenset({"project.blocked"}),
            )
        )
    )
    save_policy_file(path, policy_file)
    calls = json_at(decode_object(path.read_text()), "python", "calls")
    assert calls == {
        "allow": ["project.allowed"],
        "ask": ["project.review"],
        "deny": ["project.blocked"],
    }


def test_save_policy_file_preserves_rule_reason_metadata(tmp_path: Path) -> None:
    path = tmp_path / ".agent-permissions.jsonc"
    reason = "Generated output; modify its source."
    policy_file = PolicyFile(policy=Policy(deny=(NamedTool("Write", "generated/**", rationale=reason),)))
    save_policy_file(path, policy_file)

    saved = decode_object(path.read_text())
    assert json_at(saved, "permissions", "deny") == [{"Write(generated/**)": {"reason": reason}}]
    loaded = load_policy_file(path).policy
    assert loaded.deny == policy_file.policy.deny
    assert loaded.deny[0].rationale == reason


def test_save_policy_file_clears_existing_python_call_decisions(tmp_path: Path) -> None:
    path = tmp_path / ".agent-permissions.jsonc"
    raw: JsonObject = {"python": {"calls": {"deny": ["stale.call"], "extension": "preserved"}}}
    save_policy_file(path, PolicyFile(policy=Policy(), raw=raw))
    calls = json_at(decode_object(path.read_text()), "python", "calls")
    assert calls == {"allow": [], "ask": [], "deny": [], "extension": "preserved"}
    assert load_policy_file(path).policy.python_calls == PythonCallPolicy()


def test_save_policy_file_round_trips_and_clears_redirection_policy(tmp_path: Path) -> None:
    path = tmp_path / ".agent-permissions.jsonc"
    policy = Policy(
        redirection=RedirectionPolicy(
            stdout_to_file=Decision.Allow,
            append_to_file=Decision.Deny,
        )
    )
    save_policy_file(path, PolicyFile(policy=policy))
    assert load_policy_file(path).policy.redirection == policy.redirection

    raw = decode_object(path.read_text())
    save_policy_file(path, PolicyFile(policy=Policy(), raw=raw))
    assert load_policy_file(path).policy.redirection == RedirectionPolicy()


# ---- Redirect allowPaths ---------------------------------------------------


def test_global_allow_paths_permits_matching_redirect(tmp_path: Path) -> None:
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Ask, allow_paths=("/tmp",)),
    )
    verdict = _decide(policy, "echo hi > /tmp/out.txt")
    assert verdict.decision is Decision.Allow


def test_global_allow_paths_asks_for_non_matching_redirect() -> None:
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Ask, allow_paths=("/tmp",)),
    )
    verdict = _decide(policy, "echo hi > /etc/out.txt")
    assert verdict.decision is Decision.Ask


def test_global_allow_paths_with_glob(tmp_path: Path) -> None:
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(allow_paths=(str(tmp_path / "out-*"),)),
    )
    target = tmp_path / "out-123" / "file.txt"
    verdict = _decide(policy, f"echo hi > {target}")
    assert verdict.decision is Decision.Allow


def test_per_rule_allow_paths_permits_redirect() -> None:
    rule = parse_rule({"Shell(mise exec just synth-env)": {"allowPaths": ["/tmp"]}})
    assert isinstance(rule, ShellPattern)
    policy = Policy(allow=(rule,))
    verdict = _decide(policy, "mise exec -- just synth-env pr-9 > /tmp/out.txt")
    assert verdict.decision is Decision.Allow


def test_per_rule_allow_paths_from_narrower_rule_applies_when_broader_matches_first() -> None:
    broad_rule = parse_rule("Shell({echo,ls})")
    narrow_with_paths = parse_rule({"Shell(echo)": {"allowPaths": ["/tmp"]}})
    assert isinstance(broad_rule, ShellPattern)
    assert isinstance(narrow_with_paths, ShellPattern)
    policy = Policy(allow=(broad_rule, narrow_with_paths))
    assert _decide(policy, "echo hi > /tmp/out.txt").decision is Decision.Allow
    assert _decide(policy, "ls > /tmp/out.txt").decision is Decision.Ask


def test_per_rule_allow_paths_not_applied_when_different_rule_matches() -> None:
    rule_with_paths = parse_rule({"Shell(mise exec just synth-env)": {"allowPaths": ["/tmp"]}})
    rule_echo = parse_rule("Shell(echo)")
    assert isinstance(rule_with_paths, ShellPattern)
    assert isinstance(rule_echo, ShellPattern)
    policy = Policy(allow=(rule_with_paths, rule_echo))
    verdict = _decide(policy, "echo hi > /tmp/out.txt")
    assert verdict.decision is Decision.Ask


def test_global_and_per_rule_paths_combined() -> None:
    rule = parse_rule({"Shell(echo)": {"allowPaths": ["/var/log"]}})
    assert isinstance(rule, ShellPattern)
    policy = Policy(
        allow=(rule,),
        redirection=RedirectionPolicy(allow_paths=("/tmp",)),
    )
    assert _decide(policy, "echo hi > /tmp/out.txt").decision is Decision.Allow
    assert _decide(policy, "echo hi > /var/log/app.log").decision is Decision.Allow
    assert _decide(policy, "echo hi > /etc/out.txt").decision is Decision.Ask


def test_allow_paths_applies_to_appends() -> None:
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(append_to_file=Decision.Ask, allow_paths=("/tmp",)),
    )
    verdict = _decide(policy, "echo hi >> /tmp/out.txt")
    assert verdict.decision is Decision.Allow


def test_allow_paths_relative_target_resolved_with_cwd(tmp_path: Path) -> None:
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(allow_paths=(str(tmp_path),)),
    )
    verdict = _decide(policy, "echo hi > out.txt", cwd=tmp_path)
    assert verdict.decision is Decision.Allow
    verdict_no_cwd = _decide(policy, "echo hi > out.txt")
    assert verdict_no_cwd.decision is Decision.Ask


def test_allow_paths_symlink_resolution(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real_dir)
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(allow_paths=(str(link),)),
    )
    verdict = _decide(policy, f"echo hi > {real_dir}/out.txt")
    assert verdict.decision is Decision.Allow


def test_allow_paths_merge_deduplicates() -> None:
    a = RedirectionPolicy(allow_paths=("/tmp", "/var"))
    b = RedirectionPolicy(allow_paths=("/var", "/home"))
    merged = a.merged_with(b)
    assert merged.allow_paths == ("/tmp", "/var", "/home")


def test_allow_paths_policy_file_round_trip(tmp_path: Path) -> None:
    path = tmp_path / ".agent-permissions.jsonc"
    policy = Policy(
        redirection=RedirectionPolicy(
            stdout_to_file=Decision.Ask,
            allow_paths=("/tmp", "/var/log"),
        )
    )
    save_policy_file(path, PolicyFile(policy=policy, raw={}))
    reloaded = load_policy_file(path)
    assert reloaded.policy.redirection.allow_paths == ("/tmp", "/var/log")
    assert reloaded.policy.redirection.stdout_to_file is Decision.Ask


# ---- File permissions ------------------------------------------------------


@pytest.mark.parametrize("exists_before", [False, True])
def test_atomic_write_sets_owner_only_permissions(tmp_path: Path, exists_before: bool) -> None:
    path = tmp_path / "policy.jsonc"
    if exists_before:
        path.write_text("{}")
        os.chmod(path, 0o644)
    from agentperm.fileio import atomic_write

    atomic_write(path, '{"version": 1}\n')
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
