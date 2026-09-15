"""Shell pattern DSL tests — parser, normalizer, matcher, policy integration."""

from __future__ import annotations

import pytest

from agentperm import (
    Decision,
    Policy,
    ShellPattern,
    parse_rule,
)
from agentperm.errors import PolicyError
from agentperm.shellpattern import parse_shell_pattern
from tests.pattern_support import decide as _decide
from tests.pattern_support import segment as _seg
from tests.pattern_support import shell_rule as _shell_rule

# ---- Policy integration -------------------------------------------------


def test_policy_shell_allow() -> None:
    rule = _shell_rule("Shell(git {status,log,diff})")
    policy = Policy(allow=(rule,))
    result = _decide(policy, "git status --short")
    assert result.decision is Decision.Allow


def test_policy_shell_deny_overrides_allow() -> None:
    allow = _shell_rule("Shell(git push)")
    deny = _shell_rule("Shell(git push {--force,--force-with-lease,-f})")
    policy = Policy(allow=(allow,), deny=(deny,))
    assert _decide(policy, "git push origin main").decision is Decision.Allow
    assert _decide(policy, "git push --force origin main").decision is Decision.Deny


def test_policy_shell_forbidden_flag_deny() -> None:
    deny = _shell_rule("Shell(rm -r -f)")
    policy = Policy(deny=(deny,))
    assert _decide(policy, "rm -rf /").decision is Decision.Deny
    assert _decide(policy, "rm foo").decision is Decision.NoOpinion


def test_unknown_global_option_value_cannot_hide_deny_path() -> None:
    deny = _shell_rule("Shell(git push --force)")
    policy = Policy(deny=(deny,))
    assert _decide(policy, "git -C /repo push --force").decision is Decision.Deny


def test_unknown_option_value_cannot_smuggle_git_alias_into_open_allow_path() -> None:
    allow = _shell_rule("Shell(git status)")
    policy = Policy(allow=(allow,))
    command = "git -c 'alias.status=!touch /tmp/pwned' status"
    assert _decide(policy, command).decision is Decision.NoOpinion


def test_closed_flag_allow_rejects_attached_semantic_option_value() -> None:
    allow = _shell_rule("Shell(git status !-*)")
    policy = Policy(allow=(allow,))
    command = "git -calias.status='!touch /tmp/pwned' status"
    assert _decide(policy, command).decision is Decision.NoOpinion


def test_policy_shell_coexists_with_bash_command() -> None:
    from agentperm import BashCommand

    bash_rule = BashCommand(("ls",))
    shell_rule = _shell_rule("Shell(git {status,log})")
    policy = Policy(allow=(bash_rule, shell_rule))
    assert _decide(policy, "ls -la").decision is Decision.Allow
    assert _decide(policy, "git status").decision is Decision.Allow
    assert _decide(policy, "rm foo").decision is Decision.NoOpinion


def test_policy_shell_compound_command() -> None:
    allow = _shell_rule("Shell(git status)")
    policy = Policy(allow=(allow,))
    result = _decide(policy, "git status && echo done")
    assert result.decision is Decision.Allow


def test_policy_shell_dict_values() -> None:
    """Dict form {"rule": "Shell(...)", "values": [...]} merges into value_flags."""
    rule = parse_rule({"rule": "Shell(aws ec2 describe-*)", "values": ["--region", "--profile"]})
    assert isinstance(rule, ShellPattern)
    assert rule.value_flags == frozenset({"--region", "--profile"})
    policy = Policy(allow=(rule,))
    assert _decide(policy, "aws --region us-east-1 ec2 describe-instances").decision is Decision.Allow
    assert _decide(policy, "aws ec2 describe-instances").decision is Decision.Allow


def test_policy_shell_dict_values_merge_with_inline() -> None:
    """Dict values merge with inline values()."""
    rule = parse_rule(
        {
            "rule": "Shell(aws values(--output) ec2 describe-*)",
            "values": ["--region", "--profile"],
        }
    )
    assert isinstance(rule, ShellPattern)
    assert rule.value_flags == frozenset({"--output", "--region", "--profile"})


def test_policy_shell_dict_no_values_key() -> None:
    """Dict form without 'values' key is equivalent to the string form."""
    rule = parse_rule({"rule": "Shell(aws ec2 describe-*)"})
    assert isinstance(rule, ShellPattern)
    assert rule.value_flags == frozenset()


def test_policy_shell_dict_values_invalid_non_flag() -> None:
    with pytest.raises(PolicyError, match="non-flag"):
        parse_rule({"rule": "Shell(aws ec2 describe-*)", "values": ["region"]})


def test_policy_shell_dict_values_invalid_not_array() -> None:
    with pytest.raises(PolicyError, match="array"):
        parse_rule({"rule": "Shell(aws ec2 describe-*)", "values": "--region"})


def test_policy_shell_dict_values_round_trip() -> None:
    """Dict-form values survive serialization round-trip via rule-as-key."""
    rule = parse_rule({"Shell(aws ec2 describe-*)": {"values": ["--region", "--profile"]}})
    assert isinstance(rule, ShellPattern)
    serialized = rule.serialize()
    assert isinstance(serialized, dict)
    key = "Shell(aws ec2 describe-*)"
    assert key in serialized
    opts = serialized[key]
    assert isinstance(opts, dict)
    values = opts["values"]
    assert isinstance(values, list)
    assert sorted(str(v) for v in values) == ["--profile", "--region"]
    reloaded = parse_rule(serialized)
    assert isinstance(reloaded, ShellPattern)
    assert reloaded.value_flags == frozenset({"--region", "--profile"})


def test_policy_shell_inline_values_serialize_as_string() -> None:
    """Inline values() serializes as a plain string, not a dict."""
    rule = parse_rule("Shell(aws values(--region) ec2 describe-*)")
    assert isinstance(rule, ShellPattern)
    serialized = rule.serialize()
    assert isinstance(serialized, str)
    assert serialized == "Shell(aws values(--region) ec2 describe-*)"


def test_shell_pattern_rejects_inconsistent_external_values() -> None:
    base = parse_shell_pattern("git status")
    with pytest.raises(ValueError, match="external values"):
        ShellPattern(
            raw=base.raw,
            path=base.path,
            flags=base.flags,
            flag_sets=base.flag_sets,
            closed_flags=base.closed_flags,
            exact=base.exact,
            value_flags=frozenset(),
            extra_values=frozenset({"--repo"}),
        )


def test_policy_shell_sed_with_forbidden_flag() -> None:
    allow = _shell_rule("Shell({sed,gsed} !{-i,--in-place})")
    policy = Policy(allow=(allow,))
    assert _decide(policy, "sed -n 1,10p foo").decision is Decision.Allow
    assert _decide(policy, "sed -i '' s/a/b/ foo").decision is Decision.NoOpinion
    assert _decide(policy, "gsed -e s/a/b/ foo").decision is Decision.Allow


# ---- Rule-as-key dict form -------------------------------------------------


def test_rule_as_key_parses_allow_paths() -> None:
    rule = parse_rule({"Shell(echo)": {"allowPaths": ["/tmp", "/var"]}})
    assert isinstance(rule, ShellPattern)
    assert rule.allow_paths == ("/tmp", "/var")
    assert rule.matches(_seg("echo", "hi"))


def test_rule_as_key_parses_values() -> None:
    rule = parse_rule({"Shell(git status)": {"values": ["-C"]}})
    assert isinstance(rule, ShellPattern)
    assert rule.extra_values == frozenset({"-C"})
    assert "-C" in rule.value_flags


def test_rule_as_key_parses_combined_values_and_allow_paths() -> None:
    rule = parse_rule({"Shell(git status)": {"values": ["-C"], "allowPaths": ["/tmp"]}})
    assert isinstance(rule, ShellPattern)
    assert rule.extra_values == frozenset({"-C"})
    assert rule.allow_paths == ("/tmp",)


def test_rule_as_key_serialize_round_trip() -> None:
    rule = parse_rule({"Shell(echo)": {"allowPaths": ["/tmp"]}})
    assert isinstance(rule, ShellPattern)
    serialized = rule.serialize()
    assert isinstance(serialized, dict)
    assert "Shell(echo)" in serialized
    reloaded = parse_rule(serialized)
    assert isinstance(reloaded, ShellPattern)
    assert reloaded.allow_paths == ("/tmp",)


def test_rule_as_key_combined_serialize_round_trip() -> None:
    rule = parse_rule({"Shell(git status)": {"values": ["-C"], "allowPaths": ["/tmp"]}})
    assert isinstance(rule, ShellPattern)
    serialized = rule.serialize()
    reloaded = parse_rule(serialized)
    assert isinstance(reloaded, ShellPattern)
    assert reloaded.extra_values == frozenset({"-C"})
    assert reloaded.allow_paths == ("/tmp",)


def test_rule_as_key_rejects_non_dict_value() -> None:
    with pytest.raises(PolicyError, match="must be an object"):
        parse_rule({"Shell(echo)": "bad"})


def test_rule_as_key_rejects_bad_allow_paths() -> None:
    with pytest.raises(PolicyError, match="allowPaths"):
        parse_rule({"Shell(echo)": {"allowPaths": "not a list"}})


def test_rule_as_key_rejects_empty_allow_path_entry() -> None:
    with pytest.raises(PolicyError, match="non-empty string"):
        parse_rule({"Shell(echo)": {"allowPaths": [""]}})
