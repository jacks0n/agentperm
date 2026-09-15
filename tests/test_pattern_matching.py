"""Shell pattern DSL tests — parser, normalizer, matcher, policy integration."""

from __future__ import annotations

import pytest

from agentperm import (
    Segment,
    ShellPattern,
    parse_rule,
)
from agentperm.shellpattern import parse_shell_pattern, split_and_normalize
from tests.pattern_support import segment as _seg

# ---- Argv normalizer: argv[0] always operand -----------------------------


def test_normalize_argv0_dash_prefix_is_operand() -> None:
    """argv[0] starting with '-' must be treated as an operand, not a flag."""
    ops, atoms, _vals = split_and_normalize(("-weird", "-a", "file"), frozenset())
    assert ops[0] == "-weird"
    assert "-weird" not in atoms
    assert "-a" in atoms


# ---- Argv normalizer -----------------------------------------------------


def test_normalize_short_cluster() -> None:
    ops, atoms, _vals = split_and_normalize(("rm", "-rf", "/"), frozenset())
    assert atoms == {"-r", "-f"}
    assert ops == ["rm", "/"]


def test_normalize_long_flag_equals() -> None:
    ops, atoms, vals = split_and_normalize(("curl", "--output=data.json"), frozenset())
    assert "--output" in atoms
    assert vals["--output"] == ["data.json"]
    assert ops == ["curl"]


def test_normalize_double_dash_terminates_flags() -> None:
    ops, atoms, _vals = split_and_normalize(("git", "push", "--", "--force"), frozenset())
    assert "--force" not in atoms
    assert ops == ["git", "push", "--force"]


def test_normalize_bare_dash_is_operand() -> None:
    ops, atoms, _vals = split_and_normalize(("cat", "-"), frozenset())
    assert ops == ["cat", "-"]
    assert len(atoms) == 0


def test_normalize_declared_value_flag_long() -> None:
    ops, atoms, vals = split_and_normalize(
        ("curl", "--output", "data.json", "http://example.com"),
        frozenset({"--output"}),
    )
    assert "--output" in atoms
    assert vals["--output"] == ["data.json"]
    assert ops == ["curl", "http://example.com"]


def test_normalize_declared_value_flag_short() -> None:
    ops, atoms, vals = split_and_normalize(
        ("tar", "-f", "archive.tar", "-x"),
        frozenset({"-f"}),
    )
    assert "-f" in atoms
    assert vals["-f"] == ["archive.tar"]
    assert "-x" in atoms
    assert ops == ["tar"]


def test_normalize_value_consumed_dash_token_preserved_as_flag() -> None:
    """A dash-prefixed token consumed as a value is also preserved in flag_atoms."""
    ops, atoms, _vals = split_and_normalize(
        ("cmd", "--mode", "--danger", "run"),
        frozenset({"--mode"}),
    )
    assert "--mode" in atoms
    assert "--danger" in atoms
    assert ops == ["cmd", "run"]


@pytest.mark.parametrize(
    ("argv", "value_flags", "expected_atoms", "expected_vals", "absent_atoms", "expected_ops"),
    [
        # Value flag in trailing cluster position — attached value
        (
            ("curl", "-sXGET", "http://x.com"),
            frozenset({"-X"}),
            {"-s", "-X"},
            {"-X": ["GET"]},
            {"-G", "-E", "-T"},
            ["curl", "http://x.com"],
        ),
        # Value flag at end of cluster — next token consumed
        (
            ("curl", "-sX", "GET", "http://x.com"),
            frozenset({"-X"}),
            {"-s", "-X"},
            {"-X": ["GET"]},
            set[str](),
            ["curl", "http://x.com"],
        ),
        # Value flag at start of cluster (existing behaviour)
        (
            ("curl", "-XGET", "http://x.com"),
            frozenset({"-X"}),
            {"-X"},
            {"-X": ["GET"]},
            {"-G", "-E", "-T"},
            ["curl", "http://x.com"],
        ),
        # Multiple boolean flags before value flag
        (
            ("tar", "-czf", "out.tar.gz", "src/"),
            frozenset({"-f"}),
            {"-c", "-z", "-f"},
            {"-f": ["out.tar.gz"]},
            set[str](),
            ["tar", "src/"],
        ),
    ],
)
def test_normalize_value_flag_in_cluster(
    argv: tuple[str, ...],
    value_flags: frozenset[str],
    expected_atoms: set[str],
    expected_vals: dict[str, list[str]],
    absent_atoms: set[str],
    expected_ops: list[str],
) -> None:
    ops, atoms, vals = split_and_normalize(argv, value_flags)
    assert expected_atoms <= atoms
    for flag, values in expected_vals.items():
        assert vals[flag] == values
    for absent in absent_atoms:
        assert absent not in atoms
    assert ops == expected_ops


@pytest.mark.parametrize(
    ("consumed", "expected"),
    [
        ("-rf", {"-r", "-f"}),
        ("--danger=x", {"--danger"}),
        ("-XDELETE", {"-X", "-D", "-E", "-L", "-T"}),
    ],
)
def test_normalize_consumed_dash_token_uses_canonical_atoms(consumed: str, expected: set[str]) -> None:
    _ops, atoms, _vals = split_and_normalize(
        ("cmd", "--mode", consumed, "run"),
        frozenset({"--mode"}),
    )
    assert expected <= atoms


def test_normalize_value_consumed_dash_token_short() -> None:
    """Same preservation for short value flags."""
    ops, atoms, _vals = split_and_normalize(
        ("cmd", "-m", "--danger", "run"),
        frozenset({"-m"}),
    )
    assert "-m" in atoms
    assert "--danger" in atoms
    assert ops == ["cmd", "run"]


def test_normalize_repeated_flag_values() -> None:
    """Repeated flags collect all values."""
    _ops, _atoms, vals = split_and_normalize(
        ("curl", "--output=a.txt", "--output=b.json"),
        frozenset(),
    )
    assert vals["--output"] == ["a.txt", "b.json"]


def test_normalize_short_option_attached_value() -> None:
    """A declared short value option consumes the remainder of its token."""
    ops, atoms, vals = split_and_normalize(
        ("cmd", "-abc", "file"),
        frozenset({"-a"}),
    )
    assert atoms == {"-a"}
    assert ops == ["cmd", "file"]
    assert vals["-a"] == ["bc"]


@pytest.mark.parametrize(("token", "value"), [("-XGET", "GET"), ("-X=GET", "GET")])
def test_normalize_short_option_attached_value_forms(token: str, value: str) -> None:
    ops, atoms, vals = split_and_normalize(("gh", token, "api"), frozenset({"-X"}))
    assert ops == ["gh", "api"]
    assert atoms == {"-X"}
    assert vals["-X"] == [value]


# ---- Matching: parametrized ----------------------------------------------


@pytest.mark.parametrize(
    "pattern, argv, expected",
    [
        # Basic prefix matching
        ("git status", ("git", "status"), True),
        ("git status", ("git", "status", "--short"), True),
        ("git status", ("git",), False),
        ("git status", ("ls",), False),
        # Basename matching on argv[0]
        ("git status", ("/usr/bin/git", "status"), True),
        # Glob in operand
        ("git checkout feature/*", ("git", "checkout", "feature/login"), True),
        ("git checkout feature/*", ("git", "checkout", "main"), False),
        # Bare * matches one operand
        ("git *", ("git", "status"), True),
        ("git *", ("git",), False),
        ("git * --short", ("git", "status", "--short"), True),
        # Alternation set
        ("git {status,log,diff}", ("git", "status"), True),
        ("git {status,log,diff}", ("git", "log"), True),
        ("git {status,log,diff}", ("git", "push"), False),
        # Alternation with glob members
        ("git checkout {feature/*,fix/*}", ("git", "checkout", "feature/x"), True),
        ("git checkout {feature/*,fix/*}", ("git", "checkout", "main"), False),
        # Negated set
        ("git !{push,reset}", ("git", "status"), True),
        ("git !{push,reset}", ("git", "push"), False),
        ("git !{push,reset}", ("git",), False),
        # Gap (...)
        ("docker ... up", ("docker", "compose", "up"), True),
        ("docker ... up", ("docker", "up"), True),
        ("docker ... up", ("docker", "compose", "-f", "x.yml", "up"), True),
        ("docker ... up", ("docker", "compose", "down"), False),
        # Exact operands (!...)
        ("git stash !...", ("git", "stash"), True),
        ("git stash !...", ("git", "stash", "list"), False),
        # Exact with gap
        ("cmd ... target !...", ("cmd", "a", "b", "target"), True),
        ("cmd ... target !...", ("cmd", "a", "target", "b"), False),
        # Required flag
        ("git push --set-upstream", ("git", "push", "--set-upstream", "origin"), True),
        ("git push --set-upstream", ("git", "push", "origin"), False),
        # Required flag — position independence
        ("git push --set-upstream", ("git", "--set-upstream", "push", "origin"), True),
        # Forbidden flag
        ("git push !--force", ("git", "push", "origin"), True),
        ("git push !--force", ("git", "push", "--force", "origin"), False),
        ("git push !--force", ("git", "--force", "push", "origin"), False),
        # Short flag cluster normalization
        ("rm -r -f", ("rm", "-rf", "/"), True),
        ("rm -r -f", ("rm", "-r", "-f", "/"), True),
        ("rm -r -f", ("rm", "-r", "/"), False),
        # Closed flags (!-*)
        ("git stash !-*", ("git", "stash"), True),
        ("git stash !-*", ("git", "stash", "list"), True),
        ("git stash !-*", ("git", "stash", "--keep-index"), False),
        # only(...)
        ("git stash only(--keep-index, -p)", ("git", "stash", "--keep-index"), True),
        ("git stash only(--keep-index, -p)", ("git", "stash", "-p"), True),
        ("git stash only(--keep-index, -p)", ("git", "stash"), True),
        ("git stash only(--keep-index, -p)", ("git", "stash", "--force"), False),
        # only(...) with required flag — required flag is auto-permitted
        ("git push --set-upstream only(--no-verify)", ("git", "push", "--set-upstream", "origin"), True),
        ("git push --set-upstream only(--no-verify)", ("git", "push", "--set-upstream", "--no-verify", "origin"), True),
        ("git push --set-upstream only(--no-verify)", ("git", "push", "--set-upstream", "--force", "origin"), False),
        # Exact + closed
        ("git status --short !... !-*", ("git", "status", "--short"), True),
        ("git status --short !... !-*", ("git", "status"), False),
        ("git status --short !... !-*", ("git", "status", "--short", "--verbose"), False),
        ("git status --short !... !-*", ("git", "status", "--short", "extra"), False),
        # Value constraint
        ("curl --output=*.json", ("curl", "--output=data.json", "http://x"), True),
        ("curl --output=*.json", ("curl", "--output=data.xml", "http://x"), False),
        ("curl --output=*.json", ("curl", "http://x"), False),
        # Value constraint with space-separated value
        ("curl --output=*.json", ("curl", "--output", "data.json", "http://x"), True),
        ("curl --output=*.json", ("curl", "--output", "data.xml", "http://x"), False),
        # Flag any-of set
        ("git push {--force,--force-with-lease,-f}", ("git", "push", "--force"), True),
        ("git push {--force,--force-with-lease,-f}", ("git", "push", "-f"), True),
        ("git push {--force,--force-with-lease,-f}", ("git", "push"), False),
        # -- separator: flags after -- are operands
        ("git push !--force", ("git", "push", "--", "--force"), True),
        # Forbidden flag set
        ("sed !{-i,--in-place}", ("sed", "-n", "1,10p"), True),
        ("sed !{-i,--in-place}", ("sed", "-i", "s/a/b/"), False),
        ("sed !{-i,--in-place}", ("sed", "--in-place", "s/a/b/"), False),
        # Empty argv
        ("git status", (), False),
        # Single-word pattern
        ("ls", ("ls",), True),
        ("ls", ("ls", "-la"), True),
        ("ls", ("/bin/ls", "-la"), True),
        # Complex real-world: read-only AWS
        ("aws {ec2,s3} {describe-*,list-*}", ("aws", "ec2", "describe-instances", "--region", "us-east-1"), True),
        ("aws {ec2,s3} {describe-*,list-*}", ("aws", "s3", "list-buckets"), True),
        ("aws {ec2,s3} {describe-*,list-*}", ("aws", "ec2", "run-instances"), False),
        ("aws {ec2,s3} {describe-*,list-*}", ("aws", "iam", "list-users"), False),
        # values() arity hint — flag value before operands
        (
            "aws values(--region, --profile) ec2 describe-*",
            ("aws", "--region", "us-east-1", "ec2", "describe-instances"),
            True,
        ),
        (
            "aws values(--region, --profile) ec2 describe-*",
            ("aws", "--profile", "dev", "--region", "ap-southeast-2", "ec2", "describe-instances"),
            True,
        ),
        ("aws values(--region, --profile) ec2 describe-*", ("aws", "ec2", "describe-instances"), True),
        (
            "aws values(--region, --profile) ec2 describe-*",
            ("aws", "ec2", "describe-instances", "--region", "us-east-1"),
            True,
        ),
        (
            "aws values(--region, --profile) ec2 describe-*",
            ("aws", "ec2", "describe-instances", "--region=us-east-1"),
            True,
        ),
        # Without values(), a possible option value stays an operand and cannot be
        # skipped to reach a later command path.
        ("aws ec2 describe-*", ("aws", "--region", "us-east-1", "ec2", "describe-instances"), False),
        # Global value options must be declared before separate values are consumed.
        ("gh pr view", ("gh", "--repo", "owner/repo", "pr", "view"), False),
        ("gh values(--repo) pr view", ("gh", "--repo", "owner/repo", "pr", "view"), True),
        ("git push --force", ("git", "-C", "/repo", "push", "--force"), False),
        # Ordinary operands that do not follow a flag are never skipped.
        ("gh pr view", ("gh", "unexpected", "pr", "view"), False),
        # -- terminates option inference.
        ("gh pr view", ("gh", "--", "--repo", "owner/repo", "pr", "view"), False),
        # A pattern may explicitly require the end-of-options separator. Patterns
        # that omit it retain the historical behavior where argv normalization
        # drops the separator.
        ("mise exec -- just {check,dev}", ("mise", "exec", "--", "just", "check"), True),
        ("mise exec -- just {check,dev}", ("mise", "exec", "--", "just", "dev"), True),
        ("mise exec -- just {check,dev}", ("mise", "exec", "just", "dev"), False),
        ("mise exec just dev", ("mise", "exec", "--", "just", "dev"), True),
        # values() with short flag
        ("git values(-C) status", ("git", "-C", "/other/repo", "status"), True),
        # Value-consumed token that looks like a flag is still visible to forbidden check
        ("cmd values(--mode) run !--danger", ("cmd", "--mode", "--danger", "run"), False),
        ("cmd values(--mode) run !--danger", ("cmd", "--mode", "safe", "run"), True),
        ("cmd values(--mode) run !-r", ("cmd", "--mode", "-rf", "run"), False),
        ("cmd values(--mode) run !-f", ("cmd", "--mode", "-rf", "run"), False),
        ("cmd values(--mode) run !--danger", ("cmd", "--mode", "--danger=x", "run"), False),
        ("cmd values(--mode) run !-X", ("cmd", "--mode", "-XDELETE", "run"), False),
        # Short value options support separate and attached forms consistently.
        ("gh -X=GET api", ("gh", "-X", "GET", "api"), True),
        ("gh -X=GET api", ("gh", "-XGET", "api"), True),
        ("gh -X=GET api", ("gh", "-X=GET", "api"), True),
        ("gh -X=GET api", ("gh", "-XDELETE", "api"), False),
        # Repeated constrained option — ALL values must match
        ("curl --output=*.json", ("curl", "--output=a.json", "--output=b.json"), True),
        ("curl --output=*.json", ("curl", "--output=bad.txt", "--output=good.json"), False),
        ("curl --output=*.json", ("curl", "--output=good.json", "--output=bad.txt"), False),
        ("curl --output=*.json", ("curl", "--output=good.json", "--output"), False),
        ("curl --output=*.json", ("curl", "--output", "--output=good.json"), False),
        # Multiple gaps (exercises memoized path matching)
        ("cmd ... middle ... end", ("cmd", "a", "b", "middle", "c", "end"), True),
        ("cmd ... middle ... end", ("cmd", "middle", "end"), True),
        ("cmd ... middle ... end", ("cmd", "a", "end"), False),
        # Escaped star matches literal asterisk
        ("echo \\*", ("echo", "*"), True),
        ("echo \\*", ("echo", "foo"), False),
    ],
)
def test_shell_pattern_match(pattern: str, argv: tuple[str, ...], expected: bool) -> None:
    rule = parse_shell_pattern(pattern)
    segment = _seg(*argv) if argv else Segment(argv=(), redirects=())
    assert rule.matches(segment) is expected, f"Shell({pattern}) vs {argv}"


# ---- Round-trip serialization --------------------------------------------


@pytest.mark.parametrize(
    "rule_str",
    [
        "Shell(git status)",
        "Shell(git {status,log,diff})",
        "Shell(git push !--force)",
        "Shell(git stash only(--keep-index, -p))",
        "Shell(git stash ?--keep-index ?-p !-*)",
        "Shell(curl --output=*.json)",
        "Shell(git stash !... !-*)",
        "Shell(docker ... up)",
        "Shell(rm -r -f)",
        "Shell(git push {--force,--force-with-lease,-f})",
        "Shell(sed !{-i,--in-place})",
        "Shell(aws values(--region, --profile) ec2 describe-*)",
        "Shell(mise exec -- just {check,dev})",
    ],
)
def test_round_trip(rule_str: str) -> None:
    rule = parse_rule(rule_str)
    assert isinstance(rule, ShellPattern)
    assert rule.serialize() == rule_str
