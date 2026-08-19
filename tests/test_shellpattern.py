"""Shell pattern DSL tests — parser, normalizer, matcher, policy integration."""

from __future__ import annotations

import pytest

from agentperm import (
    Decision,
    Policy,
    Segment,
    ShellPattern,
    ShellRequest,
    parse_pipeline,
    parse_rule,
)
from agentperm.domain import AnyRest, Disposition, OneOf, Word
from agentperm.errors import PolicyError
from agentperm.shellpattern import parse_shell_pattern, split_and_normalize


def _seg(*argv: str) -> Segment:
    return Segment(argv=argv, redirects=())


def _shell_rule(text: str) -> ShellPattern:
    rule = parse_rule(text)
    assert isinstance(rule, ShellPattern)
    return rule


def _decide(policy: Policy, command: str):
    return policy.decide(ShellRequest(parse_pipeline(command)))


# ---- Parser: basic term types --------------------------------------------


def test_parse_simple_words():
    pat = parse_shell_pattern("git status")
    assert len(pat.path) == 2
    assert isinstance(pat.path[0], Word)
    assert isinstance(pat.path[1], Word)
    assert pat.exact is False
    assert pat.closed_flags is False


def test_parse_double_dash_as_positional_separator():
    pat = parse_shell_pattern("mise exec -- just dev")
    assert isinstance(pat.path[2], Word)
    assert pat.path[2].glob == "--"
    assert not pat.flags


def test_parse_glob_in_word():
    pat = parse_shell_pattern("git checkout feature/*")
    assert isinstance(pat.path[2], Word)
    assert pat.path[2].glob == "feature/*"


def test_parse_bare_star():
    pat = parse_shell_pattern("git *")
    assert isinstance(pat.path[1], Word)
    assert pat.path[1].glob == "*"


def test_parse_alternation_set():
    pat = parse_shell_pattern("git {status,log,diff}")
    assert isinstance(pat.path[1], OneOf)
    assert pat.path[1].negated is False
    assert len(pat.path[1].globs) == 3


def test_parse_negated_set():
    pat = parse_shell_pattern("git !{push,reset}")
    assert isinstance(pat.path[1], OneOf)
    assert pat.path[1].negated is True


def test_parse_gap():
    pat = parse_shell_pattern("docker ... up")
    assert isinstance(pat.path[1], AnyRest)
    assert isinstance(pat.path[2], Word)


def test_parse_exact():
    pat = parse_shell_pattern("git stash !...")
    assert pat.exact is True
    assert pat.closed_flags is False
    assert len(pat.path) == 2


def test_parse_closed_flags():
    pat = parse_shell_pattern("git stash !-*")
    assert pat.closed_flags is True
    assert pat.exact is False


def test_parse_exact_and_closed():
    pat = parse_shell_pattern("git stash !... !-*")
    assert pat.exact is True
    assert pat.closed_flags is True


# ---- Parser: flag terms --------------------------------------------------


def test_parse_required_flag():
    pat = parse_shell_pattern("git push --set-upstream")
    assert any(
        c.atom == "--set-upstream" and c.disp is Disposition.Required
        for c in pat.flags
    )


def test_parse_required_short_flag():
    pat = parse_shell_pattern("rm -r -f")
    atoms = {c.atom for c in pat.flags if c.disp is Disposition.Required}
    assert atoms == {"-r", "-f"}


def test_parse_forbidden_flag():
    pat = parse_shell_pattern("git push !--force")
    assert any(
        c.atom == "--force" and c.disp is Disposition.Forbidden
        for c in pat.flags
    )


def test_parse_permitted_flag():
    pat = parse_shell_pattern("git stash ?--keep-index ?-p !-*")
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert permitted == {"--keep-index", "-p"}
    assert pat.closed_flags is True


def test_parse_value_constraint():
    pat = parse_shell_pattern("curl --output=*.json")
    fc = next(c for c in pat.flags if c.atom == "--output")
    assert fc.disp is Disposition.Required
    assert fc.value_glob == "*.json"
    assert "--output" in pat.value_flags


def test_parse_value_constraint_escaped_star():
    pat = parse_shell_pattern("curl --output=\\*.json")
    fc = next(c for c in pat.flags if c.atom == "--output")
    assert fc.value_glob == "[*].json"


def test_parse_empty_value_constraint():
    pat = parse_shell_pattern("curl --output=")
    fc = next(c for c in pat.flags if c.atom == "--output")
    assert fc.value_glob == ""


def test_parse_short_value_constraint():
    pat = parse_shell_pattern("gh -X=GET api")
    fc = next(c for c in pat.flags if c.atom == "-X")
    assert fc.value_glob == "GET"
    assert "-X" in pat.value_flags


# ---- Parser: only(...) ---------------------------------------------------


def test_parse_only():
    pat = parse_shell_pattern("git stash only(--keep-index, -p)")
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert permitted == {"--keep-index", "-p"}
    assert pat.closed_flags is True


def test_parse_only_with_required_flag():
    pat = parse_shell_pattern("git push --set-upstream only(--no-verify)")
    required = {c.atom for c in pat.flags if c.disp is Disposition.Required}
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert required == {"--set-upstream"}
    assert permitted == {"--no-verify"}
    assert pat.closed_flags is True


# ---- Parser: values(...) ------------------------------------------------


def test_parse_values():
    pat = parse_shell_pattern("aws values(--region, --profile) ec2 describe-*")
    assert pat.value_flags == frozenset({"--region", "--profile"})
    assert len(pat.flags) == 0
    assert len(pat.path) == 3


def test_parse_values_no_constraint():
    """values() flags don't emit any FlagConstraint."""
    pat = parse_shell_pattern("git values(-C) status")
    assert pat.value_flags == frozenset({"-C"})
    assert not any(c.atom == "-C" for c in pat.flags)


def test_parse_values_with_value_constraint():
    """values() flags and --flag=glob constraints coexist — both contribute to value_flags."""
    pat = parse_shell_pattern("curl values(--output) --output=*.json")
    assert "--output" in pat.value_flags
    fc = next(c for c in pat.flags if c.atom == "--output")
    assert fc.disp is Disposition.Required
    assert fc.value_glob == "*.json"


def test_parse_values_with_only():
    """values() and only() are orthogonal."""
    pat = parse_shell_pattern("aws values(--region) only(--output) ec2 describe-*")
    assert pat.value_flags == frozenset({"--region"})
    assert pat.closed_flags is True
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert permitted == {"--output"}


# ---- Parser: flag sets ---------------------------------------------------


def test_parse_flag_any_of_set():
    pat = parse_shell_pattern("git push {--force,--force-with-lease,-f}")
    assert len(pat.flag_sets) == 1
    assert set(pat.flag_sets[0]) == {"--force", "--force-with-lease", "-f"}


def test_parse_flag_none_of_set():
    pat = parse_shell_pattern("sed !{-i,--in-place}")
    forbidden = {c.atom for c in pat.flags if c.disp is Disposition.Forbidden}
    assert forbidden == {"-i", "--in-place"}
    assert len(pat.flag_sets) == 0


def test_parse_flag_permitted_set():
    pat = parse_shell_pattern("git stash ?{--keep-index,-p} !-*")
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert permitted == {"--keep-index", "-p"}


# ---- Parser: escaping ----------------------------------------------------


def test_parse_question_mark_not_glob():
    """? in the DSL is a sigil/literal, not an fnmatch single-char wildcard."""
    pat = parse_shell_pattern("cat file?.txt")
    assert isinstance(pat.path[1], Word)
    # ? is escaped to [?] internally so fnmatch treats it literally
    assert "[?]" in pat.path[1].glob


# ---- Parser: error cases -------------------------------------------------


def test_error_empty_pattern():
    with pytest.raises(PolicyError):
        parse_rule("Shell()")


def test_error_empty_braces():
    with pytest.raises(PolicyError, match="empty member"):
        parse_shell_pattern("git {}")


def test_error_mixed_set():
    with pytest.raises(PolicyError, match="mixed"):
        parse_shell_pattern("git {status,--flag}")


def test_error_question_on_positional():
    with pytest.raises(PolicyError):
        parse_shell_pattern("git ?status")


def test_error_bang_on_positional():
    with pytest.raises(PolicyError):
        parse_shell_pattern("git !status")


def test_error_invalid_flag_name_triple_dash():
    with pytest.raises(PolicyError, match="too many dashes"):
        parse_shell_pattern("git ---x")


def test_error_sigil_on_double_dash_separator():
    with pytest.raises(PolicyError, match="'!--' is invalid"):
        parse_shell_pattern("git push !--")


def test_error_trailing_backslash():
    with pytest.raises(PolicyError, match="trailing backslash"):
        parse_shell_pattern("git \\")


def test_error_unknown_escape():
    with pytest.raises(PolicyError, match="unknown escape"):
        parse_shell_pattern(r"echo \q")


def test_escaped_parenthesis_remains_a_literal_word():
    pattern = parse_shell_pattern(r"echo \(")
    assert pattern.matches(_seg("echo", "("))


@pytest.mark.parametrize("pattern", [
    "git (status}",
    "git {status)",
    "git only(--short}",
    "git values(--repo}",
])
def test_error_mismatched_delimiters(pattern: str):
    with pytest.raises(PolicyError, match="mismatched"):
        parse_shell_pattern(pattern)


@pytest.mark.parametrize("pattern", [
    "git status,log",
    "git status!",
    "git only(--short)suffix",
    "git values(--repo)suffix status",
    "git (status)",
])
def test_error_unescaped_or_suffixed_metacharacters(pattern: str):
    with pytest.raises(PolicyError, match="metacharacter"):
        parse_shell_pattern(pattern)


@pytest.mark.parametrize(
    ("pattern", "argv"),
    [
        (".venv/bin/{pytest,ruff,basedpyright}", (".venv/bin/pytest",)),
        (".venv/bin/{pytest,ruff,basedpyright}", (".venv/bin/basedpyright",)),
        ("git {status,log}-summary", ("git", "status-summary")),
        ("git prefix{status,log}", ("git", "prefixlog")),
    ],
)
def test_embedded_positional_alternation(pattern: str, argv: tuple[str, ...]):
    assert parse_shell_pattern(pattern).matches(_seg(*argv))


def test_embedded_positional_alternation_rejects_other_member():
    pattern = parse_shell_pattern(".venv/bin/{pytest,ruff,basedpyright}")
    assert not pattern.matches(_seg(".venv/bin/mypy"))


def test_read_only_gh_api_patterns():
    forbidden = "!{-f,--raw-field,-F,--field,--input,-H,--header}"
    default_get = parse_shell_pattern(f"gh api !{{graphql}} !{{-X,--method}} {forbidden}")
    short_get = parse_shell_pattern(f"gh api -X=GET {forbidden}")
    long_get = parse_shell_pattern(f"gh api --method=GET {forbidden}")

    assert default_get.matches(_seg("gh", "api", "repos/o/r"))
    assert not default_get.matches(_seg("gh", "api", "graphql"))
    assert not default_get.matches(_seg("gh", "api", "repos/o/r", "-f", "x=y"))
    assert short_get.matches(_seg("gh", "api", "-XGET", "repos/o/r"))
    assert short_get.matches(_seg("gh", "api", "-X", "GET", "repos/o/r"))
    assert not short_get.matches(_seg("gh", "api", "-XPOST", "repos/o/r"))
    assert long_get.matches(_seg("gh", "api", "--method", "GET", "repos/o/r"))
    assert not long_get.matches(_seg("gh", "api", "--method=POST", "repos/o/r"))


def test_error_multiple_only():
    with pytest.raises(PolicyError, match="more than once"):
        parse_shell_pattern("git only(--a) only(--b)")


def test_error_bang_only():
    with pytest.raises(PolicyError):
        parse_shell_pattern("git !only(--a)")


def test_error_question_only():
    with pytest.raises(PolicyError):
        parse_shell_pattern("git ?only(--a)")


def test_error_only_with_open_wildcard():
    with pytest.raises(PolicyError, match="contradicts"):
        parse_shell_pattern("git only(--a) -*")


def test_error_closed_with_open_wildcard():
    with pytest.raises(PolicyError, match="contradicts"):
        parse_shell_pattern("git !-* -*")


def test_error_empty_set_member():
    with pytest.raises(PolicyError, match="empty member"):
        parse_shell_pattern("git {a,,b}")


def test_error_unbalanced_brace():
    with pytest.raises(PolicyError, match="unbalanced"):
        parse_shell_pattern("git {a,b")


def test_error_only_non_flag_member():
    with pytest.raises(PolicyError, match="non-flag"):
        parse_shell_pattern("git only(status)")


def test_error_values_with_bang_sigil():
    with pytest.raises(PolicyError):
        parse_shell_pattern("git !values(--region)")


def test_error_values_with_question_sigil():
    with pytest.raises(PolicyError):
        parse_shell_pattern("git ?values(--region)")


def test_error_values_duplicate():
    with pytest.raises(PolicyError, match="more than once"):
        parse_shell_pattern("git values(--a) values(--b) status")


def test_error_values_non_flag_member():
    with pytest.raises(PolicyError, match="non-flag"):
        parse_shell_pattern("git values(status) log")


def test_error_value_constraint_on_forbidden_flag():
    with pytest.raises(PolicyError, match="value matching is only supported"):
        parse_shell_pattern("git !--flag=foo")


def test_error_value_constraint_on_permitted_flag():
    with pytest.raises(PolicyError, match="value matching is only supported"):
        parse_shell_pattern("git ?--flag=foo")


def test_error_flag_only_pattern():
    with pytest.raises(PolicyError, match="at least one command term"):
        parse_shell_pattern("--verbose --debug")


def test_error_malformed_shell_rule_no_closing_paren():
    with pytest.raises(PolicyError, match="missing closing parenthesis"):
        parse_rule("Shell(git status")


def test_error_malformed_shell_rule_empty():
    with pytest.raises(PolicyError, match="empty"):
        parse_rule("Shell()")


# ---- Argv normalizer: argv[0] always operand -----------------------------


def test_normalize_argv0_dash_prefix_is_operand():
    """argv[0] starting with '-' must be treated as an operand, not a flag."""
    ops, atoms, _vals = split_and_normalize(("-weird", "-a", "file"), frozenset())
    assert ops[0] == "-weird"
    assert "-weird" not in atoms
    assert "-a" in atoms


# ---- Argv normalizer -----------------------------------------------------


def test_normalize_short_cluster():
    ops, atoms, _vals = split_and_normalize(("rm", "-rf", "/"), frozenset())
    assert atoms == {"-r", "-f"}
    assert ops == ["rm", "/"]


def test_normalize_long_flag_equals():
    ops, atoms, vals = split_and_normalize(("curl", "--output=data.json"), frozenset())
    assert "--output" in atoms
    assert vals["--output"] == ["data.json"]
    assert ops == ["curl"]


def test_normalize_double_dash_terminates_flags():
    ops, atoms, _vals = split_and_normalize(("git", "push", "--", "--force"), frozenset())
    assert "--force" not in atoms
    assert ops == ["git", "push", "--force"]


def test_normalize_bare_dash_is_operand():
    ops, atoms, _vals = split_and_normalize(("cat", "-"), frozenset())
    assert ops == ["cat", "-"]
    assert len(atoms) == 0


def test_normalize_declared_value_flag_long():
    ops, atoms, vals = split_and_normalize(
        ("curl", "--output", "data.json", "http://example.com"),
        frozenset({"--output"}),
    )
    assert "--output" in atoms
    assert vals["--output"] == ["data.json"]
    assert ops == ["curl", "http://example.com"]


def test_normalize_declared_value_flag_short():
    ops, atoms, vals = split_and_normalize(
        ("tar", "-f", "archive.tar", "-x"),
        frozenset({"-f"}),
    )
    assert "-f" in atoms
    assert vals["-f"] == ["archive.tar"]
    assert "-x" in atoms
    assert ops == ["tar"]


def test_normalize_value_consumed_dash_token_preserved_as_flag():
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
        (("curl", "-sXGET", "http://x.com"), frozenset({"-X"}),
         {"-s", "-X"}, {"-X": ["GET"]}, {"-G", "-E", "-T"}, ["curl", "http://x.com"]),
        # Value flag at end of cluster — next token consumed
        (("curl", "-sX", "GET", "http://x.com"), frozenset({"-X"}),
         {"-s", "-X"}, {"-X": ["GET"]}, set(), ["curl", "http://x.com"]),
        # Value flag at start of cluster (existing behaviour)
        (("curl", "-XGET", "http://x.com"), frozenset({"-X"}),
         {"-X"}, {"-X": ["GET"]}, {"-G", "-E", "-T"}, ["curl", "http://x.com"]),
        # Multiple boolean flags before value flag
        (("tar", "-czf", "out.tar.gz", "src/"), frozenset({"-f"}),
         {"-c", "-z", "-f"}, {"-f": ["out.tar.gz"]}, set(), ["tar", "src/"]),
    ],
)
def test_normalize_value_flag_in_cluster(
    argv: tuple[str, ...],
    value_flags: frozenset[str],
    expected_atoms: set[str],
    expected_vals: dict[str, list[str]],
    absent_atoms: set[str],
    expected_ops: list[str],
):
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
def test_normalize_consumed_dash_token_uses_canonical_atoms(
    consumed: str, expected: set[str]
) -> None:
    _ops, atoms, _vals = split_and_normalize(
        ("cmd", "--mode", consumed, "run"),
        frozenset({"--mode"}),
    )
    assert expected <= atoms


def test_normalize_value_consumed_dash_token_short():
    """Same preservation for short value flags."""
    ops, atoms, _vals = split_and_normalize(
        ("cmd", "-m", "--danger", "run"),
        frozenset({"-m"}),
    )
    assert "-m" in atoms
    assert "--danger" in atoms
    assert ops == ["cmd", "run"]


def test_normalize_repeated_flag_values():
    """Repeated flags collect all values."""
    _ops, _atoms, vals = split_and_normalize(
        ("curl", "--output=a.txt", "--output=b.json"),
        frozenset(),
    )
    assert vals["--output"] == ["a.txt", "b.json"]


def test_normalize_short_option_attached_value():
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


@pytest.mark.parametrize("pattern, argv, expected", [
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
    ("aws values(--region, --profile) ec2 describe-*",
     ("aws", "--region", "us-east-1", "ec2", "describe-instances"), True),
    ("aws values(--region, --profile) ec2 describe-*",
     ("aws", "--profile", "dev", "--region", "ap-southeast-2", "ec2", "describe-instances"), True),
    ("aws values(--region, --profile) ec2 describe-*",
     ("aws", "ec2", "describe-instances"), True),
    ("aws values(--region, --profile) ec2 describe-*",
     ("aws", "ec2", "describe-instances", "--region", "us-east-1"), True),
    ("aws values(--region, --profile) ec2 describe-*",
     ("aws", "ec2", "describe-instances", "--region=us-east-1"), True),
    # Without values(), a possible option value stays an operand and cannot be
    # skipped to reach a later command path.
    ("aws ec2 describe-*",
     ("aws", "--region", "us-east-1", "ec2", "describe-instances"), False),

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
    ("git values(-C) status",
     ("git", "-C", "/other/repo", "status"), True),

    # Value-consumed token that looks like a flag is still visible to forbidden check
    ("cmd values(--mode) run !--danger",
     ("cmd", "--mode", "--danger", "run"), False),
    ("cmd values(--mode) run !--danger",
     ("cmd", "--mode", "safe", "run"), True),
    ("cmd values(--mode) run !-r",
     ("cmd", "--mode", "-rf", "run"), False),
    ("cmd values(--mode) run !-f",
     ("cmd", "--mode", "-rf", "run"), False),
    ("cmd values(--mode) run !--danger",
     ("cmd", "--mode", "--danger=x", "run"), False),
    ("cmd values(--mode) run !-X",
     ("cmd", "--mode", "-XDELETE", "run"), False),

    # Short value options support separate and attached forms consistently.
    ("gh -X=GET api", ("gh", "-X", "GET", "api"), True),
    ("gh -X=GET api", ("gh", "-XGET", "api"), True),
    ("gh -X=GET api", ("gh", "-X=GET", "api"), True),
    ("gh -X=GET api", ("gh", "-XDELETE", "api"), False),

    # Repeated constrained option — ALL values must match
    ("curl --output=*.json",
     ("curl", "--output=a.json", "--output=b.json"), True),
    ("curl --output=*.json",
     ("curl", "--output=bad.txt", "--output=good.json"), False),
    ("curl --output=*.json",
     ("curl", "--output=good.json", "--output=bad.txt"), False),
    ("curl --output=*.json",
     ("curl", "--output=good.json", "--output"), False),
    ("curl --output=*.json",
     ("curl", "--output", "--output=good.json"), False),

    # Multiple gaps (exercises memoized path matching)
    ("cmd ... middle ... end", ("cmd", "a", "b", "middle", "c", "end"), True),
    ("cmd ... middle ... end", ("cmd", "middle", "end"), True),
    ("cmd ... middle ... end", ("cmd", "a", "end"), False),

    # Escaped star matches literal asterisk
    ("echo \\*", ("echo", "*"), True),
    ("echo \\*", ("echo", "foo"), False),
])
def test_shell_pattern_match(pattern: str, argv: tuple[str, ...], expected: bool):
    rule = parse_shell_pattern(pattern)
    segment = _seg(*argv) if argv else Segment(argv=(), redirects=())
    assert rule.matches(segment) is expected, f"Shell({pattern}) vs {argv}"


# ---- Round-trip serialization --------------------------------------------


@pytest.mark.parametrize("rule_str", [
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
])
def test_round_trip(rule_str: str):
    rule = parse_rule(rule_str)
    assert isinstance(rule, ShellPattern)
    assert rule.serialize() == rule_str


# ---- Policy integration -------------------------------------------------


def test_policy_shell_allow():
    rule = _shell_rule("Shell(git {status,log,diff})")
    policy = Policy(allow=(rule,))
    result = _decide(policy, "git status --short")
    assert result.decision is Decision.Allow


def test_policy_shell_deny_overrides_allow():
    allow = _shell_rule("Shell(git push)")
    deny = _shell_rule("Shell(git push {--force,--force-with-lease,-f})")
    policy = Policy(allow=(allow,), deny=(deny,))
    assert _decide(policy, "git push origin main").decision is Decision.Allow
    assert _decide(policy, "git push --force origin main").decision is Decision.Deny


def test_policy_shell_forbidden_flag_deny():
    deny = _shell_rule("Shell(rm -r -f)")
    policy = Policy(deny=(deny,))
    assert _decide(policy, "rm -rf /").decision is Decision.Deny
    assert _decide(policy, "rm foo").decision is Decision.NoOpinion


def test_unknown_global_option_value_cannot_hide_deny_path():
    deny = _shell_rule("Shell(git push --force)")
    policy = Policy(deny=(deny,))
    assert _decide(policy, "git -C /repo push --force").decision is Decision.Deny


def test_unknown_option_value_cannot_smuggle_git_alias_into_open_allow_path():
    allow = _shell_rule("Shell(git status)")
    policy = Policy(allow=(allow,))
    command = "git -c 'alias.status=!touch /tmp/pwned' status"
    assert _decide(policy, command).decision is Decision.NoOpinion


def test_closed_flag_allow_rejects_attached_semantic_option_value():
    allow = _shell_rule("Shell(git status !-*)")
    policy = Policy(allow=(allow,))
    command = "git -calias.status='!touch /tmp/pwned' status"
    assert _decide(policy, command).decision is Decision.NoOpinion


def test_policy_shell_coexists_with_bash_command():
    from agentperm import BashCommand

    bash_rule = BashCommand(("ls",))
    shell_rule = _shell_rule("Shell(git {status,log})")
    policy = Policy(allow=(bash_rule, shell_rule))
    assert _decide(policy, "ls -la").decision is Decision.Allow
    assert _decide(policy, "git status").decision is Decision.Allow
    assert _decide(policy, "rm foo").decision is Decision.NoOpinion


def test_policy_shell_compound_command():
    allow = _shell_rule("Shell(git status)")
    policy = Policy(allow=(allow,))
    result = _decide(policy, "git status && echo done")
    assert result.decision is Decision.Allow


def test_policy_shell_dict_values():
    """Dict form {"rule": "Shell(...)", "values": [...]} merges into value_flags."""
    rule = parse_rule({"rule": "Shell(aws ec2 describe-*)", "values": ["--region", "--profile"]})
    assert isinstance(rule, ShellPattern)
    assert rule.value_flags == frozenset({"--region", "--profile"})
    policy = Policy(allow=(rule,))
    assert _decide(policy, "aws --region us-east-1 ec2 describe-instances").decision is Decision.Allow
    assert _decide(policy, "aws ec2 describe-instances").decision is Decision.Allow


def test_policy_shell_dict_values_merge_with_inline():
    """Dict values merge with inline values()."""
    rule = parse_rule({
        "rule": "Shell(aws values(--output) ec2 describe-*)",
        "values": ["--region", "--profile"],
    })
    assert isinstance(rule, ShellPattern)
    assert rule.value_flags == frozenset({"--output", "--region", "--profile"})


def test_policy_shell_dict_no_values_key():
    """Dict form without 'values' key is equivalent to the string form."""
    rule = parse_rule({"rule": "Shell(aws ec2 describe-*)"})
    assert isinstance(rule, ShellPattern)
    assert rule.value_flags == frozenset()


def test_policy_shell_dict_values_invalid_non_flag():
    with pytest.raises(PolicyError, match="non-flag"):
        parse_rule({"rule": "Shell(aws ec2 describe-*)", "values": ["region"]})


def test_policy_shell_dict_values_invalid_not_array():
    with pytest.raises(PolicyError, match="array"):
        parse_rule({"rule": "Shell(aws ec2 describe-*)", "values": "--region"})


def test_policy_shell_dict_values_round_trip():
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


def test_policy_shell_inline_values_serialize_as_string():
    """Inline values() serializes as a plain string, not a dict."""
    rule = parse_rule("Shell(aws values(--region) ec2 describe-*)")
    assert isinstance(rule, ShellPattern)
    serialized = rule.serialize()
    assert isinstance(serialized, str)
    assert serialized == "Shell(aws values(--region) ec2 describe-*)"


def test_shell_pattern_rejects_inconsistent_external_values():
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


def test_policy_shell_sed_with_forbidden_flag():
    allow = _shell_rule("Shell({sed,gsed} !{-i,--in-place})")
    policy = Policy(allow=(allow,))
    assert _decide(policy, "sed -n 1,10p foo").decision is Decision.Allow
    assert _decide(policy, "sed -i '' s/a/b/ foo").decision is Decision.NoOpinion
    assert _decide(policy, "gsed -e s/a/b/ foo").decision is Decision.Allow


# ---- Rule-as-key dict form -------------------------------------------------


def test_rule_as_key_parses_allow_paths():
    rule = parse_rule({"Shell(echo)": {"allowPaths": ["/tmp", "/var"]}})
    assert isinstance(rule, ShellPattern)
    assert rule.allow_paths == ("/tmp", "/var")
    assert rule.matches(_seg("echo", "hi"))


def test_rule_as_key_parses_values():
    rule = parse_rule({"Shell(git status)": {"values": ["-C"]}})
    assert isinstance(rule, ShellPattern)
    assert rule.extra_values == frozenset({"-C"})
    assert "-C" in rule.value_flags


def test_rule_as_key_parses_combined_values_and_allow_paths():
    rule = parse_rule({"Shell(git status)": {"values": ["-C"], "allowPaths": ["/tmp"]}})
    assert isinstance(rule, ShellPattern)
    assert rule.extra_values == frozenset({"-C"})
    assert rule.allow_paths == ("/tmp",)


def test_rule_as_key_serialize_round_trip():
    rule = parse_rule({"Shell(echo)": {"allowPaths": ["/tmp"]}})
    assert isinstance(rule, ShellPattern)
    serialized = rule.serialize()
    assert isinstance(serialized, dict)
    assert "Shell(echo)" in serialized
    reloaded = parse_rule(serialized)
    assert isinstance(reloaded, ShellPattern)
    assert reloaded.allow_paths == ("/tmp",)


def test_rule_as_key_combined_serialize_round_trip():
    rule = parse_rule({"Shell(git status)": {"values": ["-C"], "allowPaths": ["/tmp"]}})
    assert isinstance(rule, ShellPattern)
    serialized = rule.serialize()
    reloaded = parse_rule(serialized)
    assert isinstance(reloaded, ShellPattern)
    assert reloaded.extra_values == frozenset({"-C"})
    assert reloaded.allow_paths == ("/tmp",)


def test_rule_as_key_rejects_non_dict_value():
    with pytest.raises(PolicyError, match="must be an object"):
        parse_rule({"Shell(echo)": "bad"})


def test_rule_as_key_rejects_bad_allow_paths():
    with pytest.raises(PolicyError, match="allowPaths"):
        parse_rule({"Shell(echo)": {"allowPaths": "not a list"}})


def test_rule_as_key_rejects_empty_allow_path_entry():
    with pytest.raises(PolicyError, match="non-empty string"):
        parse_rule({"Shell(echo)": {"allowPaths": [""]}})
