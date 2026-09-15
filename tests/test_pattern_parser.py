"""Shell pattern DSL tests — parser, normalizer, matcher, policy integration."""

from __future__ import annotations

import pytest

from agentperm import (
    parse_rule,
)
from agentperm.domain import AnyRest, Disposition, OneOf, Word
from agentperm.errors import PolicyError
from agentperm.shellpattern import parse_shell_pattern
from tests.pattern_support import segment as _seg

# ---- Parser: basic term types --------------------------------------------


def test_parse_simple_words() -> None:
    pat = parse_shell_pattern("git status")
    assert len(pat.path) == 2
    assert isinstance(pat.path[0], Word)
    assert isinstance(pat.path[1], Word)
    assert pat.exact is False
    assert pat.closed_flags is False


def test_parse_double_dash_as_positional_separator() -> None:
    pat = parse_shell_pattern("mise exec -- just dev")
    assert isinstance(pat.path[2], Word)
    assert pat.path[2].glob == "--"
    assert not pat.flags


def test_parse_glob_in_word() -> None:
    pat = parse_shell_pattern("git checkout feature/*")
    assert isinstance(pat.path[2], Word)
    assert pat.path[2].glob == "feature/*"


def test_parse_bare_star() -> None:
    pat = parse_shell_pattern("git *")
    assert isinstance(pat.path[1], Word)
    assert pat.path[1].glob == "*"


def test_parse_alternation_set() -> None:
    pat = parse_shell_pattern("git {status,log,diff}")
    assert isinstance(pat.path[1], OneOf)
    assert pat.path[1].negated is False
    assert len(pat.path[1].globs) == 3


def test_parse_negated_set() -> None:
    pat = parse_shell_pattern("git !{push,reset}")
    assert isinstance(pat.path[1], OneOf)
    assert pat.path[1].negated is True


def test_parse_gap() -> None:
    pat = parse_shell_pattern("docker ... up")
    assert isinstance(pat.path[1], AnyRest)
    assert isinstance(pat.path[2], Word)


def test_parse_exact() -> None:
    pat = parse_shell_pattern("git stash !...")
    assert pat.exact is True
    assert pat.closed_flags is False
    assert len(pat.path) == 2


def test_parse_closed_flags() -> None:
    pat = parse_shell_pattern("git stash !-*")
    assert pat.closed_flags is True
    assert pat.exact is False


def test_parse_exact_and_closed() -> None:
    pat = parse_shell_pattern("git stash !... !-*")
    assert pat.exact is True
    assert pat.closed_flags is True


# ---- Parser: flag terms --------------------------------------------------


def test_parse_required_flag() -> None:
    pat = parse_shell_pattern("git push --set-upstream")
    assert any(c.atom == "--set-upstream" and c.disp is Disposition.Required for c in pat.flags)


def test_parse_required_short_flag() -> None:
    pat = parse_shell_pattern("rm -r -f")
    atoms = {c.atom for c in pat.flags if c.disp is Disposition.Required}
    assert atoms == {"-r", "-f"}


def test_parse_forbidden_flag() -> None:
    pat = parse_shell_pattern("git push !--force")
    assert any(c.atom == "--force" and c.disp is Disposition.Forbidden for c in pat.flags)


def test_parse_permitted_flag() -> None:
    pat = parse_shell_pattern("git stash ?--keep-index ?-p !-*")
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert permitted == {"--keep-index", "-p"}
    assert pat.closed_flags is True


def test_parse_value_constraint() -> None:
    pat = parse_shell_pattern("curl --output=*.json")
    fc = next(c for c in pat.flags if c.atom == "--output")
    assert fc.disp is Disposition.Required
    assert fc.value_glob == "*.json"
    assert "--output" in pat.value_flags


def test_parse_value_constraint_escaped_star() -> None:
    pat = parse_shell_pattern("curl --output=\\*.json")
    fc = next(c for c in pat.flags if c.atom == "--output")
    assert fc.value_glob == "[*].json"


def test_parse_empty_value_constraint() -> None:
    pat = parse_shell_pattern("curl --output=")
    fc = next(c for c in pat.flags if c.atom == "--output")
    assert fc.value_glob == ""


def test_parse_short_value_constraint() -> None:
    pat = parse_shell_pattern("gh -X=GET api")
    fc = next(c for c in pat.flags if c.atom == "-X")
    assert fc.value_glob == "GET"
    assert "-X" in pat.value_flags


# ---- Parser: only(...) ---------------------------------------------------


def test_parse_only() -> None:
    pat = parse_shell_pattern("git stash only(--keep-index, -p)")
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert permitted == {"--keep-index", "-p"}
    assert pat.closed_flags is True


def test_parse_only_with_required_flag() -> None:
    pat = parse_shell_pattern("git push --set-upstream only(--no-verify)")
    required = {c.atom for c in pat.flags if c.disp is Disposition.Required}
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert required == {"--set-upstream"}
    assert permitted == {"--no-verify"}
    assert pat.closed_flags is True


# ---- Parser: values(...) ------------------------------------------------


def test_parse_values() -> None:
    pat = parse_shell_pattern("aws values(--region, --profile) ec2 describe-*")
    assert pat.value_flags == frozenset({"--region", "--profile"})
    assert len(pat.flags) == 0
    assert len(pat.path) == 3


def test_parse_values_no_constraint() -> None:
    """values() flags don't emit any FlagConstraint."""
    pat = parse_shell_pattern("git values(-C) status")
    assert pat.value_flags == frozenset({"-C"})
    assert not any(c.atom == "-C" for c in pat.flags)


def test_parse_values_with_value_constraint() -> None:
    """values() flags and --flag=glob constraints coexist — both contribute to value_flags."""
    pat = parse_shell_pattern("curl values(--output) --output=*.json")
    assert "--output" in pat.value_flags
    fc = next(c for c in pat.flags if c.atom == "--output")
    assert fc.disp is Disposition.Required
    assert fc.value_glob == "*.json"


def test_parse_values_with_only() -> None:
    """values() and only() are orthogonal."""
    pat = parse_shell_pattern("aws values(--region) only(--output) ec2 describe-*")
    assert pat.value_flags == frozenset({"--region"})
    assert pat.closed_flags is True
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert permitted == {"--output"}


# ---- Parser: flag sets ---------------------------------------------------


def test_parse_flag_any_of_set() -> None:
    pat = parse_shell_pattern("git push {--force,--force-with-lease,-f}")
    assert len(pat.flag_sets) == 1
    assert set(pat.flag_sets[0]) == {"--force", "--force-with-lease", "-f"}


def test_parse_flag_none_of_set() -> None:
    pat = parse_shell_pattern("sed !{-i,--in-place}")
    forbidden = {c.atom for c in pat.flags if c.disp is Disposition.Forbidden}
    assert forbidden == {"-i", "--in-place"}
    assert len(pat.flag_sets) == 0


def test_parse_flag_permitted_set() -> None:
    pat = parse_shell_pattern("git stash ?{--keep-index,-p} !-*")
    permitted = {c.atom for c in pat.flags if c.disp is Disposition.Permitted}
    assert permitted == {"--keep-index", "-p"}


# ---- Parser: escaping ----------------------------------------------------


def test_parse_question_mark_not_glob() -> None:
    """? in the DSL is a sigil/literal, not an fnmatch single-char wildcard."""
    pat = parse_shell_pattern("cat file?.txt")
    assert isinstance(pat.path[1], Word)
    # ? is escaped to [?] internally so fnmatch treats it literally
    assert "[?]" in pat.path[1].glob


# ---- Parser: error cases -------------------------------------------------


def test_error_empty_pattern() -> None:
    with pytest.raises(PolicyError):
        parse_rule("Shell()")


def test_error_empty_braces() -> None:
    with pytest.raises(PolicyError, match="empty member"):
        parse_shell_pattern("git {}")


def test_error_mixed_set() -> None:
    with pytest.raises(PolicyError, match="mixed"):
        parse_shell_pattern("git {status,--flag}")


def test_error_question_on_positional() -> None:
    with pytest.raises(PolicyError):
        parse_shell_pattern("git ?status")


def test_error_bang_on_positional() -> None:
    with pytest.raises(PolicyError):
        parse_shell_pattern("git !status")


def test_error_invalid_flag_name_triple_dash() -> None:
    with pytest.raises(PolicyError, match="too many dashes"):
        parse_shell_pattern("git ---x")


def test_error_sigil_on_double_dash_separator() -> None:
    with pytest.raises(PolicyError, match="'!--' is invalid"):
        parse_shell_pattern("git push !--")


def test_error_trailing_backslash() -> None:
    with pytest.raises(PolicyError, match="trailing backslash"):
        parse_shell_pattern("git \\")


def test_error_unknown_escape() -> None:
    with pytest.raises(PolicyError, match="unknown escape"):
        parse_shell_pattern(r"echo \q")


def test_escaped_parenthesis_remains_a_literal_word() -> None:
    pattern = parse_shell_pattern(r"echo \(")
    assert pattern.matches(_seg("echo", "("))


@pytest.mark.parametrize(
    "pattern",
    [
        "git (status}",
        "git {status)",
        "git only(--short}",
        "git values(--repo}",
    ],
)
def test_error_mismatched_delimiters(pattern: str) -> None:
    with pytest.raises(PolicyError, match="mismatched"):
        parse_shell_pattern(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        "git status,log",
        "git status!",
        "git only(--short)suffix",
        "git values(--repo)suffix status",
        "git (status)",
    ],
)
def test_error_unescaped_or_suffixed_metacharacters(pattern: str) -> None:
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
def test_embedded_positional_alternation(pattern: str, argv: tuple[str, ...]) -> None:
    assert parse_shell_pattern(pattern).matches(_seg(*argv))


def test_embedded_positional_alternation_rejects_other_member() -> None:
    pattern = parse_shell_pattern(".venv/bin/{pytest,ruff,basedpyright}")
    assert not pattern.matches(_seg(".venv/bin/mypy"))


def test_read_only_gh_api_patterns() -> None:
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


def test_error_multiple_only() -> None:
    with pytest.raises(PolicyError, match="more than once"):
        parse_shell_pattern("git only(--a) only(--b)")


def test_error_bang_only() -> None:
    with pytest.raises(PolicyError):
        parse_shell_pattern("git !only(--a)")


def test_error_question_only() -> None:
    with pytest.raises(PolicyError):
        parse_shell_pattern("git ?only(--a)")


def test_error_only_with_open_wildcard() -> None:
    with pytest.raises(PolicyError, match="contradicts"):
        parse_shell_pattern("git only(--a) -*")


def test_error_closed_with_open_wildcard() -> None:
    with pytest.raises(PolicyError, match="contradicts"):
        parse_shell_pattern("git !-* -*")


def test_error_empty_set_member() -> None:
    with pytest.raises(PolicyError, match="empty member"):
        parse_shell_pattern("git {a,,b}")


def test_error_unbalanced_brace() -> None:
    with pytest.raises(PolicyError, match="unbalanced"):
        parse_shell_pattern("git {a,b")


def test_error_only_non_flag_member() -> None:
    with pytest.raises(PolicyError, match="non-flag"):
        parse_shell_pattern("git only(status)")


def test_error_values_with_bang_sigil() -> None:
    with pytest.raises(PolicyError):
        parse_shell_pattern("git !values(--region)")


def test_error_values_with_question_sigil() -> None:
    with pytest.raises(PolicyError):
        parse_shell_pattern("git ?values(--region)")


def test_error_values_duplicate() -> None:
    with pytest.raises(PolicyError, match="more than once"):
        parse_shell_pattern("git values(--a) values(--b) status")


def test_error_values_non_flag_member() -> None:
    with pytest.raises(PolicyError, match="non-flag"):
        parse_shell_pattern("git values(status) log")


def test_error_value_constraint_on_forbidden_flag() -> None:
    with pytest.raises(PolicyError, match="value matching is only supported"):
        parse_shell_pattern("git !--flag=foo")


def test_error_value_constraint_on_permitted_flag() -> None:
    with pytest.raises(PolicyError, match="value matching is only supported"):
        parse_shell_pattern("git ?--flag=foo")


def test_error_flag_only_pattern() -> None:
    with pytest.raises(PolicyError, match="at least one command term"):
        parse_shell_pattern("--verbose --debug")


def test_error_malformed_shell_rule_no_closing_paren() -> None:
    with pytest.raises(PolicyError, match="missing closing parenthesis"):
        parse_rule("Shell(git status")


def test_error_malformed_shell_rule_empty() -> None:
    with pytest.raises(PolicyError, match="empty"):
        parse_rule("Shell()")
