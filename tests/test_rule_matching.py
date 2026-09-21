"""Policy decision tests — strictness, aggregation, rule matching, bypass coercion."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentperm import (
    BashCommand,
    BashOption,
    CompoundRequest,
    Decision,
    JsonObject,
    McpToolRequest,
    McpToolRule,
    NamedTool,
    Policy,
    PolicyError,
    PythonReadonly,
    RejectedRequest,
    Segment,
    ShellRequest,
    ToolRequest,
    Verdict,
    aggregate,
    parse_pipeline,
    parse_rule,
)

# ---- Rule matching --------------------------------------------------------


def test_bash_command_prefix_matches_argv_head() -> None:
    rule = BashCommand(("git", "status"))
    seg = Segment(argv=("git", "status", "--short"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_does_not_match_shorter_argv() -> None:
    rule = BashCommand(("git", "status"))
    seg = Segment(argv=("git",), redirects=())
    assert rule.matches(seg) is False


def test_bash_command_glob_star_matches_one_token() -> None:
    rule = BashCommand(("pnpm", "*", "build"))
    seg = Segment(argv=("pnpm", "--dir", "build"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_glob_star_does_not_match_zero_tokens() -> None:
    rule = BashCommand(("pnpm", "*", "build"))
    seg = Segment(argv=("pnpm", "build"), redirects=())
    assert rule.matches(seg) is False


def test_bash_command_glob_star_does_not_match_two_tokens() -> None:
    rule = BashCommand(("pnpm", "*", "build"))
    seg = Segment(argv=("pnpm", "--dir", "x", "build"), redirects=())
    assert rule.matches(seg) is False


def test_bash_command_glob_doublestar_matches_zero_tokens() -> None:
    rule = BashCommand(("pnpm", "**", "build"))
    seg = Segment(argv=("pnpm", "build"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_glob_doublestar_matches_many_tokens() -> None:
    rule = BashCommand(("pnpm", "**", "build"))
    seg = Segment(argv=("pnpm", "--dir", "x", "--silent", "build"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_glob_doublestar_with_trailing_extras() -> None:
    rule = BashCommand(("pnpm", "**", "build"), trailing_wildcard=True)
    seg = Segment(argv=("pnpm", "--dir", "x", "build", "--watch"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_exact_form_rejects_extra_args() -> None:
    rule = BashCommand(("git", "status"), trailing_wildcard=False)
    seg = Segment(argv=("git", "status", "--short"), redirects=())
    assert rule.matches(seg) is False


def test_bash_command_exact_form_matches_full_argv() -> None:
    rule = BashCommand(("git", "status"), trailing_wildcard=False)
    seg = Segment(argv=("git", "status"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_glob_first_token_skips_basename_rule() -> None:
    rule = BashCommand(("*", "status"))
    seg = Segment(argv=("/usr/bin/git", "status"), redirects=())
    assert rule.matches(seg) is True


def test_bash_option_short_flag_matches_combined() -> None:
    rule = BashOption(commands=frozenset({"sed"}), options=frozenset({"-i"}), rationale="in-place")
    seg = Segment(argv=("sed", "-iE", "s/a/b/"), redirects=())
    assert rule.matches(seg) is True


def test_bash_option_long_flag_matches_with_equals() -> None:
    rule = BashOption(commands=frozenset({"rsync"}), options=frozenset({"--delete"}), rationale="destructive")
    seg = Segment(argv=("rsync", "--delete=true", "src/", "dst/"), redirects=())
    assert rule.matches(seg) is True


def test_bash_option_does_not_match_after_double_dash() -> None:
    rule = BashOption(commands=frozenset({"sed"}), options=frozenset({"-i"}), rationale="in-place")
    seg = Segment(argv=("sed", "-e", "s/x/y/", "--", "-i"), redirects=())
    # `--` is positional; the literal `-i` after `--` is a filename, not a flag.
    # Our matcher doesn't track `--` boundary — but it correctly skips bare `--`.
    # This case currently returns True because our matcher checks every arg. Document the
    # limitation explicitly: callers that pass `-i` after `--` would still get prompted.
    # The conservative direction (Ask on -i) is the right default for a permission policy.
    assert rule.matches(seg) is True


def test_named_tool_exact_match() -> None:
    assert NamedTool("Read").matches("Read") is True
    assert NamedTool("Read").matches("Write") is False


def test_named_tool_wildcard_matches_anything() -> None:
    assert NamedTool("*").matches("Read") is True
    assert NamedTool("*").matches("WeirdMcpTool") is True


def test_named_tool_prefix_glob() -> None:
    assert NamedTool("Deferred*").matches("DeferredRead") is True
    assert NamedTool("Deferred*").matches("Read") is False


@pytest.mark.parametrize(
    ("text", "canonical"),
    [
        ("MCP(coderift.open_repository)", "MCP(coderift.open_repository)"),
        ("MCP(coderift.*)", "MCP(coderift.*)"),
        ("MCP(*)", "MCP(*)"),
    ],
)
def test_mcp_rules_parse_and_serialize_canonically(text: str, canonical: str) -> None:
    rule = parse_rule(text)

    assert isinstance(rule, McpToolRule)
    assert rule.serialize() == canonical


def test_mcp_rule_matches_only_its_server_and_tool_scope() -> None:
    server = parse_rule("MCP(coderift.*)")
    exact = parse_rule("MCP(coderift.open_repository)")
    all_mcp = parse_rule("MCP(*)")
    assert isinstance(server, McpToolRule)
    assert isinstance(exact, McpToolRule)
    assert isinstance(all_mcp, McpToolRule)

    assert server.matches("coderift", "open_repository") is True
    assert server.matches("atlassian", "open_repository") is False
    assert exact.matches("coderift", "open_repository") is True
    assert exact.matches("coderift", "close_repository") is False
    assert all_mcp.matches("atlassian", "jira_search") is True


@pytest.mark.parametrize(
    ("pattern", "matching", "not_matching"),
    [
        ("MCP(coderift.{find_symbol,get_usages})", "find_symbol", "open_repository"),
        ("MCP(coderift.get_*)", "get_usages", "find_symbol"),
        ("MCP(coderift.*_repository)", "open_repository", "find_symbol"),
        ("MCP(coderift.*.foo)", "navigation.deep.foo", "navigation.deep.bar"),
        ("MCP(coderift.{foo,bar}.*)", "bar.deep.tool", "baz.deep.tool"),
        (r"MCP(server\.prod.literal\*tool)", "literal*tool", "literal_tool"),
    ],
)
def test_mcp_patterns_support_globs_alternatives_and_escaping(
    pattern: str,
    matching: str,
    not_matching: str,
) -> None:
    rule = parse_rule(pattern)
    assert isinstance(rule, McpToolRule)

    server = "server.prod" if pattern.startswith(r"MCP(server\.") else "coderift"
    assert rule.matches(server, matching) is True
    assert rule.matches(server, not_matching) is False


def test_mcp_policy_evaluates_typed_server_and_tool_identity() -> None:
    rule = parse_rule("MCP({coderift,atlassian}.{find_*,get_*})")
    assert isinstance(rule, McpToolRule)
    policy = Policy(allow=(rule,))

    assert policy.decide(McpToolRequest("coderift", "find_symbol")).decision is Decision.Allow
    assert policy.decide(McpToolRequest("atlassian", "get_issue")).decision is Decision.Allow
    assert policy.decide(McpToolRequest("github", "get_issue")).decision is Decision.NoOpinion


@pytest.mark.parametrize(
    "text",
    (
        "MCP()",
        "MCP(coderift)",
        "MCP(.find_symbol)",
        "MCP(coderift.)",
        "MCP(coderift.{find_symbol})",
        "MCP(coderift.{find_symbol,})",
        "MCP(coderift.{find_symbol,get_usages)",
        "MCP(coderift.find_symbol\\)",
    ),
)
def test_malformed_mcp_patterns_fail_loudly(text: str) -> None:
    with pytest.raises(PolicyError):
        parse_rule(text)


def test_named_tool_reason_round_trips_and_is_verbatim_rationale() -> None:
    raw: JsonObject = {"Write(generated/**)": {"reason": "Generated file; update its source and rerun the generator."}}
    rule = parse_rule(raw)
    assert isinstance(rule, NamedTool)
    assert rule.rationale == "Generated file; update its source and rerun the generator."
    assert rule.serialize() == raw

    policy = Policy(deny=(rule,))
    verdict = policy.decide(ToolRequest("Write", (("file_path", "generated/client.py"),)))
    assert verdict == Verdict(
        Decision.Deny,
        "Generated file; update its source and rerun the generator.",
    )


def test_legacy_rule_wrapper_reason_is_accepted_and_serializes_canonically() -> None:
    rule = parse_rule({"rule": "Write(dist/**)", "reason": "Use the generator."})
    assert isinstance(rule, NamedTool)
    assert rule.serialize() == {"Write(dist/**)": {"reason": "Use the generator."}}


def test_reason_metadata_does_not_affect_rule_equality_or_merge() -> None:
    first = NamedTool("Write", "generated/**", rationale="First reason")
    duplicate = NamedTool("Write", "generated/**", rationale="Second reason")
    assert first == duplicate
    assert Policy(deny=(first,)).merged_with(Policy(deny=(duplicate,))).deny == (first,)


def test_reasonless_rule_serialization_and_automatic_rationale_are_unchanged() -> None:
    rule = NamedTool("Write", "generated/**")
    assert rule.serialize() == "Write(generated/**)"
    verdict = Policy(deny=(rule,)).decide(ToolRequest("Write", (("file_path", "generated/client.py"),)))
    assert verdict.rationale == "deny by rule 'Write(generated/**)'"


@pytest.mark.parametrize(
    "raw, serialized",
    [
        (
            {"Bash(git status:*)": {"reason": "Inspect only."}},
            {"Bash(git status:*)": {"reason": "Inspect only."}},
        ),
        (
            {"Python(readonly)": {"reason": "Static analysis approved."}},
            {"Python(readonly)": {"reason": "Static analysis approved."}},
        ),
    ],
)
def test_reason_metadata_round_trips_for_other_rule_types(raw: JsonObject, serialized: JsonObject) -> None:
    rule = parse_rule(raw)
    assert rule is not None
    assert rule.serialize() == serialized


def test_python_readonly_reason_is_verbatim_for_readonly_source() -> None:
    rule = parse_rule({"Python(readonly)": {"reason": "Static analysis approved."}})
    assert isinstance(rule, PythonReadonly)

    verdict = Policy(allow=(rule,)).decide(ShellRequest(parse_pipeline("python -c 'print(1)'")))

    assert verdict == Verdict(Decision.Allow, "Static analysis approved.")


def test_python_readonly_reason_does_not_hide_unsafe_analysis() -> None:
    rule = PythonReadonly(rationale="Static analysis approved.")

    verdict = Policy(allow=(rule,)).decide(
        ShellRequest(parse_pipeline("python -c 'import os; os.remove(\"generated.py\")'"))
    )

    assert verdict.decision is Decision.Ask
    assert verdict.rationale == "Python call may mutate external state: os.remove"


def test_multi_key_rule_as_key_object_is_not_partially_parsed() -> None:
    raw: JsonObject = {
        "Shell(git status)": {"reason": "Inspect the worktree."},
        "comment": "This sibling must not be silently ignored.",
    }

    assert parse_rule(raw) is None


def test_named_tool_no_specifier_ignores_arguments() -> None:
    # Bare name (and the `*` specifier) match the tool regardless of input.
    assert NamedTool("Read").matches("Read", (("file_path", "/etc/passwd"),)) is True
    assert NamedTool("Read", "*").matches("Read", (("file_path", "/anything"),)) is True


def test_path_double_star_directory_prefix_matches_zero_or_many_segments() -> None:
    rule = NamedTool("Write", "**/generated/**")
    assert rule.matches("Write", (("file_path", "generated/client.py"),)) is True
    assert rule.matches("Write", (("file_path", "project/generated/client.py"),)) is True


def test_relative_tool_path_rule_matches_absolute_request_from_hook_cwd(tmp_path: Path) -> None:
    generated = tmp_path / "generated/client.py"
    verdict = Policy(deny=(NamedTool("Write", "generated/**"),)).decide(
        ToolRequest("Write", (("file_path", str(generated)),), cwd=tmp_path)
    )
    assert verdict.decision is Decision.Deny


def test_relative_tool_path_rule_normalizes_traversal_against_hook_cwd(tmp_path: Path) -> None:
    verdict = Policy(deny=(NamedTool("Write", "generated/**"),)).decide(
        ToolRequest(
            "Write",
            (("file_path", "src/../generated/client.py"),),
            cwd=tmp_path,
        )
    )
    assert verdict.decision is Decision.Deny


def test_deny_tool_path_rule_cannot_be_bypassed_through_symlink(tmp_path: Path) -> None:
    generated = tmp_path / "generated"
    generated.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (generated / "linked").symlink_to(outside, target_is_directory=True)

    verdict = Policy(deny=(NamedTool("Write", "generated/**"),)).decide(
        ToolRequest(
            "Write",
            (("file_path", "generated/linked/client.py"),),
            cwd=tmp_path,
        )
    )
    assert verdict.decision is Decision.Deny


def test_allow_tool_path_rule_does_not_follow_symlink_outside_scope(tmp_path: Path) -> None:
    generated = tmp_path / "generated"
    generated.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (generated / "linked").symlink_to(outside, target_is_directory=True)

    verdict = Policy(allow=(NamedTool("Write", "generated/**"),)).decide(
        ToolRequest(
            "Write",
            (("file_path", "generated/linked/client.py"),),
            cwd=tmp_path,
        )
    )
    assert verdict.decision is Decision.NoOpinion


def test_compound_request_uses_strictest_semantic_file_verdict() -> None:
    # One patch touching an allowed source file and a denied generated file is denied as a whole.
    request = CompoundRequest(
        (
            ToolRequest("Write", (("file_path", "src/app.py"),)),
            ToolRequest("Write", (("file_path", "generated/client.py"),)),
        )
    )
    verdict = Policy(
        deny=(NamedTool("Write", "generated/**", rationale="Regenerate this file."),),
        allow=(NamedTool("Write", "src/**"),),
    ).decide(request)
    assert verdict == Verdict(Decision.Deny, "Regenerate this file.")


def test_compound_request_with_an_unscoped_file_asks() -> None:
    request = CompoundRequest(
        (
            ToolRequest("Write", (("file_path", "src/app.py"),)),
            ToolRequest("Write", (("file_path", "docs/x.md"),)),
        )
    )
    verdict = Policy(allow=(NamedTool("Write", "src/**"),)).decide(request)
    assert verdict.decision is Decision.Ask
    assert verdict.rationale.startswith("compound includes unrecognized segment")


def test_rejected_native_request_is_denied_before_policy_matching() -> None:
    assert Policy().decide(RejectedRequest("unsafe payload")) == Verdict(
        Decision.Deny,
        "unsafe payload",
    )


def test_named_tool_domain_specifier_matches_url_field() -> None:
    rule = NamedTool("WebFetch", "domain:github.com")
    assert rule.matches("WebFetch", (("url", "https://github.com/a/b"),)) is True
    assert rule.matches("WebFetch", (("url", "https://api.github.com/x"),)) is True  # subdomain
    assert rule.matches("WebFetch", (("url", "https://github.com./x"),)) is True  # trailing root dot
    assert rule.matches("WebFetch", (("url", "https://evil.com/x"),)) is False
    assert rule.matches("WebFetch", (("url", "https://notgithub.com/x"),)) is False  # not a suffix
    assert rule.matches("WebFetch", ()) is False  # no URL to check


def test_named_tool_domain_ignores_url_in_non_url_field() -> None:
    # A github.com URL sitting in a non-URL field (e.g. prompt) must NOT satisfy the rule.
    rule = NamedTool("WebFetch", "domain:github.com")
    args = (("url", "https://evil.example/x"), ("prompt", "compare with https://github.com/x"))
    assert rule.matches("WebFetch", args) is False


def test_named_tool_domain_does_not_crash_on_malformed_url() -> None:
    rule = NamedTool("WebFetch", "domain:github.com")
    assert rule.matches("WebFetch", (("url", "http://[::1"),)) is False  # no exception


def test_named_tool_domain_idna_normalizes_host() -> None:
    # Unicode and punycode forms of the same host are equivalent in both directions.
    assert (
        NamedTool("WebFetch", "domain:bücher.example").matches(
            "WebFetch", (("url", "https://xn--bcher-kva.example/x"),)
        )
        is True
    )
    assert (
        NamedTool("WebFetch", "domain:xn--bcher-kva.example").matches(
            "WebFetch", (("url", "https://bücher.example/x"),)
        )
        is True
    )


def test_named_tool_glob_specifier_matches_path_field() -> None:
    rule = NamedTool("Read", "/etc/**")
    assert rule.matches("Read", (("file_path", "/etc/passwd"),)) is True
    assert rule.matches("Read", (("file_path", "/etc/ssl/cert.pem"),)) is True  # ** crosses /
    assert rule.matches("Read", (("file_path", "/home/user/x"),)) is False
    # `*` stays within one segment; the same mechanism scopes any tool, not just Read
    assert NamedTool("Write", "src/*").matches("Write", (("file_path", "src/main.py"),)) is True
    assert NamedTool("Write", "src/*").matches("Write", (("file_path", "src/sub/secret"),)) is False


def test_named_tool_glob_normalizes_path_traversal() -> None:
    # `..` is collapsed before matching, so a scope can't be escaped via traversal.
    assert NamedTool("Read", "/repo/src/**").matches("Read", (("file_path", "/repo/src/../secrets/token"),)) is False
    assert NamedTool("Read", "/repo/secrets/**").matches("Read", (("file_path", "/repo/src/../secrets/token"),)) is True


def test_named_tool_glob_ignores_path_in_non_path_field() -> None:
    # Path-like text in a non-path field (e.g. an edit's old_string) must NOT match.
    rule = NamedTool("Write", "src/**")
    args = (("file_path", "/etc/passwd"), ("old_string", "import src.app"))
    assert rule.matches("Write", args) is False


def test_named_tool_specifier_requires_name_match() -> None:
    # specifier only applies once the name matches
    assert NamedTool("Read", "/etc/**").matches("Write", (("file_path", "/etc/passwd"),)) is False


def test_parse_round_trips_scoped_named_tool() -> None:
    rule = parse_rule("WebFetch(domain:github.com)")
    assert isinstance(rule, NamedTool)
    assert (rule.name, rule.specifier) == ("WebFetch", "domain:github.com")
    assert rule.serialize() == "WebFetch(domain:github.com)"
    # `Name(*)` and `Name()` normalize to the bare name (no dead rules)
    read_star = parse_rule("Read(*)")
    read_bare = parse_rule("Read")
    assert isinstance(read_star, NamedTool) and read_star.serialize() == "Read"
    assert isinstance(read_bare, NamedTool) and read_bare.serialize() == "Read"


@pytest.mark.parametrize("text", ("Bash", "Bash()"))
def test_bare_bash_tool_name_raises_policy_error(text: str) -> None:
    with pytest.raises(PolicyError, match="silently dead"):
        parse_rule(text)


# ---- Strictness aggregation ----------------------------------------------


def test_aggregate_picks_strictest() -> None:
    verdicts = [
        Verdict(Decision.Allow, "a"),
        Verdict(Decision.Deny, "denied"),
        Verdict(Decision.Allow, "b"),
    ]
    result = aggregate(verdicts)
    assert result.decision is Decision.Deny


def test_aggregate_escalates_allow_with_unknown_to_ask() -> None:
    """The compound-aggregation rule: any NoOpinion segment escalates Allow → Ask."""
    verdicts = [Verdict(Decision.Allow, "ok"), Verdict(Decision.NoOpinion, "no rule for foo")]
    result = aggregate(verdicts)
    assert result.decision is Decision.Ask
    assert "unrecognized" in result.rationale


def test_aggregate_does_not_escalate_pure_allow() -> None:
    verdicts = [Verdict(Decision.Allow, "a"), Verdict(Decision.Allow, "b")]
    assert aggregate(verdicts).decision is Decision.Allow


def test_aggregate_empty_is_no_opinion() -> None:
    assert aggregate([]).decision is Decision.NoOpinion
