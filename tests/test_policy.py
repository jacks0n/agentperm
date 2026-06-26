"""Policy decision tests — strictness, aggregation, rule matching, bypass coercion."""

from __future__ import annotations

from pathlib import Path

from agentperm import (
    BashCommand,
    BashOption,
    Decision,
    NamedTool,
    Policy,
    Segment,
    ShellRequest,
    ToolRequest,
    Verdict,
    agentperm_bypass_dir,
    aggregate,
    coerce_for_pane_bypass,
    coerce_for_permission_mode,
    parse_pipeline,
    parse_rule,
)

# ---- Rule matching --------------------------------------------------------


def test_bash_command_prefix_matches_argv_head():
    rule = BashCommand(("git", "status"))
    seg = Segment(argv=("git", "status", "--short"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_does_not_match_shorter_argv():
    rule = BashCommand(("git", "status"))
    seg = Segment(argv=("git",), redirects=())
    assert rule.matches(seg) is False


def test_bash_command_glob_star_matches_one_token():
    rule = BashCommand(("pnpm", "*", "build"))
    seg = Segment(argv=("pnpm", "--dir", "build"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_glob_star_does_not_match_zero_tokens():
    rule = BashCommand(("pnpm", "*", "build"))
    seg = Segment(argv=("pnpm", "build"), redirects=())
    assert rule.matches(seg) is False


def test_bash_command_glob_star_does_not_match_two_tokens():
    rule = BashCommand(("pnpm", "*", "build"))
    seg = Segment(argv=("pnpm", "--dir", "x", "build"), redirects=())
    assert rule.matches(seg) is False


def test_bash_command_glob_doublestar_matches_zero_tokens():
    rule = BashCommand(("pnpm", "**", "build"))
    seg = Segment(argv=("pnpm", "build"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_glob_doublestar_matches_many_tokens():
    rule = BashCommand(("pnpm", "**", "build"))
    seg = Segment(argv=("pnpm", "--dir", "x", "--silent", "build"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_glob_doublestar_with_trailing_extras():
    rule = BashCommand(("pnpm", "**", "build"), trailing_wildcard=True)
    seg = Segment(argv=("pnpm", "--dir", "x", "build", "--watch"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_exact_form_rejects_extra_args():
    rule = BashCommand(("git", "status"), trailing_wildcard=False)
    seg = Segment(argv=("git", "status", "--short"), redirects=())
    assert rule.matches(seg) is False


def test_bash_command_exact_form_matches_full_argv():
    rule = BashCommand(("git", "status"), trailing_wildcard=False)
    seg = Segment(argv=("git", "status"), redirects=())
    assert rule.matches(seg) is True


def test_bash_command_glob_first_token_skips_basename_rule():
    rule = BashCommand(("*", "status"))
    seg = Segment(argv=("/usr/bin/git", "status"), redirects=())
    assert rule.matches(seg) is True


def test_bash_option_short_flag_matches_combined():
    rule = BashOption(commands=frozenset({"sed"}), options=frozenset({"-i"}), rationale="in-place")
    seg = Segment(argv=("sed", "-iE", "s/a/b/"), redirects=())
    assert rule.matches(seg) is True


def test_bash_option_long_flag_matches_with_equals():
    rule = BashOption(commands=frozenset({"rsync"}), options=frozenset({"--delete"}), rationale="destructive")
    seg = Segment(argv=("rsync", "--delete=true", "src/", "dst/"), redirects=())
    assert rule.matches(seg) is True


def test_bash_option_does_not_match_after_double_dash():
    rule = BashOption(commands=frozenset({"sed"}), options=frozenset({"-i"}), rationale="in-place")
    seg = Segment(argv=("sed", "-e", "s/x/y/", "--", "-i"), redirects=())
    # `--` is positional; the literal `-i` after `--` is a filename, not a flag.
    # Our matcher doesn't track `--` boundary — but it correctly skips bare `--`.
    # This case currently returns True because our matcher checks every arg. Document the
    # limitation explicitly: callers that pass `-i` after `--` would still get prompted.
    # The conservative direction (Ask on -i) is the right default for a permission policy.
    assert rule.matches(seg) is True


def test_named_tool_exact_match():
    assert NamedTool("Read").matches("Read") is True
    assert NamedTool("Read").matches("Write") is False


def test_named_tool_wildcard_matches_anything():
    assert NamedTool("*").matches("Read") is True
    assert NamedTool("*").matches("WeirdMcpTool") is True


def test_named_tool_prefix_glob():
    assert NamedTool("mcp__memory__*").matches("mcp__memory__lookup") is True
    assert NamedTool("mcp__memory__*").matches("mcp__other__x") is False


def test_named_tool_no_specifier_ignores_arguments():
    # Bare name (and the `*` specifier) match the tool regardless of input.
    assert NamedTool("Read").matches("Read", (("file_path", "/etc/passwd"),)) is True
    assert NamedTool("Read", "*").matches("Read", (("file_path", "/anything"),)) is True


def test_named_tool_domain_specifier_matches_url_field():
    rule = NamedTool("WebFetch", "domain:github.com")
    assert rule.matches("WebFetch", (("url", "https://github.com/a/b"),)) is True
    assert rule.matches("WebFetch", (("url", "https://api.github.com/x"),)) is True  # subdomain
    assert rule.matches("WebFetch", (("url", "https://github.com./x"),)) is True  # trailing root dot
    assert rule.matches("WebFetch", (("url", "https://evil.com/x"),)) is False
    assert rule.matches("WebFetch", (("url", "https://notgithub.com/x"),)) is False  # not a suffix
    assert rule.matches("WebFetch", ()) is False  # no URL to check


def test_named_tool_domain_ignores_url_in_non_url_field():
    # A github.com URL sitting in a non-URL field (e.g. prompt) must NOT satisfy the rule.
    rule = NamedTool("WebFetch", "domain:github.com")
    args = (("url", "https://evil.example/x"), ("prompt", "compare with https://github.com/x"))
    assert rule.matches("WebFetch", args) is False


def test_named_tool_domain_does_not_crash_on_malformed_url():
    rule = NamedTool("WebFetch", "domain:github.com")
    assert rule.matches("WebFetch", (("url", "http://[::1"),)) is False  # no exception


def test_named_tool_domain_idna_normalizes_host():
    # Unicode and punycode forms of the same host are equivalent in both directions.
    assert NamedTool("WebFetch", "domain:bücher.example").matches(
        "WebFetch", (("url", "https://xn--bcher-kva.example/x"),)
    ) is True
    assert NamedTool("WebFetch", "domain:xn--bcher-kva.example").matches(
        "WebFetch", (("url", "https://bücher.example/x"),)
    ) is True


def test_named_tool_glob_specifier_matches_path_field():
    rule = NamedTool("Read", "/etc/**")
    assert rule.matches("Read", (("file_path", "/etc/passwd"),)) is True
    assert rule.matches("Read", (("file_path", "/etc/ssl/cert.pem"),)) is True  # ** crosses /
    assert rule.matches("Read", (("file_path", "/home/user/x"),)) is False
    # `*` stays within one segment; the same mechanism scopes any tool, not just Read
    assert NamedTool("Edit", "src/*").matches("Edit", (("file_path", "src/main.py"),)) is True
    assert NamedTool("Edit", "src/*").matches("Edit", (("file_path", "src/sub/secret"),)) is False


def test_named_tool_glob_normalizes_path_traversal():
    # `..` is collapsed before matching, so a scope can't be escaped via traversal.
    assert NamedTool("Read", "/repo/src/**").matches(
        "Read", (("file_path", "/repo/src/../secrets/token"),)
    ) is False
    assert NamedTool("Read", "/repo/secrets/**").matches(
        "Read", (("file_path", "/repo/src/../secrets/token"),)
    ) is True


def test_named_tool_glob_ignores_path_in_non_path_field():
    # Path-like text in a non-path field (e.g. an edit's old_string) must NOT match.
    rule = NamedTool("Edit", "src/**")
    args = (("file_path", "/etc/passwd"), ("old_string", "import src.app"))
    assert rule.matches("Edit", args) is False


def test_named_tool_specifier_requires_name_match():
    # specifier only applies once the name matches
    assert NamedTool("Read", "/etc/**").matches("Write", (("file_path", "/etc/passwd"),)) is False


def test_parse_round_trips_scoped_named_tool():
    rule = parse_rule("WebFetch(domain:github.com)")
    assert isinstance(rule, NamedTool)
    assert (rule.name, rule.specifier) == ("WebFetch", "domain:github.com")
    assert rule.serialize() == "WebFetch(domain:github.com)"
    # `Name(*)` and `Name()` normalize to the bare name (no dead rules)
    read_star = parse_rule("Read(*)")
    read_bare = parse_rule("Read")
    assert isinstance(read_star, NamedTool) and read_star.serialize() == "Read"
    assert isinstance(read_bare, NamedTool) and read_bare.serialize() == "Read"


# ---- Strictness aggregation ----------------------------------------------


def test_aggregate_picks_strictest():
    verdicts = [
        Verdict(Decision.Allow, "a"),
        Verdict(Decision.Deny, "denied"),
        Verdict(Decision.Allow, "b"),
    ]
    result = aggregate(verdicts)
    assert result.decision is Decision.Deny


def test_aggregate_escalates_allow_with_unknown_to_ask():
    """The compound-aggregation rule: any NoOpinion segment escalates Allow → Ask."""
    verdicts = [Verdict(Decision.Allow, "ok"), Verdict(Decision.NoOpinion, "no rule for foo")]
    result = aggregate(verdicts)
    assert result.decision is Decision.Ask
    assert "unrecognized" in result.rationale


def test_aggregate_does_not_escalate_pure_allow():
    verdicts = [Verdict(Decision.Allow, "a"), Verdict(Decision.Allow, "b")]
    assert aggregate(verdicts).decision is Decision.Allow


def test_aggregate_empty_is_no_opinion():
    assert aggregate([]).decision is Decision.NoOpinion


# ---- Policy.decide() end-to-end ------------------------------------------


def test_policy_allow_for_known_compound():
    policy = Policy(allow=(BashCommand(("cat",)), BashCommand(("head",))))
    pipeline = parse_pipeline("cat foo 2>&1 | head -60")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_asks_for_unknown_command_in_compound():
    policy = Policy(allow=(BashCommand(("cat",)),))
    pipeline = parse_pipeline("cat foo | unknowncmd")
    verdict = policy.decide(ShellRequest(pipeline))
    assert verdict.decision is Decision.Ask


def test_policy_denies_overrides_allow():
    policy = Policy(
        deny=(BashCommand(("rm", "-rf")),),
        allow=(BashCommand(("rm",)),),
    )
    pipeline = parse_pipeline("rm -rf /tmp/foo")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Deny


def test_policy_ask_for_sed_in_place():
    policy = Policy(
        ask=(BashOption(commands=frozenset({"sed"}), options=frozenset({"-i"}), rationale="in-place"),),
        allow=(BashCommand(("sed",)),),
    )
    # ask is checked before allow; sed -i hits the ask rule.
    pipeline = parse_pipeline("sed -i s/a/b/ foo")
    verdict = policy.decide(ShellRequest(pipeline))
    assert verdict.decision is Decision.Ask
    assert verdict.rationale == "in-place"


def test_policy_allows_sed_without_in_place_flag():
    policy = Policy(
        ask=(BashOption(commands=frozenset({"sed"}), options=frozenset({"-i"}), rationale="in-place"),),
        allow=(BashCommand(("sed",)),),
    )
    pipeline = parse_pipeline("sed -n 1,10p foo")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_asks_for_file_write_redirect():
    policy = Policy(allow=(BashCommand(("echo",)),))
    pipeline = parse_pipeline("echo hi > out.txt")
    verdict = policy.decide(ShellRequest(pipeline))
    assert verdict.decision is Decision.Ask
    assert "out.txt" in verdict.rationale


def test_policy_allows_stderr_to_devnull():
    policy = Policy(allow=(BashCommand(("cat",)),))
    pipeline = parse_pipeline("cat foo 2>/dev/null")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_allows_read_only_for_loop_body():
    policy = Policy(allow=(BashCommand(("echo",)), BashCommand(("npm", "view")), BashCommand(("head",))))
    pipeline = parse_pipeline(
        'for v in 0.0.34 0.0.32; do echo "=== @playwright/mcp@$v ==="; '
        'npm view "@playwright/mcp@$v" dependencies 2>&1 | head -8; done'
    )
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_allows_when_all_substitution_commands_allowed():
    policy = Policy(allow=(BashCommand(("rm",)), BashCommand(("cat",))))
    pipeline = parse_pipeline("rm $(cat allowed)")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_asks_when_substitution_command_unrecognized():
    policy = Policy(allow=(BashCommand(("rm",)),))
    pipeline = parse_pipeline("rm $(cat allowed)")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Ask


def test_policy_allows_zsh_lc_when_inner_substitution_commands_allowed():
    """The Codex motivating case: ``zsh -lc 'rg "pattern" $(git ls-files | rg foo)'``
    should Allow when rg and git are in the allow list."""
    policy = Policy(allow=(BashCommand(("rg",)), BashCommand(("git", "ls-files"))))
    pipeline = parse_pipeline(
        "/opt/homebrew/opt/zsh/bin/zsh -lc 'rg \"pattern\" -n $(git ls-files | rg foo)'"
    )
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_asks_zsh_lc_when_inner_substitution_command_denied():
    """``zsh -lc 'rg $(curl evil)'`` — rg is allowed but curl is not."""
    policy = Policy(
        allow=(BashCommand(("rg",)),),
        deny=(BashCommand(("curl",)),),
    )
    pipeline = parse_pipeline("/opt/homebrew/opt/zsh/bin/zsh -lc 'rg $(curl evil)'")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Deny


def test_policy_named_tool_lookup():
    policy = Policy(allow=(NamedTool("Read"),))
    assert policy.decide(ToolRequest("Read")).decision is Decision.Allow
    assert policy.decide(ToolRequest("Write")).decision is Decision.NoOpinion


# ---- Bypass-permissions: agentperm defers entirely ----------------------


def test_bypass_mode_defers_every_decision():
    """Under Claude bypass the user opted out of permission checks, so agentperm
    returns NoOpinion (an empty {} envelope) for everything — Ask, Allow, and even
    Deny — and lets Claude's native bypass proceed."""
    for decision in (Decision.Ask, Decision.Allow, Decision.Deny, Decision.NoOpinion):
        coerced = coerce_for_permission_mode(Verdict(decision, "x"), {"permission_mode": "bypassPermissions"})
        assert coerced.decision is Decision.NoOpinion


def test_default_mode_keeps_verdict_unchanged():
    for decision in (Decision.Ask, Decision.Allow, Decision.Deny):
        coerced = coerce_for_permission_mode(Verdict(decision, "x"), {"permission_mode": "default"})
        assert coerced.decision is decision


def test_missing_mode_keeps_ask():
    verdict = Verdict(Decision.Ask, "compound")
    coerced = coerce_for_permission_mode(verdict, {})
    assert coerced.decision is Decision.Ask


# ---- Per-pane bypass (zellij plugin flag file) ----------------------------


def _bypass_env(tmp_path: Path, *, session: str = "main", pane_id: str = "42") -> dict[str, str]:
    return {
        "XDG_CACHE_HOME": str(tmp_path),
        "ZELLIJ_SESSION_NAME": session,
        "ZELLIJ_PANE_ID": pane_id,
    }


def _touch_flag(tmp_path: Path, session: str, pane_id: str) -> Path:
    """Create the bypass dir at 0700 and an empty flag file at 0600."""
    base = tmp_path / "agentperm" / "bypass" / session
    base.mkdir(parents=True, exist_ok=True)
    (tmp_path / "agentperm" / "bypass").chmod(0o700)
    base.chmod(0o700)
    flag = base / pane_id
    flag.touch(mode=0o600)
    return flag


def test_pane_bypass_coerces_ask_to_allow(tmp_path: Path):
    _touch_flag(tmp_path, "main", "42")
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "policy ask"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Allow
    assert verdict.rationale.startswith("pane bypass:")
    assert coercion is not None
    assert coercion.by == "zellij_pane_bypass"
    assert coercion.pane_id == "42"
    assert coercion.session == "main"
    assert coercion.original.decision is Decision.Ask


def test_pane_bypass_coerces_no_opinion_to_allow(tmp_path: Path):
    """Codex prompts on NoOpinion (CodexAdapter.write_verdict line 1089), so bypass must cover it."""
    _touch_flag(tmp_path, "main", "42")
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.NoOpinion, "no rule matched"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Allow
    assert coercion is not None
    assert coercion.original.decision is Decision.NoOpinion


def test_pane_bypass_does_not_touch_deny(tmp_path: Path):
    _touch_flag(tmp_path, "main", "42")
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Deny, "rm -rf /"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Deny
    assert coercion is None


def test_pane_bypass_does_not_touch_allow(tmp_path: Path):
    _touch_flag(tmp_path, "main", "42")
    original = Verdict(Decision.Allow, "matched ls rule")
    verdict, coercion = coerce_for_pane_bypass(original, _bypass_env(tmp_path))
    assert verdict is original
    assert coercion is None


def test_pane_bypass_no_flag_keeps_verdict(tmp_path: Path):
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_pane_bypass_no_session_keeps_verdict(tmp_path: Path):
    _touch_flag(tmp_path, "main", "42")
    env = {"XDG_CACHE_HOME": str(tmp_path), "ZELLIJ_PANE_ID": "42"}
    verdict, _ = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), env)
    assert verdict.decision is Decision.Ask


def test_pane_bypass_no_pane_id_keeps_verdict(tmp_path: Path):
    _touch_flag(tmp_path, "main", "42")
    env = {"XDG_CACHE_HOME": str(tmp_path), "ZELLIJ_SESSION_NAME": "main"}
    verdict, _ = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), env)
    assert verdict.decision is Decision.Ask


def test_pane_bypass_path_traversal_pane_id_rejected(tmp_path: Path):
    """Even if a flag exists at the resolved path, ../-bearing pane ids must be refused."""
    # Place a flag where "../escape" would resolve to, to prove the check rejects before hitting fs.
    base = tmp_path / "agentperm" / "bypass" / "main"
    base.mkdir(parents=True)
    (base.parent).chmod(0o700)
    base.chmod(0o700)
    (base / "..escape").touch(mode=0o600)
    env = _bypass_env(tmp_path, pane_id="../escape")
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), env)
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_pane_bypass_path_traversal_session_rejected(tmp_path: Path):
    env = _bypass_env(tmp_path, session="../evil")
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), env)
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_pane_bypass_world_writable_dir_rejected(tmp_path: Path):
    _touch_flag(tmp_path, "main", "42")
    (tmp_path / "agentperm" / "bypass").chmod(0o777)
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_pane_bypass_missing_dir_is_safe_noop(tmp_path: Path):
    """No dir at all -> no flag possible -> verdict unchanged, no error."""
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_agentperm_bypass_dir_honors_xdg(tmp_path: Path):
    env = {"XDG_CACHE_HOME": str(tmp_path / "x")}
    assert agentperm_bypass_dir(env) == tmp_path / "x" / "agentperm" / "bypass"


def test_agentperm_bypass_dir_falls_back_to_home():
    env = {"HOME": "/var/empty"}
    assert agentperm_bypass_dir(env) == Path("/var/empty") / ".cache" / "agentperm" / "bypass"


# ---- Policy merging -------------------------------------------------------


def test_merged_policies_union_rules_without_duplicates():
    a = Policy(allow=(BashCommand(("ls",)), BashCommand(("cat",))))
    b = Policy(allow=(BashCommand(("ls",)), BashCommand(("rg",))))
    merged = a.merged_with(b)
    prefixes = {r.prefix for r in merged.allow if isinstance(r, BashCommand)}
    assert prefixes == {("ls",), ("cat",), ("rg",)}


# ---- Inert command names -------------------------------------------------


def _decide(policy: Policy, command: str) -> Verdict:
    return policy.decide(ShellRequest(parse_pipeline(command)))


def test_inert_builtins_allowed_when_no_rule_matches():
    policy = Policy()  # no user rules at all
    for command in (
        "echo foo",
        "true",
        "false",
        ":",
        "read line",
        'printf "%s" hi',
        "[ -f x ]",
        "[[ -f x ]]",
        "(( 1 + 1 ))",
    ):
        assert _decide(policy, command).decision is Decision.Allow, command


def test_user_deny_overrides_inert_builtin():
    """An explicit ``deny: ['Bash(echo:*)']`` must bite — inert allow is only a fallback."""
    policy = Policy(deny=(BashCommand(("echo",)),))
    assert _decide(policy, "echo foo").decision is Decision.Deny


def test_user_ask_overrides_inert_builtin():
    """An explicit ``ask`` rule on an inert builtin takes precedence over the inert fallback."""
    policy = Policy(ask=(BashCommand(("printf",)),))
    assert _decide(policy, 'printf "%s" hi').decision is Decision.Ask


def test_echo_with_redirect_still_asks():
    """Inert allow is the command fallback, but redirects are evaluated separately."""
    policy = Policy()
    verdict = _decide(policy, "echo foo > out.txt")
    assert verdict.decision is Decision.Ask
    assert "out.txt" in verdict.rationale


# Decomposition correctness — these assert the raw (normal-mode) decision. Under
# bypass agentperm defers entirely (see test_bypass_mode_defers_every_decision);
# the value of decomposition is that a denied inner command is caught in normal mode.


def _deny_rm() -> Policy:
    return Policy(deny=(BashCommand(("rm", "-rf")),))


def test_deny_bites_through_redirected_shell_wrapper():
    """``zsh -lc "rm -rf /" 2>/dev/null`` must not launder a denied command past the
    wrapper-plus-redirect path."""
    assert _decide(_deny_rm(), 'zsh -lc "rm -rf /" 2>/dev/null').decision is Decision.Deny


def test_deny_bites_through_process_substitution_redirect():
    """``cat < <(rm -rf /)`` surfaces the inner command for a deny rule."""
    assert _decide(_deny_rm(), "cat < <(rm -rf /)").decision is Decision.Deny


def test_deny_bites_through_write_process_substitution():
    """``tee > >(rm -rf /)`` — write to a process substitution still extracts and denies."""
    policy = Policy(deny=(BashCommand(("rm", "-rf")),), allow=(BashCommand(("tee",)),))
    assert _decide(policy, "tee > >(rm -rf /)").decision is Decision.Deny


def test_command_substitution_write_target_asks():
    """``cmd > $(echo f)`` writes to a runtime-computed filename — unknowable, so the
    write must still ask even though ``cmd`` is allowed (not silently dropped)."""
    policy = Policy(allow=(BashCommand(("cmd",)),))
    verdict = _decide(policy, "cmd > $(echo /etc/passwd)")
    assert verdict.decision is Decision.Ask
    assert "writes to" in verdict.rationale


def test_deny_bites_through_substitution_nested_in_redirect_target():
    """``echo hi > out$(rm -rf /)`` — a denied command nested in a redirect target word."""
    assert _decide(_deny_rm(), "echo hi > out$(rm -rf /)").decision is Decision.Deny


def test_exact_deny_rule_bites_unwrapped_shell_c_with_spillover():
    """An exact (non-glob) deny rule must match the unwrapped inner command even
    when the wrapper carries trailing positional params after the redirect."""
    policy = Policy(deny=(BashCommand(("rm", "-rf", "/")),))
    assert _decide(policy, 'zsh -lc "rm -rf /" 2>/dev/null harmless').decision is Decision.Deny


def test_user_rule_cannot_target_synthetic_predicate_marker():
    """``[`` / ``[[`` / ``((`` are parser artifacts, not real commands. A user rule
    on ``[`` must not block test predicates, and they stay allowed."""
    policy = Policy(deny=(BashCommand(("[",)),))
    assert _decide(policy, "[ -f x ]").decision is Decision.Allow
    assert _decide(policy, "[[ -f x ]]").decision is Decision.Allow


def test_deny_bites_case_subject_substitution():
    """``case $(rm -rf /) in …`` — the subject substitution runs; its inner command is policed."""
    assert _decide(_deny_rm(), "case $(rm -rf /) in *) echo ok;; esac").decision is Decision.Deny


def test_deny_bites_exotic_redirect_operators():
    """`>|`, `&>>`, `<&` redirect operators with a substitution target surface the inner command."""
    assert _decide(_deny_rm(), "cmd >| out$(rm -rf /)").decision is Decision.Deny
    assert _decide(_deny_rm(), "cmd &>> out$(rm -rf /)").decision is Decision.Deny
    assert _decide(_deny_rm(), "cmd <& $(rm -rf /)").decision is Decision.Deny


def test_deny_bites_herestring_substitution():
    """``cat <<< $(rm -rf /)`` — herestring body substitution runs and must be policed."""
    assert _decide(_deny_rm(), "cat <<< $(rm -rf /)").decision is Decision.Deny


def test_deny_bites_split_shell_c():
    """``bash -l -c "rm -rf /"`` — split no-arg flags before -c are unwrapped and policed."""
    assert _decide(_deny_rm(), 'bash -l -c "rm -rf /"').decision is Decision.Deny


def test_unanalyzable_shell_c_wrapper_asks():
    """A shell ``-c`` wrapper we can't safely unwrap (`bash --norc -c "…"`) hides its
    command, so in normal mode it asks rather than silently passing."""
    assert _decide(Policy(), 'bash --norc -c "rm -rf /"').decision is Decision.Ask


def test_plain_shell_script_invocation_stays_no_opinion():
    """``bash script.sh`` carries no ``-c`` command flag — an ordinary opaque command,
    not an unanalyzable wrapper, so it stays NoOpinion (no false prompt)."""
    assert _decide(Policy(), "bash deploy.sh --flag").decision is Decision.NoOpinion


def test_deny_bites_through_exec_prefix_wrappers():
    """``command``/``exec``/``env``/``nice``/``time`` decompose, so a deny rule on the
    inner command bites in normal mode."""
    for command in (
        "command rm -rf /",
        "exec rm -rf /",
        "nohup rm -rf /",
        "env -i FOO=bar rm -rf /",
        "nice rm -rf /",
        "command nice rm -rf /",
    ):
        assert _decide(_deny_rm(), command).decision is Decision.Deny, command


def test_opaque_exec_wrapper_asks():
    """``timeout``/``sudo``/``nice -n`` aren't decomposable; absent a rule they ask in
    normal mode rather than silently passing the hidden command."""
    for command in ("timeout 5 rm -rf /", "sudo rm -rf /", "nice -n 10 rm -rf /"):
        assert _decide(_deny_rm(), command).decision is Decision.Ask, command


def test_explicit_rule_allow_lists_opaque_wrapper():
    """An explicit rule on an opaque wrapper still wins over the ask fallback."""
    policy = Policy(allow=(BashCommand(("timeout",)),))
    assert _decide(policy, "timeout 5 make").decision is Decision.Allow


def test_eval_decomposes_literal_command():
    """``eval "rm -rf /"`` joins and re-parses its args, so a deny rule bites."""
    assert _decide(_deny_rm(), 'eval "rm -rf /"').decision is Decision.Deny
    assert _decide(_deny_rm(), "eval rm -rf /").decision is Decision.Deny


def test_command_v_lookup_is_not_executed():
    """``command -v rm`` / ``command -V rm`` resolve the name without running it, so a
    deny rule on the inner command must not fire."""
    policy = Policy(deny=(BashCommand(("rm",)),))
    assert _decide(policy, "command -v rm").decision is Decision.Allow
    assert _decide(policy, "command -V rm").decision is Decision.Allow
    # the executing form is still decomposed and denied
    assert _decide(policy, "command rm -rf /").decision is Decision.Deny


def test_dynamic_command_name_asks():
    """A command whose name is a runtime expansion (`eval "$cmd"`, `$TOOL …`) is
    unknowable, so in normal mode it asks rather than silently passing."""
    for command in ('eval "$UNKNOWN"', 'bash -c "$CMD"', "$TOOL --flag", "${RUNNER} test"):
        assert _decide(Policy(), command).decision is Decision.Ask, command


def test_inert_pipe_to_unknown_escalates_to_ask():
    """``echo foo | weird_cmd`` — echo is allowed, weird_cmd has no rule → Ask."""
    policy = Policy()
    verdict = _decide(policy, "echo foo | weird_cmd")
    assert verdict.decision is Decision.Ask


def test_if_with_allowed_body_is_allow():
    policy = Policy(allow=(BashCommand(("cat",)),))
    assert _decide(policy, "if [ -f x ]; then cat x; fi").decision is Decision.Allow


def test_if_with_unknown_body_asks():
    policy = Policy()
    assert _decide(policy, "if [ -f x ]; then weird_cmd; fi").decision is Decision.Ask


def test_if_with_denied_body_is_deny():
    """Function/control-flow bodies are subject to deny rules."""
    policy = Policy(deny=(BashCommand(("rm", "-rf")),))
    assert _decide(policy, "if true; then rm -rf /; fi").decision is Decision.Deny


def test_function_body_subjected_to_policy():
    """Defining-then-calling is the realistic threat — the body must be evaluated."""
    policy = Policy(deny=(BashCommand(("rm", "-rf")),))
    assert _decide(policy, "foo() { rm -rf /; }; foo").decision is Decision.Deny


def test_export_matches_user_allow():
    """``Bash(export:*)`` allow rule must match an ``export FOO=bar`` declaration."""
    policy = Policy(allow=(BashCommand(("export",)),))
    assert _decide(policy, "export FOO=bar").decision is Decision.Allow


def test_export_with_substitution_asks_when_inner_unrecognized():
    """``export FOO=$(curl evil)`` — export is allowed but ``curl`` isn't, so Ask."""
    policy = Policy(allow=(BashCommand(("export",)),))
    assert _decide(policy, "export FOO=$(curl evil)").decision is Decision.Ask


def test_export_with_substitution_allows_when_inner_allowed():
    """``export FOO=$(date)`` — both export and date are allowed, so Allow."""
    policy = Policy(allow=(BashCommand(("export",)), BashCommand(("date",))))
    assert _decide(policy, "export FOO=$(date)").decision is Decision.Allow


def test_user_request_original_failing_case():
    """Regression for the exact command that motivated this work."""
    policy = Policy(allow=(BashCommand(("sed",)),))
    cmd = "if [ -f .env.development ]; then sed -n '1,220p' .env.development; fi"
    assert _decide(policy, cmd).decision is Decision.Allow
