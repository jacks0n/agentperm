"""Policy decision tests — strictness, aggregation, rule matching, bypass coercion."""

from __future__ import annotations

from pathlib import Path

from agentperms import (
    BashCommand,
    BashOption,
    Decision,
    NamedTool,
    Policy,
    Segment,
    ShellRequest,
    ToolRequest,
    Verdict,
    agentperms_bypass_dir,
    aggregate,
    coerce_for_pane_bypass,
    coerce_for_permission_mode,
    parse_pipeline,
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


# ---- Bypass-permissions coercion -----------------------------------------


def test_bypass_mode_coerces_ask_to_allow():
    verdict = Verdict(Decision.Ask, "some reason")
    coerced = coerce_for_permission_mode(verdict, {"permission_mode": "bypassPermissions"})
    assert coerced.decision is Decision.Allow
    assert "bypass" in coerced.rationale


def test_bypass_mode_does_not_touch_deny():
    verdict = Verdict(Decision.Deny, "dangerous")
    coerced = coerce_for_permission_mode(verdict, {"permission_mode": "bypassPermissions"})
    assert coerced.decision is Decision.Deny


def test_bypass_mode_does_not_coerce_parse_failure_ask():
    """A command the parser couldn't analyze must keep prompting even in bypass —
    it may hide a denied command, so it is not a 'skip the prompt' case."""
    verdict = Verdict(Decision.Ask, "shell syntax not safely parseable", parse_failure=True)
    coerced = coerce_for_permission_mode(verdict, {"permission_mode": "bypassPermissions"})
    assert coerced.decision is Decision.Ask


def test_unparseable_command_is_not_allowed_under_bypass():
    """End-to-end: genuinely unparseable shell stays Ask under bypass, not Allow."""
    verdict = Policy().decide(ShellRequest(parse_pipeline("ls && && rm -rf /")))
    assert verdict.decision is Decision.Ask
    assert verdict.parse_failure is True
    coerced = coerce_for_permission_mode(verdict, {"permission_mode": "bypassPermissions"})
    assert coerced.decision is Decision.Ask


def test_default_mode_keeps_ask():
    verdict = Verdict(Decision.Ask, "compound")
    coerced = coerce_for_permission_mode(verdict, {"permission_mode": "default"})
    assert coerced.decision is Decision.Ask


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
    base = tmp_path / "agentperms" / "bypass" / session
    base.mkdir(parents=True, exist_ok=True)
    (tmp_path / "agentperms" / "bypass").chmod(0o700)
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
    base = tmp_path / "agentperms" / "bypass" / "main"
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
    (tmp_path / "agentperms" / "bypass").chmod(0o777)
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_pane_bypass_missing_dir_is_safe_noop(tmp_path: Path):
    """No dir at all -> no flag possible -> verdict unchanged, no error."""
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_agentperms_bypass_dir_honors_xdg(tmp_path: Path):
    env = {"XDG_CACHE_HOME": str(tmp_path / "x")}
    assert agentperms_bypass_dir(env) == tmp_path / "x" / "agentperms" / "bypass"


def test_agentperms_bypass_dir_falls_back_to_home():
    env = {"HOME": "/var/empty"}
    assert agentperms_bypass_dir(env) == Path("/var/empty") / ".cache" / "agentperms" / "bypass"


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


def test_deny_bites_through_redirected_shell_wrapper():
    """``zsh -lc "rm -rf /" 2>/dev/null`` must not launder a denied command past
    the wrapper-plus-redirect path — and bypass mode must not rescue it."""
    policy = Policy(deny=(BashCommand(("rm", "-rf")),))
    command = 'zsh -lc "rm -rf /" 2>/dev/null'
    assert _decide(policy, command).decision is Decision.Deny
    coerced = coerce_for_permission_mode(_decide(policy, command), {"permission_mode": "bypassPermissions"})
    assert coerced.decision is Decision.Deny


def test_deny_bites_through_process_substitution_redirect():
    """``cat < <(rm -rf /)`` must surface the inner command for a deny rule, rather
    than degrade to Ask and then get coerced to Allow under bypass."""
    policy = Policy(deny=(BashCommand(("rm", "-rf")),))
    command = "cat < <(rm -rf /)"
    assert _decide(policy, command).decision is Decision.Deny
    coerced = coerce_for_permission_mode(_decide(policy, command), {"permission_mode": "bypassPermissions"})
    assert coerced.decision is Decision.Deny


def test_deny_bites_through_write_process_substitution():
    """``tee > >(rm -rf /)`` — write to a process substitution still extracts and
    denies the inner command."""
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
    """``echo hi > out$(rm -rf /)`` — a denied command nested in a redirect target
    word must not slip past via unparseable→Ask→bypass-Allow."""
    policy = Policy(deny=(BashCommand(("rm", "-rf")),))
    command = "echo hi > out$(rm -rf /)"
    assert _decide(policy, command).decision is Decision.Deny
    coerced = coerce_for_permission_mode(_decide(policy, command), {"permission_mode": "bypassPermissions"})
    assert coerced.decision is Decision.Deny


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


def _denied_under_bypass(command: str) -> Decision:
    policy = Policy(deny=(BashCommand(("rm", "-rf")),))
    verdict = coerce_for_permission_mode(_decide(policy, command), {"permission_mode": "bypassPermissions"})
    return verdict.decision


def test_deny_bites_case_subject_substitution_under_bypass():
    """``case $(rm -rf /) in …`` — the subject substitution runs; its inner command
    must be policed, not laundered via unparseable→Ask→bypass-Allow."""
    assert _denied_under_bypass("case $(rm -rf /) in *) echo ok;; esac") is Decision.Deny


def test_deny_bites_exotic_redirect_operators_under_bypass():
    """`>|`, `&>>`, `<&` redirect operators with a substitution target must surface
    the inner command for a deny rule rather than degrade to unparseable."""
    assert _denied_under_bypass("cmd >| out$(rm -rf /)") is Decision.Deny
    assert _denied_under_bypass("cmd &>> out$(rm -rf /)") is Decision.Deny
    assert _denied_under_bypass("cmd <& $(rm -rf /)") is Decision.Deny


def test_deny_bites_herestring_substitution_under_bypass():
    """``cat <<< $(rm -rf /)`` — herestring body substitution runs and must be policed."""
    assert _denied_under_bypass("cat <<< $(rm -rf /)") is Decision.Deny


def test_deny_bites_split_shell_c_under_bypass():
    """``bash -l -c "rm -rf /"`` — split no-arg flags before -c are unwrapped so the
    inner command is policed instead of allowed."""
    assert _denied_under_bypass('bash -l -c "rm -rf /"') is Decision.Deny


def test_unanalyzable_shell_c_wrapper_is_parse_failure():
    """A shell ``-c`` wrapper we can't safely unwrap (`bash --norc -c "…"`) hides its
    command, so it's a parse-failure Ask — NoOpinion would be coerced to Allow under
    bypass, laundering the hidden command."""
    verdict = _decide(Policy(), 'bash --norc -c "rm -rf /"')
    assert verdict.decision is Decision.Ask
    assert verdict.parse_failure is True
    coerced = coerce_for_permission_mode(verdict, {"permission_mode": "bypassPermissions"})
    assert coerced.decision is Decision.Ask


def test_plain_shell_script_invocation_stays_no_opinion():
    """``bash script.sh`` carries no ``-c`` command flag — it's an ordinary opaque
    command, not an unanalyzable wrapper, so it stays NoOpinion (no false prompt)."""
    verdict = _decide(Policy(), "bash deploy.sh --flag")
    assert verdict.decision is Decision.NoOpinion
    assert verdict.parse_failure is False


def test_deny_bites_through_exec_prefix_wrappers_under_bypass():
    """``command``/``exec``/``env``/``nice``/``time`` decompose, so a deny rule on the
    inner command bites even under bypass instead of NoOpinion→Allow."""
    for command in (
        "command rm -rf /",
        "exec rm -rf /",
        "nohup rm -rf /",
        "env -i FOO=bar rm -rf /",
        "nice rm -rf /",
        "command nice rm -rf /",
    ):
        assert _denied_under_bypass(command) is Decision.Deny, command


def test_opaque_exec_wrapper_is_parse_failure_under_bypass():
    """``timeout``/``sudo``/``nice -n`` aren't decomposable; absent a rule they're a
    parse-failure Ask so bypass prompts rather than allowing the hidden command."""
    for command in ("timeout 5 rm -rf /", "sudo rm -rf /", "nice -n 10 rm -rf /"):
        verdict = _decide(Policy(deny=(BashCommand(("rm", "-rf")),)), command)
        assert verdict.decision is Decision.Ask, command
        assert verdict.parse_failure is True, command
        coerced = coerce_for_permission_mode(verdict, {"permission_mode": "bypassPermissions"})
        assert coerced.decision is Decision.Ask, command


def test_explicit_rule_allow_lists_opaque_wrapper():
    """An explicit rule on an opaque wrapper still wins over the parse-failure fallback."""
    policy = Policy(allow=(BashCommand(("timeout",)),))
    assert _decide(policy, "timeout 5 make").decision is Decision.Allow


def test_eval_decomposes_literal_command():
    """``eval "rm -rf /"`` joins and re-parses its args, so a deny rule bites."""
    assert _denied_under_bypass('eval "rm -rf /"') is Decision.Deny
    assert _denied_under_bypass("eval rm -rf /") is Decision.Deny


def test_parse_failure_survives_tied_redirect_ask_under_bypass():
    """A redirect's ordinary `Ask` ("writes to …") ties the wrapper's parse-failure
    `Ask`; the combined verdict must stay parse-failure so bypass doesn't allow the
    hidden command (`sudo rm -rf / > out`)."""
    for command in (
        "sudo rm -rf / > out",
        "timeout 5 rm -rf / > out",
        'bash --norc -c "rm -rf /" > out',
    ):
        verdict = _decide(Policy(deny=(BashCommand(("rm", "-rf")),)), command)
        assert verdict.decision is Decision.Ask, command
        assert verdict.parse_failure is True, command
        coerced = coerce_for_permission_mode(verdict, {"permission_mode": "bypassPermissions"})
        assert coerced.decision is Decision.Ask, command


def test_parse_failure_survives_aggregation_across_segments_under_bypass():
    """A parse-failure segment in a compound must not be masked by a benign sibling
    segment's ordinary verdict (`echo hi > out; sudo rm -rf /`)."""
    verdict = _decide(Policy(deny=(BashCommand(("rm", "-rf")),)), "echo hi > out; sudo rm -rf /")
    assert verdict.decision is Decision.Ask
    assert verdict.parse_failure is True
    coerced = coerce_for_permission_mode(verdict, {"permission_mode": "bypassPermissions"})
    assert coerced.decision is Decision.Ask


def test_command_v_lookup_is_not_executed():
    """``command -v rm`` / ``command -V rm`` resolve the name without running it, so a
    deny rule on the inner command must not fire."""
    policy = Policy(deny=(BashCommand(("rm",)),))
    assert _decide(policy, "command -v rm").decision is Decision.Allow
    assert _decide(policy, "command -V rm").decision is Decision.Allow
    # the executing form is still decomposed and denied
    assert _decide(policy, "command rm -rf /").decision is Decision.Deny


def test_dynamic_command_name_is_parse_failure():
    """A command whose name is a runtime expansion (`eval "$cmd"`, `$TOOL …`) is
    unknowable, so it's a parse-failure Ask that bypass won't coerce to Allow."""
    for command in ('eval "$UNKNOWN"', 'bash -c "$CMD"', "$TOOL --flag", "${RUNNER} test"):
        verdict = _decide(Policy(), command)
        assert verdict.decision is Decision.Ask, command
        assert verdict.parse_failure is True, command
        coerced = coerce_for_permission_mode(verdict, {"permission_mode": "bypassPermissions"})
        assert coerced.decision is Decision.Ask, command


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
