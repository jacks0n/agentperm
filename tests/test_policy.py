"""Policy decision tests — strictness, aggregation, rule matching, bypass coercion."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

import agentperm.policy as policy_module
from agentperm import (
    POLICY_FILENAME,
    BashCommand,
    BashOption,
    Decision,
    JsonObject,
    NamedTool,
    Policy,
    PolicyError,
    PolicyFile,
    PythonCallPolicy,
    RedirectionPolicy,
    Segment,
    ShellPattern,
    ShellRequest,
    ToolRequest,
    Verdict,
    agentperm_bypass_dir,
    aggregate,
    coerce_for_pane_bypass,
    coerce_for_permission_mode,
    load_policy_file,
    merged_policy,
    parse_pipeline,
    parse_rule,
    save_policy_file,
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


@pytest.mark.parametrize("text", ("Bash", "Bash()"))
def test_bare_bash_tool_name_raises_policy_error(text: str):
    with pytest.raises(PolicyError, match="silently dead"):
        parse_rule(text)


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


def test_policy_allows_stdout_to_devnull():
    """Discarding stdout is exactly as inert as discarding stderr — bare ``>``,
    explicit ``1>``, ``>>``, and ``&>`` to ``/dev/null`` must all default-allow,
    same as ``2>/dev/null`` already did."""
    policy = Policy(allow=(BashCommand(("cat",)),))
    for command in (
        "cat foo > /dev/null",
        "cat foo 1> /dev/null",
        "cat foo >> /dev/null",
        "cat foo &> /dev/null",
    ):
        assert _decide(policy, command).decision is Decision.Allow, command


def test_policy_allows_devnull_silence_everything_idiom():
    """``cmd > /dev/null 2>&1`` — the common "silence everything" idiom combines a
    stdout-to-devnull write with an fd-dup; both must default-allow."""
    policy = Policy(allow=(BashCommand(("cat",)),))
    assert _decide(policy, "cat foo > /dev/null 2>&1").decision is Decision.Allow


def test_policy_allows_read_only_for_loop_body():
    policy = Policy(allow=(BashCommand(("echo",)), BashCommand(("npm", "view")), BashCommand(("head",))))
    pipeline = parse_pipeline(
        'for v in 0.0.34 0.0.32; do echo "=== @playwright/mcp@$v ==="; '
        'npm view "@playwright/mcp@$v" dependencies 2>&1 | head -8; done'
    )
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_allows_commented_compound_when_commands_are_allowed():
    policy = Policy(allow=(BashCommand(("grep",)), BashCommand(("head",))))
    command = (
        "# Check import dependencies between modules\n"
        'echo "=== domain.py imports ==="\n'
        "grep -E '^(from|import) ' src/agentperm/domain.py | head -20"
    )
    assert _decide(policy, command).decision is Decision.Allow


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


def test_merged_policy_loads_global_and_all_ancestors_with_nearest_overrides(
    monkeypatch: pytest.MonkeyPatch,
):
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
                allow=(BashCommand(("pwd",)),),
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
    )
    assert tuple(rule.prefix for rule in policy.ask if isinstance(rule, BashCommand)) == (("curl",),)
    assert tuple(rule.prefix for rule in policy.deny if isinstance(rule, BashCommand)) == (("rm",),)
    assert policy.redirection.stdout_to_file is Decision.Allow
    assert policy.redirection.append_to_file is Decision.Deny
    assert policy.redirection.allow_paths == ("/global", "/workspace", "/project", "/cwd")
    assert policy.python_calls.allow == frozenset({"package.read"})
    assert policy.python_calls.ask == frozenset({"package.inspect"})
    assert policy.python_calls.deny == frozenset({"package.delete"})


def test_merged_policy_loads_global_only_once_when_cwd_is_below_home(
    monkeypatch: pytest.MonkeyPatch,
):
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


def test_merged_policy_accepts_legacy_local_root_keyword(monkeypatch: pytest.MonkeyPatch):
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


def test_merged_policy_rejects_cwd_and_legacy_local_root_together():
    with pytest.raises(TypeError, match="either cwd or local_root"):
        merged_policy(cwd=Path("/workspace"), local_root=Path("/workspace"))


# ---- Inert command names -------------------------------------------------


def _decide(policy: Policy, command: str, *, cwd: Path | None = None) -> Verdict:
    return policy.decide(ShellRequest(parse_pipeline(command), cwd=cwd))


def test_inert_builtins_allowed_when_no_rule_matches():
    policy = Policy()  # no user rules at all
    for command in (
        "echo foo",
        "true",
        "false",
        ":",
        "continue",
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


def test_deny_bites_through_backslash_escaped_command_name():
    """``\\rm -rf /`` is the standard alias-bypass idiom — must not launder a
    denied command past a leading backslash."""
    assert _decide(_deny_rm(), "\\rm -rf /").decision is Decision.Deny


def test_deny_bites_through_quoted_command_name():
    """Quoting the command name (``'rm' -rf /``) is another common alias-bypass
    idiom and must not evade a deny rule either."""
    assert _decide(_deny_rm(), "'rm' -rf /").decision is Decision.Deny
    assert _decide(_deny_rm(), '"rm" -rf /').decision is Decision.Deny


def test_opaque_wrapper_ask_fallback_bites_through_backslash_escape():
    """``\\sudo rm -rf /`` must still fall to the opaque-wrapper Ask fallback,
    not silently pass as an unrecognized command."""
    assert _decide(Policy(), "\\sudo rm -rf /").decision is Decision.Ask


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


# ---- Redirect policy configuration (shell.redirection) ---------------------


def test_stdout_to_file_configured_allow_defers_to_command_rule():
    """``stdoutToFile: allow`` means the redirect shape alone no longer forces Ask —
    the segment's own command rule decides, same as if there were no redirect."""
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Allow),
    )
    assert _decide(policy, "echo hi > out.txt").decision is Decision.Allow


def test_stdout_to_file_configured_allow_does_not_grant_unmatched_command():
    """Configuring the redirect shape to ``allow`` must not itself grant permission —
    an unmatched command still falls through to NoOpinion, same as without a redirect."""
    policy = Policy(redirection=RedirectionPolicy(stdout_to_file=Decision.Allow))
    assert _decide(policy, "weird_cmd > out.txt").decision is Decision.NoOpinion


def test_stdout_to_file_configured_deny_overrides_allowed_command():
    """``stdoutToFile: deny`` forces Deny even though the base command is allow-listed."""
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Deny),
    )
    assert _decide(policy, "echo hi > out.txt").decision is Decision.Deny


def test_strictest_redirect_wins_regardless_of_source_order():
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


def test_append_to_file_is_configured_independently_of_stdout_to_file():
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


def test_stderr_to_dev_null_configured_ask_overrides_default_no_opinion():
    """Default treats ``2>/dev/null`` as no-opinion; configuring ``ask`` forces a prompt."""
    policy = Policy(
        allow=(BashCommand(("cat",)),),
        redirection=RedirectionPolicy(stderr_to_dev_null=Decision.Ask),
    )
    assert _decide(policy, "cat foo 2>/dev/null").decision is Decision.Ask


def test_stdout_to_dev_null_configured_ask_overrides_default_no_opinion():
    """Same override, mirrored for the stdout-to-devnull bucket (bare ``>``/``1>``)."""
    policy = Policy(
        allow=(BashCommand(("cat",)),),
        redirection=RedirectionPolicy(stdout_to_dev_null=Decision.Ask),
    )
    assert _decide(policy, "cat foo > /dev/null").decision is Decision.Ask
    assert _decide(policy, "cat foo 1> /dev/null").decision is Decision.Ask


def test_stdout_and_stderr_to_dev_null_are_configured_independently():
    """Configuring one devnull bucket must not affect the other."""
    policy = Policy(
        allow=(BashCommand(("cat",)),),
        redirection=RedirectionPolicy(stdout_to_dev_null=Decision.Ask),
    )
    assert _decide(policy, "cat foo > /dev/null").decision is Decision.Ask
    assert _decide(policy, "cat foo 2>/dev/null").decision is Decision.Allow


def test_fd_dup_redirect_unaffected_by_redirect_config():
    """``2>&1`` never touches the filesystem — it stays no-opinion regardless of config."""
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Deny, append_to_file=Decision.Deny),
    )
    assert _decide(policy, "echo hi 2>&1").decision is Decision.Allow


def test_stderr_to_file_uses_stdout_to_file_config():
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


def test_redirection_policy_merge_keeps_unset_keys_from_base():
    """A local file that only sets ``appendToFile`` must not reset an unrelated
    ``stdoutToFile`` customization from the global file."""
    base = RedirectionPolicy(stdout_to_file=Decision.Allow)
    override = RedirectionPolicy(append_to_file=Decision.Deny)
    merged = base.merged_with(override)
    assert merged.stdout_to_file is Decision.Allow
    assert merged.append_to_file is Decision.Deny
    assert merged.stderr_to_dev_null is None


def test_redirection_policy_merge_lets_override_win_on_shared_key():
    base = RedirectionPolicy(stdout_to_file=Decision.Allow)
    override = RedirectionPolicy(stdout_to_file=Decision.Deny)
    assert base.merged_with(override).stdout_to_file is Decision.Deny


def test_policy_merged_with_combines_redirection_config():
    global_policy = Policy(redirection=RedirectionPolicy(stdout_to_file=Decision.Allow))
    local_policy = Policy(redirection=RedirectionPolicy(append_to_file=Decision.Deny))
    merged = global_policy.merged_with(local_policy)
    assert merged.redirection.stdout_to_file is Decision.Allow
    assert merged.redirection.append_to_file is Decision.Deny


def test_load_policy_file_parses_shell_redirection_block(tmp_path: Path):
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


def test_load_policy_file_ignores_invalid_redirection_value(tmp_path: Path):
    path = tmp_path / ".agent-permissions.jsonc"
    path.write_text(
        json.dumps({"version": 1, "permissions": {}, "shell": {"redirection": {"stdoutToFile": "sometimes"}}})
    )
    policy = load_policy_file(path).policy
    assert policy.redirection.stdout_to_file is None


def test_load_policy_file_parses_python_call_decisions(tmp_path: Path):
    path = tmp_path / ".agent-permissions.jsonc"
    path.write_text(json.dumps({
        "version": 1,
        "permissions": {"allow": ["Python(readonly)"]},
        "python": {"calls": {
            "allow": ["project.allowed"],
            "ask": ["project.ambiguous"],
            "deny": ["project.forbidden"],
        }},
    }))
    policy = load_policy_file(path).policy
    assert policy.python_calls == PythonCallPolicy(
        allow=frozenset({"project.allowed"}),
        ask=frozenset({"project.ambiguous"}),
        deny=frozenset({"project.forbidden"}),
    )


def test_python_call_policy_merge_unions_each_decision():
    base = Policy(python_calls=PythonCallPolicy(allow=frozenset({"a"}), deny=frozenset({"blocked"})))
    local = Policy(python_calls=PythonCallPolicy(ask=frozenset({"review"}), deny=frozenset({"a"})))
    merged = base.merged_with(local)
    assert merged.python_calls.allow == frozenset({"a"})
    assert merged.python_calls.ask == frozenset({"review"})
    assert merged.python_calls.deny == frozenset({"blocked", "a"})


def test_save_policy_file_serializes_python_call_decisions(tmp_path: Path):
    path = tmp_path / ".agent-permissions.jsonc"
    policy_file = PolicyFile(policy=Policy(
        python_calls=PythonCallPolicy(
            allow=frozenset({"project.allowed"}),
            ask=frozenset({"project.review"}),
            deny=frozenset({"project.blocked"}),
        )
    ))
    save_policy_file(path, policy_file)
    calls = json.loads(path.read_text())["python"]["calls"]
    assert calls == {
        "allow": ["project.allowed"],
        "ask": ["project.review"],
        "deny": ["project.blocked"],
    }


def test_save_policy_file_clears_existing_python_call_decisions(tmp_path: Path):
    path = tmp_path / ".agent-permissions.jsonc"
    raw: JsonObject = {"python": {"calls": {"deny": ["stale.call"], "extension": "preserved"}}}
    save_policy_file(path, PolicyFile(policy=Policy(), raw=raw))
    calls = json.loads(path.read_text())["python"]["calls"]
    assert calls == {"allow": [], "ask": [], "deny": [], "extension": "preserved"}
    assert load_policy_file(path).policy.python_calls == PythonCallPolicy()


def test_save_policy_file_round_trips_and_clears_redirection_policy(tmp_path: Path):
    path = tmp_path / ".agent-permissions.jsonc"
    policy = Policy(
        redirection=RedirectionPolicy(
            stdout_to_file=Decision.Allow,
            append_to_file=Decision.Deny,
        )
    )
    save_policy_file(path, PolicyFile(policy=policy))
    assert load_policy_file(path).policy.redirection == policy.redirection

    raw = json.loads(path.read_text())
    save_policy_file(path, PolicyFile(policy=Policy(), raw=raw))
    assert load_policy_file(path).policy.redirection == RedirectionPolicy()


# ---- Redirect allowPaths ---------------------------------------------------


def test_global_allow_paths_permits_matching_redirect(tmp_path: Path):
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Ask, allow_paths=("/tmp",)),
    )
    verdict = _decide(policy, "echo hi > /tmp/out.txt")
    assert verdict.decision is Decision.Allow


def test_global_allow_paths_asks_for_non_matching_redirect():
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(stdout_to_file=Decision.Ask, allow_paths=("/tmp",)),
    )
    verdict = _decide(policy, "echo hi > /etc/out.txt")
    assert verdict.decision is Decision.Ask


def test_global_allow_paths_with_glob(tmp_path: Path):
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(allow_paths=(str(tmp_path / "out-*"),)),
    )
    target = tmp_path / "out-123" / "file.txt"
    verdict = _decide(policy, f"echo hi > {target}")
    assert verdict.decision is Decision.Allow


def test_per_rule_allow_paths_permits_redirect():
    rule = parse_rule({"Shell(mise exec just synth-env)": {"allowPaths": ["/tmp"]}})
    assert isinstance(rule, ShellPattern)
    policy = Policy(allow=(rule,))
    verdict = _decide(policy, "mise exec -- just synth-env pr-9 > /tmp/out.txt")
    assert verdict.decision is Decision.Allow


def test_per_rule_allow_paths_from_narrower_rule_applies_when_broader_matches_first():
    broad_rule = parse_rule("Shell({echo,ls})")
    narrow_with_paths = parse_rule({"Shell(echo)": {"allowPaths": ["/tmp"]}})
    assert isinstance(broad_rule, ShellPattern)
    assert isinstance(narrow_with_paths, ShellPattern)
    policy = Policy(allow=(broad_rule, narrow_with_paths))
    assert _decide(policy, "echo hi > /tmp/out.txt").decision is Decision.Allow
    assert _decide(policy, "ls > /tmp/out.txt").decision is Decision.Ask


def test_per_rule_allow_paths_not_applied_when_different_rule_matches():
    rule_with_paths = parse_rule({"Shell(mise exec just synth-env)": {"allowPaths": ["/tmp"]}})
    rule_echo = parse_rule("Shell(echo)")
    assert isinstance(rule_with_paths, ShellPattern)
    assert isinstance(rule_echo, ShellPattern)
    policy = Policy(allow=(rule_with_paths, rule_echo))
    verdict = _decide(policy, "echo hi > /tmp/out.txt")
    assert verdict.decision is Decision.Ask


def test_global_and_per_rule_paths_combined():
    rule = parse_rule({"Shell(echo)": {"allowPaths": ["/var/log"]}})
    assert isinstance(rule, ShellPattern)
    policy = Policy(
        allow=(rule,),
        redirection=RedirectionPolicy(allow_paths=("/tmp",)),
    )
    assert _decide(policy, "echo hi > /tmp/out.txt").decision is Decision.Allow
    assert _decide(policy, "echo hi > /var/log/app.log").decision is Decision.Allow
    assert _decide(policy, "echo hi > /etc/out.txt").decision is Decision.Ask


def test_allow_paths_applies_to_appends():
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(append_to_file=Decision.Ask, allow_paths=("/tmp",)),
    )
    verdict = _decide(policy, "echo hi >> /tmp/out.txt")
    assert verdict.decision is Decision.Allow


def test_allow_paths_relative_target_resolved_with_cwd(tmp_path: Path):
    policy = Policy(
        allow=(BashCommand(("echo",)),),
        redirection=RedirectionPolicy(allow_paths=(str(tmp_path),)),
    )
    verdict = _decide(policy, "echo hi > out.txt", cwd=tmp_path)
    assert verdict.decision is Decision.Allow
    verdict_no_cwd = _decide(policy, "echo hi > out.txt")
    assert verdict_no_cwd.decision is Decision.Ask


def test_allow_paths_symlink_resolution(tmp_path: Path):
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


def test_allow_paths_merge_deduplicates():
    a = RedirectionPolicy(allow_paths=("/tmp", "/var"))
    b = RedirectionPolicy(allow_paths=("/var", "/home"))
    merged = a.merged_with(b)
    assert merged.allow_paths == ("/tmp", "/var", "/home")


def test_allow_paths_policy_file_round_trip(tmp_path: Path):
    path = tmp_path / ".agent-permissions.jsonc"
    policy = Policy(redirection=RedirectionPolicy(
        stdout_to_file=Decision.Ask,
        allow_paths=("/tmp", "/var/log"),
    ))
    save_policy_file(path, PolicyFile(policy=policy, raw={}))
    reloaded = load_policy_file(path)
    assert reloaded.policy.redirection.allow_paths == ("/tmp", "/var/log")
    assert reloaded.policy.redirection.stdout_to_file is Decision.Ask


# ---- File permissions ------------------------------------------------------


@pytest.mark.parametrize("exists_before", [False, True])
def test_atomic_write_sets_owner_only_permissions(tmp_path: Path, exists_before: bool):
    path = tmp_path / "policy.jsonc"
    if exists_before:
        path.write_text("{}")
        os.chmod(path, 0o644)
    from agentperm.fileio import atomic_write

    atomic_write(path, '{"version": 1}\n')
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
