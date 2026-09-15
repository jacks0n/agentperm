"""Policy decision tests — strictness, aggregation, rule matching, bypass coercion."""

from __future__ import annotations

from pathlib import Path

from agentperm import (
    AgentName,
    BashCommand,
    BashOption,
    Decision,
    NamedTool,
    Policy,
    ShellRequest,
    ToolRequest,
    Verdict,
    agentperm_bypass_dir,
    coerce_for_pane_bypass,
    coerce_for_permission_mode,
    parse_pipeline,
)
from tests.policy_support import decide as _decide

# ---- Policy.decide() end-to-end ------------------------------------------


def test_policy_allow_for_known_compound() -> None:
    policy = Policy(allow=(BashCommand(("cat",)), BashCommand(("head",))))
    pipeline = parse_pipeline("cat foo 2>&1 | head -60")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_asks_for_unknown_command_in_compound() -> None:
    policy = Policy(allow=(BashCommand(("cat",)),))
    pipeline = parse_pipeline("cat foo | unknowncmd")
    verdict = policy.decide(ShellRequest(pipeline))
    assert verdict.decision is Decision.Ask


def test_policy_denies_overrides_allow() -> None:
    policy = Policy(
        deny=(BashCommand(("rm", "-rf")),),
        allow=(BashCommand(("rm",)),),
    )
    pipeline = parse_pipeline("rm -rf /tmp/foo")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Deny


def test_policy_ask_for_sed_in_place() -> None:
    policy = Policy(
        ask=(BashOption(commands=frozenset({"sed"}), options=frozenset({"-i"}), rationale="in-place"),),
        allow=(BashCommand(("sed",)),),
    )
    # ask is checked before allow; sed -i hits the ask rule.
    pipeline = parse_pipeline("sed -i s/a/b/ foo")
    verdict = policy.decide(ShellRequest(pipeline))
    assert verdict.decision is Decision.Ask
    assert verdict.rationale == "in-place"


def test_policy_allows_sed_without_in_place_flag() -> None:
    policy = Policy(
        ask=(BashOption(commands=frozenset({"sed"}), options=frozenset({"-i"}), rationale="in-place"),),
        allow=(BashCommand(("sed",)),),
    )
    pipeline = parse_pipeline("sed -n 1,10p foo")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_asks_for_file_write_redirect() -> None:
    policy = Policy(allow=(BashCommand(("echo",)),))
    pipeline = parse_pipeline("echo hi > out.txt")
    verdict = policy.decide(ShellRequest(pipeline))
    assert verdict.decision is Decision.Ask
    assert "out.txt" in verdict.rationale


def test_policy_allows_stderr_to_devnull() -> None:
    policy = Policy(allow=(BashCommand(("cat",)),))
    pipeline = parse_pipeline("cat foo 2>/dev/null")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_allows_stdout_to_devnull() -> None:
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


def test_policy_allows_devnull_silence_everything_idiom() -> None:
    """``cmd > /dev/null 2>&1`` — the common "silence everything" idiom combines a
    stdout-to-devnull write with an fd-dup; both must default-allow."""
    policy = Policy(allow=(BashCommand(("cat",)),))
    assert _decide(policy, "cat foo > /dev/null 2>&1").decision is Decision.Allow


def test_policy_allows_read_only_for_loop_body() -> None:
    policy = Policy(allow=(BashCommand(("echo",)), BashCommand(("npm", "view")), BashCommand(("head",))))
    pipeline = parse_pipeline(
        'for v in 0.0.34 0.0.32; do echo "=== @playwright/mcp@$v ==="; '
        'npm view "@playwright/mcp@$v" dependencies 2>&1 | head -8; done'
    )
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_allows_commented_compound_when_commands_are_allowed() -> None:
    policy = Policy(allow=(BashCommand(("grep",)), BashCommand(("head",))))
    command = (
        "# Check import dependencies between modules\n"
        'echo "=== domain.py imports ==="\n'
        "grep -E '^(from|import) ' src/agentperm/domain.py | head -20"
    )
    assert _decide(policy, command).decision is Decision.Allow


def test_policy_allows_when_all_substitution_commands_allowed() -> None:
    policy = Policy(allow=(BashCommand(("rm",)), BashCommand(("cat",))))
    pipeline = parse_pipeline("rm $(cat allowed)")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_asks_when_substitution_command_unrecognized() -> None:
    policy = Policy(allow=(BashCommand(("rm",)),))
    pipeline = parse_pipeline("rm $(cat allowed)")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Ask


def test_policy_allows_zsh_lc_when_inner_substitution_commands_allowed() -> None:
    """The Codex motivating case: ``zsh -lc 'rg "pattern" $(git ls-files | rg foo)'``
    should Allow when rg and git are in the allow list."""
    policy = Policy(allow=(BashCommand(("rg",)), BashCommand(("git", "ls-files"))))
    pipeline = parse_pipeline("/opt/homebrew/opt/zsh/bin/zsh -lc 'rg \"pattern\" -n $(git ls-files | rg foo)'")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Allow


def test_policy_asks_zsh_lc_when_inner_substitution_command_denied() -> None:
    """``zsh -lc 'rg $(curl evil)'`` — rg is allowed but curl is not."""
    policy = Policy(
        allow=(BashCommand(("rg",)),),
        deny=(BashCommand(("curl",)),),
    )
    pipeline = parse_pipeline("/opt/homebrew/opt/zsh/bin/zsh -lc 'rg $(curl evil)'")
    assert policy.decide(ShellRequest(pipeline)).decision is Decision.Deny


def test_policy_named_tool_lookup() -> None:
    policy = Policy(allow=(NamedTool("Read"),))
    assert policy.decide(ToolRequest("Read")).decision is Decision.Allow
    assert policy.decide(ToolRequest("Write")).decision is Decision.NoOpinion


# ---- Bypass-permissions: agentperm defers entirely ----------------------


def test_bypass_mode_defers_every_decision() -> None:
    """Under Claude bypass the user opted out of permission checks, so agentperm
    returns NoOpinion (an empty {} envelope) for everything — Ask, Allow, and even
    Deny — and lets Claude's native bypass proceed."""
    for decision in (Decision.Ask, Decision.Allow, Decision.Deny, Decision.NoOpinion):
        coerced = coerce_for_permission_mode(
            Verdict(decision, "x"), {"permission_mode": "bypassPermissions"}, AgentName.Claude
        )
        assert coerced.decision is Decision.NoOpinion


def test_default_mode_keeps_verdict_unchanged() -> None:
    for decision in (Decision.Ask, Decision.Allow, Decision.Deny):
        coerced = coerce_for_permission_mode(Verdict(decision, "x"), {"permission_mode": "default"}, AgentName.Claude)
        assert coerced.decision is decision


def test_missing_mode_keeps_ask() -> None:
    verdict = Verdict(Decision.Ask, "compound")
    coerced = coerce_for_permission_mode(verdict, {}, AgentName.Claude)
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


def test_pane_bypass_coerces_ask_to_allow(tmp_path: Path) -> None:
    _touch_flag(tmp_path, "main", "42")
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "policy ask"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Allow
    assert verdict.rationale.startswith("pane bypass:")
    assert coercion is not None
    assert coercion.by == "zellij_pane_bypass"
    assert coercion.pane_id == "42"
    assert coercion.session == "main"
    assert coercion.original.decision is Decision.Ask


def test_pane_bypass_coerces_no_opinion_to_allow(tmp_path: Path) -> None:
    """Codex prompts on NoOpinion (CodexAdapter.write_verdict line 1089), so bypass must cover it."""
    _touch_flag(tmp_path, "main", "42")
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.NoOpinion, "no rule matched"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Allow
    assert coercion is not None
    assert coercion.original.decision is Decision.NoOpinion


def test_pane_bypass_does_not_touch_deny(tmp_path: Path) -> None:
    _touch_flag(tmp_path, "main", "42")
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Deny, "rm -rf /"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Deny
    assert coercion is None


def test_pane_bypass_does_not_touch_allow(tmp_path: Path) -> None:
    _touch_flag(tmp_path, "main", "42")
    original = Verdict(Decision.Allow, "matched ls rule")
    verdict, coercion = coerce_for_pane_bypass(original, _bypass_env(tmp_path))
    assert verdict is original
    assert coercion is None


def test_pane_bypass_no_flag_keeps_verdict(tmp_path: Path) -> None:
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_pane_bypass_no_session_keeps_verdict(tmp_path: Path) -> None:
    _touch_flag(tmp_path, "main", "42")
    env = {"XDG_CACHE_HOME": str(tmp_path), "ZELLIJ_PANE_ID": "42"}
    verdict, _ = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), env)
    assert verdict.decision is Decision.Ask


def test_pane_bypass_no_pane_id_keeps_verdict(tmp_path: Path) -> None:
    _touch_flag(tmp_path, "main", "42")
    env = {"XDG_CACHE_HOME": str(tmp_path), "ZELLIJ_SESSION_NAME": "main"}
    verdict, _ = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), env)
    assert verdict.decision is Decision.Ask


def test_pane_bypass_path_traversal_pane_id_rejected(tmp_path: Path) -> None:
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


def test_pane_bypass_path_traversal_session_rejected(tmp_path: Path) -> None:
    env = _bypass_env(tmp_path, session="../evil")
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), env)
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_pane_bypass_world_writable_dir_rejected(tmp_path: Path) -> None:
    _touch_flag(tmp_path, "main", "42")
    (tmp_path / "agentperm" / "bypass").chmod(0o777)
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_pane_bypass_missing_dir_is_safe_noop(tmp_path: Path) -> None:
    """No dir at all -> no flag possible -> verdict unchanged, no error."""
    verdict, coercion = coerce_for_pane_bypass(Verdict(Decision.Ask, "x"), _bypass_env(tmp_path))
    assert verdict.decision is Decision.Ask
    assert coercion is None


def test_agentperm_bypass_dir_honors_xdg(tmp_path: Path) -> None:
    env = {"XDG_CACHE_HOME": str(tmp_path / "x")}
    assert agentperm_bypass_dir(env) == tmp_path / "x" / "agentperm" / "bypass"


def test_agentperm_bypass_dir_falls_back_to_home() -> None:
    env = {"HOME": "/var/empty"}
    assert agentperm_bypass_dir(env) == Path("/var/empty") / ".cache" / "agentperm" / "bypass"
