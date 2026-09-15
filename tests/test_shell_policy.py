"""Policy decision tests — strictness, aggregation, rule matching, bypass coercion."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentperm import (
    BashCommand,
    Decision,
    Policy,
    load_template,
    parse_policy_text,
)
from tests.policy_support import decide as _decide


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("launchctl list", Decision.Allow),
        ("launchctl list com.example.service", Decision.NoOpinion),
        ("launchctl list --json", Decision.NoOpinion),
        ("launchctl bootstrap gui/501 service.plist", Decision.NoOpinion),
        ("launchctl bootout gui/501/com.example.service", Decision.NoOpinion),
        ("launchctl kickstart gui/501/com.example.service", Decision.NoOpinion),
    ],
)
def test_launchctl_policy_allows_only_exact_inventory(
    command: str, expected: Decision, tmp_path: Path
) -> None:
    policy = load_template("file-inspection").file.policy
    assert _decide(policy, command, cwd=tmp_path).decision is expected


def test_read_only_policy_allows_launch_agent_diagnostic(tmp_path: Path) -> None:
    policy = parse_policy_text(
        """{
          "version": 1,
          "permissions": {
            "allow": [
              "Shell(launchctl list !... !-*)",
              "Shell(plutil -p !-*)",
              "Shell({find,rg,echo,true})"
            ]
          },
          "shell": {"redirection": {"stderrToDevNull": "allow"}}
        }""",
        "test",
    ).policy
    command = (
        "find /Users/jackson/Library/LaunchAgents /Library/LaunchAgents "
        "-maxdepth 1 -type f -print 2>/dev/null | while IFS= read -r f; do "
        "if rg -q 'mcphub|samanhappy' \"$f\"; then echo \"$f\"; "
        'plutil -p "$f"; fi; done\n'
        "launchctl list | rg -i 'mcphub|mcp' || true"
    )
    assert _decide(policy, command, cwd=tmp_path).decision is Decision.Allow

# ---- Inert command names -------------------------------------------------


def test_inert_builtins_allowed_when_no_rule_matches() -> None:
    policy = Policy()  # no user rules at all
    for command in (
        "echo foo",
        "true",
        "false",
        ":",
        "break",
        "continue",
        "export FOO=bar",
        "read line",
        "unset FOO",
        'printf "%s" hi',
        "[ -f x ]",
        "[[ -f x ]]",
        "(( 1 + 1 ))",
    ):
        assert _decide(policy, command).decision is Decision.Allow, command


def test_break_in_loop_does_not_require_a_user_rule() -> None:
    policy = Policy(allow=(BashCommand(("echo",)),))
    command = "for item in a b; do echo $item; if true; then break; fi; done"

    assert _decide(policy, command).decision is Decision.Allow


def test_export_mode_toggles_are_intrinsic_but_other_set_forms_are_not() -> None:
    policy = Policy()

    assert _decide(policy, "set -a").decision is Decision.Allow
    assert _decide(policy, "set +a").decision is Decision.Allow
    assert _decide(policy, "set -- one two").decision is Decision.Allow
    assert _decide(policy, 'set -- "$spec"').decision is Decision.Allow
    assert _decide(policy, "set").decision is Decision.NoOpinion
    assert _decide(policy, "set -x").decision is Decision.NoOpinion


def test_positional_parameter_assignment_does_not_escalate_read_only_loop() -> None:
    policy = Policy(allow=(BashCommand(("aws", "cloudwatch", "get-metric-statistics")),))
    command = "for spec in 'SNAP query operation'; do set -- $spec; aws cloudwatch get-metric-statistics; done"

    assert _decide(policy, command).decision is Decision.Allow


def test_user_deny_overrides_inert_builtin() -> None:
    """An explicit ``deny: ['Bash(echo:*)']`` must bite — inert allow is only a fallback."""
    policy = Policy(deny=(BashCommand(("echo",)),))
    assert _decide(policy, "echo foo").decision is Decision.Deny


def test_user_ask_overrides_inert_builtin() -> None:
    """An explicit ``ask`` rule on an inert builtin takes precedence over the inert fallback."""
    policy = Policy(ask=(BashCommand(("printf",)),))
    assert _decide(policy, 'printf "%s" hi').decision is Decision.Ask


@pytest.mark.parametrize("command", ("export FOO=bar", "unset FOO"))
def test_user_deny_overrides_inert_variable_builtin(command: str) -> None:
    policy = Policy(deny=(BashCommand((command.split()[0],)),))
    assert _decide(policy, command).decision is Decision.Deny


def test_echo_with_redirect_still_asks() -> None:
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


def test_deny_bites_through_redirected_shell_wrapper() -> None:
    """``zsh -lc "rm -rf /" 2>/dev/null`` must not launder a denied command past the
    wrapper-plus-redirect path."""
    assert _decide(_deny_rm(), 'zsh -lc "rm -rf /" 2>/dev/null').decision is Decision.Deny


def test_deny_bites_through_process_substitution_redirect() -> None:
    """``cat < <(rm -rf /)`` surfaces the inner command for a deny rule."""
    assert _decide(_deny_rm(), "cat < <(rm -rf /)").decision is Decision.Deny


def test_deny_bites_through_backslash_escaped_command_name() -> None:
    """``\\rm -rf /`` is the standard alias-bypass idiom — must not launder a
    denied command past a leading backslash."""
    assert _decide(_deny_rm(), "\\rm -rf /").decision is Decision.Deny


def test_deny_bites_through_quoted_command_name() -> None:
    """Quoting the command name (``'rm' -rf /``) is another common alias-bypass
    idiom and must not evade a deny rule either."""
    assert _decide(_deny_rm(), "'rm' -rf /").decision is Decision.Deny
    assert _decide(_deny_rm(), '"rm" -rf /').decision is Decision.Deny


def test_opaque_wrapper_ask_fallback_bites_through_backslash_escape() -> None:
    """``\\sudo rm -rf /`` must still fall to the opaque-wrapper Ask fallback,
    not silently pass as an unrecognized command."""
    assert _decide(Policy(), "\\sudo rm -rf /").decision is Decision.Ask


def test_deny_bites_through_write_process_substitution() -> None:
    """``tee > >(rm -rf /)`` — write to a process substitution still extracts and denies."""
    policy = Policy(deny=(BashCommand(("rm", "-rf")),), allow=(BashCommand(("tee",)),))
    assert _decide(policy, "tee > >(rm -rf /)").decision is Decision.Deny


def test_command_substitution_write_target_asks() -> None:
    """``cmd > $(echo f)`` writes to a runtime-computed filename — unknowable, so the
    write must still ask even though ``cmd`` is allowed (not silently dropped)."""
    policy = Policy(allow=(BashCommand(("cmd",)),))
    verdict = _decide(policy, "cmd > $(echo /etc/passwd)")
    assert verdict.decision is Decision.Ask
    assert "writes to" in verdict.rationale


def test_deny_bites_through_substitution_nested_in_redirect_target() -> None:
    """``echo hi > out$(rm -rf /)`` — a denied command nested in a redirect target word."""
    assert _decide(_deny_rm(), "echo hi > out$(rm -rf /)").decision is Decision.Deny


def test_exact_deny_rule_bites_unwrapped_shell_c_with_spillover() -> None:
    """An exact (non-glob) deny rule must match the unwrapped inner command even
    when the wrapper carries trailing positional params after the redirect."""
    policy = Policy(deny=(BashCommand(("rm", "-rf", "/")),))
    assert _decide(policy, 'zsh -lc "rm -rf /" 2>/dev/null harmless').decision is Decision.Deny


def test_user_rule_cannot_target_synthetic_predicate_marker() -> None:
    """``[`` / ``[[`` / ``((`` are parser artifacts, not real commands. A user rule
    on ``[`` must not block test predicates, and they stay allowed."""
    policy = Policy(deny=(BashCommand(("[",)),))
    assert _decide(policy, "[ -f x ]").decision is Decision.Allow
    assert _decide(policy, "[[ -f x ]]").decision is Decision.Allow


def test_deny_bites_case_subject_substitution() -> None:
    """``case $(rm -rf /) in …`` — the subject substitution runs; its inner command is policed."""
    assert _decide(_deny_rm(), "case $(rm -rf /) in *) echo ok;; esac").decision is Decision.Deny


def test_deny_bites_exotic_redirect_operators() -> None:
    """`>|`, `&>>`, `<&` redirect operators with a substitution target surface the inner command."""
    assert _decide(_deny_rm(), "cmd >| out$(rm -rf /)").decision is Decision.Deny
    assert _decide(_deny_rm(), "cmd &>> out$(rm -rf /)").decision is Decision.Deny
    assert _decide(_deny_rm(), "cmd <& $(rm -rf /)").decision is Decision.Deny


def test_deny_bites_herestring_substitution() -> None:
    """``cat <<< $(rm -rf /)`` — herestring body substitution runs and must be policed."""
    assert _decide(_deny_rm(), "cat <<< $(rm -rf /)").decision is Decision.Deny


def test_deny_bites_split_shell_c() -> None:
    """``bash -l -c "rm -rf /"`` — split no-arg flags before -c are unwrapped and policed."""
    assert _decide(_deny_rm(), 'bash -l -c "rm -rf /"').decision is Decision.Deny


def test_unanalyzable_shell_c_wrapper_asks() -> None:
    """A shell ``-c`` wrapper we can't safely unwrap (`bash --norc -c "…"`) hides its
    command, so in normal mode it asks rather than silently passing."""
    assert _decide(Policy(), 'bash --norc -c "rm -rf /"').decision is Decision.Ask


def test_plain_shell_script_invocation_stays_no_opinion() -> None:
    """``bash script.sh`` carries no ``-c`` command flag — an ordinary opaque command,
    not an unanalyzable wrapper, so it stays NoOpinion (no false prompt)."""
    assert _decide(Policy(), "bash deploy.sh --flag").decision is Decision.NoOpinion


def test_deny_bites_through_exec_prefix_wrappers() -> None:
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


def test_opaque_exec_wrapper_asks() -> None:
    """``timeout``/``sudo``/``nice -n`` aren't decomposable; absent a rule they ask in
    normal mode rather than silently passing the hidden command."""
    for command in ("timeout 5 rm -rf /", "sudo rm -rf /", "nice -n 10 rm -rf /"):
        assert _decide(_deny_rm(), command).decision is Decision.Ask, command


def test_explicit_rule_allow_lists_opaque_wrapper() -> None:
    """An explicit rule on an opaque wrapper still wins over the ask fallback."""
    policy = Policy(allow=(BashCommand(("timeout",)),))
    assert _decide(policy, "timeout 5 make").decision is Decision.Allow


def test_eval_decomposes_literal_command() -> None:
    """``eval "rm -rf /"`` joins and re-parses its args, so a deny rule bites."""
    assert _decide(_deny_rm(), 'eval "rm -rf /"').decision is Decision.Deny
    assert _decide(_deny_rm(), "eval rm -rf /").decision is Decision.Deny


def test_command_v_lookup_is_not_executed() -> None:
    """``command -v rm`` / ``command -V rm`` resolve the name without running it, so a
    deny rule on the inner command must not fire."""
    policy = Policy(deny=(BashCommand(("rm",)),))
    assert _decide(policy, "command -v rm").decision is Decision.Allow
    assert _decide(policy, "command -V rm").decision is Decision.Allow
    # the executing form is still decomposed and denied
    assert _decide(policy, "command rm -rf /").decision is Decision.Deny


def test_dynamic_command_name_asks() -> None:
    """A command whose name is a runtime expansion (`eval "$cmd"`, `$TOOL …`) is
    unknowable, so in normal mode it asks rather than silently passing."""
    for command in ('eval "$UNKNOWN"', 'bash -c "$CMD"', "$TOOL --flag", "${RUNNER} test"):
        assert _decide(Policy(), command).decision is Decision.Ask, command


def test_inert_pipe_to_unknown_escalates_to_ask() -> None:
    """``echo foo | weird_cmd`` — echo is allowed, weird_cmd has no rule → Ask."""
    policy = Policy()
    verdict = _decide(policy, "echo foo | weird_cmd")
    assert verdict.decision is Decision.Ask


def test_if_with_allowed_body_is_allow() -> None:
    policy = Policy(allow=(BashCommand(("cat",)),))
    assert _decide(policy, "if [ -f x ]; then cat x; fi").decision is Decision.Allow


def test_if_with_unknown_body_asks() -> None:
    policy = Policy()
    assert _decide(policy, "if [ -f x ]; then weird_cmd; fi").decision is Decision.Ask


def test_if_with_denied_body_is_deny() -> None:
    """Function/control-flow bodies are subject to deny rules."""
    policy = Policy(deny=(BashCommand(("rm", "-rf")),))
    assert _decide(policy, "if true; then rm -rf /; fi").decision is Decision.Deny


def test_function_body_subjected_to_policy() -> None:
    """Defining-then-calling is the realistic threat — the body must be evaluated."""
    policy = Policy(deny=(BashCommand(("rm", "-rf")),))
    assert _decide(policy, "foo() { rm -rf /; }; foo").decision is Decision.Deny


def test_export_matches_user_allow() -> None:
    """``Bash(export:*)`` allow rule must match an ``export FOO=bar`` declaration."""
    policy = Policy(allow=(BashCommand(("export",)),))
    assert _decide(policy, "export FOO=bar").decision is Decision.Allow


def test_export_with_substitution_asks_when_inner_unrecognized() -> None:
    """``export FOO=$(curl evil)`` — export is allowed but ``curl`` isn't, so Ask."""
    policy = Policy(allow=(BashCommand(("export",)),))
    assert _decide(policy, "export FOO=$(curl evil)").decision is Decision.Ask


def test_export_with_substitution_allows_when_inner_allowed() -> None:
    """``export FOO=$(date)`` — both export and date are allowed, so Allow."""
    policy = Policy(allow=(BashCommand(("export",)), BashCommand(("date",))))
    assert _decide(policy, "export FOO=$(date)").decision is Decision.Allow


def test_user_request_original_failing_case() -> None:
    """Regression for the exact command that motivated this work."""
    policy = Policy(allow=(BashCommand(("sed",)),))
    cmd = "if [ -f .env.development ]; then sed -n '1,220p' .env.development; fi"
    assert _decide(policy, cmd).decision is Decision.Allow
