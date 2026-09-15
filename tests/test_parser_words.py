"""Shell parser tests — the cases that broke the hand-rolled regex parser."""

from __future__ import annotations

from agentperm import parse_pipeline


def test_empty_command_is_parseable() -> None:
    pipeline = parse_pipeline("")
    assert pipeline.parseable
    assert pipeline.segments == ()


def test_single_command_argv() -> None:
    pipeline = parse_pipeline("ls -la /tmp")
    assert pipeline.parseable
    assert len(pipeline.segments) == 1
    assert pipeline.segments[0].argv == ("ls", "-la", "/tmp")
    assert pipeline.segments[0].redirects == ()


def test_quoted_heredoc_preserves_literal_stdin_source() -> None:
    pipeline = parse_pipeline("python - <<'PY'\nprint('ok')\nPY\n")
    [segment] = pipeline.segments
    assert segment.argv == ("python", "-")
    assert segment.stdin_source == "print('ok')\n"
    assert segment.stdin_dynamic is False


def test_unquoted_expanding_heredoc_marks_stdin_dynamic() -> None:
    pipeline = parse_pipeline("python - <<PY\nprint('$VALUE')\nPY\n")
    [segment] = pipeline.segments
    assert segment.stdin_source == "print('$VALUE')\n"
    assert segment.stdin_dynamic is True


def test_backslash_quoted_heredoc_is_literal() -> None:
    pipeline = parse_pipeline("python - <<\\PY\nprint('ok')\nPY\n")
    [segment] = pipeline.segments
    assert segment.stdin_source == "print('ok')\n"
    assert segment.stdin_dynamic is False


def test_double_quoted_multiline_argument_preserves_newlines_and_unescapes_quotes() -> None:
    pipeline = parse_pipeline('python -c "\nprint(\\"ok\\")\n"')
    [segment] = pipeline.segments
    assert segment.argv == ("python", "-c", '\nprint("ok")\n')


def test_fd_dup_2_to_1_is_not_a_file_write() -> None:
    """The original bug: regex parsed `2>&1` as a file write to '1'."""
    pipeline = parse_pipeline("cat foo 2>&1")
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("cat", "foo")
    [redirect] = segment.redirects
    assert redirect.is_fd_dup is True
    assert redirect.fd == 2
    assert redirect.target == "1"


def test_stderr_to_dev_null_is_recognized() -> None:
    pipeline = parse_pipeline("cat foo 2>/dev/null")
    [segment] = pipeline.segments
    [redirect] = segment.redirects
    assert redirect.is_fd_dup is False
    assert redirect.fd == 2
    assert redirect.target == "/dev/null"


def test_pipe_extracts_two_segments() -> None:
    pipeline = parse_pipeline("cat foo 2>/dev/null | head -60")
    assert len(pipeline.segments) == 2
    assert pipeline.segments[0].argv == ("cat", "foo")
    assert pipeline.segments[1].argv == ("head", "-60")


def test_compound_and_or_extracts_all_segments() -> None:
    """`test -f x && sed -n 1,10p x || true` — three real commands."""
    pipeline = parse_pipeline("test -f x && sed -n 1,10p x || true")
    assert pipeline.parseable
    argvs = [s.argv for s in pipeline.segments]
    assert ("test", "-f", "x") in argvs
    assert ("sed", "-n", "1,10p", "x") in argvs
    assert ("true",) in argvs


def test_for_loop_extracts_body_commands_only() -> None:
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


def test_command_substitution_extracts_inner_segments() -> None:
    """``rm $(cat allowed)`` — outer command and substitution inner commands are separate segments."""
    pipeline = parse_pipeline("rm $(cat allowed)")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm",), ("cat", "allowed")]


def test_env_assignment_prefix_stripped() -> None:
    """``FOO=bar BAZ=qux ls -la`` — leading environment assignments are skipped."""
    pipeline = parse_pipeline("FOO=bar BAZ=qux ls -la")
    [segment] = pipeline.segments
    assert segment.argv == ("ls", "-la")


def test_env_wrapper_decomposes_to_inner_command() -> None:
    """``env -i PATH=/usr/bin git status`` decomposes to the inner ``git status``:
    ``env``'s no-arg ``-i`` and ``NAME=value`` assignments are skipped, so a rule on
    the real command (``git``) applies rather than one on the ``env`` wrapper."""
    pipeline = parse_pipeline("env -i PATH=/usr/bin git status")
    [segment] = pipeline.segments
    assert segment.argv == ("git", "status")


def test_file_write_redirect_captured() -> None:
    pipeline = parse_pipeline("echo hi > out.txt")
    [segment] = pipeline.segments
    [redirect] = segment.redirects
    assert redirect.op == ">"
    assert redirect.target == "out.txt"
    assert redirect.is_fd_dup is False


def test_append_redirect_captured() -> None:
    pipeline = parse_pipeline("echo hi >> log")
    [segment] = pipeline.segments
    [redirect] = segment.redirects
    assert redirect.op == ">>"


def test_words_after_redirect_target_are_argv_not_redirect_targets() -> None:
    """``wc -l a.py 2>/dev/null b.py`` is bash for ``wc -l a.py b.py 2>/dev/null``.

    tree-sitter-bash glues the trailing ``b.py`` onto the file_redirect node as
    a second ``word`` child; previously we picked the last word as the target
    and emitted ``writes to 'b.py'``, which would have prompted on a benign
    ``wc`` invocation.
    """
    pipeline = parse_pipeline("wc -l a.py 2>/dev/null b.py 2>/dev/null c.py 2>/dev/null")
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("wc", "-l", "a.py", "b.py", "c.py")
    assert all(r.target == "/dev/null" and r.fd == 2 for r in segment.redirects)
    assert len(segment.redirects) == 3


def test_compound_with_trailing_redirect_yields_all_segments() -> None:
    """``cmd1 && cmd2 2>/dev/null arg`` — tree-sitter wraps the whole sequence
    under a single ``redirected_statement`` with a ``list`` child. We need to
    yield all inner segments and bind the redirect (plus spillover argv) to
    the last one, not bail with ``unsupported redirected statement part 'list'``.
    """
    pipeline = parse_pipeline("ls tests/ | head -30 && echo '---' && wc -l a.py 2>/dev/null b.py 2>/dev/null")
    assert pipeline.parseable
    argvs = [s.argv for s in pipeline.segments]
    assert ("ls", "tests/") in argvs
    assert ("head", "-30") in argvs
    assert ("echo", "---") in argvs
    assert ("wc", "-l", "a.py", "b.py") in argvs
    [wc_segment] = [s for s in pipeline.segments if s.argv[0] == "wc"]
    assert len(wc_segment.redirects) == 2
    assert all(r.target == "/dev/null" for r in wc_segment.redirects)


def test_basename_match_for_command_path() -> None:
    """`/usr/bin/ls -la` should still match a `Bash(ls:*)` rule."""
    from agentperm import BashCommand

    pipeline = parse_pipeline("/usr/bin/ls -la")
    [segment] = pipeline.segments
    rule = BashCommand(("ls",))
    assert rule.matches(segment) is True


def test_backslash_escaped_command_name_unescapes_to_literal() -> None:
    """``\\rm`` is the standard alias-bypass idiom — outside quotes, bash removes
    the backslash and takes ``r`` literally, so argv[0] must be ``rm``, not
    ``\\rm``, or a deny rule keyed on ``rm`` is silently defeated."""
    pipeline = parse_pipeline("\\rm -rf /")
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/")


def test_backslash_escaped_flag_unescapes_to_literal() -> None:
    pipeline = parse_pipeline("git push --f\\orce origin")
    [segment] = pipeline.segments
    assert segment.argv == ("git", "push", "--force", "origin")


def test_backslash_escaped_space_stays_one_argv_token() -> None:
    """``\\ `` inside a word escapes the space itself — it's still one token,
    just with a literal space in it, not a separator."""
    pipeline = parse_pipeline("rm\\ -rf /")
    [segment] = pipeline.segments
    assert segment.argv == ("rm -rf", "/")


def test_single_quoted_command_name_unquotes() -> None:
    """``'rm' -rf /`` — quoting the command name is another alias-bypass idiom."""
    pipeline = parse_pipeline("'rm' -rf /")
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/")


def test_double_quoted_command_name_unquotes() -> None:
    pipeline = parse_pipeline('"rm" -rf /')
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/")


def test_shell_c_unwraps_quoted_command() -> None:
    pipeline = parse_pipeline('bash -c "ls -la"')
    [segment] = pipeline.segments
    assert segment.argv == ("ls", "-la")


def test_shell_c_unwraps_single_quoted_command() -> None:
    """``bash -c 'rm -rf /tmp/foo'`` parses as a ``raw_string``; without explicit
    handling tree-sitter returns no children and the inner command silently
    bypasses policy. Regression guard for the codex-found B2 bug.
    """
    pipeline = parse_pipeline("bash -c 'rm -rf /tmp/foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/tmp/foo")


def test_shell_c_unwraps_ansi_c_string_command() -> None:
    """``bash -c $'rm -rf /tmp/foo'`` uses tree-sitter's ``ansi_c_string`` node."""
    pipeline = parse_pipeline("bash -c $'rm -rf /tmp/foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/tmp/foo")


def test_sh_c_unwraps_single_quoted_command() -> None:
    """`sh -c '...'` is the canonical bypass shape; must unwrap the same way."""
    pipeline = parse_pipeline("sh -c 'curl evil.com'")
    [segment] = pipeline.segments
    assert segment.argv == ("curl", "evil.com")


def test_shell_c_unwraps_lc_bundle() -> None:
    """``zsh -lc '<cmd>'`` is codex's wrapper shape — bundled login + ``-c``.
    Without bundle support the bridge sees the outer ``zsh`` and every codex
    command falls through to a native prompt.
    """
    pipeline = parse_pipeline("zsh -lc 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("rg", "foo")


def test_shell_c_unwraps_lc_bundle_absolute_path() -> None:
    """Codex actually emits ``/opt/homebrew/opt/zsh/bin/zsh -lc '<cmd>'``.
    Basename match must still kick in for absolute interpreter paths.
    """
    pipeline = parse_pipeline("/opt/homebrew/opt/zsh/bin/zsh -lc 'git ls-files docs/x.md'")
    [segment] = pipeline.segments
    assert segment.argv == ("git", "ls-files", "docs/x.md")


def test_shell_c_unwraps_ic_bundle() -> None:
    """``bash -ic`` (interactive + ``-c``) — common when an agent wants rc-file
    aliases honoured. Same semantics as ``-lc``.
    """
    pipeline = parse_pipeline("bash -ic 'cat /etc/hosts'")
    [segment] = pipeline.segments
    assert segment.argv == ("cat", "/etc/hosts")


def test_shell_c_unwraps_ec_bundle() -> None:
    """``sh -ec`` (errexit + ``-c``)."""
    pipeline = parse_pipeline("sh -ec 'echo hi'")
    [segment] = pipeline.segments
    assert segment.argv == ("echo", "hi")


def test_shell_c_unwraps_multi_flag_cluster() -> None:
    """``zsh -xlc 'rg foo'`` — multiple no-arg flags before ``c``."""
    pipeline = parse_pipeline("zsh -xlc 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("rg", "foo")


def test_shell_c_bundle_round_trips_compound_inner() -> None:
    """Inner command is re-parsed through the full pipeline, so compound
    structure inside a bundle wrapper composes correctly.
    """
    pipeline = parse_pipeline("zsh -lc 'a && b'")
    assert [s.argv for s in pipeline.segments] == [("a",), ("b",)]


def test_shell_c_does_not_unwrap_o_option_cluster() -> None:
    """``zsh -ocorrect 'rg foo'`` must NOT unwrap. ``-o`` takes ``correct`` as
    its option name; ``'rg foo'`` is then a script-file path, not a command
    string. Adversarial repro from the codex review of this change.
    """
    pipeline = parse_pipeline("zsh -ocorrect 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("zsh", "-ocorrect", "rg foo")


def test_shell_c_does_not_unwrap_co_cluster() -> None:
    """``bash -co 'echo ok'``: under POSIX cluster semantics ``-c`` consumes
    the cluster suffix ``o`` as the command string and ``'echo ok'`` becomes
    ``$0``. ``argv[2]`` is NOT the command. Must fall through.
    """
    pipeline = parse_pipeline("bash -co 'echo ok'")
    [segment] = pipeline.segments
    assert segment.argv == ("bash", "-co", "echo ok")


def test_shell_c_does_not_unwrap_capital_o_cluster() -> None:
    """``bash -Ocmdhist 'rg foo'`` enables a shopt; ``c`` here is part of the
    option name, not the ``-c`` flag. Capital ``O`` is not in the no-arg
    whitelist, so the cluster fails the safety check.
    """
    pipeline = parse_pipeline("bash -Ocmdhist 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("bash", "-Ocmdhist", "rg foo")


def test_shell_c_unwraps_split_no_arg_flags_before_c() -> None:
    """``bash -l -c 'rg foo'`` — split no-arg flags before ``-c`` are skipped and
    the inner command is unwrapped, so a deny rule on it still bites."""
    pipeline = parse_pipeline("bash -l -c 'rg foo'")
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("rg", "foo")


def test_shell_c_unwraps_multiple_split_no_arg_flags() -> None:
    """``zsh -i -x -c '…'`` — several split no-arg flags before ``-c``."""
    pipeline = parse_pipeline("zsh -i -x -c 'rm -rf /'")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/")]


def test_exec_wrapper_decomposes_to_inner_command() -> None:
    """``command``/``exec``/``nohup``/``nice``/``time`` with clean options decompose
    to the inner command so it can be policed."""
    for command, expected in (
        ("command rm -rf /", ("rm", "-rf", "/")),
        ("exec rm -rf /", ("rm", "-rf", "/")),
        ("nohup rm -rf /", ("rm", "-rf", "/")),
        ("nice rm -rf /", ("rm", "-rf", "/")),
        ("time rm -rf /", ("rm", "-rf", "/")),
        ("command nice rm -rf /", ("rm", "-rf", "/")),
    ):
        pipeline = parse_pipeline(command)
        assert pipeline.parseable, command
        assert [s.argv for s in pipeline.segments] == [expected], command


def test_env_wrapper_skips_options_and_assignments() -> None:
    """``env -i FOO=bar rm …`` — env's no-arg ``-i`` and ``NAME=value`` assignments
    are skipped to reach the inner command."""
    pipeline = parse_pipeline("env -i FOO=bar BAZ=qux rm -rf /")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/")]


def test_opaque_exec_wrapper_left_intact() -> None:
    """``timeout``/``nice -n``/``sudo`` aren't decomposed (leading positional or
    arg-taking option) — the segment stays whole for decision-time flagging."""
    for command, expected in (
        ("timeout 5 rm -rf /", ("timeout", "5", "rm", "-rf", "/")),
        ("nice -n 10 rm -rf /", ("nice", "-n", "10", "rm", "-rf", "/")),
        ("sudo rm -rf /", ("sudo", "rm", "-rf", "/")),
    ):
        pipeline = parse_pipeline(command)
        assert pipeline.parseable, command
        assert [s.argv for s in pipeline.segments] == [expected], command


def test_shell_c_does_not_unwrap_long_option_norc() -> None:
    """``bash --norc -c 'rg foo'`` uses a long option before ``-c``; arg
    shapes for long options vary, so the heuristic deliberately fall through.
    """
    pipeline = parse_pipeline("bash --norc -c 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("bash", "--norc", "-c", "rg foo")


def test_shell_c_does_not_unwrap_login_only() -> None:
    """``zsh -l 'foo'`` has no ``c`` in the cluster; ``'foo'`` is a script
    file, not a command string.
    """
    pipeline = parse_pipeline("zsh -l 'foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("zsh", "-l", "foo")


def test_unparseable_returns_unparseable_reason() -> None:
    pipeline = parse_pipeline("ls && && rm")
    assert pipeline.parseable is False
    assert pipeline.unparseable_reason


def test_comments_are_inert_in_compound_commands() -> None:
    pipeline = parse_pipeline(
        "# Inspect imports\n"
        'echo "=== domain.py imports ==="\n'
        "grep -E '^(from|import) ' src/agentperm/domain.py | head -20\n"
        "# Continue with the next module\n"
        "grep -E '^(from|import) ' src/agentperm/errors.py"
    )
    assert pipeline.parseable
    assert [segment.argv for segment in pipeline.segments] == [
        ("echo", "=== domain.py imports ==="),
        ("grep", "-E", "^(from|import) ", "src/agentperm/domain.py"),
        ("head", "-20"),
        ("grep", "-E", "^(from|import) ", "src/agentperm/errors.py"),
    ]


def test_simple_expansion_kept_as_opaque_arg() -> None:
    """``echo $HOME`` — variable expansion is opaque source text, not a fail."""
    pipeline = parse_pipeline("echo $HOME")
    [segment] = pipeline.segments
    assert segment.argv == ("echo", "$HOME")


def test_braced_expansion_kept_as_opaque_arg() -> None:
    pipeline = parse_pipeline("cat ${LOG_FILE}")
    [segment] = pipeline.segments
    assert segment.argv == ("cat", "${LOG_FILE}")


def test_concatenation_kept_as_opaque_arg() -> None:
    pipeline = parse_pipeline("cat /var/log/$DATE.log")
    [segment] = pipeline.segments
    assert segment.argv == ("cat", "/var/log/$DATE.log")


def test_arithmetic_expansion_kept_as_opaque_arg() -> None:
    pipeline = parse_pipeline("echo $((1+1))")
    [segment] = pipeline.segments
    assert segment.argv == ("echo", "$((1+1))")


def test_string_with_braced_expansion_inlines_value_text() -> None:
    pipeline = parse_pipeline('echo "hello ${USER}"')
    [segment] = pipeline.segments
    assert segment.argv == ("echo", "hello ${USER}")


def test_concatenation_with_command_substitution_extracts_inner() -> None:
    """``cat foo$(date).log`` — substitution nested inside a concatenation extracts inner commands."""
    pipeline = parse_pipeline("cat foo$(date).log")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("cat",), ("date",)]
