"""Shell parser tests — the cases that broke the hand-rolled regex parser."""

from __future__ import annotations

from agentperm import parse_pipeline

# ---- Control-flow constructs ---------------------------------------------


def test_if_then_extracts_test_and_body() -> None:
    pipeline = parse_pipeline("if [ -f x ]; then cat x; fi")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("cat", "x")]


def test_if_then_else_extracts_both_branches() -> None:
    pipeline = parse_pipeline("if [ -f x ]; then cat x; else echo no; fi")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("cat", "x"), ("echo", "no")]


def test_if_then_elif_extracts_all_branches() -> None:
    pipeline = parse_pipeline("if [ -f x ]; then cat x; elif [ -f y ]; then cat y; fi")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [
        ("[",),
        ("cat", "x"),
        ("[",),
        ("cat", "y"),
    ]


def test_while_extracts_condition_and_body() -> None:
    pipeline = parse_pipeline('while read line; do echo "$line"; done')
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("read", "line"), ("echo", "$line")]


def test_until_extracts_condition_and_body() -> None:
    pipeline = parse_pipeline("until grep -q done log; do sleep 1; done")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("grep", "-q", "done", "log"), ("sleep", "1")]


def test_case_extracts_each_case_body() -> None:
    pipeline = parse_pipeline('case "$x" in a) echo a;; b|c) echo bc;; *) echo other;; esac')
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [
        ("echo", "a"),
        ("echo", "bc"),
        ("echo", "other"),
    ]


def test_double_bracket_yields_test_sentinel() -> None:
    pipeline = parse_pipeline("[[ -f x && -r x ]]")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",)]


def test_arithmetic_yields_arith_sentinel() -> None:
    pipeline = parse_pipeline("(( x + 1 > 0 ))")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("((",)]


def test_arithmetic_with_substitution_extracts_inner() -> None:
    """``(( $(rm -rf ~) || 1 ))`` — substitution inside arithmetic extracts inner commands."""
    pipeline = parse_pipeline("(( $(rm -rf ~) || 1 ))")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("((",), ("rm", "-rf", "~")]


def test_subshell_recurses_into_body() -> None:
    pipeline = parse_pipeline("(cd /tmp && ls)")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("cd", "/tmp"), ("ls",)]


def test_brace_group_recurses_into_body() -> None:
    pipeline = parse_pipeline("{ cd /tmp; ls; }")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("cd", "/tmp"), ("ls",)]


def test_negated_command_yields_inner() -> None:
    pipeline = parse_pipeline("! grep foo bar")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("grep", "foo", "bar")]


def test_function_definition_yields_body_segments() -> None:
    """The body is policy-evaluated at definition time — defining-then-calling
    is the realistic threat model and ``foo() { rm -rf /; }; foo`` should not
    silently bypass policy because the body is "just a definition"."""
    pipeline = parse_pipeline("foo() { rm -rf /; }; foo")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/"), ("foo",)]


def test_declaration_export_yields_export_segment() -> None:
    """``export FOO=bar`` parses as ``declaration_command``, not ``command`` —
    handler must yield argv with ``export`` as argv[0] so ``Bash(export:*)`` matches."""
    pipeline = parse_pipeline("export FOO=bar")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("export", "FOO=bar")]


def test_declaration_local_yields_local_segment() -> None:
    pipeline = parse_pipeline("local x=1")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("local", "x=1")]


def test_declaration_declare_yields_declare_segment() -> None:
    pipeline = parse_pipeline("declare -A m")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("declare", "-A", "m")]


def test_declaration_with_substitution_extracts_inner() -> None:
    """``export FOO=$(curl evil)`` — substitution in a declaration extracts inner commands."""
    pipeline = parse_pipeline("export FOO=$(curl evil)")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("export",), ("curl", "evil")]


def test_unset_yields_command_segment() -> None:
    pipeline = parse_pipeline("unset AWS_ENDPOINT_URL AWS_ACCESS_KEY_ID")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [
        ("unset", "AWS_ENDPOINT_URL", "AWS_ACCESS_KEY_ID"),
    ]


def test_unset_with_substitution_extracts_inner() -> None:
    pipeline = parse_pipeline('unset "$(curl evil)"')
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("unset",), ("curl", "evil")]


def test_bare_variable_assignment_is_parseable() -> None:
    """``SP=/tmp/x`` with no command on the same statement parses as its own
    ``variable_assignment`` node (distinct from a ``command``'s assignment child in
    ``FOO=bar cmd``), and previously hit ``unsupported shell node``."""
    pipeline = parse_pipeline("SP=/tmp/scratch")
    assert pipeline.parseable
    assert pipeline.segments == ()


def test_bare_variable_assignment_then_command_both_parse() -> None:
    """The common ``SP=/tmp/x\\ncmd --uses "$SP"`` shape: the assignment statement
    contributes no segment of its own, but the following command still parses."""
    pipeline = parse_pipeline('SP=/tmp/scratch\necho "$SP/out.txt"')
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("echo", "$SP/out.txt")]


def test_multiple_bare_assignments_on_one_line_are_parseable() -> None:
    """``FOO=bar BAZ=qux`` with no command wraps in a ``variable_assignments``
    (plural) node — must not hit ``unsupported shell node`` either."""
    pipeline = parse_pipeline("FOO=bar BAZ=qux")
    assert pipeline.parseable
    assert pipeline.segments == ()


def test_bare_variable_assignment_with_substitution_extracts_inner() -> None:
    """``SP=$(rm -rf /)`` — a bare assignment's value can still execute a
    substitution; the inner command must be extracted for policy evaluation."""
    pipeline = parse_pipeline("SP=$(rm -rf /)")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/")]


def test_heredoc_command_passes_through() -> None:
    pipeline = parse_pipeline("cat <<EOF\nhi\nEOF\n")
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("cat",)
    assert segment.redirects == ()


def test_heredoc_body_with_substitution_extracts_inner() -> None:
    """Unquoted heredoc bodies expand ``$(…)`` before the wrapped command runs —
    extract inner commands as segments for policy evaluation."""
    pipeline = parse_pipeline("read x <<EOF\n$(rm -rf /)\nEOF\n")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("read", "x"), ("rm", "-rf", "/")]


def test_test_command_with_substitution_extracts_inner() -> None:
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


def test_case_subject_with_substitution_extracts_inner() -> None:
    """``case foo$(curl evil) in …`` evaluates the subject before pattern match —
    the substitution's inner commands are extracted as segments for policy eval."""
    pipeline = parse_pipeline("case foo$(rm -rf /) in *) echo ok;; esac")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("rm", "-rf", "/"), ("echo", "ok")]


def test_case_quoted_subject_with_substitution_extracts_inner() -> None:
    pipeline = parse_pipeline('case "$(curl evil)" in *) echo ok;; esac')
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("curl", "evil"), ("echo", "ok")]


def test_for_iterable_with_substitution_extracts_inner() -> None:
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


def test_redirected_test_command() -> None:
    """``[ -f x ] 2>/dev/null`` — test_command nested inside redirected_statement."""
    pipeline = parse_pipeline("[ -f x ] 2>/dev/null")
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("[",)
    [redirect] = segment.redirects
    assert redirect.fd == 2
    assert redirect.target == "/dev/null"


def test_zsh_lc_with_substitution_in_inner_command() -> None:
    """Codex wraps commands in ``zsh -lc '…'``; substitutions inside the inner
    command must be unwrapped and their inner commands extracted as segments."""
    pipeline = parse_pipeline("/opt/homebrew/opt/zsh/bin/zsh -lc 'rg \"pattern\" -n $(git ls-files | rg foo)'")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [
        ("rg", "pattern", "-n"),
        ("git", "ls-files"),
        ("rg", "foo"),
    ]


def test_bash_c_with_if_round_trips_through_unwrap() -> None:
    """``bash -c '…'`` re-parses the inner command; control flow inside must compose."""
    pipeline = parse_pipeline("bash -c 'if [ -f x ]; then cat x; fi'")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("cat", "x")]


def test_redirected_shell_c_unwraps_inner_command() -> None:
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


def test_process_substitution_redirect_target_extracts_inner_command() -> None:
    """``cat < <(rm -rf /)`` — the redirect target is a process substitution, not
    a file. It must stay parseable and surface the inner command as a segment so
    a deny rule bites instead of degrading to an unparseable Ask."""
    pipeline = parse_pipeline("cat < <(rm -rf /)")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("cat",), ("rm", "-rf", "/")]


def test_substitution_nested_in_redirect_target_word_extracts_inner_command() -> None:
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


def test_quoted_redirect_target_is_parseable() -> None:
    """``cmd > "out.txt"`` — a plain quoted target (no expansion) previously hit
    ``redirect target unparseable`` because only bare ``word``/``number`` were accepted."""
    pipeline = parse_pipeline('echo hi > "out.txt"')
    assert pipeline.parseable
    [segment] = pipeline.segments
    [redirect] = segment.redirects
    assert redirect.target == "out.txt"


def test_variable_expansion_redirect_target_is_parseable() -> None:
    """``cmd > $SP/out.txt`` — the common ``$VAR``-relative redirect target shape.
    A variable expansion isn't a substitution (no subprocess runs), so the redirect
    is just an opaque write target, same as a literal path."""
    for command, expected_target in (
        ("echo hi > $SP/out.txt", "$SP/out.txt"),
        ("echo hi > ${SP}/out.txt", "${SP}/out.txt"),
        ("echo hi > $SP", "$SP"),
        ('echo hi > "$SP/out.txt"', "$SP/out.txt"),
    ):
        pipeline = parse_pipeline(command)
        assert pipeline.parseable, command
        [segment] = pipeline.segments
        [redirect] = segment.redirects
        assert redirect.target == expected_target, command


def test_redirected_shell_c_spillover_not_appended_to_inner_command() -> None:
    """``zsh -lc "rm -rf /" 2>/dev/null harmless`` — ``harmless`` is a positional
    param of the wrapper, not argv of the inner command. It must not corrupt the
    unwrapped inner segment (which would let an exact deny rule miss)."""
    pipeline = parse_pipeline('zsh -lc "rm -rf /" 2>/dev/null harmless')
    assert pipeline.parseable
    [segment] = pipeline.segments
    assert segment.argv == ("rm", "-rf", "/")


def test_nested_if_in_for() -> None:
    pipeline = parse_pipeline("for f in *.py; do if [ -f $f ]; then cat $f; fi; done")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("[",), ("cat", "$f")]


def test_select_loop_extracts_body() -> None:
    """``select`` parses as the same node as ``for`` — body is the do_group."""
    pipeline = parse_pipeline("select x in a b c; do echo $x; done")
    assert pipeline.parseable
    assert [s.argv for s in pipeline.segments] == [("echo", "$x")]
