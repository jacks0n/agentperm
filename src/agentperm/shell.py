"""Tree-sitter Bash shell parser for agentperm."""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

import tree_sitter_bash
from tree_sitter import Language, Node, Parser

from .domain import Decision, Pipeline, Redirect, RedirectionPolicy, Segment, Verdict, basename

# -----------------------------------------------------------------------------
# Redirect policy — shapes are fixed here, but each shape's decision is
# user-tunable via a policy file's ``shell.redirection`` block (RedirectionPolicy).
# -----------------------------------------------------------------------------


def evaluate_redirects(
    redirects: Iterable[Redirect],
    policy: RedirectionPolicy,
    *,
    allow_paths: tuple[str, ...] = (),
    cwd: Path | None = None,
) -> Verdict:
    strictest = Verdict(Decision.NoOpinion, "")
    for r in redirects:
        verdict = _evaluate_redirect(r, policy, allow_paths, cwd)
        if verdict.decision is Decision.Deny:
            return verdict
        if verdict.decision is Decision.Ask and strictest.decision is Decision.NoOpinion:
            strictest = verdict
    return strictest


def _evaluate_redirect(
    r: Redirect,
    policy: RedirectionPolicy,
    allow_paths: tuple[str, ...] = (),
    cwd: Path | None = None,
) -> Verdict:
    if r.is_fd_dup:
        return Verdict(Decision.NoOpinion, "")
    if r.op == "<":
        return Verdict(Decision.NoOpinion, "")
    if r.target == "/dev/null":
        if r.fd == 2:
            return _configured_verdict(policy.stderr_to_dev_null, Decision.Allow, "stderr to /dev/null")
        return _configured_verdict(policy.stdout_to_dev_null, Decision.Allow, "stdout to /dev/null")
    # Path allowlist — checked before the operator-based policy so an allowed
    # directory overrides the default ask/deny for writes and appends.
    is_write = r.op in (">", "&>", ">|", ">>", "&>>")
    if is_write and allow_paths and _redirect_path_allowed(r.target, allow_paths, cwd):
        return Verdict(Decision.NoOpinion, "")
    if r.op in (">", "&>", ">|"):
        return _configured_verdict(policy.stdout_to_file, Decision.Ask, f"writes to {r.target!r}")
    if r.op in (">>", "&>>"):
        return _configured_verdict(policy.append_to_file, Decision.Ask, f"appends to {r.target!r}")
    return Verdict(Decision.Ask, f"unrecognized redirection {r.op!r}")


def _redirect_path_allowed(
    target: str, allow_paths: tuple[str, ...], cwd: Path | None
) -> bool:
    if os.path.isabs(target):
        resolved = os.path.realpath(target)
    elif cwd is not None:
        resolved = os.path.realpath(cwd / target)
    else:
        return False
    resolved_parts = Path(resolved).parts
    for pattern in allow_paths:
        canonical = os.path.realpath(pattern)
        pattern_parts = Path(canonical).parts
        if len(pattern_parts) > len(resolved_parts):
            continue
        if all(
            fnmatch.fnmatch(actual, pat)
            for actual, pat in zip(resolved_parts, pattern_parts, strict=False)
        ):
            return True
    return False


def _configured_verdict(configured: Decision | None, default: Decision, rationale: str) -> Verdict:
    """Turn a redirect shape's configured/default decision into a Verdict.

    ``Allow`` defers entirely to the segment's own command rule (NoOpinion);
    ``Ask``/``Deny`` force that verdict regardless of what the command rule says.
    """
    intended = configured if configured is not None else default
    if intended is Decision.Allow:
        return Verdict(Decision.NoOpinion, "")
    if intended is Decision.Deny:
        return Verdict(Decision.Deny, rationale)
    return Verdict(Decision.Ask, rationale)


# -----------------------------------------------------------------------------
# Shell parser (Tree-sitter Bash -> Pipeline)
#
# Tree-sitter exposes generic Node objects with grammar-specific ``type`` strings.
# The helpers below are the only place that talks to that boundary; everything
# outside this section only sees the typed Pipeline/Segment/Redirect domain types.
# -----------------------------------------------------------------------------


class _UnsupportedShellError(Exception):
    pass


_SHELL_COMMANDS = frozenset({"bash", "sh", "zsh"})

# Exec-prefix wrappers run a *following* command. We decompose them so a deny rule
# on the inner command still bites. Value = short option letters that take NO
# argument; the inner command is the first token that is neither one of those
# options nor (for ``env``) a ``NAME=value`` assignment. A wrapper invocation whose
# options we can't classify is left intact and flagged at decision time.
_EXEC_WRAPPER_NO_ARG_OPTS: dict[str, frozenset[str]] = {
    "command": frozenset("pvV"),
    "exec": frozenset("cl"),
    "nohup": frozenset(),
    "setsid": frozenset("cfw"),
    "env": frozenset("i"),
    "nice": frozenset(),
    "time": frozenset("p"),
}

# Exec wrappers we never decompose — leading positionals (``timeout 5 cmd``) or
# option grammars too varied to model. Flagged at decision time so bypass prompts
# rather than allowing the hidden command; an explicit rule still allow-lists them.
_OPAQUE_EXEC_WRAPPERS: frozenset[str] = frozenset({
    "timeout", "sudo", "doas", "su", "runuser", "xargs", "stdbuf", "ionice",
    "chrt", "setarch", "setpriv", "unshare", "watch", "parallel", "flock", "eval",
})

ALL_EXEC_WRAPPERS: frozenset[str] = frozenset(_EXEC_WRAPPER_NO_ARG_OPTS) | _OPAQUE_EXEC_WRAPPERS

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_BASH_LANGUAGE = Language(tree_sitter_bash.language())
_BASH_PARSER = Parser()
_BASH_PARSER.language = _BASH_LANGUAGE

# Argument-position nodes whose literal source text is safe to treat as opaque
# argument text. Variable values aren't expanded at parse time, so argv[0] rule
# matching is unaffected. ``_node_contains_substitution`` still rejects anything
# nesting a command/process substitution, so e.g. ``cat foo$(date)`` is blocked
# even though the outer node here is a ``concatenation``.
_OPAQUE_ARG_TYPES = frozenset({
    "word", "number", "string", "raw_string",
    "simple_expansion", "expansion", "concatenation",
    "arithmetic_expansion", "ansi_c_string", "translated_string",
})

# Children of control-flow nodes that are subjects/patterns/names rather than
# executable segments — skipped during recursion. Includes function names
# (``foo`` in ``foo() { … }``, parsed as ``word``) and ``case`` patterns.
_PATTERN_CHILD_TYPES = frozenset({"extglob_pattern", "regex"}) | _OPAQUE_ARG_TYPES

# Control-flow / grouping nodes whose named children are recursable into segments.
# Excludes ``for_statement`` (handled separately because the iterable list contains
# ``variable_name``/etc. that aren't pattern types but also aren't recursable).
_CONTROL_FLOW_TYPES = frozenset({
    "program", "list", "pipeline", "do_group",
    "if_statement", "while_statement", "until_statement",
    "case_statement", "case_item",
    "elif_clause", "else_clause",
    "subshell", "negated_command", "function_definition",
})

# AST node types that ``_build_redirected_segment`` will recurse into via
# ``_extract_segments`` to collect inner segments before attaching the redirect.
_REDIRECT_INNER_TYPES = frozenset({
    "list", "pipeline", "subshell",
    "test_command", "compound_statement",
    "if_statement", "while_statement", "until_statement",
    "case_statement", "negated_command",
    "function_definition", "declaration_command",
})


def parse_pipeline(command: str) -> Pipeline:
    if not command.strip():
        return Pipeline(segments=(), parseable=True)
    source = command.encode()
    tree = _BASH_PARSER.parse(source)
    if tree.root_node.has_error:
        return Pipeline((), parseable=False, unparseable_reason="tree-sitter: shell syntax error")
    segments: list[Segment] = []
    try:
        segments.extend(_extract_segments(tree.root_node, source))
    except _UnsupportedShellError as error:
        return Pipeline((), parseable=False, unparseable_reason=str(error))
    return Pipeline(tuple(segments), parseable=True)


def _extract_segments(node: Node, source: bytes) -> Iterator[Segment]:
    if node.type == "comment":
        # Comments are named Tree-sitter nodes but never execute. Ignore them at
        # any recursion depth so an otherwise safe command list does not fail
        # closed merely because an agent included an explanatory shell comment.
        return
    if node.type == "command":
        segment, inner = _build_segment(node, source)
        unwrapped = _unwrap_shell_c(segment)
        if unwrapped is not None:
            yield from unwrapped
            yield from inner
            return
        yield from _unwrap_exec_wrapper(segment)
        yield from inner
        return
    if node.type == "redirected_statement":
        yield from _build_redirected_segment(node, source)
        return
    if node.type in ("command_substitution", "process_substitution"):
        # A bare substitution standing where a command is expected — e.g. a
        # ``case $(rm -rf /) in …`` subject. The substitution runs; extract its
        # inner commands for policy evaluation rather than bailing as unparseable.
        yield from _extract_substitution_segments(node, source)
        return
    if node.type == "compound_statement":
        # ``(( … ))`` and ``{ …; }`` share this AST node — disambiguate by source prefix.
        # Arithmetic is a pure predicate (in-process state only); brace groups are
        # ordinary command lists wrapped in braces.
        if source[node.start_byte:node.start_byte + 2] == b"((":
            yield Segment(("((",), ())
            yield from _extract_substitution_segments(node, source)
            return
        for child in node.named_children:
            if child.type in _PATTERN_CHILD_TYPES:
                continue
            yield from _extract_segments(child, source)
        return
    if node.type == "test_command":
        # ``[ … ]`` and ``[[ … ]]`` are pure predicates — collapse to a synthetic
        # segment the inert-builtin matcher recognizes. Children are expressions
        # (test_operator, unary_expression, …) and yield no commands of their own.
        # Substitutions inside (e.g. ``[[ -f $(curl evil) ]]``) execute before
        # the predicate — extract their inner commands as segments for policy eval.
        yield Segment(("[",), ())
        yield from _extract_substitution_segments(node, source)
        return
    if node.type in ("variable_assignment", "variable_assignments"):
        # A bare ``FOO=bar`` statement with no command on the same line — e.g. the
        # first line of ``SP=/tmp/x\ncat "$SP/f"``. tree-sitter gives this its own
        # node type (``variable_assignments`` wraps multiple, as in ``FOO=bar
        # BAZ=qux``), distinct from a ``command`` node's variable_assignment
        # children (``FOO=bar cmd``, already skipped in ``_build_segment``). It
        # only sets a shell variable — no OS-level side effect of its own — but a
        # substitution in the value (``FOO=$(rm -rf /)``) still executes before
        # the assignment completes, so extract it for policy evaluation.
        yield from _extract_substitution_segments(node, source)
        return
    if node.type == "declaration_command":
        # ``export FOO=bar`` / ``local`` / ``declare`` / ``readonly`` / ``typeset``.
        # tree-sitter parses these as their own node type, not as ``command``, so a
        # user ``Bash(export:*)`` rule would never match without explicit handling.
        # Yield a normal segment with the keyword as argv[0] and the assignments/
        # words as subsequent argv tokens. Substitution-containing children are
        # dropped from argv and their inner commands yielded as separate segments.
        if not node.children:
            raise _UnsupportedShellError("declaration_command missing keyword")
        decl_argv: list[str] = [_node_text(node.children[0], source)]
        decl_inner: list[Segment] = []
        for child in node.named_children:
            if child.type in ("command_substitution", "process_substitution") \
                    or _node_contains_substitution(child):
                decl_inner.extend(_extract_substitution_segments(child, source))
                continue
            decl_argv.append(_node_text(child, source))
        yield Segment(tuple(decl_argv), ())
        yield from decl_inner
        return
    if node.type in _CONTROL_FLOW_TYPES:
        for child in node.named_children:
            if child.type in _PATTERN_CHILD_TYPES:
                # Subjects/patterns are skipped from segment extraction, but
                # ``case foo$(curl evil) in …`` would still execute the
                # substitution before pattern matching. Extract inner commands
                # as segments for policy evaluation.
                yield from _extract_substitution_segments(child, source)
                continue
            yield from _extract_segments(child, source)
        return
    if node.type == "for_statement":
        # Covers ``for v in …`` and ``select v in …`` (same node). The iterable
        # list is opaque text; only the ``do_group`` body holds executable commands.
        # The iterable can trigger substitutions (e.g. ``for f in $(curl evil);
        # do …; done``) which execute before the loop runs — extract their inner
        # commands as segments for policy evaluation.
        for child in node.named_children:
            if child.type == "do_group":
                yield from _extract_segments(child, source)
                continue
            if child.type == "variable_name":
                continue
            if child.type in ("command_substitution", "process_substitution") \
                    or _node_contains_substitution(child):
                yield from _extract_substitution_segments(child, source)
        return
    raise _UnsupportedShellError(f"unsupported shell node {node.type!r}")


def _build_segment(command_node: Node, source: bytes) -> tuple[Segment, tuple[Segment, ...]]:
    """Build a ``Segment`` from a ``command`` AST node.

    Returns ``(segment, substitution_segments)`` — the main command plus any
    segments extracted from command/process substitutions in its arguments.
    Substitution-containing arguments are dropped from argv (their runtime
    value is unknowable); the inner commands are returned so the policy
    evaluator can check them independently.
    """
    argv: list[str] = []
    inner: list[Segment] = []
    for child in command_node.named_children:
        if child.type in ("command_substitution", "process_substitution") \
                or _node_contains_substitution(child):
            inner.extend(_extract_substitution_segments(child, source))
            continue
        if child.type == "variable_assignment":
            continue
        if child.type == "command_name":
            inner_name = child.named_children
            if len(inner_name) != 1:
                raise _UnsupportedShellError(f"unsupported command_name shape ({len(inner_name)} children)")
            argv.append(_argument_text(inner_name[0], source))
            continue
        if child.type in _OPAQUE_ARG_TYPES:
            argv.append(_argument_text(child, source))
            continue
        if child.type == "herestring_redirect":
            # ``cmd <<< word`` feeds a string to stdin — input only, no file write.
            # A herestring carrying a substitution is extracted by the branch above.
            continue
        raise _UnsupportedShellError(f"unsupported command part {child.type!r}")
    return Segment(tuple(argv), ()), tuple(inner)


def _build_redirected_segment(node: Node, source: bytes) -> Iterator[Segment]:
    # tree-sitter-bash flattens trailing argv into the file_redirect node and
    # wraps any compound left-hand side under a single ``list``/``pipeline``
    # child. ``cmd1 && cmd2 2>file foo`` parses as
    # ``redirected_statement(list(cmd1, &&, cmd2), file_redirect(2>file foo))``
    # even though bash binds the redirect to ``cmd2`` and treats ``foo`` as
    # ``cmd2``'s argv. We invert that here: yield each inner segment, append
    # spillover words to the last segment, and attach all collected redirects
    # to that same last segment.
    inner_segments: list[Segment] = []
    substitution_segments: list[Segment] = []
    redirects: list[Redirect] = []
    spillover: list[str] = []
    stdin_source: str | None = None
    stdin_dynamic = False
    last_was_unwrapped_wrapper = False
    previous_end = node.start_byte
    for child in node.named_children:
        if child.type == "command":
            segment, sub_segs = _build_segment(child, source)
            # ``zsh -lc "rm -rf /" 2>file`` wraps the inner command; unwrap it like
            # ``_extract_segments`` does, else a deny rule on the inner command can't
            # bite. The trailing redirect then attaches to the last inner segment.
            unwrapped = _unwrap_shell_c(segment)
            if unwrapped is not None:
                inner_segments.extend(unwrapped)
                last_was_unwrapped_wrapper = True
            else:
                # Exec-wrapper spillover (`nohup cmd 2>f extra`) is argv of the inner
                # command, so it must rejoin — unlike a shell -c wrapper's positionals.
                inner_segments.extend(_unwrap_exec_wrapper(segment))
                last_was_unwrapped_wrapper = False
            substitution_segments.extend(sub_segs)
            previous_end = child.end_byte
            continue
        if child.type in _REDIRECT_INNER_TYPES:
            inner_segments.extend(_extract_segments(child, source))
            last_was_unwrapped_wrapper = False
            previous_end = child.end_byte
            continue
        if child.type == "file_redirect":
            redirect, extras, redirect_subs = _build_redirect(child, source)
            if redirect is not None:
                redirects.append(redirect)
            spillover.extend(extras)
            substitution_segments.extend(redirect_subs)
            previous_end = child.end_byte
            continue
        if child.type == "heredoc_redirect":
            # tree-sitter-bash omits a bare stdin marker immediately before a
            # heredoc (``python - <<'PY'``) from the command node. Recover that
            # one literal token from the gap; other gap text is left untouched.
            if source[previous_end:child.start_byte].strip() == b"-" and inner_segments:
                last = inner_segments[-1]
                inner_segments[-1] = Segment(
                    (*last.argv, "-"),
                    last.redirects,
                    last.stdin_source,
                    last.stdin_dynamic,
                )
            stdin_source, stdin_dynamic = _heredoc_source(child, source)
            # ``cat <<EOF … EOF`` feeds the body to stdin; no file write, no policy
            # impact. Preserve literal input for interpreters that can analyse it.
            # An unquoted heredoc body still expands ``$(…)`` before the command
            # runs — extract inner commands as segments for policy evaluation.
            substitution_segments.extend(_extract_substitution_segments(child, source))
            previous_end = child.end_byte
            continue
        raise _UnsupportedShellError(f"unsupported redirected statement part {child.type!r}")
    if not inner_segments:
        raise _UnsupportedShellError("redirected statement missing command")
    # Words after a ``shell -c "…"`` wrapper are the wrapper's positional params
    # ($0, $1, …), not argv of the unwrapped inner command — they vanish with the
    # discarded wrapper. Spillover only rejoins argv when the last segment is a
    # real command tree-sitter split the redirect away from.
    if last_was_unwrapped_wrapper:
        spillover = []
    *head, last = inner_segments
    yield from head
    yield Segment(
        last.argv + tuple(spillover),
        last.redirects + tuple(redirects),
        stdin_source if stdin_source is not None else last.stdin_source,
        stdin_dynamic if stdin_source is not None else last.stdin_dynamic,
    )
    yield from substitution_segments


def _heredoc_source(node: Node, source: bytes) -> tuple[str | None, bool]:
    start: str | None = None
    body: str | None = None
    for child in node.named_children:
        if child.type == "heredoc_start":
            start = _node_text(child, source)
        elif child.type == "heredoc_body":
            body = _node_text(child, source)
    if body is None:
        return None, False
    quoted = bool(start) and (
        (len(start) >= 2 and start[0] in "'\"" and start[-1] == start[0])
        or start.startswith("\\")
    )
    # An unquoted body is literal only when bash has nothing to expand. Dollar,
    # backtick, and backslash all change heredoc processing at runtime.
    dynamic = not quoted and any(marker in body for marker in ("$", "`", "\\"))
    return body, dynamic


# Short flags that take no argument and are safe to share a ``-c`` cluster with.
# Intersection of ``bash(1)`` / ``zsh(1)`` / POSIX ``sh(1)`` no-arg short options.
# A flag absent from this set forces fall-through (NoOpinion → native prompt)
# rather than a guess about which cluster element steals ``argv[2]``.
_NO_ARG_SHELL_FLAGS = frozenset("efilmnpstuvx")


def _is_safe_c_bundle(flag: str) -> bool:
    """True iff ``flag`` is ``-c`` or a short-flag cluster ending in ``c`` whose
    other chars are all in ``_NO_ARG_SHELL_FLAGS``. Only then is the token after
    it reliably the command string under POSIX cluster semantics: any arg-taking
    flag in the cluster (``-o``, ``-O``…) would steal it instead.
    """
    if not flag.startswith("-") or flag.startswith("--") or "=" in flag:
        return False
    chars = flag[1:]
    if not chars or chars[-1] != "c":
        return False
    return all(ch in _NO_ARG_SHELL_FLAGS for ch in chars[:-1])


def _is_no_arg_short_cluster(flag: str) -> bool:
    """True iff ``flag`` is a short-flag cluster of known no-arg flags (``-l``,
    ``-i``, ``-xv``…). Such flags consume no following token, so we can skip past
    them when locating ``-c``. Excludes ``-c`` bundles (handled separately) since
    ``c`` is not in ``_NO_ARG_SHELL_FLAGS``, long options, and arg-taking flags.
    """
    if not flag.startswith("-") or flag.startswith("--") or "=" in flag:
        return False
    chars = flag[1:]
    return bool(chars) and all(ch in _NO_ARG_SHELL_FLAGS for ch in chars)


def _unwrap_shell_c(segment: Segment) -> tuple[Segment, ...] | None:
    """``bash -c "ls -la"`` → segments of the inner command. None if the
    wrapper shape is not provably safe to unwrap.

    Accepts ``-c`` whether bundled (``-lc``, ``-xlc``) or split across preceding
    no-arg short flags (``bash -l -c``, ``zsh -i -x -c``). The command string is
    the token immediately after the ``-c`` flag. Long-option and arg-taking-flag
    forms (``bash --norc -c``, ``bash -O cmdhist -c``, ``zsh -ocorrect``) fall
    through to the native prompt — their arg shapes vary too much to model safely.

    Tree-sitter string arguments are normalised before this point, so the command
    string is a single argv token. We re-parse it via ``parse_pipeline`` so any
    compound/redirect/control-flow structure inside is faithfully preserved.
    """
    argv = segment.argv
    if len(argv) < 3 or basename(argv[0]) not in _SHELL_COMMANDS:
        return None
    idx = 1
    while idx < len(argv) - 1:
        token = argv[idx]
        if _is_safe_c_bundle(token):
            inner = parse_pipeline(argv[idx + 1])
            return inner.segments if inner.parseable else None
        if _is_no_arg_short_cluster(token):
            idx += 1
            continue
        return None
    return None


def _unwrap_exec_wrapper(segment: Segment) -> tuple[Segment, ...]:
    """``command rm -rf /`` / ``env -i rm -rf /`` → segments of the inner command,
    so a deny rule on it still bites. Returns ``(segment,)`` unchanged when the
    segment is not a decomposable wrapper, or when its options can't be classified
    (then it's flagged at decision time instead — see ``_match_bash``).

    The inner command is the first token after the wrapper that is neither a known
    no-arg option nor (for ``env``) a ``NAME=value`` assignment. Decomposition
    recurses, so stacked wrappers (``command nice rm -rf /``) fully unwrap.
    """
    if not segment.argv:
        return (segment,)
    name = basename(segment.argv[0])
    if name == "eval":
        # ``eval`` joins its args and executes the result as a command — re-parse
        # the joined string like a ``-c`` wrapper. If it isn't statically parseable
        # (e.g. ``eval "$cmd"``), leave it intact for decision-time flagging.
        if len(segment.argv) < 2:
            return (segment,)
        inner = parse_pipeline(" ".join(segment.argv[1:]))
        return inner.segments if inner.parseable else (segment,)
    no_arg = _EXEC_WRAPPER_NO_ARG_OPTS.get(name)
    if no_arg is None:
        return (segment,)
    if is_command_lookup(segment):
        return (segment,)  # `command -v/-V X` resolves X without running it
    argv = segment.argv
    idx = 1
    while idx < len(argv):
        token = argv[idx]
        if token == "--":
            idx += 1
            break
        if basename(argv[0]) == "env" and _ENV_ASSIGNMENT_RE.match(token):
            idx += 1
            continue
        if token.startswith("-") and len(token) > 1:
            if all(ch in no_arg for ch in token[1:]):
                idx += 1
                continue
            return (segment,)  # arg-taking/unknown option — leave intact, flag later
        break
    if idx >= len(argv):
        return (segment,)  # wrapper with no inner command (bare ``env`` / ``command``)
    inner = Segment(argv[idx:], segment.redirects, segment.stdin_source, segment.stdin_dynamic)
    unwrapped = _unwrap_shell_c(inner)
    return unwrapped if unwrapped is not None else _unwrap_exec_wrapper(inner)


def is_command_lookup(segment: Segment) -> bool:
    """True for ``command -v X`` / ``command -V X`` — these resolve ``X`` (like
    ``which``) without executing it, so the inner command must not be decomposed
    and policed as if it ran."""
    if not segment.argv or basename(segment.argv[0]) != "command":
        return False
    for token in segment.argv[1:]:
        if token == "--" or not token.startswith("-"):
            return False
        if "v" in token[1:] or "V" in token[1:]:
            return True
    return False


def is_opaque_shell_command(segment: Segment) -> bool:
    """True iff ``segment`` is a shell wrapper (``bash``/``sh``/``zsh``) carrying a
    ``-c`` command flag that ``_unwrap_shell_c`` could not safely unwrap — the
    embedded command is hidden, so the segment cannot be analyzed.

    Unwrappable ``-c`` forms never reach a verdict as a wrapper segment (they were
    expanded into their inner segments upstream), so any ``-c``-bearing shell
    segment seen at decision time is one we declined to unwrap. Plain script /
    interactive invocations (``bash script.sh``, ``zsh -l``) carry no ``-c`` and
    stay NoOpinion.

    Cluster semantics matter: in a short-flag cluster a ``c`` only means the
    command flag if every preceding char is a no-arg flag. ``-Ocmdhist`` /
    ``-ocorrect`` are ``-O``/``-o`` with an *argument* that happens to contain
    ``c`` — not a ``-c`` command flag — so they don't count.
    """
    if not segment.argv or basename(segment.argv[0]) not in _SHELL_COMMANDS:
        return False
    for token in segment.argv[1:]:
        if token == "--":
            break
        if not token.startswith("-") or token.startswith("--"):
            continue
        for ch in token[1:]:
            if ch == "c":
                return True
            if ch not in _NO_ARG_SHELL_FLAGS:
                break  # an arg-taking/unknown flag consumes the rest of the cluster
    return False


def _node_contains_substitution(node: Node) -> bool:
    for child in node.children:
        if child.type in ("command_substitution", "process_substitution"):
            return True
        if _node_contains_substitution(child):
            return True
    return False


def _extract_substitution_segments(node: Node, source: bytes) -> Iterator[Segment]:
    """Find command/process substitutions in *node* and yield their inner commands as segments."""
    if node.type in ("command_substitution", "process_substitution"):
        for child in node.named_children:
            yield from _extract_segments(child, source)
        return
    for child in node.children:
        yield from _extract_substitution_segments(child, source)


def _build_redirect(node: Node, source: bytes) -> tuple[Redirect | None, tuple[str, ...], tuple[Segment, ...]]:
    """Return the redirect, extra positional words, and any inner substitution segments.

    tree-sitter-bash will absorb ``b.py`` from ``cmd a 2>/dev/null b.py`` into
    the redirect node as a second ``word`` child, even though bash treats
    ``b.py`` as argv to ``cmd``. We take the first opaque-argument node (see
    ``_OPAQUE_ARG_TYPES`` — covers bare words, quoted strings, and variable
    expansions like ``$SP``/``${SP}``/``$SP/file.log``) after the operator as
    the target and return the rest as spillover for the caller to re-attach to
    the surrounding command.

    A process-substitution target (``cat < <(rm -rf /)``) is not a file path —
    it's a pipe to a command that runs. The returned ``Redirect`` is ``None`` (no
    file write to police) and the substitution's inner commands are returned as
    segments so a deny rule on them still bites. A command-substitution target
    (``cmd > $(echo f)``), or one nested in a word (``cmd > out$(echo f)``,
    ``cmd > "$(echo f)"``), *is* a file path, but computed at runtime: it stays
    the (opaque) target so a write still asks, and its inner command is extracted.
    """
    fd: int | None = None
    op: str | None = None
    target: str | None = None
    extras: list[str] = []
    substitutions: list[Segment] = []
    for child in node.children:
        if child.type == "file_descriptor":
            fd = int(_node_text(child, source))
            continue
        if child.type in (">", ">>", "<", ">&", "&>", ">|", "&>>", "<&"):
            op = child.type
            continue
        if child.type == "process_substitution":
            substitutions.extend(_extract_substitution_segments(child, source))
            continue
        if child.type == "command_substitution" or _node_contains_substitution(child):
            # A command substitution (bare or nested in a string/concatenation
            # target word): the filename is runtime-computed and unknowable. Keep
            # it as the opaque target so a write still asks, and extract the inner
            # command so a deny rule on it still bites.
            substitutions.extend(_extract_substitution_segments(child, source))
            if target is None:
                target = _node_text(child, source)
            continue
        if child.is_named and child.type in _OPAQUE_ARG_TYPES:
            text = _argument_text(child, source)
            if target is None:
                target = text
            else:
                extras.append(text)
            continue
    if op is not None and target is None and substitutions:
        return None, tuple(extras), tuple(substitutions)
    if op is None or target is None:
        raise _UnsupportedShellError("redirect target unparseable")
    return Redirect(fd=fd, op=op, target=target, is_fd_dup=op in (">&", "<&")), tuple(extras), tuple(substitutions)


def _argument_text(node: Node, source: bytes) -> str:
    if node.type == "string":
        return _string_text(node, source)
    if node.type == "raw_string":
        # ``raw_string`` is a leaf in tree-sitter-bash (no named children); the
        # body lives in the unnamed bytes between the surrounding single quotes.
        text = _node_text(node, source)
        if len(text) >= 2 and text.startswith("'") and text.endswith("'"):
            return text[1:-1]
        return text
    if node.type == "ansi_c_string":
        # ``$'...'``: strip the ``$'`` prefix and trailing ``'``. Escape sequences
        # aren't interpreted — the literal content is sufficient for argv-prefix
        # rule matching, and not interpreting is the conservative choice.
        text = _node_text(node, source)
        if len(text) >= 3 and text.startswith("$'") and text.endswith("'"):
            return text[2:-1]
        return text
    if node.type == "word":
        # Outside quotes, bash removes a backslash and takes the next character
        # literally (``\rm`` -> ``rm``, ``--f\orce`` -> ``--force``) — the standard
        # alias-bypass idiom. argv-keyed rule matching must see the same string
        # bash's argv[0]/argv[n] would be, or a leading ``\`` silently defeats it.
        return _unescape_word(_node_text(node, source))
    if node.type in _OPAQUE_ARG_TYPES:
        return _node_text(node, source)
    raise _UnsupportedShellError(f"unsupported argument node {node.type!r}")


def _unescape_word(text: str) -> str:
    """Undo bash's outside-quotes backslash removal for a literal ``word`` token."""
    if "\\" not in text:
        return text
    out: list[str] = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            i += 2
            if nxt != "\n":  # backslash-newline is a line continuation: drop both
                out.append(nxt)
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _string_text(node: Node, source: bytes) -> str:
    # Slice between the quotes rather than joining named ``string_content``
    # children: tree-sitter leaves whitespace/newlines in unnamed gaps, and
    # joining children corrupts multiline ``python -c`` source. Apply bash's
    # limited double-quote backslash processing so argv reflects execution.
    text = _node_text(node, source)
    if len(text) < 2 or not text.startswith('"') or not text.endswith('"'):
        raise _UnsupportedShellError("malformed double-quoted string")
    body = text[1:-1]
    parts: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body) and body[index + 1] in '$`"\\\n':
            escaped = body[index + 1]
            if escaped != "\n":
                parts.append(escaped)
            index += 2
            continue
        parts.append(char)
        index += 1
    return "".join(parts)
def _node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode()
