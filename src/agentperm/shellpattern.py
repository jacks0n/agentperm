"""Shell pattern DSL: parser, argv normalizer, and matcher."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from .domain import (
    AnyRest,
    Disposition,
    FlagConstraint,
    NestedExecCapture,
    NestedShellCapture,
    OneOf,
    PathTerm,
    Segment,
    ShellPattern,
    SqlCapture,
    Word,
    basename,
)
from .sql.domain import CapturedSql, SqlCaptureKind, SqlOrigin

# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_NAMECHAR = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_DYNAMIC_SHELL_SQL = re.compile(r"`|(?<!\$)\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\}|\(|\(\()")
_ESCAPABLE = frozenset("*{},!?-()\\ ")
_CLOSER_FOR = {"{": "}", "(": ")"}
_OPENER_FOR = {"}": "{", ")": "("}


@dataclass(frozen=True)
class _RawToken:
    text: str
    start: int


def _tokenize(pattern: str) -> list[_RawToken]:
    from .errors import PolicyError

    tokens: list[_RawToken] = []
    i = 0
    length = len(pattern)
    while i < length:
        while i < length and pattern[i] in (" ", "\t"):
            i += 1
        if i >= length:
            break
        start = i
        delimiters: list[tuple[str, int]] = []
        chars: list[str] = []
        while i < length:
            ch = pattern[i]
            if ch == "\\" and i + 1 < length:
                escaped = pattern[i + 1]
                if escaped not in _ESCAPABLE:
                    raise PolicyError(f"unknown escape '\\{escaped}' at position {i}")
                chars.append(ch)
                chars.append(escaped)
                i += 2
                continue
            if ch in ("{", "("):
                delimiters.append((ch, i))
            elif ch in ("}", ")"):
                expected_opener = _OPENER_FOR[ch]
                if not delimiters:
                    raise PolicyError(f"unbalanced '{ch}' at position {i}")
                opener, opener_pos = delimiters.pop()
                if opener != expected_opener:
                    expected_closer = _CLOSER_FOR[opener]
                    raise PolicyError(
                        f"mismatched '{ch}' at position {i}: "
                        f"expected '{expected_closer}' for '{opener}' at position {opener_pos}"
                    )
            if ch in (" ", "\t") and not delimiters:
                break
            chars.append(ch)
            i += 1
        if delimiters:
            opener, opener_pos = delimiters[-1]
            raise PolicyError(f"unbalanced '{opener}' at position {opener_pos}")
        text = "".join(chars)
        if text:
            tokens.append(_RawToken(text, start))
    return tokens


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_glob(text: str) -> str:
    """Convert DSL text to an fnmatch glob, handling escapes in one pass.

    ``\\*`` → ``[*]`` (literal star), unescaped ``?`` → ``[?]``,
    and unescaped ``[`` → ``[[]``.
    """
    from .errors import PolicyError

    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            if i + 1 >= len(text):
                raise PolicyError("trailing backslash in pattern")
            nxt = text[i + 1]
            if nxt not in _ESCAPABLE:
                raise PolicyError(f"unknown escape '\\{nxt}' in pattern")
            if nxt == "*":
                out.append("[*]")
            elif nxt == "?":
                out.append("[?]")
            elif nxt == "[":
                out.append("[[]")
            else:
                out.append(nxt)
            i += 2
        elif ch == "?":
            out.append("[?]")
            i += 1
        elif ch == "[":
            out.append("[[]")
            i += 1
        elif ch in "{},!()":
            raise PolicyError(f"unescaped metacharacter {ch!r} in word")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _split_set_members(inner: str) -> list[str]:
    from .errors import PolicyError

    members: list[str] = []
    current: list[str] = []
    depth = 0
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == "\\" and i + 1 < len(inner):
            current.append(ch)
            current.append(inner[i + 1])
            i += 2
            continue
        if ch in ("{", "("):
            depth += 1
        elif ch in ("}", ")"):
            depth -= 1
        if ch == "," and depth == 0:
            members.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    members.append("".join(current).strip())
    for m in members:
        if not m:
            raise PolicyError("empty member in set")
    return members


def _expand_positional_alternation(text: str) -> tuple[str, ...]:
    """Expand embedded ``{a,b}`` groups into positional globs.

    Alternation is useful inside executable paths and other single argv tokens,
    for example ``.venv/bin/{pytest,ruff}`` or ``{foo,bar}/check``. Multiple
    groups form a Cartesian product. Escaped braces remain literal.
    """
    opener = -1
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "{":
            opener = i
            break
        i += 1

    if opener < 0:
        return (_to_glob(text),)

    depth = 0
    closer = -1
    i = opener
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                closer = i
                break
        i += 1

    # The tokenizer validates delimiter balance, so this is defensive only.
    if closer < 0:
        from .errors import PolicyError

        raise PolicyError(f"unbalanced '{{' at position {opener}")

    prefix = text[:opener]
    suffix = text[closer + 1 :]
    expanded: list[str] = []
    for member in _split_set_members(text[opener + 1 : closer]):
        expanded.extend(_expand_positional_alternation(prefix + member + suffix))
    return tuple(expanded)


def is_flag(text: str) -> bool:
    return text.startswith("-") and len(text) > 1


def validate_flag_name(name: str, position: int) -> None:
    from .errors import PolicyError

    if name.startswith("--"):
        body = name[2:]
    elif name.startswith("-"):
        body = name[1:]
    else:
        raise PolicyError(f"invalid flag name {name!r} at position {position}: must start with -")
    if not body:
        raise PolicyError(f"invalid flag name {name!r} at position {position}: empty after dashes")
    if name.startswith("---"):
        raise PolicyError(f"invalid flag name {name!r} at position {position}: too many dashes")
    for ch in body:
        if ch not in _NAMECHAR:
            raise PolicyError(f"invalid character {ch!r} in flag name {name!r} at position {position}")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_shell_pattern(pattern: str) -> ShellPattern:
    from .errors import PolicyError

    tokens = _tokenize(pattern)
    if not tokens:
        raise PolicyError("empty Shell() pattern")

    path_terms: list[PathTerm] = []
    flag_constraints: list[FlagConstraint] = []
    flag_sets: list[tuple[str, ...]] = []
    closed_flags = False
    exact = False
    value_flags: set[str] = set()
    has_only = False
    has_values = False
    has_open_wildcard = False
    sql_value_captures: list[tuple[str | None, tuple[str, ...]]] = []
    captures_stdin_sql = False
    stdin_sql_profile: str | None = None

    for token in tokens:
        text = token.text
        start = token.start

        # Step 1: strip leading sigil
        sigil: str | None = None
        remainder = text
        if text.startswith("!"):
            sigil = "!"
            remainder = text[1:]
        elif text.startswith("?"):
            sigil = "?"
            remainder = text[1:]

        if not remainder:
            raise PolicyError(f"bare '{sigil}' at position {start}")

        # Step 2: ... or !...
        if remainder == "...":
            if sigil == "?":
                raise PolicyError(f"'?...' is invalid at position {start}")
            if sigil == "!":
                exact = True
            else:
                path_terms.append(AnyRest())
            continue

        # A standalone ``--`` is the end-of-options separator, not a flag.
        # Preserve it as a positional term when the policy author spells it so
        # patterns can require the same boundary as the command.
        if remainder == "--":
            if sigil is not None:
                raise PolicyError(f"'{sigil}--' is invalid at position {start}")
            path_terms.append(Word("--"))
            continue

        is_sql, sql_profile = _sql_placeholder_profile(remainder)
        if is_sql:
            if sigil is not None:
                raise PolicyError(f"'{sigil}{remainder}' is invalid at position {start}")
            path_terms.append(SqlCapture(sql_profile))
            continue

        if remainder == "<SHELL>":
            if sigil is not None:
                raise PolicyError(f"'{sigil}<SHELL>' is invalid at position {start}")
            path_terms.append(NestedShellCapture())
            continue

        if remainder == "<EXEC>":
            if sigil is not None:
                raise PolicyError(f"'{sigil}<EXEC>' is invalid at position {start}")
            path_terms.append(NestedExecCapture())
            continue

        if remainder.startswith("stdin(") and remainder.endswith(")"):
            if sigil is not None or captures_stdin_sql:
                raise PolicyError(f"invalid or repeated stdin(...) at position {start}")
            is_sql, profile = _sql_placeholder_profile(remainder[6:-1])
            if not is_sql:
                raise PolicyError(f"stdin(...) requires <SQL> or <SQL:name> at position {start}")
            captures_stdin_sql = True
            stdin_sql_profile = profile
            continue

        if remainder.startswith("sqlvalues(") and remainder.endswith(")"):
            if sigil is not None:
                raise PolicyError(f"'{sigil}sqlvalues(...)' is invalid at position {start}")
            members = _split_set_members(remainder[10:-1])
            is_sql, profile = _sql_placeholder_profile(members[0])
            if not is_sql:
                raise PolicyError(f"sqlvalues(...) must begin with <SQL> or <SQL:name> at position {start}")
            flags = tuple(members[1:])
            if not flags:
                raise PolicyError(f"sqlvalues(...) requires at least one flag at position {start}")
            for flag in flags:
                if not is_flag(flag):
                    raise PolicyError(f"non-flag member {flag!r} in sqlvalues(...) at position {start}")
                validate_flag_name(flag, start)
                value_flags.add(flag)
            sql_value_captures.append((profile, flags))
            continue

        # Step 3: -* or !-*
        if remainder == "-*":
            if sigil == "?":
                raise PolicyError(f"'?-*' is invalid at position {start}")
            if sigil == "!":
                closed_flags = True
            else:
                has_open_wildcard = True
            continue

        # Step 4: only(...)
        if remainder.startswith("only(") and remainder.endswith(")"):
            if sigil is not None:
                raise PolicyError(f"'{sigil}only(...)' is invalid at position {start}")
            if has_only:
                raise PolicyError(f"only(...) appears more than once at position {start}")
            has_only = True
            inner = remainder[5:-1]
            members = _split_set_members(inner)
            for m in members:
                if not is_flag(m):
                    raise PolicyError(f"non-flag member {m!r} in only(...) at position {start}")
                validate_flag_name(m, start)
                flag_constraints.append(FlagConstraint(m, Disposition.Permitted))
            closed_flags = True
            continue

        # Step 5: values(...)
        if remainder.startswith("values(") and remainder.endswith(")"):
            if sigil is not None:
                raise PolicyError(f"'{sigil}values(...)' is invalid at position {start}")
            if has_values:
                raise PolicyError(f"values(...) appears more than once at position {start}")
            has_values = True
            inner = remainder[7:-1]
            members = _split_set_members(inner)
            for m in members:
                if not is_flag(m):
                    raise PolicyError(f"non-flag member {m!r} in values(...) at position {start}")
                validate_flag_name(m, start)
                value_flags.add(m)
            continue

        # Step 6: flag terms (-x, --flag, --flag=glob)
        if is_flag(remainder):
            atom = remainder
            value_glob: str | None = None
            if "=" in remainder:
                eq_pos = remainder.index("=")
                atom = remainder[:eq_pos]
                value_glob = _to_glob(remainder[eq_pos + 1:])
            validate_flag_name(atom, start)

            if value_glob is not None and sigil is not None:
                raise PolicyError(
                    f"value constraint on '{sigil}{atom}=' at position {start}: "
                    f"value matching is only supported on required flags"
                )

            if sigil == "!":
                flag_constraints.append(FlagConstraint(atom, Disposition.Forbidden))
            elif sigil == "?":
                flag_constraints.append(FlagConstraint(atom, Disposition.Permitted))
            else:
                flag_constraints.append(FlagConstraint(atom, Disposition.Required, value_glob))
                if value_glob is not None:
                    value_flags.add(atom)
            continue

        # Step 6: sets {a,b,c} or {--a,--b}
        if remainder.startswith("{") and remainder.endswith("}"):
            inner = remainder[1:-1]
            members = _split_set_members(inner)
            is_all_flags = all(is_flag(m) for m in members)
            is_all_positional = all(not is_flag(m) for m in members)

            if not is_all_flags and not is_all_positional:
                raise PolicyError(f"mixed flag/positional members in set at position {start}")

            if is_all_flags:
                for m in members:
                    validate_flag_name(m, start)
                if sigil == "!":
                    # !{--a,--b} = none may be present -> expand to individual Forbidden
                    for m in members:
                        flag_constraints.append(FlagConstraint(m, Disposition.Forbidden))
                elif sigil == "?":
                    # ?{--a,--b} = all permitted
                    for m in members:
                        flag_constraints.append(FlagConstraint(m, Disposition.Permitted))
                else:
                    # {--a,--b} = any-of required -> stored as flag_set
                    flag_sets.append(tuple(members))
            else:
                # Positional set
                if sigil == "?":
                    raise PolicyError(f"'?' on positional set at position {start}")
                globs = tuple(_to_glob(m) for m in members)
                path_terms.append(OneOf(globs, negated=(sigil == "!")))
            continue

        # Step 7: positional word
        if sigil == "?":
            raise PolicyError(f"'?' on positional term at position {start}")
        if sigil == "!":
            raise PolicyError(f"'!' on positional term {remainder!r} at position {start}")
        globs = _expand_positional_alternation(remainder)
        path_terms.append(Word(globs[0]) if len(globs) == 1 else OneOf(globs))

    # Post-parse validation
    if not path_terms:
        raise PolicyError("pattern must contain at least one command term")
    if closed_flags and has_open_wildcard:
        raise PolicyError("closed flag constraint contradicts explicit open flag wildcard '-*'")
    if any(isinstance(term, NestedExecCapture) for term in path_terms[:-1]):
        raise PolicyError("<EXEC> must be the final positional term")
    if any(isinstance(term, NestedExecCapture) for term in path_terms):
        if any(not isinstance(term, (Word, OneOf, NestedExecCapture)) for term in path_terms):
            raise PolicyError("<EXEC> requires a fixed positional prefix")
        if flag_constraints or flag_sets or value_flags:
            raise PolicyError("<EXEC> cannot be combined with outer option matching")

    return ShellPattern(
        raw=pattern,
        path=tuple(path_terms),
        flags=tuple(flag_constraints),
        flag_sets=tuple(flag_sets),
        closed_flags=closed_flags,
        exact=exact,
        value_flags=frozenset(value_flags),
        sql_value_captures=tuple(sql_value_captures),
        stdin_sql_profile=stdin_sql_profile,
        captures_stdin_sql=captures_stdin_sql,
    )


def _sql_placeholder_profile(text: str) -> tuple[bool, str | None]:
    if text == "<SQL>":
        return True, None
    if text.startswith("<SQL:") and text.endswith(">"):
        profile = text[5:-1]
        if profile and all(ch.isalnum() or ch in "_-" for ch in profile):
            return True, profile
    return False, None


# ---------------------------------------------------------------------------
# Argv normalizer
# ---------------------------------------------------------------------------


def split_and_normalize(
    argv: tuple[str, ...],
    value_flags: frozenset[str],
    *,
    known_flags: frozenset[str] = frozenset(),
    optional_operands: set[int] | None = None,
    preserve_double_dash: bool = False,
) -> tuple[list[str], set[str], dict[str, list[str | None]]]:
    """Split argv into operands and normalized flag atoms.

    Returns (operands, flag_atoms, flag_values).
    flag_values maps each atom to ALL values seen (for repeated options).
    """
    operands: list[str] = []
    flag_atoms: set[str] = set()
    flag_values: dict[str, list[str | None]] = {}

    def short_value_prefix(arg: str) -> str | None:
        """Return the longest declared short option prefix with an attached value."""
        candidates = (
            atom
            for atom in value_flags
            if atom.startswith("-")
            and not atom.startswith("--")
            and len(arg) > len(atom)
            and arg.startswith(atom)
        )
        return max(candidates, key=len, default=None)

    def preserve_consumed_flag(value: str) -> None:
        """Expose a flag-looking value to constraints using canonical flag atoms."""
        if value in ("-", "--") or not value.startswith("-"):
            return
        if value.startswith("--"):
            flag_atoms.add(value.split("=", 1)[0])
            return
        prefix = short_value_prefix(value)
        if prefix is not None:
            flag_atoms.add(prefix)
            return
        flag_atoms.update(f"-{ch}" for ch in value[1:])

    def attached_value(value: str) -> str:
        """Normalize quotes retained inside a shell ``--flag='value'`` word."""
        if len(value) >= 2 and value[0] in "'\"" and value[-1] == value[0]:
            return value[1:-1]
        return value

    if not argv:
        return operands, flag_atoms, flag_values

    operands.append(argv[0])

    past_double_dash = False
    previous_unknown_flag = False
    i = 1
    while i < len(argv):
        arg = argv[i]

        if past_double_dash:
            operands.append(arg)
            previous_unknown_flag = False
            i += 1
            continue

        if arg == "--":
            if preserve_double_dash:
                operands.append(arg)
            past_double_dash = True
            previous_unknown_flag = False
            i += 1
            continue

        # Bare - is an operand (stdin convention)
        if arg == "-" or not arg.startswith("-"):
            operands.append(arg)
            if previous_unknown_flag and optional_operands is not None:
                optional_operands.add(len(operands) - 1)
            previous_unknown_flag = False
            i += 1
            continue

        # Long flag
        if arg.startswith("--"):
            if "=" in arg:
                eq_pos = arg.index("=")
                atom = arg[:eq_pos]
                flag_atoms.add(atom)
                flag_values.setdefault(atom, []).append(attached_value(arg[eq_pos + 1:]))
                previous_unknown_flag = False
            else:
                flag_atoms.add(arg)
                # Declared value flag: consume next token as value
                if arg in value_flags and i + 1 < len(argv):
                    i += 1
                    consumed = argv[i]
                    # A separate value that looks like another option is ambiguous.
                    # Preserve its atoms for deny/closed checks and fail value-glob
                    # constraints closed; callers can use ``--flag=-value`` when the
                    # leading dash is intentionally part of the value.
                    captured = None if is_flag(consumed) else consumed
                    flag_values.setdefault(arg, []).append(captured)
                    preserve_consumed_flag(consumed)
                elif arg in value_flags:
                    flag_values.setdefault(arg, []).append(None)
                previous_unknown_flag = arg not in value_flags and arg not in known_flags
            i += 1
            continue

        # A declared short value option is one atom. It accepts either a following
        # token (``-X GET``) or an attached value (``-XGET`` / ``-X=GET``).
        cluster = arg[1:]
        if arg in value_flags:
            flag_atoms.add(arg)
            if i + 1 < len(argv):
                i += 1
                consumed = argv[i]
                captured = None if is_flag(consumed) else consumed
                flag_values.setdefault(arg, []).append(captured)
                preserve_consumed_flag(consumed)
            else:
                flag_values.setdefault(arg, []).append(None)
            previous_unknown_flag = False
        else:
            consumed_value = False
            for j, ch in enumerate(cluster):
                atom = f"-{ch}"
                flag_atoms.add(atom)
                if atom in value_flags:
                    rest = cluster[j + 1:]
                    if rest:
                        if rest.startswith("="):
                            rest = rest[1:]
                        flag_values.setdefault(atom, []).append(attached_value(rest))
                    elif i + 1 < len(argv):
                        i += 1
                        consumed = argv[i]
                        captured = None if is_flag(consumed) else consumed
                        flag_values.setdefault(atom, []).append(captured)
                        preserve_consumed_flag(consumed)
                    else:
                        flag_values.setdefault(atom, []).append(None)
                    consumed_value = True
                    break
            previous_unknown_flag = False if consumed_value else not {f"-{ch}" for ch in cluster}.issubset(known_flags)
        i += 1

    return operands, flag_atoms, flag_values


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------


def _match_path(
    path: tuple[PathTerm, ...],
    operands: list[str],
    optional_operands: frozenset[int] = frozenset(),
) -> set[int]:
    """Return the set of operand counts the path can consume."""
    memo: dict[tuple[int, int], frozenset[int]] = {}

    def rec(pi: int, oi: int) -> frozenset[int]:
        key = (pi, oi)
        if key in memo:
            return memo[key]

        if pi >= len(path):
            result = rec(pi, oi + 1) if oi in optional_operands else frozenset({oi})
            memo[key] = result
            return result

        term = path[pi]
        skipped = rec(pi, oi + 1) if oi in optional_operands else frozenset()
        if isinstance(term, AnyRest):
            parts: set[int] = set()
            for skip in range(len(operands) - oi + 1):
                parts |= rec(pi + 1, oi + skip)
            result = frozenset(parts) | skipped
            memo[key] = result
            return result

        if isinstance(term, NestedExecCapture):
            result = frozenset({len(operands)}) if oi < len(operands) else frozenset()
            memo[key] = result
            return result

        if oi >= len(operands):
            memo[key] = frozenset()
            return frozenset()

        def matches_glob(glob: str) -> bool:
            # Bare executable names match by basename for portability. An
            # explicitly path-qualified pattern opts into matching argv[0]
            # itself, which permits rules such as
            # ``.venv/bin/{pytest,ruff,basedpyright}``.
            actual = operands[oi] if oi != 0 or "/" in glob else basename(operands[oi])
            return fnmatch.fnmatch(actual, glob)

        if isinstance(term, (SqlCapture, NestedShellCapture)):
            matched = rec(pi + 1, oi + 1)
            result = matched | skipped
        elif isinstance(term, Word):
            matched = rec(pi + 1, oi + 1) if matches_glob(term.glob) else frozenset()
            result = matched | skipped
        elif isinstance(term, OneOf):
            matches = any(matches_glob(g) for g in term.globs)
            hit = matches if not term.negated else not matches
            matched = rec(pi + 1, oi + 1) if hit else frozenset()
            result = matched | skipped
        else:
            result = skipped

        memo[key] = result
        return result

    return set(rec(0, 0))


def match_shell_pattern(
    pattern: ShellPattern,
    segment: Segment,
    *,
    ambiguous_option_values: bool = False,
) -> bool:
    if not segment.argv:
        return False

    optional_operands: set[int] | None = set() if ambiguous_option_values else None
    known_flags = {constraint.atom for constraint in pattern.flags}
    for group in pattern.flag_sets:
        known_flags.update(group)
    preserve_double_dash = any(
        isinstance(term, Word) and term.glob == "--" for term in pattern.path
    )
    operands, flag_atoms, flag_values = split_and_normalize(
        segment.argv,
        pattern.value_flags,
        known_flags=frozenset(known_flags),
        optional_operands=optional_operands,
        preserve_double_dash=preserve_double_dash,
    )

    # Positional path matching
    consumable = _match_path(pattern.path, operands, frozenset(optional_operands or ()))
    if pattern.exact:
        if len(operands) not in consumable:
            return False
    else:
        if not any(c <= len(operands) for c in consumable):
            return False

    # Individual flag constraints
    for c in pattern.flags:
        if c.disp is Disposition.Required:
            if c.atom not in flag_atoms:
                return False
            if c.value_glob is not None:
                vals = flag_values.get(c.atom)
                if vals is None or not all(
                    v is not None and fnmatch.fnmatch(v, c.value_glob) for v in vals
                ):
                    return False
        elif c.disp is Disposition.Forbidden:
            if c.atom in flag_atoms:
                return False

    # Flag any-of sets
    for group in pattern.flag_sets:
        if not any(atom in flag_atoms for atom in group):
            return False

    # Closed flag set
    if pattern.closed_flags:
        permitted: set[str] = set()
        for c in pattern.flags:
            if c.disp is not Disposition.Forbidden:
                permitted.add(c.atom)
        for group in pattern.flag_sets:
            permitted.update(group)
        if any(atom not in permitted for atom in flag_atoms):
            return False

    return True


@dataclass(frozen=True)
class ShellPatternMatch:
    sql: tuple[CapturedSql, ...]
    nested_shell: tuple[str, ...]
    nested_exec: tuple[tuple[str, ...], ...]


def match_shell_pattern_details(
    pattern: ShellPattern,
    segment: Segment,
    *,
    ambiguous_option_values: bool = False,
) -> ShellPatternMatch | None:
    """Match argv and return semantic values captured by the pattern."""
    if not match_shell_pattern(pattern, segment, ambiguous_option_values=ambiguous_option_values):
        return None
    operands, _, flag_values = split_and_normalize(segment.argv, pattern.value_flags)
    sql: list[CapturedSql] = []
    nested_shell: list[str] = []
    nested_exec: list[tuple[str, ...]] = []

    # Capturing patterns are intentionally deterministic: a gap before a capture
    # consumes the smallest prefix that permits the suffix to match.
    oi = 0
    for index, term in enumerate(pattern.path):
        if isinstance(term, AnyRest):
            remaining = len(pattern.path) - index - 1
            oi = max(oi, len(operands) - remaining)
        elif isinstance(term, NestedExecCapture):
            nested_exec.append(segment.argv[len(pattern.path) - 1 :])
            oi = len(operands)
        elif isinstance(term, SqlCapture):
            if oi >= len(operands):
                return None
            if _DYNAMIC_SHELL_SQL.search(operands[oi]):
                return None
            sql.append(CapturedSql(operands[oi], term.profile, SqlOrigin(SqlCaptureKind.Argument, f"argv[{oi}]")))
            oi += 1
        elif isinstance(term, NestedShellCapture):
            if oi >= len(operands):
                return None
            nested_shell.append(operands[oi])
            oi += 1
        else:
            oi += 1

    for profile, flags in pattern.sql_value_captures:
        captured_count = 0
        for flag in flags:
            for value in flag_values.get(flag, ()):
                if value is None:
                    return None
                if _DYNAMIC_SHELL_SQL.search(value):
                    return None
                sql.append(CapturedSql(value, profile, SqlOrigin(SqlCaptureKind.OptionValue, flag)))
                captured_count += 1
        if captured_count == 0:
            return None
    if pattern.captures_stdin_sql:
        if segment.stdin_source is None or segment.stdin_dynamic:
            return None
        if _DYNAMIC_SHELL_SQL.search(segment.stdin_source):
            return None
        sql.append(
            CapturedSql(
                segment.stdin_source,
                pattern.stdin_sql_profile,
                SqlOrigin(SqlCaptureKind.Stdin, "stdin"),
            )
        )
    return ShellPatternMatch(tuple(sql), tuple(nested_shell), tuple(nested_exec))
