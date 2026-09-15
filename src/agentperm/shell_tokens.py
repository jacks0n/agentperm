"""Shell-pattern tokens, escaping, and flag vocabulary."""

from dataclasses import dataclass

_NAMECHAR = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_ESCAPABLE = frozenset("*{},!?-()\\ ")
_CLOSER_FOR = {"{": "}", "(": ")"}
_OPENER_FOR = {"}": "{", ")": "("}


@dataclass(frozen=True)
class RawToken:
    text: str
    start: int


def tokenize(pattern: str) -> list[RawToken]:
    from .errors import PolicyError

    tokens: list[RawToken] = []
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
            tokens.append(RawToken(text, start))
    return tokens


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def to_glob(text: str) -> str:
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


def split_set_members(inner: str) -> list[str]:
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


def expand_positional_alternation(text: str) -> tuple[str, ...]:
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
        return (to_glob(text),)

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
    for member in split_set_members(text[opener + 1 : closer]):
        expanded.extend(expand_positional_alternation(prefix + member + suffix))
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
