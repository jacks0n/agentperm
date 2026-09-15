"""Literal shell-word decoding at the Tree-sitter boundary."""

from tree_sitter import Node


class UnsupportedShellError(Exception):
    pass


OPAQUE_ARG_TYPES = frozenset(
    {
        "word",
        "number",
        "string",
        "raw_string",
        "simple_expansion",
        "expansion",
        "concatenation",
        "arithmetic_expansion",
        "ansi_c_string",
        "translated_string",
    }
)


def argument_text(node: Node, source: bytes) -> str:
    if node.type == "string":
        return string_text(node, source)
    if node.type == "raw_string":
        # ``raw_string`` is a leaf in tree-sitter-bash (no named children); the
        # body lives in the unnamed bytes between the surrounding single quotes.
        text = node_text(node, source)
        if len(text) >= 2 and text.startswith("'") and text.endswith("'"):
            return text[1:-1]
        return text
    if node.type == "ansi_c_string":
        # ``$'...'``: strip the ``$'`` prefix and trailing ``'``. Escape sequences
        # aren't interpreted — the literal content is sufficient for argv-prefix
        # rule matching, and not interpreting is the conservative choice.
        text = node_text(node, source)
        if len(text) >= 3 and text.startswith("$'") and text.endswith("'"):
            return text[2:-1]
        return text
    if node.type == "word":
        # Outside quotes, bash removes a backslash and takes the next character
        # literally (``\rm`` -> ``rm``, ``--f\orce`` -> ``--force``) — the standard
        # alias-bypass idiom. argv-keyed rule matching must see the same string
        # bash's argv[0]/argv[n] would be, or a leading ``\`` silently defeats it.
        return unescape_word(node_text(node, source))
    if node.type in OPAQUE_ARG_TYPES:
        return node_text(node, source)
    raise UnsupportedShellError(f"unsupported argument node {node.type!r}")


def unescape_word(text: str) -> str:
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


def string_text(node: Node, source: bytes) -> str:
    # Slice between the quotes rather than joining named ``string_content``
    # children: tree-sitter leaves whitespace/newlines in unnamed gaps, and
    # joining children corrupts multiline ``python -c`` source. Apply bash's
    # limited double-quote backslash processing so argv reflects execution.
    text = node_text(node, source)
    if len(text) < 2 or not text.startswith('"') or not text.endswith('"'):
        raise UnsupportedShellError("malformed double-quoted string")
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


def node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode()
