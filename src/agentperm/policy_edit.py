"""Lossless, fail-closed edits to permission rules in JSON5 policy text.

The policy loader deliberately accepts JSON5, while ordinary JSON decoders discard
comments, quoting, ordering, and duplicate-key evidence.  This module therefore
uses a small concrete-syntax parser to locate spans, but delegates value semantics
to :func:`decode_jsonc` and rule semantics to :func:`parse_rule`.

Only the bytes needed for the requested permission edit are changed.  Existing
documents are never rendered wholesale.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .domain import JsonValue
from .errors import PolicyError
from .json_boundary import decode_jsonc
from .rules import serialize_rule_json

type PermissionDecision = Literal["allow", "ask", "deny"]


class PolicyEditError(PolicyError):
    """The document or requested lossless edit is unsafe or ambiguous."""


@dataclass(frozen=True)
class AddPermissionRule:
    decision: PermissionDecision
    rule: JsonValue


@dataclass(frozen=True)
class ReplacePermissionRule:
    decision: PermissionDecision
    old_rule: JsonValue
    new_rule: JsonValue


@dataclass(frozen=True)
class RemovePermissionRule:
    decision: PermissionDecision
    rule: JsonValue


type PermissionEdit = AddPermissionRule | ReplacePermissionRule | RemovePermissionRule


@dataclass(frozen=True)
class PermissionRuleEntry:
    """One permission-list value and its exact source span."""

    decision: PermissionDecision
    index: int
    value: JsonValue
    start: int
    end: int


@dataclass(frozen=True)
class _Member:
    key: str
    value: _Node
    comma_after: int | None


@dataclass(frozen=True)
class _Item:
    value: _Node
    comma_after: int | None


@dataclass(frozen=True)
class _Node:
    kind: Literal["object", "array", "scalar"]
    start: int
    end: int
    open_at: int | None = None
    close_at: int | None = None
    members: tuple[_Member, ...] = ()
    items: tuple[_Item, ...] = ()

    def member(self, key: str) -> _Member | None:
        return next((member for member in self.members if member.key == key), None)


def permission_rule_entries(text: str) -> tuple[PermissionRuleEntry, ...]:
    """Return permission rules with decoded values and exact source spans.

    Parsing the complete document also rejects duplicate keys anywhere, rather
    than allowing a JSON5 decoder's last-key-wins behavior to hide ambiguity.
    """

    root = _parse_document(text)
    permissions = _permission_object(root)
    if permissions is None:
        return ()
    entries: list[PermissionRuleEntry] = []
    for decision in _DECISIONS:
        member = permissions.member(decision)
        if member is None:
            continue
        array = _require_kind(member.value, "array", f"permissions.{decision} must be an array")
        for index, item in enumerate(array.items):
            entries.append(
                PermissionRuleEntry(
                    decision=decision,
                    index=index,
                    value=_decode_span(text, item.value),
                    start=item.value.start,
                    end=item.value.end,
                )
            )
    return tuple(entries)


def edit_permission_rules(text: str, edits: Sequence[PermissionEdit]) -> str:
    """Apply permission edits sequentially while preserving untouched bytes."""

    updated = text
    for edit in edits:
        if isinstance(edit, AddPermissionRule):
            updated = add_permission_rule(updated, edit.decision, edit.rule)
        elif isinstance(edit, ReplacePermissionRule):
            updated = replace_permission_rule(updated, edit.decision, edit.old_rule, edit.new_rule)
        else:
            updated = remove_permission_rule(updated, edit.decision, edit.rule)
    return updated


def add_permission_rule(text: str, decision: PermissionDecision, rule: JsonValue) -> str:
    """Add ``rule`` unless an equal value already exists in ``decision``."""

    _validate_decision(decision)
    canonical = _canonical_rule(rule)
    expected = _decode_canonical(canonical)
    root = _parse_document(text)
    permissions = _permission_object(root)
    if permissions is None:
        return _insert_permissions_object(text, root, decision, canonical)
    member = permissions.member(decision)
    if member is None:
        return _insert_decision_array(text, permissions, decision, canonical)
    array = _require_kind(member.value, "array", f"permissions.{decision} must be an array")
    matches = _matching_items(text, array, expected)
    if len(matches) > 1:
        raise PolicyEditError(f"permissions.{decision}: found {len(matches)} duplicate matching rules")
    if matches:
        return text
    return _append_array_value(text, array, canonical)


def replace_permission_rule(
    text: str,
    decision: PermissionDecision,
    old_rule: JsonValue,
    new_rule: JsonValue,
) -> str:
    """Replace exactly one semantically equal rule in ``decision``."""

    _validate_decision(decision)
    canonical = _canonical_rule(new_rule)
    replacement = _decode_canonical(canonical)
    array = _decision_array(_parse_document(text), decision, required=True)
    assert array is not None
    matches = _matching_items(text, array, old_rule)
    if len(matches) != 1:
        raise PolicyEditError(
            f"permissions.{decision}: expected one matching rule to replace, found {len(matches)}"
        )
    replacement_matches = _matching_items(text, array, replacement)
    if any(item is not matches[0] for item in replacement_matches):
        raise PolicyEditError(f"permissions.{decision}: replacement rule already exists")
    target = matches[0].value
    return text[: target.start] + canonical + text[target.end :]


def remove_permission_rule(text: str, decision: PermissionDecision, rule: JsonValue) -> str:
    """Remove exactly one semantically equal rule from ``decision``."""

    _validate_decision(decision)
    array = _decision_array(_parse_document(text), decision, required=True)
    assert array is not None
    matches = _matching_items(text, array, rule)
    if len(matches) != 1:
        raise PolicyEditError(
            f"permissions.{decision}: expected one matching rule to remove, found {len(matches)}"
        )
    target = matches[0]
    index = array.items.index(target)
    spans = [(target.value.start, target.value.end)]
    if target.comma_after is not None:
        spans.append((target.comma_after, target.comma_after + 1))
    elif index > 0:
        previous = array.items[index - 1]
        if previous.comma_after is None:
            raise PolicyEditError(f"permissions.{decision}: ambiguous array separators")
        spans.append((previous.comma_after, previous.comma_after + 1))
    return _remove_spans(text, spans)


_DECISIONS: tuple[PermissionDecision, ...] = ("allow", "ask", "deny")


def _validate_decision(decision: str) -> None:
    if decision not in _DECISIONS:
        raise PolicyEditError(f"unsupported permission decision {decision!r}")


def _canonical_rule(rule: JsonValue) -> str:
    try:
        return serialize_rule_json(rule)
    except PolicyError as error:
        raise PolicyEditError(str(error)) from error


def _decode_canonical(canonical: str) -> JsonValue:
    try:
        return decode_jsonc(canonical)
    except Exception as error:  # pragma: no cover - generated by our strict encoder
        raise PolicyEditError(f"internal error encoding permission rule: {error}") from error


def _encode(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _semantic_key(value: JsonValue) -> str:
    return _encode(value)


def _decode_span(text: str, node: _Node) -> JsonValue:
    try:
        return decode_jsonc(text[node.start : node.end])
    except Exception as error:
        raise PolicyEditError(f"invalid JSON5 value at offset {node.start}: {error}") from error


def _matching_items(text: str, array: _Node, expected: JsonValue) -> list[_Item]:
    key = _semantic_key(expected)
    return [item for item in array.items if _semantic_key(_decode_span(text, item.value)) == key]


def _remove_spans(text: str, spans: list[tuple[int, int]]) -> str:
    updated = text
    for start, end in sorted(spans, reverse=True):
        updated = updated[:start] + updated[end:]
    return updated


def _permission_object(root: _Node) -> _Node | None:
    root = _require_kind(root, "object", "policy document must be an object")
    member = root.member("permissions")
    if member is None:
        return None
    permissions = _require_kind(member.value, "object", "permissions must be an object")
    for decision in _DECISIONS:
        decision_member = permissions.member(decision)
        if decision_member is not None:
            _require_kind(decision_member.value, "array", f"permissions.{decision} must be an array")
    return permissions


def _decision_array(root: _Node, decision: PermissionDecision, *, required: bool) -> _Node | None:
    permissions = _permission_object(root)
    if permissions is None:
        if required:
            raise PolicyEditError("policy has no permissions object")
        return None
    member = permissions.member(decision)
    if member is None:
        if required:
            raise PolicyEditError(f"policy has no permissions.{decision} array")
        return None
    return _require_kind(member.value, "array", f"permissions.{decision} must be an array")


def _require_kind(node: _Node, kind: str, message: str) -> _Node:
    if node.kind != kind:
        raise PolicyEditError(message)
    return node


def _insert_permissions_object(text: str, root: _Node, decision: PermissionDecision, rule: str) -> str:
    root = _require_kind(root, "object", "policy document must be an object")
    root_indent = _line_indent(text, root.start)
    member_indent = root_indent + "  "
    newline = _newline(text)
    body = (
        f'"permissions": {{{newline}'
        f'{member_indent}  "{decision}": [{newline}'
        f"{member_indent}    {rule}{newline}"
        f"{member_indent}  ]{newline}"
        f"{member_indent}}}"
    )
    return _append_object_member(text, root, body, member_indent)


def _insert_decision_array(text: str, permissions: _Node, decision: PermissionDecision, rule: str) -> str:
    object_indent = _line_indent(text, permissions.start)
    member_indent = object_indent + "  "
    newline = _newline(text)
    body = f'"{decision}": [{newline}{member_indent}  {rule}{newline}{member_indent}]'
    return _append_object_member(text, permissions, body, member_indent)


def _append_object_member(text: str, obj: _Node, rendered: str, indent: str) -> str:
    close = _required_close(obj)
    multiline = "\n" in text[obj.start:close]
    newline = _newline(text)
    if not obj.members:
        if multiline:
            insertion_at = _closing_indent_start(text, close)
            prefix = _insertion_prefix(text, insertion_at, close, newline)
            return text[:insertion_at] + prefix + indent + rendered + newline + text[insertion_at:]
        return text[:close] + rendered + text[close:]

    comma_at = _trailing_comma(obj)
    updated = text
    if comma_at is None:
        last = obj.members[-1].value
        updated = text[: last.end] + "," + text[last.end :]
        close += 1
    if multiline:
        insertion_at = _closing_indent_start(updated, close)
        prefix = _insertion_prefix(updated, insertion_at, close, newline)
        return updated[:insertion_at] + prefix + indent + rendered + newline + updated[insertion_at:]
    spacer = "" if close > 0 and updated[close - 1].isspace() else " "
    return updated[:close] + spacer + rendered + updated[close:]


def _append_array_value(text: str, array: _Node, rendered: str) -> str:
    close = _required_close(array)
    multiline = "\n" in text[array.start:close]
    newline = _newline(text)
    indent = _array_item_indent(text, array)
    updated = text
    if array.items and _trailing_comma(array) is None:
        last = array.items[-1].value
        updated = text[: last.end] + "," + text[last.end :]
        close += 1
    if multiline:
        insertion_at = _closing_indent_start(updated, close)
        prefix = _insertion_prefix(updated, insertion_at, close, newline)
        return updated[:insertion_at] + prefix + indent + rendered + newline + updated[insertion_at:]
    spacer = "" if not array.items or (close > 0 and updated[close - 1].isspace()) else " "
    return updated[:close] + spacer + rendered + updated[close:]


def _array_item_indent(text: str, array: _Node) -> str:
    if array.items:
        return _line_indent(text, array.items[0].value.start)
    return _line_indent(text, _required_close(array)) + "  "


def _trailing_comma(node: _Node) -> int | None:
    if node.kind == "array" and node.items:
        return node.items[-1].comma_after
    if node.kind == "object" and node.members:
        return node.members[-1].comma_after
    return None


def _required_close(node: _Node) -> int:
    if node.close_at is None:
        raise PolicyEditError("container has no closing delimiter")
    return node.close_at


def _line_indent(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    prefix = text[line_start:offset]
    return prefix[: len(prefix) - len(prefix.lstrip(" \t"))]


def _newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def _insertion_prefix(text: str, insertion_at: int, close: int, newline: str) -> str:
    if insertion_at < close or insertion_at == 0 or text[insertion_at - 1] in "\r\n":
        return ""
    return newline


def _closing_indent_start(text: str, close: int) -> int:
    line_start = text.rfind("\n", 0, close) + 1
    if text[line_start:close].strip():
        return close
    return line_start


def _parse_document(text: str) -> _Node:
    try:
        decoded = decode_jsonc(text)
    except Exception as error:
        raise PolicyEditError(f"invalid JSON5 policy: {error}") from error
    if not isinstance(decoded, dict):
        raise PolicyEditError("policy document must be an object")
    parser = _Parser(text)
    node = parser.parse_value()
    parser.skip_trivia()
    if parser.position != len(text):
        raise PolicyEditError(f"unexpected content at offset {parser.position}")
    return node


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0

    def parse_value(self) -> _Node:
        self.skip_trivia()
        start = self.position
        if start >= len(self.text):
            raise PolicyEditError("expected a JSON5 value at end of document")
        character = self.text[start]
        if character == "{":
            return self._parse_object()
        if character == "[":
            return self._parse_array()
        if character in "\"'":
            self._scan_string()
        else:
            self._scan_scalar()
        return _Node("scalar", start, self.position)

    def _parse_object(self) -> _Node:
        start = self.position
        self.position += 1
        members: list[_Member] = []
        keys: set[str] = set()
        self.skip_trivia()
        if self._take("}"):
            return _Node("object", start, self.position, start, self.position - 1)
        while True:
            self.skip_trivia()
            key_start = self.position
            if self._peek() in "\"'":
                self._scan_string()
            else:
                self._scan_key()
            key_source = self.text[key_start : self.position]
            key = self._decode_key(key_source, key_start)
            if key in keys:
                raise PolicyEditError(f"duplicate object key {key!r} at offset {key_start}")
            keys.add(key)
            self.skip_trivia()
            self._expect(":")
            value = self.parse_value()
            self.skip_trivia()
            if self._take("}"):
                members.append(_Member(key, value, None))
                return _Node("object", start, self.position, start, self.position - 1, tuple(members))
            comma = self.position
            self._expect(",")
            members.append(_Member(key, value, comma))
            self.skip_trivia()
            if self._take("}"):
                return _Node("object", start, self.position, start, self.position - 1, tuple(members))

    def _parse_array(self) -> _Node:
        start = self.position
        self.position += 1
        items: list[_Item] = []
        self.skip_trivia()
        if self._take("]"):
            return _Node("array", start, self.position, start, self.position - 1)
        while True:
            value = self.parse_value()
            self.skip_trivia()
            if self._take("]"):
                items.append(_Item(value, None))
                return _Node("array", start, self.position, start, self.position - 1, items=tuple(items))
            comma = self.position
            self._expect(",")
            items.append(_Item(value, comma))
            self.skip_trivia()
            if self._take("]"):
                return _Node("array", start, self.position, start, self.position - 1, items=tuple(items))

    def skip_trivia(self) -> None:
        while self.position < len(self.text):
            if self.text[self.position].isspace():
                self.position += 1
                continue
            if self.text.startswith("//", self.position):
                newline = self.text.find("\n", self.position + 2)
                self.position = len(self.text) if newline < 0 else newline + 1
                continue
            if self.text.startswith("/*", self.position):
                closing = self.text.find("*/", self.position + 2)
                if closing < 0:
                    raise PolicyEditError(f"unterminated comment at offset {self.position}")
                self.position = closing + 2
                continue
            return

    def _scan_string(self) -> None:
        quote = self._peek()
        start = self.position
        self.position += 1
        escaped = False
        while self.position < len(self.text):
            character = self.text[self.position]
            self.position += 1
            if escaped:
                if character == "\r" and self._peek() == "\n":
                    self.position += 1
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                return
            elif character in "\r\n":
                raise PolicyEditError(f"unterminated string at offset {start}")
        raise PolicyEditError(f"unterminated string at offset {start}")

    def _scan_scalar(self) -> None:
        start = self.position
        while self.position < len(self.text):
            character = self.text[self.position]
            if character.isspace() or character in ",]}":
                break
            if self.text.startswith("//", self.position) or self.text.startswith("/*", self.position):
                break
            self.position += 1
        if self.position == start:
            raise PolicyEditError(f"expected a value at offset {start}")

    def _scan_key(self) -> None:
        start = self.position
        while self.position < len(self.text):
            character = self.text[self.position]
            if character.isspace() or character == ":":
                break
            if self.text.startswith("//", self.position) or self.text.startswith("/*", self.position):
                break
            if character in "{},[]":
                raise PolicyEditError(f"invalid unquoted key at offset {start}")
            self.position += 1
        if self.position == start:
            raise PolicyEditError(f"expected an object key at offset {start}")

    def _decode_key(self, source: str, offset: int) -> str:
        try:
            decoded = decode_jsonc("{" + source + ":null}")
        except Exception as error:
            raise PolicyEditError(f"invalid object key at offset {offset}: {error}") from error
        if not isinstance(decoded, dict) or len(decoded) != 1:
            raise PolicyEditError(f"invalid object key at offset {offset}")
        return next(iter(decoded))

    def _peek(self) -> str:
        return self.text[self.position] if self.position < len(self.text) else ""

    def _take(self, expected: str) -> bool:
        if self._peek() != expected:
            return False
        self.position += 1
        return True

    def _expect(self, expected: str) -> None:
        if not self._take(expected):
            raise PolicyEditError(f"expected {expected!r} at offset {self.position}")
