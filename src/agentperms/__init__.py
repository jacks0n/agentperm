"""Permission policy mediator for Claude Code, Codex, OpenCode, and Gemini CLI.

The user maintains one policy file (``~/.agent-permissions.jsonc``); this module
is called by agent hooks configured outside the bridge.

Module layout:
    Domain        — Decision, Verdict, Rule, Request, Pipeline, Segment, Policy
    Shell         — Tree-sitter Bash -> Pipeline
    Rule I/O      — string/dict <-> Rule
    Policy I/O    — file <-> Policy
    Adapter       — AgentAdapter ABC + Claude/Codex/Opencode/Gemini implementations
    CLI           — import, check, edit
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import ClassVar

import pyjson5
import tomlkit
import tree_sitter_bash
from tree_sitter import Language, Node, Parser

POLICY_FILENAME = ".agent-permissions.jsonc"


# -----------------------------------------------------------------------------
# JSON value model (system-boundary type)
# -----------------------------------------------------------------------------

type JsonScalar = str | int | float | bool | None
# Sequence/Mapping (covariant) — so list[str] ⊆ JsonValue without dict-invariance grief.
type JsonValue = JsonScalar | Sequence["JsonValue"] | Mapping[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]
type JsonArray = list[JsonValue]
def narrow_json(value: object) -> JsonValue:
    """Convert untyped JSON output (json.load / pyjson5.decode) into a typed JsonValue.

    Anything outside the JSON value set raises ``PolicyError`` — fail-loud at the boundary
    so downstream code never sees ``object`` or ``Any``.
    """
    if value is None:
        return None
    if isinstance(value, bool):  # check before int — bool is a subclass of int
        return value
    if isinstance(value, (str, int, float)):
        return value
    if isinstance(value, list):
        return [narrow_json(v) for v in value]
    if isinstance(value, dict):
        result: JsonObject = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise PolicyError(f"non-string JSON key: {k!r}")
            result[k] = narrow_json(v)
        return result
    raise PolicyError(f"unsupported JSON value: {type(value).__name__}")


# -----------------------------------------------------------------------------
# Domain
# -----------------------------------------------------------------------------


class Decision(StrEnum):
    Allow = "allow"
    Ask = "ask"
    Deny = "deny"
    NoOpinion = "no-opinion"


class AgentName(StrEnum):
    Auto = "auto"
    Claude = "claude"
    Codex = "codex"
    Opencode = "opencode"
    Gemini = "gemini"


class InstallMode(StrEnum):
    """Where ``install`` writes hook entries.

    ``Rulesync`` — merge into ``~/.rulesync/hooks.json``; user re-runs rulesync to
    materialise per-tool configs. ``Direct`` — merge straight into per-tool configs
    (Claude ``settings.json``, Codex ``hooks.json``+``config.toml``, Gemini ``settings.json``).
    OpenCode plugin is always written directly regardless of mode (rulesync has no
    schema for ``permission.ask`` plugins).
    """

    Rulesync = "rulesync"
    Direct = "direct"


_STRICTNESS = {Decision.Deny: 3, Decision.Ask: 2, Decision.Allow: 1, Decision.NoOpinion: 0}


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    rationale: str


@dataclass(frozen=True)
class Redirect:
    fd: int | None
    op: str
    target: str
    is_fd_dup: bool  # 2>&1, 1>&2 — duplicates fd, doesn't write to a file


@dataclass(frozen=True)
class Segment:
    argv: tuple[str, ...]
    redirects: tuple[Redirect, ...]


@dataclass(frozen=True)
class Pipeline:
    segments: tuple[Segment, ...]
    parseable: bool
    unparseable_reason: str = ""


class Request:
    """Marker base for ShellRequest / ToolRequest. Sum-typed via isinstance dispatch."""


@dataclass(frozen=True)
class ShellRequest(Request):
    pipeline: Pipeline


@dataclass(frozen=True)
class ToolRequest(Request):
    tool: str


# Permission rules are a sum type. Each rule knows how to match its kind of request.


class Rule(ABC):
    @abstractmethod
    def serialize(self) -> str | JsonObject: ...


@dataclass(frozen=True)
class BashCommand(Rule):
    """``Bash(git status:*)`` — matches a bash segment whose argv starts with the prefix."""

    prefix: tuple[str, ...]

    def matches(self, segment: Segment) -> bool:
        if not self.prefix or len(segment.argv) < len(self.prefix):
            return False
        head = tuple(_basename(a) if i == 0 else a for i, a in enumerate(segment.argv[: len(self.prefix)]))
        return head == self.prefix

    def serialize(self) -> str:
        return f"Bash({' '.join(self.prefix)}:*)"


@dataclass(frozen=True)
class BashOption(Rule):
    """Structured: matches bash segments that invoke a command with a specific option."""

    commands: frozenset[str]
    options: frozenset[str]
    rationale: str

    def matches(self, segment: Segment) -> bool:
        if not segment.argv:
            return False
        if _basename(segment.argv[0]) not in self.commands:
            return False
        return any(_arg_matches_option(arg, opt) for arg in segment.argv[1:] for opt in self.options)

    def serialize(self) -> JsonObject:
        return {
            "tool": "Bash",
            "command": sorted(self.commands),
            "when": {"hasOption": sorted(self.options)},
            "reason": self.rationale,
        }


@dataclass(frozen=True)
class NamedTool(Rule):
    """Tool name pattern: exact (``Read``), wildcard (``*``), or prefix (``mcp__memory__*``)."""

    pattern: str

    def matches(self, name: str) -> bool:
        if self.pattern in ("*", name):
            return True
        if self.pattern.endswith("*"):
            return name.startswith(self.pattern[:-1])
        return False

    def serialize(self) -> str:
        return self.pattern


def _basename(arg: str) -> str:
    return arg.rsplit("/", 1)[-1]


def _arg_matches_option(arg: str, option: str) -> bool:
    if arg == "--":
        return False
    if option.startswith("--"):
        return arg == option or arg.startswith(option + "=")
    if option.startswith("-"):
        short = option[1:]
        if not arg.startswith("-") or arg.startswith("--"):
            return False
        return short in arg[1:]
    return False


# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    deny: tuple[Rule, ...] = ()
    ask: tuple[Rule, ...] = ()
    allow: tuple[Rule, ...] = ()

    def decide(self, request: Request) -> Verdict:
        if isinstance(request, ShellRequest):
            return self._decide_shell(request.pipeline)
        if isinstance(request, ToolRequest):
            return self._decide_tool(request.tool)
        return Verdict(Decision.NoOpinion, "unrecognized request")

    def all_rules(self) -> Iterator[tuple[Decision, Rule]]:
        for rule in self.deny:
            yield Decision.Deny, rule
        for rule in self.ask:
            yield Decision.Ask, rule
        for rule in self.allow:
            yield Decision.Allow, rule

    def merged_with(self, other: Policy) -> Policy:
        def union(a: tuple[Rule, ...], b: tuple[Rule, ...]) -> tuple[Rule, ...]:
            seen: list[Rule] = list(a)
            for rule in b:
                if rule not in seen:
                    seen.append(rule)
            return tuple(seen)

        return Policy(
            deny=union(self.deny, other.deny),
            ask=union(self.ask, other.ask),
            allow=union(self.allow, other.allow),
        )

    def _decide_shell(self, pipeline: Pipeline) -> Verdict:
        if not pipeline.parseable:
            return Verdict(Decision.Ask, pipeline.unparseable_reason or "shell syntax not safely parseable")
        if not pipeline.segments:
            return Verdict(Decision.NoOpinion, "")
        verdicts = [self._decide_segment(seg) for seg in pipeline.segments]
        return aggregate(verdicts)

    def _decide_segment(self, segment: Segment) -> Verdict:
        return _stricter(_evaluate_redirects(segment.redirects), self._match_bash(segment))

    def _match_bash(self, segment: Segment) -> Verdict:
        for decision, rule in self.all_rules():
            if isinstance(rule, BashCommand | BashOption) and rule.matches(segment):
                rationale = rule.rationale if isinstance(rule, BashOption) else _format_rule(rule, decision)
                return Verdict(decision, rationale)
        argv0 = segment.argv[0] if segment.argv else "<empty>"
        return Verdict(Decision.NoOpinion, f"no rule matched {argv0!r}")

    def _decide_tool(self, name: str) -> Verdict:
        for decision, rule in self.all_rules():
            if isinstance(rule, NamedTool) and rule.matches(name):
                return Verdict(decision, _format_rule(rule, decision))
        return Verdict(Decision.NoOpinion, f"no rule matched {name!r}")


def _format_rule(rule: Rule, decision: Decision) -> str:
    return f"{decision.value} by rule {rule.serialize()!r}"


def _stricter(left: Verdict, right: Verdict) -> Verdict:
    if _STRICTNESS[left.decision] > _STRICTNESS[right.decision]:
        return left
    if _STRICTNESS[right.decision] > _STRICTNESS[left.decision]:
        return right
    # Tie on strictness: prefer the side with an informative rationale.
    return left if left.rationale else right


def aggregate(verdicts: list[Verdict]) -> Verdict:
    """Aggregate per-segment verdicts. Strictest wins; an unrecognized segment escalates Allow to Ask."""
    if not verdicts:
        return Verdict(Decision.NoOpinion, "")
    strictest = max(verdicts, key=lambda v: _STRICTNESS[v.decision])
    if strictest.decision is Decision.Allow:
        unknown = next((v for v in verdicts if v.decision is Decision.NoOpinion), None)
        if unknown is not None:
            return Verdict(Decision.Ask, f"compound includes unrecognized segment: {unknown.rationale}")
    return strictest


# -----------------------------------------------------------------------------
# Redirect policy (built-in; not user-tunable)
# -----------------------------------------------------------------------------


def _evaluate_redirects(redirects: Iterable[Redirect]) -> Verdict:
    for r in redirects:
        verdict = _evaluate_redirect(r)
        if verdict.decision is not Decision.NoOpinion:
            return verdict
    return Verdict(Decision.NoOpinion, "")


def _evaluate_redirect(r: Redirect) -> Verdict:
    if r.is_fd_dup:
        return Verdict(Decision.NoOpinion, "")
    if r.fd == 2 and r.op in (">", ">>") and r.target == "/dev/null":
        return Verdict(Decision.NoOpinion, "")
    if r.op in (">", ">>", "&>"):
        return Verdict(Decision.Ask, f"writes to {r.target!r}")
    if r.op == "<":
        return Verdict(Decision.NoOpinion, "")
    return Verdict(Decision.Ask, f"unrecognized redirection {r.op!r}")


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

# Subset valid as children of a ``string`` node (i.e. inside double quotes).
# ``concatenation`` doesn't appear here — strings are leaves in tree-sitter-bash.
_STRING_CHILD_TYPES = frozenset({
    "string_content", "simple_expansion", "expansion", "arithmetic_expansion",
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
    if node.type == "command":
        segment = _build_segment(node, source)
        unwrapped = _unwrap_shell_c(segment)
        if unwrapped is not None:
            yield from unwrapped
            return
        yield segment
        return
    if node.type == "redirected_statement":
        yield from _build_redirected_segment(node, source)
        return
    if node.type == "compound_statement":
        # ``(( … ))`` and ``{ …; }`` share this AST node — disambiguate by source prefix.
        # Arithmetic is a pure predicate (in-process state only); brace groups are
        # ordinary command lists wrapped in braces.
        if source[node.start_byte:node.start_byte + 2] == b"((":
            if _node_contains_substitution(node):
                raise _UnsupportedShellError("command/process substitution requires approval")
            yield Segment(("((",), ())
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
        # A substitution inside (e.g. ``[[ -f $(curl evil) ]]``) executes before
        # the predicate, so it must surface a prompt rather than be swallowed.
        if _node_contains_substitution(node):
            raise _UnsupportedShellError("command/process substitution requires approval")
        yield Segment(("[",), ())
        return
    if node.type == "declaration_command":
        # ``export FOO=bar`` / ``local`` / ``declare`` / ``readonly`` / ``typeset``.
        # tree-sitter parses these as their own node type, not as ``command``, so a
        # user ``Bash(export:*)`` rule would never match without explicit handling.
        # Yield a normal segment with the keyword as argv[0] and the assignments/
        # words as subsequent argv tokens.
        if _node_contains_substitution(node):
            raise _UnsupportedShellError("command/process substitution requires approval")
        if not node.children:
            raise _UnsupportedShellError("declaration_command missing keyword")
        argv: list[str] = [_node_text(node.children[0], source)]
        for child in node.named_children:
            argv.append(_node_text(child, source))
        yield Segment(tuple(argv), ())
        return
    if node.type in _CONTROL_FLOW_TYPES:
        for child in node.named_children:
            if child.type in _PATTERN_CHILD_TYPES:
                # Subjects/patterns are skipped from segment extraction, but
                # ``case foo$(curl evil) in …`` would still execute the
                # substitution before pattern matching. Reject anything carrying
                # a substitution rather than silently dropping it.
                if _node_contains_substitution(child):
                    raise _UnsupportedShellError("command/process substitution requires approval")
                continue
            yield from _extract_segments(child, source)
        return
    if node.type == "for_statement":
        # Covers ``for v in …`` and ``select v in …`` (same node). The iterable
        # list is opaque text; only the ``do_group`` body holds executable commands.
        # The iterable can still trigger substitutions (e.g. ``for f in $(curl
        # evil); do …; done``) which execute before the loop runs, so reject
        # any non-body child that carries a substitution.
        for child in node.named_children:
            if child.type == "do_group":
                yield from _extract_segments(child, source)
                continue
            if child.type == "variable_name":
                continue
            if child.type in ("command_substitution", "process_substitution") \
                    or _node_contains_substitution(child):
                raise _UnsupportedShellError("command/process substitution requires approval")
        return
    raise _UnsupportedShellError(f"unsupported shell node {node.type!r}")


def _build_segment(command_node: Node, source: bytes) -> Segment:
    argv: list[str] = []
    for child in command_node.named_children:
        if _node_contains_substitution(child):
            raise _UnsupportedShellError("command/process substitution requires approval")
        if child.type == "variable_assignment":
            # Tree-sitter marks leading ``FOO=bar`` env-assignment words as variable assignments;
            # they are not part of the executed command's argv.
            continue
        if child.type == "command_name":
            argv.append(_node_text(child, source))
            continue
        if child.type in _OPAQUE_ARG_TYPES:
            argv.append(_argument_text(child, source))
            continue
        raise _UnsupportedShellError(f"unsupported command part {child.type!r}")
    return Segment(tuple(argv), ())


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
    redirects: list[Redirect] = []
    spillover: list[str] = []
    for child in node.named_children:
        if child.type == "command":
            inner_segments.append(_build_segment(child, source))
            continue
        if child.type in _REDIRECT_INNER_TYPES:
            inner_segments.extend(_extract_segments(child, source))
            continue
        if child.type == "file_redirect":
            redirect, extras = _build_redirect(child, source)
            redirects.append(redirect)
            spillover.extend(extras)
            continue
        if child.type == "heredoc_redirect":
            # ``cat <<EOF … EOF`` feeds the body to stdin; no file write, no policy
            # impact. Drop it so the wrapped command flows through normal matching.
            # An unquoted heredoc body still expands ``$(…)`` before the command
            # runs, so reject any heredoc carrying a substitution rather than
            # silently feeding it through.
            if _node_contains_substitution(child):
                raise _UnsupportedShellError("command/process substitution requires approval")
            continue
        raise _UnsupportedShellError(f"unsupported redirected statement part {child.type!r}")
    if not inner_segments:
        raise _UnsupportedShellError("redirected statement missing command")
    *head, last = inner_segments
    yield from head
    yield Segment(
        last.argv + tuple(spillover),
        last.redirects + tuple(redirects),
    )


def _unwrap_shell_c(segment: Segment) -> tuple[Segment, ...] | None:
    """``bash -c "ls -la"`` → segments of the inner command. None if not a shell-wrapper.

    Tree-sitter string arguments are normalized before this point, so the inner
    command is just ``segment.argv[2]``. We re-parse it via the same pipeline so
    any compound/redirect structure inside is faithfully preserved.
    """
    if len(segment.argv) < 3 or _basename(segment.argv[0]) not in _SHELL_COMMANDS:
        return None
    if segment.argv[1] != "-c":
        return None
    inner = parse_pipeline(segment.argv[2])
    if not inner.parseable:
        return None
    return inner.segments


def _node_contains_substitution(node: Node) -> bool:
    for child in node.children:
        if child.type in ("command_substitution", "process_substitution"):
            return True
        if _node_contains_substitution(child):
            return True
    return False


def _build_redirect(node: Node, source: bytes) -> tuple[Redirect, tuple[str, ...]]:
    """Return the redirect plus any extra positional words tree-sitter folded in.

    tree-sitter-bash will absorb ``b.py`` from ``cmd a 2>/dev/null b.py`` into
    the redirect node as a second ``word`` child, even though bash treats
    ``b.py`` as argv to ``cmd``. We take the first ``word``/``number`` after
    the operator as the target and return the rest as spillover for the caller
    to re-attach to the surrounding command.
    """
    fd: int | None = None
    op: str | None = None
    target: str | None = None
    extras: list[str] = []
    for child in node.children:
        if child.type == "file_descriptor":
            fd = int(_node_text(child, source))
            continue
        if child.type in (">", ">>", "<", ">&", "&>"):
            op = child.type
            continue
        if child.is_named and child.type in ("word", "number"):
            text = _node_text(child, source)
            if target is None:
                target = text
            else:
                extras.append(text)
            continue
    if op is None or target is None:
        raise _UnsupportedShellError("redirect target unparseable")
    return Redirect(fd=fd, op=op, target=target, is_fd_dup=op == ">&"), tuple(extras)


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
    if node.type in _OPAQUE_ARG_TYPES:
        return _node_text(node, source)
    raise _UnsupportedShellError(f"unsupported argument node {node.type!r}")


def _string_text(node: Node, source: bytes) -> str:
    parts: list[str] = []
    for child in node.named_children:
        if child.type in _STRING_CHILD_TYPES:
            parts.append(_node_text(child, source))
            continue
        raise _UnsupportedShellError(f"unsupported string part {child.type!r}")
    return "".join(parts)


def _node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode()


# -----------------------------------------------------------------------------
# Rule serialization (string/dict <-> Rule)
# -----------------------------------------------------------------------------


def parse_rule(raw: JsonValue) -> Rule | None:
    if isinstance(raw, str):
        return _parse_string_rule(raw)
    if isinstance(raw, dict):
        return _parse_dict_rule(raw)
    return None


def _parse_string_rule(text: str) -> Rule | None:
    text = text.strip()
    bash_wildcard = re.fullmatch(r"Bash\((.+):\*\)", text)
    if bash_wildcard:
        return BashCommand(tuple(bash_wildcard.group(1).split()))
    bash_exact = re.fullmatch(r"Bash\((.+)\)", text)
    if bash_exact:
        return BashCommand(tuple(bash_exact.group(1).split()))
    if text:
        return NamedTool(text)
    return None


def _parse_dict_rule(data: JsonObject) -> Rule | None:
    if data.get("tool") != "Bash":
        return None
    commands_raw = data.get("command")
    if isinstance(commands_raw, str):
        commands = [commands_raw]
    elif isinstance(commands_raw, list):
        commands = [c for c in commands_raw if isinstance(c, str)]
    else:
        return None
    if not commands:
        return None
    when = data.get("when")
    if not isinstance(when, dict):
        return None
    options_raw = when.get("hasOption")
    if isinstance(options_raw, str):
        options = [options_raw]
    elif isinstance(options_raw, list):
        options = [o for o in options_raw if isinstance(o, str)]
    else:
        return None
    if not options:
        return None
    reason = data.get("reason")
    return BashOption(
        commands=frozenset(commands),
        options=frozenset(options),
        rationale=reason if isinstance(reason, str) else "",
    )


# -----------------------------------------------------------------------------
# Policy I/O
# -----------------------------------------------------------------------------


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class PolicyFile:
    """Round-trips ``.agent-permissions.jsonc`` data, preserving fields we don't model."""

    policy: Policy
    raw: JsonObject = field(default_factory=dict)


def load_policy_file(path: Path) -> PolicyFile:
    text = path.read_text()
    try:
        decoded: object = pyjson5.decode(text)
    except Exception as error:
        raise PolicyError(f"{path}: invalid JSON/JSONC ({error})") from error
    data = narrow_json(decoded)
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: top-level must be an object")
    return PolicyFile(policy=_policy_from_dict(data), raw=data)


def _policy_from_dict(data: JsonObject) -> Policy:
    permissions = data.get("permissions")
    if not isinstance(permissions, dict):
        return Policy()
    return Policy(
        deny=tuple(_rules_from_list(permissions.get("deny"))),
        ask=tuple(_rules_from_list(permissions.get("ask"))),
        allow=tuple(_rules_from_list(permissions.get("allow"))),
    )


def _rules_from_list(raw: JsonValue) -> Iterator[Rule]:
    if not isinstance(raw, list):
        return
    for item in raw:
        rule = parse_rule(item)
        if rule is not None:
            yield rule


def save_policy_file(path: Path, policy_file: PolicyFile) -> None:
    raw: JsonObject = dict(policy_file.raw)
    raw.setdefault("version", 1)
    raw["permissions"] = {
        "allow": [r.serialize() for r in policy_file.policy.allow],
        "ask": [r.serialize() for r in policy_file.policy.ask],
        "deny": [r.serialize() for r in policy_file.policy.deny],
    }
    _atomic_write(path, json.dumps(raw, indent=2) + "\n")


def merged_policy(local_root: Path | None) -> Policy:
    """Merge global ``~/.agent-permissions.jsonc`` with optional project-local file."""
    paths: list[Path] = [Path.home() / POLICY_FILENAME]
    if local_root is not None:
        candidate = local_root / POLICY_FILENAME
        if candidate not in paths:
            paths.append(candidate)
    policy = Policy()
    for path in paths:
        if not path.exists():
            continue
        policy = policy.merged_with(load_policy_file(path).policy)
    return policy


def project_root(cwd: Path) -> Path:
    try:
        output = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(cwd),
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if output:
            return Path(output)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return cwd


def write_default_policy(path: Path) -> None:
    default: JsonObject = {
        "version": 1,
        "permissions": {
            "allow": [],
            "ask": [],
            "deny": [],
        },
    }
    _atomic_write(path, json.dumps(default, indent=2) + "\n")


# -----------------------------------------------------------------------------
# Agent adapters
# -----------------------------------------------------------------------------


class AgentAdapter(ABC):
    name: ClassVar[AgentName]

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        return iter(())

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        return None

    def write_verdict(self, verdict: Verdict, event_name: str) -> None:
        json.dump({}, sys.stdout)

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        """Wire the bridge into this agent's hook config.

        Returns the list of paths the install touched (or would touch under
        ``dry_run``). An empty list means "already up to date".
        """
        return []


def _pretooluse_output(decision: Decision, rationale: str) -> JsonObject:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.value,
            "permissionDecisionReason": rationale,
        }
    }


def _permission_request_output(decision: Decision, rationale: str) -> JsonObject:
    if decision is Decision.Allow:
        return {"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}}
    if decision is Decision.Deny:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "deny", "message": rationale},
            }
        }
    return {}


# ---------- Claude ----------


class ClaudeAdapter(AgentAdapter):
    name = AgentName.Claude
    settings_path: ClassVar[Path] = Path.home() / ".claude/settings.json"

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        for path in (self.settings_path, self.settings_path.with_name("settings.local.json")):
            if not path.exists():
                continue
            settings = _read_json(path)
            permissions = settings.get("permissions")
            if not isinstance(permissions, dict):
                continue
            for decision_key, target_decision in (
                ("deny", Decision.Deny),
                ("ask", Decision.Ask),
                ("allow", Decision.Allow),
            ):
                raw_list = permissions.get(decision_key)
                if not isinstance(raw_list, list):
                    continue
                for raw in raw_list:
                    rule = parse_rule(raw)
                    if rule is not None:
                        yield target_decision, rule

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str):
            return None
        if tool_name == "Bash":
            tool_input = payload.get("tool_input")
            command = tool_input.get("command") if isinstance(tool_input, dict) else None
            return ShellRequest(parse_pipeline(command if isinstance(command, str) else ""))
        return ToolRequest(tool_name)

    def write_verdict(self, verdict: Verdict, event_name: str) -> None:
        if verdict.decision is Decision.NoOpinion:
            json.dump({}, sys.stdout)
            return
        if event_name == "PreToolUse":
            json.dump(_pretooluse_output(verdict.decision, verdict.rationale), sys.stdout)
            return
        if event_name == "PermissionRequest":
            json.dump(_permission_request_output(verdict.decision, verdict.rationale), sys.stdout)
            return
        json.dump({}, sys.stdout)

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        # Claude doesn't fire ``PermissionRequest`` — strip any bridge entry that
        # made it there from an older or third-party installer.
        if mode is InstallMode.Rulesync:
            return _merge_rulesync_hooks(
                block="claudecode",
                add=[("preToolUse", "PreToolUse", "*")],
                strip=["permissionRequest"],
                agent_name="claude",
                dry_run=dry_run,
            )
        return _merge_nested_hooks(
            self.settings_path,
            add=[("PreToolUse", "*")],
            strip=["PermissionRequest"],
            agent_name="claude",
            dry_run=dry_run,
        )


# ---------- Codex ----------


class CodexAdapter(AgentAdapter):
    name = AgentName.Codex
    config_path: ClassVar[Path] = Path.home() / ".codex/config.toml"
    hooks_path: ClassVar[Path] = Path.home() / ".codex/hooks.json"

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        rules_dir = self.config_path.parent / "rules"
        if not rules_dir.exists():
            return
        for rules_file in sorted(rules_dir.glob("*.rules")):
            for tokens, decision_text in _parse_codex_prefix_rules(rules_file.read_text()):
                decision = {"allow": Decision.Allow, "prompt": Decision.Ask, "forbidden": Decision.Deny}.get(
                    decision_text
                )
                if decision is None or not tokens:
                    continue
                yield decision, BashCommand(tuple(tokens))

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        if event_name == "PermissionRequest":
            permission = payload.get("permission")
            if not isinstance(permission, dict):
                return None
            permission_type = permission.get("type")
            metadata = permission.get("metadata")
            if permission_type == "Bash":
                command = metadata.get("command") if isinstance(metadata, dict) else None
                return ShellRequest(parse_pipeline(command if isinstance(command, str) else ""))
            if isinstance(permission_type, str):
                return ToolRequest(permission_type)
            return None
        return ClaudeAdapter().parse_event(payload, event_name)

    def write_verdict(self, verdict: Verdict, event_name: str) -> None:
        # Codex's two events split responsibilities: PreToolUse is the fast-path
        # veto (Deny only), PermissionRequest is where we may pre-approve. Allow
        # / Ask on PreToolUse fall through to Codex's normal flow so the user
        # still sees a prompt for anything not explicitly denied.
        if event_name == "PreToolUse":
            if verdict.decision is Decision.Deny:
                json.dump(_pretooluse_output(Decision.Deny, verdict.rationale), sys.stdout)
                return
            json.dump({}, sys.stdout)
            return
        if event_name == "PermissionRequest":
            if verdict.decision is Decision.Allow:
                json.dump(_permission_request_output(Decision.Allow, verdict.rationale), sys.stdout)
                return
            if verdict.decision is Decision.Deny:
                json.dump(_permission_request_output(Decision.Deny, verdict.rationale), sys.stdout)
                return
        json.dump({}, sys.stdout)

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        if mode is InstallMode.Rulesync:
            # rulesync owns enabling [features].codex_hooks; we only emit hook entries.
            return _merge_rulesync_hooks(
                block="codexcli",
                add=[
                    ("preToolUse", "PreToolUse", ".*"),
                    ("permissionRequest", "PermissionRequest", ".*"),
                ],
                strip=[],
                agent_name="codex",
                dry_run=dry_run,
            )
        touched = _merge_nested_hooks(
            self.hooks_path,
            add=[("PreToolUse", "Bash"), ("PermissionRequest", "Bash|apply_patch|mcp__.*")],
            strip=[],
            agent_name="codex",
            dry_run=dry_run,
        )
        touched.extend(_enable_codex_hooks_feature(self.config_path, dry_run=dry_run))
        return touched


def _enable_codex_hooks_feature(path: Path, *, dry_run: bool) -> list[Path]:
    """Ensure ``[features] codex_hooks = true`` in ``~/.codex/config.toml``.

    Codex gates hook execution behind this feature flag; the hook entries in
    ``hooks.json`` are inert until it is set.
    """
    if path.exists():
        try:
            doc = tomlkit.parse(path.read_text())
        except Exception as error:
            raise PolicyError(f"{path}: {error}") from error
    else:
        doc = tomlkit.document()
    features = doc.get("features")
    if not isinstance(features, dict):
        features = tomlkit.table()
        doc["features"] = features
    if features.get("codex_hooks") is True:
        return []
    features["codex_hooks"] = True
    if not dry_run:
        _atomic_write(path, tomlkit.dumps(doc))
    return [path]


def _parse_codex_prefix_rules(text: str) -> Iterator[tuple[list[str], str]]:
    for match in re.finditer(r"prefix_rule\((.*?)\)", text, flags=re.DOTALL):
        body = match.group(1)
        pattern_match = re.search(r"pattern\s*=\s*\[(.*?)\]", body, flags=re.DOTALL)
        decision_match = re.search(r"decision\s*=\s*['\"]([^'\"]+)['\"]", body)
        if pattern_match is None or decision_match is None:
            continue
        tokens = re.findall(r"['\"]([^'\"]+)['\"]", pattern_match.group(1))
        if tokens:
            yield tokens, decision_match.group(1)


# ---------- OpenCode ----------


_OPENCODE_PLUGIN_TEMPLATE = """import {{ spawnSync }} from "node:child_process";

const bridge = {bridge};

function bridgeDecision(payload) {{
  const proc = spawnSync(
    bridge,
    ["check", "--agent", "opencode", "--event", "permission.ask"],
    {{ input: JSON.stringify(payload), encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] }},
  );
  if (proc.status !== 0 || !proc.stdout.trim()) return null;
  try {{ return JSON.parse(proc.stdout); }} catch {{ return null; }}
}}

export const AgentBridgePlugin = async (input) => ({{
  "permission.ask": async (permission, output) => {{
    const decision = bridgeDecision({{
      cwd: input.directory,
      hook_event_name: "permission.ask",
      permission,
      tool_name: permission.type,
      tool_input: permission.metadata ?? permission,
    }});
    if (decision?.status === "allow" || decision?.status === "deny" || decision?.status === "ask") {{
      output.status = decision.status;
    }}
  }},
}});
"""


class OpencodeAdapter(AgentAdapter):
    name = AgentName.Opencode
    config_path: ClassVar[Path] = Path.home() / ".config/opencode/opencode.json"
    plugin_path: ClassVar[Path] = Path.home() / ".config/opencode/plugins/agentperms.js"

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        for path in (self.config_path, self.config_path.with_suffix(".jsonc")):
            if not path.exists():
                continue
            data = _read_json(path)
            permissions = data.get("permission")
            if not isinstance(permissions, dict):
                continue
            for tool_name, raw_rules in permissions.items():
                if isinstance(raw_rules, str):
                    rule = _opencode_rule(tool_name, "*")
                    if rule is None:
                        continue
                    decision = _opencode_decision(raw_rules)
                    if decision is not None:
                        yield decision, rule
                    continue
                if not isinstance(raw_rules, dict):
                    continue
                for pattern, action in raw_rules.items():
                    if not isinstance(action, str):
                        continue
                    decision = _opencode_decision(action)
                    if decision is None:
                        continue
                    rule = _opencode_rule(tool_name, pattern)
                    if rule is not None:
                        yield decision, rule

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        permission = payload.get("permission")
        if not isinstance(permission, dict):
            return None
        permission_type = permission.get("type")
        metadata_raw = permission.get("metadata")
        metadata: JsonObject = metadata_raw if isinstance(metadata_raw, dict) else permission
        if permission_type == "bash":
            command = metadata.get("command")
            return ShellRequest(parse_pipeline(command if isinstance(command, str) else ""))
        if isinstance(permission_type, str):
            return ToolRequest(permission_type)
        return None

    def write_verdict(self, verdict: Verdict, event_name: str) -> None:
        if verdict.decision is Decision.NoOpinion:
            json.dump({}, sys.stdout)
            return
        json.dump({"status": verdict.decision.value, "reason": verdict.rationale}, sys.stdout)

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        """Always writes the OpenCode plugin shim regardless of ``mode``.

        rulesync has no ``permission.ask`` plugin emitter — there is no schema for
        it — so the plugin is always installed directly. The plugin embeds the
        absolute path to ``agentperms`` resolved at install time, JSON-quoted
        so paths containing backslashes or quotes survive interpolation into a JS
        string literal.
        """
        bridge_literal = json.dumps(_resolve_bridge_command())
        contents = _OPENCODE_PLUGIN_TEMPLATE.format(bridge=bridge_literal)
        if self.plugin_path.exists() and self.plugin_path.read_text() == contents:
            return []
        if not dry_run:
            _atomic_write(self.plugin_path, contents)
        return [self.plugin_path]


def _opencode_rule(tool: str, pattern: str) -> Rule | None:
    if tool == "bash":
        if pattern == "*":
            return None
        return BashCommand(tuple(pattern.split()))
    return NamedTool(
        {
            "read": "Read",
            "grep": "Grep",
            "glob": "Glob",
            "edit": "Edit",
            "write": "Write",
            "webfetch": "WebFetch",
            "websearch": "WebSearch",
            "task": "Task",
            "skill": "Skill",
        }.get(tool, tool)
    )


def _opencode_decision(action: str) -> Decision | None:
    return {"allow": Decision.Allow, "ask": Decision.Ask, "deny": Decision.Deny}.get(action)


# ---------- Gemini ----------


class GeminiAdapter(AgentAdapter):
    name = AgentName.Gemini
    settings_path: ClassVar[Path] = Path.home() / ".gemini/settings.json"

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str):
            return None
        tool_input = payload.get("tool_input")
        if tool_name == "run_shell_command":
            command = tool_input.get("command") if isinstance(tool_input, dict) else None
            return ShellRequest(parse_pipeline(command if isinstance(command, str) else ""))
        return ToolRequest(_gemini_tool_name(tool_name))

    def write_verdict(self, verdict: Verdict, event_name: str) -> None:
        if verdict.decision is Decision.NoOpinion:
            json.dump({}, sys.stdout)
            return
        if verdict.decision is Decision.Ask:
            json.dump({"decision": "deny", "reason": f"approval required: {verdict.rationale}"}, sys.stdout)
            return
        json.dump({"decision": verdict.decision.value, "reason": verdict.rationale}, sys.stdout)

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        # rulesync's ``geminicli.preToolUse`` block is materialised as Gemini's
        # ``BeforeTool`` hook by rulesync itself; the bridge command embedded in
        # the entry uses ``--event BeforeTool`` since that's what Gemini fires
        # at runtime. Direct mode writes the same nested-group shape into
        # ``hooks.BeforeTool`` of ``settings.json`` with the same event arg.
        if mode is InstallMode.Rulesync:
            return _merge_rulesync_hooks(
                block="geminicli",
                add=[("preToolUse", "BeforeTool", ".*")],
                strip=[],
                agent_name="gemini",
                dry_run=dry_run,
            )
        return _merge_nested_hooks(
            self.settings_path,
            add=[("BeforeTool", ".*")],
            strip=[],
            agent_name="gemini",
            dry_run=dry_run,
        )


def _gemini_tool_name(name: str) -> str:
    return {
        "glob": "Glob",
        "grep_search": "Grep",
        "read_file": "Read",
        "read_many_files": "Read",
        "list_directory": "LS",
        "web_fetch": "WebFetch",
        "google_web_search": "WebSearch",
        "replace": "Edit",
        "write_file": "Write",
    }.get(name, name)


_GEMINI_TOOL_NAMES = frozenset(
    {
        "run_shell_command",
        "glob",
        "grep_search",
        "read_file",
        "read_many_files",
        "list_directory",
        "web_fetch",
        "google_web_search",
        "replace",
        "write_file",
    }
)


ADAPTERS: dict[AgentName, AgentAdapter] = {
    AgentName.Claude: ClaudeAdapter(),
    AgentName.Codex: CodexAdapter(),
    AgentName.Opencode: OpencodeAdapter(),
    AgentName.Gemini: GeminiAdapter(),
}


# -----------------------------------------------------------------------------
# Hook config helpers (used by install)
# -----------------------------------------------------------------------------


BRIDGE_HOOK_MARKER = "agentperms"

# Per-agent hook timeouts. Claude/Codex use seconds; Gemini uses milliseconds.
_HOOK_TIMEOUTS: dict[str, int] = {
    "claude": 30,
    "codex": 30,
    "gemini": 30000,
}


def _resolve_bridge_command() -> str:
    """Return the absolute path to ``agentperms`` if findable.

    GUI-launched OpenCode (Raycast/Spotlight) inherits a sparse ``PATH``; baking
    the resolved absolute path eliminates a class of silent ``ENOENT`` bugs. Falls
    back to the bare name if nothing is on ``PATH`` at install time, with a stderr
    warning so the user knows runtime PATH lookup is in play.
    """
    resolved = shutil.which(BRIDGE_HOOK_MARKER)
    if resolved:
        return resolved
    print(
        f"warning: '{BRIDGE_HOOK_MARKER}' not on PATH at install time; "
        f"hooks will rely on runtime PATH",
        file=sys.stderr,
    )
    return BRIDGE_HOOK_MARKER


def _bridge_command_string(agent: str, event: str) -> str:
    """Build the shell-safe bridge invocation embedded in hook configs.

    Quotes the resolved path so spaces or shell metacharacters in the install
    location can't break the command line or smuggle arguments. Agent and event
    are constrained internally so they need no quoting, but we shlex-quote them
    anyway as a defensive habit.
    """
    return " ".join(
        shlex.quote(part)
        for part in (_resolve_bridge_command(), "check", "--agent", agent, "--event", event)
    )


def _hook_group(matcher: str, *, agent: str, event: str, status_message: str | None = None) -> JsonObject:
    """Build a Claude/Codex/Gemini-style nested ``{matcher, hooks: [...]}`` group."""
    hook: JsonObject = {
        "type": "command",
        "command": _bridge_command_string(agent, event),
        "timeout": _HOOK_TIMEOUTS[agent],
    }
    if status_message is not None:
        hook["statusMessage"] = status_message
    return {"matcher": matcher, "hooks": [hook]}


def _rulesync_entry(agent: str, event: str, matcher: str) -> JsonObject:
    """Build a flat rulesync-style hook entry."""
    return {
        "type": "command",
        "command": _bridge_command_string(agent, event),
        "matcher": matcher,
        "timeout": _HOOK_TIMEOUTS[agent],
    }


def _is_bridge_hook(hook: JsonValue) -> bool:
    """True iff this entry is one the bridge's installer wrote.

    Matches strictly on shape: the command must split into a binary whose
    basename is ``agentperms`` followed by ``check``. This avoids
    false-stripping unrelated wrappers whose paths happen to contain the
    substring ``agentperms``.
    """
    if not isinstance(hook, dict):
        return False
    command = hook.get("command")
    if not isinstance(command, str) or not command.strip():
        return False
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return False
    if len(parts) < 2:
        return False
    return Path(parts[0]).name == BRIDGE_HOOK_MARKER and parts[1] == "check"


def _strip_bridge_groups(groups: JsonArray) -> JsonArray:
    """Remove bridge entries from nested ``{matcher, hooks: [...]}`` groups.

    Drops groups whose hooks list is left empty; preserves all non-bridge entries
    untouched. Idempotency guarantee: re-running ``install`` produces no churn.
    """
    kept: JsonArray = []
    for group in groups:
        if not isinstance(group, dict):
            kept.append(group)
            continue
        hooks = group.get("hooks")
        if not isinstance(hooks, list):
            kept.append(group)
            continue
        remaining: JsonArray = [hook for hook in hooks if not _is_bridge_hook(hook)]
        if not remaining:
            continue
        kept.append({**group, "hooks": remaining})
    return kept


def _strip_bridge_entries(entries: JsonArray) -> JsonArray:
    """Remove bridge entries from a flat rulesync-style entry list."""
    return [entry for entry in entries if not _is_bridge_hook(entry)]


def _section(parent: JsonObject, key: str) -> JsonObject:
    value = parent.get(key)
    if isinstance(value, dict):
        return value
    section: JsonObject = {}
    parent[key] = section
    return section


def _ensure_list(parent: JsonObject, key: str) -> JsonArray:
    value = parent.get(key)
    if isinstance(value, list):
        return value
    new_list: JsonArray = []
    parent[key] = new_list
    return new_list


def _rulesync_hooks_path() -> Path:
    return Path.home() / ".rulesync/hooks.json"


def _write_json_if_changed(path: Path, before: JsonObject, after: JsonObject, *, dry_run: bool) -> list[Path]:
    """Atomic write iff ``after`` differs structurally from ``before``."""
    if after == before:
        return []
    if not dry_run:
        _atomic_write(path, json.dumps(after, indent=2) + "\n")
    return [path]


def _merge_rulesync_hooks(
    *,
    block: str,
    add: list[tuple[str, str, str]],
    strip: list[str],
    agent_name: str,
    dry_run: bool,
) -> list[Path]:
    """Merge bridge entries into ``~/.rulesync/hooks.json`` for one agent block.

    ``add`` is a list of ``(rulesync_key, bridge_event, matcher)`` triples. The
    ``rulesync_key`` (camelCase) is where rulesync materialises the hook into the
    per-tool config; ``bridge_event`` is the per-tool event name the bridge will
    receive at runtime (e.g. rulesync's ``preToolUse`` for Gemini maps to
    ``BeforeTool``, so we embed ``--event BeforeTool``). ``strip`` removes stale
    bridge entries (e.g. Claude doesn't fire ``permissionRequest``).
    """
    path = _rulesync_hooks_path()
    before = _read_json(path)
    after: JsonObject = json.loads(json.dumps(before))
    after.setdefault("version", 1)
    agent_section = _section(after, block)
    hooks = _section(agent_section, "hooks")
    for rulesync_key, bridge_event, matcher in add:
        entries = _strip_bridge_entries(_ensure_list(hooks, rulesync_key))
        entries.append(_rulesync_entry(agent_name, bridge_event, matcher))
        hooks[rulesync_key] = entries
    for event_name in strip:
        if event_name in hooks:
            current = hooks[event_name]
            if isinstance(current, list):
                stripped = _strip_bridge_entries(current)
                if stripped:
                    hooks[event_name] = stripped
                else:
                    del hooks[event_name]
    return _write_json_if_changed(path, before, after, dry_run=dry_run)


def _merge_nested_hooks(
    path: Path,
    *,
    add: list[tuple[str, str]],
    strip: list[str],
    agent_name: str,
    dry_run: bool,
) -> list[Path]:
    """Merge bridge groups into a Claude-style ``hooks.<Event>`` config file.

    The schema is the nested ``[{matcher, hooks: [...]}]`` group form used by
    Claude ``settings.json``, Codex ``hooks.json``, and Gemini ``settings.json``.
    Each entry in ``add`` is ``(event_name, matcher)``; the embedded bridge
    invocation uses ``event_name`` as the ``--event`` argument since direct-mode
    keys are the per-tool event names.
    """
    before = _read_json(path)
    after: JsonObject = json.loads(json.dumps(before))
    hooks_section = _section(after, "hooks")
    for event_name, matcher in add:
        groups = _strip_bridge_groups(_ensure_list(hooks_section, event_name))
        groups.append(_hook_group(matcher, agent=agent_name, event=event_name))
        hooks_section[event_name] = groups
    for event_name in strip:
        if event_name in hooks_section:
            current = hooks_section[event_name]
            if isinstance(current, list):
                stripped = _strip_bridge_groups(current)
                if stripped:
                    hooks_section[event_name] = stripped
                else:
                    del hooks_section[event_name]
    return _write_json_if_changed(path, before, after, dry_run=dry_run)


# -----------------------------------------------------------------------------
# File helpers
# -----------------------------------------------------------------------------


def _read_json(path: Path) -> JsonObject:
    if not path.exists():
        return {}
    try:
        decoded: object = pyjson5.decode(path.read_text())
    except Exception as error:
        raise PolicyError(f"{path}: {error}") from error
    narrowed = narrow_json(decoded)
    return narrowed if isinstance(narrowed, dict) else {}


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent)) as handle:
        handle.write(text)
        tmp_path = Path(handle.name)
    tmp_path.replace(path)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentperms")
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("install", help="wire the bridge into agent hook configs")
    install.add_argument(
        "--mode",
        choices=["auto", "rulesync", "direct"],
        default="auto",
        help="auto: detect rulesync; rulesync: write ~/.rulesync/hooks.json; direct: per-tool configs",
    )
    install.add_argument(
        "--dry-run",
        action="store_true",
        help="print would-be writes without modifying files",
    )

    sub.add_parser("import", help="pull native allow/ask/deny rules into ~/.agent-permissions.jsonc")

    check = sub.add_parser("check", help="runtime decision; reads stdin, writes stdout")
    check.add_argument("--agent", required=True, choices=[a.value for a in AgentName])
    check.add_argument("--event", required=True)

    sub.add_parser("edit", help="open the policy file in $EDITOR (creates a default if missing)")

    args = parser.parse_args(argv)

    if args.command == "install":
        return _cmd_install(mode=args.mode, dry_run=args.dry_run)
    if args.command == "import":
        return _cmd_import()
    if args.command == "check":
        return _cmd_check(AgentName(args.agent), args.event)
    if args.command == "edit":
        return _cmd_edit()
    parser.error(f"unknown command {args.command}")
    return 2


def _resolve_install_mode(mode: str) -> InstallMode:
    if mode == "rulesync":
        if not (Path.home() / ".rulesync").exists():
            raise PolicyError("--mode rulesync requires ~/.rulesync/ to exist")
        return InstallMode.Rulesync
    if mode == "direct":
        return InstallMode.Direct
    return InstallMode.Rulesync if (Path.home() / ".rulesync").exists() else InstallMode.Direct


def _cmd_install(*, mode: str, dry_run: bool) -> int:
    try:
        resolved_mode = _resolve_install_mode(mode)
    except PolicyError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(f"mode: {resolved_mode.value}{' (dry-run)' if dry_run else ''}")
    failed = False
    for adapter in ADAPTERS.values():
        try:
            touched = adapter.install(resolved_mode, dry_run=dry_run)
        except Exception as error:
            print(f"{adapter.name.value}: failed ({error})", file=sys.stderr)
            failed = True
            continue
        if not touched:
            print(f"{adapter.name.value}: up to date")
            continue
        verb = "would write" if dry_run else "wrote"
        for path in touched:
            print(f"{adapter.name.value}: {verb} {path}")
    return 1 if failed else 0


def _cmd_import() -> int:
    policy_path = Path.home() / POLICY_FILENAME
    if not policy_path.exists():
        write_default_policy(policy_path)
    policy_file = load_policy_file(policy_path)
    seen: set[tuple[Decision, Rule]] = {(d, r) for d, r in policy_file.policy.all_rules()}
    new_by_decision: dict[Decision, list[Rule]] = {Decision.Allow: [], Decision.Ask: [], Decision.Deny: []}
    for adapter in ADAPTERS.values():
        for decision, rule in adapter.import_native_rules():
            key = (decision, rule)
            if key in seen:
                continue
            seen.add(key)
            new_by_decision[decision].append(rule)
    if not any(new_by_decision.values()):
        print("no new rules")
        return 0
    updated = Policy(
        deny=policy_file.policy.deny + tuple(new_by_decision[Decision.Deny]),
        ask=policy_file.policy.ask + tuple(new_by_decision[Decision.Ask]),
        allow=policy_file.policy.allow + tuple(new_by_decision[Decision.Allow]),
    )
    save_policy_file(policy_path, PolicyFile(updated, policy_file.raw))
    for decision, rules in new_by_decision.items():
        for rule in rules:
            print(f"+{decision.value} {rule.serialize()!r}")
    return 0


def _cmd_check(agent: AgentName, event: str) -> int:
    try:
        raw_payload: object = json.load(sys.stdin)
    except json.JSONDecodeError:
        _trace(agent, event, None, None, "json decode failed")
        json.dump({}, sys.stdout)
        return 0
    try:
        payload_value = narrow_json(raw_payload)
    except PolicyError:
        _trace(agent, event, None, None, "payload narrow failed")
        json.dump({}, sys.stdout)
        return 0
    if not isinstance(payload_value, dict):
        _trace(agent, event, None, None, "payload not object")
        json.dump({}, sys.stdout)
        return 0
    payload: JsonObject = payload_value
    event = _effective_event(event, payload)
    adapter = _select_adapter(agent, event, payload)
    request = adapter.parse_event(payload, event)
    if request is None:
        _trace(agent, event, payload, None, "request unparseable")
        json.dump({}, sys.stdout)
        return 0
    cwd_value = payload.get("cwd")
    cwd = Path(cwd_value) if isinstance(cwd_value, str) else Path(os.getcwd())
    try:
        policy = merged_policy(local_root=project_root(cwd))
    except PolicyError as error:
        # Fail closed: prompt rather than auto-allow when the policy file is broken.
        _trace(agent, event, payload, None, f"policy load failed: {error}")
        adapter.write_verdict(Verdict(Decision.Ask, f"policy load failed: {error}"), event)
        return 0
    verdict = policy.decide(request)
    verdict = coerce_for_permission_mode(verdict, payload)
    _trace(agent, event, payload, verdict, None)
    adapter.write_verdict(verdict, event)
    return 0


def _effective_event(event: str, payload: JsonObject) -> str:
    if event != "auto":
        return event
    payload_event = payload.get("hook_event_name")
    return payload_event if isinstance(payload_event, str) else event


def _select_adapter(agent: AgentName, event: str, payload: JsonObject) -> AgentAdapter:
    if agent is not AgentName.Auto:
        return ADAPTERS[agent]
    if event in ("BeforeTool", "AfterTool"):
        return ADAPTERS[AgentName.Gemini]
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name in _GEMINI_TOOL_NAMES:
        return ADAPTERS[AgentName.Gemini]
    if event == "PermissionRequest" and isinstance(payload.get("permission"), dict):
        return ADAPTERS[AgentName.Codex]
    if event == "PermissionRequest":
        return ADAPTERS[AgentName.Claude]
    if event in ("permission.ask", "permission.asked"):
        return ADAPTERS[AgentName.Opencode]
    return ADAPTERS[AgentName.Claude]


def _trace(
    agent: AgentName, event: str, payload: JsonObject | None, verdict: Verdict | None, note: str | None
) -> None:
    """Append one JSON line per invocation to ``$AGENTPERMS_TRACE`` if set.

    Off by default. Set the env var to a writable path to enable. Used to debug whether the
    bridge is actually being called for a given command.
    """
    target = os.environ.get("AGENTPERMS_TRACE")
    if not target:
        return
    record: JsonObject = {
        "agent": agent.value,
        "event": event,
        "payload": payload,
        "note": note,
    }
    if verdict is not None:
        record["verdict"] = {"decision": verdict.decision.value, "rationale": verdict.rationale}
    try:
        with open(target, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


def coerce_for_permission_mode(verdict: Verdict, payload: JsonObject) -> Verdict:
    """If the host agent is in bypass-permissions mode, suppress Ask. Only Deny still bites.

    Claude Code surfaces ``permission_mode`` in the hook payload. Returning ``"ask"`` from a
    PreToolUse hook forces a prompt even in bypass mode, which defeats the user's intent.
    """
    if payload.get("permission_mode") == "bypassPermissions" and verdict.decision is Decision.Ask:
        return Verdict(Decision.Allow, f"bypass mode: {verdict.rationale}")
    return verdict


def _cmd_edit() -> int:
    path = Path.home() / POLICY_FILENAME
    if not path.exists():
        write_default_policy(path)
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or _default_editor()
    return subprocess.call([editor, str(path)])


def _default_editor() -> str:
    for candidate in ("nvim", "vim", "vi", "nano"):
        if shutil.which(candidate):
            return candidate
    return "vi"


if __name__ == "__main__":
    sys.exit(main())
