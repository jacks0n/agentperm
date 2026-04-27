"""Permission policy mediator for Claude Code, Codex, OpenCode, and Gemini CLI.

The user maintains one policy file (``~/.agent-permissions.jsonc``); this module
installs a hook into each agent that consults the policy at runtime.

Module layout:
    Domain        — Decision, Verdict, Rule, Request, Pipeline, Segment, Policy
    Shell         — bashlex -> Pipeline
    Rule I/O      — string/dict <-> Rule
    Policy I/O    — file <-> Policy
    Adapter       — AgentAdapter ABC + Claude/Codex/Opencode/Gemini implementations
    CLI           — install, import, check, edit
"""

from __future__ import annotations

import argparse
import json
import os
import re
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

import bashlex
import bashlex.errors
import pyjson5
import tomlkit
import tomlkit.items

POLICY_FILENAME = ".agent-permissions.jsonc"
BRIDGE_HOOK_MARKER = "llm-agent-bridge"


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
    Claude = "claude"
    Codex = "codex"
    Opencode = "opencode"
    Gemini = "gemini"


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
# Shell parser (bashlex -> Pipeline)
#
# bashlex is dynamically typed. The narrowing helpers below are the only place
# that talks to bashlex's untyped attributes; everything outside this section
# only sees the typed Pipeline/Segment/Redirect domain types.
# -----------------------------------------------------------------------------


class _UnsupportedShellError(Exception):
    pass


_SHELL_COMMANDS = frozenset({"bash", "sh", "zsh"})


def parse_pipeline(command: str) -> Pipeline:
    if not command.strip():
        return Pipeline(segments=(), parseable=True)
    try:
        trees = bashlex.parse(command)
    except (bashlex.errors.ParsingError, NotImplementedError) as error:
        return Pipeline((), parseable=False, unparseable_reason=f"bashlex: {error}")
    segments: list[Segment] = []
    try:
        for tree in trees:
            segments.extend(_extract_segments(tree))
    except _UnsupportedShellError as error:
        return Pipeline((), parseable=False, unparseable_reason=str(error))
    return Pipeline(tuple(segments), parseable=True)


def _node_kind(node: object) -> str:
    kind = getattr(node, "kind", None)
    if not isinstance(kind, str):
        raise _UnsupportedShellError("bashlex node missing 'kind'")
    return kind


def _node_parts(node: object) -> list[object]:
    parts = getattr(node, "parts", None)
    if isinstance(parts, list):
        return list(parts)
    return []


def _node_compound_list(node: object) -> list[object]:
    items = getattr(node, "list", None)
    if isinstance(items, list):
        return list(items)
    return []


def _node_word(node: object) -> str:
    word = getattr(node, "word", None)
    if not isinstance(word, str):
        raise _UnsupportedShellError("bashlex word node missing 'word'")
    return word


def _node_int_attr(node: object, attr: str) -> int | None:
    value = getattr(node, attr, None)
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _extract_segments(node: object) -> Iterator[Segment]:
    kind = _node_kind(node)
    if kind == "command":
        segment = _build_segment(node)
        unwrapped = _unwrap_shell_c(segment)
        if unwrapped is not None:
            yield from unwrapped
            return
        yield segment
        return
    if kind in ("list", "pipeline"):
        for child in _node_parts(node):
            child_kind = _node_kind(child)
            if child_kind in ("operator", "pipe", "reservedword"):
                continue
            yield from _extract_segments(child)
        return
    if kind == "compound":
        for child in _node_compound_list(node):
            yield from _extract_segments(child)
        return
    raise _UnsupportedShellError(f"unsupported shell node {kind!r}")


def _build_segment(command_node: object) -> Segment:
    argv: list[str] = []
    redirects: list[Redirect] = []
    for part in _node_parts(command_node):
        kind = _node_kind(part)
        if kind == "word":
            if _word_has_command_substitution(part):
                raise _UnsupportedShellError("command/process substitution requires approval")
            argv.append(_node_word(part))
        elif kind == "redirect":
            redirects.append(_build_redirect(part))
        elif kind == "assignment":
            # bashlex marks leading ``FOO=bar`` env-assignment words as kind="assignment";
            # they are not part of the executed command's argv.
            continue
    return Segment(tuple(argv), tuple(redirects))


def _unwrap_shell_c(segment: Segment) -> tuple[Segment, ...] | None:
    """``bash -c "ls -la"`` → segments of the inner command. None if not a shell-wrapper.

    bashlex strips the surrounding quotes from the ``-c`` argument at the word level,
    so the inner command is just ``segment.argv[2]``. We re-parse it via the same
    pipeline so any compound/redirect structure inside is faithfully preserved.
    """
    if len(segment.argv) < 3 or _basename(segment.argv[0]) not in _SHELL_COMMANDS:
        return None
    if segment.argv[1] != "-c":
        return None
    inner = parse_pipeline(segment.argv[2])
    if not inner.parseable:
        return None
    return inner.segments


def _word_has_command_substitution(word_node: object) -> bool:
    for part in _node_parts(word_node):
        kind = getattr(part, "kind", None)
        if isinstance(kind, str) and kind in ("commandsubstitution", "processsubstitution"):
            return True
    return False


def _build_redirect(node: object) -> Redirect:
    op = getattr(node, "type", None)
    if not isinstance(op, str):
        raise _UnsupportedShellError("bashlex redirect missing 'type'")
    fd = _node_int_attr(node, "input")
    output = getattr(node, "output", None)
    if isinstance(output, int) and not isinstance(output, bool):
        return Redirect(fd=fd, op=op, target=str(output), is_fd_dup=True)
    word = getattr(output, "word", None) if output is not None else None
    if isinstance(word, str):
        return Redirect(fd=fd, op=op, target=word, is_fd_dup=False)
    raise _UnsupportedShellError("bashlex redirect target unparseable")


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
            "allow": [
                "Bash(cat:*)",
                "Bash(echo:*)",
                "Bash(grep:*)",
                "Bash(head:*)",
                "Bash(ls:*)",
                "Bash(pwd)",
                "Bash(rg:*)",
                "Bash(tail:*)",
                "Bash(test -f:*)",
                "Bash(wc:*)",
                "Bash(which:*)",
                "Bash(git status)",
                "Bash(git status:*)",
                "Bash(git diff:*)",
                "Bash(git log:*)",
                "Read",
                "Glob",
                "Grep",
            ],
            "ask": [
                {
                    "tool": "Bash",
                    "command": ["sed", "gsed"],
                    "when": {"hasOption": ["-i", "--in-place"]},
                    "reason": "sed in-place editing changes files",
                },
            ],
            "deny": [
                "Bash(sudo:*)",
                "Bash(su:*)",
                "Bash(rm -rf /*)",
            ],
        },
    }
    _atomic_write(path, json.dumps(default, indent=2) + "\n")


# -----------------------------------------------------------------------------
# Agent adapters
# -----------------------------------------------------------------------------


class AgentAdapter(ABC):
    name: ClassVar[AgentName]

    @abstractmethod
    def install(self) -> Path | None:
        """Write whatever config the agent needs to invoke the bridge. Return the path written, or None if no change."""

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        return iter(())

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        return None

    def write_verdict(self, verdict: Verdict, event_name: str) -> None:
        json.dump({}, sys.stdout)


# ---------- Claude ----------


class ClaudeAdapter(AgentAdapter):
    name = AgentName.Claude
    settings_path: ClassVar[Path] = Path.home() / ".claude/settings.json"

    def install(self) -> Path | None:
        settings = _read_json(self.settings_path)
        hooks = _section(settings, "hooks")
        pre_tool_use = _ensure_list(hooks, "PreToolUse")
        new_groups = _strip_bridge_groups(pre_tool_use)
        new_groups.append(_hook_group("*", agent="claude", event="PreToolUse"))
        if new_groups == pre_tool_use:
            return None
        hooks["PreToolUse"] = new_groups
        _atomic_write(self.settings_path, json.dumps(settings, indent=2) + "\n")
        return self.settings_path

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
        output: JsonObject = {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "permissionDecision": verdict.decision.value,
                "permissionDecisionReason": verdict.rationale,
            }
        }
        json.dump(output, sys.stdout)


# ---------- Codex ----------


class CodexAdapter(AgentAdapter):
    name = AgentName.Codex
    hooks_path: ClassVar[Path] = Path.home() / ".codex/hooks.json"
    config_path: ClassVar[Path] = Path.home() / ".codex/config.toml"

    def install(self) -> Path | None:
        hooks_config = _read_json(self.hooks_path)
        hooks = _section(hooks_config, "hooks")

        pre_tool_use = _strip_bridge_groups(_ensure_list(hooks, "PreToolUse"))
        pre_tool_use.append(_hook_group("Bash", agent="codex", event="PreToolUse"))
        hooks["PreToolUse"] = pre_tool_use

        permission_request = _strip_bridge_groups(_ensure_list(hooks, "PermissionRequest"))
        permission_request.append(
            _hook_group(
                "Bash|apply_patch|mcp__.*",
                agent="codex",
                event="PermissionRequest",
                status_message="Checking llm-agent-bridge policy",
            )
        )
        hooks["PermissionRequest"] = permission_request

        _atomic_write(self.hooks_path, json.dumps(hooks_config, indent=2) + "\n")
        self._enable_codex_hooks()
        return self.hooks_path

    def _enable_codex_hooks(self) -> None:
        doc = tomlkit.parse(self.config_path.read_text()) if self.config_path.exists() else tomlkit.document()
        features = doc.get("features")
        if not isinstance(features, tomlkit.items.Table):
            features = tomlkit.table()
            doc["features"] = features
        if features.get("codex_hooks") is True:
            return
        features["codex_hooks"] = True
        _atomic_write(self.config_path, tomlkit.dumps(doc))

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
        if event_name == "PreToolUse":
            if verdict.decision is Decision.Deny:
                json.dump(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": verdict.rationale,
                        }
                    },
                    sys.stdout,
                )
                return
            json.dump({}, sys.stdout)
            return
        if event_name == "PermissionRequest":
            if verdict.decision is Decision.Allow:
                json.dump(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PermissionRequest",
                            "decision": {"behavior": "allow"},
                        }
                    },
                    sys.stdout,
                )
                return
            if verdict.decision is Decision.Deny:
                json.dump(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PermissionRequest",
                            "decision": {"behavior": "deny", "message": verdict.rationale},
                        }
                    },
                    sys.stdout,
                )
                return
        json.dump({}, sys.stdout)


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

const bridge = "{bridge}";

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
    plugin_path: ClassVar[Path] = Path.home() / ".config/opencode/plugins/agent-bridge.js"
    config_path: ClassVar[Path] = Path.home() / ".config/opencode/opencode.json"

    def install(self) -> Path | None:
        contents = _OPENCODE_PLUGIN_TEMPLATE.format(bridge=BRIDGE_HOOK_MARKER)
        if self.plugin_path.exists() and self.plugin_path.read_text() == contents:
            return None
        _atomic_write(self.plugin_path, contents)
        return self.plugin_path

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
    policy_path: ClassVar[Path] = Path.home() / ".gemini/policies/agent-bridge.toml"

    def install(self) -> Path | None:
        policy = merged_policy(local_root=None)
        doc = tomlkit.document()
        doc.add(tomlkit.comment("Generated by llm-agent-bridge. Edit ~/.agent-permissions.jsonc instead."))
        for regex, reason in _gemini_ask_rules(policy):
            self._append_rule(doc, regex=regex, reason=reason, decision="ask_user", priority=950)
        prefixes = sorted(_gemini_allow_prefixes(policy))
        if prefixes:
            self._append_rule(doc, prefix=prefixes, decision="allow", priority=700)
        rendered = tomlkit.dumps(doc)
        if self.policy_path.exists() and self.policy_path.read_text() == rendered:
            return None
        _atomic_write(self.policy_path, rendered)
        return self.policy_path

    @staticmethod
    def _append_rule(
        doc: tomlkit.TOMLDocument,
        *,
        regex: str | None = None,
        prefix: list[str] | None = None,
        reason: str = "",
        decision: str,
        priority: int,
    ) -> None:
        rule = tomlkit.table()
        rule["toolName"] = "run_shell_command"
        if regex is not None:
            rule["commandRegex"] = regex
        if prefix is not None:
            rule["commandPrefix"] = prefix
            rule["allow_redirection"] = True
        rule["decision"] = decision
        rule["priority"] = priority
        if reason:
            rule["deny_message"] = reason
        existing = doc.get("rule")
        if isinstance(existing, tomlkit.items.AoT):
            existing.append(rule)
            return
        rules = tomlkit.aot()
        rules.append(rule)
        doc["rule"] = rules


def _gemini_allow_prefixes(policy: Policy) -> set[str]:
    return {" ".join(rule.prefix) for rule in policy.allow if isinstance(rule, BashCommand)}


def _gemini_ask_rules(policy: Policy) -> Iterator[tuple[str, str]]:
    yield (r".*(?:^|\s)(?:>|>>|1>|1>>|&>)\s*[^\s]+", "stdout redirection writes to a file and requires approval")
    for rule in policy.ask:
        if not isinstance(rule, BashOption):
            continue
        command_regex = "|".join(re.escape(c) for c in sorted(rule.commands))
        option_regexes: list[str] = []
        for option in sorted(rule.options):
            if option.startswith("--"):
                option_regexes.append(re.escape(option) + r"(?:=|\s|$)")
            elif option.startswith("-"):
                option_regexes.append(r"-[A-Za-z]*" + re.escape(option[1:]) + r"(?:[A-Za-z.]*|\s|$)")
        if option_regexes:
            options_alt = "|".join(option_regexes)
            yield (
                rf"(?:{command_regex})\s+.*(?:{options_alt})",
                rule.rationale or "command requires approval",
            )


ADAPTERS: dict[AgentName, AgentAdapter] = {
    AgentName.Claude: ClaudeAdapter(),
    AgentName.Codex: CodexAdapter(),
    AgentName.Opencode: OpencodeAdapter(),
    AgentName.Gemini: GeminiAdapter(),
}


# -----------------------------------------------------------------------------
# Hook config helpers
# -----------------------------------------------------------------------------


def _hook_group(matcher: str, *, agent: str, event: str, status_message: str | None = None) -> JsonObject:
    hook: JsonObject = {
        "type": "command",
        "command": f"{BRIDGE_HOOK_MARKER} check --agent {agent} --event {event}",
        "timeout": 30,
    }
    if status_message is not None:
        hook["statusMessage"] = status_message
    return {"matcher": matcher, "hooks": [hook]}


def _strip_bridge_groups(groups: JsonArray) -> JsonArray:
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
        rebuilt: JsonObject = {**group, "hooks": remaining}
        kept.append(rebuilt)
    return kept


def _is_bridge_hook(hook: JsonValue) -> bool:
    if not isinstance(hook, dict):
        return False
    command = hook.get("command")
    return isinstance(command, str) and BRIDGE_HOOK_MARKER in command


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
    parser = argparse.ArgumentParser(prog="llm-agent-bridge")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("install", help="install hooks for every detected agent")

    sub.add_parser("import", help="pull native allow/ask/deny rules into ~/.agent-permissions.jsonc")

    check = sub.add_parser("check", help="runtime decision; reads stdin, writes stdout")
    check.add_argument("--agent", required=True, choices=[a.value for a in AgentName])
    check.add_argument("--event", required=True)

    sub.add_parser("edit", help="open the policy file in $EDITOR (creates a default if missing)")

    args = parser.parse_args(argv)

    if args.command == "install":
        return _cmd_install()
    if args.command == "import":
        return _cmd_import()
    if args.command == "check":
        return _cmd_check(AgentName(args.agent), args.event)
    if args.command == "edit":
        return _cmd_edit()
    parser.error(f"unknown command {args.command}")
    return 2


def _cmd_install() -> int:
    policy_path = Path.home() / POLICY_FILENAME
    if not policy_path.exists():
        write_default_policy(policy_path)
        print(f"created {policy_path}")
    for adapter in ADAPTERS.values():
        try:
            written = adapter.install()
        except Exception as error:
            print(f"{adapter.name}: failed ({error})", file=sys.stderr)
            continue
        if written is not None:
            print(f"{adapter.name}: wrote {written}")
        else:
            print(f"{adapter.name}: up to date")
    return 0


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
    adapter = ADAPTERS[agent]
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


def _trace(
    agent: AgentName, event: str, payload: JsonObject | None, verdict: Verdict | None, note: str | None
) -> None:
    """Append one JSON line per invocation to ``$LLM_AGENT_BRIDGE_TRACE`` if set.

    Off by default. Set the env var to a writable path to enable. Used to debug whether the
    bridge is actually being called for a given command.
    """
    target = os.environ.get("LLM_AGENT_BRIDGE_TRACE")
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
