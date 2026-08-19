"""Domain types and Policy engine for agentperm."""

from __future__ import annotations

import posixpath
import re
import urllib.parse
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path

from .errors import PolicyError

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
    Kiro = "kiro"


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
class RedirectionPolicy:
    """User-tunable overrides for the built-in shell-redirect opinions.

    Loaded from a policy file's ``shell.redirection`` block. Each field holds the
    decision the user configured for that redirect shape, or ``None`` if that file
    didn't mention it (``merged_with`` lets a later file override only the keys it
    sets). ``Decision.Allow`` means the shape carries no independent opinion — the
    segment's own command rule decides; ``Ask``/``Deny`` force that verdict
    regardless of the command rule. Unset fields fall back to today's hardcoded
    defaults at evaluation time (see ``shell._evaluate_redirect``).
    """

    stderr_to_dev_null: Decision | None = None
    stdout_to_dev_null: Decision | None = None
    stdout_to_file: Decision | None = None
    append_to_file: Decision | None = None
    allow_paths: tuple[str, ...] = ()

    def merged_with(self, other: RedirectionPolicy) -> RedirectionPolicy:
        def pick(base: Decision | None, override: Decision | None) -> Decision | None:
            return override if override is not None else base

        return RedirectionPolicy(
            stderr_to_dev_null=pick(self.stderr_to_dev_null, other.stderr_to_dev_null),
            stdout_to_dev_null=pick(self.stdout_to_dev_null, other.stdout_to_dev_null),
            stdout_to_file=pick(self.stdout_to_file, other.stdout_to_file),
            append_to_file=pick(self.append_to_file, other.append_to_file),
            allow_paths=tuple(dict.fromkeys(self.allow_paths + other.allow_paths)),
        )


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
    # Literal stdin supplied by a heredoc. ``None`` means the shell command did
    # not carry statically available stdin source. Dynamic heredocs retain their
    # source for diagnostics but are never safe to analyse as the executed text.
    stdin_source: str | None = None
    stdin_dynamic: bool = False


@dataclass(frozen=True)
class Pipeline:
    segments: tuple[Segment, ...]
    parseable: bool
    unparseable_reason: str = ""


# A tool request's input flattened to (field-name, value) pairs, e.g.
# (("url", "https://github.com/x"), ("prompt", "…")). Keeping field identity lets a scoped
# rule match only the authoritative field, never a look-alike value in another field.
ToolArguments = tuple[tuple[str, str], ...]


class Request:
    """Marker base for ShellRequest / ToolRequest. Sum-typed via isinstance dispatch."""


@dataclass(frozen=True)
class ShellRequest(Request):
    pipeline: Pipeline
    cwd: Path | None = None


@dataclass(frozen=True)
class ToolRequest(Request):
    tool: str
    arguments: ToolArguments = ()


# Permission rules are a sum type. Each rule knows how to match its kind of request.


class Rule(ABC):
    @abstractmethod
    def serialize(self) -> str | JsonObject: ...


@dataclass(frozen=True)
class PythonReadonly(Rule):
    """Enable shallow AST analysis for inline Python code."""

    def serialize(self) -> str:
        return "Python(readonly)"


@dataclass(frozen=True)
class BashCommand(Rule):
    """``Bash(git status:*)`` — matches a bash segment whose argv matches the token pattern.

    Tokens are literals by default; ``*`` matches exactly one argv element and ``**`` matches
    zero or more. ``trailing_wildcard`` corresponds to the ``:*`` suffix and lets argv extend
    past the pattern; without it, argv must be consumed exactly.
    """

    prefix: tuple[str, ...]
    trailing_wildcard: bool = True

    def matches(self, segment: Segment) -> bool:
        if not self.prefix:
            return False
        return _glob_match_argv(self.prefix, segment.argv, self.trailing_wildcard)

    def serialize(self) -> str:
        body = " ".join(self.prefix)
        return f"Bash({body}:*)" if self.trailing_wildcard else f"Bash({body})"


def _glob_match_argv(pattern: tuple[str, ...], argv: tuple[str, ...], trailing_wildcard: bool) -> bool:
    """Match a token-glob pattern against argv.

    Literals require exact equality (basename rule for argv[0] only). ``*`` consumes exactly
    one argv token; ``**`` consumes zero or more. When ``*`` or ``**`` covers position 0 the
    basename rule does not apply — the glob doesn't carry the literal token to compare.
    """
    def go(pi: int, ai: int) -> bool:
        while pi < len(pattern):
            tok = pattern[pi]
            if tok == "**":
                return any(go(pi + 1, ai + skip) for skip in range(len(argv) - ai + 1))
            if ai >= len(argv):
                return False
            if tok == "*":
                pi += 1
                ai += 1
                continue
            actual = basename(argv[ai]) if ai == 0 else argv[ai]
            if actual != tok:
                return False
            pi += 1
            ai += 1
        return trailing_wildcard or ai == len(argv)

    return go(0, 0)


@dataclass(frozen=True)
class BashOption(Rule):
    """Structured: matches bash segments that invoke a command with a specific option."""

    commands: frozenset[str]
    options: frozenset[str]
    rationale: str

    def matches(self, segment: Segment) -> bool:
        if not segment.argv:
            return False
        if basename(segment.argv[0]) not in self.commands:
            return False
        return any(_arg_matches_option(arg, opt) for arg in segment.argv[1:] for opt in self.options)

    def serialize(self) -> JsonObject:
        return {
            "tool": "Bash",
            "command": sorted(self.commands),
            "when": {"hasOption": sorted(self.options)},
            "reason": self.rationale,
        }


# ---------------------------------------------------------------------------
# Shell pattern DSL types
# ---------------------------------------------------------------------------


class PathTerm:
    """Base for positional pattern terms. Sum type via isinstance."""


@dataclass(frozen=True)
class Word(PathTerm):
    glob: str


@dataclass(frozen=True)
class OneOf(PathTerm):
    globs: tuple[str, ...]
    negated: bool = False


@dataclass(frozen=True)
class AnyRest(PathTerm):
    pass


class Disposition(Enum):
    Required = "required"
    Forbidden = "forbidden"
    Permitted = "permitted"


@dataclass(frozen=True)
class FlagConstraint:
    atom: str
    disp: Disposition
    value_glob: str | None = None


@dataclass(frozen=True)
class ShellPattern(Rule):
    raw: str
    path: tuple[PathTerm, ...]
    flags: tuple[FlagConstraint, ...]
    flag_sets: tuple[tuple[str, ...], ...]
    closed_flags: bool
    exact: bool
    value_flags: frozenset[str]
    extra_values: frozenset[str] = frozenset()
    allow_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.raw or not self.path:
            raise ValueError("ShellPattern requires non-empty source and command path")
        if not self.extra_values.issubset(self.value_flags):
            raise ValueError("external values must be included in value_flags")
        constrained_values = {
            constraint.atom for constraint in self.flags if constraint.value_glob is not None
        }
        if not constrained_values.issubset(self.value_flags):
            raise ValueError("value-constrained flags must be included in value_flags")

    def matches(self, segment: Segment, *, ambiguous_option_values: bool = False) -> bool:
        from .shellpattern import match_shell_pattern

        return match_shell_pattern(self, segment, ambiguous_option_values=ambiguous_option_values)

    def serialize(self) -> str | JsonObject:
        shell_str = f"Shell({self.raw})"
        if not self.extra_values and not self.allow_paths:
            return shell_str
        opts: JsonObject = {}
        if self.extra_values:
            opts["values"] = sorted(self.extra_values)
        if self.allow_paths:
            opts["allowPaths"] = list(self.allow_paths)
        return {shell_str: opts}


_URL_ARG_KEYS = frozenset({"url", "uri", "href"})
_PATH_ARG_KEYS = frozenset(
    {"path", "file_path", "filepath", "paths", "file_paths", "notebook_path", "absolute_path"}
)
_MAX_ARG_NODES = 1000


@dataclass(frozen=True)
class NamedTool(Rule):
    """Non-shell tool rule: a name plus an optional argument specifier.

    Name matches exactly (``Read``), as a prefix glob (``mcp__memory__*``), or as ``*``.
    The optional specifier scopes by the tool's input, keyed by conventional field names so
    the same syntax works for any tool without hard-coding tool names:

    - ``WebFetch(domain:github.com)`` — a URL field (``url`` / ``uri`` / ``href``) whose
      host is ``github.com`` or a subdomain.
    - ``Read(/etc/**)`` / ``Edit(src/*)`` — a path field (``path`` / ``file_path`` / …)
      matching the glob: ``*`` within one segment, ``**`` across ``/``.
    - bare name / ``(*)`` / ``()`` — matches the tool regardless of input.
    """

    name: str
    specifier: str | None = None

    def matches(self, name: str, arguments: ToolArguments = ()) -> bool:
        if not self._name_matches(name):
            return False
        if self.specifier is None or self.specifier == "*":
            return True
        return self._specifier_matches(arguments)

    def _name_matches(self, name: str) -> bool:
        if self.name in ("*", name):
            return True
        return self.name.endswith("*") and name.startswith(self.name[:-1])

    def _specifier_matches(self, arguments: ToolArguments) -> bool:
        spec = self.specifier
        if spec is None:
            return True
        if spec.startswith("domain:"):
            host = spec[len("domain:"):]
            return any(_url_host_matches(value, host) for key, value in arguments if key.lower() in _URL_ARG_KEYS)
        return any(_path_glob_matches(spec, value) for key, value in arguments if key.lower() in _PATH_ARG_KEYS)

    def serialize(self) -> str:
        return self.name if self.specifier is None else f"{self.name}({self.specifier})"


@dataclass(frozen=True)
class PythonCallPolicy:
    """User decisions for statically resolved Python call targets."""

    deny: frozenset[str] = frozenset()
    ask: frozenset[str] = frozenset()
    allow: frozenset[str] = frozenset()

    def decision_for(self, target: str) -> Decision | None:
        if target in self.deny:
            return Decision.Deny
        if target in self.ask:
            return Decision.Ask
        if target in self.allow:
            return Decision.Allow
        return None

    def merged_with(self, other: PythonCallPolicy) -> PythonCallPolicy:
        return PythonCallPolicy(
            deny=self.deny | other.deny,
            ask=self.ask | other.ask,
            allow=self.allow | other.allow,
        )


def _url_host_matches(value: str, host: str) -> bool:
    """True if ``value`` is a URL whose host equals ``host`` or is a subdomain of it."""
    target = _idna_host(host)
    if not target:
        return False
    try:
        parsed = urllib.parse.urlparse(value if "//" in value else f"//{value}")
        actual = _idna_host(parsed.hostname or "")
    except ValueError:
        return False
    return bool(actual) and (actual == target or actual.endswith(f".{target}"))


def _idna_host(host: str) -> str:
    """Canonicalize a host for comparison: lowercase, no trailing root dot, IDNA/ASCII form."""
    host = host.rstrip(".").lower()
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def _path_glob_matches(pattern: str, value: str) -> bool:
    """Glob match where ``*`` stays within one path segment and ``**`` crosses ``/``.

    The value's ``.``/``..`` segments are normalized first, so a scope can't be escaped via
    traversal (``/repo/src/../secrets`` is matched as ``/repo/secrets``).
    """
    return re.fullmatch(_glob_to_regex(pattern), posixpath.normpath(value)) is not None


def _glob_to_regex(pattern: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)


def tool_arguments(value: object) -> ToolArguments:
    """Flatten a tool-input payload to (field-name, string-value) pairs for scoping.

    Breadth-first and bounded by ``_MAX_ARG_NODES`` so a deep or huge payload can't cause
    ``RecursionError`` or unbounded work; shallow (authoritative) fields are kept first.
    List items inherit their containing field's name.
    """
    out: list[tuple[str, str]] = []
    queue: deque[tuple[str, object]] = deque([("", value)])
    seen = 0
    while queue and seen < _MAX_ARG_NODES:
        key, node = queue.popleft()
        seen += 1
        if isinstance(node, str):
            out.append((key, node))
        elif isinstance(node, dict):
            for sub_key, sub_value in node.items():
                if isinstance(sub_key, str) and len(queue) < _MAX_ARG_NODES:
                    queue.append((sub_key, sub_value))
        elif isinstance(node, list):
            for item in node:
                if len(queue) < _MAX_ARG_NODES:
                    queue.append((key, item))
    return tuple(out)


def basename(arg: str) -> str:
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


# Synthetic argv markers the parser emits for predicate constructs — never real
# commands, so user rules can't meaningfully target them. Matched *before* user
# rules in ``_match_bash`` and always allowed. ``test_command`` (`[ … ]` and
# `[[ … ]]`) both collapse to ``"["``; arithmetic ``(( … ))`` to ``"(("``.
_SYNTHETIC_INERT_MARKERS: frozenset[str] = frozenset({"[", "[[", "(("})

# Real shell builtins with no OS-level side effect of their own. Allowed as a
# *fallback* in ``_match_bash`` when no user rule matches — an explicit
# ``deny``/``ask``/``allow`` rule on one of these still takes precedence.
# Redirect verdicts are applied independently in ``_decide_segment``, so e.g.
# ``echo foo > out`` still surfaces an Ask via the redirect rule.
_INERT_COMMAND_NAMES: frozenset[str] = frozenset({
    "true", "false", ":",       # status setters / no-op
    "continue",                  # loop control in the current shell
    "read",                     # in-process variable bind only
    "echo", "printf",           # output to fds; redirects evaluated separately
})


@dataclass(frozen=True)
class Policy:
    deny: tuple[Rule, ...] = ()
    ask: tuple[Rule, ...] = ()
    allow: tuple[Rule, ...] = ()
    redirection: RedirectionPolicy = RedirectionPolicy()
    python_calls: PythonCallPolicy = PythonCallPolicy()

    def __post_init__(self) -> None:
        if any(isinstance(rule, PythonReadonly) for rule in self.deny + self.ask):
            raise PolicyError("Python(readonly) is only valid in permissions.allow")

    def decide(self, request: Request) -> Verdict:
        if isinstance(request, ShellRequest):
            return self._decide_shell(request.pipeline, request.cwd)
        if isinstance(request, ToolRequest):
            return self._decide_tool(request.tool, request.arguments)
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
            redirection=self.redirection.merged_with(other.redirection),
            python_calls=self.python_calls.merged_with(other.python_calls),
        )

    def _decide_shell(self, pipeline: Pipeline, cwd: Path | None = None) -> Verdict:
        if not pipeline.parseable:
            return Verdict(Decision.Ask, pipeline.unparseable_reason or "shell syntax not safely parseable")
        if not pipeline.segments:
            return Verdict(Decision.NoOpinion, "")
        verdicts = [self._decide_segment(seg, cwd) for seg in pipeline.segments]
        return aggregate(verdicts)

    def _decide_segment(self, segment: Segment, cwd: Path | None = None) -> Verdict:
        from .shell import evaluate_redirects

        command_verdict, _ = self._match_bash(segment)
        rule_paths: list[str] = []
        for decision, rule in self.all_rules():
            if (
                decision == Decision.Allow
                and isinstance(rule, ShellPattern)
                and rule.allow_paths
                and rule.matches(segment, ambiguous_option_values=False)
            ):
                rule_paths.extend(rule.allow_paths)
        allow_paths = tuple(dict.fromkeys(self.redirection.allow_paths + tuple(rule_paths)))
        redirect_verdict = evaluate_redirects(
            segment.redirects, self.redirection, allow_paths=allow_paths, cwd=cwd,
        )
        return _stricter(redirect_verdict, command_verdict)

    def _match_bash(self, segment: Segment) -> tuple[Verdict, Rule | None]:
        from .shell import ALL_EXEC_WRAPPERS, is_command_lookup, is_opaque_shell_command
        argv0 = basename(segment.argv[0]) if segment.argv else None
        if argv0 in _SYNTHETIC_INERT_MARKERS:
            return Verdict(Decision.Allow, "inert predicate"), None
        shell_verdict: Verdict | None = None
        matched_rule: Rule | None = None
        for decision, rule in self.all_rules():
            if isinstance(rule, ShellPattern):
                matches = rule.matches(
                    segment,
                    ambiguous_option_values=decision is not Decision.Allow,
                )
            else:
                matches = isinstance(rule, BashCommand | BashOption) and rule.matches(segment)
            if matches:
                rationale = rule.rationale if isinstance(rule, BashOption) else _format_rule(rule, decision)
                shell_verdict = Verdict(decision, rationale)
                matched_rule = rule
                break

        python_verdict: Verdict | None = None
        if any(isinstance(rule, PythonReadonly) for rule in self.allow):
            from .pythoncode import analyze_python_segment

            python_verdict = analyze_python_segment(segment, self.python_calls)
        if python_verdict is not None:
            combined = python_verdict if shell_verdict is None else _stricter(shell_verdict, python_verdict)
            return combined, matched_rule
        if shell_verdict is not None:
            return shell_verdict, matched_rule
        if is_command_lookup(segment):
            return Verdict(Decision.Allow, "command lookup"), None
        if is_opaque_shell_command(segment) or (argv0 in ALL_EXEC_WRAPPERS):
            return Verdict(Decision.Ask, f"unanalyzable command wrapper {segment.argv[0]!r}"), None
        if segment.argv and "$" in segment.argv[0]:
            return Verdict(Decision.Ask, f"dynamic command name {segment.argv[0]!r}"), None
        if argv0 in _INERT_COMMAND_NAMES:
            return Verdict(Decision.Allow, "inert shell builtin"), None
        return Verdict(Decision.NoOpinion, f"no rule matched {segment.argv[0] if segment.argv else '<empty>'!r}"), None

    def _decide_tool(self, name: str, arguments: ToolArguments) -> Verdict:
        for decision, rule in self.all_rules():
            if isinstance(rule, NamedTool) and rule.matches(name, arguments):
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
