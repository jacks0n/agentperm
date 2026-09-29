"""Policy precedence and permission evaluation."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import PolicyError
from .mcp import McpToolRequest, McpToolRule
from .model import (
    BashCommand,
    BashOption,
    CompoundRequest,
    Decision,
    NamedTool,
    Pipeline,
    PythonCallPolicy,
    PythonReadonly,
    PythonSqlPattern,
    RedirectionPolicy,
    RejectedRequest,
    Request,
    Rule,
    Segment,
    ShellPattern,
    ShellRequest,
    ToolArguments,
    ToolRequest,
    Verdict,
    basename,
)

_STRICTNESS = {Decision.Deny: 3, Decision.Ask: 2, Decision.Allow: 1, Decision.NoOpinion: 0}


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
_INERT_COMMAND_NAMES: frozenset[str] = frozenset(
    {
        "true",
        "false",
        ":",  # status setters / no-op
        "break",  # loop control in the current shell
        "continue",  # loop control in the current shell
        "export",  # in-process variable export only
        "read",  # in-process variable bind only
        "unset",  # in-process variable/function removal only
        "echo",
        "printf",  # output to fds; redirects evaluated separately
    }
)

_INERT_COMMAND_SHAPES: frozenset[tuple[str, ...]] = frozenset(
    {
        ("set", "+a"),  # disable automatic export of subsequently assigned variables
        ("set", "-a"),  # enable automatic export of subsequently assigned variables
    }
)


def _is_inert_command_shape(argv: tuple[str, ...]) -> bool:
    """Return whether argv only changes non-persistent state in the current shell."""
    return argv in _INERT_COMMAND_SHAPES or (len(argv) >= 2 and argv[:2] == ("set", "--"))


@dataclass(frozen=True)
class Policy:
    deny: tuple[Rule, ...] = ()
    ask: tuple[Rule, ...] = ()
    allow: tuple[Rule, ...] = ()
    redirection: RedirectionPolicy = field(default_factory=RedirectionPolicy)
    python_calls: PythonCallPolicy = field(default_factory=PythonCallPolicy)
    _precedence: tuple[tuple[Decision, Rule], ...] = field(default=(), compare=False, repr=False)

    def __post_init__(self) -> None:
        if any(isinstance(rule, PythonReadonly) for rule in self.deny + self.ask):
            raise PolicyError("Python(readonly) is only valid in permissions.allow")

    def decide(self, request: Request, *, path_base: Path | None = None) -> Verdict:
        from ..sql.domain import SqlRequest, SqlRule

        if isinstance(request, SqlRequest):
            from ..sql.service import SqlPolicyService

            rules = tuple((decision, rule) for decision, rule in self.all_rules() if isinstance(rule, SqlRule))
            return SqlPolicyService(rules).decide(request.sql)
        if isinstance(request, ShellRequest):
            return self._decide_shell(request.pipeline, request.cwd)
        if isinstance(request, ToolRequest):
            return self._decide_tool(request.tool, request.arguments, request.cwd, path_base)
        if isinstance(request, McpToolRequest):
            return self._decide_mcp_tool(request.server, request.tool)
        if isinstance(request, CompoundRequest):
            return aggregate([self.decide(part, path_base=path_base) for part in request.requests])
        if isinstance(request, RejectedRequest):
            return Verdict(Decision.Deny, request.rationale)
        return Verdict(Decision.NoOpinion, "unrecognized request")

    def all_rules(self) -> Iterator[tuple[Decision, Rule]]:
        for rule in self.deny:
            yield Decision.Deny, rule
        yield from self._non_deny_rules()

    def _non_deny_rules(self) -> tuple[tuple[Decision, Rule], ...]:
        """Ask/Allow rules in evaluation order, most-specific policy layer first."""
        if self._precedence:
            return self._precedence
        return tuple((Decision.Ask, rule) for rule in self.ask) + tuple((Decision.Allow, rule) for rule in self.allow)

    def decide_segments(self, request: ShellRequest) -> list[tuple[Segment, Verdict]]:
        """Per-segment verdicts for a parseable shell request (`agentperm why`).

        Empty for an unparseable pipeline; ``decide`` reports that case as one
        aggregate ``Ask`` verdict.
        """
        if not request.pipeline.parseable:
            return []
        return [(segment, self._decide_segment(segment, request.cwd)) for segment in request.pipeline.segments]

    def merged_with(self, other: Policy) -> Policy:
        """Merge ``other`` as a more-specific policy layer over this policy."""

        def union(a: tuple[Rule, ...], b: tuple[Rule, ...]) -> tuple[Rule, ...]:
            seen: list[Rule] = list(a)
            for rule in b:
                if rule not in seen:
                    seen.append(rule)
            return tuple(seen)

        precedence = tuple(dict.fromkeys(other._non_deny_rules() + self._non_deny_rules()))
        return Policy(
            deny=union(self.deny, other.deny),
            ask=union(self.ask, other.ask),
            allow=union(self.allow, other.allow),
            redirection=self.redirection.merged_with(other.redirection),
            python_calls=self.python_calls.merged_with(other.python_calls),
            _precedence=precedence,
        )

    def _decide_shell(self, pipeline: Pipeline, cwd: Path | None = None) -> Verdict:
        if not pipeline.parseable:
            return Verdict(Decision.Ask, pipeline.unparseable_reason or "shell syntax not safely parseable")
        if not pipeline.segments:
            return Verdict(Decision.NoOpinion, "")
        verdicts = [self._decide_segment(seg, cwd) for seg in pipeline.segments]
        return aggregate(verdicts)

    def _decide_segment(self, segment: Segment, cwd: Path | None = None) -> Verdict:
        from ..shell import evaluate_redirects

        command_verdict, _ = self._match_bash(segment, cwd)
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
            segment.redirects,
            self.redirection,
            allow_paths=allow_paths,
            cwd=cwd,
        )
        return _stricter(redirect_verdict, command_verdict)

    def _match_bash(self, segment: Segment, cwd: Path | None = None) -> tuple[Verdict, Rule | None]:
        from ..shell import ALL_EXEC_WRAPPERS, is_command_lookup, is_opaque_shell_command, parse_pipeline
        from ..shellpattern import match_shell_pattern_details

        argv0 = basename(segment.argv[0]) if segment.argv else None
        if argv0 in _SYNTHETIC_INERT_MARKERS:
            return Verdict(Decision.Allow, "inert predicate"), None
        shell_verdict: Verdict | None = None
        matched_rule: Rule | None = None
        for decision, rule in self.all_rules():
            if isinstance(rule, ShellPattern):
                match = match_shell_pattern_details(
                    rule,
                    segment,
                    ambiguous_option_values=decision is not Decision.Allow,
                )
                if match is None:
                    continue
                base = Verdict(decision, _format_rule(rule, decision))
                semantic_verdicts: list[Verdict] = []
                if match.sql:
                    from ..sql.domain import SqlRule
                    from ..sql.service import SqlPolicyService

                    sql_rules = tuple(
                        (sql_decision, sql_rule)
                        for sql_decision, sql_rule in self.all_rules()
                        if isinstance(sql_rule, SqlRule)
                    )
                    service = SqlPolicyService(sql_rules)
                    semantic_verdicts.extend(service.decide(captured) for captured in match.sql)
                semantic_verdicts.extend(
                    self._decide_shell(parse_pipeline(source), cwd) for source in match.nested_shell
                )
                semantic_verdicts.extend(self._decide_segment(Segment(argv, ()), cwd) for argv in match.nested_exec)
                shell_verdict = aggregate([base, *semantic_verdicts]) if semantic_verdicts else base
                matched_rule = rule
                break
            elif isinstance(rule, BashCommand | BashOption) and rule.matches(segment):
                shell_verdict = Verdict(decision, _format_rule(rule, decision))
                matched_rule = rule
                break

        python_verdict: Verdict | None = None
        python_rule = next(
            (
                rule
                for decision, rule in self.all_rules()
                if decision is Decision.Allow and isinstance(rule, PythonReadonly)
            ),
            None,
        )
        python_patterns = tuple(
            (decision, rule) for decision, rule in self.all_rules() if isinstance(rule, PythonSqlPattern)
        )
        if python_rule is not None or python_patterns:
            from ..pythoncode import analyze_python_segment
            from ..sql.domain import SqlRule
            from ..sql.service import SqlPolicyService

            sql_rules = tuple((decision, rule) for decision, rule in self.all_rules() if isinstance(rule, SqlRule))
            python_verdict = analyze_python_segment(
                segment,
                self.python_calls,
                sql_patterns=python_patterns,
                sql_service=SqlPolicyService(sql_rules),
                require_sql_capture=python_rule is None,
            )
            if (
                python_verdict is not None
                and python_verdict.decision is Decision.Allow
                and python_rule is not None
                and python_rule.rationale
            ):
                python_verdict = Verdict(Decision.Allow, python_rule.rationale)
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
        if _is_inert_command_shape(segment.argv):
            return Verdict(Decision.Allow, "inert shell setup"), None
        if argv0 in _INERT_COMMAND_NAMES:
            return Verdict(Decision.Allow, "inert shell builtin"), None
        return Verdict(Decision.NoOpinion, f"no rule matched {segment.argv[0] if segment.argv else '<empty>'!r}"), None

    def _decide_tool(
        self,
        name: str,
        arguments: ToolArguments,
        cwd: Path | None = None,
        path_base: Path | None = None,
    ) -> Verdict:
        for decision, rule in self.all_rules():
            if isinstance(rule, NamedTool) and rule.matches(
                name,
                arguments,
                cwd,
                path_base=path_base,
                conservative_paths=decision is not Decision.Allow,
            ):
                return Verdict(decision, _format_rule(rule, decision))
        return Verdict(Decision.NoOpinion, f"no rule matched {name!r}")

    def _decide_mcp_tool(self, server: str, tool: str) -> Verdict:
        for decision, rule in self.all_rules():
            if isinstance(rule, McpToolRule) and rule.matches(server, tool):
                return Verdict(decision, _format_rule(rule, decision))
        return Verdict(Decision.NoOpinion, f"no rule matched MCP({server}.{tool})")


def _format_rule(rule: Rule, decision: Decision) -> str:
    if rule.rationale:
        return rule.rationale
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
