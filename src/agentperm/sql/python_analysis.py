"""Application service for evaluating SQL captured from Python calls."""

from __future__ import annotations

import ast
import fnmatch
from collections.abc import Callable
from dataclasses import dataclass

from ..domain import Decision, PythonSqlPattern, Verdict
from .domain import CapturedSql, SqlCaptureKind, SqlOrigin
from .python_capture import PythonSqlSourceResolver
from .service import SqlPolicyService


@dataclass(frozen=True)
class PythonSqlCallResult:
    matched: bool
    verdicts: tuple[Verdict, ...] = ()
    allow_rationale: str | None = None


class PythonSqlAnalysis:
    """Own SQL-source flow tracking and policy evaluation for Python AST analysis."""

    def __init__(
        self,
        patterns: tuple[tuple[Decision, PythonSqlPattern], ...],
        service: SqlPolicyService | None,
        call_target: Callable[[ast.expr], str | None],
    ) -> None:
        self.patterns = patterns
        self.service = service
        self.sources = PythonSqlSourceResolver(call_target)
        self.matched_pattern = False

    def match_call(self, node: ast.Call, target: str) -> PythonSqlCallResult:
        configured = next(
            ((decision, pattern) for decision, pattern in self.patterns if fnmatch.fnmatchcase(target, pattern.target)),
            None,
        )
        if configured is None:
            return PythonSqlCallResult(False)
        self.matched_pattern = True
        decision, pattern = configured
        if decision is Decision.Deny:
            return PythonSqlCallResult(
                True,
                (Verdict(Decision.Deny, pattern.rationale or f"Python SQL call denied by policy: {target}"),),
            )
        argument = self._argument(node, pattern)
        texts = self.sources.resolve(argument)
        if texts is None:
            return PythonSqlCallResult(
                True,
                (Verdict(Decision.Ask, f"SQL argument for Python call {target} is not a static string"),),
            )
        verdicts: list[Verdict] = []
        if decision is Decision.Ask:
            verdicts.append(
                Verdict(Decision.Ask, pattern.rationale or f"Python SQL call requires approval by policy: {target}")
            )
        if self.service is None:
            verdicts.append(Verdict(Decision.Ask, f"no SQL policy is configured for Python call {target}"))
        else:
            verdicts.extend(
                self.service.decide(
                    CapturedSql(text, pattern.profile, SqlOrigin(SqlCaptureKind.PythonArgument, target))
                )
                for text in texts
            )
        rationale = (
            pattern.rationale
            if decision is Decision.Allow and all(item.decision is Decision.Allow for item in verdicts)
            else None
        )
        return PythonSqlCallResult(True, tuple(verdicts), rationale)

    @staticmethod
    def _argument(node: ast.Call, pattern: PythonSqlPattern) -> ast.expr | None:
        if pattern.position is not None and len(node.args) > pattern.position:
            return node.args[pattern.position]
        if pattern.keyword is not None:
            return next((item.value for item in node.keywords if item.arg == pattern.keyword), None)
        return None
