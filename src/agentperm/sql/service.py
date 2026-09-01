"""Evaluate captured SQL against the configured SQL rule set."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..domain import Decision, Verdict
from .domain import CapturedSql, SqlFacts, SqlRule
from .parser import SqlParseError, parse_sql


@dataclass
class SqlPolicyService:
    rules: tuple[tuple[Decision, SqlRule], ...]
    _facts_cache: dict[tuple[str, str, str], SqlFacts] = field(default_factory=dict, init=False)
    _failure_cache: dict[tuple[str, str, str], str] = field(default_factory=dict, init=False)

    def decide(self, captured: CapturedSql) -> Verdict:
        deny_rules = tuple(
            (decision, rule)
            for decision, rule in self.rules
            if decision is Decision.Deny
        )
        non_deny_rules = tuple(
            (decision, rule)
            for decision, rule in self.rules
            if decision is not Decision.Deny and (captured.profile is None or rule.name == captured.profile)
        )

        failures: list[str] = []
        denied = self._first_match(captured, deny_rules, failures)
        if denied is not None:
            return denied
        if captured.profile is not None and not non_deny_rules:
            return Verdict(Decision.Ask, f"unknown SQL profile {captured.profile!r}")
        matched = self._first_match(captured, non_deny_rules, failures)
        if matched is not None:
            return matched
        detail = failures[0] if failures else "no SQL rule matched the parsed statements"
        return Verdict(Decision.Ask, f"SQL capture requires approval: {detail}")

    def _first_match(
        self,
        captured: CapturedSql,
        rules: tuple[tuple[Decision, SqlRule], ...],
        failures: list[str],
    ) -> Verdict | None:
        for decision, rule in rules:
            key = (captured.text, rule.dialect.value, rule.document_format.value)
            facts = self._facts_cache.get(key)
            failure = self._failure_cache.get(key)
            if facts is None and failure is None:
                try:
                    facts = parse_sql(captured.text, rule.dialect, rule.document_format)
                except SqlParseError as error:
                    failure = str(error)
                    self._failure_cache[key] = failure
                else:
                    self._facts_cache[key] = facts
            if failure is not None:
                failures.append(f"{rule.dialect.value}/{rule.document_format.value}: {failure}")
                continue
            if facts is None:
                continue
            if rule.matches(facts):
                rationale = rule.rationale or f"{decision.value} by SQL({rule.name})"
                return Verdict(decision, rationale)
        return None
