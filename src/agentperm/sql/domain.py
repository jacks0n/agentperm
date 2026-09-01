"""Stable SQL policy value objects, independent of the parser library."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import StrEnum

from ..domain import JsonObject, Request, Rule


class SqlDialect(StrEnum):
    Oracle = "oracle"
    Postgres = "postgres"
    MySql = "mysql"
    Sqlite = "sqlite"


class SqlDocumentFormat(StrEnum):
    Plain = "plain"
    SqlPlus = "sqlplus"
    Psql = "psql"
    MySql = "mysql"
    Sqlite = "sqlite"


class SqlEffect(StrEnum):
    Read = "read"
    DataWrite = "data-write"
    SchemaWrite = "schema-write"
    SessionChange = "session-change"
    TransactionControl = "transaction-control"
    Lock = "lock"
    ExternalIo = "external-io"
    CodeExecution = "code-execution"
    Unknown = "unknown"


class SqlStatementKind(StrEnum):
    Query = "query"
    Insert = "insert"
    Update = "update"
    Delete = "delete"
    Merge = "merge"
    Ddl = "ddl"
    Session = "session"
    Transaction = "transaction"
    Explain = "explain"
    Other = "other"


class SqlSelectorMode(StrEnum):
    Some = "any"
    Every = "all"
    Exclusive = "only"


@dataclass(frozen=True)
class SqlSelector:
    mode: SqlSelectorMode
    patterns: tuple[str, ...]

    def matches(self, values: tuple[str, ...], *, unknown: bool = False) -> bool:
        candidates = tuple(
            (value, value.split(":", 1)[1]) if ":" in value else (value,)
            for value in values
        )
        hits = tuple(
            any(
                fnmatch.fnmatchcase(candidate.lower(), pattern.lower())
                for candidate in alternatives
                for pattern in self.patterns
            )
            for alternatives in candidates
        )
        if self.mode is SqlSelectorMode.Some:
            return bool(values) and any(hits)
        if self.mode is SqlSelectorMode.Every:
            return all(hits)
        return not unknown and all(hits)

    def serialize(self) -> JsonObject:
        return {self.mode.value: list(self.patterns)}


@dataclass(frozen=True)
class SqlRelationRef:
    name: str


@dataclass(frozen=True)
class SqlFunctionRef:
    name: str
    builtin: bool


@dataclass(frozen=True)
class SqlFacts:
    effects: frozenset[SqlEffect]
    statements: tuple[SqlStatementKind, ...]
    relations: tuple[SqlRelationRef, ...]
    functions: tuple[SqlFunctionRef, ...]


class SqlCaptureKind(StrEnum):
    Argument = "argument"
    OptionValue = "option-value"
    Stdin = "stdin"
    PythonArgument = "python-argument"


@dataclass(frozen=True)
class SqlOrigin:
    kind: SqlCaptureKind
    description: str


@dataclass(frozen=True)
class CapturedSql:
    text: str
    profile: str | None
    origin: SqlOrigin


@dataclass(frozen=True)
class SqlRequest(Request):
    sql: CapturedSql


@dataclass(frozen=True)
class SqlRule(Rule):
    name: str
    dialect: SqlDialect
    document_format: SqlDocumentFormat = SqlDocumentFormat.Plain
    effects: SqlSelector | None = None
    statements: SqlSelector | None = None
    relations: SqlSelector | None = None
    functions: SqlSelector | None = None
    rationale: str = field(default="", compare=False)

    def matches(self, facts: SqlFacts) -> bool:
        effect_values = tuple(effect.value for effect in sorted(facts.effects, key=lambda item: item.value))
        statement_values = tuple(statement.value for statement in facts.statements)
        relation_values = tuple(ref.name for ref in facts.relations)
        function_values = tuple(ref.name for ref in facts.functions)
        if self.effects is not None and not self.effects.matches(
            effect_values,
            unknown=SqlEffect.Unknown in facts.effects,
        ):
            return False
        if self.statements is not None and not self.statements.matches(statement_values):
            return False
        if self.relations is not None and not self.relations.matches(relation_values):
            return False
        if self.functions is not None and not self.functions.matches(function_values):
            return False
        return self.functions is not None or all(ref.builtin for ref in facts.functions)

    def serialize(self) -> str | JsonObject:
        metadata: JsonObject = {"dialect": self.dialect.value, "format": self.document_format.value}
        for key, selector in (
            ("effects", self.effects),
            ("statements", self.statements),
            ("relations", self.relations),
            ("functions", self.functions),
        ):
            if selector is not None:
                metadata[key] = selector.serialize()
        if self.rationale:
            metadata["reason"] = self.rationale
        return {f"SQL({self.name})": metadata}
