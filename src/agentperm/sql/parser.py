"""sqlglot adapter: SQL text to agentperm facts."""

from __future__ import annotations

import logging
import re
from threading import Lock

from sqlglot import ErrorLevel, Expr, exp, parse
from sqlglot.errors import ParseError, TokenError
from sqlglot.optimizer.scope import traverse_scope

from .documents import SqlDocumentError, sql_text
from .domain import (
    SqlDialect,
    SqlDocumentFormat,
    SqlEffect,
    SqlFacts,
    SqlFunctionRef,
    SqlRelationRef,
    SqlStatementKind,
)


class SqlParseError(ValueError):
    pass


_MAX_SOURCE_BYTES = 250_000
_MAX_STATEMENTS = 100
_MAX_AST_NODES = 50_000
_WRITE_ROOTS: tuple[type[Expr], ...] = (exp.Insert, exp.Update, exp.Delete, exp.Merge)
_DDL_ROOTS: tuple[type[Expr], ...] = (exp.Create, exp.Drop, exp.Alter, exp.TruncateTable)
_SESSION_ROOTS: tuple[type[Expr], ...] = (
    exp.Set,
    exp.Use,
    exp.Pragma,
    exp.Attach,
    exp.Detach,
    exp.Analyze,
)
_TRANSACTION_ROOTS: tuple[type[Expr], ...] = (exp.Commit, exp.Rollback, exp.Transaction)
_SQLGLOT_LOGGER = logging.getLogger("sqlglot")
_SQLGLOT_PARSE_LOCK = Lock()
_POSTGRES_EXPLAIN_OPTIONS = frozenset({
    "analyze", "buffers", "costs", "format", "generic_plan", "memory",
    "serialize", "settings", "summary", "timing", "verbose", "wal",
})
_POSTGRES_EXPLAIN_VALUES = frozenset({
    "binary", "false", "json", "none", "off", "on", "text", "true", "xml", "yaml",
})
_POSTGRES_EXPLAIN_LEGACY_OPTION = re.compile(r"(?i)^(analyze|verbose)\b")


def parse_sql(document: str, dialect: SqlDialect, document_format: SqlDocumentFormat) -> SqlFacts:
    if len(document.encode()) > _MAX_SOURCE_BYTES:
        raise SqlParseError(f"SQL document exceeds {_MAX_SOURCE_BYTES} byte analysis limit")
    try:
        source = sql_text(document, document_format)
    except SqlDocumentError as error:
        raise SqlParseError(str(error)) from error
    if not source:
        raise SqlParseError("SQL document contains no SQL statements")
    try:
        parsed = _parse_without_library_stderr(source, dialect)
    except (ParseError, TokenError, ValueError) as error:
        raise SqlParseError(str(error)) from error
    parsed_roots = tuple(root for root in parsed if root is not None)
    if not parsed_roots:
        raise SqlParseError("SQL parser returned an opaque or empty statement")
    roots = tuple(_classifiable_root(root, dialect) for root in parsed_roots)
    if len(roots) > _MAX_STATEMENTS:
        raise SqlParseError(f"SQL document exceeds {_MAX_STATEMENTS} statement analysis limit")

    effects: set[SqlEffect] = set()
    statements: list[SqlStatementKind] = []
    relations: dict[str, SqlRelationRef] = {}
    functions: dict[str, SqlFunctionRef] = {}
    node_count = 0
    for root, statement_kind in roots:
        statements.append(statement_kind)
        for scope in traverse_scope(root):
            for table in scope.tables:
                relation = _qualified_name(table, dialect)
                if relation and table.name not in scope.cte_sources:
                    relations.setdefault(relation.lower(), SqlRelationRef(relation.lower()))
        for node in root.walk():
            node_count += 1
            if node_count > _MAX_AST_NODES:
                raise SqlParseError(f"SQL document exceeds {_MAX_AST_NODES} node analysis limit")
            _record_effect(node, effects)
            if isinstance(node, exp.Func):
                ref = _function_ref(node, dialect)
                functions.setdefault(ref.name.lower(), ref)
    if not effects:
        effects.add(SqlEffect.Unknown)
    return SqlFacts(
        effects=frozenset(effects),
        statements=tuple(statements),
        relations=tuple(relations.values()),
        functions=tuple(functions.values()),
    )


def _classifiable_root(root: Expr, dialect: SqlDialect) -> tuple[Expr, SqlStatementKind]:
    if not isinstance(root, exp.Command):
        return root, _statement_kind(root)
    if dialect is not SqlDialect.Postgres or str(root.this).upper() != "EXPLAIN":
        raise SqlParseError("SQL parser returned an opaque or empty statement")
    expression = root.expression
    if not isinstance(expression, exp.Literal) or not expression.is_string:
        raise SqlParseError("PostgreSQL EXPLAIN body is not statically available")
    inner_source = _postgres_explain_inner(expression.this)
    inner_roots = tuple(item for item in _parse_without_library_stderr(inner_source, dialect) if item is not None)
    if len(inner_roots) != 1 or isinstance(inner_roots[0], exp.Command):
        raise SqlParseError("PostgreSQL EXPLAIN must contain one classifiable statement")
    return inner_roots[0], SqlStatementKind.Explain


def _postgres_explain_inner(source: str) -> str:
    remaining = source.strip()
    if remaining.startswith("("):
        closing = remaining.find(")")
        if closing < 0:
            raise SqlParseError("PostgreSQL EXPLAIN options are not closed")
        options = remaining[1:closing]
        if not options.strip():
            raise SqlParseError("PostgreSQL EXPLAIN option list is empty")
        for raw_option in options.split(","):
            parts = raw_option.strip().lower().split()
            if not 1 <= len(parts) <= 2 or parts[0] not in _POSTGRES_EXPLAIN_OPTIONS:
                raise SqlParseError("PostgreSQL EXPLAIN contains an unsupported option")
            if len(parts) == 2 and parts[1] not in _POSTGRES_EXPLAIN_VALUES:
                raise SqlParseError("PostgreSQL EXPLAIN contains an unsupported option value")
        remaining = remaining[closing + 1:].strip()
    else:
        while match := _POSTGRES_EXPLAIN_LEGACY_OPTION.match(remaining):
            remaining = remaining[match.end():].lstrip()
    if not remaining:
        raise SqlParseError("PostgreSQL EXPLAIN contains no statement")
    return remaining


def _parse_without_library_stderr(source: str, dialect: SqlDialect) -> list[Expr | None]:
    """Parse while suppressing SQLGlot's redundant opaque-command warning.

    SQLGlot logs a warning before returning ``exp.Command`` for unsupported
    syntax even with ``ErrorLevel.RAISE``. Agentperm rejects that node directly,
    so allowing the library warning to escape would pollute hook stderr without
    adding information. The lock makes the temporary logger state safe if this
    adapter is called concurrently in one process.
    """
    with _SQLGLOT_PARSE_LOCK:
        was_disabled = _SQLGLOT_LOGGER.disabled
        _SQLGLOT_LOGGER.disabled = True
        try:
            return parse(source, read=dialect.value, error_level=ErrorLevel.RAISE)
        finally:
            _SQLGLOT_LOGGER.disabled = was_disabled


def _statement_kind(root: Expr) -> SqlStatementKind:
    if isinstance(root, exp.Query):
        return SqlStatementKind.Query
    if isinstance(root, exp.Insert):
        return SqlStatementKind.Insert
    if isinstance(root, exp.Update):
        return SqlStatementKind.Update
    if isinstance(root, exp.Delete):
        return SqlStatementKind.Delete
    if isinstance(root, exp.Merge):
        return SqlStatementKind.Merge
    if isinstance(root, _DDL_ROOTS):
        return SqlStatementKind.Ddl
    if isinstance(root, _SESSION_ROOTS):
        return SqlStatementKind.Session
    if isinstance(root, _TRANSACTION_ROOTS):
        return SqlStatementKind.Transaction
    return SqlStatementKind.Other


def _record_effect(node: Expr, effects: set[SqlEffect]) -> None:
    if isinstance(node, _WRITE_ROOTS):
        effects.add(SqlEffect.DataWrite)
    elif isinstance(node, _DDL_ROOTS):
        effects.add(SqlEffect.SchemaWrite)
    elif isinstance(node, _SESSION_ROOTS):
        effects.add(SqlEffect.SessionChange)
    elif isinstance(node, _TRANSACTION_ROOTS):
        effects.add(SqlEffect.TransactionControl)
    elif isinstance(node, exp.Lock):
        effects.add(SqlEffect.Lock)
    elif isinstance(node, exp.Copy):
        effects.add(SqlEffect.ExternalIo)
    elif isinstance(node, exp.Execute):
        effects.add(SqlEffect.CodeExecution)
    elif isinstance(node, exp.Into):
        effects.add(SqlEffect.DataWrite)
    elif isinstance(node, exp.Query):
        effects.add(SqlEffect.Read)


def _qualified_name(table: exp.Table, dialect: SqlDialect) -> str:
    parts = [part for part in (table.catalog, table.db, table.name) if part]
    return f"{dialect.value}:{'.'.join(parts)}" if parts else ""


def _function_ref(node: exp.Func, dialect: SqlDialect) -> SqlFunctionRef:
    if isinstance(node, exp.Anonymous):
        name = node.name or node.sql_name()
        if isinstance(node.parent, exp.Dot) and node.parent.expression is node:
            name = f"{node.parent.this.sql(dialect=dialect.value)}.{name}"
        return SqlFunctionRef(f"{dialect.value}:{name.lower()}", builtin=False)
    return SqlFunctionRef(f"builtin:{node.sql_name().lower()}", builtin=True)
