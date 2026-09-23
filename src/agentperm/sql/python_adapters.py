"""Adapters for Python libraries that wrap SQL text before execution."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class PythonSqlCallAdapter:
    """Describe a pure call whose single argument remains the SQL source."""

    targets: frozenset[str]

    def unwrap(self, node: ast.Call, target: str | None) -> ast.expr | None:
        if target not in self.targets or len(node.args) != 1 or node.keywords:
            return None
        return node.args[0]


PYTHON_SQL_CALL_ADAPTERS: tuple[PythonSqlCallAdapter, ...] = (
    PythonSqlCallAdapter(
        frozenset(
            {
                "sqlalchemy.text",
                "sqlalchemy.sql.text",
                "sqlalchemy.sql.expression.text",
            }
        )
    ),
)
