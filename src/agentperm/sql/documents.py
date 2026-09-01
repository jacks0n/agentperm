"""Extract SQL from interactive-client document formats."""

from __future__ import annotations

import re

from .domain import SqlDocumentFormat


class SqlDocumentError(ValueError):
    pass


_SQLPLUS_SAFE_SET = frozenset(
    {
        "echo",
        "feedback",
        "heading",
        "linesize",
        "newpage",
        "null",
        "numwidth",
        "pagesize",
        "sqlprompt",
        "tab",
        "termout",
        "timing",
        "trimout",
        "trimspool",
        "verify",
        "wrap",
    }
)
_SQLPLUS_UNSAFE = re.compile(
    r"^\s*(?:host|spool|start|@{1,2}|define|undefine|variable|print|accept|password|connect|disconnect|store|save|get|edit)\b",
    re.IGNORECASE,
)
_SQLITE_SAFE = frozenset({".headers", ".mode", ".nullvalue", ".quit", ".width"})


def sql_text(document: str, document_format: SqlDocumentFormat) -> str:
    if document_format is SqlDocumentFormat.Plain:
        return document
    lines: list[str] = []
    for line in document.splitlines():
        stripped = line.strip()
        if document_format is SqlDocumentFormat.SqlPlus:
            words = stripped.lower().split()
            if stripped == "/" or (words and words[0] in {"exit", "quit", "column", "col", "remark"}):
                continue
            if words and words[0] == "set":
                if len(words) >= 2 and words[1] in _SQLPLUS_SAFE_SET:
                    continue
                raise SqlDocumentError(f"unsupported SQL*Plus SET directive: {stripped}")
            if _SQLPLUS_UNSAFE.match(line):
                raise SqlDocumentError(f"effectful SQL*Plus directive: {stripped}")
        elif document_format is SqlDocumentFormat.Psql and stripped.startswith("\\"):
            command = stripped.split(maxsplit=1)[0].lower()
            if command in {"\\pset", "\\x", "\\timing", "\\q", "\\quit"}:
                continue
            raise SqlDocumentError(f"unsupported psql meta-command: {command}")
        elif document_format is SqlDocumentFormat.MySql:
            if re.match(r"^\s*(?:delimiter|source|tee|notee|system)\b", line, re.IGNORECASE):
                raise SqlDocumentError(f"unsupported mysql client directive: {stripped}")
        elif document_format is SqlDocumentFormat.Sqlite and stripped.startswith("."):
            command = stripped.split(maxsplit=1)[0].lower()
            if command in _SQLITE_SAFE:
                continue
            raise SqlDocumentError(f"unsupported sqlite meta-command: {command}")
        lines.append(line)
    return "\n".join(lines).strip()
