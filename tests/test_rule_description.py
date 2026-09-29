from __future__ import annotations

import pytest

from agentperm import PolicyError, serialize_rule_json
from agentperm.domain import JsonObject, JsonValue, Rule
from agentperm.rule_description import describe_rule


@pytest.mark.parametrize(
    ("value", "kind", "effect"),
    [
        ("Shell(git status)", "shell", "unknown"),
        ("Bash(git status:*)", "legacy_bash", "unknown"),
        ({"tool": "Bash", "command": "git", "when": {"hasOption": "--help"}}, "bash_option", "unknown"),
        ("Python(readonly)", "python_readonly", "read_only"),
        ("Python(query(<SQL:ro>))", "python_sql_capture", "unknown"),
        ({"SQL(ro)": {"dialect": "sqlite", "effects": {"only": ["read"]}}}, "sql", "read_only"),
        ({"SQL(write)": {"dialect": "sqlite", "effects": {"only": ["data-write"]}}}, "sql", "mutating"),
        ("Read", "capability", "read_only"),
        ("Write(src/**)", "capability", "mutating"),
        ("WebSearch", "capability", "read_only"),
        ("MCP(github.get_*)", "mcp", "unknown"),
    ],
)
def test_describe_rule_uses_authoritative_domain(value: JsonValue, kind: str, effect: str) -> None:
    description = describe_rule(value)
    assert description.kind == kind
    assert description.semantic_effect == effect
    assert description.canonical_value is not None
    assert description.display


def test_python_readonly_is_allow_only() -> None:
    assert describe_rule("Python(readonly)").valid_decisions == ("allow",)


def test_structured_metadata_is_canonicalized() -> None:
    description = describe_rule({"Python(readonly)": {"reason": "Static AST proof"}})
    assert description.canonical_value == {"Python(readonly)": {"reason": "Static AST proof"}}


def test_unparseable_rule_is_rejected() -> None:
    with pytest.raises(PolicyError):
        describe_rule({"not": "a rule"})


def test_shared_rule_string_serializer_uses_domain_canonicalization() -> None:
    assert serialize_rule_json(
        {"SQL(read-only)": {"effects": {"only": ["read"]}, "dialect": "sqlite"}}
    ) == (
        '{"SQL(read-only)":{"dialect":"sqlite","effects":{"only":["read"]},'
        '"format":"plain"}}'
    )


def test_new_rule_types_have_safe_client_metadata_without_a_parallel_registry() -> None:
    class FutureRule(Rule):
        rationale = ""

        def serialize(self) -> str | JsonObject:
            return "Future"

    rule = FutureRule()

    assert rule.api_kind == "futurerule"
    assert rule.semantic_effect == "unknown"
    assert rule.valid_decisions == ("allow", "ask", "deny")
