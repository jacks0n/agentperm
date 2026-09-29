"""Machine-readable rule inspection owned by agentperm's domain model."""

from __future__ import annotations

import json
from dataclasses import dataclass

from .domain import JsonValue
from .errors import PolicyError
from .rules import parse_rule, serialize_rule_value


@dataclass(frozen=True)
class RuleDescription:
    canonical_value: JsonValue
    display: str
    kind: str
    semantic_effect: str
    valid_decisions: tuple[str, ...]

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "canonical_value": self.canonical_value,
            "display": self.display,
            "kind": self.kind,
            "semantic_effect": self.semantic_effect,
            "valid_decisions": list(self.valid_decisions),
        }


def describe_rule(value: JsonValue) -> RuleDescription:
    """Parse and classify one policy value through the authoritative rule parser."""
    rule = parse_rule(value)
    if rule is None:
        raise PolicyError("unparseable rule")
    canonical = serialize_rule_value(value)
    return RuleDescription(
        canonical_value=canonical,
        display=_display(canonical),
        kind=rule.api_kind,
        semantic_effect=rule.semantic_effect,
        valid_decisions=rule.valid_decisions,
    )


def _display(value: JsonValue) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, separators=(",", ":"))
