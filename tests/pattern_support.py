"""Shell pattern DSL tests — parser, normalizer, matcher, policy integration."""

from __future__ import annotations

from agentperm import (
    Policy,
    Segment,
    ShellPattern,
    ShellRequest,
    Verdict,
    parse_pipeline,
    parse_rule,
)


def segment(*argv: str) -> Segment:
    return Segment(argv=argv, redirects=())


def shell_rule(text: str) -> ShellPattern:
    rule = parse_rule(text)
    assert isinstance(rule, ShellPattern)
    return rule


def decide(policy: Policy, command: str) -> Verdict:
    return policy.decide(ShellRequest(parse_pipeline(command)))
