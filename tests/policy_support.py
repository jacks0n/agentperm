"""Common policy assertions use the same public parsing boundary."""

from pathlib import Path

from agentperm import Policy, ShellRequest, Verdict, parse_pipeline


def decide(policy: Policy, command: str, *, cwd: Path | None = None) -> Verdict:
    return policy.decide(ShellRequest(parse_pipeline(command), cwd=cwd))
