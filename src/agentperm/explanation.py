"""Policy explanation shared by human and machine-readable CLI surfaces."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path

from .domain import Decision, Pipeline, ShellRequest
from .scoped_policy import decide_with_discovered_policy, policy_layers_for_shell_request
from .shell import parse_pipeline


@dataclass(frozen=True)
class SegmentExplanation:
    command: str
    decision: Decision
    rationale: str


@dataclass(frozen=True)
class CommandExplanation:
    decision: Decision
    rationale: str
    segments: tuple[SegmentExplanation, ...]
    sources: tuple[Path, ...]


def explain_shell_command(command: str, cwd: Path) -> CommandExplanation:
    request = ShellRequest(parse_pipeline(command), cwd=cwd)
    verdict = decide_with_discovered_policy(request, cwd)
    segments = tuple(
        SegmentExplanation(
            command=shlex.join(segment.argv),
            decision=segment_verdict.decision,
            rationale=segment_verdict.rationale,
        )
        for segment in request.pipeline.segments
        for segment_verdict in (
            decide_with_discovered_policy(
                ShellRequest(Pipeline((segment,), parseable=True), cwd=cwd), cwd
            ),
        )
    )
    sources = tuple(
        dict.fromkeys(
            source
            for layer in policy_layers_for_shell_request(request, cwd)
            for source in layer.sources
        )
    )
    return CommandExplanation(verdict.decision, verdict.rationale, segments, sources)
