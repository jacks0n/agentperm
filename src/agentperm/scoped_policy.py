"""Target-aware policy discovery for path-bearing tool requests."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from .domain import (
    Capability,
    CompoundRequest,
    Decision,
    Policy,
    Request,
    ShellRequest,
    ToolArguments,
    ToolRequest,
    Verdict,
    aggregate,
    tool_path_arguments,
)
from .policy import PolicyLayer, merged_policy, policy_layers
from .shell_reads import shell_read_targets


def decide_with_discovered_policy(request: Request, cwd: Path) -> Verdict:
    """Decide a request using cwd policy or each file target's own ancestry."""
    if isinstance(request, CompoundRequest):
        return aggregate([decide_with_discovered_policy(part, cwd) for part in request.requests])
    if isinstance(request, ShellRequest) and request.pipeline.parseable:
        verdict = merged_policy(cwd=cwd).decide(request)
        return aggregate([verdict, *_shell_read_restrictions(request, cwd)])
    if not isinstance(request, ToolRequest):
        return merged_policy(cwd=cwd).decide(request)

    path_arguments = tool_path_arguments(request.arguments)
    if not path_arguments:
        return merged_policy(cwd=cwd).decide(request)

    verdicts = [
        _decide_path_target(
            ToolRequest(request.tool, _arguments_for_target(request.arguments, target), request.cwd),
            target[1],
            cwd,
        )
        for target in path_arguments
    ]
    return aggregate(verdicts)


def _shell_read_restrictions(request: ShellRequest, cwd: Path) -> list[Verdict]:
    """Deny/Ask verdicts of ``Read`` rules for each path the shell command names."""
    restrictions: list[Verdict] = []
    layers_for = _directory_layers()
    targets = shell_read_targets(request.pipeline, request.cwd or cwd)
    if targets is None:
        return [Verdict(Decision.Ask, "shell read analysis exceeded its safe path limit")]
    for target in targets:
        read = ToolRequest(Capability.Read, (("path", target),), request.cwd)
        verdict = _decide_path_target(read, target, cwd, layers_for)
        if verdict.decision in (Decision.Deny, Decision.Ask):
            restrictions.append(verdict)
    return restrictions


def _arguments_for_target(arguments: ToolArguments, target: tuple[str, str]) -> ToolArguments:
    """Keep non-path metadata while isolating one authoritative path target."""
    remaining = list(tool_path_arguments(arguments))
    kept_target = False
    selected: list[tuple[str, str]] = []
    for argument in arguments:
        if argument not in remaining:
            selected.append(argument)
            continue
        remaining.remove(argument)
        if not kept_target and argument == target:
            selected.append(argument)
            kept_target = True
    return tuple(selected)


def _decide_path_target(
    request: ToolRequest,
    value: str,
    cwd: Path,
    layers_for: Callable[..., tuple[PolicyLayer, ...]] = policy_layers,
) -> Verdict:
    supplied = Path(value).expanduser()
    lexical = Path(os.path.abspath(supplied if supplied.is_absolute() else cwd / supplied))
    resolved = lexical.resolve(strict=False)
    stacks = [layers_for(lexical, preserve_symlinks=True)]
    if resolved != lexical:
        stacks.append(layers_for(resolved))
    return aggregate([_decide_layers(layers, request) for layers in stacks])


def _directory_layers() -> Callable[..., tuple[PolicyLayer, ...]]:
    """``policy_layers`` memoised by directory: files in one directory share its policy ancestry."""
    cache: dict[tuple[Path, bool], tuple[PolicyLayer, ...]] = {}

    def layers_for(path: Path, *, preserve_symlinks: bool = False) -> tuple[PolicyLayer, ...]:
        directory = path if path.is_dir() else path.parent
        key = (directory, preserve_symlinks)
        if key not in cache:
            cache[key] = policy_layers(directory, preserve_symlinks=preserve_symlinks)
        return cache[key]

    return layers_for


def _decide_layers(layers: tuple[PolicyLayer, ...], request: ToolRequest) -> Verdict:
    for layer in layers:
        verdict = Policy(deny=layer.policy.deny).decide(request, path_base=layer.anchor)
        if verdict.decision is Decision.Deny:
            return verdict

    for layer in reversed(layers):
        verdict = Policy(ask=layer.policy.ask, allow=layer.policy.allow).decide(
            request,
            path_base=layer.anchor,
        )
        if verdict.decision is not Decision.NoOpinion:
            return verdict
    return Verdict(Decision.NoOpinion, f"no rule matched {request.tool!r}")
