"""Permission decisions for shell redirections."""

import fnmatch
import os
from collections.abc import Iterable
from pathlib import Path

from .domain import Decision, Redirect, RedirectionPolicy, Verdict


def evaluate_redirects(
    redirects: Iterable[Redirect],
    policy: RedirectionPolicy,
    *,
    allow_paths: tuple[str, ...] = (),
    cwd: Path | None = None,
) -> Verdict:
    strictest = Verdict(Decision.NoOpinion, "")
    for r in redirects:
        verdict = _evaluate_redirect(r, policy, allow_paths, cwd)
        if verdict.decision is Decision.Deny:
            return verdict
        if verdict.decision is Decision.Ask and strictest.decision is Decision.NoOpinion:
            strictest = verdict
    return strictest


def _evaluate_redirect(
    r: Redirect,
    policy: RedirectionPolicy,
    allow_paths: tuple[str, ...] = (),
    cwd: Path | None = None,
) -> Verdict:
    if r.is_fd_dup:
        return Verdict(Decision.NoOpinion, "")
    if r.op == "<":
        return Verdict(Decision.NoOpinion, "")
    if r.target == "/dev/null":
        if r.fd == 2:
            return _configured_verdict(policy.stderr_to_dev_null, Decision.Allow, "stderr to /dev/null")
        return _configured_verdict(policy.stdout_to_dev_null, Decision.Allow, "stdout to /dev/null")
    # Path allowlist — checked before the operator-based policy so an allowed
    # directory overrides the default ask/deny for writes and appends.
    is_write = r.op in (">", "&>", ">|", ">>", "&>>")
    if is_write and allow_paths and _redirect_path_allowed(r.target, allow_paths, cwd):
        return Verdict(Decision.NoOpinion, "")
    if r.op in (">", "&>", ">|"):
        return _configured_verdict(policy.stdout_to_file, Decision.Ask, f"writes to {r.target!r}")
    if r.op in (">>", "&>>"):
        return _configured_verdict(policy.append_to_file, Decision.Ask, f"appends to {r.target!r}")
    return Verdict(Decision.Ask, f"unrecognized redirection {r.op!r}")


def _redirect_path_allowed(target: str, allow_paths: tuple[str, ...], cwd: Path | None) -> bool:
    if os.path.isabs(target):
        resolved = os.path.realpath(target)
    elif cwd is not None:
        resolved = os.path.realpath(cwd / target)
    else:
        return False
    resolved_parts = Path(resolved).parts
    for pattern in allow_paths:
        canonical = os.path.realpath(pattern)
        pattern_parts = Path(canonical).parts
        if len(pattern_parts) > len(resolved_parts):
            continue
        if all(fnmatch.fnmatch(actual, pat) for actual, pat in zip(resolved_parts, pattern_parts, strict=False)):
            return True
    return False


def _configured_verdict(configured: Decision | None, default: Decision, rationale: str) -> Verdict:
    """Turn a redirect shape's configured/default decision into a Verdict.

    ``Allow`` defers entirely to the segment's own command rule (NoOpinion);
    ``Ask``/``Deny`` force that verdict regardless of what the command rule says.
    """
    intended = configured if configured is not None else default
    if intended is Decision.Allow:
        return Verdict(Decision.NoOpinion, "")
    if intended is Decision.Deny:
        return Verdict(Decision.Deny, rationale)
    return Verdict(Decision.Ask, rationale)
