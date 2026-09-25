"""The files a shell command names, as ``Read`` targets.

Scoped ``Read`` denies and asks protect paths, not tools: a shell command that names a
path inside such a scope is held to the same verdict as a native read tool. Every
operand, ``--option=value``, input redirect, and string literal inside an operand counts
as a candidate path, because candidates only ever tighten a decision; ``Read`` allows
never approve a shell command.
"""

from __future__ import annotations

import glob
import os
import re
from pathlib import Path

from .config import (
    MAX_SHELL_DIRECTORIES,
    MAX_SHELL_GLOB_MATCHES,
    MAX_SHELL_READ_TARGETS,
)
from .domain import Pipeline, Segment, basename

# Commands that read the working directory when no path operand is given.
_CWD_READERS = frozenset({"ag", "du", "fd", "find", "ls", "rg", "tree"})
_DIR_CHANGERS = frozenset({"cd", "pushd"})
_INPUT_REDIRECTS = frozenset({"<", "<>"})
_STRING_LITERAL = re.compile(r"""["']([^"'\n]+)["']""")


def shell_read_targets(pipeline: Pipeline, cwd: Path) -> tuple[str, ...] | None:
    """Absolute paths each segment may read, or ``None`` when safe analysis is too large."""
    targets: list[str] = []
    directories = (cwd,)
    for segment in pipeline.segments:
        if not segment.argv:
            continue
        operands = _operands(segment)
        command = basename(segment.argv[0])
        if command in _DIR_CHANGERS and len(operands) == 1:
            changed = (_resolve(operands[0], directory) for directory in directories)
            # Static analysis cannot know whether a directory change will run or
            # succeed. Keep both states so either control-flow outcome is covered.
            directories = tuple(
                dict.fromkeys((*directories, *(Path(path) for path in changed if path is not None)))
            )
            if len(directories) > MAX_SHELL_DIRECTORIES:
                return None
            continue
        for directory in directories:
            if command in _CWD_READERS:
                targets.append(f"{directory}/**")
            if "/" in segment.argv[0]:
                targets.extend(_expand(segment.argv[0], directory))
            for operand in operands:
                targets.extend(_expand(operand, directory))
            if len(targets) > MAX_SHELL_READ_TARGETS:
                return None
    return tuple(dict.fromkeys(targets))


def _operands(segment: Segment) -> list[str]:
    operands: list[str] = []
    for arg in segment.argv[1:]:
        if arg.startswith("-"):
            if "=" in arg:
                operands.append(arg.split("=", 1)[1])
            continue
        operands.append(arg)
    # Inline programs (``python -c``, ``node -e``, awk scripts) name files in string literals.
    operands.extend(match.group(1) for operand in list(operands) for match in _STRING_LITERAL.finditer(operand))
    operands.extend(
        redirect.target
        for redirect in segment.redirects
        if redirect.op in _INPUT_REDIRECTS and not redirect.is_fd_dup
    )
    return [operand for operand in operands if operand and "://" not in operand]


def _resolve(operand: str, cwd: Path) -> str | None:
    value = os.path.expandvars(os.path.expanduser(operand))
    if "$" in value:
        return None
    return os.path.normpath(value if os.path.isabs(value) else os.path.join(cwd, value))


def _expand(operand: str, cwd: Path) -> list[str]:
    path = _resolve(operand, cwd)
    if path is None:
        return []
    candidates = [path]
    if glob.has_magic(path):
        candidates.extend(sorted(glob.glob(path))[:MAX_SHELL_GLOB_MATCHES])
    return [f"{candidate}/**" if os.path.isdir(candidate) else candidate for candidate in candidates]
