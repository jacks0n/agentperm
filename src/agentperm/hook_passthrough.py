"""Transparent execution of a downstream hook for unresolved decisions."""

from __future__ import annotations

import subprocess
import sys


def run_passthrough(command: tuple[str, ...], original_payload: str) -> int | None:
    """Relay one hook command without interpreting its input or output protocol."""
    if not command:
        return None
    try:
        completed = subprocess.run(
            command,
            input=original_payload,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        print(f"agentperm: passthrough hook unavailable: {error}", file=sys.stderr)
        return None
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    return completed.returncode
