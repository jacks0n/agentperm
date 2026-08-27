"""Translate apply-patch payloads into semantic file-mutation requests."""

from __future__ import annotations

from pathlib import Path

from ..domain import CompoundRequest, RejectedRequest, Request, ToolRequest

_BEGIN_PATCH = "*** Begin Patch"
_END_PATCH = "*** End Patch"
_ADD_FILE = "*** Add File: "
_DELETE_FILE = "*** Delete File: "
_UPDATE_FILE = "*** Update File: "
_MOVE_TO = "*** Move to: "
_ENVIRONMENT_ID = "*** Environment ID: "


def parse_apply_patch_request(patch: str, cwd: Path | None = None) -> Request:
    """Parse Codex/OpenCode patch targets into canonical Edit/Write requests.

    The host validates patch contents independently.  agentperm only needs the
    complete set of target paths, but it validates the outer envelope and hunk
    headers so a changed/unknown patch dialect fails closed instead of bypassing
    a scoped file-mutation rule.
    """
    lines = patch.strip().splitlines()
    if len(lines) < 3 or lines[0].strip() != _BEGIN_PATCH or lines[-1].strip() != _END_PATCH:
        return RejectedRequest("apply_patch input is not safely parseable")

    requests: list[Request] = []
    active_update = False
    for line in lines[1:-1]:
        if line.startswith(_ENVIRONMENT_ID) and not requests:
            continue
        if line.startswith(_ADD_FILE):
            path = line.removeprefix(_ADD_FILE)
            if not path:
                return RejectedRequest("apply_patch contains an empty add path")
            requests.append(ToolRequest("Write", (("file_path", path),), cwd=cwd))
            active_update = False
        elif line.startswith(_DELETE_FILE):
            path = line.removeprefix(_DELETE_FILE)
            if not path:
                return RejectedRequest("apply_patch contains an empty delete path")
            requests.append(ToolRequest("Edit", (("file_path", path),), cwd=cwd))
            active_update = False
        elif line.startswith(_UPDATE_FILE):
            path = line.removeprefix(_UPDATE_FILE)
            if not path:
                return RejectedRequest("apply_patch contains an empty update path")
            requests.append(ToolRequest("Edit", (("file_path", path),), cwd=cwd))
            active_update = True
        elif line.startswith(_MOVE_TO):
            path = line.removeprefix(_MOVE_TO)
            if not active_update or not path:
                return RejectedRequest("apply_patch contains an invalid move target")
            requests.append(ToolRequest("Write", (("file_path", path),), cwd=cwd))
            active_update = False
        elif line.startswith("*** ") and line not in ("*** End of File",):
            return RejectedRequest(f"unrecognized apply_patch marker: {line}")

    if not requests:
        return RejectedRequest("apply_patch contains no file operations")
    return CompoundRequest(tuple(requests))
