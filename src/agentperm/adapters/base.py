"""AgentAdapter ABC and shared hook-config helpers."""

from __future__ import annotations

import json
import shlex
import shutil
import sys
from abc import ABC
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from ..domain import (
    AgentName,
    Decision,
    InstallMode,
    JsonArray,
    JsonObject,
    JsonValue,
    Request,
    Rule,
    Verdict,
)
from ..fileio import atomic_write, read_json


class AgentAdapter(ABC):
    name: ClassVar[AgentName]

    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]:
        return iter(())

    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None:
        return None

    def write_verdict(self, verdict: Verdict, event_name: str) -> int:
        json.dump({}, sys.stdout)
        return 0

    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        """Wire the bridge into this agent's hook config.

        Returns the list of paths the install touched (or would touch under
        ``dry_run``). An empty list means "already up to date".
        """
        return []

    def uninstall(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]:
        """Remove every hook entry ``install`` wrote from this agent's config.

        The inverse of ``install``: strips bridge entries and deletes containers
        that are left empty, leaving everything else in the config untouched.
        Returns the paths that changed (or would change under ``dry_run``).
        """
        return []


def mcp_bypass_input(payload: JsonObject) -> JsonObject | None:
    """When Claude Code is in bypass mode and the tool call targets an MCP server,
    return an updated tool input with ``approval-policy: "never"`` so the downstream
    agent runs full-auto.  PreToolUse hooks on the downstream agent still fire, so
    Deny rules still bite.
    """
    if payload.get("permission_mode") != "bypassPermissions":
        return None
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.startswith("mcp__codex__"):
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    return {**tool_input, "approval-policy": "never"}


def pretooluse_output(decision: Decision, rationale: str) -> JsonObject:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.value,
            "permissionDecisionReason": rationale,
        }
    }


def permission_request_output(decision: Decision, rationale: str) -> JsonObject:
    if decision is Decision.Allow:
        return {"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}}
    if decision is Decision.Deny:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "deny", "message": rationale},
            }
        }
    return {}


# -----------------------------------------------------------------------------
# Hook config helpers (used by install)
# -----------------------------------------------------------------------------


BRIDGE_HOOK_MARKER = "agentperm"

# Per-agent hook timeouts. Claude/Codex use seconds; Gemini uses milliseconds.
_HOOK_TIMEOUTS: dict[str, int] = {
    "claude": 30,
    "codex": 30,
    "gemini": 30000,
    "kiro": 30,
}


def resolve_bridge_command() -> str:
    """Return the absolute path to ``agentperm`` if findable.

    GUI-launched OpenCode (Raycast/Spotlight) inherits a sparse ``PATH``; baking
    the resolved absolute path eliminates a class of silent ``ENOENT`` bugs. Falls
    back to the bare name if nothing is on ``PATH`` at install time, with a stderr
    warning so the user knows runtime PATH lookup is in play.
    """
    resolved = shutil.which(BRIDGE_HOOK_MARKER)
    if resolved:
        return resolved
    print(
        f"warning: '{BRIDGE_HOOK_MARKER}' not on PATH at install time; "
        f"hooks will rely on runtime PATH",
        file=sys.stderr,
    )
    return BRIDGE_HOOK_MARKER


def _bridge_command_string(agent: str, event: str) -> str:
    """Build the shell-safe bridge invocation embedded in hook configs.

    Quotes the resolved path so spaces or shell metacharacters in the install
    location can't break the command line or smuggle arguments. Agent and event
    are constrained internally so they need no quoting, but we shlex-quote them
    anyway as a defensive habit.
    """
    return " ".join(
        shlex.quote(part)
        for part in (resolve_bridge_command(), "check", "--agent", agent, "--event", event)
    )


def _hook_group(matcher: str, *, agent: str, event: str, status_message: str | None = None) -> JsonObject:
    """Build a Claude/Codex/Gemini-style nested ``{matcher, hooks: [...]}`` group."""
    hook: JsonObject = {
        "type": "command",
        "command": _bridge_command_string(agent, event),
        "timeout": _HOOK_TIMEOUTS[agent],
    }
    if status_message is not None:
        hook["statusMessage"] = status_message
    return {"matcher": matcher, "hooks": [hook]}


def _rulesync_entry(agent: str, event: str, matcher: str) -> JsonObject:
    """Build a flat rulesync-style hook entry."""
    return {
        "type": "command",
        "command": _bridge_command_string(agent, event),
        "matcher": matcher,
        "timeout": _HOOK_TIMEOUTS[agent],
    }


def is_bridge_hook(hook: JsonValue) -> bool:
    """True iff this entry is one the bridge's installer wrote.

    Matches strictly on shape: the command must split into a binary whose
    basename is ``agentperm`` followed by ``check``. This avoids
    false-stripping unrelated wrappers whose paths happen to contain the
    substring ``agentperm``.
    """
    if not isinstance(hook, dict):
        return False
    command = hook.get("command")
    if not isinstance(command, str) or not command.strip():
        return False
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return False
    if len(parts) < 2:
        return False
    return Path(parts[0]).name == BRIDGE_HOOK_MARKER and parts[1] == "check"


def _strip_bridge_groups(groups: JsonArray) -> JsonArray:
    """Remove bridge entries from nested ``{matcher, hooks: [...]}`` groups.

    Drops groups whose hooks list is left empty; preserves all non-bridge entries
    untouched. Idempotency guarantee: re-running ``install`` produces no churn.
    """
    kept: JsonArray = []
    for group in groups:
        if not isinstance(group, dict):
            kept.append(group)
            continue
        hooks = group.get("hooks")
        if not isinstance(hooks, list):
            kept.append(group)
            continue
        remaining: JsonArray = [hook for hook in hooks if not is_bridge_hook(hook)]
        if not remaining:
            continue
        kept.append({**group, "hooks": remaining})
    return kept


def _strip_bridge_entries(entries: JsonArray) -> JsonArray:
    """Remove bridge entries from a flat rulesync-style entry list."""
    return [entry for entry in entries if not is_bridge_hook(entry)]


def _section(parent: JsonObject, key: str) -> JsonObject:
    value = parent.get(key)
    if isinstance(value, dict):
        return value
    section: JsonObject = {}
    parent[key] = section
    return section


def _ensure_list(parent: JsonObject, key: str) -> JsonArray:
    value = parent.get(key)
    if isinstance(value, list):
        return value
    new_list: JsonArray = []
    parent[key] = new_list
    return new_list


def _rulesync_hooks_path() -> Path:
    return Path.home() / ".rulesync/hooks.json"


def _write_json_if_changed(path: Path, before: JsonObject, after: JsonObject, *, dry_run: bool) -> list[Path]:
    """Atomic write iff ``after`` differs structurally from ``before``."""
    if after == before:
        return []
    if not dry_run:
        atomic_write(path, json.dumps(after, indent=2) + "\n")
    return [path]


def merge_rulesync_hooks(
    *,
    block: str,
    add: list[tuple[str, str, str]],
    strip: list[str],
    agent_name: str,
    dry_run: bool,
) -> list[Path]:
    """Merge bridge entries into ``~/.rulesync/hooks.json`` for one agent block.

    ``add`` is a list of ``(rulesync_key, bridge_event, matcher)`` triples. The
    ``rulesync_key`` (camelCase) is where rulesync materialises the hook into the
    per-tool config; ``bridge_event`` is the per-tool event name the bridge will
    receive at runtime (e.g. rulesync's ``preToolUse`` for Gemini maps to
    ``BeforeTool``, so we embed ``--event BeforeTool``). ``strip`` removes stale
    bridge entries (e.g. Claude doesn't fire ``permissionRequest``).
    """
    path = _rulesync_hooks_path()
    before = read_json(path)
    after: JsonObject = json.loads(json.dumps(before))
    after.setdefault("version", 1)
    agent_section = _section(after, block)
    hooks = _section(agent_section, "hooks")
    for rulesync_key, bridge_event, matcher in add:
        entries = _strip_bridge_entries(_ensure_list(hooks, rulesync_key))
        entries.append(_rulesync_entry(agent_name, bridge_event, matcher))
        hooks[rulesync_key] = entries
    for event_name in strip:
        if event_name in hooks:
            current = hooks[event_name]
            if isinstance(current, list):
                stripped = _strip_bridge_entries(current)
                if stripped:
                    hooks[event_name] = stripped
                else:
                    del hooks[event_name]
    return _write_json_if_changed(path, before, after, dry_run=dry_run)


def strip_rulesync_hooks(*, block: str, keys: list[str], dry_run: bool) -> list[Path]:
    """Remove bridge entries from one agent block of ``~/.rulesync/hooks.json``.

    Never creates the file or any section: a missing file, block, or hooks map is
    already uninstalled. Containers left empty by the strip are deleted so an
    install/uninstall round trip restores the original structure.
    """
    path = _rulesync_hooks_path()
    if not path.exists():
        return []
    before = read_json(path)
    after: JsonObject = json.loads(json.dumps(before))
    block_section = after.get(block)
    hooks = block_section.get("hooks") if isinstance(block_section, dict) else None
    if not isinstance(block_section, dict) or not isinstance(hooks, dict):
        return []
    for key in keys:
        current = hooks.get(key)
        if not isinstance(current, list):
            continue
        stripped = _strip_bridge_entries(current)
        if stripped:
            hooks[key] = stripped
        else:
            del hooks[key]
    if not hooks:
        del block_section["hooks"]
    if not block_section:
        del after[block]
    return _write_json_if_changed(path, before, after, dry_run=dry_run)


def strip_nested_hooks(path: Path, *, events: list[str], dry_run: bool) -> list[Path]:
    """Remove bridge groups from a Claude-style ``hooks.<Event>`` config file.

    Never creates the file or the ``hooks`` section. Event lists and the
    ``hooks`` section itself are deleted when the strip leaves them empty.
    """
    if not path.exists():
        return []
    before = read_json(path)
    after: JsonObject = json.loads(json.dumps(before))
    hooks_section = after.get("hooks")
    if not isinstance(hooks_section, dict):
        return []
    for event_name in events:
        current = hooks_section.get(event_name)
        if not isinstance(current, list):
            continue
        stripped = _strip_bridge_groups(current)
        if stripped:
            hooks_section[event_name] = stripped
        else:
            del hooks_section[event_name]
    if not hooks_section:
        del after["hooks"]
    return _write_json_if_changed(path, before, after, dry_run=dry_run)


def merge_nested_hooks(
    path: Path,
    *,
    add: list[tuple[str, str]],
    strip: list[str],
    agent_name: str,
    dry_run: bool,
) -> list[Path]:
    """Merge bridge groups into a Claude-style ``hooks.<Event>`` config file.

    The schema is the nested ``[{matcher, hooks: [...]}]`` group form used by
    Claude ``settings.json``, Codex ``hooks.json``, and Gemini ``settings.json``.
    Each entry in ``add`` is ``(event_name, matcher)``; the embedded bridge
    invocation uses ``event_name`` as the ``--event`` argument since direct-mode
    keys are the per-tool event names.
    """
    before = read_json(path)
    after: JsonObject = json.loads(json.dumps(before))
    hooks_section = _section(after, "hooks")
    for event_name, matcher in add:
        groups = _strip_bridge_groups(_ensure_list(hooks_section, event_name))
        groups.append(_hook_group(matcher, agent=agent_name, event=event_name))
        hooks_section[event_name] = groups
    for event_name in strip:
        if event_name in hooks_section:
            current = hooks_section[event_name]
            if isinstance(current, list):
                stripped = _strip_bridge_groups(current)
                if stripped:
                    hooks_section[event_name] = stripped
                else:
                    del hooks_section[event_name]
    return _write_json_if_changed(path, before, after, dry_run=dry_run)

