from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .adapters import ADAPTERS, ClaudeAdapter, select_adapter
from .adapters.base import mcp_bypass_input
from .domain import (
    POLICY_FILENAME,
    AgentName,
    Decision,
    InstallMode,
    JsonObject,
    Policy,
    Rule,
    ShellRequest,
    Verdict,
    narrow_json,
)
from .policy import (
    PolicyError,
    PolicyFile,
    git_toplevel,
    load_policy_file,
    merged_policy,
    save_policy_file,
    write_default_policy,
)

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def _package_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("agentperm")
    except PackageNotFoundError:
        return "0+unknown"


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    parser = argparse.ArgumentParser(prog="agentperm")
    parser.add_argument("--version", action="version", version=f"%(prog)s {_package_version()}")
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("install", help="wire the bridge into agent hook configs")
    install.add_argument(
        "--mode",
        choices=["auto", "rulesync", "direct"],
        default="auto",
        help="auto: detect rulesync; rulesync: write ~/.rulesync/hooks.json; direct: per-tool configs",
    )
    install.add_argument(
        "--dry-run",
        action="store_true",
        help="print would-be writes without modifying files",
    )

    sub.add_parser("import", help="pull native allow/ask/deny rules into ~/.agent-permissions.jsonc")

    check = sub.add_parser("check", help="runtime decision; reads stdin, writes stdout")
    check.add_argument("--agent", required=True, choices=[a.value for a in AgentName])
    check.add_argument("--event", required=True)

    edit = sub.add_parser(
        "edit",
        help="open the policy file in $VISUAL/$EDITOR (creates a default if missing)",
    )
    edit_scope = edit.add_mutually_exclusive_group()
    edit_scope.add_argument(
        "--global",
        dest="edit_local",
        action="store_false",
        help="edit the global policy at ~/.agent-permissions.jsonc (default)",
    )
    edit_scope.add_argument(
        "--local",
        dest="edit_local",
        action="store_true",
        help="edit this repo's policy at <repo root>/.agent-permissions.jsonc",
    )
    edit.set_defaults(edit_local=False)

    args = parser.parse_args(argv)

    if args.command == "install":
        return _cmd_install(mode=args.mode, dry_run=args.dry_run)
    if args.command == "import":
        return _cmd_import()
    if args.command == "check":
        return cmd_check(AgentName(args.agent), args.event)
    if args.command == "edit":
        return _cmd_edit(local=args.edit_local)
    parser.error(f"unknown command {args.command}")
    return 2


def resolve_install_mode(mode: str) -> InstallMode:
    if mode == "rulesync":
        if not (Path.home() / ".rulesync").exists():
            raise PolicyError("--mode rulesync requires ~/.rulesync/ to exist")
        return InstallMode.Rulesync
    if mode == "direct":
        return InstallMode.Direct
    return InstallMode.Rulesync if (Path.home() / ".rulesync").exists() else InstallMode.Direct


def _cmd_install(*, mode: str, dry_run: bool) -> int:
    try:
        resolved_mode = resolve_install_mode(mode)
    except PolicyError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(f"mode: {resolved_mode.value}{' (dry-run)' if dry_run else ''}")
    failed = False
    for adapter in ADAPTERS.values():
        try:
            touched = adapter.install(resolved_mode, dry_run=dry_run)
        except Exception as error:
            print(f"{adapter.name.value}: failed ({error})", file=sys.stderr)
            failed = True
            continue
        if not touched:
            print(f"{adapter.name.value}: up to date")
            continue
        verb = "would write" if dry_run else "wrote"
        for path in touched:
            print(f"{adapter.name.value}: {verb} {path}")
    return 1 if failed else 0


def _cmd_import() -> int:
    policy_path = Path.home() / POLICY_FILENAME
    if not policy_path.exists():
        write_default_policy(policy_path)
    policy_file = load_policy_file(policy_path)
    seen: set[tuple[Decision, Rule]] = {(d, r) for d, r in policy_file.policy.all_rules()}
    new_by_decision: dict[Decision, list[Rule]] = {Decision.Allow: [], Decision.Ask: [], Decision.Deny: []}
    for adapter in ADAPTERS.values():
        for decision, rule in adapter.import_native_rules():
            key = (decision, rule)
            if key in seen:
                continue
            seen.add(key)
            new_by_decision[decision].append(rule)
    if not any(new_by_decision.values()):
        print("no new rules")
        return 0
    updated = Policy(
        deny=policy_file.policy.deny + tuple(new_by_decision[Decision.Deny]),
        ask=policy_file.policy.ask + tuple(new_by_decision[Decision.Ask]),
        allow=policy_file.policy.allow + tuple(new_by_decision[Decision.Allow]),
    )
    save_policy_file(policy_path, PolicyFile(updated, policy_file.raw))
    for decision, rules in new_by_decision.items():
        for rule in rules:
            print(f"+{decision.value} {rule.serialize()!r}")
    return 0


def cmd_check(agent: AgentName, event: str) -> int:
    try:
        raw_payload: object = json.load(sys.stdin)
    except json.JSONDecodeError:
        _trace(agent, event, None, None, "json decode failed")
        json.dump({}, sys.stdout)
        return 0
    try:
        payload_value = narrow_json(raw_payload)
    except PolicyError:
        _trace(agent, event, None, None, "payload narrow failed")
        json.dump({}, sys.stdout)
        return 0
    if not isinstance(payload_value, dict):
        _trace(agent, event, None, None, "payload not object")
        json.dump({}, sys.stdout)
        return 0
    payload: JsonObject = payload_value
    event = effective_event(event, payload)
    adapter = select_adapter(agent, event, payload)
    request = adapter.parse_event(payload, event)
    if request is None:
        _trace(agent, event, payload, None, "request unparseable")
        json.dump({}, sys.stdout)
        return 0
    cwd_value = payload.get("cwd")
    cwd = Path(cwd_value) if isinstance(cwd_value, str) else Path(os.getcwd())
    if isinstance(request, ShellRequest):
        request = ShellRequest(pipeline=request.pipeline, cwd=cwd)
    try:
        policy = merged_policy(cwd=cwd)
    except PolicyError as error:
        _trace(agent, event, payload, None, f"policy load failed: {error}")
        return adapter.write_verdict(Verdict(Decision.Ask, f"policy load failed: {error}"), event)
    verdict = policy.decide(request)
    verdict = coerce_for_permission_mode(verdict, payload)
    verdict, coercion = coerce_for_pane_bypass(verdict, os.environ)
    _trace(agent, event, payload, verdict, None, coercion)
    if isinstance(adapter, ClaudeAdapter):
        adapter.write_verdict(verdict, event, updated_input=mcp_bypass_input(payload))
        return 0
    return adapter.write_verdict(verdict, event)


def effective_event(event: str, payload: JsonObject) -> str:
    if event != "auto":
        return event
    payload_event = payload.get("hook_event_name")
    return payload_event if isinstance(payload_event, str) else event


def _load_dotenv() -> None:
    """Merge ``<repo>/.env`` into ``os.environ`` for development debugging.

    Resolves ``.env`` three levels above this file (the repo root for editable
    installs); silently does nothing if it is missing or unreadable. Existing
    environment variables win so the process environment can still override.
    """
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    try:
        text = env_path.read_text()
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def _trace(
    agent: AgentName,
    event: str,
    payload: JsonObject | None,
    verdict: Verdict | None,
    note: str | None,
    coercion: Coercion | None = None,
) -> None:
    """Append one JSON line per invocation to ``$AGENTPERM_TRACE`` if set.

    Off by default. Set the env var to a writable path to enable — either in the
    process environment or in ``<repo>/.env`` (loaded by ``_load_dotenv`` from
    ``main``). Used to debug whether the bridge is actually being called for a
    given command.
    """
    target = os.environ.get("AGENTPERM_TRACE")
    if not target:
        return
    record: JsonObject = {
        "agent": agent.value,
        "event": event,
        "payload": payload,
        "note": note,
    }
    if verdict is not None:
        record["verdict"] = {"decision": verdict.decision.value, "rationale": verdict.rationale}
    if coercion is not None:
        record["coercion"] = {
            "by": coercion.by,
            "pane_id": coercion.pane_id,
            "session": coercion.session,
            "original_decision": coercion.original.decision.value,
            "original_rationale": coercion.original.rationale,
        }
    try:
        with open(target, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


def coerce_for_permission_mode(verdict: Verdict, payload: JsonObject) -> Verdict:
    """Under Claude's ``bypassPermissions`` mode, agentperm defers entirely.

    Claude fires ``PreToolUse`` hooks even in bypass mode, but the user has explicitly opted
    out of permission checks — so the bridge stays out of the way: it returns ``NoOpinion``
    (an empty ``{}`` envelope) and lets Claude's native bypass proceed. The Claude write path
    still attaches any MCP-bypass ``updatedInput`` (so bypass propagates to a downstream Codex
    MCP tool). Pane bypass and non-bypass modes are unaffected.
    """
    if payload.get("permission_mode") == "bypassPermissions":
        return Verdict(Decision.NoOpinion, "bypass: deferring to host")
    return verdict


# -----------------------------------------------------------------------------
# Per-pane bypass (zellij plugin writes the flag file; agentperm reads it)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Coercion:
    """Structured trace metadata for a coerced verdict.

    Captures which mechanism overrode the original decision so the trace log
    records both the policy's actual answer and the override that suppressed it.
    """

    by: str
    pane_id: str | None
    session: str | None
    original: Verdict


def agentperm_bypass_dir(env: Mapping[str, str]) -> Path:
    """Resolve the per-pane bypass cache dir, honoring ``XDG_CACHE_HOME``.

    The plugin (writer) and agentperm (reader) must agree on this path; both
    derive it through this same helper / the same XDG semantics in the plugin.
    """
    base = env.get("XDG_CACHE_HOME") or str(Path(env.get("HOME", str(Path.home()))) / ".cache")
    return Path(base) / "agentperm" / "bypass"


def _bypass_dir_is_safe(path: Path) -> bool:
    """True iff the bypass dir is missing OR is owned by current uid and not group/world-writable.

    A missing dir is safe: no flag file can exist, so the bypass check is a no-op.
    Refusing a g/o-writable dir means another local user cannot drop a flag file
    that grants themselves silent permission inside our policy mediator.
    On Windows ``os.getuid`` is absent; the uid check is skipped (different security
    model) and we still reject if the mode bits indicate world-writable.
    """
    try:
        st = path.stat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        return False
    return not st.st_mode & 0o022


def coerce_for_pane_bypass(
    verdict: Verdict,
    env: Mapping[str, str],
) -> tuple[Verdict, Coercion | None]:
    """If the current zellij pane has a bypass flag file, suppress Ask/NoOpinion. Deny still bites.

    Pane is identified by ``(ZELLIJ_SESSION_NAME, ZELLIJ_PANE_ID)`` — both inherited
    from the zellij pane the agent runs inside. Flag file:
    ``<agentperm_bypass_dir>/<session>/<pane_id>``. Presence = bypass on.

    ``NoOpinion`` is coerced too: codex's ``PermissionRequest`` adapter falls
    through to ``{}`` on ``NoOpinion`` in ``CodexAdapter.write_verdict``, which causes codex to prompt —
    so the bypass must cover it for "approve everything I haven't denied" to hold.
    """
    if verdict.decision not in (Decision.Ask, Decision.NoOpinion):
        return verdict, None
    pane_id = env.get("ZELLIJ_PANE_ID")
    session = env.get("ZELLIJ_SESSION_NAME")
    if not pane_id or not session:
        return verdict, None
    if any(bad in pane_id or bad in session for bad in ("/", "\\", "..", "\0")):
        return verdict, None
    base = agentperm_bypass_dir(env)
    if not _bypass_dir_is_safe(base):
        return verdict, None
    if not (base / session / pane_id).exists():
        return verdict, None
    coerced = Verdict(Decision.Allow, f"pane bypass: {verdict.rationale}")
    return coerced, Coercion(
        by="zellij_pane_bypass",
        pane_id=pane_id,
        session=session,
        original=verdict,
    )


def _cmd_edit(*, local: bool = False) -> int:
    if local:
        # Keep --local anchored to a deliberate project boundary even though
        # runtime discovery also supports more specific directory policies.
        # Require a worktree so we never create a stray file in an unrelated cwd.
        root = git_toplevel(Path.cwd())
        if root is None:
            print("edit --local: not inside a git repository", file=sys.stderr)
            return 2
        path = root / POLICY_FILENAME
    else:
        path = Path.home() / POLICY_FILENAME
    if not path.exists():
        write_default_policy(path)
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or _default_editor()
    # shlex.split so $VISUAL/$EDITOR values with arguments (e.g. "code --wait") work.
    return subprocess.call([*shlex.split(editor), str(path)])


def _default_editor() -> str:
    for candidate in ("nvim", "vim", "vi", "nano"):
        if shutil.which(candidate):
            return candidate
    return "vi"
