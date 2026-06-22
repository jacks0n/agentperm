# CLI reference

```sh
agentperm <command> [args]
```

Four subcommands: `install`, `import`, `check`, `edit`. The first three are usually run once at setup time; `check` is what the agent itself runs at decision time.

## `install`

Wires the bridge into every supported agent's hook config.

```sh
agentperm install [--mode auto|rulesync|direct] [--dry-run]
```

### Modes

`install` runs in one of two modes; `--mode auto` (the default) picks based on whether `~/.rulesync/` exists.

**Rulesync mode** — when `~/.rulesync/` exists, hook entries are merged into `~/.rulesync/hooks.json` under each agent's block (`claudecode`, `codexcli`, `geminicli`). You re-run `rulesync` afterwards to regenerate per-tool configs from this source of truth. The OpenCode plugin shim is still installed directly (rulesync has no schema for `permission.ask` plugins), and the Codex `[features].hooks` flag is rulesync's responsibility, not the bridge's.

**Direct mode** — bypasses rulesync entirely:

- **Claude Code:** appends a `PreToolUse` hook to `~/.claude/settings.json` (matcher `*`). Strips any spurious bridge entry that ended up in `PermissionRequest` (Claude doesn't fire that event).
- **Codex CLI:** appends `PreToolUse` (matcher `Bash`) and `PermissionRequest` (matcher `Bash|apply_patch|mcp__.*`) hooks to `~/.codex/hooks.json`, and enables `[features].hooks = true` in `~/.codex/config.toml`.
- **Gemini CLI:** appends a `BeforeTool` hook to `~/.gemini/settings.json` (matcher `.*`).
- **OpenCode:** writes `~/.config/opencode/plugins/agentperm.js` — always, regardless of mode.

### Flags

- `--mode auto|rulesync|direct` — `auto` detects rulesync; `rulesync` requires `~/.rulesync/` and exits non-zero if missing; `direct` always writes per-tool configs.
- `--dry-run` — print what would change without modifying any file.

Each installed entry embeds an explicit `--event <Name>` argument matching the hook event under which the bridge will be invoked, so `check` does not have to infer the event from payload shape — required for Codex `PermissionRequest`, whose payload carries no `hook_event_name`. Hook timeouts are set per-agent in the unit each tool expects (Claude/Codex `30` seconds, Gemini `30000` milliseconds).

### Idempotency

Re-running `install` is safe: existing bridge entries are stripped before the new entry is appended, so the merged file is byte-stable across runs. Hooks from other tools (notification daemons, telemetry, etc.) are preserved untouched.

The bridge resolves its own absolute path via `which` at install time and bakes it into the hook command, so GUI-launched agents (Raycast / Spotlight) with sparse `PATH` still find it.

After install, every agent consults `~/.agent-permissions.jsonc` for permission decisions. If the file doesn't exist yet, run `edit` to create it.

## `import`

Pulls each agent's existing native rules into `~/.agent-permissions.jsonc`.

```sh
agentperm import
```

This reads:

- `~/.claude/settings.json` and `~/.claude/settings.local.json` → `permissions.allow / ask / deny`
- `~/.codex/rules/*.rules` → `prefix_rule(...)` declarations
- `~/.config/opencode/opencode.json` → `permission` blocks

Rules are merged into the policy file (existing rules kept, new rules appended). Run `edit` afterwards to deduplicate or reorganize. Native config files are not modified — they keep working as fallback fast paths.

## `check`

Runtime decision endpoint. Reads the agent's hook payload from stdin, writes a verdict envelope to stdout. **You don't run this manually** — `install` wires it up.

```sh
agentperm check --agent <claude|codex|opencode|gemini> --event <event-name>
```

Arguments:

- `--agent` (required): which adapter to use to parse the payload and format the verdict
- `--event` (required): the agent-specific event name, e.g. `PreToolUse`, `PermissionRequest`, `permission.ask`

Behavior:

1. Read JSON payload from stdin
2. Parse it via the named adapter into a `Request`
3. Load merged policy (global + project-local if cwd is inside a git repo)
4. Decide → aggregate → coerce for permission mode → emit verdict envelope on stdout

Failure modes (all fail open with empty `{}` so the agent's native flow takes over):

- Malformed JSON → empty
- Payload doesn't match an expected shape → empty
- Policy file is broken (parse error) → emits `Ask` with rationale `"policy load failed: ..."` to surface the problem to the user

### Tracing

Set `AGENTPERM_TRACE` to a writable path to log every invocation:

```sh
export AGENTPERM_TRACE=/tmp/bridge-trace.log
```

Each invocation appends one JSON line: `{ agent, event, payload, verdict, note }`. Useful when debugging "why did this prompt me?" — see [Troubleshooting](troubleshooting.md).

When the verdict was overridden by [pane bypass](#pane-bypass), the line also carries a `coercion` object: `{ by: "zellij_pane_bypass", pane_id, session, original_decision, original_rationale }`. Use that field to reconstruct what the policy *would* have decided absent the bypass.

### Pane bypass

A per-zellij-pane "skip prompts" toggle, analogous to Claude Code's `--dangerously-skip-permissions` but scoped to one pane. Implemented by the [`zellij-plugin/`](../zellij-plugin/README.md) WASM plugin, honored by `check`.

When the focused pane has a flag file present, `check` coerces `Decision.Ask` and `Decision.NoOpinion` to `Allow` for that invocation. `Decision.Deny` is unaffected — deny rules still bite (unlike Claude's own `bypassPermissions`, where agentperm defers entirely). Coercing `NoOpinion` matters because Codex prompts on `NoOpinion` (the empty `{}` envelope falls through to its native flow), so suppressing only `Ask` would leave unknown commands prompting under bypass.

The pane is identified by the pair `(ZELLIJ_SESSION_NAME, ZELLIJ_PANE_ID)` inherited from the agent's process environment. The flag file lives at:

```
$XDG_CACHE_HOME/agentperm/bypass/<session>/<pane_id>
```

…falling back to `$HOME/.cache/agentperm/bypass/<session>/<pane_id>` when `XDG_CACHE_HOME` is unset. Presence of the file = bypass on; absence = bypass off. The plugin owns all writes; `check` only reads.

Safety checks `check` applies before honoring a flag:

- **Path-traversal sanitization.** If `ZELLIJ_PANE_ID` or `ZELLIJ_SESSION_NAME` contains `/`, `\`, `..`, or a NUL byte, the flag is ignored.
- **Directory ownership and mode.** The bypass directory must be owned by the current uid and not group/world-writable. A directory with mode `0777`, or owned by another user, is ignored. A missing directory is treated as "no flag" (safe).
- **Missing env vars.** No `ZELLIJ_PANE_ID` or no `ZELLIJ_SESSION_NAME` → the bypass code path is skipped entirely.

#### TOCTOU caveat

Bypass applies to *future* permission decisions. A command already approved by `check` cannot be retroactively un-approved by toggling bypass off mid-flight, and a long-running command that was denied before bypass was turned on does not retroactively succeed. Toggle, then run.

## `edit`

Opens `~/.agent-permissions.jsonc` in `$EDITOR` (or `$VISUAL`, falling back to `vi`). Creates the file with a sensible default policy if it doesn't exist.

```sh
agentperm edit
```

The default policy ships with read-only commands (cat, ls, grep, etc.) and read-only git commands on the allow list, `sed -i` on the ask list, and `sudo` / `rm -rf /` on the deny list. Edit to taste.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Normal — the bridge ran to completion. For `check`, this is independent of the verdict; the verdict itself is on stdout. |
| `2` | Argument parsing error. |

The bridge does not signal "deny" via exit code; it always emits its decision via the stdout envelope. This matches every adapter's expectation that a non-zero exit means "the hook itself failed", not "policy denied."
