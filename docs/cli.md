# CLI reference

```sh
llm-agent-bridge <command> [args]
```

Four subcommands: `install`, `import`, `check`, `edit`. The first three are usually run once at setup time; `check` is what the agent itself runs at decision time.

## `install`

Wires the bridge into every supported agent's hook config.

```sh
llm-agent-bridge install [--mode auto|rulesync|direct] [--dry-run]
```

### Modes

`install` runs in one of two modes; `--mode auto` (the default) picks based on whether `~/.rulesync/` exists.

**Rulesync mode** — when `~/.rulesync/` exists, hook entries are merged into `~/.rulesync/hooks.json` under each agent's block (`claudecode`, `codexcli`, `geminicli`). You re-run `rulesync` afterwards to regenerate per-tool configs from this source of truth. The OpenCode plugin shim is still installed directly (rulesync has no schema for `permission.ask` plugins), and the Codex `[features].codex_hooks` flag is rulesync's responsibility, not the bridge's.

**Direct mode** — bypasses rulesync entirely:

- **Claude Code:** appends a `PreToolUse` hook to `~/.claude/settings.json` (matcher `*`). Strips any spurious bridge entry that ended up in `PermissionRequest` (Claude doesn't fire that event).
- **Codex CLI:** appends `PreToolUse` (matcher `Bash`) and `PermissionRequest` (matcher `Bash|apply_patch|mcp__.*`) hooks to `~/.codex/hooks.json`, and enables `[features].codex_hooks = true` in `~/.codex/config.toml`.
- **Gemini CLI:** appends a `BeforeTool` hook to `~/.gemini/settings.json` (matcher `.*`).
- **OpenCode:** writes `~/.config/opencode/plugins/agent-bridge.js` — always, regardless of mode.

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
llm-agent-bridge import
```

This reads:

- `~/.claude/settings.json` and `~/.claude/settings.local.json` → `permissions.allow / ask / deny`
- `~/.codex/rules/*.rules` → `prefix_rule(...)` declarations
- `~/.config/opencode/opencode.json` → `permission` blocks

Rules are merged into the policy file (existing rules kept, new rules appended). Run `edit` afterwards to deduplicate or reorganize. Native config files are not modified — they keep working as fallback fast paths.

## `check`

Runtime decision endpoint. Reads the agent's hook payload from stdin, writes a verdict envelope to stdout. **You don't run this manually** — `install` wires it up.

```sh
llm-agent-bridge check --agent <claude|codex|opencode|gemini> --event <event-name>
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

Set `LLM_AGENT_BRIDGE_TRACE` to a writable path to log every invocation:

```sh
export LLM_AGENT_BRIDGE_TRACE=/tmp/bridge-trace.log
```

Each invocation appends one JSON line: `{ agent, event, payload, verdict, note }`. Useful when debugging "why did this prompt me?" — see [Troubleshooting](troubleshooting.md).

## `edit`

Opens `~/.agent-permissions.jsonc` in `$EDITOR` (or `$VISUAL`, falling back to `vi`). Creates the file with a sensible default policy if it doesn't exist.

```sh
llm-agent-bridge edit
```

The default policy ships with read-only commands (cat, ls, grep, etc.) and read-only git commands on the allow list, `sed -i` on the ask list, and `sudo` / `rm -rf /` on the deny list. Edit to taste.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Normal — the bridge ran to completion. For `check`, this is independent of the verdict; the verdict itself is on stdout. |
| `2` | Argument parsing error. |

The bridge does not signal "deny" via exit code; it always emits its decision via the stdout envelope. This matches every adapter's expectation that a non-zero exit means "the hook itself failed", not "policy denied."
