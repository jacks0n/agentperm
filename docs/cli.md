# CLI reference

```sh
llm-agent-bridge <command> [args]
```

Four subcommands: `install`, `import`, `check`, `edit`. The first three are usually run once at setup time; `check` is what the agent itself runs at decision time.

## `install`

Writes hooks/plugins for every detected agent.

```sh
llm-agent-bridge install
```

What it does:

- **Claude Code:** appends a `PreToolUse` hook to `~/.claude/settings.json` that runs `llm-agent-bridge check --agent claude --event PreToolUse`. Existing bridge hooks are stripped first so re-runs are idempotent.
- **Codex CLI:** appends `PreToolUse` and `PermissionRequest` hooks to `~/.codex/hooks.json`, and enables `[features].codex_hooks = true` in `~/.codex/config.toml`.
- **OpenCode:** writes `~/.config/opencode/plugins/agent-bridge.js` — a plugin that shells out to the bridge from OpenCode's `permission.ask` callback.
- **Gemini CLI:** writes `~/.gemini/policies/agent-bridge.toml` — Gemini's regex-based policy file, generated from the rules in your `.agent-permissions.jsonc`.

If a config file doesn't exist or the agent isn't installed, the adapter is silently skipped. Re-running `install` is safe; existing bridge entries are replaced, not duplicated. Hooks from other tools (e.g. notification daemons) are preserved.

After install, every agent will consult `~/.agent-permissions.jsonc` for permission decisions. If the file doesn't exist yet, run `edit` to create it.

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
