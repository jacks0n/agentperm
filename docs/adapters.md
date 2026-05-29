# Adapter notes

Each agent has its own hook protocol, payload shape, and verdict envelope. The adapters in `src/agentperms/__init__.py` translate between them and the bridge's uniform `Request` / `Verdict` types.

## Claude Code

**Hook:** `PreToolUse` in `~/.claude/settings.json`, matcher `*`. In rulesync mode, the same entry is merged into `claudecode.hooks.preToolUse` of `~/.rulesync/hooks.json`. `install` also strips any bridge entry from `permissionRequest` — Claude doesn't fire that event, but older configs sometimes contain a stale entry there.

**Payload shape:**
```json
{
  "session_id": "...",
  "transcript_path": "...",
  "cwd": "/path/to/cwd",
  "permission_mode": "default" | "plan" | "acceptEdits" | "bypassPermissions",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": { "command": "..." },
  "tool_use_id": "..."
}
```

**Verdict envelope:**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow" | "ask" | "deny",
    "permissionDecisionReason": "<rationale>"
  }
}
```

`NoOpinion` emits an empty `{}` and Claude falls back to its native permission flow (which honors `~/.claude/settings.json` `permissions.allow / ask / deny`).

### Bypass mode

Claude Code's `permission_mode == "bypassPermissions"` means the user has opted out of prompts. The bridge respects this:

- `Deny` → still `Deny` (bypass means "skip prompts", not "skip safety")
- `Ask` → coerced to `Allow` with rationale prefix `"bypass mode: ..."`
- `Allow` / `NoOpinion` → unchanged (Claude's native bypass takes over for `NoOpinion`)

### MCP bypass propagation

When Claude Code calls an MCP tool (e.g. `mcp__codex__codex`) in bypass mode, the bridge uses `updatedInput` to inject `"approval-policy": "never"` into the tool input. This causes the downstream agent (Codex) to run in full-auto mode — its `PermissionRequest` hooks don't fire, so agentperms doesn't prompt. `PreToolUse` hooks still fire, so Deny rules still apply. See [architecture — MCP bypass propagation](architecture.md#mcp-bypass-propagation).

### Concatenation, not merging

Claude Code concatenates hooks across user (`~/.claude/settings.json`), project (`<repo>/.claude/settings.json`), and local (`<repo>/.claude/settings.local.json`) scopes. If the bridge is registered at user scope and a stale entry survives at project scope, **both will fire**. `install` removes bridge entries from the file it's writing to, but it can't reach into other scopes. If you have stale entries from an older install, edit those settings files manually or delete the bridge entries.

## Codex CLI

**Hooks:** `PreToolUse` (matcher `Bash`) and `PermissionRequest` (matcher `Bash|apply_patch|mcp__.*`) in `~/.codex/hooks.json`. In rulesync mode, both events are merged into `codexcli.hooks.{preToolUse,permissionRequest}` of `~/.rulesync/hooks.json` with matcher `.*`.

Codex requires `[features].hooks = true` in `~/.codex/config.toml`. `install` sets this automatically in direct mode; in rulesync mode, it's rulesync's responsibility — the bridge does not touch `config.toml`.

### Two events, two roles

- **`PreToolUse`:** fires before *every* Bash tool call. The bridge only emits a verdict here if the decision is `Deny` — this is the fast-path for hard denies. Allow / Ask / NoOpinion fall through to Codex's normal permission flow.
- **`PermissionRequest`:** fires when Codex would otherwise prompt the user. Here the bridge can emit `allow` (silently approve) or `deny` (silently reject); other decisions fall through to the prompt.

This split mirrors Codex's design: `PreToolUse` is for vetoes, `PermissionRequest` is for approvals.

**`PermissionRequest` payload (Codex CLI 0.128+):**
```json
{
  "session_id": "...",
  "turn_id": "...",
  "transcript_path": "...",
  "cwd": "/path/to/cwd",
  "hook_event_name": "PermissionRequest",
  "model": "...",
  "permission_mode": "default",
  "tool_name": "Bash" | "apply_patch" | "mcp__...",
  "tool_input": { "command": "..." }
}
```

The shape mirrors Claude's `PreToolUse`. The legacy `{"permission": {"type": ..., "metadata": {"command": ...}}}` envelope from earlier Codex builds is still parsed for back-compat.

**Allow envelope:**
```json
{ "hookSpecificOutput": { "hookEventName": "PermissionRequest", "decision": { "behavior": "allow" } } }
```

**Deny envelope:**
```json
{ "hookSpecificOutput": { "hookEventName": "PermissionRequest", "decision": { "behavior": "deny", "message": "<rationale>" } } }
```

### Native rules import

Codex's allow-list lives in `.rules` files using a `prefix_rule(pattern=[...], decision="allow|prompt|forbidden")` DSL. `import` reads `~/.codex/rules/*.rules` and converts each `prefix_rule` into a `BashCommand`.

## OpenCode

**Plugin:** `~/.config/opencode/plugins/agentperms.js`. OpenCode runs JavaScript plugins; the bridge ships a tiny shim that shells out to the Python binary. The plugin is always installed directly regardless of mode — rulesync has no schema for `permission.ask` plugins. The shim's `const bridge = "..."` is filled in with the absolute path to `agentperms` resolved at install time, so GUI launches with sparse `PATH` still find it.

**Plugin event:** `permission.ask`.

**Payload shape (synthetic — assembled by the plugin):**
```json
{
  "cwd": "<directory>",
  "hook_event_name": "permission.ask",
  "permission": { "type": "bash" | "<tool>", "metadata": { "command": "..." } },
  "tool_name": "<type>",
  "tool_input": "<metadata or permission>"
}
```

**Verdict envelope:**
```json
{ "status": "allow" | "ask" | "deny", "reason": "<rationale>" }
```

`NoOpinion` emits `{}` and the plugin leaves OpenCode's `output.status` untouched, so the native UI takes over.

### Tool name canonicalization

OpenCode names tools in lowercase (`bash`, `read`, `grep`). The bridge maps these to the Claude-style capitalized names (`Bash`, `Read`, `Grep`) when importing rules so the policy file uses one casing convention. Adapter-level translation back to OpenCode's names happens at decision time.

## Gemini CLI

**Hook:** `BeforeTool` in `~/.gemini/settings.json`, matcher `.*`, timeout `30000` ms. In rulesync mode, the entry is merged into `geminicli.hooks.preToolUse` of `~/.rulesync/hooks.json` (rulesync maps `preToolUse` → Gemini's `BeforeTool` event when it materialises per-tool configs); the embedded bridge command still uses `--event BeforeTool` since that's what Gemini fires at runtime. Gemini's hook timeout is in milliseconds, unlike Claude/Codex which use seconds.

**Payload shape:**
```json
{
  "session_id": "...",
  "tool_name": "run_shell_command" | "read_file" | ...,
  "tool_input": { "command": "..." },
  "hook_event_name": "BeforeTool"
}
```

**Verdict envelope:**
```json
{ "decision": "allow" | "deny", "reason": "<rationale>" }
```

`BeforeTool` cannot prompt the user — it only allows or denies. The bridge maps `Ask` to `deny` with a `"approval required: ..."` reason so the user sees why the tool was blocked. `NoOpinion` emits `{}` and Gemini falls back to its native flow.

`import` is not yet implemented for Gemini.

## Adapter contract

If you want to add a new agent, the contract is in `AgentAdapter`:

```python
class AgentAdapter(ABC):
    name: ClassVar[AgentName]
    def install(self, mode: InstallMode, *, dry_run: bool = False) -> list[Path]: ...
    def import_native_rules(self) -> Iterator[tuple[Decision, Rule]]: ...
    def parse_event(self, payload: JsonObject, event_name: str) -> Request | None: ...
    def write_verdict(self, verdict: Verdict, event_name: str) -> None: ...
```

`install` wires the bridge into the agent's hook config under the requested `mode` (Rulesync or Direct) and returns the list of paths it touched (empty if already up to date). `parse_event` translates the agent's payload into a `Request`. `write_verdict` serializes a `Verdict` into the agent's expected JSON envelope on stdout. `import_native_rules` is optional.

Tests for adapter parse/serialize round-trips live in `tests/test_adapters.py`.
