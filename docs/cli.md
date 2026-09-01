# CLI reference

Every agentperm command, its flags, and its exit codes. New here? Start with [getting started](getting-started.md).

```sh
agentperm <command> [args]
```

Eight subcommands: `install`, `uninstall`, `import`, `init`, `validate`, `why`, `check`, `edit`.
Most are run at setup time; `check` is what the agent itself runs at decision time, and
`validate` / `why` are for inspecting a policy after you change it.

## `install`

Wires agentperm into every supported agent's hook config.

```sh
agentperm install [--mode auto|rulesync|direct] [--dry-run]
```

### Modes

`install` runs in one of two modes; `--mode auto` (the default) picks based on whether `~/.rulesync/` exists.

**Rulesync mode** — when `~/.rulesync/` exists, hook entries are merged into `~/.rulesync/hooks.json` under each agent's block (`claudecode`, `codexcli`, `geminicli`). You re-run `rulesync` afterwards to regenerate per-tool configs from this source of truth. OpenCode and Kiro are still installed directly because Rulesync has no matching integration schema. The Codex `[features].hooks` flag is Rulesync's responsibility, not agentperm's.

**Direct mode** — bypasses rulesync entirely:

- **Claude Code:** appends a `PreToolUse` hook to `~/.claude/settings.json` (matcher `*`). Strips any spurious agentperm entry that ended up in `PermissionRequest` (Claude doesn't fire that event).
- **Codex CLI:** appends `PreToolUse` (matcher `Bash|apply_patch`) and `PermissionRequest` (matcher `Bash|apply_patch|mcp__.*`) hooks to `~/.codex/hooks.json`, and enables `[features].hooks = true` in `~/.codex/config.toml`.
- **Gemini CLI:** appends a `BeforeTool` hook to `~/.gemini/settings.json` (matcher `.*`).
- **OpenCode:** writes `~/.config/opencode/plugins/agentperm.js` with pre-execution and permission hooks — always, regardless of mode.
- **Kiro:** merges `PreToolUse` into existing global and workspace custom-agent files and writes
  `~/.kiro/hooks/agentperm.json`; this is direct in every mode.

### Flags

- `--mode auto|rulesync|direct` — `auto` detects rulesync; `rulesync` requires `~/.rulesync/` and exits non-zero if missing; `direct` always writes per-tool configs.
- `--dry-run` — print what would change without modifying any file.

Each installed entry embeds an explicit `--event <Name>` argument matching the hook event under which agentperm will be invoked, so `check` does not have to infer the event from payload shape — required for Codex `PermissionRequest`, whose payload carries no `hook_event_name`. Hook timeouts are set per-agent in the unit each tool expects (Claude/Codex `30` seconds, Gemini `30000` milliseconds).

### Idempotency

Re-running `install` is safe: existing agentperm entries are stripped before the new entry is appended, so the merged file is byte-stable across runs. Hooks from other tools (notification daemons, telemetry, etc.) are preserved untouched.

`install` resolves the absolute path to `agentperm` via `which` and bakes it into the hook command, so GUI-launched agents (Raycast / Spotlight) with sparse `PATH` still find it.

After install, every agent consults `~/.agent-permissions.jsonc` for permission decisions. If the file doesn't exist yet, run [`init`](#init) to create it from a starter set of templates.

## `uninstall`

The inverse of `install`: removes every hook entry the installer wrote and nothing else.

```sh
agentperm uninstall [--mode auto|rulesync|direct] [--dry-run]
```

- Claude / Codex / Gemini: agentperm entries are stripped from the hook configs; containers left
  empty are deleted, so an install/uninstall round trip restores the original file.
- Codex's `[features].hooks = true` in `config.toml` is deliberately left alone — it is inert
  without hook entries and other tools may rely on it.
- OpenCode: the plugin shim is deleted, but only when its content is recognizably agentperm's own;
  anything else is kept with a warning.
- Kiro: agentperm entries are stripped from every custom-agent file, and the standalone
  `~/.kiro/hooks/agentperm.json` is deleted unless it holds hooks that aren't agentperm's.
- rulesync: agentperm entries are stripped from each agent block of `~/.rulesync/hooks.json`.

Unlike `install`, `--mode auto` sweeps **both** direct and rulesync configs — uninstall means
"get agentperm out of everything it might have written". Policy files are never touched; remove
`~/.agent-permissions.jsonc` and any per-directory files yourself if you don't want them. To remove
the tool itself afterwards: `uv tool uninstall agentperm` (or `pipx uninstall agentperm`).

## `init`

Creates or extends a policy file from bundled rule templates — composable fragments grouped by
domain, so a useful policy is one command away instead of hand-written JSONC.

```sh
agentperm init [template ...] [--global | --local | -o PATH] [--list]
```

- No template names → the starter set: `safety-baseline`, `file-inspection`, `git-read-only`.
- `--list` — print every bundled template with its one-line description.
- `--global` (default) targets `~/.agent-permissions.jsonc`; `--local` the current Git repo's root
  policy; `-o PATH` anywhere else.

If the target doesn't exist, `init` writes a fresh JSONC file with rules grouped under a
`// --- <template> ---` header per template. If it does exist, `init` **merges**: rules the file
already contains are left alone, new ones are appended (each reported with the template it came
from), and the file's own redirect decisions are never overridden — templates only fill gaps.
Merging rewrites the file through the policy serializer, so hand-written comments are not
preserved (a note is printed when that happens).

Bundled templates: `safety-baseline`, `file-inspection`, `git-read-only`, `gh-read-only`,
`aws-read-only`, `docker-read-only`, `packages-read-only`, `python-checks`. Each is a plain policy
file in [`src/agentperm/templates/`](../src/agentperm/templates/) — readable, and a good reference
for the pattern DSL. For complete real-world setups, see [`examples/`](../examples/).

## `import`

Pulls each agent's existing native rules into `~/.agent-permissions.jsonc`.

```sh
agentperm import
```

This reads:

- `~/.claude/settings.json` and `~/.claude/settings.local.json` → `permissions.allow / ask / deny`
- `~/.codex/rules/*.rules` → `prefix_rule(...)` declarations
- `~/.config/opencode/opencode.json` → `permission` blocks
- Kiro `agents/*.json` → `allowedTools` and shell allowed/denied commands

Rules are merged into the policy file (existing rules kept, new rules appended). Run `edit` afterwards to deduplicate or reorganize. Native config files are not modified — they keep working as fallback fast paths. Gemini import is not supported (its regex policy can't be round-tripped safely).

## `validate`

Lints policy files for mistakes the tolerant runtime loader lets slide.

```sh
agentperm validate [path ...]
```

With no arguments, checks every file runtime discovery would load from the current directory
(the global policy plus each `.agent-permissions.jsonc` between the filesystem root and here),
including recursively included files and deterministic glob matches. Explicit paths are also
treated as policy roots and their includes are followed.

Reported as **errors** (exit 1):

- JSONC parse failures and malformed `Shell(...)` / `Python(...)` patterns
- entries the loader would silently skip — an unparseable rule protects (or allows) nothing
- redirect decisions that aren't `allow`/`ask`/`deny` (silently ignored at runtime)
- malformed `allowPaths` or `python.calls` entries
- malformed includes, unmatched include globs, unreadable fragments, and include cycles

Reported as **warnings** (exit 0 if there are no errors):

- unknown keys anywhere in the file (`"permisions"`, `"denied"`, …)
- rules like `"Shel(git status)"` that parse as a named-tool rule which never matches a shell
  command — almost always a mistyped `Shell(...)`
- `Edit(...)` rules — a deprecated alias for `Write(...)`. They are evaluated as `Write`, and
  `import`/`init` rewrite them on save; the warning shows the exact replacement

Run it after every hand edit; a broken policy file otherwise only surfaces as every command
prompting with `"policy load failed"`.

## `why`

Explains what the merged policy decides for a shell command — the fastest way to answer
"why did that prompt?" or "would this be allowed?" without involving an agent.

```sh
agentperm why "git status | head -5"
```

Prints the aggregate verdict with its rationale, a per-segment breakdown when the command is a
compound, and the policy files consulted:

```
$ agentperm why "cat foo | ./deploy.sh"
ask — compound includes unrecognized segment: no rule matched './deploy.sh'
  cat foo  → allow (allow by rule 'Shell({cat,head,tail,...})')
  ./deploy.sh  → no-opinion (no rule matched './deploy.sh')
policy files: /Users/you/.agent-permissions.jsonc
```

Policy discovery runs from the current directory, exactly as `check` would for a command executed
here. Exits 2 if a discovered policy file fails to load.

## `check`

Runtime decision endpoint. Reads the agent's hook payload from stdin, writes a verdict envelope to stdout. **You don't run this manually** — `install` wires it up. To ask "what would the policy decide?", use [`why`](#why).

```sh
agentperm check --agent <auto|claude|codex|opencode|gemini|kiro> --event <event-name>
```

Arguments:

- `--agent` (required): which adapter parses the payload and formats the verdict. `auto` infers from
  event and known tool names; installed hooks use an explicit agent.
- `--event` (required): the agent-specific event name, e.g. `PreToolUse`, `PermissionRequest`, `permission.ask`

Behavior:

1. Read JSON payload from stdin
2. Parse it via the named adapter into a `Request`
3. Load the global policy plus every policy from the filesystem root through the payload cwd
4. Decide → aggregate → coerce for permission mode → emit verdict envelope on stdout

Failure behavior is deliberately split:

- Malformed JSON, a non-object payload, or a payload the selected adapter cannot parse → empty `{}`;
  the host's native flow takes over.
- A discovered policy file that cannot load → an `Ask` verdict with rationale
  `"policy load failed: ..."`; the broken policy is visible instead of silently bypassed.
- A mutation payload recognized as a patch but not safely translatable → `Deny`; scoped file rules
  cannot be trusted without a complete target list.
- A Kiro shell payload without a command → `Ask`, which Kiro represents as a blocking exit code 2.

### Diagnostic traces

Set `AGENTPERM_TRACE` to a writable path to append one raw JSON object per hook invocation:

```sh
export AGENTPERM_TRACE=/tmp/agentperm-trace.log
```

Each line contains `agent`, `event`, the full `payload`, `verdict` when one was reached, and a
diagnostic `note` when parsing or loading stopped early. Pane bypass adds a `coercion` object with
the original decision.

This is a debugging trace, not a production audit trail:

- It can contain raw commands, file contents or patches, prompts, URLs, tokens, and other secrets
  present in agent tool payloads.
- agentperm provides no redaction, rotation, retention, indexing, access control, integrity signing,
  or tamper protection.
- Concurrent hooks append independently, so ordering and completeness are not guaranteed.
- Trace-write failures are ignored to avoid breaking permission hooks.

Choose a private path with appropriate OS permissions, arrange rotation yourself, and unset the
variable after diagnosis. Start the agent from the shell where the variable is set so hooks inherit
it. For development checkouts, `<repo>/.env` is also loaded without overriding an existing process
variable. See [Troubleshooting](troubleshooting.md#1-the-agent-prompted-but-the-trace-is-empty).

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

Opens the policy file in your editor — `$VISUAL`, then `$EDITOR`, falling back to the first installed of `nvim` / `vim` / `vi` / `nano`. Creates the file with an empty default policy (`allow` / `ask` / `deny` all empty) if it doesn't exist — run [`init`](#init) first if you want to start from the templates instead.

```sh
agentperm edit [--global | --local]
```

- `--global` (default) edits `~/.agent-permissions.jsonc`.
- `--local` edits the current Git repository's root `.agent-permissions.jsonc`. Runtime discovery also
  reads policies in more specific directories, but those are created manually. The command exits
  non-zero outside a Git worktree rather than creating a stray file in an unrelated directory.

After editing, run [`validate`](#validate) to catch typos before they cost you protection. The exit code is the editor's own exit code. Rule syntax: [policy reference](policy-reference.md) · [pattern DSL](pattern-dsl.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Normal completion. JSON-envelope adapters report policy verdicts on stdout; Kiro uses 0 for Allow/NoOpinion. |
| `1` | `validate` found errors, or `install`/`uninstall` failed for at least one adapter. |
| `2` | Usage/configuration error, `why` with an unloadable policy, or Kiro Ask/Deny (its hook protocol uses exit codes). |

Claude, Codex, OpenCode, and Gemini do not signal Deny through the process exit code; their verdict
is the stdout envelope. Kiro is the deliberate exception—see [adapter notes](adapters.md#kiro-cli--ide).

---

Back to the [docs index](README.md).
