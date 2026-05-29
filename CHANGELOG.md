# Changelog

All notable changes to this project are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Per-pane bypass via the new [`zellij-plugin/`](zellij-plugin/README.md) WASM plugin. A keybind toggles a flag file at `$XDG_CACHE_HOME/agentperms/bypass/<session>/<pane_id>` (keyed by `ZELLIJ_SESSION_NAME` and `ZELLIJ_PANE_ID`); while present, `check` coerces both `Decision.Ask` and `Decision.NoOpinion` to `Allow` for that pane only. `Decision.Deny` is unaffected. Coercing `NoOpinion` (not just `Ask`) is required because Codex prompts on the empty `{}` envelope. The bypass directory is rejected if it is group/world-writable or not owned by the current uid; `ZELLIJ_PANE_ID` / `ZELLIJ_SESSION_NAME` are sanitized against path traversal. Coerced verdicts gain a structured `coercion` field in `$AGENTPERMS_TRACE` records (`{ by, pane_id, session, original_decision, original_rationale }`) so the original policy verdict is recoverable.
- Shell parser now traverses control-flow constructs and treats them as transparent. `if … then … fi`, `while`/`until` loops, `case` statements, brace groups (`{ …; }`), subshells (`( … )`), function definitions, and `! cmd` negation are all decomposed into their inner commands and each segment evaluated against policy. The original failing case — `if [ -f x ]; then sed -n '1,220p' x; fi` with `Bash(sed:*)` allowed — now returns `Allow` instead of `Ask`.
- Command and process substitutions (`$(…)`, `<(…)`, `>(…)`) are now recursively evaluated instead of rejected as unparseable. Inner commands are extracted as separate segments and each is checked against the policy independently. `rg "pattern" $(git ls-files | rg foo)` with `Bash(rg:*)` and `Bash(git ls-files:*)` allowed now returns `Allow` instead of falling through to the native prompt. If any inner command is unrecognized or denied, the aggregate verdict escalates (e.g. `rm $(curl evil)` with `curl` not allowed → `Ask`). This applies across all traversal surfaces: command arguments, `[[ -f $(…) ]]` predicates, `case $(…)` subjects, `for f in $(…)` iterables, `export FOO=$(…)` declarations, `(( $(…) ))` arithmetic, and unquoted heredoc bodies.
- Inert command names have no OS-level side effect on their own and split into two groups. Synthetic predicate markers (`[`, `[[`, `((`) are parser artifacts, not real commands, so they are always allowed and user rules can't target them. Real builtins (`true`, `false`, `:`, `read`, `echo`, `printf`) are allowed only as a fallback when no user rule matches — an explicit `allow`/`ask`/`deny` rule takes precedence, so `deny: Bash(echo:*)` blocks `echo`. Redirects and pipe aggregation still apply per-segment, so `echo foo > out` still asks and `echo foo | weird_cmd` still escalates to ask.
- `declaration_command` (`export FOO=bar`, `local`, `declare`, `readonly`, `typeset`) parses as a regular segment with the keyword as `argv[0]`, so `Bash(export:*)` rules now match. Substitution-bearing forms (`export FOO=$(curl evil)`) extract the inner commands as separate segments for policy evaluation.
- `Bash(...)` string rules support glob tokens: `*` matches one argv token, `**` matches zero or more. `Bash(pnpm --dir * build:*)` matches `pnpm --dir <anything> build [extras]`; `Bash(pnpm ** build:*)` matches `pnpm` with any intermediate flags before `build`. Literal-only patterns are unchanged.
- Heredoc redirects (`<<EOF`) are recognised and dropped from the redirect list (input-only, no file write).
- `install` subcommand wires the bridge into Claude Code (`PreToolUse`), Codex (`PreToolUse` + `PermissionRequest`), Gemini (`BeforeTool`), and OpenCode (`permission.ask` plugin shim). `--mode auto` (default) uses `~/.rulesync/hooks.json` as the source of truth when `~/.rulesync/` exists; else falls back to writing per-tool configs (`~/.claude/settings.json`, `~/.codex/hooks.json`+`config.toml`, `~/.gemini/settings.json`) directly. The OpenCode plugin is always installed directly because rulesync has no schema for `permission.ask` plugins.
- `install --dry-run` previews changes without writing.
- `agentperms --version` prints the installed package version (resolved via `importlib.metadata`).
- `install` strips stale bridge entries from Claude's `permissionRequest` block — Claude doesn't fire that event, but older configs sometimes contain a leftover entry there.
- The bridge resolves its own absolute path via `which` at install time and embeds it in hook commands, so GUI-launched agents (Raycast / Spotlight) with sparse `PATH` still find it.

### Changed

- Gemini support switched from a generated static-TOML policy file to a runtime `BeforeTool` hook. Delete `~/.gemini/policies/agent-bridge.toml` if you installed a previous version.
- Each installed hook entry now embeds an explicit `--event <Name>` arg so the bridge does not have to infer the event from payload shape. Codex `PermissionRequest` payloads carry no `hook_event_name`, so without this the installed Codex approval hook silently approved nothing. Per-agent hook timeouts now match each tool's expected unit (Claude/Codex `30` s, Gemini `30000` ms).
- `install` writes a top-level `version: 1` into a fresh `~/.rulesync/hooks.json`; rulesync rejects files without the schema version.

### Fixed

- Shell parser now correctly handles tree-sitter-bash's habit of (a) folding trailing positional argv into the preceding `file_redirect` node and (b) wrapping any compound left-hand side under a single `list` child of `redirected_statement`. ``wc -l a.py 2>/dev/null b.py`` previously parsed as "writes to 'b.py'"; ``cmd1 && cmd2 2>/dev/null path`` previously bailed with "unsupported redirected statement part 'list'". Both now match bash semantics — redirects bind to the last segment, spillover words rejoin its argv.
- Shell parser now recursively unwraps `bash -c '…'` (single-quoted) and `bash -c $'…'` (ANSI-C) wrappers. tree-sitter-bash exposes these as `raw_string` / `ansi_c_string` leaves with no named children, so the previous walk produced an empty argv and the inner command bypassed policy entirely. Double-quoted `bash -c "…"` was already handled.
- `Bash(<command>)` (no `:*` suffix) now means "exact argv match" as the docs always claimed; the previous matcher silently treated it as a prefix. Rules using the `:*` form are unchanged.
- Codex `PermissionRequest` parser now accepts the Claude-shaped envelope (top-level `tool_name` + `tool_input`) that Codex CLI 0.128+ ships. The previous parser only recognised the legacy `permission.metadata.command` wrapper, so 0.128+ payloads fell through as "request unparseable" and Codex prompted the user despite a matching allow rule. Legacy envelope still accepted.
- Bridge ownership check is now a strict basename match against the resolved binary plus a leading `check` subcommand, parsed via `shlex.split`. Substring matching could falsely strip neighbour tools whose paths happened to contain `agentperms`.
- Embedded bridge invocation is now `shlex.quote`d so paths containing spaces or shell metacharacters (e.g. `~/Library/Application Support/...`) no longer break the hook command line.
- OpenCode plugin embeds the bridge path through `json.dumps`, so paths containing backslashes or quotes survive interpolation as a valid JS string literal.
- Shell wrappers inside a redirected statement are now unwrapped: `zsh -lc "rm -rf /" 2>/dev/null` previously kept its `(zsh, -lc, …)` argv (the inner command was never extracted), so a `deny: Bash(rm -rf:*)` rule could not see `rm -rf` and the command was allowed. The wrapper is now unwrapped like the non-redirected path and the trailing redirect binds to the inner command. Words trailing the redirect (`… 2>/dev/null harmless`) are the wrapper's positional params and are dropped rather than appended to the inner command's argv, so exact deny rules match too. **Security fix** — a denied command could be laundered through a redirected shell wrapper.
- Substitution redirect targets no longer degrade the pipeline to "unparseable" → `Ask` (which bypass mode then coerced to `Allow`, letting a denied command through). A process-substitution target (`cat < <(rm -rf /)`) is a pipe, not a file: no write is policed and the inner command is extracted and checked. A command-substitution target — bare (`cmd > $(echo f)`) or nested in a target word (`echo hi > out$(rm -rf /)`, `> "$(rm -rf /)"`) — is a runtime-computed filename: the write still asks and the inner command is extracted. **Security fix.**
- Bypass modes no longer coerce a **parse-failure** `Ask` to `Allow`. A command the parser can't safely analyze (a syntax error, or a valid construct the grammar walk doesn't yet model) keeps prompting even under `bypassPermissions` / pane bypass, instead of being silently allowed — an un-analyzable command may hide a denied one. Deliberate policy `Ask`s (e.g. file writes) are still coerced as before. **Security fix** — closes the whole "unparseable → Ask → bypass Allow" class, not just the specific constructs below. `Verdict` gains a `parse_failure` flag to distinguish the two.
- Shell-parser coverage extended so common-but-previously-unhandled constructs decompose (and thus deny their inner commands) instead of degrading to unparseable: a bare substitution as a `case` subject (`case $(rm -rf /) in …`); the `>|`, `&>>`, and `<&` redirect operators; substitutions nested in a redirect target word (`> out$(…)`); herestrings (`<<< word`, `<<< $(…)`); and split no-arg flags before `-c` (`bash -l -c "…"`, `zsh -i -x -c "…"`).
- Exec-prefix wrappers are decomposed so a deny rule on the wrapped command bites. `command`, `exec`, `nohup`, `setsid`, `env` (skipping `-i` and `NAME=value`), `nice`, and `time` with classifiable options expand to their inner command (`env -i FOO=bar git status` is now matched as `git status`, not the `env` wrapper — a behavior change from the previous literal matching). Wrappers we can't safely decompose (`timeout`, `sudo`, `xargs`, `nice -n N`, `env -u NAME`, … — leading positionals or arg-taking options) are flagged as parse-failures so bypass prompts rather than allowing the hidden command; an explicit rule (`Bash(sudo:*)`) still allow-lists them. **Security fix** under bypass. The recognized wrapper list isn't exhaustive — an unrecognized executor prefixing a denied command remains a known limitation.
- `eval` is decomposed by re-parsing its joined arguments (`eval "rm -rf /"` is policed as `rm -rf /`). A command whose *name* is a runtime expansion (`eval "$cmd"`, `bash -c "$cmd"`, `$TOOL args`) is unknowable statically and is flagged as a parse-failure so bypass prompts rather than allowing whatever it resolves to. **Security fix** under bypass.

## [0.1.0] — 2026-04-27

Initial public release.

### Added

- Single-policy permission mediator for Claude Code, Codex CLI, OpenCode, and Gemini CLI.
- `~/.agent-permissions.jsonc` policy file with global + per-project merging.
- bashlex-based AST parsing — handles pipes, sequences (`;`, `&&`, `||`), redirects (`>`, `>>`, `<`, `2>`, `2>&1`, `&>`), env-var prefixes (`FOO=bar ls`), and `bash -c "..."` recursive unwrapping.
- Rule grammar: `BashCommand` (prefix), `BashOption` (command + flag), `NamedTool` (exact / wildcard / prefix).
- Aggregation: strictest wins; `Allow + NoOpinion` segments escalate to `Ask` to prevent silent allow-on-unknown in compounds.
- Built-in redirect policy: file writes (`>`, `>>`, `&>`) → `Ask`; fd duplication (`2>&1`) and `2>/dev/null` → `NoOpinion`.
- Claude Code bypass-mode coercion: `Ask → Allow` under `permission_mode: "bypassPermissions"`; `Deny` still bites.
- `AGENTPERMS_TRACE` env var for diagnostic logging.
- CLI: `install`, `import`, `check`, `edit`.
- 57 tests covering parser, policy, and adapter round-trips.

### Notes

- Gemini import is not implemented (regex DSL is hard to round-trip safely).
- POSIX `--` argument terminator is not tracked by `BashOption.matches` — flags after `--` may match. Conservative direction is `Ask`, which is correct for a permission policy.

[Unreleased]: https://github.com/jacks0n/agentperms/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jacks0n/agentperms/releases/tag/v0.1.0
