# Changelog

All notable changes to this project are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `install` subcommand wires the bridge into Claude Code (`PreToolUse`), Codex (`PreToolUse` + `PermissionRequest`), Gemini (`BeforeTool`), and OpenCode (`permission.ask` plugin shim). `--mode auto` (default) uses `~/.rulesync/hooks.json` as the source of truth when `~/.rulesync/` exists; else falls back to writing per-tool configs (`~/.claude/settings.json`, `~/.codex/hooks.json`+`config.toml`, `~/.gemini/settings.json`) directly. The OpenCode plugin is always installed directly because rulesync has no schema for `permission.ask` plugins.
- `install --dry-run` previews changes without writing.
- `install` strips stale bridge entries from Claude's `permissionRequest` block — Claude doesn't fire that event, but older configs sometimes contain a leftover entry there.
- The bridge resolves its own absolute path via `which` at install time and embeds it in hook commands, so GUI-launched agents (Raycast / Spotlight) with sparse `PATH` still find it.

### Changed

- Gemini support switched from a generated static-TOML policy file to a runtime `BeforeTool` hook. Delete `~/.gemini/policies/agent-bridge.toml` if you installed a previous version.
- Each installed hook entry now embeds an explicit `--event <Name>` arg so the bridge does not have to infer the event from payload shape. Codex `PermissionRequest` payloads carry no `hook_event_name`, so without this the installed Codex approval hook silently approved nothing. Per-agent hook timeouts now match each tool's expected unit (Claude/Codex `30` s, Gemini `30000` ms).
- `install` writes a top-level `version: 1` into a fresh `~/.rulesync/hooks.json`; rulesync rejects files without the schema version.

### Fixed

- Shell parser now recursively unwraps `bash -c '…'` (single-quoted) and `bash -c $'…'` (ANSI-C) wrappers. tree-sitter-bash exposes these as `raw_string` / `ansi_c_string` leaves with no named children, so the previous walk produced an empty argv and the inner command bypassed policy entirely. Double-quoted `bash -c "…"` was already handled.
- Bridge ownership check is now a strict basename match against the resolved binary plus a leading `check` subcommand, parsed via `shlex.split`. Substring matching could falsely strip neighbour tools whose paths happened to contain `llm-agent-bridge`.
- Embedded bridge invocation is now `shlex.quote`d so paths containing spaces or shell metacharacters (e.g. `~/Library/Application Support/...`) no longer break the hook command line.
- OpenCode plugin embeds the bridge path through `json.dumps`, so paths containing backslashes or quotes survive interpolation as a valid JS string literal.

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
- `LLM_AGENT_BRIDGE_TRACE` env var for diagnostic logging.
- CLI: `install`, `import`, `check`, `edit`.
- 57 tests covering parser, policy, and adapter round-trips.

### Notes

- Gemini import is not implemented (regex DSL is hard to round-trip safely).
- POSIX `--` argument terminator is not tracked by `BashOption.matches` — flags after `--` may match. Conservative direction is `Ask`, which is correct for a permission policy.

[Unreleased]: https://github.com/jacks0n/llm-agent-bridge/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jacks0n/llm-agent-bridge/releases/tag/v0.1.0
