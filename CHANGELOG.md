# Changelog

All notable changes to this project are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
