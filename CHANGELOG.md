# Changelog

Notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `Shell(...)` accepts a standalone `--` operand, allowing patterns to require an end-of-options boundary while `--name` remains a flag.
- Published GitHub releases build and publish matching non-prerelease tags to PyPI via trusted publishing.

### Fixed

- `unset` is parsed as a policy-governed command, including nested substitutions.
- `continue` receives the overridable inert-builtin fallback allow.

## [0.3.0] — 2026-08-04

### Added

- `Shell(...)`: order-independent operands and flags, alternation, globs, exactness, allow/deny/permit constraints, value matching and explicit option arity.
- `Python(readonly)`: AST checks for inline Python and literal heredocs, with configurable call-level allow/ask/deny rules.
- Kiro CLI/IDE support, including event handling, install, native-rule import, workspace agents and `KIRO_HOME`.
- Configurable redirect decisions and global/per-rule `allowPaths`, with relative, glob and symlink-aware matching.
- Starter, project and full policy examples, plus reproducible Zellij plugin build commands.

### Changed

- Split the implementation into focused domain, parser, policy, CLI and adapter modules without changing public imports.
- Structured shell rules now use `{"Shell(...)": {"values": [...], "allowPaths": [...]}}`; legacy dicts still parse.
- Shell parsing now covers comments, quoting and escapes, bare assignments, dynamic redirect targets and literal versus expanding heredocs.
- Updated the Zellij plugin to 0.44 with reproducible build/install tooling.

### Fixed

- Policy writes are atomic and owner-only.
- Imports reject unsafe blanket shell grants and unrepresentable Kiro regexes instead of broadening access.
- Shell matching fails closed on unknown option arity and preserves flag-looking option values for deny checks.

## [0.2.1] — 2026-06-27

### Added

- Named-tool rules can scope URL and path inputs, including domain matching and `*`/`**` path globs.
- Added starter, project and comprehensive example policies.

### Fixed

- Parenthesized named-tool rules such as `Read(*)` and `WebFetch(domain:…)` now match.

## [0.2.0] — 2026-06-26

### Added

- `edit --global` and `edit --local`, including safe creation at the global or Git-root policy path.

### Changed

- Project policy lookup is anchored to the Git worktree root.

### Fixed

- Editors configured with arguments, such as `code --wait`, launch correctly.

## [0.1.0] — 2026-06-22

Initial public release.

### Added

- One merged global/project policy for Claude Code, Codex CLI, OpenCode and Gemini CLI, with deny-over-ask-over-allow precedence.
- Shell and named-tool rules, option checks, token globs, strict compound-command aggregation and configurable tracing.
- Tree-sitter Bash analysis for pipelines, lists, control flow, functions, substitutions, declarations, assignments, heredocs, redirects and shell/exec wrappers.
- Redirect safety: file writes ask, safe fd duplication and `/dev/null` defer, and computed targets still inspect nested commands.
- `install`, `import`, `check`, `edit`, `--dry-run` and `--version`, with Rulesync or direct agent configuration.
- Automatic local `.env` loading for hook configuration.
- Secure per-Zellij-pane prompt bypass with deny enforcement and traceable coercions.
- Overridable fallback allows for side-effect-free predicates and builtins.

### Changed

- Claude `bypassPermissions` fully defers to Claude; Gemini uses runtime hooks; installed hooks carry explicit events and suitable timeouts.

### Fixed

- Hardened parsing against denied-command laundering through quoting, substitutions, redirects, `bash -c`, `eval` and recognized executor prefixes.
- Corrected Codex 0.128+ permission envelopes, exact `Bash(...)` matching, redirect binding/spillover and escaped installation paths.
- Hardened hook installation with strict self-detection, stale-entry cleanup, Rulesync schema output and safe shell/JavaScript path embedding.

### Notes

- Gemini native-rule import is unavailable because its regex policy cannot be safely round-tripped.
- Legacy `BashOption` matching conservatively ignores the `--` boundary; use `Shell(...)` for boundary-aware rules.

[0.3.0]: https://github.com/jacks0n/agentperm/releases/tag/v0.3.0
[0.2.1]: https://github.com/jacks0n/agentperm/releases/tag/v0.2.1
[0.2.0]: https://github.com/jacks0n/agentperm/releases/tag/v0.2.0
[0.1.0]: https://github.com/jacks0n/agentperm/releases/tag/v0.1.0
