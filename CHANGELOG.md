# Changelog

Notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Recursive policy `include` entries with explicit paths and deterministic glob expansion. Included
  fragments merge as one logical policy layer, preserve Ask/Allow precedence, reject unmatched
  patterns and cycles, and are followed by runtime discovery, `validate`, and `why`.
- First-class semantic SQL rules for Oracle, PostgreSQL, MySQL/MariaDB, and SQLite, with recursive
  effect classification, conservative PostgreSQL `EXPLAIN` unwrapping, and selectors for statements,
  relations, and functions.
- Generic SQL captures in `Shell(...)` positional operands, repeated option values, literal stdin,
  nested executable/shell wrappers, and statically resolved inline-Python calls. Client names,
  option names, environment variables, and Python helper names remain policy-defined.

### Changed

- The semantic `Edit` file capability is folded into `Write`. Every native file mutation (Claude
  `Edit`, `MultiEdit`, `NotebookEdit`, `Write`; Codex and OpenCode `apply_patch`
  add/update/delete/move; OpenCode `edit`/`write`; Gemini `replace`/`write_file`; Kiro
  `write`/`fs_write`/`fsWrite`) is evaluated as `Write(path)`, so a scoped `Write` rule now governs
  overwrites of existing files, which previously fell through to the host prompt when only
  `Edit(...)` was denied. `Edit(...)` is retained as a compatibility alias: it parses as the same
  `Write(...)` rule, deduplicates against it, is written back as `Write(...)` by `import`/`init`,
  and `agentperm validate` warns about it. An existing `allow Edit(...)` rule now also allows
  creating files in its scope.
- Documentation now states the built-in `bash`/`sh`/`zsh -c` contract, including supported flag
  forms, Bash-compatible inner syntax, positional parameters, and fail-closed cases.

### Fixed

- `break`, `export`, `unset`, `set -a`, and `set +a` now receive the overridable inert-shell fallback
  allow; redirects, substitutions, and explicit user rules still take precedence.
- `Python(readonly)` now analyzes literal heredocs with or without an explicit stdin `-`.

## [0.4.0] — 2026-08-28

### Added

- Optional per-rule `reason` metadata for named tools, `Shell(...)`, `Bash(...)`, and
  `Python(readonly)`; custom text is returned verbatim when the rule fires.
- Cross-agent semantic `Edit`/`Write` enforcement for Claude Code, Codex, OpenCode, Gemini CLI,
  and Kiro, including multi-file patch and move decomposition with cwd- and symlink-aware paths.
- `agentperm init`: create or extend a policy file from bundled, composable rule templates grouped
  by domain — `safety-baseline`, `file-inspection`, `git-read-only`, `gh-read-only`, `aws-read-only`,
  `docker-read-only`, `packages-read-only`, and `python-checks`. With no arguments it writes a
  starter set (`safety-baseline file-inspection git-read-only`); `--list` enumerates templates;
  `--local` targets the repo root and `-o PATH` anywhere else. A fresh file keeps rules grouped
  under per-template comment headers; an existing file gains only the rules it doesn't already
  have, and its redirect decisions are never overridden.
- `agentperm uninstall`: the inverse of `install`. Strips every hook entry the installer wrote from
  Claude Code, Codex, OpenCode, Gemini CLI, Kiro, and rulesync configs, deleting containers left
  empty so an install/uninstall round trip restores the original file. Everything else is left
  untouched: Codex's `[features] hooks` flag stays, an OpenCode plugin file that isn't recognizably
  ours is kept with a warning, and policy files are never removed. `--mode` limits the sweep;
  `--dry-run` previews it.
- `agentperm validate`: lint policy files for what the tolerant runtime loader lets slide —
  entries that would be silently dropped, mistyped `Shell` prefixes that become never-matching
  named-tool rules, unknown keys, and redirect decisions that would be silently ignored. With no
  arguments it checks every file runtime discovery would load from the current directory. Exit 1
  on errors; warnings alone exit 0.
- `agentperm why "<command>"`: explain what the merged policy decides for a shell command —
  the aggregate verdict, a per-segment breakdown for compounds, and the policy files consulted.
- `SECURITY.md`: threat model, the implicit trust of project-level policy files, bypass surfaces,
  and failure behavior.
- `Shell(...)` accepts a standalone `--` operand, allowing patterns to require an end-of-options boundary while `--name` remains a flag.

### Changed

- Runtime policy discovery now merges the global policy with every `.agent-permissions.jsonc` from
  the filesystem root through the command's working directory instead of limiting local policy to
  the Git worktree root. Directory policies also apply outside Git repositories; rules union across
  levels, while the nearest override-style setting wins.
- `check` uses the working directory from the hook payload for policy discovery. A malformed policy
  at any discovered level produces an `ask` verdict whose reason identifies the failing file.
- `edit --local` remains anchored to the Git worktree root; nested directory policies are created
  manually.
- The exported `merged_policy` API accepts `cwd` for hierarchy discovery while retaining
  `local_root` as a compatibility alias.

### Fixed

- `Python(readonly)` now returns its configured per-rule reason for read-only source while retaining
  analyzer explanations for unsafe or ambiguous source. Rule-as-key objects now require exactly one
  rule key instead of partially parsing a rule and ignoring sibling fields.
- Codex `apply_patch` calls are now covered by the `PreToolUse` hook matcher and translated into
  scoped file operations. OpenCode now uses a pre-execution hook so native allow settings cannot
  bypass an agentperm deny.
- Recognized but unparseable Codex/OpenCode patch payloads now deny instead of bypassing scoped file
  rules. Kiro shell events without a command now require approval instead of becoming an empty
  operation.
- Policy-layer precedence now keeps `deny` non-overridable across every file, while the nearest
  matching `ask`/`allow` rule wins. A project `allow` can therefore whitelist an ancestor/global
  `ask`; an `ask` still precedes `allow` within the same file. This also applies to `python.calls`.
- OpenCode imports preserve scoped non-shell permission patterns instead of widening them to whole-tool rules.
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

[Unreleased]: https://github.com/jacks0n/agentperm/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/jacks0n/agentperm/releases/tag/v0.4.0
[0.3.0]: https://github.com/jacks0n/agentperm/releases/tag/v0.3.0
[0.2.1]: https://github.com/jacks0n/agentperm/releases/tag/v0.2.1
[0.2.0]: https://github.com/jacks0n/agentperm/releases/tag/v0.2.0
[0.1.0]: https://github.com/jacks0n/agentperm/releases/tag/v0.1.0
