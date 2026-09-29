# Publishing direction

The app is deliberately read-only-first. A public release should preserve that safe default while keeping the proposal and review engine generic.

## Product modes

1. **Explain** — runs the existing `agentperm why` engine against global/home and selected repository contexts, exposing the winning rule, compound segments, and contributing files without AI.
2. **Read-only assistant (default configuration workflow)** — proposes only mechanically isolated read-only allow rules. It may split mixed commands, replace unsafe broad rules, and leave writes rejected.
3. **Policy proposal** — can propose `allow`, `ask`, or `deny` rules for Shell, Read, Write, MCP, Python, and SQL capabilities. The reviewed **Apply selected** action is the approval boundary. Risk labels and optional workflow-specific confirmation preferences may add clarity, but the product does not impose a second approval ceremony.
4. **Manual policy editor (future)** — edits targets and rules without AI, while retaining parser validation, diffs, negative controls, transactions, and undo.

The UI and transaction engine remain shared. Modes change what proposal types are admissible, not who owns writes: the local app always owns application.

## Repository placement

Move this project under `apps/agentperm-config/` in agentperm. Keep Alfred as an optional launcher and do not add app-specific agentperm subcommands. Share:

- DSL and policy fixtures
- conformance cases for include discovery and precedence
- examples of broad-safe and unsafe-neighbour rules
- release/version compatibility tests

The standalone `.github/workflows` prove the pipeline before the move. In the agentperm monorepo, merge the CI job into the root CI workflow and the `config-v*` release job into the root release workflow; nested workflow files are not discovered by GitHub Actions.

The app may continue invoking existing `agentperm validate` and `agentperm why`. If machine-readable output later becomes a general agentperm feature, adopt it because it benefits every integration—not solely this UI.

## Public roadmap

- AI provider protocol beyond the initial Codex CLI implementation
- model/profile and analysis timeout
- manifest detectors and custom project evidence files
- data retention and command-redaction controls

Repository discovery should remain indexed and incremental. Explicit command paths outrank manifest matches; ambiguous contexts require user selection.

## Distribution

- universal arm64/x86_64 release binary
- Developer ID signing and Apple notarization
- versioned `.app` zip and `.alfredworkflow` release artifacts
- Sparkle or Alfred Gallery update metadata only after the update trust model is documented
- reproducible SwiftPM build and CI on supported macOS versions
- no requirement for users to install Swift

The release workflow uses these repository secrets:

- `MACOS_CERTIFICATE_P12_BASE64`
- `MACOS_CERTIFICATE_PASSWORD`
- `MACOS_SIGNING_IDENTITY`
- `APPLE_API_KEY_P8_BASE64`
- `APPLE_API_KEY_ID`
- `APPLE_API_ISSUER_ID`

It intentionally fails a tagged release when signing or notarization credentials are absent. Pull requests still build an ad-hoc-signed universal app without secrets.

Codex and agentperm remain explicit prerequisites initially. A later app can guide installation but should not silently modify agent hook configuration.

## Public safety contract

- model output is schema-constrained data, never a patch
- policy targets are resolved and confined locally
- secrets are redacted before model submission
- files are hash-bound to the reviewed versions
- multi-file updates are all-or-nothing
- positive and unsafe-neighbour examples are checked after application
- process output is drained continuously and child processes terminate with the app
- raw commands and traces are private, short-lived, and opt-in for diagnostics
- the explicit reviewed Apply action is the only required approval; risky changes remain clearly labelled and workflows may opt into additional confirmation

## Acceptance before release

- fixtures for global include ownership, project precedence, and worktrees
- compound commands with partial read-only coverage
- widening/replacement without lost JSONC comments
- stale-file and rollback tests across several policy files
- cancellation during analysis, revision, and application
- malicious model paths/rules rejected locally
- signed release tested from a clean macOS user account through Alfred
- accessibility, keyboard navigation, VoiceOver labels, light/dark mode, and reduced motion
