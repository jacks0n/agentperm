# Agentperm Config

A native macOS policy editor for explaining why commands were allowed, denied, or prompted and turning those commands into explicit, reviewable agentperm configuration changes.

The app always explains the global policy baseline and compares it with any selected repositories. Configure mode uses Codex headlessly with `--sandbox read-only`; Codex emits a schema-constrained proposal and cannot edit policies. Agentperm's versioned local JSON API owns policy discovery, rule parsing and serialization, lossless JSON5 diffs, validation, compare-and-swap application, rollback, and undo. The native app owns workflow instructions, target selection, review, feedback, and approval.

## Install

Requirements: macOS 14+, Codex CLI, and agentperm. Alfred 5 with Powerpack is optional.

```sh
./scripts/install.sh
```

Open the app directly, or install the optional Alfred workflow and type `ap`. Alfred immediately shows the current global verdict and offers **Explain** or **Propose Changes**; leave the argument blank to use the clipboard. You can also assign a key to its Hotkey trigger.

Published releases include a universal Apple Silicon/Intel DMG: open it and drag **Agentperm Config** to **Applications**. The source installer above is for contributors and also installs the optional Alfred workflow.

Settings provide optional Codex and agentperm executable overrides (otherwise resolved from the inherited `PATH`), a Codex profile/model, additional repository roots, exclusions, global instructions, and named workflows. Agentperm owns policy discovery beginning at `~/.agent-permissions.jsonc`. Git discovery always covers the home directory and ignores missing roots. It skips system, privacy-protected, application, cache, dependency, and build directories; add a protected folder explicitly if you want macOS to grant access. The seeded **Read-only generalisation** workflow preserves the conservative broad-safe behavior; custom workflows can propose allow, ask, or deny rules while retaining the same local diff and approval boundary.

## Explain workflow

1. Paste a command or compound shell program.
2. Optionally choose repositories to compare with the automatic global policy baseline.
3. See the effective decision, the winning rule or unmatched segment, compound-command breakdown, and every contributing policy file.
4. Open a policy file in Finder or carry the same command into Propose Changes.

## Propose Changes workflow

1. Edit the captured command and choose any repositories whose local scripts or configuration matter. The searchable picker shows selections as removable chips and can toggle all filtered results.
2. Analyse. Codex reads the global include graph, selected repositories, relevant manifests, local docs, and the active workflow instructions.
3. Review each generalized rule, its positive examples, its mutating neighbours, rejected command segments, target policies, and exact multi-file diff.
4. Toggle rules and global/project targets directly, or request a revision in natural language.
5. Apply selected changes. Agentperm applies the exact reviewed plan with compare-and-swap checks; the app then performs structured behavioral checks through the same API. Any failure restores every affected file.
6. Undo from the success screen if needed.

Choose **Ad hoc…** to provide one-off instructions without creating a saved workflow. Workflow instructions define what Codex should propose; agentperm independently parses, canonicalizes, targets, and validates every proposed rule.

No terminal window is opened. `--demo` launches the editor with a non-applying sample proposal:

```sh
swift run AgentpermConfig --demo
```

## Safety model

- Codex is read-only and returns data, not patches.
- The seeded workflow tells Codex to propose only defensible read-only surfaces. Agentperm can mechanically classify semantic rules such as `Python(readonly)`, SQL effects, and native read/write capabilities, but it does not claim to prove that every arbitrary executable named by `Shell(...)` is observational.
- Global and project targets are opaque IDs issued from agentperm's actual policy/include discovery. Codex cannot invent a writable path.
- Reusable tool permissions are global-first; project policies are for repository-dependent scripts and toolchains.
- Compound commands are split, so read-only segments can be proposed while writes and uncertain segments stay rejected.
- Each rule carries allow examples and nearby mutation examples. Apply fails if positives still prompt or a negative becomes allowed.
- Multi-file application is all-or-nothing and stale proposals cannot overwrite later edits.

Commands are redacted for common secret assignments and credential flags before being sent to Codex. Selected repository evidence and global/workflow instructions are also part of that request; Explain mode itself is local and invokes only `agentperm why`.

## Development and releases

`swift test` runs the deterministic suite. `scripts/build-app.sh` creates an ad-hoc-signed universal app for local development; `scripts/package-release.sh VERSION` adds a drag-to-Applications DMG, app ZIP, Alfred workflow, and checksums.

Tags named `config-vX.Y.Z` run the macOS release workflow. It requires a Developer ID Application certificate and App Store Connect API key in the documented repository secrets, signs the app and DMG, submits the DMG to Apple's notary service, staples the ticket, and publishes the artifacts to a GitHub release. See [publishing](docs/publishing.md).
