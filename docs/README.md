# agentperm documentation

One permission policy for Claude Code, Codex CLI, OpenCode, Gemini CLI, and Kiro — these docs
cover installing it, writing rules, and how it works inside.

## Start here

- **[Getting started](getting-started.md)** — install, create a policy from templates, watch a
  prompt disappear, and grow your rules from real prompts. Read this first.
- **[CLI reference](cli.md)** — every command: `install`, `uninstall`, `import`, `init`,
  `validate`, `why`, `check`, `edit`.
- **[Troubleshooting](troubleshooting.md)** — "it still prompts me", "it allowed something it
  shouldn't have", how to remove agentperm.

## Reference

- **[Policy reference](policy-reference.md)** — the `.agent-permissions.jsonc` format: rule forms,
  compound-command behavior, redirect allowlisting, directory hierarchy, importing native rules.
- **[Shell pattern DSL](pattern-dsl.md)** — the `Shell(...)` language spec: syntax, matching
  semantics, security model, formal grammar.
- **[SECURITY.md](../SECURITY.md)** — threat model, what agentperm is not, the trust status of
  repo-level policy files, bypass surfaces.

## Internals

- **[Architecture](architecture.md)** — domain model, decision flow, shell parsing, why
  tree-sitter, module layout.
- **[Adapter notes](adapters.md)** — per-agent hook protocols, payload shapes, verdict envelopes,
  and quirks; the contract for adding a new agent.
- **[Contributing](../CONTRIBUTING.md)** — dev setup, quality gates, release process.

## Terminology

| Term | Meaning |
|---|---|
| **policy file** | A `.agent-permissions.jsonc` — the global one in `~`, plus any per-directory files merged at decision time. |
| **rule** | One entry in `permissions.allow/ask/deny`: a `Shell(...)` pattern, legacy `Bash(...)`, a named tool, or `Python(readonly)`. |
| **segment** | One simple command inside a compound — `a | b && c` has three. Each segment is decided independently. |
| **verdict** | A decision (`allow` / `ask` / `deny` / no-opinion) plus the rationale naming the rule that produced it. |
