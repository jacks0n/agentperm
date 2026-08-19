# Security model

agentperm is a **policy layer, not a sandbox**. It decides allow / ask / deny for tool calls
that coding agents route through their hook mechanisms, so that intent you've expressed once
("read-only git is fine", "never `sudo`") applies consistently across agents without
re-prompting. It does not contain what runs. This document states plainly what it defends
against, what it doesn't, and the design decisions a security reviewer should know about.

## What agentperm is — and is not

**Is:** an ergonomics and intent-expression layer. It parses shell commands the way bash does
(pipes, `&&`/`||`, subshells, redirects, `bash -c` unwrapping, quote/escape normalization) and
matches each segment against your rules, so allow/ask/deny decisions survive command
composition instead of being defeated by the first `|`.

**Is not:** an execution boundary. It matches **argv shape, not command semantics**
([pattern DSL §6](docs/pattern-dsl.md#6-security-model--limitations)). It only sees tool calls
the host agent routes through hooks. It does not resolve symlinks, prove executable identity,
model what a flag actually does, or inspect interpreters beyond the shallow
`Python(readonly)` AST check.

## Threat model

| In scope | Out of scope |
|---|---|
| Prompt fatigue that trains you to approve reflexively — the core problem it exists to reduce | A compromised or malicious agent binary (it controls the hook mechanism itself) |
| Laundering a denied command through composition: pipes, `&&` chains, subshells, `bash -c`, quoting/backslash tricks, command/process substitution — deny rules bite through all of these | Tool calls the host never routes through hooks (MCP servers with their own execution, non-hooked channels) |
| A malformed `Shell(...)` / `Python(...)` pattern silently widening or weakening access — these fail loudly at load | Kernel-level containment: filesystem/network isolation is a sandbox's job (containers, `sandbox-exec`, landlock) |
| Redirect side effects (`>`, `>>`) — writes ask by default and are path-allowlisted | Semantics of allowed commands: if you allow `git`, agentperm does not know which subcommand-flag combinations are dangerous beyond what your rules say |

Commands the parser cannot fully decompose escalate rather than pass: a recognized-but-
undecomposable wrapper (`bash --norc -c …`, `timeout`, `sudo`, `xargs`) returns **ask**, and an
unrecognized executor (`busybox rm`, `find -exec`) returns **NoOpinion**, deferring to the host
agent's own permission flow. See [architecture.md § Limitations](docs/architecture.md#limitations).

## Known gap: project policies are trusted implicitly

Policy discovery merges `~/.agent-permissions.jsonc` with **every** `.agent-permissions.jsonc`
between the filesystem root and the command's working directory
(`_policy_paths` in `src/agentperm/policy.py`). There is **no trust gating**: a repository you
clone can ship a policy file whose `allow` rules take effect the moment an agent runs inside it.

What limits the exposure today:

- **Deny and ask always win across every level.** Merging is a union where
  deny > ask > allow, so a project file can *add allows* but can never remove or weaken a
  global `deny` or `ask` rule.
- Your global denies (`Shell(sudo)`, `Shell(curl)`, …) therefore remain your floor everywhere.

What you should do: **review a checked-in `.agent-permissions.jsonc` the same way you'd review
a repo's `.vscode/tasks.json` or `.envrc` before letting tooling act on it.** A direnv-style
trust step (allows from an unapproved or changed file being inert) is a possible future
direction; until then, treat project policy files as code.

## Bypass surfaces

Two mechanisms deliberately suppress prompts; both are opt-in and both are bounded:

- **Host bypass** (Claude Code `bypassPermissions` / `--dangerously-skip-permissions`):
  agentperm defers entirely and returns no opinion — the user has explicitly opted out of
  permission checks, and agentperm does not second-guess the host
  (`coerce_for_permission_mode`, `src/agentperm/cli.py`). Under host bypass, **deny rules do
  not bite**.
- **Zellij pane bypass**: a per-pane flag file coerces ask/NoOpinion to allow, but **deny rules
  still bite** — which is why it's the recommended alternative to host bypass. Hardening:
  session/pane names are rejected if they contain path-traversal characters; the flag directory
  must be owned by the current uid and not group/world-writable, so another local user cannot
  grant themselves bypass; a missing directory is a safe no-op. There is a documented
  [TOCTOU caveat](docs/cli.md#toctou-caveat) between the flag check and command execution.

## Failure behavior

- **Malformed hook payload → fail open.** `agentperm check` returns an empty `{}` verdict and
  lets the host's native permission flow decide. agentperm mediates; it is not the last line of
  defense, and a crash that blocked every tool call would push users toward host bypass, which
  is strictly worse.
- **Malformed policy file → fail closed to ask.** Every decision returns **ask** with a
  rationale naming the failing file, so a broken policy is loud, not silently permissive.
- **Malformed `Shell(...)` and `Python(...)` patterns fail loudly at load** (`PolicyError`),
  rather than being dropped. Some mistakes are still silent, though: a typo'd rule prefix
  (`"Shel(git status)"`) parses as a named-tool rule that never matches a shell command, and
  entries of an unrecognized shape are skipped — a rule you wrote can end up protecting
  nothing without an error.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub security advisories](https://github.com/jacks0n/agentperm/security/advisories/new)
rather than public issues. Reports about deny rules being bypassable through command
composition or encoding are especially valuable — that class is in scope and has dedicated
regression tests (`tests/test_policy.py`, the `test_deny_bites_through_*` family).
