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
the host agent routes through hooks. Scoped tool paths and redirect allowlists resolve existing
symlinks before matching; Shell executable matching does not resolve symlinks or prove executable
identity. agentperm does not model what an allowed flag actually does or inspect interpreters beyond
the shallow `Python(readonly)` AST check.

## Threat model

| In scope | Out of scope |
|---|---|
| Prompt fatigue that trains you to approve reflexively — the core problem it exists to reduce | A compromised or malicious agent binary (it controls the hook mechanism itself) |
| Laundering a denied command through composition: pipes, `&&` chains, subshells, `bash -c`, quoting/backslash tricks, command/process substitution — deny rules bite through all of these | Tool calls the host never routes through hooks (MCP servers with their own execution, non-hooked channels) |
| A malformed `Shell(...)` / `Python(...)` pattern silently widening or weakening access — these fail loudly at load | Kernel-level containment: filesystem/network isolation is a sandbox's job (containers, `sandbox-exec`, landlock) |
| Redirect side effects (`>`, `>>`) — writes ask by default and are path-allowlisted | Semantics of allowed commands: if you allow `git`, agentperm does not know which subcommand-flag combinations are dangerous beyond what your rules say |
| Native file mutations translated to scoped `Edit`/`Write`, including patch moves and multi-file strictness | Writes performed internally by an allowed shell program rather than by a native file tool or shell redirect |
| Invalid mutation patches — rejected before they can evade scoped file rules | Filesystem changes between policy evaluation and execution (TOCTOU) |

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

- **Deny always wins across every level.** A project file cannot remove or weaken a global Deny;
  global denies such as `Shell(sudo)` remain your floor everywhere.
- **Ask and Allow intentionally support local overrides.** The nearest matching policy wins, so a
  project Allow can whitelist a global Ask. This makes checked-in policy review important: a
  repository can suppress prompts that your global policy would otherwise request.

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

- **Unrecognized or generically malformed hook payload → fail open.** If an adapter cannot identify
  a request, `agentperm check` returns an empty `{}` and lets the host's native flow decide.
- **Recognized malformed operations → fail closed where targets would otherwise be hidden.** An
  unparseable Codex/OpenCode patch denies; a Kiro shell request missing its command asks and blocks.
  This prevents malformed input from bypassing scoped mutation rules.
- **Malformed policy file → fail closed to ask.** Every decision returns **ask** with a
  rationale naming the failing file, so a broken policy is loud, not silently permissive.
- **Malformed `Shell(...)` and `Python(...)` patterns fail loudly at load** (`PolicyError`),
  rather than being dropped. Some mistakes are still silent at runtime, though: a typo'd rule
  prefix (`"Shel(git status)"`) parses as a named-tool rule that never matches a shell command,
  and entries of an unrecognized shape are skipped — run `agentperm validate` to catch exactly
  these cases before they cost you protection.

Adapter behavior is constrained by each host. Gemini maps Ask to a blocking deny with an
approval-required rationale; Kiro represents both Ask and Deny as exit code 2. OpenCode and Codex
use pre-execution hooks for hard denies so native allow settings cannot bypass a denied patch. See
the [capability matrix](docs/capabilities.md#enforcement-behavior) for the full comparison.

## Diagnostic traces are not an audit system

`AGENTPERM_TRACE` appends raw JSONL records for debugging. A record can include full commands, paths,
tool inputs, URLs, prompts, environment-derived context, and secrets present in the payload. Tracing
is off by default and failures to write the trace are ignored so diagnostics cannot break hooks.

agentperm provides no redaction, access-control setup, log rotation, retention, querying, integrity
signing, or tamper resistance. Concurrent hook processes append independently; do not treat ordering
or completeness as guaranteed. If you enable tracing, choose a private path, protect it with OS file
permissions, rotate or delete it yourself, and disable it after diagnosis. See
[CLI: diagnostic traces](docs/cli.md#diagnostic-traces).

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub security advisories](https://github.com/jacks0n/agentperm/security/advisories/new)
rather than public issues. Reports about deny rules being bypassable through command
composition or encoding are especially valuable — that class is in scope and has dedicated
regression tests (`tests/test_policy.py`, the `test_deny_bites_through_*` family).
