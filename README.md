# llm-agent-bridge

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)

One permission policy file for every coding agent. The bridge installs a hook into [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Codex CLI](https://github.com/openai/codex), [OpenCode](https://opencode.ai), and [Gemini CLI](https://github.com/google-gemini/gemini-cli) that consults `~/.agent-permissions.jsonc` before any tool runs — so the same allow / ask / deny rules apply everywhere.

## Why

Every agent ships its own permission system, and none of them parse compound shell commands the way a shell does. `cat foo 2>/dev/null | head -60` is two read-only segments separated by a pipe, but the native config typically can't reason about pipes, redirects, `&&`, or `bash -c "..."` — so it asks, every time. The bridge parses the command with a real shell AST ([bashlex](https://github.com/idank/bashlex)), evaluates each segment against your policy, and returns a single decision.

It also gives you one source of truth instead of four, plus a richer rule grammar (e.g. "ask before `sed -i`, allow `sed` otherwise").

## Install

```sh
pipx install llm-agent-bridge
# or
uv tool install llm-agent-bridge
```

Then:

```sh
llm-agent-bridge install   # writes hooks/plugins for every detected agent
llm-agent-bridge import    # pulls existing native rules into ~/.agent-permissions.jsonc
llm-agent-bridge edit      # opens the policy in $EDITOR (creates a default if missing)
```

After `install` you'll have `~/.agent-permissions.jsonc`. Per-project overrides live in `<project>/.agent-permissions.jsonc` — both files merge at decision time, deny wins.

## Quickstart

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [
      "Bash(git status:*)",
      "Bash(ls:*)",
      "Bash(cat:*)",
      "Read",
      "Grep",
      "WebFetch(domain:github.com)"
    ],
    "ask": [
      {
        "tool": "Bash",
        "command": ["sed", "gsed"],
        "when": { "hasOption": ["-i", "--in-place"] },
        "reason": "sed in-place editing changes files"
      }
    ],
    "deny": [
      "Bash(sudo:*)",
      "Bash(rm -rf /*)"
    ]
  }
}
```

A compound like `cat foo 2>&1 | head -60` passes through silently with the policy above — every segment matches an allow rule, the redirect is a safe `2>&1` fd-dup, and the bridge returns `allow`.

`sed -i s/foo/bar/ x.txt` surfaces a prompt with the rationale `"sed in-place editing changes files"` — the `ask` rule beats the `allow` rule on `sed`.

`rm -rf /tmp/*` is denied without prompting.

## Documentation

- [Architecture](docs/architecture.md) — domain model, AST parsing, aggregation, bypass coercion
- [Policy reference](docs/policy-reference.md) — full grammar of `.agent-permissions.jsonc`
- [CLI reference](docs/cli.md) — `install`, `import`, `check`, `edit`
- [Adapter notes](docs/adapters.md) — agent-specific behavior and limits
- [Troubleshooting](docs/troubleshooting.md) — diagnosing prompts, the trace env var, common pitfalls
- [Contributing](CONTRIBUTING.md) — dev setup, tests, PR conventions
- [Changelog](CHANGELOG.md)

## What it doesn't do

- **Manage MCP servers** — that's [rulesync](https://github.com/dyoshikawa/rulesync)'s job.
- **Replace native permission settings** — those keep working as fast paths. The bridge layers on top.
- **Manage hooks other than its own permission hook** — installs are scoped, idempotent, and safe to re-run alongside other tooling.
- **Sandbox commands** — the bridge is a policy engine, not an enforcement engine. Commands the agent decides to run still run with your shell's privileges.

## License

MIT — see [LICENSE](LICENSE).
