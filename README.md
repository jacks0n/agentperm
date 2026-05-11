# agentperms

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)

One permission policy file for coding agents. Configure [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Codex CLI](https://github.com/openai/codex), or [OpenCode](https://opencode.ai) to call the bridge from their hook systems, and they can all consult `~/.agent-permissions.jsonc` before tools run — so the same allow / ask / deny rules apply everywhere.

## Why

Every agent ships its own permission system, and none of them parse compound shell commands the way a shell does. `cat foo 2>/dev/null | head -60` is two read-only segments separated by a pipe, but the native config typically can't reason about pipes, redirects, `&&`, `for ... do ... done`, or `bash -c "..."` — so it asks, every time. The bridge parses the command with the Tree-sitter Bash grammar, evaluates each executable segment against your policy, and returns a single decision.

It also gives you one source of truth instead of four, plus a richer rule grammar (e.g. "ask before `sed -i`, allow `sed` otherwise").

## Install

```sh
pipx install agentperms
# or
uv tool install agentperms
```

Then:

```sh
agentperms import    # pulls existing native rules into ~/.agent-permissions.jsonc
agentperms install   # wires the bridge into Claude Code, Codex, OpenCode, and Gemini hooks
agentperms edit      # opens the policy in $EDITOR (creates a default if missing)
```

`install` auto-detects whether you use [Rulesync](https://github.com/dyoshikawa/rulesync) — if `~/.rulesync/` exists, it merges hook entries into `~/.rulesync/hooks.json` and you re-run `rulesync` to materialise per-tool configs. Otherwise it writes per-tool configs (`~/.claude/settings.json`, `~/.codex/hooks.json`+`config.toml`, `~/.gemini/settings.json`) directly. The OpenCode plugin shim is always installed at `~/.config/opencode/plugins/agentperms.js` because rulesync has no schema for `permission.ask` plugins. Pass `--mode rulesync|direct` to override detection or `--dry-run` to preview.

Per-project overrides live in `<project>/.agent-permissions.jsonc` — both files merge at decision time, deny wins.

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

## Bypass mode (zellij)

A per-pane "skip prompts" toggle for users running their agents inside [zellij](https://zellij.dev). Bind a key to flip a flag file for the focused pane; while the flag is on, `agentperms` coerces every `Ask` and `NoOpinion` verdict to `Allow` — but only in that pane, and `Deny` rules still bite. The toggle and indicator live in a small WASM plugin shipped at [`zellij-plugin/`](zellij-plugin/README.md).

## Documentation

- [Architecture](docs/architecture.md) — domain model, AST parsing, aggregation, bypass coercion
- [Policy reference](docs/policy-reference.md) — full grammar of `.agent-permissions.jsonc`
- [CLI reference](docs/cli.md) — `install`, `import`, `check`, `edit`, pane bypass
- [Adapter notes](docs/adapters.md) — agent-specific behavior and limits
- [Troubleshooting](docs/troubleshooting.md) — diagnosing prompts, the trace env var, common pitfalls
- [zellij plugin](zellij-plugin/README.md) — per-pane bypass toggle and indicator
- [Contributing](CONTRIBUTING.md) — dev setup, tests, PR conventions
- [Changelog](CHANGELOG.md)

## What it doesn't do

- **Manage MCP servers** — use Rulesync, native agent config, or your own dotfile tooling.
- **Replace native permission settings** — those keep working as fast paths. The bridge layers on top.
- **Sandbox commands** — the bridge is a policy engine, not an enforcement engine. Commands the agent decides to run still run with your shell's privileges.

## License

MIT — see [LICENSE](LICENSE).
