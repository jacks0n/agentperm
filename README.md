# llm-agent-bridge

Permission policy mediator for [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Codex CLI](https://github.com/openai/codex), [OpenCode](https://opencode.ai), and [Gemini CLI](https://github.com/google-gemini/gemini-cli).

One file (`.agent-permissions.jsonc`) holds your allow/ask/deny rules. The bridge installs a hook into each tool that consults the policy before commands run, so the same rules apply everywhere.

## Why

Each agent CLI has its own permission system, and none of them handle compound shell commands well. `cat foo 2>/dev/null | head -60` looks like two read-only commands, but the native config can't reason about pipes, redirects, or sub-commands. The bridge parses the command with [bashlex](https://github.com/idank/bashlex), evaluates each segment against your policy, and returns a single decision.

## Install

```sh
pipx install llm-agent-bridge
# or
uv tool install llm-agent-bridge
```

## Usage

```sh
llm-agent-bridge install   # writes hooks for every detected agent
llm-agent-bridge import    # pulls native allow/ask/deny rules into .agent-permissions.jsonc
llm-agent-bridge edit      # opens the policy file (creates a default if missing)
```

After the first install you'll have `~/.agent-permissions.jsonc`. Per-project overrides go in `<project>/.agent-permissions.jsonc` — both files merge at decision time.

## Policy file

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [
      "Bash(git status:*)",
      "Bash(ls:*)",
      "Read",
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

## What it doesn't do

- Manage MCP servers — that's [rulesync](https://github.com/dyoshikawa/rulesync)'s job.
- Manage hooks other than its own permission hook.
- Touch native permission settings — those keep working as fast paths.

## License

MIT
