# agentperm

[![PyPI](https://img.shields.io/pypi/v/agentperm.svg)](https://pypi.org/project/agentperm/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)

**One allow / ask / deny policy for [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Codex CLI](https://github.com/openai/codex), [OpenCode](https://opencode.ai), and [Gemini CLI](https://github.com/google-gemini/gemini-cli) — with a shell parser that reads compound commands the way bash does.**

## What it does

Coding agents ask before running a shell command. Each ships its own permission config, and none of them actually parse the command — to the native matcher, `cat foo | head -60` is one opaque string, so it can't tell that it's two harmless read-only commands and asks you anyway. Every time.

agentperm replaces those four separate configs with a single file every agent consults, and decides on the *whole parsed command*. Here is a policy and exactly what your agents do with it:

```jsonc
// ~/.agent-permissions.jsonc
{
  "version": 1,
  "permissions": {
    "allow": ["Bash(cat:*)", "Bash(head:*)", "Bash(sed:*)", "Bash(git status:*)", "Read", "Grep"],
    "ask":   [{ "tool": "Bash", "command": ["sed"], "when": { "hasOption": ["-i", "--in-place"] },
                "reason": "sed -i edits files in place" }],
    "deny":  ["Bash(sudo:*)", "Bash(rm -rf:*)"]
  }
}
```

| Command the agent wants to run | Verdict | Why |
|---|---|---|
| `cat foo 2>&1 \| head -60` | **allow** | both segments allowed; `2>&1` is a safe redirect |
| `git status && cat README.md` | **allow** | `&&` sequence, both sides allowed |
| `sed -i s/old/new/ x.txt` | **ask** | `sed` is allowed, but the `ask` rule on `-i` wins |
| `cat notes \| ./deploy.sh` | **ask** | `compound includes unrecognized segment: no rule matched './deploy.sh'` |
| `rm -rf /tmp/*` | **deny** | `deny by rule 'Bash(rm -rf:*)'` |

These are the real verdicts `agentperm check` returns — the same answers every wired-up agent receives (the `ask`/`deny` rows quote the exact rationale string). The first two run with **no prompt**; the native matchers ask about both, because a single pipe or `&&` defeats literal string matching.

## Install

```sh
uv tool install agentperm   # or: pipx install agentperm
```

## Set up (once)

```sh
agentperm import    # copy your agents' existing rules into ~/.agent-permissions.jsonc
agentperm install   # wire agentperm into each agent's hooks
agentperm edit      # open the policy in your editor ($VISUAL/$EDITOR; writes a default if none exists)
```

After `install`, each agent calls agentperm before running a tool. Your native settings keep working underneath as a fast path — nothing is taken away.

`install` writes to each agent's hook config (`~/.claude/settings.json`, `~/.codex/`, `~/.gemini/settings.json`, plus an OpenCode plugin), or merges into `~/.rulesync/hooks.json` if you use [Rulesync](https://github.com/dyoshikawa/rulesync). Preview with `--dry-run`; force a path with `--mode rulesync|direct`. See the [CLI reference](docs/cli.md).

## Writing rules

Rules go in `allow`, `ask`, or `deny`. Three forms:

- **`"Bash(git status:*)"`** — match a shell command by prefix (`git status` and anything after it). Drop the `:*` for an exact match, or use glob tokens: `*` matches one argument, `**` matches zero or more (e.g. `Bash(pnpm --dir * build:*)`).
- **`"Read"`, `"WebFetch(domain:github.com)"`** — match a non-shell tool by name (`Read`, `mcp__memory__*`, `*`). An optional specifier scopes by the tool's input fields: `WebFetch(domain:github.com)` matches a URL field on that host or a subdomain; any other specifier is a path glob (`*` within a segment, `**` across) on the tool's path fields (`Read(/etc/**)`, `Edit(src/*)`). Bare name (or `(*)`) matches any input.
- **Object form** — match on flags: `{ "tool": "Bash", "command": ["sed"], "when": { "hasOption": ["-i"] }, "reason": "..." }`.

In a compound command the strictest segment decides — one unrecognized command turns the whole line into an `ask`, and **deny always wins**. Full grammar: [policy reference](docs/policy-reference.md).

## Global + per-project

agentperm merges two policy files and applies **deny over everything**: broad defaults in your home directory, overrides per repo. Both apply at the same time.

```jsonc
// ~/.agent-permissions.jsonc — defaults, everywhere
{ "version": 1, "permissions": {
  "allow": ["Bash(cat:*)", "Bash(git push:*)", "Read", "Grep"],
  "deny":  ["Bash(sudo:*)", "Bash(rm -rf:*)"]
}}
```

```jsonc
// ~/work/payments/.agent-permissions.jsonc — only inside this repo
{ "version": 1, "permissions": {
  "allow": [
    "Bash(pytest:*)",               // this repo's own tools
    "Bash(pnpm --dir * build:*)"    // * = one arg token; ** = zero or more
  ],
  "deny": [
    { "tool": "Bash", "command": ["git"],
      "when": { "hasOption": ["--force", "-f", "--force-with-lease"] },
      "reason": "force-push rewrites shared history" }
  ]
}}
```

Working inside `~/work/payments`, an agent sees both at once:

| Command | Verdict | Source |
|---|---|---|
| `cat notes.md` | **allow** | global default |
| `pytest -q` | **allow** | project adds it |
| `pnpm --dir packages/web build` | **allow** | project glob rule |
| `git push` | **allow** | global — a normal push is still fine |
| `git push --force` | **deny** | project flag rule overrides the global allow |

So you allow a tool broadly once, and a single repo can both add its own commands and clamp down on the dangerous variants — without touching the global file.

Create or edit the project file with `agentperm edit --local` (it writes to your git repo root). `import` and `install` always act on the global file and your agents' global hooks.

## Examples

Ready-to-crib policies in [`examples/`](examples/):

- [`starter.agent-permissions.jsonc`](examples/starter.agent-permissions.jsonc) — a minimal global policy to begin from: read-only shell and tools allowed, `sed -i` asks, `sudo` / `rm -rf` denied.
- [`global.agent-permissions.jsonc`](examples/global.agent-permissions.jsonc) — a fuller real-world global policy: a large allow-list of read-only AWS and CLI commands, the `sed -i` ask rule, a deny list, and shell-redirection defaults.
- [`project.agent-permissions.jsonc`](examples/project.agent-permissions.jsonc) — this repo's own per-project file, allowing just its dev-tooling commands on top of whatever your global policy permits.

## Commands

| Command | What it does |
|---|---|
| `agentperm import` | Copy existing native rules into the policy file (Claude, Codex, OpenCode) |
| `agentperm install [--mode auto\|rulesync\|direct] [--dry-run]` | Wire agentperm into agent hooks |
| `agentperm edit [--global\|--local]` | Open the policy in your editor (`$VISUAL`/`$EDITOR`), creating a default if missing. `--global` (default) is `~/.agent-permissions.jsonc`; `--local` is this repo's root file |
| `agentperm check --agent <claude\|codex\|opencode\|gemini> --event <name>` | Runtime decision: reads a hook payload on stdin, writes a verdict on stdout. The agent runs this, not you. |
| `agentperm --version` | Print the installed version |

## Skip prompts in one pane (zellij)

Running agents inside [zellij](https://zellij.dev)? The bundled WASM plugin adds a per-pane toggle: while it's on, both `ask` **and** unmatched (no-opinion) commands become `allow` in that pane only — `deny` rules still bite. See [`zellij-plugin/`](zellij-plugin/README.md). (Under Claude Code's own `--dangerously-skip-permissions`, agentperm steps aside completely.)

## What it doesn't do

- **It doesn't sandbox.** agentperm decides allow / ask / deny; it doesn't contain what runs. An approved command runs with your normal privileges.
- **It doesn't replace native settings.** Those keep working as a fast path; agentperm layers on top.
- **It doesn't manage MCP servers.** Use Rulesync or native config for that.

## More

- [Architecture](docs/architecture.md) · [Policy reference](docs/policy-reference.md) · [CLI reference](docs/cli.md)
- [Adapter notes](docs/adapters.md) · [Troubleshooting](docs/troubleshooting.md) · [zellij plugin](zellij-plugin/README.md)
- [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE).
