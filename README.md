# agentperm

One permission policy for [Claude Code](https://docs.anthropic.com/en/docs/claude-code),
[Codex CLI](https://github.com/openai/codex), [OpenCode](https://opencode.ai),
[Gemini CLI](https://github.com/google-gemini/gemini-cli), and [Kiro](https://kiro.dev) —
and the only one that actually parses the command before deciding.

[![PyPI](https://img.shields.io/pypi/v/agentperm)](https://pypi.org/project/agentperm/)
[![Python](https://img.shields.io/pypi/pyversions/agentperm)](https://pypi.org/project/agentperm/)
[![CI](https://github.com/jacks0n/agentperm/actions/workflows/ci.yml/badge.svg)](https://github.com/jacks0n/agentperm/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jacks0n/agentperm/blob/main/LICENSE)

https://github.com/user-attachments/assets/9abcd24d-147c-4323-a1c3-970544e0d86a

[GIF fallback](https://raw.githubusercontent.com/jacks0n/agentperm/main/docs/media/demo.gif)

Coding agents prompt you constantly because their permission matchers are string prefixes:
allow `cat` and allow `head`, and `cat README.md | head -20` still prompts — the pipe defeats
the match. And you maintain that allowlist five times, once per agent, in five different formats.
agentperm installs as a hook in all five agents and parses each command the way bash does —
pipes, `&&` chains, subshells, redirects, `bash -c` wrappers, quoting tricks — deciding every
segment against one shared policy. Not a sandbox — an intent layer. Fewer prompts, consistently.

## Before / after

You allow three harmless commands:

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": ["Shell(cat)", "Shell(head)", "Shell(git status)"],
    "deny":  ["Shell(sudo)"]
  }
}
```

| The agent runs | Native matcher | agentperm |
|---|---|---|
| `cat README.md` | no prompt | no prompt |
| `cat README.md \| head -20` | **prompts** | no prompt — both segments allowed |
| `git status && cat notes.txt` | varies by agent | no prompt — both sides allowed |
| `cat foo \| ./deploy.sh` | prompts | still prompts — one unknown segment |
| `sudo ls` | depends on config | **denied**, in every agent |

The strictest segment always wins: one unrecognized command in a compound means a prompt, and a
`deny` written once bites everywhere.

## vs. native permissions

| | Native allowlists | agentperm |
|---|---|---|
| Decides each segment of `a \| b` | one opaque string | yes — tree-sitter-bash parse |
| One policy across all five agents | re-declare 5× | one `.agent-permissions.jsonc` |
| Flag-aware rules (`push` yes, `--force` no) | prefix match only | yes |
| Sees through quoting, `\r\m`, `bash -c`, `$( )` | no | normalized and decomposed before matching |
| Gates `>` / `>>` redirect targets | no | ask by default + path allowlist |
| Inspects `python -c` source | no | read-only AST check |
| Sandboxes execution | no | **no — not a sandbox** |

Your native settings aren't replaced — they keep working underneath as a fast path, and agentperm
only adds opinions on top.

## Quickstart

```sh
uv tool install agentperm   # or: pipx install agentperm
agentperm install           # hook into all five agents (preview with --dry-run)
agentperm init              # create ~/.agent-permissions.jsonc from starter templates
agentperm import            # optional: absorb the allowlists you already maintain
```

`init` composes bundled templates — `agentperm init --list` shows them all
(`aws-read-only`, `gh-read-only`, `docker-read-only`, `python-checks`, …). Verify it worked
without touching an agent:

```
$ agentperm why "git status | head -5"
allow — allow by rule 'Shell(git {status,log,diff,show,...} values(-C))'
  git status  → allow (...)
  head -5  → allow (...)
```

Then run your agent as normal: `git status | head -5` no longer prompts.
Requires Python 3.12+, macOS or Linux.

## Writing rules

Rules go in `allow`, `ask`, or `deny`; deny beats ask beats allow. Four rules, four features:

```jsonc
"Shell(git {status,log,diff} !-*)"   // {a,b} alternation; !-* rejects all flags
"Shell(git push !--force)"           // allow push, forbid one flag
"Shell(git stash {list,show} !...)"  // !... = exact: no extra operands
"Shell(aws values(--region) s3 ls)"  // values() declares flags that consume a value
```

Non-shell tools match by name: `"Read"`, `"mcp__memory__*"`, `"WebFetch(domain:github.com)"`,
`"Edit(src/**)"`. Inline Python can be allowed when provably read-only: `"Python(readonly)"`.
Full grammar: [Shell pattern DSL](https://github.com/jacks0n/agentperm/blob/main/docs/pattern-dsl.md) ·
everything else: [policy reference](https://github.com/jacks0n/agentperm/blob/main/docs/policy-reference.md).
After editing, `agentperm validate` catches typos the tolerant loader would otherwise skip silently.

## Global + per-directory policies

`~/.agent-permissions.jsonc` sets global defaults; any directory can add its own
`.agent-permissions.jsonc`, and agentperm merges every policy from the filesystem root to the
command's working directory. Rules union; deny wins across all levels, so a repo can add allows
but can never weaken your global denies. `agentperm edit --local` creates the repo-root file.

> **Review checked-in policy files.** A cloned repo can ship a `.agent-permissions.jsonc` whose
> allows take effect when an agent runs inside it — treat it like `.vscode/tasks.json`. See
> [SECURITY.md](https://github.com/jacks0n/agentperm/blob/main/SECURITY.md) for the threat model.

## Pane bypass (Zellij)

A bundled [WASM plugin](https://github.com/jacks0n/agentperm/tree/main/zellij-plugin) adds a
per-pane "skip prompts" toggle that is safer than `--dangerously-skip-permissions`: asks become
allows in that pane only, and deny rules still bite.

## What it doesn't do

- **No sandbox.** It decides allow / ask / deny; it doesn't contain what runs.
- **No replacing native settings.** Those keep working as a fast path.
- **No MCP server management.** Use [Rulesync](https://github.com/dyoshikawa/rulesync) or native config for that.
- **No repo-policy trust gating yet** — see [SECURITY.md](https://github.com/jacks0n/agentperm/blob/main/SECURITY.md).

## Uninstall

`agentperm uninstall` removes every hook the installer wrote and nothing else; policy files stay
yours. Then `uv tool uninstall agentperm`.

## Docs

[Getting started](https://github.com/jacks0n/agentperm/blob/main/docs/getting-started.md) ·
[CLI reference](https://github.com/jacks0n/agentperm/blob/main/docs/cli.md) ·
[Policy reference](https://github.com/jacks0n/agentperm/blob/main/docs/policy-reference.md) ·
[Pattern DSL](https://github.com/jacks0n/agentperm/blob/main/docs/pattern-dsl.md) ·
[Troubleshooting](https://github.com/jacks0n/agentperm/blob/main/docs/troubleshooting.md) ·
[All docs](https://github.com/jacks0n/agentperm/tree/main/docs) ·
[Changelog](https://github.com/jacks0n/agentperm/blob/main/CHANGELOG.md) ·
[Contributing](https://github.com/jacks0n/agentperm/blob/main/CONTRIBUTING.md)

## License

MIT
