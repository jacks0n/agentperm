# agentperm

One permission policy for [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Codex CLI](https://github.com/openai/codex), [OpenCode](https://opencode.ai), [Gemini CLI](https://github.com/google-gemini/gemini-cli), and [Kiro](https://kiro.dev), with a shell parser that reads compound commands the way bash does.

## The problem

Coding agents ask before running shell commands. Each has its own permission config, and none of them parse what you typed — `cat foo | head -60` is one opaque string, so every agent asks about it even though both sides are read-only. You end up maintaining the same rules in three different places, and still getting prompted for things you've already allowed.

## What agentperm does

It replaces those separate configs with a single `.agent-permissions.jsonc` that every agent consults. It parses pipes, `&&`/`||` chains, loops, subshells, redirects, and `bash -c` wrappers, then decides each segment against your rules:

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [
      "Shell(git {status,log,diff,show,branch} !-*)",
      "Shell(sed !{-i,--in-place})",
      "Shell({cat,head,grep,rg,ls,wc})",
      "Python(readonly)",
      "Read", "Grep"
    ],
    "ask": [
      { "tool": "Bash", "command": ["sed"], "when": { "hasOption": ["-i"] },
        "reason": "sed -i edits files in place" }
    ],
    "deny": ["Shell(sudo)", "Shell(rm -r -f /*)"]
  },
  "shell": {
    "redirection": {
      "stdoutToFile": "ask",
      "allowPaths": ["/tmp"]
    }
  }
}
```

| Command | Verdict | Why |
|---|---|---|
| `cat foo 2>&1 \| head -60` | **allow** | both segments allowed; `2>&1` is a safe fd dup |
| `git status && cat README.md` | **allow** | `&&` — both sides allowed |
| `sed -i s/old/new/ x.txt` | **ask** | the ask rule on `-i` wins over the allow |
| `echo hi > /tmp/out.txt` | **allow** | redirect target matches `allowPaths` |
| `echo hi > ~/notes.txt` | **ask** | redirect to file outside `allowPaths` |
| `cat foo \| ./deploy.sh` | **ask** | one unrecognized segment in a compound |
| `rm -rf /` | **deny** | deny always wins |

No prompt on the first two. Native matchers ask about both because a pipe or `&&` defeats string matching.

## Install

```sh
uv tool install agentperm   # or: pipx install agentperm
```

## Setup

```sh
agentperm install   # wire hooks into Claude Code / Codex / OpenCode / Gemini / Kiro
agentperm import    # pull existing native rules into ~/.agent-permissions.jsonc
agentperm edit      # open the policy in $VISUAL/$EDITOR
```

`install` writes to each agent's hook config, or merges into `~/.rulesync/hooks.json` if you use [Rulesync](https://github.com/dyoshikawa/rulesync). Preview with `--dry-run`. Your native settings keep working underneath — nothing is taken away.

## Writing rules

Rules go in `allow`, `ask`, or `deny`. First match wins within a list; deny beats ask beats allow across lists.

**Shell patterns** — the recommended form. Flags float; trailing args open by default:

```jsonc
"Shell(git {status,log,diff} !-*)"          // match subcommands, reject all flags
"Shell(git push !--force)"                   // allow push, forbid --force
"Shell(aws values(--region) ec2 describe-*)" // declare that --region eats the next token
"Shell(git stash {list,show} !... !-*)"      // exact subcommand, no extra args or flags
```

**Per-rule redirect paths** — allow redirects to specific directories for matching commands:

```jsonc
{"Shell(mise exec just synth-env)": {"allowPaths": ["/tmp"]}}
```

**Named tools** — match non-shell tools, optionally scoped by input:

```jsonc
"Read"                          // exact
"mcp__memory__*"                // prefix glob
"WebFetch(domain:github.com)"   // URL host scoping
"Edit(src/**)"                  // path glob scoping
```

**Legacy positional** — `"Bash(git status:*)"` remains supported for existing policies and imports.

**Flag matching** — `{ "tool": "Bash", "command": ["sed"], "when": { "hasOption": ["-i"] }, "reason": "..." }`.

**Python analysis** — `"Python(readonly)"` shallowly inspects `python -c` and heredoc source with the stdlib AST. Imports, printing, and inspection run without a prompt; mutation asks.

In compounds the strictest segment decides. One unrecognized command = ask. Deny always wins. Full spec: [Shell pattern DSL](docs/pattern-dsl.md) · [Policy reference](docs/policy-reference.md).

## Global + per-project

`~/.agent-permissions.jsonc` sets global defaults. `<repo>/.agent-permissions.jsonc` adds project-specific rules. Both apply at the same time — deny wins across both.

```jsonc
// global — broad defaults
{ "version": 1, "permissions": {
    "allow": ["Shell({cat,ls,grep,rg})", "Shell(git {status,diff,log})", "Read"],
    "deny":  ["Shell(sudo)", "Shell(rm -r -f /*)"]
}}
```

```jsonc
// ~/work/payments/.agent-permissions.jsonc — project overrides
{ "version": 1, "permissions": {
    "allow": ["Shell(pytest)", "Shell(pnpm run {build,test,lint})"],
    "deny":  [{ "tool": "Bash", "command": ["git"],
                "when": { "hasOption": ["--force"] },
                "reason": "no force-push in this repo" }]
}}
```

A repo adds its own tools and clamps down on dangerous variants without touching the global file. `agentperm edit --local` creates or opens the project file.

## Redirect allowlisting

File redirects (`>`, `>>`) default to `ask`. You can allowlist directories globally or per-rule:

```jsonc
"shell": {
  "redirection": {
    "stdoutToFile": "ask",
    "allowPaths": ["/tmp", "/private/tmp/claude-*"]
  }
}
```

Paths resolve through symlinks (`/tmp` covers `/private/tmp` on macOS). Globs match per component. Relative targets resolve against the working directory.

## Zellij pane bypass

The bundled [WASM plugin](zellij-plugin/README.md) adds a per-pane toggle: `ask` and unmatched commands become `allow` in that pane only. `deny` rules still bite. Under Claude Code's own `--dangerously-skip-permissions`, agentperm steps aside completely.

## What it doesn't do

- **No sandbox.** It decides allow / ask / deny; it doesn't contain what runs.
- **No replacing native settings.** Those keep working as a fast path.
- **No MCP server management.** Use Rulesync or native config for that.

## More

[Policy reference](docs/policy-reference.md) · [Shell pattern DSL](docs/pattern-dsl.md) · [Architecture](docs/architecture.md) · [Adapter notes](docs/adapters.md) · [Changelog](CHANGELOG.md)

## License

MIT
