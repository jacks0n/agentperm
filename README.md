# agentperm

**Stop approving the same safe command because a flag moved or it entered a pipe.**

agentperm gives [Claude Code](https://docs.anthropic.com/en/docs/claude-code),
[Codex CLI](https://github.com/openai/codex), [OpenCode](https://opencode.ai),
[Gemini CLI](https://github.com/google-gemini/gemini-cli), and [Kiro](https://kiro.dev) one local
permission policy. It parses shell programs, evaluates every command, and applies the strictest
result. You review intent once instead of maintaining five fragile string allowlists.

[![PyPI](https://img.shields.io/pypi/v/agentperm)](https://pypi.org/project/agentperm/)
[![Python](https://img.shields.io/pypi/pyversions/agentperm)](https://pypi.org/project/agentperm/)
[![CI](https://github.com/jacks0n/agentperm/actions/workflows/ci.yml/badge.svg)](https://github.com/jacks0n/agentperm/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jacks0n/agentperm/blob/main/LICENSE)

https://github.com/user-attachments/assets/9abcd24d-147c-4323-a1c3-970544e0d86a

[GIF fallback](https://raw.githubusercontent.com/jacks0n/agentperm/main/docs/media/demo.gif)

## One command, fully understood

This policy allows read-only AWS inspection, `jq`, and `git status`:

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [
      "Shell(aws values(--region, --profile) ec2 describe-* only(--region, --profile))",
      "Shell(jq !-*)",
      "Shell(git values(-C) status only(-C, --short))"
    ]
  }
}
```

Now an agent can run this without a prompt:

```sh
bash -lc 'aws --profile dev ec2 describe-instances --region ap-southeast-2 | jq ".Reservations[]" && git -C . status --short'
```

agentperm unwraps `bash -lc`, splits the pipe and `&&`, and checks `aws`, `jq`, and `git`
independently. Move `--profile` or `--region` before or after the AWS subcommand, or use
`--region=value`: the same reviewed rule still matches.

The rule does not become broad just because it is flexible. Add `--endpoint-url`, change
`describe-*` to a mutating operation, or insert an unknown pipeline stage and the compound prompts.
A deny anywhere denies the whole operation.

That structural evaluation is the difference: agentperm understands pipelines, command and process
substitutions, redirects, executable paths, quoting, supported wrappers, flag clusters, and declared
flag values. It matches normalized commands—not one opaque shell string.

## Try it

Requires Python 3.12+ on macOS or Linux.

```sh
uv tool install agentperm                 # or: pipx install agentperm
agentperm install --dry-run && agentperm install
agentperm init
```

`install --dry-run` shows every hook file before anything changes. `init` builds
`~/.agent-permissions.jsonc` from conservative starter templates. Check a decision without running
an agent:

```console
$ agentperm why "git status | head -5"
allow — allow by rule 'Shell(git {status,log,diff,show,blame,shortlog,describe,reflog} values(-C))'
  git status  → allow (...)
  head -5     → allow (...)
```

Then use your agent normally. Existing native settings stay in place and continue to participate in
the host's permission flow. See [Getting started](docs/getting-started.md) for installation modes,
starter policies, and the first safe customization.

## What one policy can express

- **Shell structure:** each command in pipes, chains, substitutions, control flow, and supported
  wrappers is evaluated independently.
- **Useful permutations:** declare value-taking flags once; their order and `--flag=value` spelling
  can vary without widening the rule.
- **Precise constraints:** alternate command paths, require or forbid flags, reject extra operands,
  and allow only reviewed flags.
- **Semantic file controls:** write `Edit(src/**)` and `Write(dist/**)` once. Agent-specific edit,
  write, notebook, and patch operations map to those capabilities.
- **Scoped tools:** match tools by name, prefix, URL domain, or normalized path, including cwd,
  traversal, and existing symlinks.
- **Read-only inline Python:** `Python(readonly)` parses literal `python -c` and heredoc source with
  Python's AST, allowing inspection while surfacing recognized mutations and dynamic effects.
- **Layered policy:** combine a global policy with directory policies. Global Deny is an immutable
  floor; for Ask and Allow, the nearest matching policy wins, so a project can whitelist a global
  prompt without weakening a deny.
- **Explainable decisions:** `why`, custom rule reasons, validation, and opt-in JSONL traces show why
  a decision happened.
- **Portable setup:** install directly or through Rulesync, and import supported native policies.

The complete per-agent differences are in the [capability matrix](docs/capabilities.md).

## Rules in 60 seconds

Rules live in `permissions.allow`, `permissions.ask`, or `permissions.deny`:

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [
      "Shell(git {status,log,diff} !-*)",
      "Shell(aws values(--region) s3 ls only(--region))",
      "Read(src/**)",
      "Python(readonly)"
    ],
    "ask": [
      "Shell(git push)"
    ],
    "deny": [
      {"Edit(generated/**)": {"reason": "Generated file; update its source instead."}},
      {"Write(generated/**)": {"reason": "Generated file; update its source instead."}},
      "Shell(git push --force)",
      "Shell(sudo)"
    ]
  }
}
```

Useful Shell forms:

| Form | Meaning |
|---|---|
| `{status,log,diff}` | one of these command-path tokens |
| `describe-*` | glob within one token |
| `values(--region)` | `--region` consumes the following token |
| `only(--region, --profile)` | reject every other flag |
| `!--force` | reject this flag |
| `!-*` | reject every flag |
| `!...` | reject trailing operands |

Run `agentperm validate` after editing. The [policy reference](docs/policy-reference.md) covers the
whole file format; the [Shell pattern DSL](docs/pattern-dsl.md) is the exact grammar and matching
specification.

## How decisions compose

agentperm returns `allow`, `ask`, `deny`, or `no-opinion`. After policy-layer precedence selects a
verdict for each operation, the strictest result within a compound request wins:

```text
deny > ask > allow > no-opinion
```

An otherwise allowed pipeline with one unknown command becomes Ask. A multi-file patch with one
denied destination becomes Deny. `no-opinion` lets the host continue its native flow.

Policies load from `~/.agent-permissions.jsonc` and then from every directory between the filesystem
root and the command's working directory. Deny matches across every layer. For Ask and Allow, the
nearest policy with a matching rule wins; within one file, Ask precedes Allow. A cloned repository
can therefore bring its own allows, so review checked-in policy files like `.envrc` or
`.vscode/tasks.json`.

## Security boundary

agentperm is a **permission intent layer, not a sandbox**. It does not contain processes, prove what
an allowed program will do, or see execution paths a host does not send through hooks. Host bypass
mode can bypass agentperm entirely. Use OS isolation when containment matters and read
[SECURITY.md](SECURITY.md) before treating policies as a security control.

- It adds decisions to native permission flows; it does not replace host settings.
- It does not configure or isolate MCP servers.
- Directory policies are not trust-gated: a cloned repository can add allows and override global
  Ask rules, though it cannot weaken any Deny.
- Shell and Python analysis classify reviewed intent; they do not prove program behavior.

Traces are also diagnostic—not a production audit system. They are off by default, may contain raw
commands and secrets, and have no built-in redaction, rotation, retention, or tamper protection.
See [CLI: diagnostic traces](docs/cli.md#diagnostic-traces).

There is no SQL syntax analyzer today. SQL clients can be constrained with Shell rules, but
agentperm does not distinguish `SELECT` from mutating SQL inside a query string.

## Zellij pane bypass

The bundled [Zellij plugin](zellij-plugin/) adds a per-pane “skip prompts” toggle. It turns Ask and
NoOpinion into Allow for that pane while preserving Deny, making it narrower than a host-wide
“dangerously skip permissions” mode.

## Documentation

- [Getting started](docs/getting-started.md) — install, initialize, and verify a policy.
- [Capability matrix](docs/capabilities.md) — exact coverage and behavior by agent.
- [Policy reference](docs/policy-reference.md) — schema, semantic tools, hierarchy, and redirects.
- [Shell pattern DSL](docs/pattern-dsl.md) — complete matching grammar and limitations.
- [CLI reference](docs/cli.md) — commands, hook installation, traces, and exit behavior.
- [Troubleshooting](docs/troubleshooting.md) — symptom-led diagnosis and fixes.
- [Architecture](docs/architecture.md) and [adapter notes](docs/adapters.md) — contributor internals.
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md) — releases and development.

`agentperm uninstall` removes only hooks written by agentperm; policy files remain yours. Then remove
the package with `uv tool uninstall agentperm` or `pipx uninstall agentperm`.

## License

MIT
