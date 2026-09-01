# Getting started

Go from installation to a verified policy in a few minutes. Requires Python 3.12+ on macOS or Linux.

## 1. Install and preview

```sh
uv tool install agentperm   # or: pipx install agentperm
agentperm install --dry-run
agentperm install
```

The dry run prints files agentperm would change. `install` adds hooks for the supported agents it
finds; it does not replace their native permission settings. In auto mode it uses Rulesync when
`~/.rulesync/` exists, otherwise it writes native hook configuration directly. OpenCode's plugin is
always installed directly. See [CLI: install](cli.md#install) for exact paths and modes.

With no policy, agentperm returns no opinion and the host continues its native flow.

### Coexisting with Beckon

agentperm and Beckon are independent: agentperm never requires or invokes Beckon, and Beckon's
ordinary lifecycle hooks do not require agentperm. Codex is the one special composition point. If
Beckon tracks human permission prompts while agentperm automatically decides the same
`PermissionRequest`, configure one ordered command:

```text
beckon permission-hook codex -- agentperm check --agent codex --event PermissionRequest
```

Do not install separate matching Codex `PermissionRequest` commands for those two responsibilities;
Codex runs them concurrently, so Beckon cannot observe agentperm's verdict. The wrapper sends the
same envelope to agentperm, immediately relays allow/deny, and records Beckon attention only for an
unresolved native prompt. Other agentperm and Beckon hooks remain separate.

After changing generated hook configuration, restart already-running host-agent processes. You may
resume their conversations; iTerm2 and the multiplexer do not need restarting.

## 2. Create a starter policy

```sh
agentperm init
```

This creates `~/.agent-permissions.jsonc` from three readable templates:

- `safety-baseline` denies commands such as `sudo`, asks on destructive flags, and gates file
  redirects.
- `file-inspection` covers common read-only file, text, and system inspection.
- `git-read-only` covers inspection-oriented Git commands.

Existing rules remain intact when templates are added again; new entries are reported with their
source template. If an existing policy is rewritten during a merge, hand-written comments are not
preserved.

```sh
agentperm init --list
agentperm init aws-read-only gh-read-only python-checks
```

Bundled templates live in [`src/agentperm/templates/`](../src/agentperm/templates/); larger examples
live in [`examples/`](../examples/).

## 3. Verify before trusting it

```console
$ agentperm why "git status | head -5"
allow — allow by rule 'Shell(git {status,log,diff,show,blame,shortlog,describe,reflog} values(-C))'
  git status  → allow (...)
  head -5     → allow (...)
```

`why` evaluates the merged policy without running the command. It also exposes the important
compound rule: all segments must be safe. One unknown segment prompts; one deny blocks everything.
Once the result is Allow, ask your agent to run the same command: the installed hook now evaluates
the pipeline as two reviewed segments instead of one opaque string.

```console
$ agentperm why "cat README.md | ./deploy.sh"
ask — compound includes unrecognized segment: no rule matched './deploy.sh'

$ agentperm why "sudo rm -rf /"
deny — deny by rule 'Shell(sudo)'
```

## 4. Add one deliberate rule

Open the global policy:

```sh
agentperm edit
```

Add rules to `allow`, `ask`, or `deny`. Within one file, Deny wins over Ask, which wins over Allow.

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [
      "Shell(terraform {plan,show,validate} !-*)",
      "Read(src/**)"
    ],
    "deny": [
      {"Write(generated/**)": {"reason": "Edit the schema and regenerate this directory."}}
    ]
  }
}
```

`Write` is a semantic operation shared across agents: native edits, overwrites, notebook edits, and
patch add/update/delete/move all map to it. The [capability matrix](capabilities.md) lists exact
host mappings and limitations.

Validate before returning to your agent:

```sh
agentperm validate
agentperm why "terraform validate"
```

The runtime loader is intentionally tolerant of unknown shapes; `validate` catches misspellings such
as `Shel(...)` that would otherwise never match.

## 5. Grow from real prompts

When a command prompts unexpectedly:

1. Run `agentperm why "<command>"`.
2. Add the narrowest rule covering the reviewed intent.
3. Run `agentperm validate` and `why` again.

Common forms:

```jsonc
"Shell(git {status,log,diff} !-*)"         // alternation; no flags
"Shell(git push !--force)"                 // forbid one flag
"Shell(git stash {list,show} !... !-*)"    // no extra operands or flags
"Shell(aws values(--region) s3 ls)"        // value flag may move
"WebFetch(domain:github.com)"              // URL field and subdomains
"Write(src/**)"                            // normalized path from request cwd
```

Use the [Shell pattern DSL](pattern-dsl.md) for shell rules and the
[policy reference](policy-reference.md) for every other setting.

## Optional: import native policies

```sh
agentperm import
```

Import reads supported Claude, Codex, OpenCode, and Kiro rules into the global policy without
modifying native configuration. Gemini import is not available. Review imported legacy
`Bash(...)` rules and narrow them where appropriate.

## Policy locations and trust

- `~/.agent-permissions.jsonc` applies globally.
- A `.agent-permissions.jsonc` in any ancestor of the request cwd adds directory policy.
- `agentperm edit --local` targets the current Git repository root.

Deny rules union across every file and cannot be overridden. For Ask and Allow, the nearest matching
policy wins: a project Allow can intentionally whitelist a global Ask, and a project Ask can narrow a
global Allow. Review checked-in policies like `.envrc`. See [SECURITY.md](../SECURITY.md).

If behavior differs from `why`, continue with [Troubleshooting](troubleshooting.md). To remove hooks
without deleting policy files, run `agentperm uninstall`.
