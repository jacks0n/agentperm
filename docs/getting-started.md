# Getting started

From nothing to "my agents stopped prompting me for read-only commands" in about ten minutes.
Requires Python 3.12+, macOS or Linux.

## 1. Install the tool

```sh
uv tool install agentperm   # or: pipx install agentperm
```

## 2. Hook it into your agents

Preview what would change, then do it:

```sh
agentperm install --dry-run
agentperm install
```

`install` wires an `agentperm check` hook into every agent it finds config for — Claude Code,
Codex CLI, OpenCode, Gemini CLI, and Kiro. Your native permission settings are not modified; they
keep working underneath as a fast path. If you use [Rulesync](https://github.com/dyoshikawa/rulesync),
entries are merged into `~/.rulesync/hooks.json` instead ([details](cli.md#install)).

At this point nothing behaves differently yet: with no policy file, agentperm has no opinion and
every agent falls back to its native flow.

## 3. Create a policy from templates

```sh
agentperm init
```

This writes `~/.agent-permissions.jsonc` from three bundled templates: `safety-baseline` (deny
`sudo` and friends, ask on `sed -i`, gate `>` redirects), `file-inspection` (read-only file, text,
and system commands), and `git-read-only`. See what else is available and add what fits your work:

```sh
agentperm init --list
agentperm init aws-read-only gh-read-only python-checks
```

Templates merge: rules you already have are left alone, new ones append, and each addition is
reported with the template it came from. Every template is a readable policy file in
[`src/agentperm/templates/`](../src/agentperm/templates/) — good reference material for writing
your own rules. Complete real-world setups live in [`examples/`](../examples/).

## 4. Watch a prompt disappear

Ask agentperm what it now decides, no agent required:

```sh
$ agentperm why "git status | head -5"
allow — allow by rule 'Shell(git {status,log,diff,show,blame,shortlog,describe,reflog} values(-C))'
  git status  → allow (...)
  head -5  → allow (...)
policy files: /Users/you/.agent-permissions.jsonc
```

Then run your agent as normal and have it execute the same compound. Before: a permission prompt,
because native matchers treat `git status | head -5` as one opaque string that no allowlist entry
matches. Now: it just runs — agentperm parsed the pipe and found both segments allowed.

The strictest segment always wins. One unknown command in a compound still prompts:

```sh
$ agentperm why "cat foo | ./deploy.sh"
ask — compound includes unrecognized segment: no rule matched './deploy.sh'
```

And a deny is a deny, everywhere, in every agent:

```sh
$ agentperm why "sudo rm -rf /"
deny — deny by rule 'Shell(sudo)'
```

## 5. Grow the policy from real prompts

The working loop, whenever an agent prompts you for something you consider harmless:

1. `agentperm why "<the command>"` — the rationale names the segment that needs a rule.
2. `agentperm edit` — add one rule. A tour of the syntax, one feature at a time:

   ```jsonc
   "Shell(terraform {plan,show,validate})",   // {a,b} alternation on subcommands
   "Shell(sed !{-i,--in-place})",             // ! forbids specific flags
   "Shell(git stash {list,show} !... !-*)",   // !... = no extra operands, !-* = no other flags
   "Shell(aws values(--region) s3 ls)"        // values() declares flags that consume a value
   ```

   The full language: [Shell pattern DSL](pattern-dsl.md). Everything else the file can express —
   dict rules, redirect allowlisting, `Python(readonly)` — is in the
   [policy reference](policy-reference.md).

3. `agentperm validate` — catches what the tolerant loader would let slide: a typo like
   `"Shel(git status)"` doesn't error at runtime, it just silently never matches.

## 6. Import what your agents already allow

If you've been maintaining native allowlists, pull them in rather than re-writing them:

```sh
agentperm import
```

This reads Claude's `settings.json`, Codex's `*.rules`, OpenCode's `permission` block, and Kiro's
agent files, appending anything your policy doesn't already contain. Native configs are left
untouched ([details and limits](cli.md#import)).

## Where the files live

- `~/.agent-permissions.jsonc` — global policy, applies everywhere.
- `<any directory>/.agent-permissions.jsonc` — at decision time, agentperm merges the global file
  with every policy between the filesystem root and the command's working directory. Rules union
  across levels; `deny` beats `ask` beats `allow` across all of them, so a repo can add its own
  allows but can never weaken your global denies. `agentperm edit --local` creates the current
  repo's root policy.

**Trust note:** a repository you clone can ship a `.agent-permissions.jsonc`, and its `allow`
rules take effect when an agent runs inside it. Review checked-in policy files like you'd review
`.vscode/tasks.json` — see [SECURITY.md](../SECURITY.md) for the full threat model.

## Something's wrong?

`agentperm why` and the [troubleshooting guide](troubleshooting.md) cover the common cases:
still prompting, allowed something it shouldn't have, install did nothing. Removing agentperm is
one command: [`agentperm uninstall`](cli.md#uninstall).

---

Back to the [docs index](README.md).
