# Troubleshooting

What to check when agentperm prompts too much, too little, or not at all.

## "It still prompts me for X"

Step through these checks in order. Most "still prompting" reports are one of the first three.

### 0. What does the policy actually decide?

Before anything else, ask agentperm directly:

```sh
agentperm why "the exact | command && that prompted"
```

It prints the verdict, a per-segment breakdown, and which policy files were consulted. If `why`
says `allow` but the agent still prompted, the problem is in the hook wiring — continue below.
If `why` says `ask` or `no-opinion`, the rationale tells you which segment needs a rule.

### 1. The agent prompted but the trace is empty

Enable the trace and reproduce:

```sh
export AGENTPERM_TRACE=/tmp/agentperm-trace.log
: > /tmp/agentperm-trace.log
# Now reproduce the prompt in your agent.
cat /tmp/agentperm-trace.log
```

For the env var to reach agentperm from inside the agent's hook, you need to either (a) set it in your shell **before** launching the agent, or (b) edit the hook command in `~/.claude/settings.json` (or equivalent) to prefix the agentperm call with `AGENTPERM_TRACE=/path/to/log`.

The trace contains raw hook payloads and may contain secrets. Use a private file, remove it after
diagnosis, and do not attach an unredacted line to an issue. It has no built-in rotation, retention,
redaction, or tamper protection; see [CLI: diagnostic traces](cli.md#diagnostic-traces).

If the log is empty after a prompt, **the hook wasn't called.** That means:
- The prompt came from the agent's own pre-hook checks (e.g. Claude's "cd outside the working directory" guard), which run before permission hooks and aren't suppressed by bypass mode
- The agent didn't know to call agentperm — re-run `agentperm install`
- The hook was overridden by a different config scope (see "Stale entries" below)

If the log shows the call, look at the verdict and rationale. agentperm's reasoning is right there.

### 2. Stale entries from an older install

Claude Code (and others) load hooks from multiple config scopes and concatenate them, not merge. If you previously installed an older version — or a related tool that registered itself as `claude-agent-bridge` — those entries can survive at project or local scope:

```sh
grep -l "agent-bridge" \
  ~/.claude/settings.json \
  ~/.claude/settings.local.json \
  $(find ~/Code -path '*/.claude/settings*.json' 2>/dev/null) \
  $(find ~/Code -path '*/.rulesync/hooks*' 2>/dev/null)
```

Edit the offending files manually and remove the stale entries. Re-running `agentperm install` only writes to the global scope (`~/.claude/settings.json`).

### 3. "cd outside working directory" guard

Claude Code prompts on any `cd` to a path outside the agent's current working directory, regardless of permission mode. agentperm cannot suppress this — it's a separate workdir-safety check that fires before permission hooks. Either:

- Launch the agent in the directory you want to work in, or
- Use absolute paths instead of `cd`-then-relative-paths

### 4. Bypass mode still prompts / still denies

When Claude Code is in `bypassPermissions` mode, agentperm **defers entirely** — it emits an empty `{}` for every command and lets Claude handle it. It won't prompt and won't deny. If you're still seeing prompts or denials in bypass mode:
- Claude's built-in cwd guard still fires (see above) — that's Claude, not agentperm
- Another hook may be running (Claude concatenates hooks across scopes; see [adapters.md](adapters.md#concatenation-not-merging))
- The installed hook may be stale — confirm `agentperm --version` matches your checkout
- If you *want* deny rules to keep biting while suppressing prompts, use [pane bypass](cli.md#pane-bypass) instead of Claude's `bypassPermissions`

### 5. Compound command escalation

`cat foo | weird_thing` is `Allow + NoOpinion`, which **aggregates to Ask**. This is intentional: if a compound has any unrecognized segment, agentperm surfaces a prompt rather than silently allowing the command. Either add a rule for the unknown segment, or run the segments separately.

`agentperm why "cat foo | weird_thing"` shows exactly this: the known segment allows, the unknown one is `no-opinion`, and the aggregate rationale reads `"compound includes unrecognized segment: no rule matched 'weird_thing'"`.

### 6. Rules on `[ … ]` test predicates aren't taking effect

The synthetic predicate markers (`[`, `[[`, `((`) are parser artifacts, not real commands, so a `Bash([:*)` rule can't gate them — they are always allowed. This is intentional: `[ -f x ]` and `(( 1 + 1 ))` have no OS-level side effect.

Rules on the **real builtins** (`true`, `false`, `:`, `continue`, `read`, `echo`, `printf`) *do* take effect — e.g. `deny: Bash(echo:*)` blocks `echo`. Absent any rule, those builtins fall through to an inert allow (nothing to prompt about on a bare `echo foo`). The side effects around them are still gated regardless: `echo foo > sensitive.txt` surfaces an Ask via the redirect rule, and `echo foo | weird_cmd` escalates to Ask via pipe aggregation if `weird_cmd` is unrecognised.

See [Policy reference: Inert command names](policy-reference.md#inert-command-names) for the full list and rationale.

### 7. The policy file is broken

A parse error in any discovered `.agent-permissions.jsonc` causes agentperm to emit `Ask` for **every command**, with rationale `"policy load failed: ..."` naming the failing file. Lint your policies to find the problem:

```sh
agentperm validate
```

`validate` also catches the quieter failure mode: rules the loader silently skips (a typo like
`"Shel(git status)"` or a malformed dict rule), which don't break anything — they just stop
protecting you. Run it after every hand edit.

## "It allowed something it shouldn't have"

### Is there a stray `allow` rule?

```sh
agentperm why "the command that should have prompted"
```

The rationale names the exact rule that allowed it. Remember that **`deny` beats `allow`** — if you have an `allow: Bash(rm:*)` rule and want to block `rm -rf /tmp`, add a `deny: Bash(rm -rf /*)` rule. Don't remove the allow.

### Did a directory policy widen things?

agentperm loads the global policy and every `.agent-permissions.jsonc` from the filesystem root to
the command's working directory—`agentperm why` lists every file it consulted. Every matching Deny
applies. For Ask and Allow, the nearest matching file wins, so a directory Allow can explain an
unexpectedly silent operation and a directory Ask can narrow a global Allow. A policy file checked
into a cloned repository deserves review like any other tooling config; see
[SECURITY.md](../SECURITY.md).

### Is bypass mode on?

Claude host bypass makes agentperm return NoOpinion for every result, including Deny. Pane bypass is
different: it changes Ask and NoOpinion to Allow while preserving Deny. If a command ran despite a
deny, check which bypass is active and inspect the trace's `coercion` field. See
[Security: bypass surfaces](../SECURITY.md#bypass-surfaces).

## "How do I remove agentperm?"

```sh
agentperm uninstall            # strip hooks from every agent config (preview: --dry-run)
uv tool uninstall agentperm    # or: pipx uninstall agentperm
```

`uninstall` removes exactly what `install` wrote and leaves everything else — including your policy
files — in place. Details per agent: [CLI reference](cli.md#uninstall).

## "Install didn't seem to do anything"

`agentperm install` is idempotent. If the hook was already installed at the same path, it returns without writing. To force a rewrite:

```sh
agentperm uninstall
agentperm install
```

The output of `install` lists each adapter and whether it wrote a file or skipped.

## "Tests fail with Tree-sitter errors"

Tree-sitter Bash parses shell syntax into the `Pipeline` domain model. If you're seeing parser exceptions in the trace, that's expected — `parse_pipeline` catches them and returns `Pipeline(parseable=False)`, which the policy treats as `Ask`. The verdict rationale will include the parse error.

If you're seeing a Python `ImportError` or version conflict for Tree-sitter, check `pyproject.toml` for the pinned `tree-sitter` and `tree-sitter-bash` ranges and reinstall.

## Reporting a bug

Include:

1. The agent and version (`claude --version`, etc.)
2. The exact command that prompted (or didn't)
3. Your `.agent-permissions.jsonc` (redact anything sensitive)
4. The output of `agentperm why "<the command>"`
5. A redacted trace log line for the offending invocation (set `AGENTPERM_TRACE` and reproduce)

Issue tracker: <https://github.com/jacks0n/agentperm/issues>

---

Back to the [docs index](README.md).
