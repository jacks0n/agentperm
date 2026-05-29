# Troubleshooting

## "It still prompts me for X"

Step through these checks in order. Most "still prompting" reports are one of the first three.

### 1. Is the bridge actually being called?

Enable the trace and reproduce:

```sh
export AGENTPERMS_TRACE=/tmp/bridge-trace.log
: > /tmp/bridge-trace.log
# Now reproduce the prompt in your agent.
cat /tmp/bridge-trace.log
```

For the env var to reach the bridge from inside the agent's hook, you need to either (a) set it in your shell **before** launching the agent, or (b) edit the hook command in `~/.claude/settings.json` (or equivalent) to prefix the bridge call with `AGENTPERMS_TRACE=/path/to/log`.

If the log is empty after a prompt, **the bridge wasn't called.** That means:
- The prompt came from the agent's own pre-hook checks (e.g. Claude's "cd outside the working directory" guard), which run before permission hooks and aren't suppressed by bypass mode
- The agent didn't know to call the bridge — re-run `agentperms install`
- The hook was overridden by a different config scope (see "Stale entries" below)

If the log shows the call, look at the verdict and rationale. The bridge's reasoning is right there.

### 2. Stale entries from an older install

Claude Code (and others) load hooks from multiple config scopes and concatenate them, not merge. If you previously installed an older version of the bridge — or a related tool that registered itself as `claude-agent-bridge` — those entries can survive at project or local scope:

```sh
grep -l "agent-bridge" \
  ~/.claude/settings.json \
  ~/.claude/settings.local.json \
  $(find ~/Code -path '*/.claude/settings*.json' 2>/dev/null) \
  $(find ~/Code -path '*/.rulesync/hooks*' 2>/dev/null)
```

Edit the offending files manually and remove the stale entries. Re-running `agentperms install` only writes to the global scope (`~/.claude/settings.json`).

### 3. "cd outside working directory" guard

Claude Code prompts on any `cd` to a path outside the agent's current working directory, regardless of permission mode. The bridge cannot suppress this — it's a separate workdir-safety check that fires before permission hooks. Either:

- Launch the agent in the directory you want to work in, or
- Use absolute paths instead of `cd`-then-relative-paths

### 4. Bypass mode doesn't suppress everything

When Claude Code is in `bypassPermissions` mode, the bridge coerces `Ask → Allow`, but:
- `Deny` still fires (intentional — bypass means "skip prompts", not "skip safety")
- Claude's built-in cwd guard still fires (see above)
- If the bridge wasn't called for that command (see check #1), bypass coercion couldn't help

### 5. Compound command escalation

`cat foo | weird_thing` is `Allow + NoOpinion`, which **aggregates to Ask**. This is intentional: if a compound has any unrecognized segment, the bridge surfaces a prompt rather than silently allowing the command. Either add a rule for the unknown segment, or run the segments separately.

The trace will show the verdict rationale: `"compound includes unrecognized segment: no rule matched 'weird_thing'"`.

### 6. Rules on `[ … ]` test predicates aren't taking effect

The synthetic predicate markers (`[`, `[[`, `((`) are parser artifacts, not real commands, so a `Bash([:*)` rule can't gate them — they are always allowed. This is intentional: `[ -f x ]` and `(( 1 + 1 ))` have no OS-level side effect.

Rules on the **real builtins** (`true`, `false`, `:`, `read`, `echo`, `printf`) *do* take effect — e.g. `deny: Bash(echo:*)` blocks `echo`. Absent any rule, those builtins fall through to an inert allow (nothing to prompt about on a bare `echo foo`). The side effects around them are still gated regardless: `echo foo > sensitive.txt` surfaces an Ask via the redirect rule, and `echo foo | weird_cmd` escalates to Ask via pipe aggregation if `weird_cmd` is unrecognised.

See [Policy reference: Inert command names](policy-reference.md#inert-command-names) for the full list and rationale.

### 7. The policy file is broken

A parse error in `~/.agent-permissions.jsonc` causes the bridge to emit `Ask` with rationale `"policy load failed: ..."`. The agent surfaces this as a prompt with the parse error message — fix the file and re-run.

```sh
agentperms edit
```

## "It allowed something it shouldn't have"

### Is there a stray `allow` rule?

```sh
grep -E '"(Bash\(|allow)' ~/.agent-permissions.jsonc
```

Remember that **`deny` beats `allow`** — if you have an `allow: Bash(rm:*)` rule and want to block `rm -rf /tmp`, add a `deny: Bash(rm -rf /*)` rule. Don't remove the allow.

### Did a project-local override widen things?

```sh
cat <repo>/.agent-permissions.jsonc
```

Project-local rules union with global. To narrow at project level, add `deny` rules — there's no "remove from upstream" form.

### Is bypass mode on?

`Ask` becomes `Allow` under bypass. If you actually want to be prompted for something even in bypass mode, the only way is `Deny` — there's no "Ask wins over bypass" mode.

## "Install didn't seem to do anything"

`agentperms install` is idempotent. If the bridge was already installed at the same path, it returns without writing. To force a rewrite:

```sh
# Edit ~/.claude/settings.json and remove the bridge PreToolUse entry.
# Then re-run install.
agentperms install
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
4. A trace log line for the offending invocation (set `AGENTPERMS_TRACE` and reproduce)

Issue tracker: <https://github.com/jacks0n/agentperms/issues>
