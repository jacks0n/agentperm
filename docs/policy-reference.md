# Policy reference

The policy file is JSON-with-comments (JSON5-compatible). It lives at:

- `~/.agent-permissions.jsonc` — global policy
- `<project-root>/.agent-permissions.jsonc` — per-project override

Both are loaded; rules union, deny wins. Project-root is detected via `git rev-parse --show-toplevel`, falling back to the current working directory.

## Top-level shape

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [ /* rules */ ],
    "ask":   [ /* rules */ ],
    "deny":  [ /* rules */ ]
  }
}
```

`version` is reserved for future schema migrations. Currently only `1` is valid.

The three lists are evaluated in order **deny → ask → allow** for any single rule lookup; the first match wins. (Aggregation across compound segments is separate — see [Architecture](architecture.md#aggregation).)

## Rule forms

A rule is either a **string** (compact form, matches Claude Code's existing syntax) or a **dict** (structured form, more expressive).

### String rules

#### `"Bash(<command>:*)"` — bash command prefix

Matches a shell segment whose argv starts with `<command>`.

```jsonc
"Bash(ls:*)"          // ls -la, /usr/bin/ls, ls foo bar
"Bash(git status:*)"  // git status, git status --short
"Bash(git status)"    // exact match — only `git status` with no args
```

The trailing `:*` is convention; with or without it, the rule matches the prefix. The rule matches by **basename** on the first arg, so `/usr/bin/ls` and `ls` both match `Bash(ls:*)`.

#### `"<ToolName>"` — named tool

Matches a non-Bash tool by name.

```jsonc
"Read"           // exact match
"Grep"           // exact match
"Write"          // exact match
"WebFetch"       // exact match
"*"              // matches every tool name
"mcp__memory__*" // prefix glob — matches mcp__memory__lookup, mcp__memory__store, etc.
```

#### `"WebFetch(domain:<host>)"` — currently a named-tool match

Parsed as `WebFetch(domain:github.com)` and matched against tool name. Future versions may add per-domain matching at the request level; today it's accepted for native-config import compatibility.

### Dict rules

For anything more expressive than a prefix, use the dict form.

#### `BashOption` — bash command + flag

```jsonc
{
  "tool": "Bash",
  "command": ["sed", "gsed"],
  "when": { "hasOption": ["-i", "--in-place"] },
  "reason": "sed in-place editing changes files"
}
```

- `command`: a list of command basenames; the rule matches if argv[0]'s basename is in this list.
- `when.hasOption`: a list of option strings. Matches if **any** arg in argv[1:] equals (or starts with) one of these options. Short flags match combined forms (`-i` matches `-iE`); long flags match `=`-form (`--delete` matches `--delete=true`).
- `reason`: surfaced as the rationale when the rule fires.

⚠️  `--` terminator handling: the matcher does not yet track the POSIX `--` boundary. `sed -e s/x/y/ -- -i` will still match `BashOption(-i)` even though `-i` after `--` is a positional filename. The conservative direction (Ask on `-i`) is correct for a permission policy.

## Examples

### Read-only allow-list

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [
      "Bash(cat:*)", "Bash(echo:*)", "Bash(grep:*)", "Bash(head:*)",
      "Bash(ls:*)", "Bash(pwd)", "Bash(rg:*)", "Bash(tail:*)",
      "Bash(test -f:*)", "Bash(wc:*)", "Bash(which:*)",
      "Bash(git status:*)", "Bash(git diff:*)", "Bash(git log:*)",
      "Read", "Glob", "Grep"
    ]
  }
}
```

### Ask before destructive flags

```jsonc
{
  "version": 1,
  "permissions": {
    "ask": [
      {
        "tool": "Bash",
        "command": ["sed", "gsed"],
        "when": { "hasOption": ["-i", "--in-place"] },
        "reason": "sed in-place edit"
      },
      {
        "tool": "Bash",
        "command": ["rsync"],
        "when": { "hasOption": ["--delete"] },
        "reason": "rsync --delete is destructive"
      },
      {
        "tool": "Bash",
        "command": ["find"],
        "when": { "hasOption": ["-delete", "-exec"] },
        "reason": "find -delete / -exec mutates the filesystem"
      }
    ],
    "allow": [ "Bash(sed:*)", "Bash(rsync:*)", "Bash(find:*)" ]
  }
}
```

`ask` is checked before `allow`, so `sed -i` hits the ask rule and `sed -n 1,10p foo` hits the allow rule.

### Hard deny

```jsonc
{
  "version": 1,
  "permissions": {
    "deny": [
      "Bash(sudo:*)",
      "Bash(su:*)",
      "Bash(rm -rf /*)",
      "Bash(chmod:*)",
      "Bash(chown:*)"
    ]
  }
}
```

Deny beats every other list. Even an explicit `allow` for `Bash(rm:*)` cannot override `deny: Bash(rm -rf /*)`.

## Compound command behavior

Compound shell commands are decomposed into segments and each is evaluated against the policy. The result aggregates per the rules in [Architecture: Aggregation](architecture.md#aggregation):

| Command | Per-segment | Aggregate |
|---|---|---|
| `cat foo` | `[Allow]` | Allow |
| `cat foo | head -60` | `[Allow, Allow]` | Allow |
| `cat foo 2>&1 | head -60` | `[Allow, Allow]` (fd-dup is safe) | Allow |
| `cat foo | weird_thing` | `[Allow, NoOpinion]` | **Ask** (escalation) |
| `echo hi > out.txt` | `[Allow + redirect Ask]` | Ask |
| `rm -rf /tmp; cat foo` | `[Deny, Allow]` | Deny |
| `rm $(cat allowed)` | unparseable | Ask |

## Importing native rules

`agentperms import` walks every adapter's native config and merges rules into your `.agent-permissions.jsonc`:

- **Claude Code:** reads `~/.claude/settings.json` and `~/.claude/settings.local.json`, parses `permissions.allow / ask / deny`.
- **Codex CLI:** reads `~/.codex/rules/*.rules`, extracts `prefix_rule(...)` declarations.
- **OpenCode:** reads `~/.config/opencode/opencode.json` (or `.jsonc`), parses `permission` blocks.
- **Gemini CLI:** no import yet — Gemini's policy DSL is regex-only and round-tripping safely needs more work.

Imports are additive: existing rules in the policy file are kept, new rules are appended. Run `import` then `edit` to deduplicate or reorganize.
