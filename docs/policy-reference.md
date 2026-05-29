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

Matches a shell segment whose argv matches the whitespace-separated token pattern.

```jsonc
"Bash(ls:*)"          // ls -la, /usr/bin/ls, ls foo bar
"Bash(git status:*)"  // git status, git status --short
"Bash(git status)"    // exact match — only `git status` with no args
```

The trailing `:*` controls whether argv may extend past the pattern: with `:*`, extra args are allowed; without it, argv must match exactly. The rule matches by **basename** on the first arg, so `/usr/bin/ls` and `ls` both match `Bash(ls:*)`.

##### Glob tokens — `*` and `**`

Tokens in the pattern can be globs:

- `*` matches **exactly one** argv token.
- `**` matches **zero or more** argv tokens.

```jsonc
"Bash(pnpm --dir * build:*)"  // pnpm --dir <anything> build [more args]
"Bash(pnpm ** build:*)"       // pnpm with any intermediate flags, then build
"Bash(git * --short:*)"       // git <subcommand> --short ...
```

How matching works in practice:

| Rule                                    | Matches                                                                | Doesn't match                                          |
| --------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------ |
| `Bash(pnpm --dir * build:*)`            | `pnpm --dir foo build`, `pnpm --dir foo build --watch`                 | `pnpm build` (no `--dir`), `pnpm --dir foo bar build`  |
| `Bash(pnpm ** build:*)`                 | `pnpm build`, `pnpm --dir foo build`, `pnpm -r --silent build`         | `pnpm install`                                         |
| `Bash(pnpm --filter * test:*)`          | `pnpm --filter @scope/pkg test`                                        | `pnpm test`, `pnpm --filter @scope/pkg --filter b test`|
| `Bash(docker compose ** up:*)`          | `docker compose up`, `docker compose -f x.yml up -d`                   | `docker run …`                                         |
| `Bash(cargo ** --release:*)`            | `cargo build --release`, `cargo test --workspace --release`            | `cargo check`                                          |

Position counts. `*` is one token, not "any string" — `pnpm --dir foo build` is 4 argv tokens (matches a 4-token rule), but `pnpm --dir=foo build` is 3 argv tokens and won't match `Bash(pnpm --dir * build:*)`. Add a separate rule for the `=` form if your agent uses it (`Bash(pnpm --dir=* build:*)` won't help — `--dir=*` is one literal token, not a prefix glob).

`**` is greedy but backtracks, so `Bash(pnpm ** build:*)` correctly matches `pnpm --dir foo build --watch` even though `--watch` could also be consumed by `**` — the matcher tries every split until one works.

The basename rule applies only when the first token is a **literal** — a `*` or `**` covering position 0 doesn't carry the literal needed for basename comparison. There is no escape syntax for a literal `*` argv token (rare, since shells expand `*` before exec); if you need to match one, use the dict form or contact the maintainer.

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

## Inert command names

Two categories of shell input have no OS-level side effect on their own:

**Control flow and grouping** — the parser traverses these and evaluates the *commands they contain*. The control-flow construct itself is never something to allow or deny:

- `if … then … elif … else … fi`
- `while … do … done`, `until … do … done`
- `for x in …; do … done`, `select x in …; do … done`
- `case x in p) … ;; esac`
- `{ …; }` brace groups
- `( … )` subshells
- `! cmd` negation
- `foo() { … }` function definitions (body evaluated at definition time)

**Inert command names** — these have no OS-level side effect of their own (they cannot create, modify, or read files; cannot fork processes; cannot mutate state visible outside the parsing shell). They split into two groups with different precedence:

| Name | Why inert | Precedence |
|---|---|---|
| `[`, `[[` | Synthetic from `test_command` AST node (both emit `("[",)`) | Allowed *before* user rules — not real commands |
| `((` | Synthetic from arithmetic `compound_statement` | Allowed *before* user rules — not real commands |
| `true`, `false`, `:` | Status setters / no-op | Allowed as a *fallback* — user rules override |
| `read` | Binds shell variable from stdin (process-local) | Allowed as a *fallback* — user rules override |
| `echo`, `printf` | Write to fds; redirects evaluated separately | Allowed as a *fallback* — user rules override |

The **synthetic markers** (`[`, `[[`, `((`) aren't real commands, so a user rule can't target them; they are always allowed. A user rule on a **real builtin** still bites — e.g. `deny: Bash(echo:*)` blocks `echo`, because the inert allow for real builtins is only a fallback used when no rule matches.

What is *not* bypassed for the fallback-allowed builtins:

- **Redirects** are evaluated independently. `echo foo > out.txt` still surfaces an Ask via the redirect rule (write-to-file), because `>` is a side effect even though `echo` isn't.
- **Pipe aggregation** still applies. `echo foo | weird_cmd` still escalates to Ask under "Allow + NoOpinion → Ask" if `weird_cmd` is unrecognised.
- **Anything with real side effects** stays under user rules: `cd`, `export`, `kill`, `source`, etc. are parsed as regular commands and require an explicit `Bash(<name>:*)` rule. Command-introducing wrappers (`bash -c`, `eval`, `command`, `exec`, `env`, `nice`, …) are decomposed to the inner command where possible, so you rule the inner command, not the wrapper; wrappers that can't be safely decomposed prompt under bypass instead of being allowed.

See [Architecture: Inert command names](architecture.md#inert-command-names) for the rationale.

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

### Workspace build commands (using globs)

Whitelist build/test commands across a monorepo without enumerating every package or flag combination:

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [
      // pnpm workspace operations — agent picks the package via --dir or --filter
      "Bash(pnpm --dir * build:*)",
      "Bash(pnpm --dir * test:*)",
      "Bash(pnpm --dir * lint:*)",
      "Bash(pnpm --filter * build:*)",
      "Bash(pnpm --filter * test:*)",

      // any pnpm invocation that ends in `build` or `test` (more permissive)
      "Bash(pnpm ** build:*)",
      "Bash(pnpm ** test:*)",

      // cargo release builds across any workspace shape
      "Bash(cargo ** --release:*)",

      // docker compose subcommands with arbitrary flags
      "Bash(docker compose ** up:*)",
      "Bash(docker compose ** down:*)",
      "Bash(docker compose ** logs:*)"
    ],
    "ask": [
      // package-manager mutations escalate even though they'd otherwise match `pnpm **`
      // (`ask` is checked before `allow`, so these win for `pnpm install`, `pnpm add x`, etc.)
      "Bash(pnpm install:*)", "Bash(pnpm add:*)", "Bash(pnpm remove:*)", "Bash(pnpm update:*)",
      "Bash(npm install:*)",  "Bash(npm i:*)",   "Bash(npm uninstall:*)",
      "Bash(yarn add:*)",     "Bash(yarn remove:*)"
    ]
  }
}
```

`hasOption` (the dict form's `when`) only matches arguments starting with `-`. To gate a *subcommand* like `install`, use a string rule with a literal token instead — as shown above.

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
| `rm $(cat allowed)` (both `rm` and `cat` allowed) | `[Allow, Allow]` | Allow |
| `rm $(curl evil)` (`curl` not allowed) | `[Allow, NoOpinion]` | **Ask** (escalation) |

## Importing native rules

`agentperms import` walks every adapter's native config and merges rules into your `.agent-permissions.jsonc`:

- **Claude Code:** reads `~/.claude/settings.json` and `~/.claude/settings.local.json`, parses `permissions.allow / ask / deny`.
- **Codex CLI:** reads `~/.codex/rules/*.rules`, extracts `prefix_rule(...)` declarations.
- **OpenCode:** reads `~/.config/opencode/opencode.json` (or `.jsonc`), parses `permission` blocks.
- **Gemini CLI:** no import yet — Gemini's policy DSL is regex-only and round-tripping safely needs more work.

Imports are additive: existing rules in the policy file are kept, new rules are appended. Run `import` then `edit` to deduplicate or reorganize.
