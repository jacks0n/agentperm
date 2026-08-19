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
  },
  "shell": {
    "redirection": { /* optional — see Shell redirects */ }
  },
  "python": {
    "calls": { /* optional — see Inline Python analysis */ }
  }
}
```

agentperm currently writes schema `version: 1`; `Shell(...)` does not introduce version 2 and
there is no automatic Bash-to-Shell schema migration. The loader currently treats `version` as
reserved metadata rather than selecting different rule semantics from it.

The three lists are evaluated in order **deny → ask → allow** for any single rule lookup; the first match wins. (Aggregation across compound segments is separate — see [Architecture](architecture.md#aggregation).)

## Rule forms

A rule is either a **string** or a **dict**. `Shell(...)` is recommended for new shell rules;
legacy `Bash(...)` and structured Bash option rules remain supported. Both syntaxes use policy
schema version `1`.

### String rules

#### `"Python(readonly)"` — shallow inline-Python analysis

`Python(readonly)` is valid only in `permissions.allow`. It recognizes `python`/`python3`
(including path-qualified interpreters) and `uv run python` using `-c` or literal heredoc input:

```jsonc
"Python(readonly)"
```

```sh
python -c "import inspect; print(inspect.signature(len))"
uv run python - <<'PY'
import agentperm
print(type(agentperm), len(agentperm.__all__))
PY
```

The source is parsed with Python's standard-library AST without being executed. Imports, local
variables, ordinary calls, printing, and inspection are allowed. Recognized filesystem, process,
network, database, environment, attribute, or subscript mutation asks. Syntax errors, dynamic call
targets, shell-expanded heredocs, and unavailable stdin also ask.

This is deliberately shallow and assumes a non-adversarial caller. It tracks direct import aliases,
but does not inspect function bodies or follow assignment aliases such as `f = os.remove`. Hidden
effects inside an otherwise ordinary function call are outside the v1 model. `python -m`, script
files, and interactive Python are unaffected.

Call decisions can be customized by exact qualified name:

```jsonc
{
  "python": {
    "calls": {
      "allow": ["project.intentional_mutation"],
      "ask": ["library.ambiguous_operation"],
      "deny": ["dangerous.module.call"]
    }
  }
}
```

Precedence is configured `deny` → `ask` → `allow`, then the built-in catalogue, then the ordinary-call
default. An explicit configured allow can override a built-in unsafe classification. Global and
project call lists union, so a project deny still beats a global allow. Structural operations such as
attribute assignment are not call targets and cannot be overridden through `python.calls`.

Once enabled, the Python result is combined with ordinary shell rules by strictness. This means an
AST Ask cannot be bypassed by a broad `Shell(python -c)` allow, while explicit shell and configured
call denies still win. Redirects and shell substitutions remain independently evaluated.

#### `"Shell(<pattern>)"` — order-independent shell pattern

`Shell` separates the ordered command path from flags, which may appear anywhere. Trailing
operands and unspecified flags are allowed by default:

```jsonc
"Shell(git {status,log,diff,show})"
"Shell(git push !--force)"
"Shell(git stash only(--keep-index, -p))"
"Shell(git status --short !... !-*)"
```

Options using `--flag=value` are recognized automatically. Space-separated option values must be
declared so they can be consumed before matching a later subcommand; undeclared values remain
operands and fail closed for allow rules. Deny and ask rules conservatively explore both possible
interpretations so global options cannot hide a dangerous command path:

```jsonc
"Shell(aws values(--region, --profile) ec2 describe-*)"
{"Shell(aws ec2 describe-*)": {"values": ["--region", "--profile"]}}
```

The two `values` forms have the same matching semantics and only teach normalization which flags
consume the following token; they do not require, permit, or forbid those flags. agentperm does not
need a command-specific option catalogue.

The compact syntax supports positional globs and sets, required/forbidden/permitted flags,
`only(...)`, exact matching, and mid-path gaps. See the complete [Shell pattern DSL](pattern-dsl.md).

#### `"Bash(<command>:*)"` — legacy positional shell matcher

Matches a shell segment whose argv matches the whitespace-separated token pattern. This form is
retained for existing policies and imported native rules; it is not automatically migrated.

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

#### `"<ToolName>(<specifier>)"` — named tool scoped by its input

An optional specifier in parentheses scopes the rule by the tool's input values (URLs, file paths, etc.). The name part still matches as above (exact / `*` / prefix glob); the specifier is then checked against the arguments. This works for any tool, not a fixed list.

```jsonc
"WebFetch(domain:github.com)" // host is github.com or a subdomain (api.github.com)
"Read(/etc/**)"               // a file-path argument matches the glob /etc/**
"Edit(src/*)"                 // same mechanism, any tool
"Read(*)"                     // explicit "any input" — identical to bare "Read"
```

- **`domain:<host>`** — matches when a **URL field** of the tool input (`url`, `uri`, `href`) has a host equal to `<host>` or a subdomain of it (`github.com` matches `api.github.com`). Host comparison is case-, trailing-dot-, and IDNA-insensitive (Unicode and punycode forms are equivalent); malformed URLs simply don't match.
- **any other specifier** — a glob matched against the tool's **path fields** (`path`, `file_path`, `paths`, `notebook_path`, `absolute_path`, …). `*` matches within a single path segment; `**` matches across `/` (`Read(/etc/**)` matches `/etc/ssl/cert.pem`, `Edit(src/*)` does not match `src/sub/x`).
- **`*` or empty** — matches the tool regardless of input (so `Read(*)` and `Read` are equivalent).

Matching is **keyed by field name**, so a specifier only ever checks the authoritative field — `WebFetch(domain:github.com)` will not be satisfied by a `github.com` URL that happens to appear in a `prompt`, and `Edit(src/**)` will not be satisfied by path-like text in `old_string`. Adapters that don't surface those fields only match the name-only forms.

### Dict rules

#### Rule-as-key dict — per-rule options

A Shell rule can carry additional options (`values`, `allowPaths`) by using the rule string as the
key and a dict of options as the value:

```jsonc
{"Shell(aws ec2 describe-*)": {"values": ["--region", "--profile"]}}
{"Shell(mise exec just synth-env)": {"allowPaths": ["/tmp"]}}
{"Shell(git status)": {"values": ["-C"], "allowPaths": ["/var/log"]}}
```

- `values` — declares which flags consume the next token (same as inline `values(...)`).
- `allowPaths` — directories where file redirects are allowed when this rule matches. See [Redirect allowlisting](#redirect-allowlisting).

The older `{"rule": "Shell(...)", "values": [...]}` form is still parsed but no longer written on save.

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
| `continue` | Changes loop control only in the current shell | Allowed as a *fallback* — user rules override |
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
      "Shell({cat,echo,grep,head,ls,rg,tail,wc,which})",
      "Shell(git {status,diff,log,show})",
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

### Workspace build commands

```jsonc
{
  "version": 1,
  "permissions": {
    "allow": [
      "Shell(pnpm run {build,test,lint})",
      "Shell(pnpm {exec,list,why})",
      "Shell(docker compose {build,up,down,logs})",
      "Shell(cargo build)",
      "Shell(cargo test)"
    ],
    "ask": [
      "Shell(pnpm {install,add,remove,update})",
      "Shell(npm {install,uninstall})",
      "Shell(yarn {add,remove})"
    ]
  }
}
```

`ask` is checked before `allow`, so `pnpm install` hits the ask rule even though `pnpm` commands are broadly allowed.

### Hard deny

```jsonc
{
  "version": 1,
  "permissions": {
    "deny": [
      "Shell(sudo)",
      "Shell(su)",
      "Shell(rm -r -f /*)",
      "Shell(chmod)",
      "Shell(chown)"
    ]
  }
}
```

Deny beats every other list. An explicit allow cannot override a deny.
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

## Shell redirects

A redirect's *shape* (which fd, which operator, whether the target is `/dev/null`) is fixed, but the decision each shape produces is configurable via `shell.redirection`:

```jsonc
{
  "version": 1,
  "permissions": { /* ... */ },
  "shell": {
    "redirection": {
      "stderrToDevNull": "allow",
      "stdoutToDevNull": "allow",
      "stdoutToFile": "ask",
      "appendToFile": "ask",
      "allowPaths": ["/tmp", "/private/tmp/claude-*"]
    }
  }
}
```

| Key | Matches | Default |
|---|---|---|
| `stderrToDevNull` | Any write op targeting `/dev/null` with an explicit fd of `2` (`2>/dev/null`, `2>>/dev/null`, …) | `allow` |
| `stdoutToDevNull` | Any write op targeting `/dev/null` *without* an explicit fd `2` — bare `>`/`>>` (defaults to stdout), explicit `1>`, and `&>`/`&>>` (both streams, which has no explicit fd) | `allow` |
| `stdoutToFile` | Truncating writes to anything else: `>`, `&>`, `>\|` | `ask` |
| `appendToFile` | Appending writes to anything else: `>>`, `&>>` | `ask` |

Discarding output is inert no matter which stream or operator carries it, so both devnull keys default to `allow` — including the common `cmd > /dev/null 2>&1` idiom (a `stdoutToDevNull` write plus a no-op fd-dup).

Each value is one of:

- **`allow`** — this redirect shape carries no independent opinion; the segment's own command rule decides (same as if the redirect weren't there at all). This does **not** grant permission by itself — an unmatched or denied command still asks or is denied.
- **`ask`** — force an Ask for any segment with this redirect shape, even if the command itself is allow-listed. This is the default for file writes, since a redirect target can be any path on disk regardless of how safe the command is.
- **`deny`** — force a Deny for any segment with this redirect shape, regardless of the command rule. Useful if you never want an agent writing to files under any circumstances.

Two shapes are **not** configurable, because they never touch the filesystem: fd-duplication (`2>&1`, `1>&2`, …) and input redirection (`<`) always evaluate to no-opinion.

A local (`<project-root>/.agent-permissions.jsonc`) `shell.redirection` block only overrides the keys it sets — an unset key keeps whatever the global file configured.

### Redirect allowlisting

`allowPaths` lets you keep `stdoutToFile: ask` as the safe default while auto-allowing redirects to specific directories:

```jsonc
"shell": {
  "redirection": {
    "stdoutToFile": "ask",
    "allowPaths": ["/tmp", "/private/tmp/claude-*"]
  }
}
```

When a redirect target (`>`, `>>`, `&>`, etc.) resolves to a path under an `allowPaths` entry, the redirect evaluates as `allow` instead of the configured `stdoutToFile`/`appendToFile` decision.

Path matching:

- Both the target and pattern are resolved through symlinks (`os.path.realpath`), so `/tmp` on macOS covers `/private/tmp`.
- Each path component is matched individually with `fnmatch`, so `/private/tmp/claude-*` matches `/private/tmp/claude-502/scratchpad/out.txt`.
- Relative redirect targets are resolved against the working directory from the hook payload.

**Per-rule `allowPaths`** scope path allowlisting to specific commands via the rule-as-key dict form:

```jsonc
"allow": [
  {"Shell(mise exec just synth-env)": {"allowPaths": ["/tmp"]}},
  "Shell(echo)"
]
```

Here `mise exec -- just synth-env > /tmp/out.txt` is allowed, but `echo hi > /tmp/out.txt` still asks (unless `/tmp` is also in the global `allowPaths`). Per-rule paths combine with global paths — if both are set, the union applies when that command matches.

When multiple allow rules match the same command (e.g. a broad `Shell({echo,ls})` and a narrow `Shell(echo)` with `allowPaths`), the `allowPaths` from all matching allow rules are collected. A broader rule matching first doesn't shadow a narrower rule's paths.

## Importing native rules

`agentperm import` walks every adapter's native config and merges rules into your `.agent-permissions.jsonc`:

- **Claude Code:** reads `~/.claude/settings.json` and `~/.claude/settings.local.json`, parses `permissions.allow / ask / deny`.
- **Codex CLI:** reads `~/.codex/rules/*.rules`, extracts `prefix_rule(...)` declarations.
- **OpenCode:** reads `~/.config/opencode/opencode.json` (or `.jsonc`), parses `permission` blocks.
- **Gemini CLI:** no import yet — Gemini's policy DSL is regex-only and round-tripping safely needs more work.
- **Kiro:** reads `~/.kiro/agents/*.json`, importing named tools and simple shell command patterns.

Imports are additive: existing rules in the policy file are kept, new rules are appended in the
form produced by the native adapter. Import does not migrate existing `Bash(...)` rules to
`Shell(...)`. Run `import` then `edit` to deduplicate or reorganize.
