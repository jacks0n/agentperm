# Policy reference

Everything the `.agent-permissions.jsonc` format can express. For a guided introduction, start with [getting started](getting-started.md); for ready-made rule sets, see the bundled [templates](../src/agentperm/templates/) (`agentperm init --list`) and the complete setups in [`examples/`](../examples/).

The policy file is JSON-with-comments (JSON5-compatible). Policies can live at:

- `~/.agent-permissions.jsonc` — global policy
- `<any-directory>/.agent-permissions.jsonc` — directory-scoped policy

The global policy is loaded first, followed by every policy from the filesystem root through the
command's working directory. Duplicate paths are loaded once. Deny rules union and always win. Ask
and Allow use nearest-policy precedence: the closest matching layer wins, with Ask before Allow
inside one logical layer. Other override-style settings also prefer layers closer to the working
directory.

## Includes and policy fragments

Any policy file can recursively include other policy files with explicit paths or glob patterns:

```jsonc
{
  "version": 1,
  "include": [
    ".agent-permissions.d/core.jsonc",
    ".agent-permissions.d/aws/*.jsonc",
    ".agent-permissions.d/**/*.local.jsonc"
  ],
  "permissions": {
    "deny": ["Shell(sudo)"]
  }
}
```

Relative entries resolve from the directory containing the file that declares them. Absolute paths
and `~` are also accepted. Glob entries support `*`, `?`, character ranges such as `[0-9]`, and
recursive `**`. Matches are loaded in lexical path order; the entries in `include` retain their
declared order. A path reached more than once within one layer is loaded once, using its resolved
filesystem identity.

Included permissions and the including file form **one logical policy layer**. All Deny, Ask, and
Allow lists union, duplicates are removed, and Ask still precedes Allow across the whole layer. A
split policy therefore decides permissions exactly like the equivalent single file. Override-style
settings are applied depth-first: later include entries override earlier ones, later glob matches
override earlier matches, and the including file overrides all of its includes. `allowPaths` values
union rather than replace.

Includes are fail-safe. An entry that matches no files, an unreadable included file, malformed
`include` data, or an include cycle fails the policy load. In particular, do not use a glob that
also matches the file declaring it. `agentperm validate` follows includes and reports each source
file; `agentperm why` lists every contributing file.

## Top-level shape

```jsonc
{
  "version": 1,
  "include": [ /* optional paths and globs */ ],
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

Within one logical policy layer, including all of its fragments, the lists are evaluated
**deny → ask → allow**. Across directory layers, every Deny is checked first; then Ask and Allow are
checked from the nearest policy back toward the global policy.
The first match wins. Aggregation across compound segments is separate—see
[Architecture](architecture.md#aggregation).

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
python <<'PY'
print("the explicit stdin dash is optional for a literal heredoc")
PY
```

The source is parsed with Python's standard-library AST without being executed. Imports, local
variables, ordinary calls, printing, and inspection are allowed. Recognized filesystem, process,
network, database, environment, attribute, or subscript mutation asks. Syntax errors, dynamic call
targets, shell-expanded heredocs, and unavailable stdin also ask.

This is deliberately shallow and assumes a non-adversarial caller. It tracks import aliases and
direct assignment rebinding such as `f = os.remove`, and visits syntax inside function definitions.
It does not perform interprocedural analysis: calling a user-defined function does not prove or
re-evaluate that function's effects. Hidden effects inside an otherwise ordinary call remain outside
the v1 model. `python -m`, script files, and interactive Python are unaffected.

SQL passed to a database client or Python helper is parsed only when a configured semantic capture
identifies the argument. See [Semantic SQL policies](sql-policy.md).

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

Within one file, precedence is configured `deny` → `ask` → `allow`, then the built-in catalogue,
then the ordinary-call default. Across files, every configured Deny applies; Ask and Allow use the
nearest matching file. An explicit configured Allow can override a built-in unsafe classification.
Structural operations such as attribute assignment are not call targets and cannot be overridden
through `python.calls`.

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

SQL-bearing operands can be marked with `<SQL>`, `<SQL:name>`, `stdin(<SQL...>)`, or
`sqlvalues(<SQL...>,flags...)`. Generic wrapper layouts can mark nested argv with `<EXEC>` or one
literal nested shell program with `<SHELL>`. These captures add semantic evaluation; they do not add
a catalogue of clients, flags, environment variables, or helper functions. See
[Semantic SQL policies](sql-policy.md).

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
"Write(src/*)"                // same mechanism, any tool
"Read(*)"                     // explicit "any input" — identical to bare "Read"
```

- **`domain:<host>`** — matches when a **URL field** of the tool input (`url`, `uri`, `href`) has a host equal to `<host>` or a subdomain of it (`github.com` matches `api.github.com`). Host comparison is case-, trailing-dot-, and IDNA-insensitive (Unicode and punycode forms are equivalent); malformed URLs simply don't match.
- **any other specifier** — a glob matched against the tool's **path fields** (`path`, `file_path`, `paths`, `notebook_path`, `absolute_path`, …). `*` matches within a single path segment; `**` matches across `/` (`Read(/etc/**)` matches `/etc/ssl/cert.pem`, `Write(src/*)` does not match `src/sub/x`).
- **`*` or empty** — matches the tool regardless of input (so `Read(*)` and `Read` are equivalent).

Matching is **keyed by field name**, so a specifier only ever checks the authoritative field — `WebFetch(domain:github.com)` will not be satisfied by a `github.com` URL that happens to appear in a `prompt`, and `Write(src/**)` will not be satisfied by path-like text in `old_string`. Adapters that don't surface those fields only match the name-only forms.

Relative path specifiers are evaluated from the hook's working directory, whether the agent sends
a relative or absolute path. `.`/`..` segments and existing symlinks are resolved before matching,
so a path cannot remain inside a protected glob lexically while resolving outside it.

`Write` is a semantic capability, not a literal host tool name. Every native operation that
creates, overwrites, edits, deletes, or moves a file is evaluated as `Write` on that path:

| Native operation | Semantic request |
|---|---|
| Claude Edit / MultiEdit / Write | `Write` |
| Claude NotebookEdit | `Write` (on `notebook_path`) |
| Codex or OpenCode patch add/update/delete | `Write` |
| Codex or OpenCode patch move | source `Write` + destination `Write` |
| OpenCode edit/write | `Write` |
| Gemini replace/write_file | `Write` |
| Kiro write aliases | `Write` |

Patch operations are collected into one `CompoundRequest`; the strictest file verdict wins. A
mutation patch with an invalid envelope, unknown marker, empty target, invalid move, or no file
operation becomes a rejected request and is denied.

`Edit(...)` is a deprecated alias for `Write(...)`. It still parses and is evaluated as the same
rule, `import` and `init` write it back as `Write(...)`, and `agentperm validate` warns with the
exact replacement. Consequences: an `allow Edit(src/**)` also allows creating files under `src/`;
when a file lists both spellings for one path they are one rule and the first-listed `reason`
wins; a `deny` on either spelling always beats an `allow` on the other.

These rules cover native agent file tools, not writes hidden inside arbitrary shell commands. See
the [capability matrix](capabilities.md#semantic-file-operations) for per-agent coverage.

### Dict rules

#### Rule-as-key dict — per-rule options and reasons

Any rule can carry an optional `reason` by using the rule string as the key and a dict of metadata
as the value. The reason is returned verbatim when the rule fires:

```jsonc
{"Write(generated/**)": {"reason": "Generated file; update its source and rerun the generator."}}
{"Shell(aws ec2 describe-*)": {"values": ["--region", "--profile"]}}
{"Shell(mise exec just synth-env)": {"allowPaths": ["/tmp"]}}
{"Shell(git status)": {"values": ["-C"], "allowPaths": ["/var/log"], "reason": "Safe inspection"}}
```

- `reason` — a non-empty string surfaced as the rationale when the rule fires. It works on named
  tools, `Shell(...)`, `Bash(...)`, and `Python(readonly)` rules.
- `values` — declares which flags consume the next token (same as inline `values(...)`).
- `allowPaths` — directories where file redirects are allowed when this rule matches. See [Redirect allowlisting](#redirect-allowlisting).

The older wrapper form (`{"rule": "Shell(...)"}` with optional `values`, `allowPaths`, or `reason`)
is still parsed but no longer written on save.

A rule-as-key object must contain exactly one rule key. Multi-key objects are rejected rather than
partially parsed, because ignoring a sibling field could hide a policy typo or unsupported option.

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
| `break`, `continue` | Change loop control only in the current shell | Allowed as a *fallback* — user rules override |
| `read` | Binds shell variable from stdin (process-local) | Allowed as a *fallback* — user rules override |
| `export`, `unset` | Change variables/functions only in the current shell | Allowed as a *fallback* — user rules override |
| `echo`, `printf` | Write to fds; redirects evaluated separately | Allowed as a *fallback* — user rules override |

The **synthetic markers** (`[`, `[[`, `((`) aren't real commands, so a user rule can't target them; they are always allowed. A user rule on a **real builtin** still bites — e.g. `deny: Bash(echo:*)` blocks `echo`, because the inert allow for real builtins is only a fallback used when no rule matches.

What is *not* bypassed for the fallback-allowed builtins:

- **Redirects** are evaluated independently. `echo foo > out.txt` still surfaces an Ask via the redirect rule (write-to-file), because `>` is a side effect even though `echo` isn't.
- **Pipe aggregation** still applies. `echo foo | weird_cmd` still escalates to Ask under "Allow + NoOpinion → Ask" if `weird_cmd` is unrecognised.
- **Substitutions** are evaluated independently. `export FOO=$(unknown-command)` still asks even though `export` itself is inert.
- **Anything with real side effects** stays under user rules: `cd`, `kill`, `source`, etc. are parsed as regular commands and require an explicit `Bash(<name>:*)` rule. Statically visible `-c` programs passed to `bash`, `sh`, or `zsh` are decomposed, including safe forms such as `-lc` and `-l -c`; ambiguous option layouts and runtime-selected programs ask. Other command-introducing wrappers (`eval`, `command`, `exec`, `env`, `nice`, …) are decomposed where possible, so you rule the inner command, not the wrapper. Explicit bypass modes have separate semantics described in [SECURITY.md](../SECURITY.md#bypass-surfaces).

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

---

Back to the [docs index](README.md).
