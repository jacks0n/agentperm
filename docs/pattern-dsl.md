# Shell pattern DSL — specification

> **Status:** implemented. Defines the grammar, semantics, and matching algorithm for the
> pattern inside `Shell(...)` rules. `Shell` is the recommended syntax for new rules; the
> positional `Bash(...)` matcher remains supported for compatibility with existing policies
> and native agent configuration.

## 1. Overview

The string inside `Shell(<pattern>)` is a compact pattern language for matching a shell
command. It should read like the command it matches, cover the common cases without noise,
and express alternation, required/forbidden flags, flag whitelisting, and value constraints.

It matches **argv shape, not command intent** (see §6). It is an ergonomics and
intent-expression layer, *not* a sandbox.

### Where the DSL sits

`Shell(...)` patterns never match the raw hook string directly. Evaluation has two distinct stages:

```text
shell source
  -> parse and unwrap pipes, chains, substitutions, redirects, and supported wrappers
  -> normalize each command's operands, flags, clusters, and declared flag values
  -> match every command against Shell(...) rules
  -> aggregate extracted commands: deny > ask > allow > no-opinion
```

For example, given these allow rules:

```jsonc
"Shell(aws values(--region, --profile) ec2 describe-* only(--region, --profile))"
"Shell(jq !-*)"
"Shell(git values(-C) status only(-C, --short))"
```

this single hook command:

```sh
bash -lc 'aws --profile dev ec2 describe-instances --region ap-southeast-2 | jq ".Reservations[]" && git -C . status --short'
```

is first reduced to three independently evaluated argv vectors:

```text
aws  --profile dev  ec2 describe-instances  --region ap-southeast-2
jq   .Reservations[]
git  -C .  status  --short
```

The AWS rule also matches `aws ec2 describe-instances --region=ap-southeast-2 --profile dev`:
declared value flags are removed from the positional path wherever they occur, while `only(...)`
rejects every unreviewed flag. If any extracted command is denied, the entire shell program is
denied; if one is unknown, an otherwise allowed compound becomes `Ask`.

The shell constructs handled before DSL matching are specified in
[Architecture: Shell parsing](architecture.md#shell-parsing). The rest of this document specifies
the second stage: normalization and matching of one extracted argv vector.

## 2. Quick start

```jsonc
// allow these git subcommands with operands but no semantic-changing flags
"Shell(git {status,log,diff,show,branch} !-*)"

// allow git push, but deny if --force is present
"Shell(git push !--force)"

// only these flags permitted on git stash — nothing else
"Shell(git stash only(--keep-index, -p))"

// require --output with a .json value
"Shell(curl --output=*.json)"

// optionally pin value-bearing flags when exact arity matters
"Shell(aws values(--region, --profile, --output) ec2 describe-*)"

// exact: only bare `git stash` — no operands, no flags
"Shell(git stash !... !-*)"

// require an explicit end-of-options separator
"Shell(mise exec -- just {check,dev})"
```

## 3. Cookbook

### Read-only git

```jsonc
// any of these subcommands, trailing operands allowed, flags closed
"Shell(git {status,log,diff,show,branch,tag,remote} !-*)"
```

### Read-only GitHub API

Use one rule for the default GET form and one per explicit GET spelling. Payload and custom
header flags are forbidden because they can change request semantics:

```jsonc
"Shell(gh api !{graphql} !{-X,--method,-f,--raw-field,-F,--field,--input,-H,--header})"
"Shell(gh api -X=GET !{-f,--raw-field,-F,--field,--input,-H,--header})"
"Shell(gh api --method=GET !{-f,--raw-field,-F,--field,--input,-H,--header})"
```

The `-X=GET` constraint accepts `-X GET`, `-XGET`, and `-X=GET`. Any repeated method occurrence
must be GET. The default-method rule excludes `graphql`, whose normal transport is not the REST
GET behavior this policy is intended to whitelist.

### Branch-scoped checkout

```jsonc
// only switch onto namespaced branches (in-token glob)
"Shell(git {checkout,switch} {feature,fix}/*)"
```

### Forbid dangerous flags

```jsonc
// deny: any force-push flag, any position
"Shell(git push {--force,--force-with-lease,-f})"

// deny: recursive force rm (both required; clustered -rf normalizes to -r,-f)
"Shell(rm -r -f)"

// allow sed, but never with in-place editing
"Shell(sed !{-i,--in-place})"
```

### Require a flag, forbid another

```jsonc
// require --set-upstream, forbid --force, everything else open
"Shell(git push --set-upstream !--force)"
```

### Whitelist safe flags

Both forms are equivalent — use whichever reads better.

```jsonc
// Sugar form: only these flags, nothing else (operands still open)
"Shell(git stash only(--keep-index, -p))"

// Primitive form: same thing, spelled out
"Shell(git stash ?--keep-index ?-p !-*)"
```

### Exact commands

```jsonc
// ONLY bare `git stash` — no extra operands
"Shell(git stash !...)"

// no extra operands AND no flags
"Shell(git stash !... !-*)"

// exactly `git status --short` (any flag order, nothing else)
"Shell(git status --short !... !-*)"

// rm with no flags: `rm f` yes, `rm -rf f` no (operands still open)
"Shell(rm !-*)"
```

### Value constraints

```jsonc
// matches --output=x.json and --output x.json
"Shell(curl --output=*.json)"
```

### Value-bearing flags (arity hints)

Space-separated option values must be declared before they can be removed from the operand
path. This fail-closed rule prevents an undeclared semantic-changing option from hiding an
arbitrary value before an otherwise allowed subcommand. Use `values(...)` to declare arity:

```jsonc
// explicitly says that --region, --profile, and --output consume the next token
"Shell(aws values(--region, --profile, --output) ec2 describe-*)"
```

All of these match:
- `aws ec2 describe-instances`
- `aws --region us-east-1 ec2 describe-instances`
- `aws ec2 describe-instances --region us-east-1`
- `aws ec2 describe-instances --region=us-east-1`

`values(...)` does not constrain flag *presence* — the flags are not required, forbidden, or
permitted. It only teaches the normalizer about arity. It composes freely with `only(...)`,
flag constraints, and all other terms.

For longer lists of value-bearing flags, the dict form keeps the pattern readable:

```jsonc
{"Shell(aws ec2 describe-*)": {"values": ["--region", "--profile", "--output", "--endpoint-url"]}}
```

Dict `values` merge with any inline `values(...)` in the pattern. Both forms produce the same
matching result — use whichever is cleaner for the number of flags. The dict form is preserved
as a dict when agentperm saves the policy; inline `values(...)` remains a string rule.

`values(...)` is deliberately declarative rather than command-aware. agentperm does not carry a
catalogue of every CLI's option arity, so `Shell(gh values(--repo) pr view)` is required to match
`gh --repo owner/repo pr view`. `--flag=value` never needs an arity declaration.

### Collapsing verbose allow-lists

Before (160+ lines of old syntax):
```jsonc
"Bash(aws ec2 describe-instances:*)",
"Bash(aws ec2 describe-vpcs:*)",
"Bash(aws s3 ls:*)",
"Bash(aws s3api list-buckets:*)",
// ... 150 more
```

After:
```jsonc
"Shell(aws {ec2,s3,s3api,iam,lambda,logs,rds,cloudformation,ssm,sts} {describe-*,get-*,list-*,head-*})"
```

### Allow vs deny precedence

**Allow `git stash list`, not `git stash`** — one rule; the longer path excludes the shorter:
```jsonc
"allow": ["Shell(git stash list)"]
```

**Allow `git stash`, not `git stash list`** — a longer command than you allow is a set
difference → use precedence:
```jsonc
"allow": ["Shell(git stash)"],
"deny":  ["Shell(git stash list)"]
```

## 4. Pattern syntax

A pattern is whitespace-separated **terms**. Terms are classified into **positional terms**
(which match the operand sequence left-to-right) and **flag terms** (which match flags in any
position).

### 4.1 Positional terms

| Syntax | Meaning |
|---|---|
| `git`, `commit`, `*.py`, `feature/*` | Word: literal or `*`-glob matching one operand |
| `{a,b,c}` | Alternation: operand matches any member |
| `.venv/bin/{pytest,ruff}` | Embedded alternation within one operand |
| `!{a,b,c}` | Negated set: operand exists and matches none |
| `...` | Gap: any number of operands (mid-pattern) |
| `!...` | Exact: pattern must consume all operands |

- **`*`** — glob *within one argument* (`fnmatch`). `*.json`, `feature/*`, `--out=*`. A bare
  `*` is just "any one operand." This is the wildcard you normally write.
- **`...`** — *any number of further arguments*. Trailing args are already allowed by default,
  so `...` is only meaningful **mid-pattern** as a gap (`docker ... up`). You rarely write it.
- **`!...`** — asserts that the pattern consumes **every** operand. Without it, extra trailing
  operands are silently allowed (the default). `!...` controls operand exactness only — flags
  are controlled independently by `!-*` and `only(...)` (see §4.2).

### 4.2 Flag terms

| Syntax | Meaning |
|---|---|
| `--flag`, `-x` | Required: flag must be present (anywhere in argv) |
| `!--flag`, `!-x` | Forbidden: flag must be absent |
| `--flag=<glob>` | Required with value: flag present, value matches glob |
| `{--a,--b}` | Any-of: at least one must be present |
| `!{--a,--b}` | None-of: none may be present |
| `only(--a, -b)` | Whitelist (sugar): these flags permitted, nothing else |
| `values(--a, -b)` | Arity hint: these flags consume the next token as a value |
| `?--flag` | Permitted: flag allowed but not required (for whitelists) |
| `!-*` | Closed: no flags beyond required/permitted ones |
| `-*` | Open: any flag allowed (the default; rarely needed) |

#### Flag whitelisting

The most common advanced pattern: allow a command with only specific flags.

**`only(...)` is the recommended form.** It marks each member as permitted and closes the
flag set in one term:

```jsonc
// git stash with only --keep-index and -p; any operands
"Shell(git stash only(--keep-index, -p))"
```

Required flags elsewhere in the pattern are automatically in the permitted set:

```jsonc
// require --message, also permit --keep-index, nothing else
"Shell(git stash push --message only(--keep-index))"
// permitted set = {--message, --keep-index}
```

**The primitive form** uses `?` (permitted) and `!-*` (closed) separately. These compose with
`only(...)` — both contribute to the permitted set:

```jsonc
// equivalent to: only(--keep-index, -p)
"Shell(git stash ?--keep-index ?-p !-*)"
```

`?` on its own (without `!-*` or `only(...)`) is a no-op — it only matters when the flag set
is closed. `only(...)` may appear at most once per pattern.

#### Value-bearing flags

Some flags take a space-separated value (`--region us-east-1`). Their arity must be declared
with `values(...)`; otherwise the following token remains an operand and cannot be skipped to
reach a later command path:

```jsonc
"Shell(aws values(--region, --profile) ec2 describe-*)"
```

`values(...)` only affects arity — it adds atoms to the internal `value_flags` set without
emitting any flag constraint. The declared flags are not required, forbidden, or permitted by
`values(...)` alone. This is orthogonal to all other flag terms:

```jsonc
// arity hint + required constraint + whitelist — all compose
"Shell(curl values(--output) --output=*.json only(--silent, --location))"
```

A flag declared in `values(...)` that also has a `--flag=<glob>` constraint elsewhere in the
pattern is valid — the `=<glob>` form already implies value-flag arity, so the `values(...)`
entry is redundant but harmless.

`values(...)` may appear at most once per pattern. Leading `!` or `?` sigils are invalid.

**Note:** `--flag=value` is always unambiguous. `values(...)` is required only for the
space-separated form.

#### Flag sets

Sets share a disposition across all members:

```jsonc
{--a,--b}     // any-of required (at least one present)
!{--a,--b}    // none-of (none may be present)
```

### 4.3 Escaping

`\` escapes the next character to a literal: `\*` `\{` `\}` `\,` `\!` `\?` `\-` `\\` (and
`\ ` for a literal space inside a token). `\-` at the start of a term forces it to be read as
a positional operand rather than a flag. Because rules live in JSON strings, the backslash is
doubled in the file: `"Shell(echo \\*)"` matches a literal `*`.

### 4.4 Classification rules

A term is classified before anything else:

1. Strip a leading disposition sigil `!` or `?` (only one; `?` is valid only before a flag or
   inside `only(...)`).
2. If the remainder is `...` → **exact** (with `!`) or **rest/gap** term.
3. If the remainder is `-*` → **flag wildcard**.
4. If the remainder is `values(...)` → **arity hint** term. Members are split on `,` and
   trimmed; all must be flags.
5. If the remainder is `only(...)` → **whitelist** term. Members are split on `,` and trimmed.
6. If the remainder starts with `-` **and is longer than one character** (`-x`, `--foo`) →
   **flag** term. A bare `-` (exactly one dash) is a literal **operand** (stdin to many tools).
7. If the remainder is `{ … }` → a **set**. Members are split on `,` and trimmed. The set is a
   **flag set** if *every* member is a flag (per rule 6), a **positional set** if *no* member
   is a flag, and **invalid** if members are mixed.
8. Otherwise → a **positional word**. Embedded `{a,b}` groups expand alternatives within that
   single operand, as in `.venv/bin/{pytest,ruff}` or `{foo,bar}/check`.

`?` is only valid as a flag disposition (`?--foo`, `?{--a,--b}`) or inside `only(...)`. `?`
before a non-flag, `values(...)`, or a bare `?` term, is invalid (§10).

### 4.5 Lexical grammar

- **word** = a non-empty sequence of literal characters, `*` globs, escapes, and embedded
  `{alternative,groups}`. Commas are valid only inside alternation; reserved characters must
  otherwise be escaped.
- **glob** = a word used in a value or operand position; `*` is the only metacharacter
  (`fnmatch`). `?` is **not** a glob char — it is a literal in words/values (it is special
  only as a leading flag disposition). An empty value glob (`--out=`) matches only an empty
  value.
- **flag name** = `-` or `--` followed by one or more of `[A-Za-z0-9_-]`. A standalone
  `--` is instead a positional end-of-options separator.

## 5. Matching semantics

### 5.1 The model in one paragraph

A command's `argv` is split into **operands** (the positional command path) and **flags**
(which float, matched in any position). The pattern's positional terms match the operand
sequence left-to-right; the pattern's flag terms constrain the flag set anywhere. Trailing
operands are **allowed by default**; you opt into exactness with `!...`. Flags are **open by
default**; you opt into closing with `!-*` or `only(...)`.

### 5.2 Operand / flag split, and flag normalization

1. Find the first standalone `--` token in argv. Everything after it is an **operand**. The
   separator itself is normally dropped, but is retained as a positional operand when the pattern
   explicitly contains `--`, allowing that pattern to require the POSIX end-of-options boundary.
2. Before `--`: a token of `-` followed by ≥1 char is a **flag**; a bare `-` and everything
   else are **operands**. Order within each group is preserved.
3. **Declared value flags:** if the pattern declares `--flag=<glob>` or lists `--flag` in
   `values(...)`, the matcher knows `--flag` takes a value, so a following `--flag value`
   token is consumed as the value, not an operand. Both sources contribute to a single
   `value_flags` set.
4. **Unknown option arity:** for allow rules, a non-flag token immediately following an
   undeclared option stays an ordinary operand and is never skipped to find a later command-path
   term. Deny and ask rules conservatively explore both interpretations so an option value cannot
   hide a dangerous path. Declare the flag with `values(...)` for an exact interpretation.
5. **Normalize flags into atoms** so clustering and `=`-values are comparable:
   - `--name` → atom `--name`; `--name=value` → atom `--name` with value `value`.
   - a short cluster `-abc` → atoms `-a`, `-b`, `-c` (POSIX clustering).
   - the result is a set `F` of flag atoms plus a map `V: atom → value` for `=`-form and
     declared value flags.

### 5.3 Positional path matching

The positional terms match the operand list left-to-right:

- **word**: `fnmatch(operand[i], word)`; for `i == 0`, bare executable patterns match the
  basename, while patterns containing `/` match the supplied argv path.
- **`{a,b}`**: `operand[i]` `fnmatch`es some member. **`!{a,b}`**: `operand[i]` **exists**
  and matches no member (a missing operand never satisfies a negation).
- **`...`**: consumes zero or more operands.

`match_path` returns the **set of operand counts it can consume** (a range, because `...`
backtracks). The caller uses this for exactness:

- **default** (no `!...`): match succeeds if *some* consumable count exists and
  ≤ `len(operands)` — extra trailing operands are allowed.
- **exact** (`!...`): match succeeds only if `len(operands)` itself is a consumable count —
  i.e. the path consumes **every** operand. This is what makes `cmd ... target !...` match
  `cmd a b target` but not `cmd a target b`.

### 5.4 Flag matching

Pattern flag terms (over the normalized atoms `F`, values `V`):

- **required** (`--foo` / `-x`): the atom is in `F`. Short flags compare per atom, so `-x`
  matches a `-x` atom produced from `-x`, `-xE`, `-ax`.
- **forbidden** (`!--foo`): the atom is not in `F`.
- **permitted** (`?--foo`, or a member of `only(...)`): declared allowed; imposes nothing on
  its own. Only affects the permitted set when flags are closed.
- **value** (`--out=<glob>`): the atom is in `F` and `fnmatch(V[atom], glob)`.
- **sets**: `{--a,--b}` ≡ require any one; `!{--a,--b}` ≡ none present.

### 5.5 Operand and flag defaults

Two independent knobs, both permissive by default:

| What you write | Operands | Flags |
|---|---|---|
| (nothing) | extra trailing allowed | any flags allowed (open) |
| `!...` | **exact**: path must consume all | any flags allowed (open) |
| `!-*` or `only(...)` | extra trailing allowed | **closed**: only permitted flags |
| `!... !-*` | **exact** | **closed** |

- **`!-*` / `only(...)` (closed flags):** every atom in `F` must be *permitted* — in the
  union of the required, value, and permitted atoms. Any unpermitted flag → no match.
  Forbidden flags (`!--foo`) reject if present regardless of open/closed.
- **`!...` (exact operands):** the positional path must consume every operand. Does **not**
  affect flags — use `!-*` or `only(...)` independently if you also want to close the flag
  set.

### 5.6 Precedence across rules

Within one policy file, `deny` > `ask` > `allow`. Across files, every matching Deny applies; Ask and
Allow are checked from the nearest policy back to the global policy. A project Allow can therefore
whitelist a global Ask, but cannot bypass a Deny. A single pattern cannot express "allow a prefix
*except* one of its extensions" (set difference)—use the deny list (see §3 Cookbook).

### 5.7 Matching algorithm

```
match(pattern, argv) -> bool:
    operands, F, V = split_and_normalize(argv, pattern.value_flags)      # §5.2

    consumable = match_path(pattern.path, operands)                      # §5.3
    if pattern.exact:                                                    # !...
        if len(operands) not in consumable:           return False
    else:
        if not any(c <= len(operands) for c in consumable): return False

    for c in pattern.flag_constraints:                                   # §5.4
        if c.required  and c.atom not in F:            return False
        if c.forbidden and c.atom in F:                return False
        if c.value is not None and not fnmatch(V.get(c.atom, MISSING), c.value):
                                                       return False
    if pattern.closed_flags:                                             # !-* or only(...)
        permitted = {c.atom for c in pattern.flag_constraints if c.disp != Forbidden}
        if any(atom not in permitted for atom in F):   return False
    return True
```

`match_path` backtracks over `*` (consumes 1), `...` (consumes 0+), and word/`{…}` terms
(consume 1 each), returning every total operand-count it can consume so the caller can apply
exactness. Sets and words apply `fnmatch`. Bare executable patterns match `argv[0]` by basename;
path-qualified patterns match the supplied argv path.

## 6. Security model & limitations

agentperm matches **argv shape, not command semantics**. The richer DSL improves
expressiveness and ergonomics; it is **not** a stronger safety boundary.

- **Negation is convenience, not containment.** `git push !--force` doesn't know every
  force-equivalent; `rm !-rf` doesn't know every deletion path. Prefer broad `deny` rules and
  the existing inner-command decomposition.
- **Operand globs are not path confinement.** `*.json` is not "a JSON file under this dir";
  symlinks, `..`, absolute paths, and tool behaviour aren't modeled. Path confinement is a
  future term (§9), not operand-glob sugar.
- **Unknown option arity fails closed for allows.** An allow-side `Shell(git stash)` does not
  match `git -C /repo stash`; use `Shell(git values(-C) stash)` after deliberately reviewing that
  option. Deny/ask rules retain conservative ambiguity so global options cannot hide a dangerous
  path. Open flag sets can still change semantics, so read-only allows should use `!-*` or
  `only(...)`.
- **Short-flag clustering is heuristic** (`-rf` → `-r`,`-f`), not the tool's real parser; some
  tools parse short flags non-POSIX-ly.
- A bare `argv[0]` pattern matches by basename. A pattern containing `/` matches the supplied
  executable path instead, allowing path-qualified rules such as `.venv/bin/{pytest,ruff}`;
  neither form resolves symlinks or proves executable identity.
- **Flags are one flat set per command.** `Shell(git stash only(--message))` permits `--message`
  *anywhere in the `git` invocation*, not specifically on `stash push` — the DSL cannot scope
  a flag to a subcommand level in v1.
- **Interpreters and unrecognized executors** (`python -c`, `make`, git aliases) can act
  without the dangerous command appearing in argv — out of scope, as in `architecture.md`.

## 7. Formal grammar (EBNF)

```
pattern    = term { WS term } ;
term       = positional | flagterm | rest | exact | only | values ;

positional = word | posset ;
word       = wordpart { wordpart } ;                 (* non-empty *)
wordpart   = wordchar | "*" | embedded_set ;
embedded_set = "{" word { "," word } "}" ;         (* expands inside one argv token *)
posset     = [ "!" ] "{" word { "," word } "}" ;     (* all members non-flag *)

flagterm   = [ "!" | "?" ] ( flag [ "=" glob ] | flagset | "-*" ) ;
flag       = ("--" | "-") namechar { namechar } ;    (* len ≥ 1 after dashes *)
flagset    = "{" flag { "," flag } "}" ;             (* all members flags *)

only       = "only(" flag { "," flag } ")" ;         (* sugar: permits + closes *)
values     = "values(" flag { "," flag } ")" ;       (* arity hint: flags consume next token *)

rest       = "..." ;
exact      = "!" "..." ;
```

## 8. Internal representation (for implementation)

```python
# Path terms (positional)
Word(glob: str)                                # literal/glob; argv path when glob contains '/'
OneOf(globs: tuple[str, ...], negated: bool)   # {a,b} / !{a,b}
AnyRest()                                       # ...   (a bare `*` is Word("*"))

class Disposition(Enum): Required; Forbidden; Permitted
FlagConstraint(atom: str, disp: Disposition, value_glob: str | None)
# a flag set expands to one FlagConstraint per member sharing a disposition
# only(...) expands to Permitted FlagConstraints + closed_flags=True

@dataclass(frozen=True)
class ShellPattern(Rule):
    raw: str
    path: tuple[PathTerm, ...]
    flags: tuple[FlagConstraint, ...]
    flag_sets: tuple[tuple[str, ...], ...]
    closed_flags: bool        # !-* or only(...) present
    exact: bool               # !... present (independent of closed_flags)
    value_flags: frozenset[str]  # atoms from values(...) + --flag=<glob> constraints
    extra_values: frozenset[str] # values supplied by the structured dict form
```

String rules serialize as their `Shell(...)` string. A structured rule with external `values`,
`allowPaths`, or `reason` serializes canonically with the rule as the key:

```jsonc
{"Shell(aws ec2 describe-*)": {"values": ["--region"], "reason": "Read-only inventory"}}
```

The legacy `{"rule": "Shell(...)", ...}` input form remains readable, but agentperm does not write
it. `ShellPattern` coexists with the legacy positional `BashCommand` matcher.
`exact` and `closed_flags` are independent booleans — either, both, or neither can be set.

## 9. Out of scope (v1) / future

- **Per-subcommand flag scoping** — separate flag constraints for `git` (global) vs `stash`
  vs `push` in `git stash push --foo`. v1 treats flags as one flat set (§6).
- **Shell-operand path confinement** — an `under:<root>` term that resolves an operand and checks it stays
  under a root (with `..` / symlink handling).
- **Numeric / regex value constraints** on flag values.

The grammar reserves no syntax that blocks these; each is a new term kind that composes
without changing existing patterns.

## 10. Invalid patterns — fail loud

A malformed `Shell(...)` rule must **raise a `PolicyError` at policy load**, never be silently
dropped or reinterpreted as a tool-name rule. Silently dropping a rule is a security bug: a
dropped `deny` becomes a wrong-allow. Invalid cases include:

- unbalanced/empty `{}` or an empty word/member;
- a `{…}` set mixing flag and positional members;
- `?` on a non-flag, or a bare `?`/`!` term;
- a malformed flag name (`---x`, `--` used as a flag);
- a trailing backslash or unknown escape;
- `only(...)` appearing more than once in a pattern;
- `only(...)` with a leading `!` or `?` sigil (`!only(...)`, `?only(...)` — `only` is its own
  term kind, not a flag);
- `only(...)` combined with explicit `-*` (open flag wildcard — contradictory);
- `only(...)` with mixed flag/non-flag members;
- `values(...)` appearing more than once in a pattern;
- `values(...)` with a leading `!` or `?` sigil;
- `values(...)` with non-flag members;
- text that begins `Shell(` but does not close with `)` / does not parse as a pattern.

Only strings that are *not* a `Shell(...)` rule fall through to the named-tool matcher;
anything shaped like `Shell(...)` must parse or error.

## 11. Compatibility with `Bash(...)`

Policy schema version `1` currently accepts both syntaxes:

- Use `Shell(...)` for new rules and for order-independent flags, alternation, constraints, and
  `values(...)` arity hints.
- Existing `Bash(cmd:*)` and exact `Bash(cmd)` rules retain their positional matching semantics
  and serialize unchanged.
- `agentperm import` preserves the form supplied by each native adapter; it does not rewrite the
  existing policy or promise to convert every imported shell rule to `Shell(...)`.

There is currently no automatic schema migration and the policy version remains `1`. If you
choose to convert a legacy rule manually, the closest common mappings are:

| Old syntax | New syntax |
|---|---|
| `Bash(git status:*)` | `Shell(git status)` |
| `Bash(git status)` | `Shell(git status !... !-*)` |
| `Bash(pnpm ** build:*)` | `Shell(pnpm ... build)` |

Review conversions that use `**` carefully: `Bash` matches the raw positional argv shape, while
`Shell` normalizes flags and has open trailing operands and flags by default.

---

Back to the [docs index](README.md).
