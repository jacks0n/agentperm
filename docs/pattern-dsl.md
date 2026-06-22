# Shell pattern DSL — specification

> **Status:** design spec (pending implementation). Defines the grammar, semantics, and
> matching algorithm for the pattern inside `Shell(...)` rules. Supersedes the positional-only
> matcher in `policy-reference.md`, which is rewritten to match once this lands.
>
> **Keyword:** the rule keyword is `Shell`. `Bash` is accepted as a **legacy alias** (Claude
> Code's keyword is `Bash`, so its rules paste and `import` unchanged); both parse to the same
> `ShellPattern`, and the canonical serialized form is `Shell(...)`.

## 1. Goals & scope

The string inside `Shell(<pattern>)` is a compact pattern language for matching a shell
command. It should read like the command it matches, cover the common cases without noise,
and express alternation, required/forbidden/whitelisted flags, and value constraints — while
staying a **superset** of the simple Claude Code forms so `import` keeps working.

It matches **argv shape, not command intent** (see §8). It is an ergonomics and
intent-expression layer, *not* a sandbox. Its verdict is still subject to bypass coercion:
under Claude `bypassPermissions` agentperm defers entirely, and under pane bypass `Ask`/`NoOpinion`
become `Allow` while `Deny` still bites (see `architecture.md`).

## 2. The model in one paragraph

A command's `argv` is split into **operands** (the positional command path) and **flags**
(which float, matched in any position). The pattern's positional terms match the operand
sequence left-to-right; the pattern's flag terms constrain the flag set anywhere. Trailing
arguments are **allowed by default**; you opt into exactness with `!...`. Flags are **open by
default**; you opt into forbidding (`!`) or whitelisting (`?…` + `!-*`).

## 3. Lexical structure

A pattern is whitespace-separated **terms**. There are exactly two wildcards, with distinct
jobs:

- **`*`** — glob *within one argument* (`fnmatch`: any run of characters). `*.json`,
  `feature/*`, `--out=*`. A bare `*` term is just `*` globbing a whole argument, i.e. "any one
  operand." This is the wildcard you normally write.
- **`...`** — *any number of further arguments*. Trailing args are already allowed by default,
  so `...` is only meaningful **mid-pattern** as a gap (`docker ... up`). You rarely write it.

A term is one of:

| Surface | Kind |
|---|---|
| `git`, `commit`, `*.py`, `feature/*` | positional word (literal + `*` glob) |
| `{a,b,c}` | positional alternation (any one) |
| `!{a,b,c}` | negated positional set (operand exists and is none) |
| `...` | mid-pattern gap: any number of operands |
| `!...` | **nothing else**: exact operands + closed flag set (§4.4) |
| `--flag`, `-x` | required flag (present anywhere) |
| `?--flag` | permitted flag (optional; for whitelists) |
| `!--flag` | forbidden flag (absent) |
| `--flag=<glob>` | required flag whose value matches `<glob>` |
| `{--a,--b}`, `!{--a,--b}`, `?{--a,--b}` | flag set (any-of present / none / all permitted) |
| `-*` | flag wildcard ("any flag"); `!-*` = no unpermitted flags |

### 3.1 Classification

A term is classified before anything else:

1. Strip a leading disposition sigil `!` or `?` (only one; `?` is valid only before a flag).
2. If the remainder is `...` → **rest/exact** term.
3. If the remainder is `-*` → **flag wildcard**.
4. If the remainder starts with `-` **and is longer than one character** (`-x`, `--foo`) → **flag** term.
   A bare `-` (exactly one dash) is a literal **operand** (it is stdin to many tools).
5. If the remainder is `{ … }` → a **set**. Members are split on `,` and trimmed of surrounding
   whitespace. The set is a **flag set** if *every* member is a flag (per rule 4), a
   **positional set** if *no* member is a flag, and **invalid** (→ §11) if members are mixed.
6. Otherwise → a **positional word**.

`?` is only valid as a flag disposition (`?--foo`, `?{--a,--b}`); `?` before a non-flag, or a
bare `?` term, is invalid (§11).

### 3.2 Lexical grammar of a word / flag

- **word** = a maximal run of `wordchar`, where `wordchar` is any character except
  unescaped whitespace and the metacharacters `* { } , ! ? \`. An unescaped `*` inside a word
  is the glob; all other `wordchar`s are literal. A word must be non-empty.
- **glob** = a word used in a value or operand position; `*` is the only metacharacter
  (`fnmatch`). `?` is **not** a glob char here — it is a literal in words/values (it is special
  only as a leading flag disposition). An empty value glob (`--out=`) matches only an empty value.
- **flag name** = `-` or `--` followed by one or more of `[A-Za-z0-9_-]`.

### 3.3 Escaping

`\` escapes the next character to a literal: `\*` `\{` `\}` `\,` `\!` `\?` `\-` `\\` (and `\ `
for a literal space inside a token). `\-` at the start of a term forces it to be read as a
positional operand rather than a flag. Because rules live in JSON strings, the backslash is
doubled in the file: `"Shell(echo \\*)"` matches a literal `*`.

### 3.4 Grammar (EBNF)

```
pattern    = term { WS term } ;
term       = positional | flagterm | rest | exact ;

positional = word | posset ;
word       = wordchar { wordchar } ;                 (* '*' = glob; non-empty *)
posset     = [ "!" ] "{" word { "," word } "}" ;     (* all members non-flag *)

flagterm   = [ "!" | "?" ] ( flag [ "=" glob ] | flagset | "-*" ) ;
flag       = ("--" | "-") namechar { namechar } ;    (* len ≥ 1 after dashes *)
flagset    = "{" flag { "," flag } "}" ;             (* all members flags *)

rest       = "..." ;
exact      = "!" "..." ;
```

`:*` (trailing) and `**` (any tokens) are accepted as **legacy aliases** for Claude
compatibility: `:*` ≡ the default trailing behaviour, `**` ≡ `...`.

## 4. Semantics

### 4.1 Operand / flag split, and flag normalization

1. Find the first standalone `--` token in argv. Everything at/after it is an **operand**
   (the `--` itself is dropped) — the POSIX end-of-options boundary.
2. Before `--`: a token of `-` followed by ≥1 char is a **flag**; a bare `-` and everything
   else are **operands**. Order within each group is preserved.
3. **Declared value flags:** if the pattern declares `--flag=<glob>`, the matcher knows
   `--flag` takes a value, so a following `--flag value` token is consumed as the value, not an
   operand. (Undeclared space-separated values are not knowable — see §8.)
4. **Normalize flags into atoms** so clustering and `=`-values are comparable:
   - `--name` → atom `--name`; `--name=value` → atom `--name` with value `value`.
   - a short cluster `-abc` → atoms `-a`, `-b`, `-c` (POSIX clustering).
   - the result is a set `F` of flag atoms plus a map `V: atom → value` for `=`-form and
     declared value flags.

### 4.2 Positional path

The positional terms match the operand list left-to-right:

- **word**: `fnmatch(operand[i], word)`; for `i == 0`, match against `basename(operand[0])`.
- **`{a,b}`**: `operand[i]` `fnmatch`es some member. **`!{a,b}`**: `operand[i]` **exists** and
  matches no member (a missing operand never satisfies a negation).
- **`...`**: consumes zero or more operands.

`match_path` returns the **set of operand counts it can consume** (a range, because `...`
backtracks). The caller uses this for exactness:

- **default** (no `!...`): match succeeds if *some* consumable count exists and ≤ `len(operands)`
  — extra trailing operands are allowed.
- **exact** (`!...`): match succeeds only if `len(operands)` itself is a consumable count — i.e.
  the path consumes **every** operand. This is what makes `cmd ... target !...` match
  `cmd a b target` but not `cmd a target b`.

### 4.3 Flags

Pattern flag terms (over the normalized atoms `F`, values `V`):

- **required** (`--foo` / `-x`): the atom is in `F`. Short flags compare per atom, so `-x`
  matches a `-x` atom produced from `-x`, `-xE`, `-ax`.
- **forbidden** (`!--foo`): the atom is not in `F`.
- **permitted** (`?--foo`): declared allowed; imposes nothing on its own (only affects closure).
- **value** (`--out=<glob>`): the atom is in `F` and `fnmatch(V[atom], glob)`.
- **sets**: `{--a,--b}` ≡ require any one; `!{--a,--b}` ≡ none present; `?{--a,--b}` ≡ permit all.

### 4.4 Trailing default, `!...`, and flag closure

Two independent knobs, both permissive by default:

| Pattern | operands | flags |
|---|---|---|
| (default) | extra trailing allowed | unnamed flags allowed (open) |
| `!-*` | extra trailing allowed | **closed**: only *permitted* atoms allowed |
| `!...` | **exact**: path consumes all operands | **closed** |

- **`!-*` (closed flags):** every atom in `F` must be *permitted* — in the union of the
  required, value, and `?`-permitted atoms. Any other flag → no match. (`!--foo` forbidden flags
  reject if present whether open or closed.)
- **`!...` (nothing else):** asserts **no unmatched operands and no unpermitted flags** — it is
  exact-operands *plus* closed-flags. So `Shell(git status --short !...)` matches `git status
  --short` (and `git --short status`) but not `git status --short --verbose` (extra flag) or
  `git status --short x` (extra operand). `Shell(git stash !...)` matches only bare `git stash`.

A **whitelist** is `!-*` with carve-outs: `Shell(git stash ?--keep-index ?-p !-*)` = "git stash,
only the flags `--keep-index`/`-p` permitted, any operands."

`-*` written without `!` is the explicit form of the open default (rarely needed).

### 4.5 Precedence across rules

Unchanged: `deny` > `ask` > `allow`. A single positional pattern cannot express "allow a prefix
*except* one of its extensions" (set difference) — use the deny list (see §6).

## 5. Matching algorithm

```
match(pattern, argv) -> bool:
    operands, F, V = split_and_normalize(argv, pattern.value_flags)      # §4.1

    consumable = match_path(pattern.path, operands)                      # §4.2 -> set[int]
    if pattern.exact:                                                    # !...
        if len(operands) not in consumable:           return False
    else:
        if not any(c <= len(operands) for c in consumable): return False

    for c in pattern.flag_constraints:                                   # §4.3
        if c.required  and c.atom not in F:            return False
        if c.forbidden and c.atom in F:                return False
        if c.value is not None and not fnmatch(V.get(c.atom, MISSING), c.value):
                                                       return False
    if pattern.closed:                                                   # !-* or !...
        permitted = {c.atom for c in pattern.flag_constraints if c.disp != Forbidden}
        if any(atom not in permitted for atom in F):   return False
    return True
```

`match_path` backtracks over `*` (consumes 1), `...` (consumes 0+), and word/`{…}` terms
(consume 1 each), returning every total operand-count it can consume so the caller can apply
exactness. Sets and words apply `fnmatch`; `argv[0]` is matched by basename.

## 6. Cookbook

```jsonc
// read-only-ish git: any of these subcommands, any args (trailing is the default)
"Shell(git {status,log,diff,show,branch,tag})"

// only switch onto namespaced branches (in-token glob)
"Shell(git {checkout,switch} {feature,fix}/*)"

// sed, any args EXCEPT in-place (a forbidden FLAG set — members are dashed)
"Shell(sed !{-i,--in-place})"

// require a flag, forbid another, rest open
"Shell(git push --set-upstream !--force)"

// deny: force-push (any force flag, any position) — deny wins over a broad allow
"Shell(git push {--force,--force-with-lease,-f})"

// deny: recursive force rm (both required; clustered -rf normalizes to -r,-f)
"Shell(rm -r -f)"

// whitelist: only these flags permitted, nothing else (operands still open)
"Shell(git stash ?--keep-index ?-p !-*)"

// value constraint (matches --output=x.json and --output x.json)
"Shell(curl --output=*.json)"

// lock-downs
"Shell(git stash !...)"       // ONLY bare `git stash` — no extra operands, no flags
"Shell(rm !-*)"               // rm with no flags: `rm f` yes, `rm -rf` no (operands open)
"Shell(git status --short !...)"  // exactly `git status --short` (in any flag order)
```

**Allow `git stash list`, not `git stash`** — one rule; the longer path excludes the shorter:
```jsonc
"allow": ["Shell(git stash list)"]
```

**Allow `git stash`, not `git stash list`** — forbidding a *longer* command than you allow is a
set difference → use precedence:
```jsonc
"allow": ["Shell(git stash)"],
"deny":  ["Shell(git stash list)"]
```

## 7. Compatibility

- Plain positional patterns (`Shell(ls)`, `Shell(git status)`) parse as before; the only change
  is the permissive trailing default (§4.4).
- **`Bash(...)` is accepted as a legacy alias** for `Shell(...)` (Claude's keyword), so existing
  policies and pasted Claude rules keep working. `:*` and `**` are likewise legacy aliases.
- **`import` is one-way faithful (Claude → agentperm).** Claude is exact-by-default and uses the
  `Bash` keyword, so its `Bash(git status)` is written into the agentperm policy as
  `Shell(git status !...)`, and its `Bash(git status:*)` becomes `Shell(git status)`. The stored
  agentperm policy is then unambiguous and canonical — `Shell(x)` always means the permissive
  default; imported exact rules carry `!...`. The reverse (exporting agentperm patterns back to
  Claude) is **lossy/unsupported**: flag predicates, sets, negation, value globs, and in-token
  globs have no Claude equivalent.
- A *dashed* token in a pattern is a flag matched anywhere, not a strict-position token — the one
  intentional divergence from Claude (it widens flag matches, which is the usual intent).

## 8. Security model & limitations

agentperm matches **argv shape, not command semantics**. The richer DSL improves expressiveness
and ergonomics; it is **not** a stronger safety boundary.

- **Negation is convenience, not containment.** `git push !--force` doesn't know every
  force-equivalent; `rm !-rf` doesn't know every deletion path. Prefer broad `deny` rules and the
  existing inner-command decomposition.
- **Operand globs are not path confinement.** `*.json` is not "a JSON file under this dir";
  symlinks, `..`, absolute paths, and tool behaviour aren't modeled. Path confinement is a future
  term (§10), not operand-glob sugar.
- **Space-separated flag values can be misread.** `git -C /repo stash` counts `/repo` as an
  operand, so `Shell(git stash)` may miss it; and adding `--out=<glob>` *changes* operand
  classification because the matcher then consumes that value. This fails *closed* for `allow`
  (→ prompt), but is an under-block for `deny`. Use `=`-form values or flag predicates.
- **Short-flag clustering is heuristic** (`-rf` → `-r`,`-f`), not the tool's real parser; some
  tools parse short flags non-POSIX-ly.
- **basename matching** of `argv[0]` is name identity, not path/executable identity.
- **Flags are one flat set per command** (§10). `Shell(git stash ?--message !-*)` permits
  `--message` *anywhere in the `git` invocation*, not specifically on `stash push` — the DSL
  cannot scope a flag to a subcommand level in v1.
- **Interpreters and unrecognized executors** (`python -c`, `make`, git aliases) can act without
  the dangerous command appearing in argv — out of scope, as in `architecture.md`.
- **Under bypass these results may not apply:** Claude bypass defers entirely; pane bypass turns
  `Ask`/`NoOpinion` into `Allow` (only `Deny` survives).

## 9. Internal representation (for implementation)

```python
# Path terms (positional)
Word(glob: str)                                # literal/glob token; basename at index 0
OneOf(globs: tuple[str, ...], negated: bool)   # {a,b} / !{a,b}
AnyRest()                                       # ...   (a bare `*` is Word("*"))

class Disposition(Enum): Required; Forbidden; Permitted
FlagConstraint(atom: str, disp: Disposition, value_glob: str | None)
# a flag set expands to one FlagConstraint per member sharing a disposition

@dataclass(frozen=True)
class ShellPattern(Rule):
    path: tuple[PathTerm, ...]
    flags: tuple[FlagConstraint, ...]
    closed_flags: bool        # !-* OR !... present
    exact: bool               # !... present (implies closed_flags + path consumes all operands)
    # serialize() round-trips to the canonical Shell(...) string
```

`ShellPattern` replaces the current string-form positional matcher (`BashCommand`). The dict
form stays for import compatibility (and is now expressible inline) — its `tool` field is
canonically `"Shell"`, with `"Bash"` accepted as an alias. Illegal states are unrepresentable: a
`FlagConstraint` is never positional, a `PathTerm` never carries a disposition, and `exact ⇒
closed_flags`.

## 10. Out of scope (v1) / future

- **Per-subcommand flag scoping** — separate flag constraints for `git` (global) vs `stash` vs
  `push` in `git stash push --foo`. v1 treats flags as one flat set (§8).
- **Path confinement** — an `under:<root>` term that resolves an operand and checks it stays
  under a root (with `..` / symlink handling).
- **Numeric / regex value constraints** on flag values.

The grammar reserves no syntax that blocks these; each is a new term kind that composes without
changing existing patterns.

## 11. Invalid patterns — fail loud

A malformed `Shell(...)` rule must **raise a `PolicyError` at policy load**, never be silently
dropped or reinterpreted as a tool-name rule. Silently dropping a rule is a security bug: a
dropped `deny` becomes a wrong-allow. Invalid cases include:

- unbalanced/empty `{}` or an empty word/member;
- a `{…}` set mixing flag and positional members (§3.1);
- `?` on a non-flag, or a bare `?`/`!` term;
- a malformed flag name (`-`, `---x`, `--`);
- a trailing backslash or unknown escape;
- text that begins `Shell(` but does not close with `)` / does not parse as a pattern.

Only strings that are *not* a `Shell(...)` rule fall through to the named-tool matcher; anything
shaped like `Shell(...)` must parse or error.
