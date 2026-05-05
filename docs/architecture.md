# Architecture

## Premise

Every coding agent (Claude Code, Codex, OpenCode, Gemini) has its own permission system. They all do roughly the same job — match a tool call against an allow / ask / deny list — but their grammars differ, none of them parse compound shell commands well, and you end up maintaining four configs that drift out of sync.

The bridge replaces "four configs" with "one policy file plus four small adapters." Each adapter knows how to install a hook into its agent and how to parse the agent's hook payload into a uniform `Request`. Decision-making and shell parsing live in one place.

## Domain model

The whole system is built on three sum types and a small set of value objects, all defined in `src/agentperms/__init__.py`.

### Decision

```python
class Decision(StrEnum):
    Allow = "allow"
    Ask = "ask"
    Deny = "deny"
    NoOpinion = "no-opinion"
```

A `Verdict` is a `Decision` plus a human-readable rationale. `NoOpinion` means "the policy doesn't speak to this" — the bridge returns an empty payload and the host agent falls back to its native permission flow.

Strictness ordering: `Deny > Ask > Allow > NoOpinion`. The strictest verdict wins when aggregating per-segment results.

### Request

```python
class Request: ...
@dataclass(frozen=True) class ShellRequest(Request): pipeline: Pipeline
@dataclass(frozen=True) class ToolRequest(Request): tool: str
```

Every adapter parses its native hook payload into one of these two types. `ShellRequest` carries a parsed `Pipeline`; `ToolRequest` carries the tool name (e.g. `"Read"`, `"WebFetch"`, `"mcp__memory__lookup"`).

### Rule

```python
class Rule(ABC): ...
@dataclass(frozen=True) class BashCommand(Rule): prefix: tuple[str, ...]
@dataclass(frozen=True) class BashOption(Rule): commands, options, rationale
@dataclass(frozen=True) class NamedTool(Rule): pattern: str
```

`BashCommand("git status:*")` matches a shell segment whose argv starts with `("git", "status")`. `BashOption(commands={"sed"}, options={"-i"})` matches `sed` invoked with `-i` (or `-iE`, or `--in-place=true`). `NamedTool` matches by tool name with optional `*` wildcard or `mcp__memory__*` prefix.

### Policy

`Policy` is `(deny, ask, allow)` — three immutable tuples of `Rule`. Decisions are evaluated in that order; the first matching rule wins. Two policies merge by taking the union of each list (deduplicated by structural equality) — that's how `~/.agent-permissions.jsonc` and a project-local override combine.

## Decision flow

```
agent hook payload
       │
       ▼
adapter.parse_event   →  Request | None
       │
       ▼
policy.decide(request)
       │
       ▼  (per-segment for ShellRequest)
aggregate(verdicts)   →  Verdict
       │
       ▼
coerce_for_permission_mode  (suppresses Ask under Claude bypass)
       │
       ▼
adapter.write_verdict (agent-specific JSON envelope)
```

### Aggregation

For a compound like `cat foo | head -60`, the bridge produces a `Verdict` per segment and aggregates:

- **Strictest wins.** `Deny` from any segment beats everything.
- **Allow + NoOpinion → Ask.** If at least one segment is allowed but another is unrecognized, the result escalates to `Ask`. This is the rule that prevents "I have a rule for `cat`" from silently allowing `cat foo | unknown_command`.
- **All Allow → Allow.** Every segment matched an allow rule.
- **All NoOpinion → NoOpinion.** No rule speaks; the host's native flow takes over.

### Redirect policy

Redirects are evaluated independently of argv:

| Redirect form | Verdict |
|---|---|
| `2>&1`, `1>&2` (fd duplication) | `NoOpinion` |
| `2>/dev/null`, `2>>/dev/null` | `NoOpinion` |
| `>file`, `>>file`, `&>file` | `Ask` ("writes to '<file>'") |
| `<file` | `NoOpinion` |

This is hard-coded — file writes always surface a prompt regardless of the surrounding rule. The earlier regex parser misread `2>&1` as a write to a file called `1`; the Tree-sitter Bash AST gets it right.

### Bypass coercion (Claude-specific)

Claude Code's hook payload includes `permission_mode`. When the user is in `bypassPermissions` mode they've explicitly opted out of prompts. The bridge respects that:

```python
def coerce_for_permission_mode(verdict, payload):
    if payload.get("permission_mode") != "bypassPermissions":
        return verdict
    if verdict.decision is Decision.Ask:
        return Verdict(Decision.Allow, f"bypass mode: {verdict.rationale}")
    return verdict
```

`Ask` becomes `Allow`. `Deny` still bites — bypass means "skip the prompt", not "skip safety." `NoOpinion` is left alone so Claude's native fallthrough takes over.

Codex / OpenCode / Gemini don't ship a bypass equivalent in the hook payload, so the coercion is a no-op there.

## Shell parsing

Shell parsing lives in one function: `parse_pipeline(command: str) -> Pipeline`. It hands the string to Tree-sitter's Bash grammar and walks the AST to extract `Segment(argv, redirects)` tuples. The parser handles:

- **Pipes:** `a | b` → two segments
- **Sequences:** `a; b`, `a && b`, `a || b` → multiple segments, each evaluated independently
- **Conditionals:** `if … then … elif … else … fi` → condition + each branch's commands
- **Loops:** `for`, `select`, `while`, `until` → body commands plus the `while`/`until` condition
- **Case:** `case x in p) … ;; esac` → each case-item's body
- **Brace groups & subshells:** `{ … ; }` and `( … )` → recurse into the body
- **Negation:** `! cmd` → recurses into the wrapped command
- **Function definitions:** `foo() { … }` → body recursed at definition time so policy applies even before `foo` is invoked
- **Test / arithmetic:** `[ … ]`, `[[ … ]]`, `(( … ))` → collapsed to synthetic inert segments (`("[",)` / `("((",)`); see "Inert command names" below
- **Declarations:** `export FOO=bar`, `local`, `declare`, `readonly`, `typeset` → yielded as a normal segment with the keyword as argv[0] so `Bash(export:*)` rules match
- **Redirects:** `>`, `>>`, `<`, `2>`, `2>&1`, `&>` — captured as `Redirect(fd, op, target, is_fd_dup)`. `<<EOF` heredocs are dropped (input-only, no file write)
- **Environment prefixes:** `FOO=bar ls -la` — Tree-sitter marks `FOO=bar` as a `variable_assignment` and `_build_segment` skips it
- **`bash -c "..."`:** the inner command is recursively re-parsed via `parse_pipeline`, and its segments replace the wrapper
- **Path-prefixed commands:** `/usr/bin/ls` matches a `Bash(ls:*)` rule via basename

It refuses to parse:

- **Command substitution:** `rm $(cat allowed)` — returns `parseable=False`, which the policy treats as `Ask`
- **Anything Tree-sitter reports as a shell syntax error:** parse errors → `parseable=False` → `Ask`

This is conservative on purpose. A static allow-list cannot reason about runtime command substitution; the right behavior is to surface a prompt rather than guess.

## Why Tree-sitter Bash

The first version of this bridge used a regex-based shell parser. It had real bugs:

- `2>&1` parsed as "write to file `1`" → false positive on file-write detection
- `cat foo 2>&1 | head -60` got the redirect attached to the wrong segment
- `bash -c "ls -la"` was unrecognized
- `FOO=bar ls` matched `FOO=bar` as the command name

Tree-sitter Bash is a maintained Bash grammar. It eliminates the regex parser's shell syntax bugs and supports shell constructs such as `for` loops. The bridge interfaces with it only inside `parse_pipeline` and the parser helpers — domain code never sees raw Tree-sitter `Node` values.

## Module layout

```
src/agentperms/__init__.py
├── JSON value model (system-boundary types)
├── Domain (Decision, Verdict, Rule, Request, Policy)
├── Aggregation (_stricter, aggregate)
├── Redirect policy (_evaluate_redirect)
├── Shell parser (parse_pipeline + Tree-sitter Bash boundary helpers)
├── Rule I/O (parse_rule, _parse_string_rule, _parse_dict_rule)
├── Policy I/O (load_policy_file, save_policy_file, merged_policy)
├── Agent adapters (Claude, Codex, OpenCode, Gemini)
├── Hook config helpers
└── CLI (install, import, check, edit)
```

The whole package is a single module on purpose — it's small enough that splitting it into files would obscure the data flow more than it would reveal structure.

## Type safety

The codebase runs under `basedpyright` strict mode. There is no `Any`. JSON values are typed as `JsonValue` (a recursive union of scalars, `Sequence`, and `Mapping`). `tree-sitter-bash` and `tomlkit` ship partial type information; their boundaries are isolated in `pyproject.toml` and narrowed at the seam. Domain code downstream of those seams sees only typed values.
