# Architecture

## Premise

Every coding agent (Claude Code, Codex, OpenCode, Gemini CLI, Kiro) has its own permission system. They all do roughly the same job — match a tool call against an allow / ask / deny list — but their grammars differ, none of them parse compound shell commands well, and you end up maintaining separate configs that drift out of sync.

The bridge replaces those configs with one policy file plus a small adapter per agent. Each adapter knows how to install a hook into its agent and how to parse the agent's hook payload into a uniform `Request`. Decision-making and shell parsing live in one place.

## Domain model

The whole system is built on three sum types and a small set of value objects, defined in `src/agentperm/domain.py` and re-exported from `agentperm`.

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
@dataclass(frozen=True) class ShellPattern(Rule): raw, path, flags, value_flags, ...
@dataclass(frozen=True) class NamedTool(Rule): pattern: str
```

`ShellPattern` is the recommended matcher for new shell rules: it matches an ordered operand path
and normalizes flags independently of their position. `BashCommand` remains the legacy positional
matcher used by existing policies and several native import adapters. `BashOption` matches a shell
command invoked with a selected option. `NamedTool` matches by tool name with optional `*`
wildcard or `mcp__memory__*` prefix.

### Policy

`Policy` is `(deny, ask, allow)` plus feature-specific policy objects. Decisions are evaluated in
deny, ask, allow order; the first matching rule wins. Runtime discovery folds the global policy and
every filesystem-ancestor policy through `Policy.merged_with`. Rule-like settings union and
deduplicate; override-style settings are applied from root toward the working directory so the
nearest value wins. Discovery therefore does not need feature-specific logic when `Policy` grows.

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
coerce_for_permission_mode  (defers entirely under Claude bypass → NoOpinion)
       │
       ▼
coerce_for_pane_bypass      (suppresses Ask + NoOpinion under per-pane bypass)
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

| Redirect form | Default verdict |
|---|---|
| `2>&1`, `1>&2` (fd duplication) | `NoOpinion` |
| `2>/dev/null`, `2>>/dev/null` | `NoOpinion` (configurable) |
| `>file`, `>>file`, `&>file` | `Ask` (configurable) |
| `<file` | `NoOpinion` |

File-write verdicts are configurable via `shell.redirection` (`stdoutToFile`, `appendToFile`). `allowPaths` adds directory-level exceptions: if a redirect target resolves (through symlinks) to a path under an `allowPaths` entry, the redirect evaluates as `allow` regardless of the configured default. Paths are set globally on `shell.redirection.allowPaths` and per-rule via the rule-as-key dict form (`{"Shell(cmd)": {"allowPaths": [...]}}`). When evaluating, `allowPaths` from all matching allow rules are combined with the global list.

### Bypass — agentperm defers (Claude-specific)

Claude Code's hook payload includes `permission_mode`. When the user is in `bypassPermissions` mode they've explicitly turned permission checks off — so the bridge gets out of the way entirely:

```python
def coerce_for_permission_mode(verdict, payload):
    if payload.get("permission_mode") == "bypassPermissions":
        return Verdict(Decision.NoOpinion, "bypass: deferring to host")
    return verdict
```

Claude fires `PreToolUse` hooks even in bypass mode, but the bridge returns `NoOpinion` (an empty `{}` envelope) for *everything* — `Ask`, `Allow`, even `Deny` — and lets Claude's native bypass proceed. agentperm does not second-guess a user who has explicitly chosen "skip all permissions." (The Claude write path still attaches any MCP-bypass `updatedInput`, so bypass still propagates to a downstream Codex MCP tool — see below.) If you want `deny` rules to keep biting, don't enable Claude's bypass; use [pane bypass](#pane-bypass-zellij), which *does* preserve `Deny`.

Codex / OpenCode / Gemini don't ship a bypass mode in the hook payload, so this is a no-op there. They get an out-of-band equivalent via [pane bypass](#pane-bypass-zellij) below or [MCP bypass propagation](#mcp-bypass-propagation) when running as a Claude Code MCP server.

### MCP bypass propagation

When Claude Code is in bypass mode and calls a Codex MCP tool (`mcp__codex__*`), the downstream Codex agent's own hooks don't know about Claude Code's bypass state — their payloads carry `"permission_mode": "default"`. The bridge solves this with Claude Code's `updatedInput` hook mechanism: when a PreToolUse hook fires for an `mcp__codex__*` tool in bypass mode, the bridge injects `"approval-policy": "never"` into the tool input. Codex then runs in full-auto mode, so its `PermissionRequest` hooks never fire. `PreToolUse` hooks still fire, so Deny rules still bite for any command the parser can read.

The injection is scoped to `mcp__codex__*` because `approval-policy` is Codex's input contract; other MCP servers don't honour it, so widening the prefix would inject a meaningless key into unrelated tool calls.

```python
def _mcp_bypass_input(payload):
    if payload.get("permission_mode") != "bypassPermissions":
        return None
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.startswith("mcp__codex__"):
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    return {**tool_input, "approval-policy": "never"}
```

This requires no configuration — it activates automatically when the hook detects bypass mode on a Codex MCP tool call.

### Pane bypass (zellij)

For users running an agent inside a [zellij](https://zellij.dev) pane, a separate coercion suppresses prompts on a per-pane basis — independent of the host agent's own bypass flag (if any). The toggle lives in a [WASM plugin](../zellij-plugin/README.md); `agentperm` only reads the flag.

```python
def coerce_for_pane_bypass(verdict, env):
    if verdict.decision not in (Decision.Ask, Decision.NoOpinion):
        return verdict, None
    pane_id = env.get("ZELLIJ_PANE_ID")
    session = env.get("ZELLIJ_SESSION_NAME")
    if not pane_id or not session:
        return verdict, None
    # ...path-traversal sanitization, dir-safety check elided...
    if not (agentperm_bypass_dir(env) / session / pane_id).exists():
        return verdict, None
    coerced = Verdict(Decision.Allow, f"pane bypass: {verdict.rationale}")
    return coerced, Coercion(by="zellij_pane_bypass", ...)
```

Differences from Claude bypass:

- **`Deny` still bites.** Pane bypass is agentperm' own "skip prompts for this pane" toggle, so it suppresses `Ask`/`NoOpinion` but still enforces your deny list — unlike Claude's bypass, where agentperm defers entirely.
- Coerces both `Ask` *and* `NoOpinion`. Codex falls through to its native prompt on the empty `{}` envelope that `NoOpinion` produces, so leaving it alone would defeat bypass for any unknown command.
- Returns a structured `Coercion` record alongside the verdict, recorded in `$AGENTPERM_TRACE` as a top-level `coercion` field. The original verdict is recoverable.
- Reads from the process environment (`os.environ`) rather than the hook payload — works for any adapter, not just Claude.
- Refuses to honor the flag if the bypass directory is group/world-writable or not owned by the current uid, and sanitizes pane id / session against path traversal.

`Deny` still bites. Full operational details (file path, env vars, TOCTOU) are in [docs/cli.md § Pane bypass](cli.md#pane-bypass).

### Inert command names

A small set of shell builtins / synthetic AST tokens have no possible OS-level side effect — they cannot create, modify, or read files; cannot fork processes; cannot mutate state visible outside the parsing shell. They split into two groups:

```
# synthetic markers — emitted by the parser, never real commands
[  [[                  synthetic from test_command (both collapse to "[")
((                     synthetic from arithmetic compound_statement

# real builtins — actual commands with no OS-level side effect
true  false  :         status setters / no-op
continue               loop control in the current shell
read                   binds shell variable from stdin (process-local)
echo  printf           write to fds; redirects evaluated separately
```

`_match_bash` allows the **synthetic markers** *before* user rules are consulted — they aren't real commands, so a user rule can't meaningfully target them. The **real builtins** are allowed only as a *fallback* when no user rule matches, so an explicit `deny` / `ask` / `allow` rule on one of them (e.g. `deny: Bash(echo:*)`) still takes precedence. Redirect verdicts apply per-segment via `_decide_segment`, so `echo foo > out` correctly surfaces an Ask via the redirect rule, and pipe aggregation still escalates `echo foo | unknown` to Ask.

The contract is "nothing the bridge does should turn an inert shell primitive into a permission prompt." Anything with real side effects — `cd`, `export`, `kill`, `eval`, etc. — stays under user rules.

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
- **Redirects:** `>`, `>>`, `<`, `2>`, `2>&1`, `&>`, `>|`, `&>>`, `<&` — captured as `Redirect(fd, op, target, is_fd_dup)`. A process/command-substitution target (`> $(…)`, `< <(…)`) is decomposed: the inner command becomes its own segment, and a write to a runtime-computed name still asks. `<<EOF` heredocs and `<<<` herestrings are dropped (input-only, no file write); substitutions inside them are still extracted
- **Environment prefixes:** `FOO=bar ls -la` — Tree-sitter marks `FOO=bar` as a `variable_assignment` and `_build_segment` skips it
- **`bash -c "..."`:** the inner command is recursively re-parsed via `parse_pipeline`, and its segments replace the wrapper (bundled or split no-arg flags before `-c` are handled: `bash -lc`, `bash -l -c`). A `-c` form we can't safely locate the command in (`bash --norc -c`, `bash -o emacs -c`) returns `Ask` (in normal mode) rather than an opaque allow
- **Exec-prefix wrappers:** `command`, `exec`, `nohup`, `setsid`, `env`, `nice`, `time` are decomposed to their inner command (`env -i FOO=bar git status` → `git status`) so a rule on the real command applies. Wrappers with leading positionals or arg-taking options we don't model (`timeout`, `sudo`, `xargs`, `nice -n N`, …) are left intact and `Ask` in normal mode — an explicit `Bash(<wrapper>:*)` rule still allow-lists them
- **Path-prefixed commands:** `/usr/bin/ls` matches a `Bash(ls:*)` rule via basename

- **Command/process substitutions:** `rm $(cat allowed)`, `cat <(sort file)` — inner commands are recursively extracted as separate segments and evaluated against the policy independently. The substitution-containing argument is dropped from the outer command's argv (its runtime value is unknowable). If all segments (outer command + inner commands) are allowed, the pipeline is allowed; if any inner command is unrecognized or denied, the aggregate verdict escalates accordingly

It refuses to parse:

- **Anything Tree-sitter reports as a shell syntax error:** parse errors → `parseable=False` → `Ask` (in normal mode)

## Limitations

The bridge primarily analyzes shell *command structure*. `Python(readonly)` adds deliberately shallow
AST inspection for literal `python -c` and Python heredoc source, but it does not prove the behavior of
called functions or inspect other interpreted languages:

- **Other interpreters and unsupported Python forms:** `perl -e "…"`, `ruby -e`, `node -e`, `awk 'prog'`, `python -m`, scripts, and interactive stdin remain argv-only. Inline Python is inspected only when an allow-side `Python(readonly)` rule is present.
- **Unrecognized executor prefixes:** the decomposed/​recognized wrapper lists (`command`, `env`, `timeout`, …) are not exhaustive. An executor not on either list (`busybox rm …`, `find . -exec rm …`) is treated as an ordinary command and returns `NoOpinion`.

`NoOpinion` defers to the host agent. Under any **bypass** the bridge defers entirely anyway (Claude bypass → `{}`; pane bypass → `Allow`), so commands the parser can't fully decompose are **not** caught under bypass — bypass means "I accept the risk." In normal mode, an unrecognized executor returns `NoOpinion` (host decides) while a *recognized-but-undecomposable* wrapper returns `Ask`. Treat shell rules and `Python(readonly)` as intent classification, not a security sandbox, and don't rely on bypass as a boundary against a command crafted to evade analysis.

## Why Tree-sitter Bash

The first version of this bridge used a regex-based shell parser. It had real bugs:

- `2>&1` parsed as "write to file `1`" → false positive on file-write detection
- `cat foo 2>&1 | head -60` got the redirect attached to the wrong segment
- `bash -c "ls -la"` was unrecognized
- `FOO=bar ls` matched `FOO=bar` as the command name

Tree-sitter Bash is a maintained Bash grammar. It eliminates the regex parser's shell syntax bugs and supports shell constructs such as `for` loops. The bridge interfaces with it only inside `parse_pipeline` and the parser helpers — domain code never sees raw Tree-sitter `Node` values.

## Module layout

```
src/agentperm/
├── __init__.py           Re-export shim — all public names importable from `agentperm`
├── domain.py             Decision, Verdict, Rule types, Policy engine, Request types
├── shell.py              Tree-sitter Bash → Pipeline (parse_pipeline, segment extraction)
├── shellpattern.py       Shell(...) DSL parser + matcher
├── pythoncode.py         Shallow AST analysis for inline Python (Python(readonly))
├── rules.py              Rule parsing: string/dict → Rule objects
├── policy.py             Policy file I/O (load, save, merge)
├── cli.py                CLI entry point (install, import, check, edit)
├── errors.py             PolicyError exception
├── fileio.py             read_json, atomic_write
└── adapters/
    ├── __init__.py       Adapter registry + select_adapter dispatch
    ├── base.py           AgentAdapter ABC + shared hook-config helpers
    ├── claude.py          Claude Code adapter
    ├── codex.py           Codex CLI adapter
    ├── opencode.py        OpenCode adapter
    ├── gemini.py          Gemini CLI adapter
    └── kiro.py            Kiro CLI / IDE adapter
```

## Type safety

The codebase runs under `basedpyright` strict mode. There is no `Any`. JSON values are typed as `JsonValue` (a recursive union of scalars, `Sequence`, and `Mapping`). `tree-sitter-bash` and `tomlkit` ship partial type information; their boundaries are isolated in `pyproject.toml` and narrowed at the seam. Domain code downstream of those seams sees only typed values.
