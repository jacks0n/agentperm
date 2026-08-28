# Capability matrix

agentperm exposes one policy language, but host hook APIs are not identical. This page states the
actual coverage and enforcement behavior so “supported” never implies false parity.

**Legend:** ✓ fully represented by the current adapter · ◐ supported with the limitation shown · —
not available from that host or adapter.

## Policy coverage

| Capability | Claude Code | Codex CLI | OpenCode | Gemini CLI | Kiro |
|---|---:|---:|---:|---:|---:|
| Structural Shell rules | ✓ `Bash` | ✓ `Bash` | ✓ `bash` | ✓ shell tools | ✓ shell aliases |
| Named and scoped tools | ✓ all hooked tools | ◐ hooked Bash, patch, MCP | ✓ all tools | ✓ all tools | ✓ all tools |
| Scoped `Read` | ✓ | — native Read is not in the installed matcher | ✓ | ✓ | ✓ |
| Semantic `Edit` | ✓ Edit, NotebookEdit | ✓ patch update/delete/move source | ✓ edit and patch | ✓ replace | ◐ every write checks Edit + Write |
| Semantic `Write` | ✓ Write | ✓ patch add/move destination | ✓ write and patch | ✓ write_file | ◐ every write checks Edit + Write |
| Multi-file/move aggregation | — native calls are individual | ✓ | ✓ for patchText | — native calls are individual | — native call has one path |
| `Python(readonly)` for shell calls | ✓ | ✓ | ✓ | ✓ | ✓ |
| Layered policy precedence | ✓ shared engine | ✓ shared engine | ✓ shared engine | ✓ shared engine | ✓ shared engine |
| Native-policy import | ✓ | ✓ | ✓ | — | ✓ |
| Direct installation | ✓ | ✓ | ✓ plugin | ✓ | ✓ |
| Rulesync installation | ✓ | ✓ | — plugin remains direct | ✓ | ◐ mode ignored; direct hooks |

“All tools” means every tool event the host sends to the installed hook. It does not include actions
that bypass the host hook system.

Layered precedence means every Deny remains effective, while the nearest matching Ask/Allow wins;
inside one file, Ask precedes Allow.

`Python(readonly)` is syntax-aware: it parses literal inline Python with the standard-library AST.
There is no equivalent SQL parser; database CLI invocations can use Shell rules, but SQL query text
is not classified as read-only or mutating.

## Enforcement behavior

| Behavior | Claude Code | Codex CLI | OpenCode | Gemini CLI | Kiro |
|---|---|---|---|---|---|
| Hook stage | PreToolUse | PreToolUse + PermissionRequest | tool.execute.before + permission.ask | BeforeTool | PreToolUse |
| Allow | explicit pre-approval | emitted at PermissionRequest | permission hook approves; pre-hook is deny-only | explicit allow | exit 0 / host proceeds |
| Ask | native prompt | falls through to native prompt | falls through to native prompt | host API cannot request approval; blocks with an approval-required reason | exit 2; blocks |
| Deny | pre-execution block | PreToolUse veto; PermissionRequest also denies | pre-execution exception; permission hook also denies | pre-execution block | exit 2; blocks |
| No opinion | native flow | native flow | native flow | native flow | exit 0 / native flow |
| Recognized malformed operation | generic payload defers | unparseable patch denies | unparseable patch denies | generic payload defers | missing shell command asks/blocks |
| Host bypass | Claude `bypassPermissions` makes agentperm defer entirely | none in payload | none in payload | none in payload | none in payload |
| Pane bypass | Ask/NoOpinion → Allow; Deny preserved | same | same | same | same |

Gemini and Kiro cannot preserve the interactive distinction between Ask and Deny through their
current pre-tool hook contracts. The rationale still says whether policy requested approval or
denied the action.

## Semantic file operations

Policies use stable capability names rather than native tool spellings:

| Native operation | agentperm request |
|---|---|
| Claude `Edit` | `Edit(path)` |
| Claude `NotebookEdit` | `Edit(notebook_path)` |
| Claude `Write` | `Write(path)` |
| Codex/OpenCode patch update or delete | `Edit(file_path)` |
| Codex/OpenCode patch add | `Write(file_path)` |
| Codex/OpenCode patch move | source `Edit` + destination `Write` |
| OpenCode `edit` / `write` | `Edit` / `Write` |
| Gemini `replace` / `write_file` | `Edit` / `Write` |
| Kiro `write`, `fs_write`, `fsWrite` | compound `Edit` + `Write` |

Multi-file patches become one compound request. Every child is evaluated and the strictest verdict
wins. A malformed patch that claims to mutate files but cannot be translated becomes a rejected
request and is denied. File paths are resolved from the hook cwd, normalized through `.` and `..`,
and resolved through existing symlinks before scoped rules match.

These capabilities cover native file tools, not writes hidden inside arbitrary shell commands.
Shell redirects are governed separately by `shell.redirection`; programs that write internally must
be constrained by their Shell rules or an external sandbox.

## Installation and import details

- Claude, Codex, and Gemini support direct or Rulesync hook configuration.
- OpenCode always uses `~/.config/opencode/plugins/agentperm.js` because Rulesync has no matching
  plugin schema.
- Kiro installs its custom-agent and standalone hooks directly regardless of selected mode.
- Import is additive and writes only the global agentperm policy. Native files remain unchanged.

Exact payloads and response envelopes are in [adapter notes](adapters.md). Operational paths are in
the [CLI reference](cli.md).
