# Capability matrix

agentperm exposes one policy language, but host hook APIs are not identical. This page states the
actual coverage and enforcement behavior so “supported” never implies false parity.

**Legend:** ✓ fully represented by the current adapter · ◐ supported with the limitation shown · —
not available from that host or adapter.

## Policy coverage

| Capability | Claude Code | Codex CLI | OpenCode | Gemini CLI | Kiro |
|---|---:|---:|---:|---:|---:|
| Structural Shell rules | ✓ `Bash` | ✓ `Bash` | ✓ `bash` | ✓ shell tools | ✓ shell aliases |
| [Tool capabilities](#tool-capabilities) | ✓ | ◐ Codex text reads use its shell | ✓ | ✓ | ✓ CLI and IDE |
| Canonical `MCP(server.tool)` rules | ✓ | ✓ | ✓ config-aware shim | ✓ | ✓ |
| Scoped `Read` | ✓ | ◐ `view_image` and pre-0.129 file tools | ✓ | ✓ | ✓ |
| Semantic `Write` | ✓ | ✓ patch add/update/delete/move | ✓ | ✓ | ✓ |
| Multi-file/move aggregation | — native calls are individual | ✓ | ✓ for patchText | — native calls are individual | — native call has one path |
| `Python(readonly)` for shell calls | ✓ | ✓ | ✓ | ✓ | ✓ |
| Semantic SQL captures in Shell/Python | ✓ | ✓ | ✓ | ✓ | ✓ |
| Layered policy precedence | ✓ shared engine | ✓ shared engine | ✓ shared engine | ✓ shared engine | ✓ shared engine |
| Native-policy import | ✓ | ✓ | ✓ | — | ✓ |
| Direct installation | ✓ | ✓ | ✓ plugin | ✓ | ✓ |
| Rulesync installation | ✓ | ✓ | — plugin remains direct | ✓ | ◐ mode ignored; direct hooks |

“All tools” means every tool event the host sends to the installed hook. It does not include actions
that bypass the host hook system.

Layered precedence means every Deny remains effective, while the nearest matching Ask/Allow wins;
inside one file, Ask precedes Allow.

`Python(readonly)` is syntax-aware: it parses literal inline Python with the standard-library AST.
SQL captures use SQLGlot plus explicit dialect policy and fail closed on opaque syntax. See
[Semantic SQL policies](sql-policy.md).

## Enforcement behavior

| Behavior | Claude Code | Codex CLI | OpenCode | Gemini CLI | Kiro |
|---|---|---|---|---|---|
| Hook stage | PreToolUse | PreToolUse + PermissionRequest | tool.execute.before + permission.ask | BeforeTool | PreToolUse |
| Allow | explicit pre-approval | emitted at PermissionRequest | permission hook approves; pre-hook is deny-only | explicit allow | exit 0 / host proceeds |
| Ask | native prompt | falls through to native prompt | falls through to native prompt | host API cannot request approval; blocks with an approval-required reason | structured ask |
| Deny | pre-execution block | PreToolUse veto; PermissionRequest also denies | pre-execution exception; permission hook also denies | pre-execution block | structured deny |
| No opinion | native flow | native flow | native flow | native flow | exit 0 / native flow |
| Recognized malformed operation | generic payload defers | unparseable patch denies | unparseable patch denies | generic payload defers | missing shell command asks/blocks |
| Host bypass | Claude `bypassPermissions` makes agentperm defer entirely | full-auto skips prompts; PreToolUse Deny preserved | none in payload | none in payload | none in payload |
| Pane bypass | Ask/NoOpinion → Allow; Deny preserved | same | same | same | same |

Gemini cannot preserve the interactive distinction between Ask and Deny through its current
pre-tool hook contract. Kiro receives distinct structured permission decisions and rationales.

## Tool capabilities

Policies name capabilities, never native tool spellings. Each adapter resolves every native tool
below, including names from older host releases, before a rule is matched. A native tool that is
not listed (subagents, todo lists, plan mode, …) matches no rule except `"*"`, so the host decides
it. The table is `src/agentperm/domain/tools.py`; a test keeps this page in step with it.

| Capability | Claude Code | Codex CLI | Gemini CLI | OpenCode | Kiro |
|---|---|---|---|---|---|
| `Read` | `Read`, `NotebookRead`, `Glob`, `Grep`, `LS` | `view_image`, `read_file`, `list_dir`, `grep_files` | `read_file`, `read_many_files`, `list_directory`, `glob`, `grep_search`, `search_file_content` | `read`, `list`, `glob`, `grep` | `read`, `fs_read`, `fsRead`, `glob`, `grep`, `read_file`, `readFile`, `read_files`, `readMultipleFiles`, `read_code`, `readCode`, `list_directory`, `listDirectory`, `file_search`, `fileSearch`, `grep_search`, `grepSearch` |
| `Write` | `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `apply_patch` | `write_file`, `replace` | `edit`, `write`, `multiedit`, `apply_patch`, `patch` | `write`, `fs_write`, `fsWrite`, `fs_append`, `fsAppend`, `str_replace`, `strReplace`, `edit_code`, `editCode`, `semantic_rename`, `smart_relocate`, `delete_file`, `deleteFile` |
| `WebFetch` | `WebFetch` | — | `web_fetch` | `webfetch` | `web_fetch`, `webFetch` |
| `WebSearch` | `WebSearch` | — hosted, not hooked | `google_web_search` | `websearch` | `web_search`, `webSearch`, `remote_web_search` |
| `Skill` | `Skill` | — | `activate_skill` | `skill` | — |
| `AWS` / `Code` / `Knowledge` | — | — | — | — | `aws`, `use_aws`, `useAws` / `code` / `knowledge` |
| Shell rules | `Bash` | `Bash` | `run_shell_command` | `bash` | `shell`, `execute_bash`, `execute_cmd`, `executeBash`, `executeCmd`, `run_command`, `runCommand` |

PowerShell (Claude `PowerShell`, Kiro `execute_pwsh`/`executePwsh`) is never analysed as a POSIX
shell command: it always asks. Since 0.129 Codex performs textual file reads, listing, and search
through `exec_command`; `view_image` remains a native `Read` tool. On every agent, a shell command that names a path inside a `Read`
deny or ask scope gets that verdict too, so `deny Read(secrets/**)` also stops `cat secrets/key`
(see the [policy reference](policy-reference.md) for what counts as a named path).

Scoped rules match each tool's own target: its path fields, the listed directory (`src/*`), the
searched tree (`src/**`, or the working directory), or a glob's pattern beneath its root. Any
native operation that creates, overwrites, edits, deletes, or moves a file is a `Write` on that
path, and a patch move is a `Write` on both the source and the destination.

Multi-file patches become one compound request. Every child is evaluated and the strictest verdict
wins. A malformed patch that claims to mutate files but cannot be translated becomes a rejected
request and is denied. File paths are resolved from the hook cwd, normalized through `.` and `..`,
and resolved through existing symlinks. Agentperm discovers policy from every target's ancestry;
relative scoped rules match from the directory containing their root policy.

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
