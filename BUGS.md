# Agentperm bug register

This is the durable index of confirmed Agentperm failures and integration incidents. Record a
report here before implementation detail disappears from terminal output or chat. Keep one entry
per broken invariant and cross-reference host-agent or wrapper registries when ownership is shared.

## Status

- **released**: fixed in a tagged release.
- **unreleased**: fixed in the working tree but not released.
- **mitigated**: the immediate failure is addressed, but the lifecycle or integration limitation remains.
- **open**: reproduced and not fixed.
- **external**: caused by a host contract Agentperm cannot control; safe handling is documented and tested.

## Confirmed defects and incidents

| ID | Symptom | Root cause | Evidence | Status | Required regression/invariant |
|---|---|---|---|---|---|
| AGP-001 | Claude and Codex printed non-blocking Python tracebacks for every Agentperm hook. | The executable resolved through a stale editable Python environment containing Agentperm 0.2.1 without its current `sqlglot` dependency, although the checkout's `pyproject.toml` already declared it. | Live hook tracebacks; `uv pip show`; editable reinstall upgraded the environment to Agentperm 0.4.0 and installed `sqlglot` 30.17.0. | mitigated | Installation and upgrade acceptance must invoke the installed hook executable in a sparse host-like environment and import every runtime dependency. |
| AGP-002 | Codex prompted for every command even though `agentperm why` allowed the commands. | The long-running Codex host started before hooks were regenerated and enabled, retained its startup hook snapshot, and emitted no Agentperm hook events. | Host start was 2026-09-02; generated Codex hooks changed 2026-09-03; direct Beckon → Agentperm replay returned `allow`. Related Beckon incidents: `BKN-044`, `BKN-045`. | mitigated | Install/sync output must state that already-running hosts need restarting; a fresh host must prove an allow verdict reaches Codex before release acceptance. |
| AGP-003 | A read-only CloudWatch loop prompted because `set -- "$spec"` was unrecognized. | The shell evaluator recognized only the exact inert `set -a` and `set +a` shapes; it did not classify positional-parameter assignment as process-local shell state. | `agentperm why` identified only the `set` segment as `no-opinion`; the full loop allowed after the AST-aware inert-shape fix. | unreleased | `set -- [arguments...]` is intrinsically allowed after user rules are considered; bare `set`, `set -x`, and other unreviewed forms remain `no-opinion`. |
| AGP-005 | A read-only launchd inventory command prompted while diagnosing MCP launch agents. | The file-inspection policy covered the surrounding `find`, `rg`, and `plutil` pipeline but had no rule for launchd's read-only inventory operation. | `agentperm why 'launchctl list'` returned `no-opinion`; the reported compound diagnostic allows after adding the exact rule. | unreleased | Allow only bare `launchctl list`; operands, flags, and mutating subcommands such as `bootstrap`, `bootout`, and `kickstart` remain unallowed. |
| AGP-006 | Codex YOLO mode allowed a denied file mutation, including `apply_patch` invoked from a code-mode `exec` cell. | Codex reports `approval_policy=never` to hooks as `permission_mode: bypassPermissions`; Agentperm applied its Claude-specific bypass coercion to every adapter and erased Codex's valid `PreToolUse` deny. | The denied path produces a deny verdict without the mode field, while the same Codex hook payload with `permission_mode: bypassPermissions` emitted `{}`. Codex routes code-mode nested calls through the ordinary tool registry and runs their `PreToolUse` hooks. | unreleased | Claude's explicit bypass continues to defer, but Codex `PreToolUse` hard denies remain blocking under `approval_policy=never`, for both direct and code-mode nested tools. |
| AGP-007 | Read-only database diagnostics prompted when SQLAlchemy wrapped locally constructed SQL in `text(...)`, or SQL\*Plus stdin contained `whenever` and a variable-expanded `connect`. | Python SQL capture accepted only a bare literal/name and could not resolve bounded local string helpers; SQL\*Plus document handling treated safe client control/connection directives as SQL or effectful input, while dynamic-input rejection ran before those directives could be removed. | The reported generic query shapes now return allow through both `agentperm why` and Claude `PreToolUse` replay; focused regressions prove read-only variants allow while a possible Python write and dynamic SQL\*Plus query still ask. | unreleased | Every statically possible Python query must satisfy a read-only SQL policy; SQL\*Plus may ignore safe error/session directives but must continue to reject dynamic SQL text and effectful directives. |

## Composition follow-up

| ID | Symptom | Root cause | Evidence | Status | Required regression/invariant |
|---|---|---|---|---|---|
| AGP-004 | Combined installation could narrow policy coverage to Beckon's previous matcher or leave concurrent permission handlers. | Composition inherited attention-group scope rather than preserving independent policy and foreign-handler scope. | Typed composition tests and Beckon cross-product CLI installer matrix. | unreleased | Exactly one ordered wrapper; preserve foreign matchers; both install orders, reinstall and uninstall retain the other product. |

## Host constraints

| ID | Constraint | Safe behavior |
|---|---|---|
| EXT-001 | Codex and other hosts may snapshot generated hook configuration at process startup. | Restart the host agent after hook command, matcher, timeout, or feature changes; resuming the same conversation is safe. |
| EXT-002 | Claude `bypassPermissions` is explicit host-level full-auto intent. | Agentperm defers to Claude and propagates `approval-policy: never` only to downstream Codex MCP calls; use normal Claude permissions or pane bypass when policy enforcement must remain active. |

## Incident workflow

For every new report:

1. Preserve the exact command, host, working directory, timestamps, and redacted hook output.
2. Run `agentperm why` without executing the command and identify the first non-allow segment.
3. Distinguish policy/parser decisions from missing, stale, timed-out, or discarded host hooks.
4. Add or update one register entry; cross-link shared Beckon incidents rather than duplicating ownership.
5. Reproduce the defect in a regression test before fixing it, then record verification and release status.
