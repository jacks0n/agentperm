---
name: Bug report
about: Report a prompt that shouldn't have happened, an incorrect verdict, or a crash
labels: bug
---

**Agent and version**
e.g. Claude Code 1.x, Codex CLI 0.x — output of `<agent> --version`.

**Bridge version**
`llm-agent-bridge --version` or `pip show llm-agent-bridge | grep Version`.

**What happened**
The exact command, the prompt (or absence of prompt) you got, and what you expected.

**Trace**
Run with `LLM_AGENT_BRIDGE_TRACE=/tmp/bridge-trace.log` and paste the relevant line(s). See [docs/troubleshooting.md](../../docs/troubleshooting.md#1-is-the-bridge-actually-being-called).

```
{"agent": "claude", "event": "PreToolUse", "payload": {...}, "verdict": {...}}
```

**Policy file** (redact anything sensitive)

```jsonc
{ "version": 1, "permissions": { ... } }
```

**Anything else**
OS, shell, anything weird.
