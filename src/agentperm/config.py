"""Central configuration and resource budgets for agentperm."""

from __future__ import annotations

POLICY_FILENAME = ".agent-permissions.jsonc"
POLICY_VERSION = 1
TEMPLATE_SUFFIX = ".jsonc"
DEFAULT_TEMPLATES: tuple[str, ...] = ("safety-baseline", "file-inspection", "git-read-only")

BRIDGE_HOOK_MARKER = "agentperm"
# Claude, Codex and Kiro use seconds; Gemini uses milliseconds.
HOOK_TIMEOUTS: dict[str, int] = {"claude": 30, "codex": 30, "gemini": 30_000, "kiro": 30}

RULESYNC_DIR = ".rulesync"
RULESYNC_HOOKS_PATH = ".rulesync/hooks.json"
RULESYNC_VERSION = 1
CLAUDE_SETTINGS_PATH = ".claude/settings.json"
CODEX_CONFIG_PATH = ".codex/config.toml"
CODEX_HOOKS_PATH = ".codex/hooks.json"
GEMINI_SETTINGS_PATH = ".gemini/settings.json"
OPENCODE_CONFIG_PATH = ".config/opencode/opencode.json"
OPENCODE_PLUGIN_PATH = ".config/opencode/plugins/agentperm.js"
KIRO_HOME_PATH = ".kiro"
KIRO_HOOKS_PATH = "hooks/agentperm.json"
KIRO_AGENTS_PATH = "agents"

ENV_AGENTPERM_TRACE = "AGENTPERM_TRACE"
ENV_HOME = "HOME"
ENV_KIRO_HOME = "KIRO_HOME"
ENV_XDG_CACHE_HOME = "XDG_CACHE_HOME"
ENV_ZELLIJ_PANE_ID = "ZELLIJ_PANE_ID"
ENV_ZELLIJ_SESSION_NAME = "ZELLIJ_SESSION_NAME"
DEFAULT_CACHE_PATH = ".cache"
BYPASS_CACHE_PATH = "agentperm/bypass"

MAX_TOOL_ARGUMENT_NODES = 1_000
MAX_PYTHON_SOURCE_BYTES = 100_000
MAX_PYTHON_AST_NODES = 10_000
MAX_SQL_SOURCE_BYTES = 250_000
MAX_SQL_STATEMENTS = 100
MAX_SQL_AST_NODES = 50_000
MAX_STATIC_STRING_ALTERNATIVES = 1_024
MAX_SHELL_GLOB_MATCHES = 256
MAX_SHELL_DIRECTORIES = 64
MAX_SHELL_READ_TARGETS = 1_024
MCP_PATTERN_CACHE_SIZE = 1_024
