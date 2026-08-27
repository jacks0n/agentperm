#!/usr/bin/env bash
# Record the README demo using isolated, disposable agent configuration.
# Requires vhs (brew install vhs), Claude Code, Codex CLI, and existing logins.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO_ROOT="$(mktemp -d "/tmp/agentperm-demo.XXXXXX")"
export AGENTPERM_DEMO_ROOT="$DEMO_ROOT"
export AGENTPERM_DEMO_WORK="$DEMO_ROOT/work"
export PATH="$DEMO_ROOT/bin:$REPO_ROOT/.venv/bin:$PATH"

cleanup() {
  case "$DEMO_ROOT" in
    /tmp/agentperm-demo.*) rm -rf -- "$DEMO_ROOT" ;;
    *) printf 'Refusing to remove unexpected demo path: %s\n' "$DEMO_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT

for command in vhs claude codex agentperm; do
  command -v "$command" >/dev/null || {
    printf 'Missing required command: %s\n' "$command" >&2
    exit 1
  }
done

if [[ ! -f "$HOME/.codex/auth.json" ]]; then
  printf 'Codex is not logged in: expected %s\n' "$HOME/.codex/auth.json" >&2
  exit 1
fi

mkdir -p \
  "$DEMO_ROOT/bin" \
  "$DEMO_ROOT/policy-home" \
  "$DEMO_ROOT/claude-home/.claude" \
  "$DEMO_ROOT/codex" \
  "$AGENTPERM_DEMO_WORK"
AGENTPERM_DEMO_WORK="$(cd "$AGENTPERM_DEMO_WORK" && pwd -P)"
export AGENTPERM_DEMO_WORK
cp "$HOME/.codex/auth.json" "$DEMO_ROOT/codex/auth.json"
chmod 600 "$DEMO_ROOT/codex/auth.json"
if [[ -f "$HOME/.codex/models_cache.json" ]]; then
  cp "$HOME/.codex/models_cache.json" "$DEMO_ROOT/codex/models_cache.json"
fi
CODEX_VERSION="$(codex --version | awk '{print $2}')"
printf '{"latest_version":"%s","last_checked_at":"9999-01-01T00:00:00Z","dismissed_version":null}\n' \
  "$CODEX_VERSION" > "$DEMO_ROOT/codex/version.json"

# Copy Claude's existing login into its disposable HOME. Claude stores OAuth
# credentials in this file on Linux and in Keychain on macOS.
if [[ -f "$HOME/.claude/.credentials.json" ]]; then
  cp "$HOME/.claude/.credentials.json" "$DEMO_ROOT/claude-home/.claude/.credentials.json"
elif command -v security >/dev/null && \
  security find-generic-password -s 'Claude Code-credentials' >/dev/null 2>&1; then
  security find-generic-password -w -s 'Claude Code-credentials' \
    > "$DEMO_ROOT/claude-home/.claude/.credentials.json"
else
  printf 'Claude is not logged in or its credential store is unsupported.\n' >&2
  exit 1
fi
chmod 600 "$DEMO_ROOT/claude-home/.claude/.credentials.json"

# Copy account/onboarding state so an expired access token can refresh, then
# discard personal projects and MCP state. The real ~/.claude.json is read-only.
python3 - \
  "$DEMO_ROOT/claude-home/.claude.json" \
  "$AGENTPERM_DEMO_WORK" \
  "$HOME/.claude.json" <<'PY'
import json, pathlib, sys
state_path = pathlib.Path(sys.argv[1])
work_path = str(pathlib.Path(sys.argv[2]).resolve())
source_path = pathlib.Path(sys.argv[3])
state = json.loads(source_path.read_text()) if source_path.exists() else {}
state.pop("mcpServers", None)
state.update({
    "installMethod": state.get("installMethod", "native"),
    "hasCompletedOnboarding": True,
    "lastOnboardingVersion": state.get("lastOnboardingVersion", "2.1.0"),
    "projects": {work_path: {"hasTrustDialogAccepted": True}},
})
state_path.write_text(json.dumps(state, indent=2) + "\n")
PY

# Explicit settings and an empty strict MCP config keep personal configuration
# out of the recording.
cat > "$DEMO_ROOT/claude-settings.json" <<EOF
{
  "theme": "dark",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "HOME=$DEMO_ROOT/policy-home $REPO_ROOT/.venv/bin/agentperm check --agent claude --event PreToolUse",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
EOF

# Codex gets an isolated CODEX_HOME: authentication is copied in, while MCP
# servers, AGENTS.md, history, profiles, and native exec rules stay out.
cat > "$DEMO_ROOT/codex/config.toml" <<EOF
approval_policy = "untrusted"
sandbox_mode = "danger-full-access"

[features]
hooks = true
apps = false
plugins = false
recommended_plugins = false

[projects."$AGENTPERM_DEMO_WORK"]
trust_level = "trusted"
EOF

cat > "$DEMO_ROOT/codex/hooks.json" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "HOME=$DEMO_ROOT/policy-home $REPO_ROOT/.venv/bin/agentperm check --agent codex --event PreToolUse",
            "timeout": 30
          }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "HOME=$DEMO_ROOT/policy-home $REPO_ROOT/.venv/bin/agentperm check --agent codex --event PermissionRequest",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
EOF

cat > "$DEMO_ROOT/bin/claude-demo" <<EOF
#!/usr/bin/env bash
export HOME="$DEMO_ROOT/claude-home"
exec claude \
  --model sonnet \
  --permission-mode manual \
  --setting-sources '' \
  --settings "$DEMO_ROOT/claude-settings.json" \
  --strict-mcp-config \
  --mcp-config '{"mcpServers":{}}' \
  --prompt-suggestions false \
  --tools Bash
EOF

cat > "$DEMO_ROOT/bin/codex-demo" <<EOF
#!/usr/bin/env bash
export CODEX_HOME="$DEMO_ROOT/codex"
exec codex \
  --model gpt-5.6-luna \
  --disable apps \
  --disable plugins \
  --ask-for-approval untrusted \
  --sandbox danger-full-access \
  --dangerously-bypass-hook-trust
EOF

cat > "$DEMO_ROOT/bin/agentperm" <<EOF
#!/usr/bin/env bash
exec env HOME="$DEMO_ROOT/policy-home" "$REPO_ROOT/.venv/bin/agentperm" "\$@"
EOF
chmod +x "$DEMO_ROOT/bin/agentperm" "$DEMO_ROOT/bin/claude-demo" "$DEMO_ROOT/bin/codex-demo"

cat > "$AGENTPERM_DEMO_WORK/.agent-permissions.jsonc" <<'EOF'
{
  "version": 1,
  "permissions": {
    "allow": [
      "Shell(cat)",
      "Shell(head)"
    ],
    "deny": [
      "Shell(curl)"
    ]
  }
}
EOF

cat > "$AGENTPERM_DEMO_WORK/demo-notes.txt" <<'EOF'
one policy
every agent
EOF

(
  cd "$AGENTPERM_DEMO_WORK"
  git init -q
  git config user.name "agentperm demo"
  git config user.email "demo@agentperm.local"
  git add .
  git commit -qm "demo baseline"
)

cd "$REPO_ROOT"
vhs docs/media/demo.tape
printf 'Demo ready -> docs/media/demo.gif and docs/media/demo.mp4\n'
