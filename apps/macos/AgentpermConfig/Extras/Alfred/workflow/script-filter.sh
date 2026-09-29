#!/usr/bin/env bash
set -euo pipefail

query="${1:-}"
if [[ -z "$query" ]]; then
  query="$(/usr/bin/pbpaste)"
fi

settings="$HOME/Library/Application Support/Agentperm Config/settings.json"
configured_agentperm="$(/usr/bin/plutil -extract agentpermPath raw -o - "$settings" 2>/dev/null || true)"
configured_agentperm="${configured_agentperm/#\~/$HOME}"
if [[ -n "$configured_agentperm" ]]; then
  agentperm_bin="$configured_agentperm"
else
  agentperm_bin="$(command -v agentperm 2>/dev/null || true)"
fi

if [[ -z "$query" ]]; then
  verdict="Copy a command or type one after the keyword"
elif [[ -x "$agentperm_bin" ]]; then
  verdict="$(cd "$HOME" && "$agentperm_bin" why "$query" 2>&1 | /usr/bin/head -n 1 || true)"
elif [[ -n "$configured_agentperm" ]]; then
  verdict="Configured agentperm executable is not available"
else
  verdict="agentperm is not installed or is missing from PATH"
fi

/usr/bin/osascript -l JavaScript - "$query" "$verdict" <<'JXA'
function run(argv) {
  const query = argv[0];
  const valid = query.length > 0;
  return JSON.stringify({items: [
    {
      uid: "explain",
      title: "Explain effective permission",
      subtitle: argv[1],
      arg: query,
      valid,
      icon: {path: "icon.png"},
      variables: {mode: "explain"},
      mods: {cmd: {
        subtitle: "Open directly in Propose Changes",
        arg: query,
        variables: {mode: "configure"}
      }}
    },
    {
      uid: "configure",
      title: "Propose configuration changes",
      subtitle: "Use Codex to generalise safe rules, then review and apply the diff",
      arg: query,
      valid,
      icon: {path: "icon.png"},
      variables: {mode: "configure"}
    }
  ]});
}
JXA
