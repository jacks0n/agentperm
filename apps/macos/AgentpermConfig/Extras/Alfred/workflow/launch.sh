#!/usr/bin/env bash
set -euo pipefail

app=""
for candidate in "$HOME/Applications/Agentperm Config.app" "/Applications/Agentperm Config.app"; do
  if [[ -d "$candidate" ]]; then
    app="$candidate"
    break
  fi
done
if [[ -z "$app" ]]; then
  /usr/bin/osascript -e 'display notification "Run scripts/install.sh first" with title "Agentperm Config is not installed"'
  exit 1
fi

query="${1:-}"
if [[ -z "$query" ]]; then
  query="$(/usr/bin/pbpaste)"
fi
if [[ -z "$query" ]]; then
  /usr/bin/osascript -e 'display notification "Copy or enter a command first" with title "Nothing to propose"'
  exit 1
fi

encoded="$(/usr/bin/printf '%s' "$query" | /usr/bin/base64 | /usr/bin/tr '+/' '-_' | /usr/bin/tr -d '=\n')"
mode="${mode:-explain}"
/usr/bin/open "agentperm-config://${mode}?command=${encoded}"
