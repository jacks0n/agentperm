#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$project_dir/dist"
cd "$project_dir/Extras/Alfred/workflow"
rm -f "$project_dir/dist/Agentperm Config.alfredworkflow"
/usr/bin/zip -q -r "$project_dir/dist/Agentperm Config.alfredworkflow" info.plist launch.sh script-filter.sh icon.png
echo "$project_dir/dist/Agentperm Config.alfredworkflow"
