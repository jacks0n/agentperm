#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")/.." && pwd)"
app_dir="$HOME/Applications/Agentperm Config.app"
workflow_id="user.workflow.5E90EB01-3C7C-44A5-A9B7-4867B42EE8E8"
sync_folder="$(defaults read com.runningwithcrayons.Alfred-Preferences syncfolder 2>/dev/null || true)"
sync_folder="${sync_folder/#\~/$HOME}"
if [[ -n "$sync_folder" && -d "$sync_folder/Alfred.alfredpreferences/workflows" ]]; then
  workflows_dir="$sync_folder/Alfred.alfredpreferences/workflows"
else
  workflows_dir="$HOME/Library/Application Support/Alfred/Alfred.alfredpreferences/workflows"
fi
workflow_dir="$workflows_dir/$workflow_id"
settings_dir="$HOME/Library/Application Support/Agentperm Config"
settings_path="$settings_dir/settings.json"

cd "$project_dir"
"$project_dir/scripts/build-app.sh" "0.1.0" "$project_dir/dist"

mkdir -p "$HOME/Applications" "$workflow_dir"
/usr/bin/osascript -e 'tell application id "dev.agentperm.config" to quit' >/dev/null 2>&1 || true
for _ in 1 2 3 4 5; do
  /usr/bin/pgrep -x AgentpermConfig >/dev/null 2>&1 || break
  sleep 0.2
done
if /usr/bin/pgrep -x AgentpermConfig >/dev/null 2>&1; then
  /usr/bin/pkill -x AgentpermConfig
fi
/usr/bin/ditto "$project_dir/dist/Agentperm Config.app" "$app_dir"

cp "$project_dir/Extras/Alfred/workflow/info.plist" "$workflow_dir/info.plist"
cp "$project_dir/Extras/Alfred/workflow/launch.sh" "$workflow_dir/launch.sh"
cp "$project_dir/Extras/Alfred/workflow/script-filter.sh" "$workflow_dir/script-filter.sh"
cp "$project_dir/Extras/Alfred/workflow/icon.png" "$workflow_dir/icon.png"
chmod 755 "$workflow_dir/launch.sh" "$workflow_dir/script-filter.sh"

mkdir -p "$settings_dir"
if [[ ! -f "$settings_path" ]]; then
  /usr/bin/plutil -create json "$settings_path"
fi
for executable_name in codex agentperm; do
  setting_key="${executable_name}Path"
  configured="$(/usr/bin/plutil -extract "$setting_key" raw -o - "$settings_path" 2>/dev/null || true)"
  detected="$(command -v "$executable_name" 2>/dev/null || true)"
  if [[ -z "$configured" && -n "$detected" ]]; then
    if /usr/bin/plutil -type "$setting_key" "$settings_path" >/dev/null 2>&1; then
      /usr/bin/plutil -replace "$setting_key" -string "$detected" "$settings_path"
    else
      /usr/bin/plutil -insert "$setting_key" -string "$detected" "$settings_path"
    fi
  fi
done
chmod 600 "$settings_path"

/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$app_dir"
echo "Installed app: $app_dir"
echo "Installed Alfred workflow: $workflow_dir"
echo "Type 'ap' in Alfred, or configure the workflow's Hotkey trigger."
