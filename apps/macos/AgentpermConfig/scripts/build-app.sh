#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")/.." && pwd)"
version="${1:-0.1.0}"
output_dir="${2:-$project_dir/dist}"
app_dir="$output_dir/Agentperm Config.app"
build_number="${BUILD_NUMBER:-${GITHUB_RUN_NUMBER:-1}}"

cd "$project_dir"
swift build -c release --arch arm64 --arch x86_64
binary_dir="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)"

rm -rf "$app_dir"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
cp "$binary_dir/AgentpermConfig" "$app_dir/Contents/MacOS/AgentpermConfig"
cp "$project_dir/packaging/AppInfo.plist" "$app_dir/Contents/Info.plist"
cp "$project_dir/Resources/AppIcon.icns" "$app_dir/Contents/Resources/AppIcon.icns"
chmod 755 "$app_dir/Contents/MacOS/AgentpermConfig"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" "$app_dir/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $build_number" "$app_dir/Contents/Info.plist"

if [[ -n "${CODE_SIGN_IDENTITY:-}" ]]; then
  /usr/bin/codesign --force --deep --options runtime --timestamp \
    --sign "$CODE_SIGN_IDENTITY" "$app_dir"
else
  /usr/bin/codesign --force --deep --sign - "$app_dir"
fi

/usr/bin/codesign --verify --deep --strict --verbose=2 "$app_dir"
/usr/bin/file "$app_dir/Contents/MacOS/AgentpermConfig"
echo "$app_dir"
