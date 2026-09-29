#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")/.." && pwd)"
version="${1:?usage: package-release.sh VERSION}"
dist_dir="$project_dir/dist"
app_dir="$dist_dir/Agentperm Config.app"
dmg_path="$dist_dir/Agentperm-Config-$version.dmg"
zip_path="$dist_dir/Agentperm-Config-$version.zip"
staging_dir="$(mktemp -d)"
trap 'rm -rf "$staging_dir"' EXIT

"$project_dir/scripts/build-app.sh" "$version" "$dist_dir"
cp -R "$app_dir" "$staging_dir/Agentperm Config.app"
ln -s /Applications "$staging_dir/Applications"

rm -f "$dmg_path" "$zip_path"
/usr/bin/hdiutil create -quiet -volname "Agentperm Config" -srcfolder "$staging_dir" \
  -ov -format UDZO "$dmg_path"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$app_dir" "$zip_path"

if [[ -n "${CODE_SIGN_IDENTITY:-}" ]]; then
  /usr/bin/codesign --force --timestamp --sign "$CODE_SIGN_IDENTITY" "$dmg_path"
fi

if [[ -n "${APPLE_API_KEY_PATH:-}" && -n "${APPLE_API_KEY_ID:-}" && -n "${APPLE_API_ISSUER_ID:-}" ]]; then
  /usr/bin/xcrun notarytool submit "$dmg_path" --wait \
    --key "$APPLE_API_KEY_PATH" \
    --key-id "$APPLE_API_KEY_ID" \
    --issuer "$APPLE_API_ISSUER_ID"
  /usr/bin/xcrun stapler staple "$dmg_path"
  /usr/sbin/spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg_path"
fi

"$project_dir/scripts/package-workflow.sh"
/usr/bin/shasum -a 256 "$dmg_path" "$zip_path" "$dist_dir/Agentperm Config.alfredworkflow" \
  > "$dist_dir/SHA256SUMS"
printf '%s\n%s\n' "$dmg_path" "$zip_path"
