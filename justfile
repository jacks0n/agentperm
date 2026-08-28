# agentperm — task runner. `just` to list, `just <recipe>` to run.

zellij_plugin_dir := env_var_or_default("ZELLIJ_PLUGIN_DIR", "~/.config/zellij/plugins")
wasm := "zellij-plugin/target/wasm32-wasip1/release/agentperm_indicator.wasm"

default:
    @just --list

# --- Python quality gates ---

sync:
    uv sync --extra dev --locked

test:
    uv run pytest -q

lint:
    uv run ruff check .

fmt:
    uv run ruff format .

typecheck:
    uv run basedpyright src tests

# All three gates — matches the PR checklist in CONTRIBUTING.md.
check: lint typecheck test

# Install locked dependencies and run every CI gate.
ci: sync check

build:
    uv build

# Validate that a stable release tag matches package and changelog metadata.
verify-release tag:
    #!/usr/bin/env bash
    set -euo pipefail
    package_version="$(uv version --short)"
    if [[ "{{ tag }}" != "v$package_version" ]]; then
      echo "Release tag {{ tag }} does not match package version $package_version"
      exit 1
    fi
    if ! grep -Fq "## [$package_version] —" CHANGELOG.md; then
      echo "CHANGELOG.md has no release section for $package_version"
      exit 1
    fi

publish:
    uv publish dist/* --trusted-publishing always

github-release tag:
    #!/usr/bin/env bash
    set -euo pipefail
    version="{{ tag }}"
    gh release create "{{ tag }}" dist/* \
      --verify-tag \
      --title "agentperm ${version#v}" \
      --generate-notes

# Regenerate the README demo GIF (requires vhs, claude CLI, codex CLI).
demo:
    docs/media/record-demo.sh

# --- zellij plugin ---

# One-time: install the WASI target the plugin compiles to.
zellij-setup:
    rustup target add wasm32-wasip1

# Build the plugin (release, optimised for size).
zellij-build:
    cargo build --release --target wasm32-wasip1 --manifest-path zellij-plugin/Cargo.toml

# Copy the built wasm into your zellij plugins dir. Override target with $ZELLIJ_PLUGIN_DIR.
zellij-install: zellij-build
    mkdir -p {{zellij_plugin_dir}}
    cp {{wasm}} {{zellij_plugin_dir}}/
    @echo "Installed → {{zellij_plugin_dir}}/agentperm_indicator.wasm"
    @echo "Now merge zellij-plugin/example-config.kdl into ~/.config/zellij/config.kdl,"
    @echo "and accept the FullHdAccess prompt on next zellij session start."

# Build + install in one shot.
zellij: zellij-install
