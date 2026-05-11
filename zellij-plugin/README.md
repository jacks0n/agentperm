# agentperms-indicator (zellij plugin)

A small zellij WASM plugin that lets you toggle agentperms "bypass everything"
mode for the currently focused pane, with a visible indicator. The flag file is
keyed by `(ZELLIJ_SESSION_NAME, ZELLIJ_PANE_ID)` so each pane is independent.

When the flag is on, agentperms coerces every `Ask` and `NoOpinion` verdict to
`Allow` for that pane only. `Deny` rules are unaffected.

## Build

```sh
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1 --manifest-path zellij-plugin/Cargo.toml
mkdir -p ~/.config/zellij/plugins
cp zellij-plugin/target/wasm32-wasip1/release/agentperms_indicator.wasm ~/.config/zellij/plugins/
```

## Configure

Merge the snippets in [`example-config.kdl`](./example-config.kdl) into your
`~/.config/zellij/config.kdl`. The plugin needs a 1-row slot in
`default_tab_template`, and a global keybind to message it.

On the first session start, accept the **FullHdAccess** permission prompt — the
plugin needs it to read and write `~/.cache/agentperms/bypass/<session>/`.

## Smoke test

1. Start a fresh zellij session. The slot at the top of the tab renders dim
   `agentperms`.
2. Press `Ctrl-Shift-b`. It flips to red `BYPASS`.
3. `ls ~/.cache/agentperms/bypass/$ZELLIJ_SESSION_NAME/` shows a file named
   `$ZELLIJ_PANE_ID`. (Permissions follow your umask — typically `-rw-r--r--`.
   agentperms only refuses group/world-*writable* directories, so the default
   umask of 022 is safe; tighten with `chmod -R go-rwx ~/.cache/agentperms` if
   you want to hide the bypass state from other local users.)
4. Press `Ctrl-Shift-b` again. Indicator dims, file disappears.
5. Open a second pane in the same tab, focus it. Indicator reflects the new
   pane's state (off, by default). Toggle independently.
6. Close the second pane. The next focus / pane change triggers cleanup of any
   stale flag files for panes that no longer exist.

## How it talks to agentperms

Both sides resolve the cache dir the same way:
`$XDG_CACHE_HOME/agentperms/bypass/<session>/<pane_id>` (falling back to
`$HOME/.cache/...` if `XDG_CACHE_HOME` is unset).

agentperms reads the flag file inside `coerce_for_pane_bypass`. The plugin owns
all writes. agentperms refuses to honor the flag if the bypass directory is
group/world-writable or not owned by the current uid. The plugin cannot set
mode bits explicitly (WASI has no `std::os::unix`), so files and directories
inherit the user's umask — typical defaults (`umask 022`, dir mode 0755) pass
the safety check.

## TOCTOU caveat

Bypass applies to *future* permission decisions. A command already approved by
agentperms cannot be retroactively unapproved by toggling bypass off mid-flight.
