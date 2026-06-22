use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use zellij_tile::prelude::*;

// `std::os::unix::fs::{DirBuilderExt, OpenOptionsExt}` is not available on
// wasm32-wasip1, so we cannot set mode bits explicitly. Files and directories
// inherit the user's umask (typically 0755 / 0644). agentperm's safety check
// only rejects directories that are group/world-*writable*, which a default
// umask of 022 prevents — so this is safe under normal configurations.

#[derive(Default)]
struct State {
    bypass_on: HashMap<u32, bool>,
    focused_pane: Option<u32>,
    live_panes: HashSet<u32>,
    cache_dir: PathBuf,
    permission_granted: bool,
}

register_plugin!(State);

impl ZellijPlugin for State {
    fn load(&mut self, _config: BTreeMap<String, String>) {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
        let xdg_base = std::env::var("XDG_CACHE_HOME").unwrap_or_else(|_| format!("{home}/.cache"));
        let session = std::env::var("ZELLIJ_SESSION_NAME").unwrap_or_default();
        self.cache_dir = PathBuf::from(xdg_base)
            .join("agentperm")
            .join("bypass")
            .join(&session);
        request_permission(&[
            PermissionType::ReadApplicationState,
            PermissionType::ChangeApplicationState,
            PermissionType::FullHdAccess,
        ]);
        subscribe(&[EventType::PermissionRequestResult, EventType::PaneUpdate]);
    }

    fn update(&mut self, event: Event) -> bool {
        match event {
            Event::PermissionRequestResult(_) => {
                self.permission_granted = true;
                self.ensure_dir();
                self.refresh_from_disk();
                true
            }
            Event::PaneUpdate(manifest) => {
                let mut focused = None;
                let mut live = HashSet::new();
                for (_tab, panes) in manifest.panes {
                    for pane in panes {
                        if !pane.is_plugin {
                            live.insert(pane.id);
                            if pane.is_focused {
                                focused = Some(pane.id);
                            }
                        }
                    }
                }
                self.live_panes = live;
                self.focused_pane = focused;
                if self.permission_granted {
                    self.cleanup_stale();
                    self.refresh_from_disk();
                }
                true
            }
            _ => false,
        }
    }

    fn pipe(&mut self, msg: PipeMessage) -> bool {
        if msg.name != "toggle" {
            return false;
        }
        let Some(pid) = self.focused_pane else {
            return false;
        };
        if !self.permission_granted {
            return false;
        }
        self.ensure_dir();
        let path = self.cache_dir.join(pid.to_string());
        if path.exists() {
            let _ = fs::remove_file(&path);
        } else {
            let _ = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path);
        }
        self.refresh_from_disk();
        true
    }

    fn render(&mut self, _rows: usize, _cols: usize) {
        let on = self
            .focused_pane
            .and_then(|p| self.bypass_on.get(&p).copied())
            .unwrap_or(false);
        if on {
            print!("\u{1b}[41;97;1m BYPASS \u{1b}[0m");
        } else {
            print!("\u{1b}[2m agentperm \u{1b}[0m");
        }
    }
}

impl State {
    fn ensure_dir(&self) {
        let _ = fs::create_dir_all(&self.cache_dir);
    }

    fn refresh_from_disk(&mut self) {
        self.bypass_on.clear();
        let Ok(entries) = fs::read_dir(&self.cache_dir) else {
            return;
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    self.bypass_on.insert(pid, true);
                }
            }
        }
    }

    fn cleanup_stale(&self) {
        let Ok(entries) = fs::read_dir(&self.cache_dir) else {
            return;
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    if !self.live_panes.contains(&pid) {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}
