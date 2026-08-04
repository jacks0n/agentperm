# Build the agentperm-indicator zellij WASM plugin.
#
# Resolves rustc through rustup once, then exports it for cargo.
# This works even when Homebrew's rust formula shadows rustup's proxies on PATH.

RUSTC := $(shell rustup which rustc 2>/dev/null)
TARGET := wasm32-wasip1
WASM := target/$(TARGET)/release/agentperm-indicator.wasm
INSTALL_DIR := $(HOME)/.config/zellij/plugins

.PHONY: build install clean check-rustc

build: check-rustc
	RUSTC="$(RUSTC)" cargo build --release --target $(TARGET)

install: build
	mkdir -p "$(INSTALL_DIR)"
	cp "$(WASM)" "$(INSTALL_DIR)/agentperm-indicator.wasm"

clean:
	cargo clean

check-rustc:
ifndef RUSTC
	$(error rustup not found or cannot resolve rustc. Install rustup: https://rustup.rs)
endif
ifeq ($(RUSTC),)
	$(error rustup could not resolve rustc. Run: rustup toolchain install stable && rustup target add wasm32-wasip1)
endif
