#!/bin/sh
set -eu

REPO="Jaso1024/poe"
INSTALL_DIR="${POE_INSTALL_DIR:-$HOME/.local/bin}"

main() {
    need_cmd curl
    need_cmd tar
    need_cmd uname

    local arch
    arch="$(uname -m)"
    local os
    os="$(uname -s)"

    if [ "$os" != "Linux" ]; then
        err "poe only supports Linux (got: $os)"
    fi

    local target
    case "$arch" in
        x86_64)  target="x86_64-unknown-linux-musl" ;;
        aarch64) target="aarch64-unknown-linux-gnu" ;;
        *)       err "unsupported architecture: $arch" ;;
    esac

    local version
    if [ -n "${POE_VERSION:-}" ]; then
        version="$POE_VERSION"
    else
        say "fetching latest version..."
        version="$(curl -sSf "https://api.github.com/repos/$REPO/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')"
        if [ -z "$version" ]; then
            err "could not determine latest version. Set POE_VERSION=v0.1.0 to install a specific version."
        fi
    fi

    local url="https://github.com/$REPO/releases/download/$version/poe-$target.tar.gz"
    local checksum_url="$url.sha256"

    say "installing poe $version for $target"
    say "  from: $url"
    say "  to:   $INSTALL_DIR/poe"

    local tmp
    tmp="$(mktemp -d)"
    trap "rm -rf '$tmp'" EXIT

    say "downloading..."
    curl -sSfL "$url" -o "$tmp/poe.tar.gz"
    curl -sSfL "$checksum_url" -o "$tmp/poe.tar.gz.sha256" 2>/dev/null || true

    if [ -f "$tmp/poe.tar.gz.sha256" ] && need_cmd sha256sum 2>/dev/null; then
        say "verifying checksum..."
        cd "$tmp"
        sha256sum -c poe.tar.gz.sha256
        cd - > /dev/null
    fi

    say "extracting..."
    tar xzf "$tmp/poe.tar.gz" -C "$tmp"

    mkdir -p "$INSTALL_DIR"
    mv "$tmp/poe" "$INSTALL_DIR/poe"
    chmod +x "$INSTALL_DIR/poe"

    say ""
    say "poe $version installed to $INSTALL_DIR/poe"

    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        say ""
        say "WARNING: $INSTALL_DIR is not in your PATH."
        say "Add this to your shell profile:"
        say "  export PATH=\"$INSTALL_DIR:\$PATH\""
    fi

    say ""
    say "Run 'poe doctor' to verify your system is ready."
}

say() {
    printf "poe-install: %s\n" "$*"
}

err() {
    say "ERROR: $*" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        err "need '$1' (command not found)"
    fi
}

main "$@"
