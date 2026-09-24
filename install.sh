#!/usr/bin/env bash
set -euo pipefail

REPO="lazzerex/tracelet"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
OS="linux"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64) ARCH="x86_64" ;;
    aarch64) ARCH="aarch64" ;;
    *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

usage() {
    echo "usage: $0 [VERSION]" >&2
    echo "  VERSION  e.g. v1.0.0 (default: latest)" >&2
    exit 2
}

case "${1:-}" in
    -h|--help) usage ;;
esac

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required" >&2
    exit 1
fi

if [ "${1:-}" = "" ]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"\(.*\)".*/\1/')
    if [ -z "$TAG" ]; then
        echo "failed to find latest release" >&2
        exit 1
    fi
else
    TAG="$1"
fi

ARTIFACT="tracelet-${TAG}-${OS}-${ARCH}"
TARBALL="${ARTIFACT}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}.sha256"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "downloading $TARBALL ..."
curl -fsSL -o "$TMPDIR/$TARBALL" "$URL"

echo "downloading checksum ..."
curl -fsSL -o "$TMPDIR/$TARBALL.sha256" "$CHECKSUM_URL"

echo "verifying checksum ..."
(cd "$TMPDIR" && sha256sum -c "$TARBALL.sha256")

echo "extracting ..."
tar -xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"

if [ ! -f "$TMPDIR/$ARTIFACT/tracelet" ]; then
    echo "tracelet binary not found in archive" >&2
    exit 1
fi

echo "installing to $INSTALL_DIR/tracelet ..."
sudo mkdir -p "$INSTALL_DIR"
sudo install -m 755 "$TMPDIR/$ARTIFACT/tracelet" "$INSTALL_DIR/tracelet"

echo "installed: $($INSTALL_DIR/tracelet --version)"