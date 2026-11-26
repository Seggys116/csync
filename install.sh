#!/bin/sh
# installs the latest csync release; CSYNC_VERSION pins a release, CSYNC_INSTALL_DIR overrides ~/.local/bin
set -eu

REPO="Seggys116/csync"
DEST="${CSYNC_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${CSYNC_VERSION:-latest}"

say() { printf 'csync-install: %s\n' "$*"; }
die() { printf 'csync-install: error: %s\n' "$*" >&2; exit 1; }

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$1" -O "$2"
  else
    die "curl or wget is required"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "sha256sum or shasum is required"
  fi
}

case "$(uname -s)" in
  Darwin) os="apple-darwin" ;;
  Linux) os="unknown-linux-musl" ;;
  *) die "unsupported OS $(uname -s); csync runs on macOS and Linux" ;;
esac

case "$(uname -m)" in
  arm64 | aarch64) arch="aarch64" ;;
  x86_64 | amd64) arch="x86_64" ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

# a shell under rosetta reports x86_64 on apple silicon
if [ "$os" = apple-darwin ] && [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
  arch="aarch64"
fi

target="$arch-$os"
archive="csync-$target.tar.gz"

case "$VERSION" in
  latest) base="https://github.com/$REPO/releases/latest/download" ;;
  *[!0-9A-Za-z.+-]* | "") die "invalid CSYNC_VERSION '$VERSION'" ;;
  v*) base="https://github.com/$REPO/releases/download/$VERSION" ;;
  *) base="https://github.com/$REPO/releases/download/v$VERSION" ;;
esac

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t csync)"
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' INT TERM

say "downloading $archive ($VERSION)"
fetch "$base/$archive" "$tmp/$archive" || die "download failed; no release asset for $target"
fetch "$base/$archive.sha256" "$tmp/$archive.sha256" || die "checksum download failed"

expected="$(awk 'NR == 1 {print $1}' "$tmp/$archive.sha256")"
case "$expected" in
  *[!0-9a-f]* | "") die "malformed checksum file" ;;
esac
[ "${#expected}" -eq 64 ] || die "malformed checksum file"
actual="$(sha256 "$tmp/$archive")"
[ "$expected" = "$actual" ] || die "checksum mismatch (expected $expected, got $actual)"

listing="$(tar -tzf "$tmp/$archive" | sed 's|^\./||' | LC_ALL=C sort | tr '\n' ' ')"
[ "$listing" = "LICENSE README.md csync " ] || die "unexpected archive contents: $listing"

mkdir "$tmp/x"
tar -xzf "$tmp/$archive" -C "$tmp/x"
if [ ! -f "$tmp/x/csync" ] || [ -L "$tmp/x/csync" ]; then
  die "archive csync is not a regular file"
fi

mkdir -p "$DEST"
cp "$tmp/x/csync" "$DEST/csync.new"
chmod 755 "$DEST/csync.new"
mv -f "$DEST/csync.new" "$DEST/csync"

say "installed $("$DEST/csync" --version 2>/dev/null || echo csync) to $DEST"
case ":$PATH:" in
  *":$DEST:"*) ;;
  *) say "add it to PATH:  export PATH=\"$DEST:\$PATH\"" ;;
esac

if [ "$os" = unknown-linux-musl ]; then
  say "'csync join' needs fuse3 (fusermount3) on this machine"
  if ! command -v fusermount3 >/dev/null 2>&1; then
    say "fusermount3 not found; install fuse3 with your package manager:"
    say "  Debian/Ubuntu:  sudo apt install fuse3"
    say "  Fedora/RHEL:    sudo dnf install fuse3"
    say "  Arch:           sudo pacman -S fuse3"
    say "  Alpine:         sudo apk add fuse3"
    say "  openSUSE:       sudo zypper install fuse3"
  fi
fi
say "run 'csync doctor' to check your environment"
