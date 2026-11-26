# Changelog

## 0.1.0

First release.

* `csync host` serves a project directory; `csync join` mounts it on a Linux guest over FUSE, with two-way sync,
  three-way merge of concurrent edits, and inotify events on the guest for host-side changes.
* Peers authenticate with Noise (`XX` to pair, `IK` afterwards). First pairing is confirmed by comparing an
  8-character code; `csync key show` and `csync trust add` pre-share keys for unattended setups, and `csync forget`
  revokes a peer.
* The guest is confined to the project root: ignored files are never served and `.git` is read-only.
* Hosts are found over Bonjour. The host and guest TUIs animate only while something changes; `--no-tui` prints one
  status line per event and reads commands from stdin.
* Gitignore is followed exactly, including nested ignore files, `.git/info/exclude`, global excludes and submodules.
  Ignored paths live in a plain directory on the guest and are never synced. `git status`, `log`, `diff` and `blame`
  work on the guest at close to native speed.
* `csync doctor` checks the FUSE, kernel and trust-file setup; `csync status` shows the running session.
* Static musl binaries for Linux (arm64, x86_64) and binaries for macOS (arm64, x86_64), installable with
  `install.sh`.
