# Changelog

## Unreleased

* `csync join` can run on macOS (experimental, not yet verified against a real macFUSE mount). It needs macFUSE 5.5
  or later and mounts with the FSKit backend first, falling back to the kernel extension. There is no kernel
  passthrough, writeback cache or `readdirplus` on macOS, and ignored paths live in a directory named
  `overlay.noindex` so that Spotlight skips it.
* csync loads macFUSE's `libfuse3` at run time through its own binding, so the binary needs nothing installed to build
  or to run `csync host`.
* `csync join` on macOS removes a `.DS_Store` that is the only entry of the mount point instead of refusing it.
* `csync doctor` checks the macFUSE install and version, `libfuse3`, the FSKit extension, the kernel extension, the
  macOS version, stale mounts and clonefile support on a Mac.
* The host indexes a project without reading file contents. The scan is a parallel metadata walk that records stat
  keys only; a non-empty file is indexed as pending, and two low-priority host threads fill in the hashes in the
  background and push them to guests. On one 198,640-entry tree on an M4 Mac under heavy load a cold start to an
  indexed tree took about 0.6 to 1.5 s, against about 6 to 7 s when every file was hashed during the scan. A guest
  that opens a file whose hash is not known yet asks the host to resolve it, with the bytes inline up to 48 KiB, and
  writes to such a file are checked against the entry's version. The protocol version is now 2: a host and guest from
  0.1.0 cannot talk to this release (the handshake fails without naming the version), so run `csync update` on both
  machines.
* `csync update` installs the latest release over the running binary, with the install script's checks (HTTPS from
  the GitHub release, SHA-256 of the archive, exact archive contents). `--check` reports the latest version and exits
  with 10 when an update is available; `--version X` installs a specific release.
* A guest keeps nothing between sessions. When `csync join` ends it unmounts and then deletes everything it stored for
  that host: the blob cache, the ignored-path overlay (build outputs, `node_modules`, virtual environments) and the
  session marker. The tree is no longer saved as `tree.rkyv`. Every join starts from a fresh host snapshot, so a file the host
  deleted on purpose can no longer be restored or sent back. If the mount cannot be released nothing is deleted and
  the status line says so. A guest that was killed or lost power is cleaned up by the next join to that host before it
  loads anything, and refuses to start if it cannot. The identity, trust file and host key are kept, so no join pairs
  again. Dropping and restoring the link inside one session still resumes by sequence number.
* Closing a new file no longer waits for the host: the commit is queued in order and finished in the background. A
  refusal after the close shows as a notice and as an error at the next flush, fsync or write of a handle still open
  on the file. Edits to existing files still wait at close, and `fsync` always waits for the host.

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
