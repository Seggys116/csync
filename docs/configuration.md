# Configuration

csync has no configuration file. Behaviour is set by command-line flags, a few environment variables and the trust files. This page lists all of them. See [how it works](how-it-works.md) for the design behind them.

## Install

`install.sh` in the repository downloads the latest release for the current machine, checks it against its `.sha256` file and installs the `csync` binary.

| Platform | Release target |
|---|---|
| macOS, Apple silicon or Intel | `aarch64-apple-darwin`, `x86_64-apple-darwin` |
| Linux, arm64 or x86_64 | `aarch64-unknown-linux-musl`, `x86_64-unknown-linux-musl` (static) |

| Variable | Default | Meaning |
|---|---|---|
| `CSYNC_INSTALL_DIR` | `~/.local/bin` | Where the binary goes |
| `CSYNC_VERSION` | `latest` | A release tag to install instead, with or without the leading `v` |

On Linux the script also checks for `fusermount3` and prints the package to install. Building from source needs Rust 1.89 or later: `cargo install --path .` in a checkout.

A macOS guest (experimental) also needs macFUSE 5.5 or later from https://macfuse.github.io, which the install script does not install. Enable the FSKit extension in System Settings > General > Login Items & Extensions > File System Extensions (macOS 15.4 or later), or allow the macFUSE kernel extension in System Settings > Privacy & Security, which needs Reduced Security on Apple silicon. A Mac that only runs `csync host` needs none of this.

Run `csync doctor` afterwards on each machine.

## Commands

```
csync [--no-tui] <command> [options]
```

`--no-tui` is accepted by every command. `--help` and `--version` work as usual.

### `csync host [PATH]`

Serves the project at `PATH` (default: the current directory) to guests. Runs on macOS or Linux.

| Flag | Default | Meaning |
|---|---|---|
| `--listen ADDR` | `0.0.0.0:47474` | TCP address to listen on. Port 0 picks a free port, which is then advertised over mDNS |
| `--no-pair` | off | Refuse new pairings; only guests already in the trust file can connect |
| `--no-mdns` | off | Do not advertise over mDNS; guests must use `join --connect` |
| `--all-interfaces` | off | Advertise on VPN and point-to-point interfaces too |

The host checks that the listen address is free before it scans the project. The project name shown to guests is the root directory's name.

### `csync join [MOUNTPOINT]`

Connects to a host and mounts its project with FUSE. Runs on Linux, and experimentally on macOS with macFUSE 5.5 or later; on other systems it exits with code 3. On macOS, `join` first loads macFUSE's `libfuse3` and, if that fails, exits with code 3 and the message from the loader, which says what to install. It then mounts with the FSKit backend and falls back to the kernel extension. The macOS guest has not been verified against a real macFUSE mount; see [the macOS guest](how-it-works.md#the-macos-guest-experimental).

`MOUNTPOINT` must be an empty directory owned by you, or not exist yet (it is then created). On macOS a `.DS_Store` that is the only entry is removed first. Without `MOUNTPOINT`, csync mounts at `./<project>` in the current directory once a host is chosen. A stale csync mount left at that path is unmounted first.

| Flag | Default | Meaning |
|---|---|---|
| `--connect HOST:PORT` | discover over mDNS | Connect to this address. The port defaults to 47474; IPv6 addresses go in brackets; a host name resolves to its first IPv4 address when it has one. Requires `MOUNTPOINT` |
| `--host NAME` | none | Pick the host by name, project name or fingerprint prefix. With `--connect`, picks which trusted host key to expect |
| `--repair` | off | Pair again even if the host is trusted, after a host key change or a failed resume |
| `--allow-other` | off | Let other users access the mount; on Linux needs `user_allow_other` in `/etc/fuse.conf` unless run as root |
| `--cache-size SIZE` | smaller of 10 GiB and 20% of free space | Blob cache limit, for example `4G` or `512M`. See [cache size](#cache-size) |
| `--name NAME` | this machine's short hostname | Name shown to the host and stored in its trust file. At most 64 characters, no control characters or `/` |
| `--all-interfaces` | off | Discover hosts on VPN and point-to-point interfaces too |

Which host is used:

- With `--connect` and no trusted host, csync pairs. With exactly one trusted host, it resumes with that key. With several, `--host` must say which.
- Without `--connect`, csync browses mDNS. It connects on its own when `--host` matches an advertised host, or when exactly one host is trusted and that host appears. Otherwise you choose from the list.

### `csync forget SELECTOR`

Removes a paired peer from the trust file. `SELECTOR` is a peer name, a fingerprint prefix of at least 4 hex digits, or the full key. Every matching entry is removed.

A running `csync host` on this machine closes the live session of each forgotten guest at once. On a guest, forgetting the host of a running `csync join` closes that session at once: it unmounts and exits with code 4.

Prints `forgot <role> <name> <fingerprint>` per entry. Exits with 6 when nothing matched.

### `csync trust add KEY --role ROLE`

Trusts a key copied from `csync key show` on the other machine, without the interactive pairing code.

| Argument | Meaning |
|---|---|
| `KEY` | The 44-character public key |
| `--role host\|guest` | Required. What the other machine is: `host` when run on a guest, `guest` when run on a host |
| `--name NAME` | Name to remember the peer by. Default: `<role>-<first 8 hex digits of its fingerprint>` |

Adding a key that is already trusted replaces its entry. csync refuses this machine's own key.

### `csync trust list`

Prints one line per trusted peer: role, fingerprint, name. Exits with 6 when there are none.

### `csync key show [--fingerprint]`

Prints this machine's public key (44 characters of base64), creating the identity if it does not exist yet. `--fingerprint` prints the 16-hex-digit fingerprint instead: the first 8 bytes of the key's BLAKE3 hash.

### `csync doctor`

Checks the environment and prints a fix for each problem. See [doctor checks](#doctor-checks).

| Flag | Meaning |
|---|---|
| `--mount PATH` | Also check this mount point |
| `--allow-other` | Check the requirements of `join --allow-other` |
| `--json` | Print an array of `{"check", "level", "detail", "fix"}` objects |

Exits with 3 if any check fails.

### `csync status [--json]`

Shows every csync session running on this machine under the same user and `CSYNC_HOME`, by asking each one over its control socket. `--json` prints an array with one object per session. Exits with 5 when no session is running.

### `csync update [--check] [--version VERSION]`

Installs the latest release over the running binary, with the trust model of `install.sh`: HTTPS from `github.com/Seggys116/csync` releases only, the archive checked against its published `.sha256` file before anything is unpacked, and exactly `LICENSE`, `README.md` and `csync` in the archive. It uses the system `curl` and `tar`, picks the same release target as the install script, and refuses to run when neither is on `PATH`.

The latest release is the tag that `https://github.com/Seggys116/csync/releases/latest` redirects to, and the archive is then fetched from that tag. The new binary is written beside the running one, run once with `--version` to confirm it reports the expected version, and renamed into place, so a failed update never leaves a partial binary. Running `host` and `join` sessions are not touched; restart them to use the new version.

| Flag | Meaning |
|---|---|
| `--check` | Print the current and latest versions and install nothing. Exits with 10 when an update is available, 0 when up to date |
| `--version VERSION` | Install this release instead of the latest, with or without the leading `v`; only letters, digits, `.`, `+` and `-` are accepted. An older version is installed as a deliberate downgrade |

Without `--version`, `update` does nothing when the running version is already the latest or newer. It leaves a binary in a directory you cannot write, or one that a package manager owns (Homebrew, Nix, `/usr/bin`), alone and exits with 3, naming the install script or the package manager to use. It never runs `sudo`.

### `csync bench`

Hidden from `--help`. Runs local micro-benchmarks. Flags: `--path PATH` (tree to scan, default the current directory), `--quick`, `--json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Failure not covered below (for example the listen port is in use) |
| 2 | Usage: bad arguments, project root not a directory, `--connect` without `MOUNTPOINT`, several trusted hosts without `--host` |
| 3 | Environment: FUSE or mount point problems (on macOS, a missing or too old macFUSE), `join` on a system other than Linux or macOS, an unreadable or insecure identity or trust file, a failed `doctor` check |
| 4 | Trust or pairing refused (host key mismatch, pairing declined or timed out, guest revoked), or another permission error |
| 5 | `status` found no running session |
| 6 | `forget` or `trust list` matched nothing |
| 10 | `update --check` found a newer release |
| 130 | Interrupted by SIGINT, or stopped by a second signal before a clean shutdown finished |

## Terminal interface

`host` and `join` show a full-screen interface when stdin and stdout are terminals.

| Key | Where | Action |
|---|---|---|
| `q`, `Ctrl-C` | both | Quit cleanly. Pressed again during shutdown, exit at once |
| `Up`, `k` / `Down`, `j` | both | Move the selection in the guest list (host) or host list (guest) |
| `a` | host | Accept the pending pairing request |
| `r` | host | Reject the pending pairing request |
| `x`, then `y` | host | Revoke the selected guest: remove its key and close its session. Any key other than `y` cancels |
| `y` / `n` | guest | Confirm or decline the pairing code |
| `Enter` | guest | Join the selected host from the discovery list |

SIGINT, SIGTERM and SIGHUP ask for a clean shutdown; a second signal exits at once.

Colours follow the terminal: a non-empty `NO_COLOR` turns them off, `COLORTERM=truecolor` or `24bit` enables 24-bit colour, and a `TERM` containing `256` or `direct` enables 256 colours. With `TERM=dumb`, or when the terminal cannot be set up, csync falls back to the line protocol below.

## Line protocol

Without a terminal on stdin or stdout, or with `--no-tui`, `host` and `join` print one record per line and read commands from stdin. This is meant for scripts, agents and CI.

### Records

Each record is `kind key=value ...`. Values are percent-escaped: any byte that is not printable ASCII, and `%` and `=`, become `%XX`, so a record always splits on spaces.

Records printed as the state changes:

| Kind | Fields |
|---|---|
| `session` | `role`, `pid`, `project`; on a host `root` and `listen`; on a guest `host` (address), `mount` and `mounted` |
| `mounted`, `unmounted` | `path` |
| `peer` | `id`, `name`, `fpr`, `state`, and per state: `sas` (pairing), `done` and `total` (syncing), `since_ms` (disconnected). `peer id=N state=gone` when a peer leaves |
| `pairing` | `peer`, `name`, `sas`, `expires_ms`, `reply` (`accept\|reject` on a host, `confirm yes\|no` on a guest). `pairing state=closed` when the request ends |
| `found` | A host seen during discovery: `index`, `label`, `addr`, `fpr`, `paired` |
| `notice` | `ts` (Unix ms), `kind`, `path` |
| `stats` | `files`, `cached_bytes`, `cache_cap`, `fetches`, `commits`, `merged`, `refused`, `tx`, `rx`, `inject_backlog`, `skew_ms` |
| `hint` | `text` |
| `signal` | `number`, `action` (`quit` or `exit`) |
| `error` | `text`, for a command that could not be parsed or delivered |
| `help` | `text` |

`state` is one of `waiting`, `discovering`, `handshaking`, `pairing`, `syncing`, `live`, `disconnected`. Notice kinds are `refused`, `merged`, `promoted`, `discarded`, `resynced` and `rules`.

### Commands

One command per line, at most 4,096 bytes.

| Command | Action |
|---|---|
| `accept [ID]` | Host: accept the pending pairing (or the one from peer `ID`) |
| `reject [ID]` | Host: reject it |
| `confirm yes\|no` (or `yes`, `no`) | Guest: confirm or decline the pairing code |
| `join N` | Guest: join the host listed in `found index=N` |
| `revoke ID` | Host: revoke the guest with peer id `ID` |
| `status` | Print a full report (below) |
| `help` | Print the command list |
| `quit` (or `exit`) | Shut down cleanly |

### Status report

The `status` command and `csync status` print a full report: `session`, then one `peer` per peer (with `rtt_us`, and `tx`, `rx` and `pending` where known), `pairing`, one `host` per discovered host (same fields as `found`), `stats`, a `guest` record on guests (`hits`, `misses`, `inflight`, `prefetch_done`, `prefetch_total`, `passthrough`), the last 20 `notice` records and every `hint`.

`csync status --json` turns each report into one object: `session`, `stats`, `guest` and `pairing` become objects, and the repeated kinds become arrays named `peers`, `hosts`, `notices` and `hints`. Counters and `true`/`false` fields are JSON numbers and booleans.

## Directories and files

| | macOS | Linux and others |
|---|---|---|
| config | `~/Library/Application Support/csync` | `$XDG_CONFIG_HOME/csync` (default `~/.config/csync`) |
| state | `~/Library/Application Support/csync/state` | `$XDG_STATE_HOME/csync` (default `~/.local/state/csync`) |
| cache | `~/Library/Caches/csync` | `$XDG_CACHE_HOME/csync` (default `~/.cache/csync`) |

When `CSYNC_HOME` is set to an absolute path, the three are `$CSYNC_HOME/config`, `$CSYNC_HOME/state` and `$CSYNC_HOME/cache` instead. This keeps separate identities apart on one machine, for example a host and a guest under test. `XDG_*` variables are used only when they hold absolute paths, and `HOME` must be absolute.

Every directory csync creates has mode 0700, and private files have mode 0600. csync refuses to use any of these directories, or a trust file, that is owned by another user or accessible to group or others.

| Path | Side | Contents |
|---|---|---|
| `config/identity` | both | The 32-byte X25519 secret key |
| `config/peers` | both | The trust file, see [trust files](#trust-files) |
| `state/projects/<id>/index.rkyv` | host | Saved index for one project root and, on macOS, the FSEvents resume token. `<id>` is 12 hex digits derived from the canonical root path. Files whose hash the host has not computed yet are saved as pending and stay so until the hasher reaches them |
| `state/projects/<id>/index.rkyv.clean` | host | Written after a clean shutdown and consumed on the next start |
| `state/hosts/<fpr>/session.live` | guest | Marker written when a session starts and removed only by the wipe at its end. Finding it at the next start means the earlier session did not end cleanly |
| `state/hosts/<fpr>/overlay/` | guest | Guest-only files for paths the host ignores, for the length of one session |
| `cache/<fpr>/blobs/<xx>/<hash>` | guest | Cached file contents, named by BLAKE3 hash, sharded by its first byte; for one session |
| `cache/<fpr>/tmp/` | guest | Blobs being filled |
| `cache/<fpr>/lru.bin` | guest | Cache recency, used to pick eviction order inside the session |
| `state/run/host-<id>.sock`, `state/run/guest-<id>.sock` | both | Control sockets used by `status` and `forget`, mode 0600, one per running session. `<id>` derives from the project root or mount point |

If the control socket path would exceed the Unix socket path limit, csync uses `csync-<uid>` under the system temporary directory instead of `state/run`.

Everything a guest keeps for a host (`state/hosts/<fpr>/` and `cache/<fpr>/`, the overlay and the blob cache included) is temporary. When a guest session ends, after the unmount, csync deletes both directories; if it was killed or crashed, the next `csync join` to that host deletes them before anything is loaded, and refuses to start if it cannot. Nothing in them is ever restored on a later join, so a file the host deleted cannot come back. The wipe stays inside those two directories: `config/identity`, `config/peers` and the host key are never touched, so a join after a wipe does not pair again. If the mount cannot be released, nothing is deleted and the status line says so. A `tree.rkyv` or other file left by an older csync in `state/hosts/<fpr>/` is deleted the same way.

`csync doctor` briefly creates and removes `.doctor-<pid>-a` and `-b` files in the cache directory to test reflink support on Linux. On macOS it only creates the cache directory if it is missing and reads the filesystem type of its volume.

On a macOS guest the overlay for ignored paths is `state/hosts/<fpr>/overlay.noindex/` instead of `state/hosts/<fpr>/overlay/`, so that Spotlight does not index it. Time Machine is not told to skip it, but it is wiped when the session ends, like the rest.

## Environment variables

| Variable | Read by | Meaning |
|---|---|---|
| `CSYNC_HOME` | all commands | Root for the config, state and cache directories |
| `HOME` | all commands | Base for the default directories; must be absolute |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME` | all commands, not macOS | Override the default directory locations |
| `XDG_CONFIG_HOME` | host | Also locates git's default global excludes file, `$XDG_CONFIG_HOME/git/ignore` |
| `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_GLOBAL` | host | Which git config files csync reads for `core.excludesFile` when the `git` command cannot be run |
| `NO_COLOR`, `COLORTERM`, `TERM` | `host`, `join` | Colour depth of the terminal interface; `TERM=dumb` selects the line protocol |
| `PATH` | `doctor` | Where to look for `fusermount3` on Linux (also `/usr/bin`, `/bin`, `/usr/local/bin`) |

When csync runs `git` on the host, it removes `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE` and the other repository-selecting variables from its environment and sets `GIT_OPTIONAL_LOCKS=0`, `GIT_TERMINAL_PROMPT=0` and `LC_ALL=C`.

## Cache size

The guest's blob cache for each host has a size cap. The cache is deleted when the session ends, so the cap bounds the disk one session can use and nothing carries over to the next join:

- Default: 20% of the free space on the filesystem holding the cache directory, at most 10 GiB, measured when `csync join` starts.
- `--cache-size SIZE` sets it directly. `SIZE` is a number with an optional unit `K`, `M`, `G` or `T` (also `KB`/`KiB` and so on; all binary multiples, case-insensitive). Decimals are allowed, for example `1.5G`. The minimum is 256 MiB.

When the cache passes its cap, the least recently used blobs are removed until it is at 95% of the cap. Blobs of open files are never removed, and blobs opened in the last 15 minutes go only when nothing else is left. Background warming stops once the cache reaches 90% of the cap.

Staging copies of files being written are anonymous temporary files on the cache filesystem. On a filesystem that supports reflinks (`FICLONE` on Linux, `clonefile` on APFS) they share blocks with the cached version; otherwise they are full copies. `csync doctor` reports which applies.

## Trust files

`config/identity` holds the 32-byte secret key. It is created on first use, and the public key derived from it is what `csync key show` prints.

`config/peers` has one line per trusted peer:

```
<role> <base64 public key> <name> <unix time added>
```

`role` is `host` or `guest`. Names may contain spaces but no control characters. Empty lines and lines starting with `#` are skipped when loading, but csync rewrites the whole file whenever it changes it, so comments do not survive. The file is replaced atomically, and a file larger than 1 MiB or with a malformed line or duplicate key is refused.

To set up trust without pairing (for CI), run `csync key show` on each machine, then `csync trust add <host key> --role host` on the guest and `csync trust add <guest key> --role guest` on the host.

## Doctor checks

Checks run in this order. Linux-only checks are skipped on macOS and macOS-only checks on Linux. The macOS guest checks are written for the experimental macOS guest and have not been run against a real macFUSE install.

| Check | Platform | Passes when |
|---|---|---|
| `/dev/fuse` | Linux | It can be opened for reading and writing |
| `fusermount3` | Linux | Found on `PATH` and setuid root, or csync runs as root |
| `kernel` | Linux | 5.15 or later; reports whether FUSE passthrough (6.9 or later) is available |
| `CAP_SYS_ADMIN` | Linux | Present (warning when absent: file data is served by csync instead of kernel passthrough) |
| `fuse.conf` | Linux | `user_allow_other` is set in `/etc/fuse.conf`, or running as root; checked only with `--allow-other` |
| `macFUSE` | macOS | `/Library/Filesystems/macfuse.fs` exists and its version, read from `Contents/Info.plist`, is 5.5 or later (warning below 5.5). A missing install is information only unless `--mount` is given, when it fails, because only `join` needs it |
| `libfuse3` | macOS | `/usr/local/lib/libfuse3.4.dylib` loads and provides what csync needs; on failure the message says what to install. Skipped when macFUSE is not installed |
| `FSKit module` | macOS | `pluginkit -m -i io.macfuse.app.fsmodule.macfuse` lists the extension as enabled (warning otherwise: csync falls back to the kernel extension). Enable it in System Settings > General > Login Items & Extensions > File System Extensions. Skipped when macFUSE is not installed |
| `kernel extension` | macOS | Information only: whether the macFUSE kernel extension is loaded, which matters only when the FSKit backend cannot mount. Skipped when macFUSE is not installed |
| `macOS` | macOS | Darwin 24.4 (macOS 15.4) or later, which the FSKit backend needs (warning below) |
| `mount point` | Linux, macOS | The `--mount` path is missing, or an empty directory you own, and not a stale mount. On macOS a lone `.DS_Store` is accepted and removed by `join` |
| `stale mounts` | Linux, macOS | No csync mount on this machine is dead: `ENOTCONN` on Linux, `ENOTCONN` or `ENXIO` on macOS, where mounts are found from the output of `mount` |
| `cache space` | all | At least 2 GiB free under the cache directory; also prints the default cache cap |
| `reflink` | Linux | The cache filesystem supports reflinks (information only) |
| `clonefile` | macOS | The cache volume is APFS, so staging copies are clones (information only) |
| `max_user_watches` | Linux | `fs.inotify.max_user_watches` is at least 524,288, which matters for a Linux host |
| `clock skew` | all | A running session measured less than 1 s between host and guest |
| `git` | all | `git --version` runs; without git on a host, tracked files under ignored paths are not synced |
| `trust files` | all | The config directory and trust files are private to you |

Each result is `pass`, `info`, `warn` or `fail`, followed by a suggested fix where there is one.

## Network

| What | Where |
|---|---|
| Sync traffic | TCP, host port 47474 by default (`--listen`), guest connects out |
| Discovery | mDNS service `_csync._tcp.local.` |

The host registers the instance `<project>-<first 8 hex digits of its fingerprint>` (project name cut to 40 bytes) on the host name `csync-<fingerprint>.local.`, with these TXT fields:

| Field | Value |
|---|---|
| `p` | Project name, cut to 200 bytes |
| `v` | Protocol version (currently 2) |
| `k` | The host key's 16-hex-digit fingerprint |

Guests ignore advertisements with a different protocol version, without a port or without a usable address, and use at most 8 addresses per host, IPv4 first. Link-local IPv6 addresses are skipped.

By default both advertising and discovery skip point-to-point interfaces and interfaces whose names start with `utun`, `tun`, `tap`, `wg`, `ppp`, `ipsec`, `tailscale`, `zt`, `gif`, `stf`, `awdl` or `llw`. `--all-interfaces` includes them. If mDNS is unavailable on your network, start the host with `--no-mdns` and join with `--connect`.
