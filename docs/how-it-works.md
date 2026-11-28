# How csync works

csync keeps one project directory on a macOS host and a FUSE mount on a Linux guest (or, experimentally, a macOS guest) in step, in both directions. This page covers the design behind the README: the components, what happens on a read or a write, ignore rules, the wire protocol, trust, and how it fails.

## Purpose

The host directory is the source of truth. The guest sees the same tree through a FUSE mount and can read and write it as if it were local. The intended use is two editors working on one project at the same time, typically one coding agent (or person) on the Mac and another inside a Linux VM, without a shared filesystem, rsync loops or manual pushes.

When both sides change the same file, the later write is checked against the version it started from. If the host's copy moved on, the guest merges the two edits when it can and otherwise refuses its own write. Nothing is overwritten silently and no conflict copies are left behind.

## Components

### Host (`csync host`)

| Part | What it does |
|---|---|
| Watcher | FSEvents on macOS, inotify on Linux. FSEvents keeps a resume token (volume UUID and last event id) so a restart can replay what happened while the host was down. inotify watches only directories that are synced or under `.git`. |
| Index and journal | An in-memory tree of every synced path with its stat key, a sequence number and, once known, its BLAKE3 content hash. The scan does not read file contents, so a non-empty file starts without a hash ("pending"); see [lazy hashing](#lazy-hashing). Each change is also appended to a journal of up to 262,144 entries so a guest that reconnects can be sent only what it missed. The index (not the journal) is saved to disk every 60 s when it changed, and on exit, and the saved index can contain pending entries. |
| Hasher | Two low-priority threads that fill in the hashes of pending files in the background and push them to guests. See [lazy hashing](#lazy-hashing). |
| Applier | Merges watcher bursts, stats each path, reads and hashes a file at once only when its stat key changed, updates the index and pushes the resulting changes to guests. |
| Committer | One thread that applies every guest write in order: commits, mkdir, symlink, remove, rename and attribute changes. |
| Serve pool | Four threads that answer guest requests for whole files, deltas and ranges of files that still need hashing, plus two light threads for version resolution, hash lookups, batches of small files, small files and ranges, so a large transfer never queues them. |

### Guest (`csync join`, Linux; macOS is experimental)

| Part | What it does |
|---|---|
| FUSE mount | On Linux, built on `fuser`, 8 worker threads. On macOS it goes through csync's own binding to macFUSE's `libfuse3` (see [the macOS guest](#the-macos-guest-experimental)). Lookups, `getattr` and `readdir` are answered from memory without a round trip. |
| In-memory tree | The whole metadata tree, received as a snapshot on connect and kept current by pushed changes. It lives only in memory: nothing is saved to disk, and every join starts from a fresh snapshot. A link that drops inside a running session still resumes by sequence number. |
| Blob cache | File contents stored by content hash on local disk. A new blob is checked against its hash before it is stored. The cache belongs to one session: it is deleted when the session ends. |
| Overlay | Paths the host's ignore rules exclude (`target/`, `node_modules/`, `.env` and so on) live only on the guest, in a private overlay directory, for as long as the session runs. The overlay is deleted when the session ends, so build outputs, `node_modules` and virtual environments are rebuilt on the next join. |
| Session wipe | When a guest closes its session (the `q` key, SIGINT, SIGTERM, a revoked or forgotten host, or an error) csync unmounts, then deletes this host's whole state directory and blob cache. Only the identity, the trust file and the host key are kept, so the next join needs no new pairing. If the mount cannot be released the wipe is skipped, and a message on the status line says so. See [failure behaviour](#failure-behaviour). |
| Prefetch | After each connect it fetches ignore files, common manifests (`Cargo.toml`, `package.json`, `go.mod` and others) and git metadata first, then warms every file up to 1 MiB breadth-first until the cache is 90% full. Files whose hash is not known yet are fetched by version, many in one round trip. Git object directories come last, and pack files are fetched only when read. A cold open of a small file also fetches its directory's small files in one burst (see [the life of a read](#the-life-of-a-read)). It runs at a lower CPU priority and yields while a write waits on the host. |
| Injector | Replays host changes through the mount itself so inotify watchers on the guest see them. See [a host edit reaching the guest](#a-host-edit-reaching-the-guest). |

### The macOS guest (experimental)

`csync join` is also implemented for macOS. It has only run against macFUSE on CI runners so far, so treat what is not marked as measured below as the design, not as measured behaviour.

What is implemented:

- **Binding.** csync has its own binding to macFUSE's `libfuse3`, loaded with `dlopen` from `/usr/local/lib/libfuse3.4.dylib` when `csync join` starts, so the binary needs no macFUSE at build or install time. If the library is missing, not owned by root, or older than macFUSE 5.5, `csync join` exits with code 3 and a message that says what to install.
- **Backends.** It mounts with the FSKit (user-space) backend first and falls back to the macFUSE kernel extension. FSKit needs macOS 15.4 or later and the FSKit extension enabled; the kernel extension needs to be allowed with Reduced Security on Apple silicon.
- **Mount options.** `noappledouble`, `noapplexattr` and `nobrowse`, besides `nodev`, `nosuid`, `noatime` and `default_permissions`. They keep `._*` files and Finder volume entries out of the project. A `.DS_Store` that Finder left as the only entry of the mount point is removed before mounting; any other content makes `csync join` refuse the directory.
- **Attribute lifetime.** FSKit has no kernel invalidation, so the guest cannot ask the kernel to drop a cached inode or entry as it does on Linux. Attribute and entry lifetimes on the mount are therefore short, and the mechanism that makes a host change visible is the injected operations described under [event injection](#event-injection), not invalidation.
- **Overlay.** Ignored paths live in `overlay.noindex` inside the host's state directory, a name that Spotlight does not index. Like the Linux overlay it is deleted when the session ends.
- **Names.** Lookups are exact: `cat README.md` does not find `readme.md`, even though the default macOS volume folds case.

- **Injector root.** The FSKit volume can appear in the mount table 1.4 to 5.5 s after the mount call returns (measured on GitHub Actions macOS 15.8 and 26.7 runners with macFUSE 5.5.0). A directory opened before that is the plain APFS directory under the mount point, and every injected operation on it lands on APFS, never reaching the handlers. The injector thread therefore polls every 20 ms, for at most 30 s, until the mount point shows a macFUSE or FSKit filesystem type (`statfs`) or a device other than the one that was under it before the mount, and only then opens its root. Before every injected event it checks that the root's device is the volume's and not the pre-mount one, and reopens it once if not. If the volume never shows, or the root cannot be verified for an event, nothing is injected on the underlying directory: the events settle without being replayed, and the status line says so (`inval=off` and a hint).
- **Request identity.** FSKit delivers every request with pid, uid and gid 0, so the process id cannot recognise the injector's own requests. The startup self-test (run only after the root is verified) decides between recognising by process id (the request pid is csync's), by an armed window (pid not csync's and a uid or gid that is not csync's, as FSKit sends), or not replaying at all. See [event injection](#event-injection).
- **Directory listings.** A directory handle's listing is made again each time the kernel rewinds to offset 0 on it, and later offsets continue that snapshot; the first read of a freshly opened handle uses the listing `opendir` made. Before this, a rewound read was served the snapshot taken at open, so a host change never showed through a handle the kernel kept.
- **Status.** The session line of `csync status` and the status row of the terminal view name the backend and how a host change reaches the kernel: `backend=fskit` or `kext`, and `inval=native` (kernel notifications work), `injected` (replayed through the mount), `off` (not replayed) or `probing` (the self-test has not finished).

Measured on the FSKit backend with a correctly opened root and replay forced on: a host-created file showed by listing in 43 ms, by lookup in 44 ms, and a host edit in 119 ms. A listing refreshed in 42 to 180 ms with only the directory fix, but a lookup of a name that had been looked up before it was created stayed `ENOENT` for 60 s; the injected create clears that negative entry.

What is not known until it has been run:

- the self-test's attribute, entry and data steps (whether FSKit honours kernel notifications) have never been observed on a correct root, so `inval=native` or `injected` is not yet measured;
- whether FSEvents reports the operations the injector performs through the mount, which is what a watcher such as a dev server relies on;
- whether the FSKit backend keeps its caches coherent with a host edit that arrives while a file is open;
- whether FSKit passes the file handle in a truncate; a truncate with no handle is accepted as the injector's while its operation is armed;
- throughput and latency, for either backend.

Missing on macOS compared with Linux: no kernel passthrough, no writeback cache and no `readdirplus`, so every read of a synced file and every directory listing goes through csync.

## Lazy hashing

The host does not read file contents to start. The scan (`cook` in `src/index/scan.rs`) records each entry's stat key and reads no file to hash it (it reads only the `.gitignore` files it needs for ignore rules), so the content hash of a file is not known when the index is first built:

- A non-empty regular file with no hash already in the index is indexed as pending (`Meta.hash` is empty). An empty file gets the hash of empty content at once. A rescan, for example after a restart without a usable FSEvents resume token, keeps a known hash when the stat key is unchanged and leaves a new or changed file pending.
- Changes the watcher reports are different: the applier still reads and hashes a file whose stat key changed before it enters the index.
- Starting to index is therefore a metadata walk. Measured once on a tree of 198,640 entries on an M4 Mac that was under heavy load, a cold start to a complete index took about 0.6 to 1.5 s. The earlier design, which hashed every file during the scan, took about 6 to 7 s on that tree, and a parallel walk that still hashed took about 3.5 s. These figures come from that one tree and that machine state.

The walk itself is parallel and per directory. It uses up to `min(cores, 8)` workers, which start once enough directories are queued to share. Each directory is read by one worker through a descriptor handed down from its parent, and the per-directory results are merged into the tree in breadth-first order from the root.

### Versions

The content version `ver` of a file is the sequence number of its host index entry, qualified by the index identity as a `VerKey` (index id, `ver`, size). A hash that is filled in later does not change the entry's sequence number, so a `VerKey` names a version before anyone has its hash. When the host observes the file change, the entry gets a new sequence number, so an old `VerKey` stops matching.

### The host hasher

`src/host/hasher.rs` runs two threads at lower priority that hash pending files in this order:

1. directories a guest has asked about,
2. rule files, common manifests and the `.git` files git reads first,
3. files up to 1 MiB,
4. everything else.

The threads wait while the host is serving a request or applying a commit, but for at most 50 ms at a time. They read with plain BLAKE3 in 4 MiB reads. A hash is accepted only if the file's stat key (including ctime) is the same after the read as before, and only if the index entry is still the same version; otherwise it is dropped and the entry stays pending.

Learned hashes are buffered for up to 100 ms (or 8,192 hashes) and pushed to live guests in batches (`Push::Hashes`) on the bulk queue. A push is droppable: a guest whose queue is full misses it. When no pending entry is left, the host sends `Push::HashesDone`, and the guest then asks for whatever hashes it still lacks (`Op::Hashes`). That request is a pure index lookup: it returns a hash only for an entry at exactly the asked sequence number whose hash is already known, and it never hashes.

### What the guest does with hashes

- A pushed or pulled hash is a claim. It only labels a node, and the guest never stores bytes under a hash they do not match: every blob is checked against the hash it was asked for before it enters the cache.
- Opening a pending file sends `Op::Resolve`. The host hashes the file, checks that it did not change meanwhile and returns the hash, with the bytes inline for a file up to 48 KiB. A longer file is then fetched by that hash as usual.
- A fetch can also name a version instead of a hash (`Want::Ver`). The prefetcher uses this with `FetchMany` to warm many pending files in one round trip.
- A pushed hash does not by itself start a fetch. For a file nobody has opened or read, the running walk reaches it in its turn, and a walk that is already idle queues it as background work. A file that has been opened or read is fetched at once, because a new version of it is likely wanted.
- Rule files never depend on the background hasher. Before the mount, the guest fetches its pending rule files by version in batches (`resolve_pending` in `src/guest/mod.rs`), so ignore rules are known first.
- A guest operation on a pending file carries `Expect::Ver`, described under [compare-and-swap](#compare-and-swap-on-the-host). The guest never sends `Expect::Any` for a file it knows from the host.

## The life of a read

1. `open` on the guest finds the node in memory. If the file's hash is known and the blob is in the cache and complete, the file is served from it.
2. csync answers each `read` from the blob file, and the kernel keeps those pages cached across opens until the content changes, so a warm file is read from memory. Synced files are not read through FUSE passthrough; see Passthrough under [known limitations](#known-limitations) for why.
3. On a cache miss, the first `read` sends one fetch for that content hash. Concurrent readers of the same hash share it. The read waits only for the bytes it asked for. If the hash is not known yet, the open first resolves the version (see [lazy hashing](#lazy-hashing)), which also brings the bytes of a file up to 48 KiB.
4. Files of 64 MiB or more are fetched in 4 MiB ranges into a sparse blob. Files between 1 MiB and 32 MiB whose previous version is still cached are fetched as a delta against it.
5. A cold open of a synced file up to 48 KiB that has not been opened or read before takes the directory's other small files with it. Siblings with a known hash go out with the file's own bytes in one `FetchMany` that a reader of any of them waits on. Pending siblings are fetched by version in the same burst, and the tree learns their hashes from the answer. The burst is capped at one `FetchMany` part (1 MiB) and 512 files, skips files over 256 KiB, and is skipped when it would take the cache past 90% of its cap or when fewer than two files qualify. Fetched batches are stored on short-lived `csync-land` threads, so a reader waiting on one is not held up by the network reader or the prefetch thread.
6. Every cold open also hints the prefetcher, which continues with the rest of the directory's small files (each up to 256 KiB, 4 MiB in total). Eight cold opens within 50 ms make the prefetcher favour the directories being scanned: its background batches use a wider in-flight window, except once the walk has reached the git object stores, which a working-tree scan does not read.

The host serves only files that are in its index as synced or `.git` content, and only if the file on disk still has the stat key the index recorded. A file that changed underneath gets a "gone" answer, and the guest then serves whatever replaced it once that change arrives.

## The life of a write

### Close and fsync

1. Opening a synced file for writing creates a staging copy in the cache filesystem: an anonymous temporary file, cloned from the base blob with a reflink where the filesystem supports it, copied otherwise. The version the file was opened at is remembered as the base.
2. Writes go to the staging copy.
3. On `close` (FUSE flush) or `fsync`, if the content changed, the guest hashes it and sends a commit carrying the base version. The body is inline up to 48 KiB, a delta for files between 1 MiB and 32 MiB when the base is cached, and streamed in chunks otherwise.
4. An edit to a file the host already has waits for the host's answer at close, so a refused commit fails the `close` with `ECANCELED`. A new file (made by this guest, not yet on the host) does not: its commit is queued in the ordered stream when the file is flushed or released, which is before any later operation on it, and the close returns without waiting for the host. The guest keeps the staging copy until the answer arrives, and a background thread then records the host's version or runs the merge, as a close that waited would have. `fsync` always waits for the host's answer.
5. A refusal after a new file's close (a conflict that cannot be merged, a refused commit, retries that ran out) posts the `refused` notice and rolls the file back as described under Refusal. If a handle of the file is open then, its next `flush`, `fsync` or `write` fails once, with `ECANCELED` for a refused merge and the commit's own error otherwise.

### Entries the host has not answered for

Everything the guest sends to the host goes through one ordered stream, and the host applies it in that order. An entry this guest made and the host has not acknowledged yet (a new directory, a new symlink, a new file) is the guest's own until the host answers, so the operations that follow on it do not wait:

- `mkdir` and `symlink` check everything the guest can decide itself first (a name that exists or only differs in case, an invalid name, `.git`, the guest-only overlay) and fail with the same errors as before. Then the entry is added to the guest's tree, its `mk` is queued, and the call returns. A file or directory made inside it is queued after it, so the host sees the parent first without any dependency tracking. Lookups, listings and reads treat the entry as live, and a host remove of its path that arrives meanwhile is ignored, because the guest's own `mk` lands after it. A host entry of the same kind at that path replaces the entry's metadata; one of another kind wins, and what was queued below it then fails on the host.
- `chmod` and `utimes` of such an entry are queued behind its creation and return at once. For a new file the change is first merged into its commit if that has not been sent, or recorded for the commit when the file is still open. A commit that is the last thing in the queue and does not ask for durability waits up to 1 ms before it is sent, so the change that usually follows a close can still be merged into it; any other operation queued behind it ends the wait at once, and a commit made for `fsync` never waits. When the commit has already gone out, the change is sent as its own `setattr` that expects the version just committed.
- `fsync` still waits for the host's answer to its own commit, and since everything before it in the stream has been applied by then, one `fsync` of the last file is a barrier for the directories and files created before it. A refused ancestor makes it fail.

What the host decides is only learned later, so a refusal arrives after the call has returned (see Refusal). Renames, unlinks, and changes to an entry the host already has are not part of this and still wait for the host.

Every close of any copy of a file descriptor counts, so a shell redirection (`exec 3<>f; printf A >&3` closes a duplicate of the descriptor when it restores stdout) or a child process that inherits the descriptor and exits commits the write at that moment, not when the original descriptor is closed. A host program that read the file before that commit and then saves its older copy overwrites the guest write, and csync cannot detect it, because host writes are plain filesystem writes with no compare-and-swap.

### Compare-and-swap on the host

The committer applies a commit only if the file on disk still matches the base:

1. It writes the new content to a temporary file named `.csync~...` in the destination directory, created with `O_EXCL` and never following symlinks.
2. It opens the destination and checks it against the base the guest sent. A base that is a hash (`Expect::Is`) is compared with the file's current hash, taken from the index when the stat key matches and computed on the spot otherwise, so it is never an unverified hash. For a file whose hash the guest does not know yet the base is a version (`Expect::Ver`): it holds only if the index entry's sequence number equals that version and the file's live stat key still equals the indexed one. If the base does not hold, it replies with a conflict that carries the current version, and its bytes when they fit in 48 KiB.
3. It swaps the temporary file and the destination in one atomic rename-exchange, then checks that the old inode was not modified in the meantime. If it was, it swaps back and replies with a conflict. Otherwise it removes the old file.
4. It records the new stat key and hash in the index, so when the watcher reports the write it matches the index and is not sent out a second time. Other guests receive the change; the guest that made it does not.

A commit whose content is already on disk (a replay after a reconnect, for example) is answered as done.

### Merge on the guest

On a conflict the guest runs a three-way merge of base, its own content and the host's current content. It merges only when all three are UTF-8 text without NUL bytes and each is at most 8 MiB. A clean merge is written into the staging copy and committed again with the host's version as the new base. This loop runs at most three times.

### Refusal

If the merge has conflicting regions, a side is binary or too large, or the retries run out, the guest refuses its own write:

- the staging copy is replaced with the host's current content (or emptied when that is not available),
- the `close` or `fsync` that triggered the commit fails with `ECANCELED` (for a new file, whose close does not wait, see Close and fsync),
- a `refused` notice appears on both sides.

No backup, conflict copy or marker file is written on either side. The host's temporary file is removed whenever a commit does not complete.

A directory or symlink the guest made without waiting (see Entries the host has not answered for) can be refused after the call that made it returned. The guest then rolls it back:

- what is still queued below it is dropped and what was already sent fails on the host by itself, so nothing is created under a path that was refused;
- the entry and everything below it are removed from the guest's tree bottom-up, and the kernel's cached entries are invalidated;
- one `refused` notice is posted, for the root of what was removed;
- a handle still open on a file below it gets `ECANCELED` for a refusal, `EFBIG` when the host is out of space or the file is too large, and `EIO` otherwise, at its next `flush`, `fsync` or `write`, once. The same applies when a queued `chmod` or `utimes` of a file is refused. A queued change that finds the host's entry replaced by a host save leaves the host's version in place.

If the host says the path is ignored, the entries are not deleted. When the guest's own rules agree they are moved to the guest-only overlay, as for an ignore rule this guest wrote itself; when they do not, the entry is refused like any other.

### Atomic saves

Editors often save by writing a new temporary file and renaming it over the original. csync handles this in one round trip in the common case:

1. The new temporary file's first commit is sent without waiting for the answer, so its `close` returns at once.
2. The `rename` carries an expectation for the destination: the version last served to an open of it. If the temporary file's content has not reached the host, it travels inside the rename request.
3. On a conflict the guest merges with the expected version as base, the temporary file as its side and the host's current file as theirs, as above.
4. If that is refused, the `rename` fails with `ECANCELED`, and the temporary file is removed on both the guest and the host.

### Other write rules

- Moving a file between the overlay and the synced tree commits its content to the host or copies it into the overlay. Moving a directory across that boundary fails with `EXDEV`.
- On a case-insensitive host volume, creating a synced name that differs only in case from an existing one fails with `EEXIST`. On any macOS volume the same holds for names that differ only in Unicode normalisation (`é` as one code point or as `e` plus a combining accent).
- Renaming an entry to another spelling of its own name (`mv readme.md README.md`, `git mv src Src`) works on both sides: the host renames it in place.
- When a guest edit replaces a host file, the new file keeps the old one's extended attributes and ACL (Finder tags, quarantine, resource forks).

## A host edit reaching the guest

1. The watcher reports the path. The first event after 50 ms of quiet is applied at once; a burst is gathered until 1 ms of quiet or 50 ms after its first event, one entry per path. More than 262,144 distinct paths, or a watcher overflow, turns the burst into a full rescan that waits for 200 ms of quiet (5 s at most).
2. The applier stats each path, hashes files whose stat key changed, and turns the differences into upserts, removes and renames, sent in batches of up to 8,192 changes.
3. The guest applies each batch to its tree and acknowledges it. Kernel attribute and entry caches on the mount last 24 hours, so the guest relies on explicit invalidations: it asks the kernel to drop the cached inode or directory entry for everything that changed. Only one thread sends these notifications, and never while it holds the tree lock.
4. The guest also hands an event to the injector.

### Event injection

The kernel raises inotify events only for operations that pass through the mount, and an invalidation is not one of them. So csync performs a matching operation on the mount from a dedicated thread. The FUSE handlers recognise that thread's requests and apply them locally instead of forwarding them to the host.

| Host change | Operation through the mount | What watchers see |
|---|---|---|
| New file, directory or symlink | The node stays hidden until the injector creates it (`O_CREAT` and `O_EXCL`, `mkdir`, `symlink`); a file with content is also truncated to its size before the close | `IN_CREATE`, then `IN_MODIFY` and `IN_CLOSE_WRITE` for a file |
| Modified file | Open for writing, then truncate to the current size; content is untouched | `IN_MODIFY`, `IN_CLOSE_WRITE` |
| Modified file without an owner write bit | `chmod` to the same mode | `IN_ATTRIB` only |
| Mode or mtime change | `chmod` to the same mode | `IN_ATTRIB` |
| Deleted entry | The node is held until the injector unlinks it; a deleted directory's entries are unlinked first, bottom-up, in every directory the kernel has looked up (a watched directory always has been) | `IN_DELETE`, `IN_DELETE_SELF` for each watched entry |
| Renamed entry (reported as a pair) | `rename`; an entry it replaces stays visible until then, so the kernel unlinks it | `IN_MOVED_FROM` and `IN_MOVED_TO` with one cookie, `IN_MOVE_SELF`; `IN_ATTRIB` and `IN_DELETE_SELF` on a replaced file |

How the handlers recognise the injector's requests depends on the platform:

- **Linux.** By thread id: the injector thread is the only one that touches the mount.
- **macOS, request pid is csync's** (the kernel extension, if its requests carry it): by process id, the same way.
- **macOS, request pid is not csync's** (FSKit sends pid 0): by an armed window. Before each syscall the injector arms an exact description of what it is about to ask the kernel for, and disarms when the syscall returns. A handler treats a request as injected only when its operation, inode or parent and name match an armed entry exactly, so a user's request that arrives while an injection is in flight is never taken for it: it would be applied locally and never sent to the host. One syscall can cause several requests (a lookup, then the create), and each matches while the window is armed.

| Injected operation | Armed while it runs | Checked by |
|---|---|---|
| New directory | lookup and mkdir of (parent, name) | `lookup`, `mkdir` |
| New symlink | lookup and symlink of (parent, name) | `lookup`, `symlink` |
| New file | lookup and create of (parent, name), open of the new inode for writing; then a setattr of the inode for the truncate | `lookup`, `create`, `open`, `setattr` |
| Modified file | open of the inode for writing; then a setattr of the inode for the truncate (or for the `chmod` fallback); on macOS the truncate is followed by a truncate to zero and back to the size, each answered with the true size, because FSKit keeps its cached pages across a same-size truncate and only the zero-and-back drops them (measured on macOS 15.8 and 26.7) | `open`, `setattr` |
| Mode or mtime change | setattr of the inode | `setattr` |
| Deleted entry | lookup and unlink or rmdir of (parent, name) | `lookup`, `unlink`, `rmdir` |
| Renamed entry | lookup of the source and of the target, and the rename of both (parent, name) pairs | `lookup`, `rename` |

A setattr counts as injected only if it carries no file handle or the injected one, and an open only if it is for writing. A `mknod`, `link` or `fallocate` is never armed on macOS and is always served as a user's. The names compared are the bytes the kernel sends, so a backend that rewrites a name (a normalisation) makes that request an ordinary one and the event is not seen by watchers.

On macOS the injector thread first waits for the mount volume to show and opens its root only then; see [the macOS guest](#the-macos-guest-experimental).

Events for one burst of host changes are injected in the order the host reported them, so a create comes before a modify of the same file. A host change only to ctime (a rename or a new hard link) raises no `IN_ATTRIB`, as on a native filesystem.

Limits:

- Watchers also see the opens and closes csync makes to produce these events (`IN_OPEN`, `IN_CLOSE_WRITE`).
- Host reads raise no `IN_ACCESS` or `IN_OPEN` on the guest: they never pass through the guest kernel.
- The host watcher reports the state a path ends in, not each step, so a quick series of host operations on one path (for example `chmod`, write, `chmod`, or `touch`, which opens the file) shows as the events for its final state.
- Changes to a symlink's target produce no event, and neither does a host change that turns an entry into another kind (a file into a symlink or directory) in one step; the new entry is still served at once.
- At most 4,096 events wait in the queue. A larger burst (a `git checkout` of 10,000 files) waits for the queue instead of dropping events, so a watcher gets every event or, if it reads too slowly, its own `IN_Q_OVERFLOW`. Only if the injector makes no progress for 1 s do nodes change without an event until the queue is half empty again.
- Only watchers on the guest's own mount see these events.

## Ignore semantics

Every path is in one of four classes:

| Class | Paths | Treatment |
|---|---|---|
| Synced | Everything not listed below | Read and written in both directions |
| `.git` | Inside any `.git` directory, or a `.git` gitlink file | Synced to the guest read-only |
| Ignored | Matched by ignore rules | Never sent to the guest; guest copies live in the overlay |
| Internal | Names starting with `.csync~` | Reserved for csync's temporary files; never synced, and the guest cannot create them |

The rules follow git:

- `.gitignore` files apply at every level. An ignored directory hides everything under it, and a negation pattern cannot re-include a path below an ignored directory.
- Each repository root starts a fresh stack: the deepest `.gitignore` first, then `info/exclude` from the repository's git directory (the common directory for linked worktrees), then the user's global excludes file. Submodules and nested repositories, found by a `.git` directory or file, are roots of their own.
- The global excludes file is whatever `git config --path --get core.excludesFile` returns in that worktree, or `$XDG_CONFIG_HOME/git/ignore` (default `~/.config/git/ignore`) when it is unset. If git cannot be run, csync reads the system, global and repository git config files itself.
- A project root that is not a git repository still honours `.gitignore` files and the global excludes file.
- Files that git tracks even though they match an ignore rule stay synced. csync gets that list from `git ls-files -z --cached --ignored --exclude-standard` and refreshes it 200 ms after `.git/index` changes; it rescans only when the list itself changed. Without git on the host this exception list is empty.
- On a case-insensitive host volume, patterns match case-insensitively, as git does there.
- Files macOS writes on its own are always ignored, with no rule needed, unless git tracks them: `.DS_Store`, `._*` (AppleDouble), `.AppleDouble`, `.AppleDB`, `.AppleDesktop`, `.apdisk`, `.DocumentRevisions-V100`, `.fseventsd`, `.Spotlight-V100`, `.TemporaryItems`, `.Trashes`, `.VolumeIcon.icns`, `.com.apple.timemachine.donotpresent`, `Icon\r` and `.*.icloud` placeholders. Finder and Spotlight rewriting them causes no traffic, the guest never sees the host's copies, and a guest can keep its own in the overlay. The list is `OS_JUNK` in `src/ignore/rules.rs`.

When an ignore file changes on the host, the affected subtree is reclassified. Paths that become ignored are removed from the guest but left untouched on the host's disk. Paths that become synced are scanned and sent. Guest overlay entries that become synced are committed to the host; if the host already has that path, the host's copy wins and the guest copy is discarded with a notice.

A guest may edit ignore files, but those edits can only narrow what is synced. Until the host itself changes the file, the host keeps applying the last rules it trusted as well as the guest's version, so a guest cannot expose an ignored file such as `.env` by deleting or rewriting a `.gitignore`.

When a guest's own `.gitignore` edit makes entries it can already see ignored, they move into its overlay with their content and times instead of disappearing. Tools rely on this: `python -m venv`, meson, pytest, mypy and ruff fill a directory and then write a `*` `.gitignore` into it. Such a self-ignoring `.gitignore` keeps governing its directory on the guest, as it does in git, for the rest of the session. The host keeps the copies it received before the rule existed, as ignored files it never sends back. When the guest later removes the directory, the host also removes those leftovers if they are only empty directories, symlinks that stay inside, and `.gitignore` files this guest wrote; a regular file among them stays, and the removal fails with `ENOTEMPTY` until it is deleted on the host.

### Git on the guest

`.git` is visible on the guest without write permission, and writes into it fail with `EROFS` (the host refuses them too). Commits are made on the host. A command that writes, such as `git add`, `commit`, `checkout`, `stash` or `fetch`, stops at once with git's own message, for example `Unable to create '.git/index.lock': Read-only file system` (`Permission denied` for a user other than root), and leaves nothing behind. `git status` still works: it skips refreshing the index when it cannot write it. A guest can keep its own history of the mounted tree with `GIT_DIR` or `--git-dir` pointing at a directory on its own disk.

The mount reports the host's size, mtime and ctime, but its own inode numbers and the mounting user's uid and gid, which differ from what the host's git index recorded. So that git on the guest does not rehash every file on every `git status`, the guest serves each `.git/index` with those fields replaced by the mount's for every entry whose size, mtime and ctime still match the host's file, and with a recomputed checksum. Entries the host has not refreshed keep the host's values and git hashes those files as usual. No git setting is needed. This covers `.git/index` of the project and of nested repositories, and the index of a submodule under `.git/modules`; the shared index of a split index and the index of a linked worktree are served as they are.

Git renames refs, packs and the index into place and expects every path to name the newest file at once. Entries below `.git` are therefore not cached by the guest kernel, a host file that appears or disappears is visible or gone to every lookup on the guest as soon as its change arrives, and small `.git` files are fetched whole when opened. The host keeps the last pack files it served open, so a guest still reading a pack that `git gc` or `git repack` on the host deleted can finish, as a local reader could. Objects a partial clone has not fetched yet cannot be fetched from the guest.

A guest that changes a `.gitignore` applies its own change at once, so a file it creates right after is kept on the guest when the new rule ignores it.

## Wire protocol

One TCP connection per guest, encrypted with Noise (see [pairing and trust](#pairing-and-trust)).

- **Framing.** Each Noise message on the socket is a 2-byte big-endian length followed by at most 65,535 bytes of ciphertext. The decrypted plaintext is one flag byte and a body.
- **Messages and segments.** Messages are postcard-encoded. A message larger than one segment is split across several, reassembled up to 4 MiB. Segments of different messages never interleave.
- **Chunks.** File data travels as chunks outside postcard: one segment holding a request id, an offset and up to 64,000 bytes. Chunks may interleave with message segments, so a large transfer does not hold up control traffic.
- **Compression.** A message of 512 bytes or more, or a chunk, is lz4-compressed when that saves at least an eighth. For a given transfer the sender stops trying once a chunk compresses to more than 90% of its size. The declared size is checked against the limit before anything is decompressed.
- **Limits.** After decoding, every list is checked against its bound: 8,192 entries per batch, 65,536 delta signatures, 4 MiB per range request, 64 GiB per file, 1 MiB of excludes text. Names are at most 255 bytes, paths at most 4,096 bytes and 128 components. A message that breaks a limit closes the connection.
- **Request and response.** The guest sends requests with an id (fetch, fetch-many, resolve, hashes, commit, mkdir or symlink, remove, rename, set-attributes) and the host answers each by id, or the guest cancels it. At most 256 requests may be in flight; more is a protocol error. The host never sends requests to the guest.
- **Pushes and acks.** The host pushes snapshot parts, change batches, notices, hashes learned in the background and a marker that none are left pending (see [lazy hashing](#lazy-hashing)). Each change batch carries a sequence number and the guest acknowledges it; pushed hashes are not acknowledged.
- **Version.** The protocol version is 2. The version travels in the handshake hello, and a hello with another version fails the handshake as a malformed hello, so a peer on version 1 (csync 0.1.0) never connects and the failure does not name the version. Host and guest must run the same release; `csync update` on both machines does that.
- **Delta.** Content-defined chunk signatures (fastcdc) of the old version let the other side send only the new parts.
- **Keepalive and clock.** Each side pings every 30 s. The pong carries the host's clock, from which the guest estimates the clock skew shown in the status. A side that has heard nothing from its peer for 90 s closes the link and, on the guest, reconnects; without this a peer that vanished without a reset (a sleeping laptop, a dropped VPN) would be trusted for about 15 minutes.

On connect the guest says which index and sequence number it already has. The host answers with the project name, its index identity, volume traits, repository list and global excludes, then either the journal entries since that sequence number or a full snapshot.

## Pairing and trust

Each machine has a static X25519 identity key, created on first use. Connections use Noise over Curve25519 with ChaCha20-Poly1305 and BLAKE2s, built with snow's `ring-accelerated` feature.

- **First pairing (XX).** The guest connects with the XX pattern, which exchanges both keys. Both sides then show the same 8-character code derived from the handshake hash (40 bits, Crockford base32, shown as `XXXX-XXXX`). The host user accepts and the guest user confirms the code; both are required within 120 s, and only one pairing can be pending at a time. Each side then stores the other's key.
- **Every later connection (IK).** The guest connects with the IK pattern and the host key it pinned. The handshake fails unless the host proves it holds that key; a different key stops `csync join` with an error and is never re-paired silently. `csync join --repair` pairs again explicitly. The host accepts IK only from keys stored with the guest role.
- **Pre-shared keys.** `csync key show` on one machine and `csync trust add` on the other set up trust without the interactive code, for CI and scripted setups.
- **Revocation.** `csync forget`, the host TUI's revoke key and the line protocol's `revoke` remove the key from the trust file. On the host the live session of that guest is closed at once, and the guest stops with an error. On a guest, forgetting the host of a running `csync join` closes that session at once: it unmounts and exits with code 4.
- **Rate limits.** Per client address (IPv6 per /64): 20 handshakes per minute, at most 4 handshakes in progress (16 in total), and 5 pairing attempts per hour. All addresses together get 20 pairings per hour. A pairing attempt counts only once its key exchange completes. A connecting client must send its first byte within 3 s and finish the handshake within 10 s. `--no-pair` refuses XX entirely.

Rejections before the handshake completes are plaintext and could be forged by anyone on the path. On the first connect csync reports them as an "unverified response from host" and exits; while reconnecting it keeps retrying, backing off to 60 s. Only a failure inside the authenticated handshake, such as a host key mismatch, ends a running guest.

## Security model

What csync protects:

- Traffic is encrypted and authenticated. A man in the middle at first pairing is detected when the two codes differ.
- A paired guest can read and write synced files only. It cannot read ignored files, write inside `.git`, create paths named `.csync~...`, or reach outside the project root. Every path is validated and opened beneath the root without following symlinks (`openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` on Linux, `O_NOFOLLOW_ANY` on macOS).
- Symlinks a guest creates must resolve inside the root. A directory move is refused if it would carry ignored entries or symlinks that would then point outside the root.
- On case-insensitive host volumes the host refuses spellings of a parent directory that differ from the indexed one, so `.GIT/...` or a case variant of an ignored path cannot reach those files.
- Ignore-file edits from a guest cannot widen what is synced.
- Every decoded length is bounded before it is used.
- Trust files must be owned by the user and not readable by group or others; csync refuses to load them otherwise. The local control socket accepts only connections from the same user.
- Peer-supplied names are stripped of control characters before they reach the terminal or the status output.

What it does not protect:

- A paired guest can modify or delete any synced file. Pair only machines you control.
- The guest trusts the content the host sends.
- The mDNS advertisement announces the project name and the host's key fingerprint in clear on the local network. Use `--no-mdns` to stop it.
- Other local users are kept out only by file permissions.
- A host process that keeps a file open and writes to it after a guest commit replaced that file writes into the old, unlinked inode. Those writes are lost.
- Rate limits slow down an attacker on the network, but one with several addresses can still occupy handshake slots up to those limits.

## Activity feed and diffs

The full-screen interface lists recent changes in an Activity panel and can show a diff for one of them. The line protocol builds no feed and pays nothing for it, and nothing here is sent over the wire: each side builds its rows from the changes it already handles.

- **Rows.** The feed is a ring of the 256 newest changes, also bounded to 64 KiB of path text; the oldest rows go first. A batch longer than the ring keeps its newest rows plus one row that counts the rest. Repeated modifications of one path by the same side within 2 s update one row. A row says what happened (added, modified, changed, removed, renamed, dir added, dir gone, link, merged, or a notice such as `refused`) and who did it: on the host, `host` for the host's own disk or the name of the guest whose commit it was; on a guest, `host` or `you`.
- **What the host can tell.** A change record carries no earlier state, so the host cannot tell a new file from an edit and shows a file upsert as `changed`. It shows no row for a directory upsert, which is mostly a directory's mtime moving because a child came or went; the files inside get rows. A guest sees the previous state in its own tree, so it can say `added` or `modified`.
- **Selecting.** The arrow keys or `j` and `k` move the selection (on the host, `Tab` first moves focus to the panel), and a mouse click selects a row. `Enter`, or a second click on the selected row, opens its diff.
- **Computing a diff.** Nothing is computed until a row is opened, and then on one short-lived thread, so the interface never waits on it. On a guest the old version comes from the blob cache by hash, and the new one from the cache or, up to 1 MiB, a fetch by hash from the host. The host keeps no history, so it compares the file in the working tree against `git cat-file blob HEAD:...` and labels the result working tree vs git HEAD; it does not claim to show the exact change that produced the row. When no diff can be made the view says why: a binary file, a side over 1 MiB, a version evicted from the guest cache, a host that is not a git repository, or an edit that was refused and rolled back.
- **Limits.** Each side is read up to 1 MiB, and a diff is cut at 2,000 lines or 256 KiB of text with a note saying so. Closing the diff drops it. A version a guest fetched for a diff stays in the session cache like any other blob.
- **Mouse.** The interface asks the terminal for button presses and the wheel only, never motion, and only while the Activity panel can be clicked. It is off on the pairing, revoke, setup and host-pick screens and while quitting, and every exit path restores it. Hold shift while dragging to select text.

## Resource behaviour

**Threads.** csync uses a fixed set of blocking threads and no async runtime.

- Host: the terminal or line-protocol thread and its input reader, the main session loop, the accept thread plus one short-lived thread per handshake (at most 16), the watcher, the applier, the committer, four fetch threads, two light fetch threads, two background hasher threads, the control socket, mDNS, and a reader and a writer per guest (at most 16 guests). A scan starts up to 8 walker threads for its duration. The applier and committer use a rayon pool. While a diff is open in the terminal interface, one short-lived `csync-diff` thread computes it.
- Guest: the terminal or line-protocol thread and its input reader, the session loop (the only thread that sends kernel notifications), 8 FUSE workers, a network reader and writer, the injector, the prefetcher, a rule-file worker, the control socket, and a reconnect thread while the link is down. mDNS browsing stops once a host is chosen. Short-lived `csync-land` threads verify and store fetched prefetch batches, and a large batch is split over a few more of them. A `csync-diff` thread exists only while a diff is being computed.

**Idle.** Threads block in kernel reads or on channels. With nothing changing, the only timers are the 30 s ping on each link and, on the host, the periodic index save, which runs only when there is something to save. A guest never saves its tree. The TUI redraws only when the state changes, an animation is running or a deadline is due. While the terminal is unfocused it runs no animations or timers, and a state change redraws it at most once a second; a new pairing request redraws it at once and rings the terminal bell.

**Backpressure.** Every queue is bounded.

- Each link has a control queue and a bulk queue for file data. Control messages are always sent first, and each socket write batches up to 1 MiB.
- At most 64 change batches may be unacknowledged per guest. A guest that falls further behind is marked as lagging and later caught up from the journal, or with a fresh snapshot when the journal no longer covers it.
- The host runs at most 128 fetches and 64 uploads per guest and answers "busy" beyond that. An upload idle for 60 s is dropped.
- The guest cache evicts least recently used blobs once it passes its cap, down to 95% of the cap. The cap bounds one session, because the cache is deleted when it ends. Blobs of open files are never evicted, and blobs opened in the last 15 minutes go last.

## Failure behaviour

**Host restart.** On start the host loads its saved index. On macOS, if the saved resume token belongs to the same volume, FSEvents replays the events since then. Otherwise, and always on Linux, it rescans in parallel and reuses each hash whose stat key is unchanged; a new or changed file is left pending and the hasher fills it in. After a clean shutdown the index keeps its identity, so a guest that stayed running through the restart usually receives only the changes found since. After a crash the host gives the index a new identity and running guests receive a full snapshot; their cached blobs are reused because the cache is keyed by content. Leftover `.csync~` temporary files older than the new process are removed.

**Link loss.** The guest shows the host as disconnected and redials with IK, backing off from 100 ms to 5 s. If sessions keep ending before they have stayed up 30 s after their first synced batch, the wait before the first dial also grows with each one, doubling from 100 ms to at most 30 s, and a session that stays up longer clears it. Meanwhile cached files stay readable, overlay paths work normally, and uncached reads and writes to synced files wait for the link up to a deadline of a few seconds (longer for large files), then fail with `EIO`. A write interrupted by the drop is sent again once on the new link; the host answers "done" if it had already landed. On reconnect the guest asks for the changes since the last sequence number it applied. This resume works only inside a running session, from the tree in memory; it never spans two sessions.

**Session end and fresh joins.** Every join starts clean, with a fresh snapshot from the host, an empty blob cache and an empty overlay. When a guest session ends, csync unmounts and then deletes this host's state directory (the overlay, the marker file `session.live` and anything else in it) and its blob cache directory, so a file the host deleted on purpose can never be restored or sent back by a later join. The wipe never follows symlinks, opens up read-only and no-execute directories (Go module caches are `0555`), keeps going past a failure, and does not cross into another filesystem: a mount found inside the overlay is left alone and reported. It deletes nothing while the mount point is still mounted, while the unmount failed, or while another thread still uses the cache; it then keeps the state, shows a message on the status line and leaves the cleanup to the next join of that host. A guest that is killed, loses power or crashes cannot wipe anything, so `session.live` stays behind: the next `csync join` to that host deletes whatever is left before it loads or mounts anything, and refuses to start if it cannot (also if another csync process holds the cache). Pairing, the identity and the host key are not touched, so no join needs to pair again.

**Stale mounts.** A guest that was killed leaves a mount that answers `ENOTCONN`. `csync join` detects this and clears it with `fusermount3 -uz` before mounting again; `csync doctor` lists such mounts.

**Root replaced.** The host remembers the device and inode of the project root. If a full rescan or a commit finds the path now names a different directory (moved, deleted or replaced), commits are refused and the host exits with an error asking you to start it again on the new tree.

**Disk full.** On the host, `ENOSPC`, `EDQUOT` and `EFBIG` during a commit leave the previous version in place, remove the temporary file, and reach the guest as `EFBIG` from `close` or `fsync`.

## Known limitations

- **macOS case-insensitive volumes.** The host probes whether its volume folds case and Unicode normalisation. On a folding volume, names that differ only in case (or only in normalisation) cannot coexist in the synced tree, and the guest refuses to create them with `EEXIST`. Lookups on the guest stay exact: `cat README.md` does not find `readme.md`. A name the host has a volume mounted on fails with `EEXIST` on the guest and is not listed.
- **macOS host files.** Volumes mounted inside the project (disk images, network shares) are not entered, because FSEvents never reports their changes; guest writes into them fail with `EACCES`. A project on a network volume is not supported. iCloud Drive and File Provider placeholders (dataless files) are never downloaded by the host: they are left out until they are materialised on the Mac. A host file the user cannot change (`chflags uchg`, `uappnd`, an ACL that denies delete, a read-only directory) refuses guest edits with `EACCES`. Because a guest edit replaces the file by rename, an ACL entry that denies only writing does not stop it. Hard links on the host show as independent files on the guest. Extended attribute changes on the host reach the guest as a ctime change only.
- **Path limits.** Paths deeper than 128 components or longer than 4,096 bytes, and names longer than 255 bytes, are not synced (APFS allows 255 characters, so a long accented or CJK name on the Mac can exceed this and stay host-only). Names starting with `.csync~` are reserved. Guest file names must be valid UTF-8; other names fail with `EINVAL`.
- **File types.** Regular files, directories and symlinks are synced. FIFOs and Unix sockets can be created in ignored (guest-only) directories, where they work as usual until the session ends; in the synced tree `mkfifo` and `bind` fail with `EPERM`, and moving one into the synced tree fails with `EXDEV`. Device nodes are refused everywhere (the mount is `nodev`).
- **Hard links.** In ignored (guest-only) directories `link` makes a real hard link: every name is the same inode, with one page cache, size and `st_nlink`. The host index has no hard links, so in the synced tree `link` creates an independent copy of the file under the new name: it succeeds and reaches the host as a new file, both names report `st_nlink` 1, and a later write to one name does not change the other. This keeps `tar x`, `cp -a` and `rsync -aH` working on trees that contain hard links. A link between the synced tree and an ignored directory fails with `EXDEV`.- **Moves between the synced tree and ignored directories.** Renaming a file or a directory from the synced tree onto an ignored name (`mv src/.tmpX src/target`, as cargo does) or back works: csync copies the entries into the overlay or commits them to the host as new files inside the `rename` call, then removes the source. A directory with more than 4,096 entries or 1 GiB of files, or one holding `.git`, a hard-linked overlay file, or a FIFO or socket bound for the synced tree, fails with `EXDEV`, which makes `mv` fall back to its own copy. If the host changed a file while the move ran, its newer copy stays at the old path and reappears there on the guest.
- **Extended attributes.** `getxattr`, `setxattr`, `listxattr` and `removexattr` fail with `EOPNOTSUPP`, and the kernel remembers that after the first call; the kernel answers the POSIX ACL names itself with `ENODATA`. Supporting them would make the kernel ask csync for `security.capability` on every `write(2)`. `cp -a`, `tar` and `rsync -a` skip extended attributes on such a filesystem without failing; `tar --xattrs` warns for each file it cannot read or set attributes on and still exits 0, and `rsync -X` does the same and exits with code 23.
- **Ownership.** In ignored directories ownership is real: `chown` changes the backing file and the new owner is shown, with the usual rule that only root can give a file away. Synced files show the uid and gid of the csync process, because the host decides who owns them; there `chown` to any owner the kernel allows (any owner for root) succeeds and changes nothing, so `tar x`, `rsync -a` and `cp -a` running as root complete. For other users the kernel refuses `chown` to another owner with `EPERM`, as POSIX requires.
- **Modes.** New files, directories, FIFOs and sockets get exactly the mode the caller asked for after its own umask, in both trees. The host stores only the permission bits, so setuid, setgid and sticky bits are dropped in the synced tree; they work in ignored directories (the mount is `nosuid`, so setuid never takes effect).
- **Times and counts.** `utimensat` with `AT_SYMLINK_NOFOLLOW` (`touch -h`, and the symlink times `tar`, `rsync -a` and `cp -a` restore) sets a synced symlink's mtime on the host too; its atime is not kept. Synced entries report their mtime as atime; ignored entries report the backing file's own atime, mtime and ctime. Synced directories always report `st_nlink` 2; ignored directories report the backing directory's count. `statfs` reports the overlay filesystem's space and a `f_fsid` of 0.
- **Other refused operations.** `O_TMPFILE` fails with `EOPNOTSUPP` (callers fall back to a named temporary file). `renameat2` with `RENAME_EXCHANGE` swaps two entries in ignored directories and fails with `EINVAL` when either is synced, because the host has no atomic exchange; `RENAME_NOREPLACE` works everywhere. `SEEK_DATA` and `SEEK_HOLE` treat the whole file as data, because the kernel's own answer is the only one that matches its view of the file size while writes are cached. `ioctl` returns `ENOTTY`, and `cp --reflink=always` fails while `--reflink=auto` copies.
- **Locks.** `flock` and `fcntl` locks are kept by the guest kernel. They exclude other processes on the same guest but are not seen by the host or by other guests, and they do not survive a restart of the guest.
- **Symlinks.** In ignored (guest-only) directories any symlink can be made, absolute or not, as a virtual environment's `bin/python3 -> /usr/bin/python3` needs; it never leaves the guest, and csync itself never follows it. In the synced tree a symlink a guest creates that is absolute or climbs out of the root is refused with `EPERM`, and so is renaming a relative symlink to a shallower directory where it would climb out. Moving a directory that would carry such a link, or carry ignored entries, is refused with `EACCES`. A dangling relative link is fine: Emacs lock links (`.#file` pointing to `user@host.pid:boot`) are created, synced and removed like any other symlink.
- **One project per host process.** Each `csync host` serves one root, and one root can have only one running host. To serve several projects from one Mac, run several hosts with different `--listen` ports.
- **No state between joins.** Ending a guest session deletes its overlay and blob cache, so every join downloads the project again and anything that lived only in the overlay (build outputs, `node_modules`, virtual environments, guest-only files) is gone. Copy what you want to keep out of the mount before you quit. There is no option to keep the state.
- **One guest process per host cache.** The blob cache for a host is locked by the process using it, so two `csync join` sessions to the same host need different `CSYNC_HOME` directories.
- **Guest platform.** `csync join` runs on Linux, where it needs `/dev/fuse` and `fusermount3` from fuse3 (setuid root, or csync running as root), and experimentally on macOS, where it needs macFUSE 5.5 or later with the FSKit extension enabled or the kernel extension allowed. The macOS guest has not been verified against a real macFUSE mount; see [the macOS guest](#the-macos-guest-experimental) for what is implemented and what is unknown. Nothing in this page about invalidation, passthrough, the writeback cache or `inotify` applies to it unless it says so.
- **Passthrough.** Kernel passthrough for file data needs a kernel that offers it (`csync doctor` checks for 6.9 or later), `CAP_SYS_ADMIN` in the csync process, and a backing filesystem under the cache that accepts it. Without it csync serves file data itself and uses the kernel writeback cache when available. Metadata operations always go through csync. When it is on, csync uses it only for files whose backing file cannot change while they are open: ignored (guest-only) files, backed by their overlay file, and synced files a guest process is writing, backed by their staging file until the last handle closes. Reads of synced and `.git` content are served by csync from the blob cache instead. The kernel lets an open file have only one backing file and refuses every other open of it while that one is in use, but a host edit or a guest write gives a synced file new content in a different blob while readers still hold the old one, so passthrough there would make every new open fail with `EIO` until the last reader closed. Warm reads of synced files still come from the kernel page cache; only reads the page cache does not hold go through csync.
- **Merging.** Only UTF-8 text without NUL bytes, up to 8 MiB per side, is merged. The base is the version last served to any open of the file on the guest, not the one the writing process read: if another guest process (a search, a build) reads a newer host version between an agent's read and its save, the save looks like it undoes the host's edit and can be refused even though the two edits touch different lines. Edits on neighbouring lines conflict, as in `git merge`.
- **Reads racing a host save.** A guest process that opened a file just before the host replaced it, and whose content was not cached yet, cannot read the old version: the host no longer has it. csync answers `ESTALE`, but on Linux a read served through the kernel's page cache turns that into `EIO` before it reaches the application, so the application sees `EIO`. Opening the name again returns the new file. A cold file of up to 48 KiB that was never read is fetched when it is opened, and if the host has already replaced it the open follows the replacement, so small files do not hit this. Larger cold files, and a handle held open across saves, still can.
- **Clocks.** Guest timestamps come from the host's clock. Tools that compare mtimes can misbehave when the clocks differ; `csync doctor` warns at 1 s of skew.
