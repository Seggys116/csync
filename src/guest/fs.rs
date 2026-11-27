use super::cache::{BlobCache, BlobRef, Pin, WAIT, lock, pread_full, pwrite_all};
#[cfg(target_os = "macos")]
use super::coherence::{self, BackendKind};
use super::fsops;
use super::fuse::{
    BackgroundSession, BackingId, BsdFileFlags, CopyFileRangeFlags, Errno, FileAttr, FileHandle,
    FileType, Filesystem, FopenFlags, Generation, INodeNo, InitFlags, KernelConfig, LockOwner,
    Notifier, OpenAccMode, OpenFlags, Owner, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite,
    Request, TimeOrNow, WriteFlags,
};
#[cfg(target_os = "linux")]
use super::fuse::{Config, MountOption, Session, SessionACL};
use super::gitindex::{self, Shown};
use super::inject::Injector;
use super::prefetch::{Hint, Prefetch};
use super::tree::{
    DETACHED, Effect, GDomain, GNode, GTree, NodeId, ROOT, Refuse, Special, Synth, Vis, dir_meta,
    domain_for_new, domain_of,
};
use super::write::{
    Flushed, Job, NoticeFn, OpenW, Refusal, RenameReq, Writer, dest_expect, node_expect,
};
use crate::ignore::rules::{Class, Rules};
use crate::index::tree::StatKey;
use crate::proto::{
    Change, DEPTH_MAX, Expect, FILE_MAX, Hash32, INLINE_MAX, Kind, LinkTarget, Meta, Name, Notice,
    NoticeKind, PathError, RelPath, Seq, TEXT_MAX, VerKey, Version,
};
use crate::sys;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use rustc_hash::{FxHashMap, FxHashSet};
use rustix::fs::{AtFlags, Mode, OFlags, Timespec, Timestamps, UTIME_NOW, UTIME_OMIT};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::{
    cell::RefCell,
    collections::VecDeque,
    ffi::OsStr,
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak,
        atomic::{
            AtomicBool, AtomicU32, AtomicU64,
            Ordering::{Relaxed, SeqCst},
        },
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) const TTL: Duration = Duration::from_secs(86_400);
// overlay files can change size behind a passthrough handle, so their attributes are kept short
pub(super) const LOCAL_TTL: Duration = Duration::from_secs(1);
// a cached handle held open this long sees a host edit even if it may be mid-read
const SHOW_LAG: Duration = Duration::from_secs(1);
const INJ_FH: u64 = 0;
pub(super) const IO_MAX: u32 = 1 << 20;
const BACKGROUND_MAX: u16 = 64;
const STALE_TRIES: u32 = 100;
const STALE_STEP: Duration = Duration::from_millis(10);
const RESOLVE_TRIES: u32 = 4;
const VIEW_MAX: u64 = 256 << 20;
const EAGER_GIT_MAX: u64 = 64 << 10;
const EAGER_TRIES: usize = 4;
const VIEWS_MAX: usize = 64;
#[cfg(target_os = "linux")]
const WORKERS: usize = 8;
#[cfg(target_os = "linux")]
const CAP_SYS_ADMIN: u32 = 21;
#[cfg(target_os = "linux")]
const KEEP_SIZE: i32 = libc::FALLOC_FL_KEEP_SIZE;
// the fuse protocol keeps linux's mode bits and macos has no libc name for this one
#[cfg(target_os = "macos")]
const KEEP_SIZE: i32 = 1;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const NS: i64 = 1_000_000_000;
// a truncate without a handle waits this long for the write that usually follows it
const TRUNC_HOLD: Duration = Duration::from_millis(20);

type Held = (NodeId, u32, Instant);

struct Hold {
    tx: Sender<Held>,
    join: JoinHandle<()>,
}

// blocks while nothing is held, so an idle mount has no timer; on shutdown everything held is committed
fn hold_loop(core: &Core, rx: &Receiver<Held>) {
    let mut q: VecDeque<Held> = VecDeque::new();
    loop {
        let got = match q.front() {
            Some(&(_, _, due)) => rx.recv_deadline(due),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match got {
            Ok(h) => q.push_back(h),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                for (node, sid, _) in q.drain(..) {
                    let _turn = core.stage_turn(node);
                    core.fire_deferred(node, sid);
                }
                return;
            }
        }
        let now = Instant::now();
        while let Some(&(node, sid, due)) = q.front() {
            if due > now {
                break;
            }
            q.pop_front();
            let _turn = core.stage_turn(node);
            core.fire_deferred(node, sid);
        }
    }
}

// the thread behind closes that did not wait for the host: runs until stopped, one answer at a time
pub fn settle_loop(core: &Core, rx: &Receiver<Job>) {
    while let Ok(Job::Settle(sid)) = rx.recv() {
        core.settle_parked(sid);
    }
}

#[derive(Default)]
pub struct Counters {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub commits: AtomicU64,
    pub merged: AtomicU64,
    pub refused: AtomicU64,
    pub inflight: AtomicU32,
    pub ops: [AtomicU64; OPS],
}

#[derive(Clone, Copy)]
pub enum Op {
    Lookup,
    Forget,
    Getattr,
    Setattr,
    Open,
    Read,
    Write,
    Flush,
    Release,
    Opendir,
    Readdir,
    Releasedir,
    Create,
    Mutate,
    Other,
}

pub const OPS: usize = Op::Other as usize + 1;
pub const OP_NAMES: [&str; OPS] = [
    "lookup",
    "forget",
    "getattr",
    "setattr",
    "open",
    "read",
    "write",
    "flush",
    "release",
    "opendir",
    "readdir",
    "releasedir",
    "create",
    "mutate",
    "other",
];

impl Counters {
    fn op(&self, o: Op) {
        self.ops[o as usize].fetch_add(1, Relaxed);
    }

    pub fn op_counts(&self) -> [u64; OPS] {
        std::array::from_fn(|i| self.ops[i].load(Relaxed))
    }
}

// everything the fuse workers, the apply thread and the rules worker share
pub struct Core {
    pub tree: Arc<RwLock<GTree>>,
    pub cache: Arc<BlobCache>,
    pub writer: Writer,
    pub prefetch: Prefetch,
    pub rules: RwLock<Rules>,
    pub inj: OnceLock<Arc<Injector>>,
    pub inval: OnceLock<Inval>,
    pub overlay: OwnedFd,
    pub uid: u32,
    pub gid: u32,
    pub ctr: Arc<Counters>,
    // effects from fuse workers; the channel only wakes the apply thread, so nothing is ever dropped
    pub kicked: Mutex<Vec<Effect>>,
    pub kick: Sender<()>,
    pub case_fold: AtomicBool,
    pub norm_fold: AtomicBool,
    pub passthrough: AtomicBool,
    pub notice: NoticeFn,
    // nodes holding an error from a commit that failed after their last close; lets write skip the tree when none do
    pub werrs: AtomicU32,
    // nodes whose staged copy is being opened, committed, truncated or dropped; one step at a time each
    pub staging_busy: Mutex<FxHashSet<NodeId>>,
    pub staging_done: Condvar,
    // guest-only files a rule change made synced while they were open; promoted at their last close
    pub promote_later: Mutex<FxHashSet<NodeId>>,
    // directories whose rule file this guest wrote: only there does a host remove of a now-ignored entry mean demote
    pub own_scopes: Mutex<FxHashSet<RelPath>>,
    // directory moves this guest sent and has not yet made in its tree; pushes after a reply wait for them
    pub dir_moves: Mutex<Vec<(RelPath, RelPath)>>,
    pub dir_moved: Condvar,
}

// the turn on one node's staged copy, given back on drop
pub struct StageTurn<'a> {
    core: &'a Core,
    id: NodeId,
}

impl Drop for StageTurn<'_> {
    fn drop(&mut self) {
        lock(&self.core.staging_busy).remove(&self.id);
        self.core.staging_done.notify_all();
    }
}

// a directory move sent to the host, registered until the worker has made it in the tree or given up
pub struct DirMove<'a> {
    core: &'a Core,
    paths: (RelPath, RelPath),
}

impl Drop for DirMove<'_> {
    fn drop(&mut self) {
        let mut v = lock(&self.core.dir_moves);
        if let Some(i) = v.iter().position(|m| *m == self.paths) {
            v.swap_remove(i);
        }
        drop(v);
        self.core.dir_moved.notify_all();
    }
}

impl Core {
    pub fn begin_dir_move(&self, from: &RelPath, to: &RelPath) -> DirMove<'_> {
        let paths = (from.clone(), to.clone());
        lock(&self.dir_moves).push(paths.clone());
        DirMove { core: self, paths }
    }

    // the worker holding this move already has its reply and needs nothing from the caller to finish
    pub fn await_dir_move(&self, m: &(RelPath, RelPath)) {
        let mut v = lock(&self.dir_moves);
        while v.contains(m) {
            v = self.dir_moved.wait(v).unwrap_or_else(|e| e.into_inner());
        }
    }
}

fn en(e: i32) -> Errno {
    Errno::from_i32(e)
}

fn stamps(mtime_ns: i64) -> Timestamps {
    let t = Timespec {
        tv_sec: mtime_ns.div_euclid(1_000_000_000),
        tv_nsec: mtime_ns.rem_euclid(1_000_000_000) as _,
    };
    Timestamps {
        last_access: t,
        last_modification: t,
    }
}

fn eio(e: &io::Error) -> Errno {
    en(e.raw_os_error().unwrap_or(libc::EIO))
}

fn erx(e: rustix::io::Errno) -> Errno {
    en(e.raw_os_error())
}

pub fn systime(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_nanos(ns.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

pub fn ns_of(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_nanos()).unwrap_or(i64::MAX),
    }
}

fn now_ns() -> i64 {
    ns_of(SystemTime::now())
}

fn file_type(k: Kind) -> FileType {
    match k {
        Kind::File => FileType::RegularFile,
        Kind::Dir => FileType::Directory,
        Kind::Symlink => FileType::Symlink,
    }
}

fn node_type(n: &GNode) -> FileType {
    match n.special {
        Special::None => file_type(n.meta.kind),
        Special::Fifo => FileType::NamedPipe,
        Special::Socket => FileType::Socket,
    }
}

// with writeback cache the kernel keeps its own i_size for a written file and ignores the server's,
// so only the injected truncate (whose setattr reply the kernel always applies) restores the host length
fn host_content_won(node: NodeId) -> Vec<Effect> {
    vec![
        Effect::InvalInode(node),
        Effect::Synth(Synth::Modify { node }),
    ]
}

// git replaces refs and packs by rename, and prune drops object directories, expecting each path to name
// the newest entry at once; a cached dentry only does once the injector has caught up, so entries below
// .git are looked up afresh
fn ttl_of(n: &GNode) -> Duration {
    match n.domain {
        GDomain::Local => LOCAL_TTL,
        GDomain::GitRo => Duration::ZERO,
        GDomain::Synced => synced_ttl(),
    }
}

#[cfg(target_os = "linux")]
fn synced_ttl() -> Duration {
    TTL
}

// macfuse backends honour a synced entry's lifetime differently, so the startup self-test sets it
#[cfg(target_os = "macos")]
fn synced_ttl() -> Duration {
    coherence::synced_ttl()
}

fn meta_from_key(k: &StatKey, link: Option<LinkTarget>) -> Option<Meta> {
    let kind = sys::kind_of_mode(k.mode)?;
    Some(Meta {
        kind,
        perm: (k.mode & 0o7777) as u16,
        size: k.size,
        mtime_ns: k.mtime_ns,
        ctime_ns: k.ctime_ns,
        hash: None,
        link,
        git_ro: false,
    })
}

// a fifo or socket is named as an empty file; its node's special says what the kernel shows
fn special_meta(k: &StatKey) -> Meta {
    Meta {
        kind: Kind::File,
        perm: (k.mode & 0o7777) as u16,
        size: 0,
        mtime_ns: k.mtime_ns,
        ctime_ns: k.ctime_ns,
        hash: None,
        link: None,
        git_ro: false,
    }
}

fn name_of(os: &OsStr) -> Result<Name, Errno> {
    let s = os.to_str().ok_or(Errno::EINVAL)?;
    Name::new(s).map_err(|e| match e {
        PathError::TooLong => Errno::ENAMETOOLONG,
        PathError::Reserved => Errno::EPERM,
        _ => Errno::EINVAL,
    })
}

// an overlay hard link is reached through the name it was looked up by, not the node's own
fn name_path(t: &GTree, id: NodeId, n: &GNode, parent: NodeId, name: &str) -> Option<RelPath> {
    if n.domain == GDomain::Local && (n.parent != parent || n.name.as_str() != name) {
        return t.rel_path(parent)?.join(&Name::new(name).ok()?).ok();
    }
    t.rel_path(id)
}

fn refuse_errno(r: Refuse) -> Errno {
    match r {
        Refuse::ReadOnly => Errno::EROFS,
        Refuse::Invalid => Errno::EPERM,
    }
}

fn timespec(t: Option<TimeOrNow>) -> Timespec {
    match t {
        None => Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        Some(TimeOrNow::Now) => Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        },
        Some(TimeOrNow::SpecificTime(s)) => {
            let ns = ns_of(s);
            Timespec {
                tv_sec: ns.div_euclid(NS) as _,
                tv_nsec: ns.rem_euclid(NS) as _,
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn has_cap_sys_admin() -> bool {
    let Ok(s) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    s.lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .is_some_and(|c| c & (1 << CAP_SYS_ADMIN) != 0)
}

fn remove_at(dir: BorrowedFd<'_>, name: &str, depth: usize) {
    match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => return,
        Err(rustix::io::Errno::ISDIR | rustix::io::Errno::PERM) if depth < DEPTH_MAX => {}
        Err(_) => return,
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if let Ok(sub) = rustix::fs::openat(dir, name, flags, Mode::empty()) {
        let mut ents = Vec::new();
        if sys::read_dir_plus(sub.as_fd(), &mut ents).is_ok() {
            for e in &ents {
                remove_at(sub.as_fd(), e.name.as_str(), depth + 1);
            }
        }
    }
    let _ = rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR);
}

// true once the node moved on, learned a hash or is gone; false if none of that happens by the deadline
fn await_ver_change(tree: &RwLock<GTree>, id: NodeId, ver: Seq, deadline: Instant) -> bool {
    let until = deadline.min(Instant::now() + STALE_STEP * STALE_TRIES);
    loop {
        {
            let t = tree.read().unwrap_or_else(|e| e.into_inner());
            match t.get(id) {
                Some(n) if n.ver == ver && n.meta.hash.is_none() => {}
                _ => return true,
            }
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(STALE_STEP);
    }
}

// the tree learns a resolved hash only while the node still holds the host entry that was asked about
fn resolve_node(
    tree: &RwLock<GTree>,
    id: NodeId,
    deadline: Instant,
    mut resolve: impl FnMut(&RelPath, VerKey, bool, Instant) -> Result<Version, i32>,
) -> Result<Version, Errno> {
    for _ in 0..RESOLVE_TRIES {
        let (path, key) = {
            let t = tree.read().unwrap_or_else(|e| e.into_inner());
            let n = t.get(id).ok_or(Errno::ENOENT)?;
            if n.meta.kind != Kind::File {
                return Err(Errno::EINVAL);
            }
            if let Some(v) = n.meta.version() {
                return Ok(v);
            }
            if n.domain == GDomain::Local || n.ver == 0 {
                return Err(Errno::ENOENT);
            }
            let key = n.ver_key(t.index_id()).ok_or(Errno::EIO)?;
            (t.rel_path(id).ok_or(Errno::ESTALE)?, key)
        };
        match resolve(&path, key, key.size <= INLINE_MAX as u64, deadline) {
            Ok(v) => {
                let mut t = tree.write().unwrap_or_else(|e| e.into_inner());
                if t.learn_hash(id, key.ver, v.hash) {
                    return Ok(v);
                }
                let same = t
                    .get(id)
                    .is_some_and(|n| n.ver == key.ver && n.meta.size == key.size);
                if same {
                    return Ok(v);
                }
            }
            Err(libc::ESTALE) => {
                if !await_ver_change(tree, id, key.ver, deadline) {
                    return Err(Errno::ESTALE);
                }
            }
            Err(e) => return Err(en(e)),
        }
    }
    Err(Errno::ESTALE)
}

impl Core {
    // a file the host has not hashed yet is resolved first, so no caller acts on an unknown hash
    pub fn version_of(&self, id: NodeId, deadline: Instant) -> Result<Version, Errno> {
        resolve_node(&self.tree, id, deadline, |p, key, inline, d| {
            self.cache.resolve(p, key, inline, d)
        })
    }

    // None only for a file this guest made and the host has not reported: it has no host content to name
    pub fn version_or_new(&self, id: NodeId, deadline: Instant) -> Result<Option<Version>, Errno> {
        let new = self
            .t()
            .get(id)
            .is_some_and(|n| n.meta.hash.is_none() && (n.ver == 0 || n.domain == GDomain::Local));
        if new {
            return Ok(None);
        }
        self.version_of(id, deadline).map(Some)
    }

    // waits for any other step on this node's staged copy, so each one sees the state the last left
    pub fn stage_turn(&self, id: NodeId) -> StageTurn<'_> {
        let mut busy = lock(&self.staging_busy);
        while busy.contains(&id) {
            busy = self
                .staging_done
                .wait(busy)
                .unwrap_or_else(|e| e.into_inner());
        }
        busy.insert(id);
        StageTurn { core: self, id }
    }

    pub fn t(&self) -> RwLockReadGuard<'_, GTree> {
        self.tree.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn tw(&self) -> RwLockWriteGuard<'_, GTree> {
        self.tree.write().unwrap_or_else(|e| e.into_inner())
    }

    pub fn rules(&self) -> RwLockReadGuard<'_, Rules> {
        self.rules.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn rules_mut(&self) -> RwLockWriteGuard<'_, Rules> {
        self.rules.write().unwrap_or_else(|e| e.into_inner())
    }

    // workers never wait on the apply thread; a full wake channel means a drain is already due
    fn drop_open(&self, id: NodeId) {
        let last = self.t().drop_open(id);
        if last {
            self.tw().reap(id);
        }
    }

    pub fn kick(&self, mut fx: Vec<Effect>) {
        if !fx.is_empty() {
            lock(&self.kicked).append(&mut fx);
            let _ = self.kick.try_send(());
        }
    }

    pub fn take_kicked(&self) -> Vec<Effect> {
        std::mem::take(&mut *lock(&self.kicked))
    }

    fn say(&self, kind: NoticeKind, path: RelPath) {
        (self.notice)(Notice { kind, path });
    }

    // applies the outcome of a commit attempt to the node; refusals restore the host's metadata
    // the host never echoes this guest's own rule edit back, so it narrows the guest's rules here, as on the host
    fn own_rule(&self, node: NodeId, v: Option<Version>) {
        let Some(v) = v.filter(|v| v.size <= TEXT_MAX as u64) else {
            return;
        };
        let Some(p) = self.t().rel_path(node) else {
            return;
        };
        if !self.rules().is_rule_file(&p) {
            return;
        }
        // a new file's first commit is still in flight, so its text is read from the staged copy
        let staged = || {
            let fd = self.writer.staging_fd(self.t().get(node)?.staging?)?;
            let mut buf = vec![0; v.size as usize];
            let n = pread_full(fd.as_fd(), &mut buf, 0).ok()?;
            (n == buf.len() && blake3::hash(&buf).as_bytes() == &v.hash).then_some(buf)
        };
        let text = match v.size {
            0 => Some(Vec::new()),
            _ => self
                .cache
                .get(&v.hash)
                .and_then(|b| b.read_all(TEXT_MAX as u64).ok())
                .or_else(staged),
        };
        if let Some(text) = text {
            let mut r = self.rules_mut();
            r.note_guest_rule(&p, Some(v.hash));
            r.update_rule_file(&p, Some(&text));
            drop(r);
            self.own_scope(&p);
        }
    }

    fn own_scope(&self, rule: &RelPath) {
        let Some(dir) = rule.split_last().and_then(|(d, _)| RelPath::new(d).ok()) else {
            return;
        };
        let mut s = lock(&self.own_scopes);
        if s.len() < 4096 {
            s.insert(dir);
        }
    }

    // a rule file that ignores itself lives in the overlay but still governs its synced directory, as in git
    pub fn local_rule(&self, p: &RelPath) {
        let Ok(fd) = sys::open_beneath(self.overlay.as_fd(), p, OFlags::RDONLY | OFlags::NONBLOCK)
        else {
            return;
        };
        let Some(len) = rustix::fs::fstat(&fd)
            .ok()
            .and_then(|st| usize::try_from(st.st_size).ok())
            .filter(|&l| l <= TEXT_MAX)
        else {
            return;
        };
        let mut buf = vec![0; len];
        let Ok(n) = pread_full(fd.as_fd(), &mut buf, 0) else {
            return;
        };
        buf.truncate(n);
        let mut r = self.rules_mut();
        r.note_guest_rule(p, Some(*blake3::hash(&buf).as_bytes()));
        r.update_rule_file(p, Some(&buf));
        drop(r);
        self.own_scope(p);
    }

    pub fn finish(&self, node: NodeId, r: Result<Flushed, Refusal>) -> Result<(), Errno> {
        match r {
            Ok(Flushed::Clean) => Ok(()),
            Ok(Flushed::Sent(v)) => {
                if let Some(n) = self.tw().get_mut(node) {
                    n.meta.hash = Some(v.hash);
                    n.meta.size = v.size;
                    n.meta.mtime_ns = now_ns();
                    n.read_ver = Some(v);
                }
                self.own_rule(node, Some(v));
                Ok(())
            }
            Ok(Flushed::Committed { meta, merged }) => {
                self.ctr.commits.fetch_add(1, Relaxed);
                self.own_rule(node, meta.version());
                let mut t = self.tw();
                if let Some(n) = t.get_mut(node) {
                    n.read_ver = meta.version();
                    n.meta = meta;
                }
                t.note_acked(node);
                drop(t);
                if merged {
                    self.kick(host_content_won(node));
                }
                Ok(())
            }
            Err(e) => {
                if e.refused {
                    let mut t = self.tw();
                    match e.current {
                        Some(m) if t.get(node).is_some_and(|n| n.meta.kind == m.kind) => {
                            if let Some(n) = t.get_mut(node) {
                                n.meta = m;
                            }
                            drop(t);
                            self.kick(host_content_won(node));
                        }
                        // the kernel fails an inode whose type changes, so another kind of entry gets a new node
                        Some(m) => {
                            let mut fx = Vec::new();
                            if let Some(path) = t.rel_path(node) {
                                let up = Change::Upsert {
                                    path,
                                    meta: m,
                                    ver: 0,
                                };
                                t.apply(&up, &mut fx);
                            }
                            drop(t);
                            self.kick(fx);
                        }
                        // the host has no such file: the guest copy goes too
                        None => {
                            let at = t
                                .get(node)
                                .filter(|n| n.attached())
                                .map(|n| (n.parent, n.name.clone()));
                            if let Some((parent, name)) = at {
                                t.remove(node);
                                drop(t);
                                self.kick(vec![
                                    Effect::InvalEntry(parent, name),
                                    Effect::InvalInode(parent),
                                    Effect::InvalInode(node),
                                ]);
                            }
                        }
                    }
                }
                Err(en(e.errno))
            }
        }
    }

    // the error of a commit that failed after the node's last close, given out once
    pub fn take_werr(&self, node: NodeId) -> Result<(), Errno> {
        if self.werrs.load(Relaxed) == 0 {
            return Ok(());
        }
        let e = self.tw().take_werr(node);
        if e == 0 {
            return Ok(());
        }
        self.werrs.fetch_sub(1, Relaxed);
        Err(en(e))
    }

    // the rest of a close that left a new file's commit to the host's answer, off the fuse workers
    pub fn settle_parked(&self, sid: u32) {
        let Some(node) = self.writer.parked_node(sid) else {
            return;
        };
        let _turn = self.stage_turn(node);
        if let Some(r) = self.writer.settle_parked(sid) {
            let errno = r.as_ref().err().map_or(0, |e| e.errno);
            if self.finish(node, r).is_err() {
                if let Some(n) = self.tw().get_mut(node) {
                    n.page = None;
                }
                self.kick(vec![Effect::InvalInode(node)]);
                if errno != 0 && self.tw().set_werr(node, errno) {
                    self.werrs.fetch_add(1, Relaxed);
                }
            }
        }
        if self.writer.staging_fd(sid).is_none()
            && let Some(n) = self.tw().get_mut(node)
            && n.staging == Some(sid)
        {
            n.staging = None;
        }
    }

    fn attr_with(&self, id: NodeId, n: &GNode, size: u64, mtime_ns: i64) -> FileAttr {
        let m = &n.meta;
        let mut perm = m.perm & 0o7777;
        if n.domain == GDomain::GitRo {
            perm &= !0o222;
        }
        let mtime = systime(mtime_ns);
        FileAttr {
            ino: INodeNo(id),
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: systime(m.ctime_ns),
            crtime: mtime,
            kind: node_type(n),
            perm,
            nlink: if m.kind == Kind::Dir {
                2
            } else {
                u32::from(n.attached())
            },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    pub fn attr(&self, id: NodeId, n: &GNode) -> FileAttr {
        let size = match (&n.meta.kind, &n.meta.link) {
            (Kind::Symlink, Some(l)) => l.as_str().len() as u64,
            _ => n.kernel_size(),
        };
        self.attr_with(id, n, size, n.meta.mtime_ns)
    }

    // entry replies must not undo a local size the host has not seen yet; an overlay file's tree meta
    // is only a snapshot, so its size comes from the file itself
    fn entry_attr(&self, t: &GTree, id: NodeId, n: &GNode) -> FileAttr {
        if n.domain == GDomain::Local
            && let Some(st) = t
                .rel_path(id)
                .and_then(|p| fsops::stat_beneath(self.overlay.as_fd(), &p).ok())
        {
            return self.stat_attr(id, n, &st);
        }
        match n.staging.and_then(|s| self.writer.staged_stat(s)) {
            Some(k) => self.attr_with(id, n, k.size, k.mtime_ns),
            None => self.attr(id, n),
        }
    }

    // hard links share the backing inode, so its links, owner and size are what every name reports
    fn stat_attr(&self, id: NodeId, n: &GNode, st: &fsops::LStat) -> FileAttr {
        let mtime = systime(st.mtime_ns);
        FileAttr {
            ino: INodeNo(id),
            size: if n.is_dir() { 0 } else { st.size },
            blocks: st.blocks,
            atime: systime(st.atime_ns),
            mtime,
            ctime: systime(st.ctime_ns),
            crtime: mtime,
            kind: node_type(n),
            perm: (st.mode & 0o7777) as u16,
            nlink: st.nlink,
            uid: st.uid,
            gid: st.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn fire_deferred(&self, node: NodeId, sid: u32) {
        if let Some(r) = self.writer.end_deferred(sid)
            && self.finish(node, r).is_err()
        {
            if let Some(n) = self.tw().get_mut(node) {
                n.page = None;
            }
            self.kick(vec![Effect::InvalInode(node)]);
        }
        if self.writer.staging_fd(sid).is_none()
            && let Some(n) = self.tw().get_mut(node)
            && n.staging == Some(sid)
        {
            n.staging = None;
        }
    }

    // the node is being removed or replaced: its unadopted truncate never reaches the host
    fn drop_deferred(&self, node: NodeId) {
        let Some(sid) = self.t().get(node).and_then(|n| n.staging) else {
            return;
        };
        self.writer.cancel_deferred(sid);
        if self.writer.staging_fd(sid).is_none()
            && let Some(n) = self.tw().get_mut(node)
            && n.staging == Some(sid)
        {
            n.staging = None;
        }
    }

    // a node being written reports its staging copy's size and mtime
    fn live_attr(&self, id: NodeId) -> Result<(FileAttr, Duration, u64), Errno> {
        let (domain, staging) = {
            let t = self.t();
            let n = t.get(id).ok_or(Errno::ENOENT)?;
            (n.domain, n.staging)
        };
        if domain == GDomain::Local {
            let path = self.t().rel_path(id).ok_or(Errno::ENOENT)?;
            let st = fsops::stat_beneath(self.overlay.as_fd(), &path).map_err(en)?;
            let t = self.t();
            let n = t.get(id).ok_or(Errno::ENOENT)?;
            return Ok((self.stat_attr(id, n, &st), ttl_of(n), n.r#gen));
        }
        let over = staging
            .and_then(|s| self.writer.staging_fd(s))
            .and_then(|fd| sys::stat_key(fd.as_fd()).ok());
        let t = self.t();
        let n = t.get(id).ok_or(Errno::ENOENT)?;
        let a = match over {
            Some(k) => self.attr_with(id, n, k.size, k.mtime_ns),
            None => self.attr(id, n),
        };
        Ok((a, ttl_of(n), n.r#gen))
    }

    fn refresh_local(&self, id: NodeId) -> Result<(), Errno> {
        let path = self.t().rel_path(id).ok_or(Errno::ENOENT)?;
        let k = fsops::stat_key_beneath(self.overlay.as_fd(), &path).map_err(|e| eio(&e))?;
        let mut t = self.tw();
        if let Some(n) = t.get_mut(id) {
            let link = n.meta.link.take();
            match meta_from_key(&k, link.clone()) {
                Some(m) => n.meta = m,
                None if n.special != Special::None => n.meta = special_meta(&k),
                None => n.meta.link = link,
            }
        }
        Ok(())
    }

    // overlay directory for a relative dir path, created on demand; never follows symlinks
    pub fn overlay_dir(&self, dir: &str, create: bool) -> io::Result<OwnedFd> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut cur = rustix::fs::openat(&self.overlay, ".", flags, Mode::empty())?;
        for c in dir.split('/').filter(|c| !c.is_empty()) {
            let next = match rustix::fs::openat(&cur, c, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) if create => {
                    match rustix::fs::mkdirat(&cur, c, Mode::from_bits_truncate(0o755)) {
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(e) => return Err(e.into()),
                    }
                    rustix::fs::openat(&cur, c, flags, Mode::empty())?
                }
                Err(e) => return Err(e.into()),
            };
            cur = next;
        }
        Ok(cur)
    }

    pub fn remove_overlay(&self, rel: &RelPath) {
        let Some((dir, name)) = rel.split_last() else {
            return;
        };
        if let Ok(d) = self.overlay_dir(dir, false) {
            remove_at(d.as_fd(), name, 0);
        }
    }

    // guest-only entries that live in the overlay counterpart of dir, loaded once per directory
    pub fn load_local(&self, dir: NodeId) {
        let (path, synced) = {
            let t = self.t();
            if t.local_loaded(dir) {
                return;
            }
            match t.get(dir) {
                Some(n) if n.is_dir() && n.attached() && n.domain != GDomain::GitRo => {
                    (t.rel_path(dir), n.domain == GDomain::Synced)
                }
                _ => return,
            }
        };
        let Some(path) = path else { return };
        let mut ents = Vec::new();
        let ok = match sys::open_beneath(
            self.overlay.as_fd(),
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY,
        ) {
            Ok(fd) => sys::read_dir_plus(fd.as_fd(), &mut ents).is_ok(),
            Err(e) => matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)),
        };
        if !ok {
            return;
        }
        // nothing guest-only here: marking it needs no write lock
        if ents.is_empty() {
            self.t().set_local_loaded(dir);
            return;
        }
        let mut rule = None;
        let mut t = self.tw();
        for e in ents {
            if t.child(dir, e.name.as_str()).is_some() {
                continue;
            }
            if let Some(meta) = meta_from_key(&e.stat, None) {
                if synced && meta.kind == Kind::File && e.name.as_str() == ".gitignore" {
                    rule = path.join(&e.name).ok();
                }
                t.insert(dir, e.name, meta, GDomain::Local, Vis::Live);
            } else if let s @ (Special::Fifo | Special::Socket) =
                fsops::special_of_mode(e.stat.mode)
            {
                let id = t.insert(
                    dir,
                    e.name,
                    special_meta(&e.stat),
                    GDomain::Local,
                    Vis::Live,
                );
                if let Some(n) = t.get_mut(id) {
                    n.special = s;
                }
            }
        }
        t.set_local_loaded(dir);
        drop(t);
        if let Some(p) = rule {
            self.local_rule(&p);
        }
    }

    fn classify_new(&self, parent: GDomain, path: &RelPath, dir: bool) -> Result<GDomain, Errno> {
        let class = self.rules().classify(path, dir);
        domain_for_new(parent, class).map_err(refuse_errno)
    }

    // `own` is a rename source, which may take another spelling of its own name
    fn fold_clash(&self, t: &GTree, parent: NodeId, name: &Name, own: Option<NodeId>) -> bool {
        let (case, norm) = (self.case_fold.load(Relaxed), self.norm_fold.load(Relaxed));
        if !case && !norm {
            return false;
        }
        let key = name.fold_key(case, norm);
        t.get(parent)
            .and_then(|p| p.children.as_ref())
            .is_some_and(|k| {
                k.iter().any(|(n, &c)| {
                    n != name
                        && Some(c) != own
                        && n.fold_key(case, norm) == key
                        && t.get(c).is_some_and(|x| x.domain != GDomain::Local)
                })
            })
    }

    // after an ignore-rule change: guest-only entries that are now synced are committed to the host
    pub fn promote(&self, scope: &RelPath) {
        let Some(root) = self.t().resolve(scope) else {
            return;
        };
        let mut stack = vec![root];
        let mut cands = Vec::new();
        while let Some(d) = stack.pop() {
            self.load_local(d);
            let t = self.t();
            let Some(kids) = t.get(d).and_then(|n| n.children.as_ref()) else {
                continue;
            };
            for &c in kids.values() {
                match t.get(c) {
                    Some(n) if n.domain == GDomain::Local && n.special == Special::None => {
                        cands.push(c)
                    }
                    Some(n) if n.domain == GDomain::Synced && n.is_dir() => stack.push(c),
                    _ => {}
                }
            }
        }
        for c in cands {
            self.promote_node(c, 0);
        }
    }

    // a guest-only file created or closed around a rule change: the walk over the scope may not have seen it
    pub fn promote_closed(&self, id: NodeId) {
        if lock(&self.promote_later).remove(&id) {
            self.promote_node(id, 0);
        }
    }

    pub fn promote_new(&self, id: NodeId) {
        let path = {
            let t = self.t();
            match t.get(id) {
                Some(n) if n.domain == GDomain::Local => t.rel_path(id).map(|p| (p, n.is_dir())),
                _ => None,
            }
        };
        if let Some((p, dir)) = path
            && self.rules().classify(&p, dir) == Class::Synced
        {
            self.promote_node(id, 0);
        }
    }

    fn promote_node(&self, id: NodeId, depth: usize) {
        let _turn = self.stage_turn(id);
        let (path, kind, perm, parent, name, open) = {
            let t = self.t();
            let Some(n) = t.get(id).filter(|n| {
                n.domain == GDomain::Local && n.attached() && n.special == Special::None
            }) else {
                return;
            };
            let Some(p) = t.rel_path(id) else { return };
            (
                p,
                n.meta.kind,
                n.meta.perm,
                n.parent,
                n.name.clone(),
                n.open.load(Relaxed),
            )
        };
        if depth > DEPTH_MAX || self.rules().classify(&path, kind == Kind::Dir) != Class::Synced {
            return;
        }
        // its handles write the overlay copy, so it moves to the host once the last one closes
        if kind == Kind::File && open > 0 {
            lock(&self.promote_later).insert(id);
            let closed = self.t().get(id).is_none_or(|n| n.open.load(Relaxed) == 0);
            if !(closed && lock(&self.promote_later).remove(&id)) {
                return;
            }
        }
        let done = match kind {
            Kind::File => {
                let Ok(fd) = sys::open_beneath(self.overlay.as_fd(), &path, OFlags::RDONLY) else {
                    return;
                };
                let r = self.writer.rename(RenameReq {
                    from: &path,
                    to: &path,
                    from_expect: Expect::Absent,
                    to_expect: Expect::Absent,
                    staging: None,
                    local: Some((fd.as_fd(), perm)),
                    discard: false,
                });
                match r {
                    Ok(m) => Some(m),
                    Err(e) if e.refused => return self.discard(id, parent, name, &path),
                    Err(_) => return,
                }
            }
            Kind::Symlink => {
                let Some(target) = self.read_local_link(&path) else {
                    return;
                };
                match self.writer.symlink(&path, &target) {
                    Ok(m) => Some(m),
                    Err(libc::EEXIST) => return self.discard(id, parent, name, &path),
                    Err(_) => return,
                }
            }
            Kind::Dir => match self.writer.mkdir(&path, perm) {
                Ok(m) => Some(m),
                Err(libc::EEXIST) => None,
                Err(_) => return,
            },
        };
        {
            let mut t = self.tw();
            if let Some(n) = t.get_mut(id) {
                n.domain = GDomain::Synced;
                if let Some(m) = done {
                    n.read_ver = m.version();
                    n.meta = m;
                }
            }
        }
        if kind == Kind::Dir {
            self.load_local(id);
            let kids: Vec<NodeId> = self
                .t()
                .get(id)
                .and_then(|n| n.children.as_ref())
                .map(|k| k.values().copied().collect())
                .unwrap_or_default();
            for c in kids {
                self.promote_node(c, depth + 1);
            }
            if let Some((dir, nm)) = path.split_last()
                && let Ok(d) = self.overlay_dir(dir, false)
            {
                let _ = rustix::fs::unlinkat(&d, nm, AtFlags::REMOVEDIR);
            }
        } else {
            self.remove_overlay(&path);
        }
        self.kick(vec![Effect::InvalInode(id), Effect::InvalInode(parent)]);
        self.say(NoticeKind::Promoted, path);
    }

    // the host already has this path: the guest-only copy is dropped
    fn discard(&self, id: NodeId, parent: NodeId, name: Name, path: &RelPath) {
        self.remove_overlay(path);
        self.tw().remove(id);
        self.kick(vec![
            Effect::InvalEntry(parent, name),
            Effect::InvalInode(parent),
        ]);
        self.say(NoticeKind::Discarded, path.clone());
    }

    // this guest's own rule edit made synced entries ignored (python -m venv, meson and tool caches write a
    // `*` .gitignore into a directory they just filled): the host keeps its copies, the guest keeps them in the overlay
    pub fn demote(&self, scope: &RelPath) {
        let Some(root) = self.t().resolve(scope) else {
            return;
        };
        let mut items: Vec<(NodeId, RelPath, Meta, Option<u32>)> = Vec::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            self.load_local(id);
            let t = self.t();
            let Some(n) = t
                .get(id)
                .filter(|n| n.domain == GDomain::Synced && n.attached())
            else {
                continue;
            };
            if id == root && self.rules().classify(scope, n.is_dir()) != Class::Ignored {
                return;
            }
            let Some(p) = t.rel_path(id) else { continue };
            if let Some(k) = &n.children {
                stack.extend(k.iter().filter_map(|(nm, &c)| {
                    t.get(c)
                        .is_some_and(|x| x.parent == id && x.name == *nm)
                        .then_some(c)
                }));
            }
            items.push((id, p, n.meta.clone(), n.staging));
        }
        let mut fx = Vec::new();
        let mut dirs = Vec::new();
        for (id, path, meta, staging) in items {
            let ok = self.demote_one(id, &path, &meta, staging).is_ok();
            let mut t = self.tw();
            let Some(n) = t.get_mut(id) else { continue };
            if !ok {
                let (parent, name) = (n.parent, n.name.clone());
                t.remove(id);
                fx.push(Effect::InvalEntry(parent, name));
                fx.push(Effect::InvalInode(parent));
                continue;
            }
            n.domain = GDomain::Local;
            n.staging = None;
            n.page = None;
            if *n.open.get_mut() == 0
                && let Some(v) = n.read_ver.take()
            {
                fx.push(Effect::Unpin(v.hash));
            }
            if meta.kind == Kind::Dir {
                t.set_local_loaded(id);
                dirs.push((path, meta.mtime_ns));
            }
            drop(t);
            let _ = self.refresh_local(id);
            fx.push(Effect::InvalInode(id));
        }
        // children made inside each directory moved its mtime, so directories get theirs back last
        for (path, mtime) in dirs.iter().rev() {
            if let Some((d, nm)) = path.split_last()
                && let Ok(dfd) = self.overlay_dir(d, false)
            {
                let _ = rustix::fs::utimensat(&dfd, nm, &stamps(*mtime), AtFlags::SYMLINK_NOFOLLOW);
            }
        }
        for (path, _) in &dirs {
            let id = self.t().resolve(path);
            if let Some(id) = id {
                let _ = self.refresh_local(id);
            }
        }
        self.kick(fx);
    }

    fn demote_one(
        &self,
        id: NodeId,
        path: &RelPath,
        meta: &Meta,
        staging: Option<u32>,
    ) -> Result<(), i32> {
        let (dir, name) = path.split_last().ok_or(libc::EINVAL)?;
        let d = self
            .overlay_dir(dir, true)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        match meta.kind {
            Kind::Dir => match fsops::mkdir(d.as_fd(), name, u32::from(meta.perm)) {
                Ok(()) | Err(libc::EEXIST) => Ok(()),
                Err(e) => Err(e),
            },
            Kind::Symlink => {
                let l = meta.link.as_ref().ok_or(libc::EIO)?;
                rustix::fs::symlinkat(l.as_str(), &d, name).map_err(|e| e.raw_os_error())
            }
            Kind::File => {
                // the host no longer serves an ignored path, so only bytes already on the guest can move
                let staged = staging.and_then(|s| self.writer.staging_fd(s));
                let blob = match (&staged, meta.version()) {
                    (None, Some(v)) if v.size > 0 => Some(
                        self.cache
                            .get(&v.hash)
                            .filter(BlobRef::is_complete)
                            .ok_or(libc::ENOENT)?,
                    ),
                    _ => None,
                };
                // a host file still without a hash was never read here, so none of its bytes are cached
                let unhashed = staged.is_none()
                    && meta.size > 0
                    && meta.hash.is_none()
                    && self.t().get(id).is_some_and(|n| n.ver != 0);
                if unhashed {
                    return Err(libc::ENOENT);
                }
                let tmp = format!("{}dm{id}", crate::proto::path::TMP_PREFIX);
                let flags = OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::WRONLY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC;
                let out =
                    rustix::fs::openat(&d, tmp.as_str(), flags, Mode::from_bits_truncate(0o600))
                        .map_err(|e| e.raw_os_error())?;
                let src = staged
                    .as_ref()
                    .map(|f| f.as_fd())
                    .or(blob.as_ref().map(BlobRef::fd));
                let r = fsops::fix_mode(out.as_fd(), u32::from(meta.perm))
                    .and_then(|()| match src {
                        Some(s) => sys::clone_or_copy(s, out.as_fd())
                            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO)),
                        None => Ok(()),
                    })
                    .and_then(|()| {
                        let ts = stamps(meta.mtime_ns);
                        rustix::fs::futimens(&out, &ts).map_err(|e| e.raw_os_error())
                    });
                drop(out);
                let r = r.and_then(|()| {
                    rustix::fs::renameat(&d, tmp.as_str(), &d, name).map_err(|e| e.raw_os_error())
                });
                if r.is_err() {
                    let _ = rustix::fs::unlinkat(&d, tmp.as_str(), AtFlags::empty());
                }
                r
            }
        }
    }

    fn read_local_link(&self, path: &RelPath) -> Option<LinkTarget> {
        fsops::read_link_beneath(self.overlay.as_fd(), path)
    }
}

// the kernel refuses any open of an inode that has a backing file unless it passes through to that same
// file, so only files whose backing cannot change while open get one: a synced blob is replaced under
// its readers by every host edit and guest write, so those are served by csync instead
#[derive(Clone, Copy, PartialEq, Eq)]
enum BKey {
    Staged(u32),
    Local(bool),
}

impl BKey {
    // a read-write overlay backing also serves read-only opens
    fn serves(self, want: BKey) -> bool {
        self == want || (self == BKey::Local(true) && want == BKey::Local(false))
    }

    // 0: the blob cache filesystem, 1: the overlay
    fn fs(self) -> usize {
        usize::from(matches!(self, BKey::Local(_)))
    }
}

#[derive(Default)]
struct NodeIo {
    key: Option<BKey>,
    backing: Weak<BackingId>,
    cached: u32,
}

enum Io {
    None,
    Cached,
    // cached io that first drops whatever an older version left in the page cache
    Fresh,
    Direct,
    Pass(Arc<BackingId>),
}

type Listing = Arc<Vec<(NodeId, Option<Name>)>>;

type Swap = Mutex<Option<Box<(Version, RelPath)>>>;

enum Src {
    Dir(Listing),
    Empty,
    Blob {
        path: RelPath,
        ver: Version,
        blob: OnceLock<BlobRef>,
        _pin: Option<Pin>,
        // the version a direct handle moved to when the host had replaced its own before any byte was read
        swap: Swap,
    },
    Staged {
        id: u32,
        fd: Arc<OwnedFd>,
    },
    Local {
        fd: OwnedFd,
    },
}

struct Handle {
    node: NodeId,
    io: Io,
    src: Src,
}

// a directory moving between the synced tree and the overlay is copied entry by entry inside the rename;
// past these bounds it gets EXDEV like a cross-device rename, and mv falls back to its own copy
const MOVE_ENTRIES: usize = 4096;
const MOVE_BYTES: u64 = 1 << 30;

struct Move<'a> {
    sid: NodeId,
    from: &'a RelPath,
    to: &'a RelPath,
    perm: u16,
    src: (NodeId, &'a str),
    dst: (NodeId, Name),
    replaces: Option<NodeId>,
}

// one entry below a moving directory, parents before children
struct Moved {
    id: NodeId,
    up: Option<usize>,
    rel: String,
    meta: Meta,
    expect: Expect,
    staging: Option<u32>,
    special: Special,
    local: bool,
    open: bool,
}

fn under(base: &RelPath, rel: &str) -> Result<RelPath, Errno> {
    RelPath::new(&format!("{}/{rel}", base.as_str())).map_err(|_| Errno::ENAMETOOLONG)
}

// for what a host reply just described, which always carries a file's hash
fn expect_of(m: &Meta) -> Expect {
    match m.kind {
        Kind::Dir => Expect::Dir,
        Kind::File => m.version().map_or(Expect::Any, Expect::Is),
        Kind::Symlink => Expect::Any,
    }
}

// what the host still holds after a move it partly refused reappears at its old path
fn restore_left(t: &mut GTree, p: &RelPath, meta: Meta, fx: &mut Vec<Effect>) {
    let Some((dir, name)) = p.split_last() else {
        return;
    };
    let mut cur = ROOT;
    for c in dir.split('/').filter(|c| !c.is_empty()) {
        cur = match t.child(cur, c) {
            Some(id) => id,
            None => {
                let Ok(nm) = Name::new(c) else { return };
                let id = t.insert_dir(cur, nm.clone(), dir_meta(0o755), GDomain::Synced);
                if id == DETACHED {
                    return;
                }
                fx.push(Effect::InvalEntry(cur, nm));
                fx.push(Effect::InvalInode(cur));
                id
            }
        };
    }
    let Ok(nm) = Name::new(name) else { return };
    if t.child(cur, name).is_some() {
        return;
    }
    let dom = domain_of(&meta);
    if meta.kind == Kind::Dir {
        t.insert_dir(cur, nm.clone(), meta, dom);
    } else {
        t.insert(cur, nm.clone(), meta, dom, Vis::Live);
    }
    fx.push(Effect::InvalEntry(cur, nm));
    fx.push(Effect::InvalInode(cur));
}

pub struct GuestFs {
    core: Arc<Core>,
    handles: Mutex<FxHashMap<u64, Arc<Handle>>>,
    next: AtomicU64,
    io: Mutex<FxHashMap<NodeId, NodeIo>>,
    // listings of directories read without an opendir, keyed by inode until read to the end
    lists: Mutex<FxHashMap<NodeId, Listing>>,
    pass: bool,
    no_backing: [AtomicBool; 2],
    no_opendir: bool,
    noflush: bool,
    hold: Mutex<Option<Hold>>,
    // git index blob to the guest view of it, or to itself when no view applies
    views: Mutex<FxHashMap<Hash32, Version>>,
}

thread_local! {
    static BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn read_into(len: usize, f: impl FnOnce(&mut [u8]) -> Result<usize, Errno>, reply: ReplyData) {
    BUF.with_borrow_mut(|b| {
        if b.len() < len {
            b.resize(len, 0);
        }
        let Some(dst) = b.get_mut(..len) else {
            return reply.error(Errno::EIO);
        };
        match f(dst) {
            Ok(n) => reply.data(dst.get(..n).unwrap_or_default()),
            Err(e) => reply.error(e),
        }
    });
}

#[cfg(target_os = "linux")]
fn fopen(io: &Io) -> FopenFlags {
    match io {
        Io::Cached => FopenFlags::FOPEN_KEEP_CACHE,
        Io::Fresh => FopenFlags::empty(),
        Io::Direct => FopenFlags::FOPEN_DIRECT_IO,
        Io::None | Io::Pass(_) => FopenFlags::empty(),
    }
}

// a page cache is only kept across opens where the backend is known to drop it on invalidation
#[cfg(target_os = "macos")]
fn fopen(io: &Io) -> FopenFlags {
    match io {
        Io::Cached if coherence::keep_cache() => FopenFlags::FOPEN_KEEP_CACHE,
        Io::Direct => FopenFlags::FOPEN_DIRECT_IO,
        Io::Cached | Io::Fresh | Io::None | Io::Pass(_) => FopenFlags::empty(),
    }
}

impl GuestFs {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            core,
            handles: Mutex::new(FxHashMap::default()),
            next: AtomicU64::new(INJ_FH + 1),
            io: Mutex::new(FxHashMap::default()),
            lists: Mutex::new(FxHashMap::default()),
            pass: false,
            no_backing: [AtomicBool::new(false), AtomicBool::new(false)],
            no_opendir: false,
            noflush: false,
            hold: Mutex::new(None),
            views: Mutex::new(FxHashMap::default()),
        }
    }

    fn hold_truncate(&self, node: NodeId, sid: u32) {
        let held = (node, sid, Instant::now() + TRUNC_HOLD);
        let mut g = lock(&self.hold);
        if g.is_none() {
            let (tx, rx) = crossbeam_channel::unbounded();
            let core = self.core.clone();
            let spawned = std::thread::Builder::new()
                .name("csync-trunc".into())
                .spawn(move || hold_loop(&core, &rx));
            if let Ok(join) = spawned {
                *g = Some(Hold { tx, join });
            }
        }
        let sent = g.as_ref().is_some_and(|h| h.tx.send(held).is_ok());
        drop(g);
        if !sent {
            self.core.fire_deferred(node, sid);
        }
    }

    #[cfg(target_os = "linux")]
    fn is_inj(&self, req: &Request) -> bool {
        self.core.inj.get().is_some_and(|i| i.is_self(req.pid()))
    }

    // the startup self-test drives the mount from the injector thread and must be served as a user
    #[cfg(target_os = "macos")]
    fn is_inj(&self, req: &Request) -> bool {
        !coherence::PROBE.active() && self.core.inj.get().is_some_and(|i| i.is_self(req.pid()))
    }

    fn add_handle(&self, h: Handle) -> u64 {
        let fh = self.next.fetch_add(1, Relaxed);
        lock(&self.handles).insert(fh, Arc::new(h));
        fh
    }

    fn handle(&self, fh: u64) -> Option<Arc<Handle>> {
        lock(&self.handles).get(&fh).cloned()
    }

    // attributes of an overlay node with no name left, from any handle still open on it
    fn open_local_stat(
        &self,
        node: NodeId,
        fh: Option<FileHandle>,
    ) -> Option<(FileAttr, Duration)> {
        let h = fh
            .and_then(|f| self.handle(f.0))
            .filter(|h| h.node == node)
            .or_else(|| {
                lock(&self.handles)
                    .values()
                    .find(|h| h.node == node && matches!(h.src, Src::Local { .. }))
                    .cloned()
            })?;
        let Src::Local { fd } = &h.src else {
            return None;
        };
        let st = fsops::stat_fd(fd.as_fd()).ok()?;
        let t = self.core.t();
        let n = t.get(node)?;
        Some((self.core.stat_attr(node, n, &st), ttl_of(n)))
    }

    // one backing file per inode at a time; direct io is only legal once the kernel has dropped the old one
    fn choose_io(
        &self,
        node: NodeId,
        src: Option<(BKey, BorrowedFd<'_>)>,
        mk: &dyn Fn(BorrowedFd<'_>) -> io::Result<BackingId>,
    ) -> Io {
        let mut m = lock(&self.io);
        let e = m.entry(node).or_default();
        let live = e.backing.upgrade();
        if self.pass
            && self.core.passthrough.load(Relaxed)
            && let Some((key, fd)) = src
            && !self.no_backing[key.fs()].load(Relaxed)
        {
            match &live {
                Some(b) if e.key.is_some_and(|k| k.serves(key)) => return Io::Pass(b.clone()),
                None if e.cached == 0 => match mk(fd) {
                    Ok(b) => {
                        let b = Arc::new(b);
                        e.backing = Arc::downgrade(&b);
                        e.key = Some(key);
                        return Io::Pass(b);
                    }
                    // a stacked or unsupported backing filesystem refuses every file on it alike
                    Err(err) => match err.raw_os_error() {
                        Some(libc::EPERM) => self.core.passthrough.store(false, Relaxed),
                        Some(libc::ELOOP | libc::EOPNOTSUPP | libc::EINVAL) => {
                            self.no_backing[key.fs()].store(true, Relaxed)
                        }
                        _ => {}
                    },
                },
                _ => {}
            }
        }
        if live.is_some() {
            return Io::Direct;
        }
        e.cached += 1;
        Io::Cached
    }

    fn listing(&self, ino: NodeId) -> Result<Listing, Errno> {
        self.core.load_local(ino);
        let mut list = Vec::new();
        let t = self.core.t();
        match t.get(ino) {
            Some(n) if n.is_dir() => {}
            Some(_) => return Err(Errno::ENOTDIR),
            None => return Err(Errno::ENOENT),
        }
        t.list(ino, &mut list);
        // as lookups do there: git rescans objects/pack for the pack a repack just replaced
        if let Some(kids) = t
            .get(ino)
            .filter(|n| n.domain == GDomain::GitRo)
            .and_then(|n| n.children.as_ref())
        {
            list.retain(|(id, _)| t.get(*id).is_some_and(|n| n.vis != Vis::PendingDelete));
            for (name, &id) in kids {
                if t.pending_create(ino, name.as_str()) == Some(id) {
                    list.push((id, None));
                }
            }
        }
        Ok(Arc::new(list))
    }

    // fh 0 means the kernel skips opendir: offset 0 snapshots the directory, later offsets reuse it
    fn dir_list(&self, ino: NodeId, fh: u64, offset: u64) -> Result<Listing, Errno> {
        if fh != INJ_FH {
            return match self.handle(fh).as_deref() {
                Some(Handle {
                    src: Src::Dir(l), ..
                }) => Ok(l.clone()),
                _ => Err(Errno::EBADF),
            };
        }
        if offset != 0
            && let Some(l) = lock(&self.lists).get(&ino)
        {
            return Ok(l.clone());
        }
        let l = self.listing(ino)?;
        lock(&self.lists).insert(ino, l.clone());
        Ok(l)
    }

    fn dir_done(&self, ino: NodeId, fh: u64, l: &Listing) {
        if fh == INJ_FH {
            let mut m = lock(&self.lists);
            if m.get(&ino).is_some_and(|x| Arc::ptr_eq(x, l)) {
                m.remove(&ino);
            }
        }
    }

    fn close_handle(&self, h: Arc<Handle>) {
        let node = h.node;
        let cached = matches!(h.io, Io::Cached | Io::Fresh);
        let dir = matches!(h.src, Src::Dir(_));
        let blob = matches!(h.src, Src::Blob { .. } | Src::Empty);
        drop(h);
        if cached && blob {
            self.uncache(node);
        }
        if !dir {
            let mut m = lock(&self.io);
            if let Some(e) = m.get_mut(&node) {
                if cached {
                    e.cached = e.cached.saturating_sub(1);
                }
                if e.cached == 0 && e.backing.strong_count() == 0 {
                    m.remove(&node);
                }
            }
            drop(m);
            self.core.drop_open(node);
        }
    }

    // the last reader of a page cache another version waits behind lets the notify thread move it
    fn uncache(&self, id: NodeId) {
        let moved = self.core.t().get(id).is_some_and(|n| {
            let mut c = n.cached.load(Relaxed);
            while c > 0 {
                match n.cached.compare_exchange_weak(c, c - 1, Relaxed, Relaxed) {
                    Ok(_) => break,
                    Err(now) => c = now,
                }
            }
            c == 1 && n.kernel_ver() != n.meta.version()
        });
        if moved {
            self.core.kick(vec![Effect::Reshow(id)]);
        }
    }

    // a blob open counted as cached before its io was known gives the count back if it is not
    fn counted(&self, id: NodeId, io: Io) -> Io {
        if !matches!(io, Io::Cached | Io::Fresh) {
            self.uncache(id);
        }
        io
    }

    // only staged handles act on flush, so the rest skip the close round trip
    fn noflush(&self, src: &Src) -> FopenFlags {
        if self.noflush && !matches!(src, Src::Staged { .. }) {
            FopenFlags::FOPEN_NOFLUSH
        } else {
            FopenFlags::empty()
        }
    }

    fn reply_new(&self, reply: ReplyOpen, h: Handle) {
        let h = Arc::new(h);
        let fh = self.next.fetch_add(1, Relaxed);
        lock(&self.handles).insert(fh, h.clone());
        self.reply_open(reply, fh, &h);
    }

    fn reply_open(&self, reply: ReplyOpen, fh: u64, h: &Handle) {
        let nf = self.noflush(&h.src);
        match &h.io {
            // the kernel fails a passthrough open with EIO for any flag outside its mask, KEEP_CACHE included
            Io::Pass(b) => reply.opened_passthrough(FileHandle(fh), nf, b),
            io => reply.opened(FileHandle(fh), fopen(io) | nf),
        }
    }

    fn attr_reply(&self, id: NodeId, ttl: &Duration, a: &FileAttr, reply: ReplyAttr) {
        let reply = match self.core.inval.get() {
            Some(k) => k.hold(id, reply),
            None => Some(reply),
        };
        if let Some(r) = reply {
            r.attr(ttl, a);
        }
    }

    fn node_staging_fd(&self, id: NodeId) -> Option<Arc<OwnedFd>> {
        let s = self.core.t().get(id)?.staging?;
        self.core.writer.staging_fd(s)
    }

    // the host replaced a version before it could be fetched; its change is already on the way, so wait for the tree
    fn newer_meta(&self, id: NodeId, old: Option<Version>) -> Option<Meta> {
        for _ in 0..STALE_TRIES {
            match self.core.t().get(id) {
                Some(n) if n.meta.version() != old => return Some(n.meta.clone()),
                Some(_) => {}
                None => return None,
            }
            std::thread::sleep(STALE_STEP);
        }
        None
    }

    // the host moved on before this version was fetched: the same bytes from where the file was moved
    // to, or, for a direct handle starting a read, what replaced it; another version under a size the
    // kernel already has, or after bytes of this one, would tear the read, so that fails instead
    #[allow(clippy::too_many_arguments)]
    fn read_newer(
        &self,
        id: NodeId,
        old: Version,
        at: &RelPath,
        offset: u64,
        want: usize,
        err: i32,
        reply: ReplyData,
        swap: Option<&Swap>,
    ) {
        let first = old;
        let (mut old, mut at, mut err) = (old, at.clone(), err);
        let start = Instant::now();
        // a host still rewriting the file can replace each version before it is fetched, so follow it
        loop {
            let Some((cur, path)) = self.newer_place(id, old, &at) else {
                return reply.error(en(err));
            };
            if cur != Some(first) && swap.is_none() {
                return reply.error(Errno::ESTALE);
            }
            let Some(v) = cur else {
                return reply.data(&[]);
            };
            let len = v.size.saturating_sub(offset).min(want as u64) as usize;
            if len == 0 {
                return reply.data(&[]);
            }
            let deadline = start + WAIT + Duration::from_millis(v.size >> 12);
            match self
                .core
                .cache
                .fetch_at(&v.hash, &path, v.size, offset, len as u32, deadline)
            {
                Ok(b) => {
                    if let Some(s) = swap.filter(|_| v != first) {
                        *lock(s) = Some(Box::new((v, path)));
                    }
                    return read_into(len, |dst| b.read_at(dst, offset).map_err(en), reply);
                }
                Err(e @ (libc::ESTALE | libc::EIO)) if Instant::now() < deadline => {
                    (old, at, err) = (v, path, e);
                }
                Err(e) => return reply.error(en(e)),
            }
        }
    }

    // the change that made the host refuse a fetch is on its way: wait for a new version or a new path
    fn newer_place(
        &self,
        id: NodeId,
        old: Version,
        at: &RelPath,
    ) -> Option<(Option<Version>, RelPath)> {
        let deadline = Instant::now() + WAIT;
        for _ in 0..STALE_TRIES {
            let (node, path, moved, held) = {
                let t = self.core.t();
                let n = t.get(id)?;
                if n.meta.kind != Kind::File {
                    return None;
                }
                match t.rel_path(id) {
                    // replaced by another file: what is at the path now is all there is to read
                    None => {
                        let rid = t.resolve(at)?;
                        let r = t.get(rid).filter(|r| r.meta.kind == Kind::File)?;
                        (rid, at.clone(), false, r.meta.version())
                    }
                    Some(p) => {
                        let moved = p != *at;
                        (id, p, moved, n.meta.version())
                    }
                }
            };
            let cur = match held {
                Some(v) => Some(v),
                None => self.core.version_or_new(node, deadline).ok()?,
            };
            if moved || cur != Some(old) {
                return Some((cur, path));
            }
            std::thread::sleep(STALE_STEP);
        }
        None
    }

    // page cache and i_size belong to the inode, so a cached handle opened on another version must
    // serve the one they describe: newer tree content shows only once the kernel has dropped them
    fn moved_on(&self, h: &Handle) -> Option<(Option<Version>, RelPath)> {
        let opened = match (&h.io, &h.src) {
            (Io::Cached | Io::Fresh, Src::Blob { ver, .. }) => Some(*ver),
            (Io::Cached | Io::Fresh, Src::Empty) => None,
            _ => return None,
        };
        let t = self.core.t();
        let n = t.get(h.node)?;
        let shown = n.kernel_ver();
        if n.meta.kind != Kind::File || shown == opened {
            return None;
        }
        // git replaces its files whole and reads what it opened, so a .git handle that has its bytes keeps them
        if n.domain == GDomain::GitRo
            && matches!(&h.src, Src::Blob { blob, .. } if blob.get().is_some())
        {
            return None;
        }
        Some((shown, t.rel_path(h.node)?))
    }

    #[allow(clippy::too_many_arguments)]
    fn read_version(
        &self,
        node: NodeId,
        v: Version,
        path: &RelPath,
        offset: u64,
        want: usize,
        reply: ReplyData,
        swap: Option<&Swap>,
    ) {
        if offset >= v.size {
            return reply.data(&[]);
        }
        let len = (v.size - offset).min(want as u64) as usize;
        let res = match self.core.cache.get(&v.hash).filter(|b| b.is_complete()) {
            Some(b) => Ok(b),
            None => {
                let deadline = Instant::now() + WAIT + Duration::from_millis(v.size >> 12);
                let c = &self.core.ctr.inflight;
                c.fetch_add(1, Relaxed);
                let r = self
                    .core
                    .cache
                    .fetch_at(&v.hash, path, v.size, offset, len as u32, deadline);
                c.fetch_sub(1, Relaxed);
                r
            }
        };
        match res {
            Ok(b) => read_into(len, |dst| b.read_at(dst, offset).map_err(en), reply),
            Err(e @ (libc::ESTALE | libc::EIO)) => {
                self.read_newer(node, v, path, offset, want, e, reply, swap)
            }
            Err(e) => reply.error(en(e)),
        }
    }

    // the host version a write starts from; a file the host has not hashed is resolved first
    fn base_of(&self, id: NodeId, meta: &Meta) -> Result<Option<Version>, Errno> {
        match meta.version() {
            Some(v) => Ok(Some(v)),
            None => self.core.version_or_new(id, Instant::now() + WAIT),
        }
    }

    fn open_staged(&self, id: NodeId, o: OpenW<'_>) -> Result<(u32, Arc<OwnedFd>), Errno> {
        let _turn = self.core.stage_turn(id);
        // a last close may have committed and dropped the copy since the caller looked: join or start from what is there now
        let seen = {
            let t = self.core.t();
            t.get(id)
                .map(|n| (n.meta.version(), n.meta.perm, n.staging))
        };
        let o = match seen {
            Some((held, perm, staging)) => {
                // the base of a write is a version the host has confirmed, so an unhashed file is resolved first
                let base = match held {
                    Some(v) => Some(v),
                    None => match self.core.version_or_new(id, Instant::now() + WAIT) {
                        Ok(v) => v,
                        // a copy already staged is joined, and needs no base
                        Err(_) if staging.is_some() => None,
                        Err(e) => return Err(e),
                    },
                };
                OpenW {
                    base,
                    perm,
                    staging,
                    ..o
                }
            }
            None => o,
        };
        let (path, trunc, staging, old) = (o.path, o.trunc, o.staging, o.base);
        let (sid, fd) = match self.core.writer.open_for_write(o) {
            Err(libc::ESTALE) if staging.is_none() => {
                let m = self.newer_meta(id, old).ok_or(Errno::ESTALE)?;
                let base = match m.version() {
                    Some(v) => Some(v),
                    None => self.core.version_or_new(id, Instant::now() + WAIT)?,
                };
                self.core
                    .writer
                    .open_for_write(OpenW {
                        path,
                        base,
                        perm: m.perm,
                        trunc,
                        staging,
                    })
                    .map_err(en)?
            }
            r => r.map_err(en)?,
        };
        let mut t = self.core.tw();
        if let Some(n) = t.get_mut(id) {
            n.staging = Some(sid);
        }
        t.add_open(id);
        Ok((sid, fd))
    }

    fn local_flags(flags: i32) -> OFlags {
        let mut of = match OpenFlags(flags).acc_mode() {
            OpenAccMode::O_RDONLY => OFlags::RDONLY,
            OpenAccMode::O_WRONLY => OFlags::WRONLY,
            OpenAccMode::O_RDWR => OFlags::RDWR,
        };
        // no O_APPEND: the kernel picks every append offset itself (writeback pages land mid-file, and
        // pwrite on an O_APPEND fd ignores its offset)
        if flags & libc::O_TRUNC != 0 {
            of |= OFlags::TRUNC;
        }
        of
    }

    // validates a new entry and decides which domain it belongs to
    fn prep_new(
        &self,
        parent: NodeId,
        name: &Name,
        dir: bool,
    ) -> Result<(GDomain, RelPath), Errno> {
        self.core.load_local(parent);
        let t = self.core.t();
        let p = t.get(parent).ok_or(Errno::ENOENT)?;
        if !p.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if !p.attached() {
            return Err(Errno::ENOENT);
        }
        if t.lookup(parent, name.as_str()).is_some() || t.child(parent, name.as_str()).is_some() {
            return Err(Errno::EEXIST);
        }
        let path = t
            .rel_path(parent)
            .ok_or(Errno::ENOENT)?
            .join(name)
            .map_err(|_| Errno::ENAMETOOLONG)?;
        let dom = self.core.classify_new(p.domain, &path, dir)?;
        if dom == GDomain::Synced && self.core.fold_clash(&t, parent, name, None) {
            return Err(Errno::EEXIST);
        }
        Ok((dom, path))
    }

    fn insert_new(
        &self,
        parent: NodeId,
        name: &Name,
        meta: Meta,
        dom: GDomain,
    ) -> Result<NodeId, Errno> {
        let dir = meta.kind == Kind::Dir;
        let mut t = self.core.tw();
        let id = if dir {
            t.insert_dir(parent, name.clone(), meta, dom)
        } else {
            t.insert(parent, name.clone(), meta, dom, Vis::Live)
        };
        if id == DETACHED {
            return Err(Errno::ENOENT);
        }
        if dir && dom == GDomain::Local {
            t.set_local_loaded(id);
        }
        t.add_lookup(id);
        Ok(id)
    }

    fn entry_reply(&self, id: NodeId, reply: ReplyEntry) {
        let t = self.core.t();
        match t.get(id) {
            Some(n) => reply.entry(
                &ttl_of(n),
                &self.core.entry_attr(&t, id, n),
                Generation(n.r#gen),
            ),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn new_file(&self, parent: NodeId, name: &Name, perm: u16) -> Result<(NodeId, Src), Errno> {
        let (dom, path) = self.prep_new(parent, name, false)?;
        match dom {
            GDomain::Local => {
                let (dir, _) = path.split_last().ok_or(Errno::EINVAL)?;
                let d = self.core.overlay_dir(dir, true).map_err(|e| eio(&e))?;
                let flags = OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::RDWR
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC;
                let fd = rustix::fs::openat(
                    &d,
                    name.as_str(),
                    flags,
                    Mode::from_bits_truncate(u32::from(perm) as _),
                )
                .map_err(erx)?;
                if let Err(e) = fsops::fix_mode(fd.as_fd(), u32::from(perm)) {
                    let _ = rustix::fs::unlinkat(&d, name.as_str(), AtFlags::empty());
                    return Err(en(e));
                }
                let k = sys::stat_key(fd.as_fd()).map_err(|e| eio(&e))?;
                let meta = meta_from_key(&k, None).ok_or(Errno::EIO)?;
                let id = self.insert_new(parent, name, meta, GDomain::Local)?;
                self.core.t().add_open(id);
                // classified under the rules before a change whose promotion walk may have missed it
                self.core.promote_new(id);
                Ok((id, Src::Local { fd }))
            }
            GDomain::Synced => {
                let now = now_ns();
                let meta = Meta {
                    kind: Kind::File,
                    perm,
                    size: 0,
                    mtime_ns: now,
                    ctime_ns: now,
                    hash: None,
                    link: None,
                    git_ro: false,
                };
                let id = self.insert_new(parent, name, meta, GDomain::Synced)?;
                match self.open_staged(
                    id,
                    OpenW {
                        path: &path,
                        base: None,
                        perm,
                        trunc: true,
                        staging: None,
                    },
                ) {
                    Ok((sid, fd)) => Ok((id, Src::Staged { id: sid, fd })),
                    Err(e) => {
                        self.core.tw().remove(id);
                        Err(e)
                    }
                }
            }
            GDomain::GitRo => Err(Errno::EROFS),
        }
    }

    fn insert_local(
        &self,
        parent: NodeId,
        name: &Name,
        meta: Meta,
        special: Special,
    ) -> Result<NodeId, Errno> {
        let mut t = self.core.tw();
        let id = t.insert(parent, name.clone(), meta, GDomain::Local, Vis::Live);
        let n = t.get_mut(id).ok_or(Errno::ENOENT)?;
        n.special = special;
        t.add_lookup(id);
        Ok(id)
    }

    // fifos and sockets live only in the overlay: the host cannot hold them
    fn new_special(
        &self,
        parent: NodeId,
        name: &Name,
        kind: Special,
        perm: u16,
    ) -> Result<NodeId, Errno> {
        let (dom, path) = self.prep_new(parent, name, false)?;
        if dom != GDomain::Local {
            return Err(Errno::EPERM);
        }
        let (dir, _) = path.split_last().ok_or(Errno::EINVAL)?;
        let d = self.core.overlay_dir(dir, true).map_err(|e| eio(&e))?;
        fsops::mknod(d.as_fd(), name.as_str(), kind, u32::from(perm)).map_err(en)?;
        let k = sys::stat_key_at(d.as_fd(), name.as_str()).map_err(|e| eio(&e))?;
        self.insert_local(parent, name, special_meta(&k), kind)
    }

    // a .git directory's worktree is its parent; a git directory elsewhere (a submodule's under
    // .git/modules) names it with core.worktree
    fn git_worktree(&self, gitdir: &str) -> Option<NodeId> {
        let base = match gitdir.rsplit_once('/') {
            Some((up, ".git")) => return self.core.t().resolve(&RelPath::new(up).ok()?),
            None if gitdir == ".git" => return Some(ROOT),
            _ => gitdir,
        };
        let cfg = RelPath::new(&format!("{base}/config")).ok()?;
        let cfg_node = self.core.t().resolve(&cfg)?;
        let ver = self.core.version_of(cfg_node, Instant::now() + WAIT).ok()?;
        let deadline = Instant::now() + WAIT;
        let b = self
            .core
            .cache
            .fetch_whole(&ver.hash, &cfg, ver.size, deadline)
            .ok()?;
        let rel = gitindex::core_worktree(&b.read_all(1 << 20).ok()?)?;
        if rel.starts_with('/') {
            return None;
        }
        let mut parts: Vec<&str> = base.split('/').collect();
        for c in rel.split('/') {
            match c {
                "" | "." => {}
                ".." => {
                    parts.pop()?;
                }
                c => parts.push(c),
            }
        }
        if parts.is_empty() {
            return Some(ROOT);
        }
        self.core.t().resolve(&RelPath::new(&parts.join("/")).ok()?)
    }

    // a small .git file is fetched whole at open, since git reads it right after: one the host deleted
    // meanwhile, such as a loose ref pack-refs pruned, then fails the open as natively, not the read
    fn git_small(
        &self,
        id: NodeId,
        ver: Version,
        path: &RelPath,
    ) -> Result<(Version, Option<BlobRef>), Errno> {
        if let Some(b) = self.core.cache.get(&ver.hash).filter(BlobRef::is_complete) {
            return Ok((ver, Some(b)));
        }
        let mut ver = ver;
        for _ in 0..EAGER_TRIES {
            let deadline = Instant::now() + WAIT;
            match self
                .core
                .cache
                .fetch_whole(&ver.hash, path, ver.size, deadline)
            {
                Ok(b) => return Ok((ver, Some(b))),
                Err(libc::ENOENT | libc::ESTALE) => {}
                Err(_) => return Ok((ver, None)),
            }
            let mut next = None;
            for _ in 0..STALE_TRIES {
                let held = match self.core.t().get(id) {
                    Some(n) if n.attached() && n.vis != Vis::PendingDelete => n.meta.version(),
                    _ => return Err(Errno::ENOENT),
                };
                let cur = match held {
                    Some(v) => Some(v),
                    None => match self.core.version_or_new(id, Instant::now() + WAIT) {
                        Ok(v) => v,
                        Err(_) => break,
                    },
                };
                if cur != Some(ver) {
                    next = cur;
                    break;
                }
                std::thread::sleep(STALE_STEP);
            }
            match next {
                Some(v) if v.size <= EAGER_GIT_MAX => ver = v,
                _ => break,
            }
        }
        Ok((ver, None))
    }

    // the index as git on the guest should see it; None serves the host's bytes unchanged
    fn git_view(&self, raw: Version, path: &RelPath) -> Option<BlobRef> {
        let (gitdir, name) = path.as_str().rsplit_once('/')?;
        if name != "index" || raw.size > VIEW_MAX {
            return None;
        }
        if let Some(v) = lock(&self.views).get(&raw.hash).copied() {
            if v.hash == raw.hash {
                return None;
            }
            if let Some(b) = self.core.cache.get(&v.hash).filter(BlobRef::is_complete) {
                return Some(b);
            }
        }
        let work = self.git_worktree(gitdir)?;
        let deadline = Instant::now() + WAIT;
        let b = self
            .core
            .cache
            .fetch_whole(&raw.hash, path, raw.size, deadline)
            .ok()?;
        let bytes = b.read_all(VIEW_MAX).ok()?;
        drop(b);
        let (uid, gid) = (self.core.uid, self.core.gid);
        let out = {
            let t = self.core.t();
            let mut last: (Vec<u8>, Option<NodeId>) = (Vec::new(), Some(work));
            gitindex::rewrite(&bytes, |p| {
                let (dir, file) = match p.iter().rposition(|&c| c == b'/') {
                    Some(i) => (&p[..i], &p[i + 1..]),
                    None => (&p[..0], p),
                };
                // index entries are sorted, so a run of files shares one directory lookup
                if dir != last.0.as_slice() {
                    let mut cur = Some(work);
                    if !dir.is_empty() {
                        for c in dir.split(|&c| c == b'/') {
                            cur = cur.and_then(|d| t.child(d, std::str::from_utf8(c).ok()?));
                        }
                    }
                    last = (dir.to_vec(), cur);
                }
                let id = t.child(last.1?, std::str::from_utf8(file).ok()?)?;
                let n = t.get(id)?;
                if n.domain != GDomain::Synced || n.vis != Vis::Live || n.staging.is_some() {
                    return None;
                }
                let size = match (&n.meta.kind, &n.meta.link) {
                    (Kind::File, _) => n.meta.size,
                    (Kind::Symlink, Some(l)) => l.as_str().len() as u64,
                    _ => return None,
                };
                Some(Shown {
                    ino: id,
                    uid,
                    gid,
                    mtime_ns: n.meta.mtime_ns,
                    ctime_ns: n.meta.ctime_ns,
                    size,
                })
            })
        };
        let (view, shown) = match out {
            Some(out) => {
                let h = *blake3::hash(&out).as_bytes();
                self.core.cache.insert_bytes(&h, &out, None).ok()?;
                let v = self.core.cache.get(&h).filter(BlobRef::is_complete)?;
                (Some(v), h)
            }
            None => (None, raw.hash),
        };
        let mut m = lock(&self.views);
        if m.len() >= VIEWS_MAX {
            m.clear();
        }
        m.insert(
            raw.hash,
            Version {
                hash: shown,
                size: raw.size,
            },
        );
        view
    }

    fn src_key<'a>(src: &'a Src) -> Option<(BKey, BorrowedFd<'a>)> {
        match src {
            Src::Staged { id, fd } => Some((BKey::Staged(*id), fd.as_fd())),
            Src::Local { fd } => Some((BKey::Local(true), fd.as_fd())),
            Src::Blob { .. } | Src::Dir(_) | Src::Empty => None,
        }
    }

    fn do_unlink(&self, parent: NodeId, name: &OsStr, dir: bool) -> Result<(), Errno> {
        let name = name.to_str().ok_or(Errno::ENOENT)?;
        if dir {
            let found = self.core.t().lookup(parent, name).map(|(id, _)| id);
            if let Some(id) = found {
                self.core.load_local(id);
            }
        }
        // a commit of this file still in flight decides which version the host is told to remove
        let found = self.core.t().lookup(parent, name).map(|(id, _)| id);
        let _turn = found.map(|id| self.core.stage_turn(id));
        let (id, domain, kind, expect, path, vis, empty) = {
            let t = self.core.t();
            let (id, n) = t.lookup(parent, name).ok_or(Errno::ENOENT)?;
            let mut l = Vec::new();
            let empty = !n.is_dir() || (t.list(id, &mut l) && l.is_empty());
            (
                id,
                n.domain,
                n.meta.kind,
                node_expect(n, t.index_id()),
                name_path(&t, id, n, parent, name).ok_or(Errno::ENOENT)?,
                n.vis,
                empty,
            )
        };
        match (dir, kind == Kind::Dir) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            _ => {}
        }
        if !empty {
            return Err(Errno::ENOTEMPTY);
        }
        let (pdir, nm) = path.split_last().ok_or(Errno::EBUSY)?;
        match domain {
            GDomain::GitRo => return Err(Errno::EROFS),
            GDomain::Local => {
                let d = self.core.overlay_dir(pdir, false).map_err(|e| eio(&e))?;
                let flags = if dir {
                    AtFlags::REMOVEDIR
                } else {
                    AtFlags::empty()
                };
                match rustix::fs::unlinkat(&d, nm, flags) {
                    Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                    Err(e) => return Err(erx(e)),
                }
            }
            GDomain::Synced if vis == Vis::PendingDelete => {}
            GDomain::Synced => {
                match self.core.writer.remove(&path, expect) {
                    Ok(_) => {}
                    Err(e) if !e.refused && e.errno == libc::ENOENT => {}
                    Err(e) => return self.core.finish(id, Err(e)),
                }
                self.core.drop_deferred(id);
                if let Some(sid) = self.core.t().get(id).and_then(|n| n.staging) {
                    self.core.writer.unlinked(sid);
                }
                if dir {
                    self.core.remove_overlay(&path);
                }
            }
        }
        self.core.tw().remove_at(id, parent, name);
        Ok(())
    }

    fn do_rename(
        &self,
        parent: NodeId,
        name: &OsStr,
        newparent: NodeId,
        newname: &OsStr,
        flags: RenameFlags,
    ) -> Result<(), Errno> {
        if flags.contains(RenameFlags::RENAME_WHITEOUT) {
            return Err(Errno::EINVAL);
        }
        let name = name.to_str().ok_or(Errno::ENOENT)?;
        let newname = name_of(newname)?;
        if flags.contains(RenameFlags::RENAME_EXCHANGE) {
            return self.do_exchange(parent, name, newparent, &newname);
        }
        self.core.load_local(newparent);
        let existing = self
            .core
            .t()
            .lookup(newparent, newname.as_str())
            .map(|(id, _)| id);
        if let Some(d) = existing {
            self.core.load_local(d);
        }
        struct Plan {
            sid: NodeId,
            skind: Kind,
            sdom: GDomain,
            sexpect: Expect,
            sperm: u16,
            staging: Option<u32>,
            link: Option<LinkTarget>,
            from: RelPath,
            to: RelPath,
            ddom: GDomain,
            dst: Option<NodeId>,
            to_expect: Expect,
        }
        let plan = {
            let t = self.core.t();
            let (sid, s) = t.lookup(parent, name).ok_or(Errno::ENOENT)?;
            let np = t.get(newparent).ok_or(Errno::ENOENT)?;
            if !np.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            if s.is_dir() && t.is_within(newparent, sid) {
                return Err(Errno::EINVAL);
            }
            let dst = t.lookup(newparent, newname.as_str());
            if let Some((did, d)) = dst {
                if did == sid {
                    return Ok(());
                }
                if flags.contains(RenameFlags::RENAME_NOREPLACE) {
                    return Err(Errno::EEXIST);
                }
                match (s.is_dir(), d.is_dir()) {
                    (true, false) => return Err(Errno::ENOTDIR),
                    (false, true) => return Err(Errno::EISDIR),
                    (true, true) => {
                        let mut l = Vec::new();
                        if t.list(did, &mut l) && !l.is_empty() {
                            return Err(Errno::ENOTEMPTY);
                        }
                    }
                    (false, false) => {}
                }
            }
            if s.domain == GDomain::GitRo
                || np.domain == GDomain::GitRo
                || dst.is_some_and(|(_, d)| d.domain == GDomain::GitRo)
            {
                return Err(Errno::EROFS);
            }
            let from = name_path(&t, sid, s, parent, name).ok_or(Errno::ENOENT)?;
            let to = t
                .rel_path(newparent)
                .ok_or(Errno::ENOENT)?
                .join(&newname)
                .map_err(|_| Errno::ENAMETOOLONG)?;
            let ddom = match dst {
                Some((_, d)) => d.domain,
                None => self.core.classify_new(np.domain, &to, s.is_dir())?,
            };
            // the host has no fifos or sockets
            if s.special != Special::None && ddom != GDomain::Local {
                return Err(Errno::EXDEV);
            }
            if ddom == GDomain::Synced
                && dst.is_none()
                && self.core.fold_clash(&t, newparent, &newname, Some(sid))
            {
                return Err(Errno::EEXIST);
            }
            Plan {
                sid,
                skind: s.meta.kind,
                sdom: s.domain,
                sexpect: node_expect(s, t.index_id()),
                sperm: s.meta.perm,
                staging: s.staging,
                link: s.meta.link.clone(),
                from,
                to,
                ddom,
                dst: dst.map(|(i, _)| i),
                to_expect: dest_expect(dst.map(|(_, d)| d), t.index_id()),
            }
        };
        let p = plan;
        let dir = p.skind == Kind::Dir;
        let (fdir, fname) = p.from.split_last().ok_or(Errno::EBUSY)?;
        let (tdir, tname) = p.to.split_last().ok_or(Errno::EINVAL)?;
        let _moving = (dir && p.sdom == GDomain::Synced && p.ddom == GDomain::Synced)
            .then(|| self.core.begin_dir_move(&p.from, &p.to));
        let new_meta = match (p.sdom, p.ddom) {
            (GDomain::Local, GDomain::Local) => {
                let sd = self.core.overlay_dir(fdir, false).map_err(|e| eio(&e))?;
                let dd = self.core.overlay_dir(tdir, true).map_err(|e| eio(&e))?;
                rustix::fs::renameat(&sd, fname, &dd, tname).map_err(erx)?;
                None
            }
            (GDomain::Synced, GDomain::Synced) => {
                if let Some(l) = &p.link
                    && !l.stays_within(&p.to)
                {
                    return Err(Errno::EPERM);
                }
                let from_expect = p.sexpect;
                let own = p.skind == Kind::File && self.core.t().was_acked(p.sid);
                let r = self.core.writer.rename(RenameReq {
                    from: &p.from,
                    to: &p.to,
                    from_expect,
                    to_expect: p.to_expect,
                    staging: p.staging,
                    local: None,
                    discard: own,
                });
                match r {
                    Ok(m) => {
                        if dir {
                            self.move_overlay(fdir, fname, tdir, tname);
                        }
                        Some(m)
                    }
                    Err(e) => {
                        if e.refused {
                            let mut fx = vec![Effect::InvalEntry(newparent, newname.clone())];
                            if let Some(d) = p.dst {
                                fx.push(Effect::InvalInode(d));
                            }
                            if p.staging.is_some() || own {
                                self.core.drop_deferred(p.sid);
                                self.core.tw().remove(p.sid);
                                if let Ok(n) = Name::new(name) {
                                    fx.push(Effect::InvalEntry(parent, n));
                                }
                            }
                            self.core.kick(fx);
                        }
                        return Err(en(e.errno));
                    }
                }
            }
            (GDomain::Local, GDomain::Synced) => {
                if dir {
                    let mv = Move {
                        sid: p.sid,
                        from: &p.from,
                        to: &p.to,
                        perm: p.sperm,
                        src: (parent, name),
                        dst: (newparent, newname),
                        replaces: p.dst,
                    };
                    return self.move_in(mv);
                }
                // the host cannot hold a second name for the same file
                if self.core.t().has_links(p.sid) {
                    return Err(Errno::EXDEV);
                }
                let m = match p.skind {
                    Kind::Symlink => {
                        let target = self.core.read_local_link(&p.from).ok_or(Errno::EIO)?;
                        if !target.stays_within(&p.to) {
                            return Err(Errno::EPERM);
                        }
                        self.core.writer.symlink(&p.to, &target).map_err(en)?
                    }
                    _ => {
                        let fd =
                            sys::open_beneath(self.core.overlay.as_fd(), &p.from, OFlags::RDONLY)
                                .map_err(|e| eio(&e))?;
                        let rq = RenameReq {
                            from: &p.from,
                            to: &p.to,
                            from_expect: Expect::Absent,
                            to_expect: p.to_expect,
                            staging: None,
                            local: Some((fd.as_fd(), p.sperm)),
                            discard: false,
                        };
                        self.core.writer.rename(rq).map_err(|e| en(e.errno))?
                    }
                };
                self.core.remove_overlay(&p.from);
                Some(m)
            }
            (GDomain::Synced, GDomain::Local) => {
                if dir {
                    let mv = Move {
                        sid: p.sid,
                        from: &p.from,
                        to: &p.to,
                        perm: p.sperm,
                        src: (parent, name),
                        dst: (newparent, newname),
                        replaces: p.dst,
                    };
                    return self.move_out(mv);
                }
                let dd = self.core.overlay_dir(tdir, true).map_err(|e| eio(&e))?;
                self.copy_out(
                    &p.from,
                    p.skind,
                    p.sid,
                    p.staging,
                    p.link.as_ref(),
                    p.sperm,
                    &dd,
                    tname,
                )?;
                let expect = match p.skind {
                    Kind::File => p.sexpect,
                    _ => Expect::Any,
                };
                match self.core.writer.remove(&p.from, expect) {
                    Ok(_) => {}
                    Err(e) if !e.refused && e.errno == libc::ENOENT => {}
                    Err(e) => {
                        let _ = rustix::fs::unlinkat(&dd, tname, AtFlags::empty());
                        return self.core.finish(p.sid, Err(e));
                    }
                }
                self.core.drop_deferred(p.sid);
                None
            }
            _ => return Err(Errno::EROFS),
        };
        if let Some(d) = p.dst {
            self.core.drop_deferred(d);
        }
        let mut t = self.core.tw();
        if !t.relink(p.sid, (parent, name), newparent, newname) {
            return Err(Errno::ENOENT);
        }
        if let Some(n) = t.get_mut(p.sid) {
            n.domain = p.ddom;
            if let Some(m) = new_meta {
                n.read_ver = m.version();
                n.meta = m;
            }
        }
        if p.ddom == GDomain::Local {
            drop(t);
            let _ = self.core.refresh_local(p.sid);
        }
        Ok(())
    }

    // a synced directory's overlay counterpart (its guest-only children) moves with it
    fn move_overlay(&self, fdir: &str, fname: &str, tdir: &str, tname: &str) {
        let Ok(sd) = self.core.overlay_dir(fdir, false) else {
            return;
        };
        if rustix::fs::statat(&sd, fname, AtFlags::SYMLINK_NOFOLLOW).is_err() {
            return;
        }
        if let Ok(dd) = self.core.overlay_dir(tdir, true) {
            let _ = rustix::fs::renameat(&sd, fname, &dd, tname);
        }
    }

    // writes the content of a synced entry into the overlay at dd/tname
    #[allow(clippy::too_many_arguments)]
    fn copy_out(
        &self,
        from: &RelPath,
        kind: Kind,
        id: NodeId,
        staging: Option<u32>,
        link: Option<&LinkTarget>,
        perm: u16,
        dd: &OwnedFd,
        tname: &str,
    ) -> Result<(), Errno> {
        if kind == Kind::Symlink {
            let l = link.ok_or(Errno::EIO)?;
            return rustix::fs::symlinkat(l.as_str(), dd, tname).map_err(erx);
        }
        let tmp = format!(
            "{}mv{}",
            crate::proto::path::TMP_PREFIX,
            self.next.fetch_add(1, Relaxed)
        );
        let flags =
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let out = rustix::fs::openat(
            dd,
            tmp.as_str(),
            flags,
            Mode::from_bits_truncate(u32::from(perm) as _),
        )
        .map_err(erx)?;
        let staged = staging.and_then(|s| self.core.writer.staging_fd(s));
        let r = fsops::fix_mode(out.as_fd(), u32::from(perm)).map_err(en);
        let r = r.and_then(|()| match staged {
            Some(fd) => sys::clone_or_copy(fd.as_fd(), out.as_fd()).map_err(|e| eio(&e)),
            None => match self.core.version_or_new(id, Instant::now() + WAIT)? {
                Some(v) if v.size > 0 => {
                    let deadline = Instant::now() + WAIT + Duration::from_millis(v.size >> 12);
                    self.core
                        .cache
                        .fetch_whole(&v.hash, from, v.size, deadline)
                        .map_err(en)
                        .and_then(|b| sys::clone_or_copy(b.fd(), out.as_fd()).map_err(|e| eio(&e)))
                }
                _ => Ok(()),
            },
        });
        drop(out);
        let r = r.and_then(|()| rustix::fs::renameat(dd, tmp.as_str(), dd, tname).map_err(erx));
        if r.is_err() {
            let _ = rustix::fs::unlinkat(dd, tmp.as_str(), AtFlags::empty());
        }
        r
    }

    // every entry below root, with the overlay loaded; anything a copy cannot carry is EXDEV
    fn scan_moved(&self, root: NodeId) -> Result<Vec<Moved>, Errno> {
        let mut out: Vec<Moved> = Vec::new();
        let mut stack: Vec<(NodeId, Option<usize>)> = vec![(root, None)];
        let mut bytes = 0u64;
        while let Some((dir, at)) = stack.pop() {
            self.core.load_local(dir);
            let t = self.core.t();
            let Some(kids) = t.get(dir).and_then(|n| n.children.as_ref()) else {
                continue;
            };
            let base = at.and_then(|i| out.get(i)).map(|m| m.rel.clone());
            for (name, &id) in kids {
                let Some(n) = t.get(id) else { continue };
                if n.vis == Vis::PendingDelete {
                    continue;
                }
                // read-only entries cannot leave the host, and a second name cannot follow its file
                if n.domain == GDomain::GitRo
                    || n.parent != dir
                    || n.name != *name
                    || t.has_links(id)
                {
                    return Err(Errno::EXDEV);
                }
                bytes = bytes.saturating_add(n.meta.size);
                if out.len() >= MOVE_ENTRIES || bytes > MOVE_BYTES {
                    return Err(Errno::EXDEV);
                }
                let rel = match &base {
                    Some(b) => format!("{b}/{}", name.as_str()),
                    None => name.as_str().to_owned(),
                };
                if n.is_dir() {
                    stack.push((id, Some(out.len())));
                }
                out.push(Moved {
                    id,
                    up: at,
                    rel,
                    meta: n.meta.clone(),
                    expect: node_expect(n, t.index_id()),
                    staging: n.staging,
                    special: n.special,
                    local: n.domain == GDomain::Local,
                    open: n.open.load(Relaxed) > 0,
                });
            }
        }
        Ok(out)
    }

    // close(2) returns before the kernel sends release, so a file written just before the rename may still
    // count as open for a moment
    fn scan_settled(&self, root: NodeId, busy: fn(&Moved) -> bool) -> Result<Vec<Moved>, Errno> {
        for _ in 0..STALE_TRIES {
            let items = self.scan_moved(root)?;
            if !items.iter().any(busy) {
                return Ok(items);
            }
            std::thread::sleep(STALE_STEP);
        }
        Err(Errno::EXDEV)
    }

    fn copy_moved(
        &self,
        from: &RelPath,
        to: &RelPath,
        m: &Moved,
    ) -> Result<Option<RelPath>, Errno> {
        let src = under(from, &m.rel)?;
        let dst = under(to, &m.rel)?;
        let (pd, nm) = dst.split_last().ok_or(Errno::EINVAL)?;
        let d = self.core.overlay_dir(pd, false).map_err(|e| eio(&e))?;
        let perm = u32::from(m.meta.perm);
        match m.meta.kind {
            Kind::Dir => match fsops::mkdir(d.as_fd(), nm, perm) {
                Ok(()) => Ok(Some(dst)),
                // the directory's guest-only part, already moved with its parent
                Err(libc::EEXIST) => fsops::chmod_at(d.as_fd(), nm, perm)
                    .map(|()| None)
                    .map_err(en),
                Err(e) => Err(en(e)),
            },
            kind => {
                let link = m.meta.link.as_ref();
                self.copy_out(&src, kind, m.id, m.staging, link, m.meta.perm, &d, nm)?;
                Ok(Some(dst))
            }
        }
    }

    fn unhost(&self, p: &RelPath, expect: Expect, meta: &Meta, left: &mut Vec<(RelPath, Meta)>) {
        match self.core.writer.remove(p, expect) {
            Ok(_) => {}
            Err(e) if !e.refused && e.errno == libc::ENOENT => {}
            Err(e) if e.refused => {
                if let Some(cur) = e.current {
                    left.push((p.clone(), cur));
                }
            }
            Err(_) => left.push((p.clone(), meta.clone())),
        }
    }

    // a synced directory renamed onto an ignored name: copied into the overlay, then removed from the host
    fn move_out(&self, mv: Move<'_>) -> Result<(), Errno> {
        // a file being written keeps its staged copy tied to the old path
        let items = self.scan_settled(mv.sid, |m| !m.local && m.staging.is_some() && m.open)?;
        let (fdir, fname) = mv.from.split_last().ok_or(Errno::EBUSY)?;
        let (tdir, tname) = mv.to.split_last().ok_or(Errno::EINVAL)?;
        let dd = self.core.overlay_dir(tdir, true).map_err(|e| eio(&e))?;
        let sd = self
            .core
            .overlay_dir(fdir, false)
            .ok()
            .filter(|sd| rustix::fs::statat(sd, fname, AtFlags::SYMLINK_NOFOLLOW).is_ok());
        // the guest-only part moves as a whole and the synced entries are copied in beside it
        let made_root = match &sd {
            Some(sd) => {
                rustix::fs::renameat(sd, fname, &dd, tname).map_err(erx)?;
                false
            }
            None => match fsops::mkdir(dd.as_fd(), tname, u32::from(mv.perm)) {
                Ok(()) => true,
                Err(libc::EEXIST) if mv.replaces.is_some() => {
                    fsops::chmod_at(dd.as_fd(), tname, u32::from(mv.perm)).map_err(en)?;
                    false
                }
                Err(e) => return Err(en(e)),
            },
        };
        let mut made: Vec<(RelPath, bool)> = Vec::new();
        let mut res = Ok(());
        for m in items.iter().filter(|m| !m.local) {
            match self.copy_moved(mv.from, mv.to, m) {
                Ok(Some(p)) => made.push((p, m.meta.kind == Kind::Dir)),
                Ok(None) => {}
                Err(e) => {
                    res = Err(e);
                    break;
                }
            }
        }
        if let Err(e) = res {
            for (p, dir) in made.iter().rev() {
                if let Some((d, n)) = p.split_last()
                    && let Ok(fd) = self.core.overlay_dir(d, false)
                {
                    let fl = if *dir {
                        AtFlags::REMOVEDIR
                    } else {
                        AtFlags::empty()
                    };
                    let _ = rustix::fs::unlinkat(&fd, n, fl);
                }
            }
            match &sd {
                Some(sd) => {
                    let _ = rustix::fs::renameat(&dd, tname, sd, fname);
                }
                None if made_root => {
                    let _ = rustix::fs::unlinkat(&dd, tname, AtFlags::REMOVEDIR);
                }
                None => {}
            }
            return Err(e);
        }
        // a held truncate must not recreate a file at the old path
        for m in items.iter().filter(|m| m.staging.is_some()) {
            self.core.drop_deferred(m.id);
        }
        let mut left = Vec::new();
        for m in items.iter().rev().filter(|m| !m.local) {
            if let Ok(p) = under(mv.from, &m.rel) {
                self.unhost(&p, m.expect, &m.meta, &mut left);
            }
        }
        let root = {
            let t = self.core.t();
            t.get(mv.sid)
                .map(|n| (n.meta.clone(), node_expect(n, t.index_id())))
        };
        if let Some((m, expect)) = root {
            self.unhost(mv.from, expect, &m, &mut left);
        }
        let mut fx = vec![Effect::InvalInode(mv.src.0), Effect::InvalInode(mv.dst.0)];
        {
            let mut t = self.core.tw();
            if !t.relink(mv.sid, mv.src, mv.dst.0, mv.dst.1) {
                drop(t);
                self.core.kick(fx);
                return Err(Errno::ENOENT);
            }
            let moved = items
                .iter()
                .filter(|m| !m.local)
                .map(|m| (m.id, m.meta.kind == Kind::Dir));
            for (id, dir) in std::iter::once((mv.sid, true)).chain(moved) {
                if let Some(n) = t.get_mut(id) {
                    n.domain = GDomain::Local;
                    n.staging = None;
                    n.page = None;
                    if *n.open.get_mut() == 0
                        && let Some(v) = n.read_ver.take()
                    {
                        fx.push(Effect::Unpin(v.hash));
                    }
                }
                if dir {
                    t.set_local_loaded(id);
                }
                fx.push(Effect::InvalInode(id));
            }
            for (p, m) in left.into_iter().rev() {
                restore_left(&mut t, &p, m, &mut fx);
            }
        }
        self.core.kick(fx);
        Ok(())
    }

    fn commit_moved(
        &self,
        from: &RelPath,
        to: &RelPath,
        m: &Moved,
        bytes: &mut u64,
    ) -> Result<(RelPath, Meta), Errno> {
        let src = under(from, &m.rel)?;
        let dst = under(to, &m.rel)?;
        let meta = match m.meta.kind {
            Kind::Dir => self.core.writer.mkdir(&dst, m.meta.perm).map_err(en)?,
            Kind::Symlink => {
                let target = self.core.read_local_link(&src).ok_or(Errno::EIO)?;
                if !target.stays_within(&dst) {
                    return Err(Errno::EXDEV);
                }
                let mut meta = self.core.writer.symlink(&dst, &target).map_err(en)?;
                meta.link.get_or_insert(target);
                meta
            }
            Kind::File => {
                let fd = sys::open_beneath(self.core.overlay.as_fd(), &src, OFlags::RDONLY)
                    .map_err(|e| eio(&e))?;
                let st = rustix::fs::fstat(&fd).map_err(erx)?;
                *bytes = bytes.saturating_add(u64::try_from(st.st_size).unwrap_or(0));
                if *bytes > MOVE_BYTES {
                    return Err(Errno::EXDEV);
                }
                let perm = (st.st_mode & 0o7777) as u16;
                self.core
                    .writer
                    .rename(RenameReq {
                        from: &dst,
                        to: &dst,
                        from_expect: Expect::Absent,
                        to_expect: Expect::Absent,
                        staging: None,
                        local: Some((fd.as_fd(), perm)),
                        discard: false,
                    })
                    .map_err(|e| en(e.errno))?
            }
        };
        Ok((dst, meta))
    }

    // an overlay directory renamed onto a synced name: its entries reach the host as new files
    fn move_in(&self, mv: Move<'_>) -> Result<(), Errno> {
        // an open overlay file would keep writing the inode left behind
        let items = self.scan_settled(mv.sid, |m| m.open && m.meta.kind == Kind::File)?;
        let mut doms: Vec<GDomain> = Vec::with_capacity(items.len());
        {
            let rules = self.core.rules();
            for m in &items {
                let up =
                    m.up.and_then(|i| doms.get(i).copied())
                        .unwrap_or(GDomain::Synced);
                let dest = under(mv.to, &m.rel)?;
                let class = rules.classify(&dest, m.meta.kind == Kind::Dir);
                let d = domain_for_new(up, class).map_err(|_| Errno::EXDEV)?;
                // the host has no fifos or sockets
                if d == GDomain::Synced && m.special != Special::None {
                    return Err(Errno::EXDEV);
                }
                doms.push(d);
            }
        }
        if mv.replaces.is_some() {
            match self.core.writer.remove(mv.to, Expect::Dir) {
                Ok(_) => {}
                Err(e) if !e.refused && e.errno == libc::ENOENT => {}
                Err(e) => return Err(en(e.errno)),
            }
        }
        let root = self.core.writer.mkdir(mv.to, mv.perm).map_err(en)?;
        let mut metas: Vec<Option<Meta>> = Vec::with_capacity(items.len());
        let mut done: Vec<(RelPath, Meta)> = Vec::new();
        let mut bytes = 0u64;
        let mut res = Ok(());
        for (m, d) in items.iter().zip(&doms) {
            if *d != GDomain::Synced {
                metas.push(None);
                continue;
            }
            match self.commit_moved(mv.from, mv.to, m, &mut bytes) {
                Ok((p, meta)) => {
                    done.push((p, meta.clone()));
                    metas.push(Some(meta));
                }
                Err(e) => {
                    res = Err(e);
                    break;
                }
            }
        }
        let (fdir, fname) = mv.from.split_last().ok_or(Errno::EBUSY)?;
        let (tdir, tname) = mv.to.split_last().ok_or(Errno::EINVAL)?;
        // the overlay entries move to the new path, where the ignored ones stay as its guest-only part
        let dd = res.and_then(|()| {
            let sd = self.core.overlay_dir(fdir, false).map_err(|e| eio(&e))?;
            let dd = self.core.overlay_dir(tdir, true).map_err(|e| eio(&e))?;
            rustix::fs::renameat(&sd, fname, &dd, tname).map_err(erx)?;
            Ok(dd)
        });
        let dd = match dd {
            Ok(dd) => dd,
            Err(e) => {
                for (p, m) in done.iter().rev() {
                    let _ = self.core.writer.remove(p, expect_of(m));
                }
                let _ = self.core.writer.remove(mv.to, Expect::Dir);
                return Err(e);
            }
        };
        for (m, d) in items.iter().zip(&doms).rev() {
            if *d != GDomain::Synced {
                continue;
            }
            if let Ok(p) = under(mv.to, &m.rel)
                && let Some((pd, nm)) = p.split_last()
                && let Ok(fd) = self.core.overlay_dir(pd, false)
            {
                let fl = if m.meta.kind == Kind::Dir {
                    AtFlags::REMOVEDIR
                } else {
                    AtFlags::empty()
                };
                let _ = rustix::fs::unlinkat(&fd, nm, fl);
            }
        }
        let _ = rustix::fs::unlinkat(&dd, tname, AtFlags::REMOVEDIR);
        let mut fx = vec![Effect::InvalInode(mv.src.0), Effect::InvalInode(mv.dst.0)];
        {
            let mut t = self.core.tw();
            if !t.relink(mv.sid, mv.src, mv.dst.0, mv.dst.1) {
                drop(t);
                self.core.kick(fx);
                return Err(Errno::ENOENT);
            }
            let moved = items.iter().zip(metas).map(|(m, meta)| (m.id, meta));
            for (id, meta) in std::iter::once((mv.sid, Some(root))).chain(moved) {
                let Some(meta) = meta else { continue };
                if let Some(n) = t.get_mut(id) {
                    n.domain = domain_of(&meta);
                    n.read_ver = meta.version();
                    n.meta = meta;
                }
                fx.push(Effect::InvalInode(id));
            }
        }
        self.core.kick(fx);
        Ok(())
    }

    // renameat2(RENAME_EXCHANGE) swaps two overlay names in place; the host has no such operation
    fn do_exchange(
        &self,
        parent: NodeId,
        name: &str,
        newparent: NodeId,
        newname: &Name,
    ) -> Result<(), Errno> {
        let nm = Name::new(name).map_err(|_| Errno::ENOENT)?;
        self.core.load_local(parent);
        self.core.load_local(newparent);
        let (a, b, from, to) = {
            let t = self.core.t();
            let (a, na) = t.lookup(parent, name).ok_or(Errno::ENOENT)?;
            let (b, nb) = t.lookup(newparent, newname.as_str()).ok_or(Errno::ENOENT)?;
            if na.domain != GDomain::Local || nb.domain != GDomain::Local {
                return Err(Errno::EINVAL);
            }
            if a == b {
                return Ok(());
            }
            (
                a,
                b,
                name_path(&t, a, na, parent, name).ok_or(Errno::ENOENT)?,
                name_path(&t, b, nb, newparent, newname.as_str()).ok_or(Errno::ENOENT)?,
            )
        };
        let (fdir, fname) = from.split_last().ok_or(Errno::EBUSY)?;
        let (tdir, tname) = to.split_last().ok_or(Errno::EBUSY)?;
        let sd = self.core.overlay_dir(fdir, false).map_err(|e| eio(&e))?;
        let dd = self.core.overlay_dir(tdir, false).map_err(|e| eio(&e))?;
        let xchg = rustix::fs::RenameFlags::EXCHANGE;
        rustix::fs::renameat_with(&sd, fname, &dd, tname, xchg).map_err(erx)?;
        if !self
            .core
            .tw()
            .exchange((a, parent, &nm), (b, newparent, newname))
        {
            let _ = rustix::fs::renameat_with(&sd, fname, &dd, tname, xchg);
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    // overlay names share the backing inode and the tree node; the host index has no hard links, so a synced
    // link is an independent copy with a link count of its own
    fn do_link(&self, id: NodeId, newparent: NodeId, newname: &OsStr) -> Result<NodeId, Errno> {
        let name = name_of(newname)?;
        let (sdom, kind, src) = {
            let t = self.core.t();
            let n = t.get(id).ok_or(Errno::ENOENT)?;
            if n.is_dir() {
                return Err(Errno::EPERM);
            }
            (n.domain, n.meta.kind, t.rel_path(id).ok_or(Errno::ENOENT)?)
        };
        let (dom, path) = self.prep_new(newparent, &name, false)?;
        match (sdom, dom) {
            (GDomain::Local, GDomain::Local) => {
                let (sdir, sname) = src.split_last().ok_or(Errno::EINVAL)?;
                let (ddir, dname) = path.split_last().ok_or(Errno::EINVAL)?;
                let sd = self.core.overlay_dir(sdir, false).map_err(|e| eio(&e))?;
                let dd = self.core.overlay_dir(ddir, true).map_err(|e| eio(&e))?;
                rustix::fs::linkat(&sd, sname, &dd, dname, AtFlags::empty()).map_err(erx)?;
                let mut t = self.core.tw();
                if !t.add_link(id, newparent, name) {
                    drop(t);
                    let _ = rustix::fs::unlinkat(&dd, dname, AtFlags::empty());
                    return Err(Errno::ENOENT);
                }
                t.add_lookup(id);
                Ok(id)
            }
            (GDomain::Synced | GDomain::GitRo, GDomain::Synced) if kind == Kind::Symlink => {
                let link = self.core.t().get(id).and_then(|n| n.meta.link.clone());
                let target = link.ok_or(Errno::EIO)?;
                if !target.stays_within(&path) {
                    return Err(Errno::EPERM);
                }
                let mut m = self.core.writer.symlink(&path, &target).map_err(en)?;
                m.link.get_or_insert(target);
                self.insert_new(newparent, &name, m, GDomain::Synced)
            }
            (GDomain::Synced | GDomain::GitRo, GDomain::Synced) => {
                self.link_copy(id, newparent, &name)
            }
            _ => Err(Errno::EXDEV),
        }
    }

    fn link_copy(&self, id: NodeId, newparent: NodeId, name: &Name) -> Result<NodeId, Errno> {
        let (path, meta, staging) = {
            let t = self.core.t();
            let n = t.get(id).ok_or(Errno::ENOENT)?;
            (
                t.rel_path(id).ok_or(Errno::ENOENT)?,
                n.meta.clone(),
                n.staging,
            )
        };
        let staged = staging.and_then(|s| self.core.writer.staging_fd(s));
        let held = match (&staged, meta.version()) {
            (None, None) => self.core.version_or_new(id, Instant::now() + WAIT)?,
            (_, v) => v,
        };
        let blob = match (&staged, held) {
            (None, Some(v)) if v.size > 0 => {
                let deadline = Instant::now() + WAIT + Duration::from_millis(v.size >> 12);
                let b = self
                    .core
                    .cache
                    .fetch_whole(&v.hash, &path, v.size, deadline);
                Some(b.map_err(en)?)
            }
            _ => None,
        };
        let (nid, src) = self.new_file(newparent, name, meta.perm)?;
        let from = staged
            .as_deref()
            .map(|f| f.as_fd())
            .or_else(|| blob.as_ref().map(|b| b.fd()));
        let (sid, copied) = match &src {
            Src::Staged { id: sid, fd } => {
                (Some(*sid), from.map(|f| sys::clone_or_copy(f, fd.as_fd())))
            }
            Src::Local { fd } => (None, from.map(|f| sys::clone_or_copy(f, fd.as_fd()))),
            _ => (None, None),
        };
        let mut r = copied.unwrap_or(Ok(())).map_err(|e| eio(&e));
        if let Some(sid) = sid {
            let f = r.and_then(|()| self.core.finish(nid, self.core.writer.flush(sid, false)));
            let rel = self
                .core
                .writer
                .release(sid)
                .map_or(Ok(()), |x| self.core.finish(nid, x));
            if self.core.writer.staging_fd(sid).is_none()
                && let Some(n) = self.core.tw().get_mut(nid)
                && n.staging == Some(sid)
            {
                n.staging = None;
            }
            r = f.and(rel);
        }
        drop(src);
        self.core.drop_open(nid);
        if r.is_err() {
            let _ = self.do_unlink(newparent, OsStr::new(name.as_str()), false);
        }
        r.map(|()| nid)
    }

    // an unlinked file lives on in its open handles, so the kernel's size and time updates land on that copy
    #[allow(clippy::too_many_arguments)]
    fn setattr_unlinked(
        &self,
        id: NodeId,
        staging: Option<u32>,
        handle: Option<Arc<Handle>>,
        mode: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<(), Errno> {
        if size.is_some_and(|sz| sz > FILE_MAX) {
            return Err(Errno::EFBIG);
        }
        let open = handle.filter(|h| h.node == id).or_else(|| {
            lock(&self.handles)
                .values()
                .find(|h| h.node == id && matches!(h.src, Src::Local { .. }))
                .cloned()
        });
        let staged = match open.as_deref().map(|h| &h.src) {
            Some(Src::Staged { fd, .. }) => Some(fd.clone()),
            _ => staging.and_then(|s| self.core.writer.staging_fd(s)),
        };
        let fd = match (&staged, open.as_deref().map(|h| &h.src)) {
            (Some(fd), _) => fd.as_fd(),
            (None, Some(Src::Local { fd })) => fd.as_fd(),
            // the kernel flushes its times to an inode it unlinks and keeps a refusal as a writeback error
            _ if size.is_none() && mode.is_none() => {
                let mut t = self.core.tw();
                let n = t
                    .get_mut(id)
                    .filter(|n| !n.attached())
                    .ok_or(Errno::ENOENT)?;
                if let Some(m) = mtime {
                    n.meta.mtime_ns = match m {
                        TimeOrNow::SpecificTime(s) => ns_of(s),
                        TimeOrNow::Now => now_ns(),
                    };
                }
                return Ok(());
            }
            _ => return Err(Errno::ENOENT),
        };
        if let Some(sz) = size {
            rustix::fs::ftruncate(fd, sz).map_err(erx)?;
        }
        if let Some(m) = mode {
            rustix::fs::fchmod(fd, Mode::from_bits_truncate((m & 0o7777) as _)).map_err(erx)?;
        }
        if atime.is_some() || mtime.is_some() {
            let ts = Timestamps {
                last_access: timespec(atime),
                last_modification: timespec(mtime),
            };
            rustix::fs::futimens(fd, &ts).map_err(erx)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn do_setattr(
        &self,
        id: NodeId,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        fh: Option<FileHandle>,
    ) -> Result<(), Errno> {
        // a truncate by path lands on the staged copy or after its commit, never in between
        let _turn = self.core.stage_turn(id);
        let (domain, kind, meta, mut staging, path) = {
            let t = self.core.t();
            let n = t.get(id).ok_or(Errno::ENOENT)?;
            (
                n.domain,
                n.meta.kind,
                n.meta.clone(),
                n.staging,
                t.rel_path(id),
            )
        };
        let changes = mode.is_some() || size.is_some() || mtime.is_some();
        let path = match path {
            Some(p) => p,
            None if !changes => return Ok(()),
            None => {
                let h = fh.and_then(|f| self.handle(f.0));
                return self.setattr_unlinked(id, staging, h, mode, size, atime, mtime);
            }
        };
        let handle = fh.and_then(|f| self.handle(f.0));
        match domain {
            GDomain::GitRo if changes => Err(Errno::EROFS),
            GDomain::GitRo => Ok(()),
            GDomain::Local => {
                let (dir, name) = path.split_last().ok_or(Errno::EINVAL)?;
                let d = self.core.overlay_dir(dir, false).map_err(|e| eio(&e))?;
                if uid.is_some() || gid.is_some() {
                    fsops::chown_at(d.as_fd(), name, uid, gid).map_err(en)?;
                }
                if let Some(m) = mode {
                    if kind == Kind::Symlink {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    fsops::chmod_at(d.as_fd(), name, m).map_err(en)?;
                }
                if let Some(sz) = size {
                    match handle.as_deref().map(|h| &h.src) {
                        Some(Src::Local { fd }) => rustix::fs::ftruncate(fd, sz).map_err(erx)?,
                        _ => {
                            let fd =
                                sys::open_beneath(self.core.overlay.as_fd(), &path, OFlags::WRONLY)
                                    .map_err(|e| eio(&e))?;
                            rustix::fs::ftruncate(&fd, sz).map_err(erx)?;
                        }
                    }
                }
                if atime.is_some() || mtime.is_some() {
                    let ts = Timestamps {
                        last_access: timespec(atime),
                        last_modification: timespec(mtime),
                    };
                    rustix::fs::utimensat(&d, name, &ts, AtFlags::SYMLINK_NOFOLLOW).map_err(erx)?;
                }
                self.core.refresh_local(id)
            }
            GDomain::Synced => {
                if let Some(sz) = size {
                    if sz > FILE_MAX {
                        return Err(Errno::EFBIG);
                    }
                    if kind != Kind::File {
                        return Err(Errno::EISDIR);
                    }
                    let fd = match handle.as_deref().map(|h| &h.src) {
                        Some(Src::Staged { fd, .. }) => Some(fd.clone()),
                        _ => staging.and_then(|s| self.core.writer.staging_fd(s)),
                    };
                    match fd {
                        Some(fd) => rustix::fs::ftruncate(&*fd, sz).map_err(erx)?,
                        // held locally and folded into the commit of the write that follows
                        None if sz == 0 => {
                            let o = OpenW {
                                path: &path,
                                base: self.base_of(id, &meta)?,
                                perm: meta.perm,
                                trunc: true,
                                staging: None,
                            };
                            let (sid, _) = self.core.writer.open_for_write(o).map_err(en)?;
                            self.core.writer.defer(sid);
                            if let Some(n) = self.core.tw().get_mut(id) {
                                n.staging = Some(sid);
                                n.page = None;
                            }
                            self.hold_truncate(id, sid);
                            staging = Some(sid);
                        }
                        None => {
                            let o = OpenW {
                                path: &path,
                                base: self.base_of(id, &meta)?,
                                perm: meta.perm,
                                trunc: false,
                                staging: None,
                            };
                            let (sid, fd) = self.core.writer.open_for_write(o).map_err(en)?;
                            let t = rustix::fs::ftruncate(&*fd, sz).map_err(erx);
                            let f = t.and_then(|()| {
                                self.core.finish(id, self.core.writer.flush(sid, false))
                            });
                            let r = self
                                .core
                                .writer
                                .release(sid)
                                .map_or(Ok(()), |r| self.core.finish(id, r));
                            f.and(r)?;
                        }
                    }
                }
                // writeback flushes carry the kernel's own mtime alone; utimensat sets atime with it
                let mtime = if staging.is_some() && mode.is_none() && atime.is_none() {
                    None
                } else {
                    mtime
                };
                // symlinks have no mode of their own; lutimes reaches the host like any other mtime
                if kind == Kind::Symlink {
                    if mode.is_some() {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    let Some(t) = mtime else { return Ok(()) };
                    let mt = match t {
                        TimeOrNow::SpecificTime(s) => ns_of(s),
                        TimeOrNow::Now => now_ns(),
                    };
                    let m = match self.core.writer.setattr(&path, Expect::Any, None, Some(mt)) {
                        Ok(m) => m,
                        Err(e) if e.refused => return self.core.finish(id, Err(e)),
                        Err(e) => return Err(en(e.errno)),
                    };
                    if let Some(n) = self.core.tw().get_mut(id) {
                        n.meta.mtime_ns = m.mtime_ns;
                        n.meta.ctime_ns = m.ctime_ns;
                    }
                    return Ok(());
                }
                if mode.is_some() || mtime.is_some() {
                    // the host must hold the content first, or a new file is not there to change
                    if let Some(sid) = staging {
                        self.core.finish(id, self.core.writer.flush_ordered(sid))?;
                    }
                    // a size change above has committed a newer version than the one read on entry
                    let expect = {
                        let t = self.core.t();
                        let n = t.get(id).ok_or(Errno::ENOENT)?;
                        node_expect(n, t.index_id())
                    };
                    let perm = mode.map(|m| (m & 0o7777) as u16);
                    let mt = mtime.map(|t| match t {
                        TimeOrNow::SpecificTime(s) => ns_of(s),
                        TimeOrNow::Now => now_ns(),
                    });
                    match self.core.writer.setattr(&path, expect, perm, mt) {
                        Ok(m) => {
                            if let Some(n) = self.core.tw().get_mut(id) {
                                n.meta.perm = m.perm;
                                n.meta.mtime_ns = m.mtime_ns;
                                n.meta.ctime_ns = m.ctime_ns;
                            }
                            // an open file reports its staging copy's mtime, so that copy takes the new one
                            if mtime.is_some()
                                && let Some(fd) =
                                    staging.and_then(|s| self.core.writer.staging_fd(s))
                            {
                                let ts = Timestamps {
                                    last_access: timespec(None),
                                    last_modification: timespec(Some(TimeOrNow::SpecificTime(
                                        systime(m.mtime_ns),
                                    ))),
                                };
                                rustix::fs::futimens(&*fd, &ts).map_err(erx)?;
                            }
                        }
                        // a newer host save supersedes a time-only change; a refusal would stick to the inode as a writeback error
                        Err(e) if e.refused && size.is_none() && mode.is_none() => {
                            let _ = self.core.finish(id, Err(e));
                        }
                        Err(e) => return self.core.finish(id, Err(e)),
                    }
                }
                Ok(())
            }
        }
    }
}

impl Filesystem for GuestFs {
    fn init(&mut self, _req: &Request, cfg: &mut KernelConfig) -> io::Result<()> {
        let caps = cfg.capabilities();
        #[cfg(target_os = "linux")]
        let base = InitFlags::FUSE_ASYNC_READ
            | InitFlags::FUSE_PARALLEL_DIROPS
            | InitFlags::FUSE_DO_READDIRPLUS
            | InitFlags::FUSE_CACHE_SYMLINKS
            | InitFlags::FUSE_ATOMIC_O_TRUNC
            | InitFlags::FUSE_MAX_PAGES
            | InitFlags::FUSE_EXPLICIT_INVAL_DATA;
        // flags that change how the kernel invalidates data or symlinks stay off where no notification is guaranteed
        #[cfg(target_os = "macos")]
        let base = InitFlags::FUSE_ASYNC_READ
            | InitFlags::FUSE_PARALLEL_DIROPS
            | InitFlags::FUSE_DO_READDIRPLUS
            | InitFlags::FUSE_ATOMIC_O_TRUNC;
        let _ = cfg.add_capabilities(base & caps);
        // passthrough and writeback cache are mutually exclusive in the kernel
        #[cfg(target_os = "linux")]
        {
            self.pass = caps.contains(InitFlags::FUSE_PASSTHROUGH)
                && has_cap_sys_admin()
                && cfg.set_max_stack_depth(1).is_ok()
                && cfg.add_capabilities(InitFlags::FUSE_PASSTHROUGH).is_ok();
        }
        #[cfg(target_os = "linux")]
        let wb = !self.pass
            && caps.contains(InitFlags::FUSE_WRITEBACK_CACHE)
            && cfg
                .add_capabilities(InitFlags::FUSE_WRITEBACK_CACHE)
                .is_ok();
        #[cfg(target_os = "macos")]
        let wb = false;
        // without writeback cache a read-only handle never holds dirty pages
        self.noflush = !wb;
        #[cfg(target_os = "linux")]
        {
            super::inject::SIZES_FROM_ATTRS.store(!wb, Relaxed);
            self.no_opendir = caps.contains(InitFlags::FUSE_NO_OPENDIR_SUPPORT);
        }
        // sizes follow attribute replies only once the startup self-test has shown they do
        #[cfg(target_os = "macos")]
        super::inject::SIZES_FROM_ATTRS.store(false, Relaxed);
        self.core.passthrough.store(self.pass, Relaxed);
        let _ = cfg.set_max_write(IO_MAX).or_else(|n| cfg.set_max_write(n));
        let _ = cfg
            .set_max_readahead(IO_MAX)
            .or_else(|n| cfg.set_max_readahead(n));
        let _ = cfg.set_max_background(BACKGROUND_MAX);
        Ok(())
    }

    // held truncates reach the host before the link closes
    fn destroy(&mut self) {
        let held = self
            .hold
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(Hold { tx, join }) = held {
            drop(tx);
            let _ = join.join();
        }
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        self.core.ctr.op(Op::Lookup);
        let Some(name) = name.to_str() else {
            return reply.error(Errno::ENOENT);
        };
        let inj = self.is_inj(req);
        let mut gone = false;
        for pass in 0..2 {
            {
                let t = self.core.t();
                // the injector's announcements lag the tree: a pending create is visible and a pending
                // delete gone at once, so no host change is seen before one applied with it, as a git
                // ref would be before the object it names
                let found = t
                    .lookup_as(parent.0, name, inj)
                    .map(|(id, _)| id)
                    .or_else(|| t.pending_create(parent.0, name).filter(|_| !inj));
                let found = found.filter(|&id| {
                    gone = !inj && t.get(id).is_some_and(|n| n.vis == Vis::PendingDelete);
                    !gone
                });
                if let Some(id) = found {
                    t.add_lookup(id);
                    #[cfg(target_os = "macos")]
                    coherence::PROBE.lookup(id);
                    if let Some(n) = t.get(id) {
                        return reply.entry(
                            &ttl_of(n),
                            &self.core.entry_attr(&t, id, n),
                            Generation(n.r#gen),
                        );
                    }
                }
                match t.get(parent.0) {
                    Some(p) if p.is_dir() => {}
                    Some(_) => return reply.error(Errno::ENOTDIR),
                    None => return reply.error(Errno::ENOENT),
                }
                if pass == 1 || t.local_loaded(parent.0) {
                    break;
                }
            }
            self.core.load_local(parent.0);
        }
        let neg = FileAttr {
            ino: INodeNo(0),
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0,
            nlink: 0,
            uid: self.core.uid,
            gid: self.core.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        };
        // an uncached miss: the injector's precedes its create, and a pending delete is still the injector's to find
        let in_git = self
            .core
            .t()
            .get(parent.0)
            .is_some_and(|p| p.domain == GDomain::GitRo);
        let ttl = if inj || gone || in_git {
            Duration::ZERO
        } else {
            synced_ttl()
        };
        reply.entry(&ttl, &neg, Generation(0));
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.core.ctr.op(Op::Forget);
        self.core.tw().forget(ino.0, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        self.core.ctr.op(Op::Getattr);
        #[cfg(target_os = "macos")]
        coherence::PROBE.getattr(ino.0);
        match self.core.live_attr(ino.0) {
            Ok((a, ttl, _)) => self.attr_reply(ino.0, &ttl, &a, reply),
            // an unlinked overlay file is still reachable through a descriptor that stays open
            Err(e) => match self.open_local_stat(ino.0, fh) {
                Some((a, ttl)) => reply.attr(&ttl, &a),
                None => reply.error(e),
            },
        }
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        _kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        self.core.ctr.op(Op::Setattr);
        #[cfg(target_os = "linux")]
        let inj = self.is_inj(req);
        // the self-test's truncate is answered as an injected one: the reply, not a truncate, sets the size
        #[cfg(target_os = "macos")]
        let inj = self.is_inj(req) || coherence::PROBE.setattr(ino.0);
        if !inj && let Err(e) = self.do_setattr(ino.0, mode, uid, gid, size, atime, mtime, fh) {
            return reply.error(e);
        }
        match self.core.live_attr(ino.0) {
            Ok((a, ttl, _)) => self.attr_reply(ino.0, &ttl, &a, reply),
            Err(e) => match self.open_local_stat(ino.0, fh) {
                Some((a, ttl)) => reply.attr(&ttl, &a),
                None => reply.error(e),
            },
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        self.core.ctr.op(Op::Other);
        let (domain, link, path) = {
            let t = self.core.t();
            let Some(n) = t.get(ino.0) else {
                return reply.error(Errno::ENOENT);
            };
            if n.meta.kind != Kind::Symlink {
                return reply.error(Errno::EINVAL);
            }
            (n.domain, n.meta.link.clone(), t.rel_path(ino.0))
        };
        let link = match (domain, link) {
            (GDomain::Local, _) => path.and_then(|p| self.core.read_local_link(&p)),
            (_, l) => l,
        };
        match link {
            Some(l) => reply.data(l.as_str().as_bytes()),
            None => reply.error(Errno::EIO),
        }
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        self.core.ctr.op(Op::Mutate);
        let special = fsops::special_of_mode(mode);
        if mode & S_IFMT != S_IFREG && special == Special::None {
            return reply.error(Errno::EPERM);
        }
        if self.is_inj(req) {
            return reply.error(Errno::EEXIST);
        }
        let name = match name_of(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        let perm = (mode & !umask & 0o7777) as u16;
        if special != Special::None {
            return match self.new_special(parent.0, &name, special, perm) {
                Ok(id) => self.entry_reply(id, reply),
                Err(e) => reply.error(e),
            };
        }
        match self.new_file(parent.0, &name, perm) {
            Ok((id, src)) => {
                let r = match src {
                    Src::Staged { id: sid, .. } => {
                        let f = self.core.finish(id, self.core.writer.flush(sid, false));
                        let rel = self
                            .core
                            .writer
                            .release(sid)
                            .map_or(Ok(()), |r| self.core.finish(id, r));
                        if let Some(n) = self.core.tw().get_mut(id) {
                            n.staging = None;
                        }
                        f.and(rel)
                    }
                    _ => Ok(()),
                };
                self.core.drop_open(id);
                match r {
                    Ok(()) => self.entry_reply(id, reply),
                    Err(e) => reply.error(e),
                }
            }
            Err(e) => reply.error(e),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        self.core.ctr.op(Op::Mutate);
        let name = match name_of(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        if self.is_inj(req) {
            let done = self.core.tw().complete_create(parent.0, name.as_str());
            return match done {
                Some(id) => {
                    self.core.tw().add_lookup(id);
                    self.entry_reply(id, reply)
                }
                None => reply.error(Errno::EEXIST),
            };
        }
        let perm = (mode & !umask & 0o7777) as u16;
        let r = (|| -> Result<NodeId, Errno> {
            let (dom, path) = self.prep_new(parent.0, &name, true)?;
            let meta = match dom {
                GDomain::Local => {
                    let (dir, nm) = path.split_last().ok_or(Errno::EINVAL)?;
                    let d = self.core.overlay_dir(dir, true).map_err(|e| eio(&e))?;
                    fsops::mkdir(d.as_fd(), nm, u32::from(perm)).map_err(en)?;
                    let k = sys::stat_key_at(d.as_fd(), nm).map_err(|e| eio(&e))?;
                    meta_from_key(&k, None).ok_or(Errno::EIO)?
                }
                GDomain::Synced => self.core.writer.mkdir(&path, perm).map_err(en)?,
                GDomain::GitRo => return Err(Errno::EROFS),
            };
            self.insert_new(parent.0, &name, meta, dom)
        })();
        match r {
            Ok(id) => self.entry_reply(id, reply),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.core.ctr.op(Op::Mutate);
        if self.is_inj(req) {
            let ok = name
                .to_str()
                .is_some_and(|n| self.core.tw().complete_delete(parent.0, n));
            return if ok {
                reply.ok()
            } else {
                reply.error(Errno::ENOENT)
            };
        }
        match self.do_unlink(parent.0, name, false) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.core.ctr.op(Op::Mutate);
        if self.is_inj(req) {
            let ok = name
                .to_str()
                .is_some_and(|n| self.core.tw().complete_delete(parent.0, n));
            return if ok {
                reply.ok()
            } else {
                reply.error(Errno::ENOENT)
            };
        }
        match self.do_unlink(parent.0, name, true) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        self.core.ctr.op(Op::Mutate);
        let name = match name_of(link_name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        if self.is_inj(req) {
            let done = self.core.tw().complete_create(parent.0, name.as_str());
            return match done {
                Some(id) => {
                    self.core.tw().add_lookup(id);
                    self.entry_reply(id, reply)
                }
                None => reply.error(Errno::EEXIST),
            };
        }
        let r = (|| -> Result<NodeId, Errno> {
            let target = target.to_str().ok_or(Errno::EINVAL)?;
            let target = LinkTarget::new(target).map_err(|e| {
                if e == PathError::TooLong {
                    Errno::ENAMETOOLONG
                } else {
                    Errno::EINVAL
                }
            })?;
            let (dom, path) = self.prep_new(parent.0, &name, false)?;
            let meta = match dom {
                GDomain::Synced => {
                    if !target.stays_within(&path) {
                        return Err(Errno::EPERM);
                    }
                    let mut m = self.core.writer.symlink(&path, &target).map_err(en)?;
                    m.link.get_or_insert(target);
                    m
                }
                GDomain::Local => {
                    let (dir, nm) = path.split_last().ok_or(Errno::EINVAL)?;
                    let d = self.core.overlay_dir(dir, true).map_err(|e| eio(&e))?;
                    rustix::fs::symlinkat(target.as_str(), &d, nm).map_err(erx)?;
                    let k = sys::stat_key_at(d.as_fd(), nm).map_err(|e| eio(&e))?;
                    meta_from_key(&k, Some(target)).ok_or(Errno::EIO)?
                }
                GDomain::GitRo => return Err(Errno::EROFS),
            };
            self.insert_new(parent.0, &name, meta, dom)
        })();
        match r {
            Ok(id) => self.entry_reply(id, reply),
            Err(e) => reply.error(e),
        }
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        _owner: Option<Owner>,
        reply: ReplyEmpty,
    ) {
        self.core.ctr.op(Op::Mutate);
        if self.is_inj(req) {
            let ok = match (name.to_str(), newname.to_str()) {
                (Some(a), Some(b)) => self.core.tw().complete_move(parent.0, a, newparent.0, b),
                _ => false,
            };
            return if ok {
                reply.ok()
            } else {
                reply.error(Errno::EINVAL)
            };
        }
        match self.do_rename(parent.0, name, newparent.0, newname, flags) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn open(
        &self,
        req: &Request,
        ino: INodeNo,
        flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        self.core.ctr.op(Op::Open);
        if self.is_inj(req) {
            let nf = self.noflush(&Src::Empty);
            let live = lock(&self.io).get(&ino.0).and_then(|e| e.backing.upgrade());
            return match live {
                // the kernel takes nothing else while the inode has a backing file
                Some(b) => reply.opened_passthrough(FileHandle(INJ_FH), nf, &b),
                None => reply.opened(FileHandle(INJ_FH), FopenFlags::FOPEN_DIRECT_IO | nf),
            };
        }
        let id = ino.0;
        let write = flags.acc_mode() != OpenAccMode::O_RDONLY;
        let trunc = flags.0 & libc::O_TRUNC != 0;
        let switching = |id| self.core.inval.get().is_some_and(|k| k.switching(id));
        let (domain, meta, staging, path, parent, settled, seen) = {
            let t = self.core.t();
            let Some(n) = t.get(id).filter(|n| n.vis != Vis::PendingDelete) else {
                return reply.error(Errno::ENOENT);
            };
            if n.meta.kind != Kind::File {
                return reply.error(if n.is_dir() {
                    Errno::EISDIR
                } else {
                    Errno::ELOOP
                });
            }
            // a reopen of the version the page cache already holds changes nothing but the open count
            let settled = !write
                && !trunc
                && n.domain != GDomain::Local
                && n.staging.is_none()
                && n.read_ver.is_some()
                && n.read_ver == n.meta.version()
                && n.page == n.meta.hash
                && n.kernel_ver() == n.meta.version()
                && !n.size_pending
                && !switching(id);
            if settled {
                t.add_open(id);
                n.cached.fetch_add(1, Relaxed);
            }
            (
                n.domain,
                n.meta.clone(),
                n.staging,
                t.rel_path(id),
                n.parent,
                settled,
                n.read_ver.is_some() || n.edited,
            )
        };
        let cached = |v: Option<Version>| {
            v.is_some_and(|v| {
                self.core
                    .cache
                    .get(&v.hash)
                    .is_some_and(|b| b.is_complete())
            })
        };
        let path = match path {
            Some(p) => p,
            // the name was replaced while the kernel opened it: the inode it found still reads its own
            // content, as a local file would, and no path is needed when that content is held here
            None if !write
                && !trunc
                && domain == GDomain::Synced
                && staging.is_none()
                && cached(meta.version()) =>
            {
                RelPath::root()
            }
            None => {
                if settled {
                    self.uncache(id);
                    self.core.drop_open(id);
                }
                // a cached name for an inode the host replaced: ESTALE makes the kernel walk the path again
                return reply.error(Errno::ESTALE);
            }
        };
        if domain == GDomain::GitRo && (write || trunc) {
            return reply.error(Errno::EROFS);
        }
        let (mut keep, mut direct) = (true, false);
        let src = if domain == GDomain::Local {
            match sys::open_beneath(self.core.overlay.as_fd(), &path, Self::local_flags(flags.0)) {
                Ok(fd) => {
                    self.core.t().add_open(id);
                    Src::Local { fd }
                }
                Err(e) => return reply.error(eio(&e)),
            }
        } else if write || trunc || staging.is_some() {
            match self.open_staged(
                id,
                OpenW {
                    path: &path,
                    base: meta.version(),
                    perm: meta.perm,
                    trunc,
                    staging,
                },
            ) {
                Ok((sid, fd)) => {
                    // writes land in the page cache under no blob, so the next read-only open drops it
                    if let Some(n) = self.core.tw().get_mut(id) {
                        n.page = None;
                    }
                    Src::Staged { id: sid, fd }
                }
                Err(e) => return reply.error(e),
            }
        } else {
            let known = match meta.version() {
                Some(v) => Some(v),
                // resolving inline fills the cache for a small file in the same round trip
                None => match self.core.version_or_new(id, Instant::now() + WAIT) {
                    Ok(v) => v,
                    Err(e) => return reply.error(e),
                },
            };
            let Some(ver) = known else {
                if meta.size != 0 {
                    return reply.error(Errno::EIO);
                }
                // the page cache still holds a blob for readers of it: read around it until it moves
                let behind = {
                    let t = self.core.t();
                    t.add_open(id);
                    t.get(id).is_some_and(|n| {
                        let b = n.kernel_ver().is_some() || switching(id);
                        if !b {
                            n.cached.fetch_add(1, Relaxed);
                        }
                        b
                    })
                };
                let io = if behind {
                    self.core.kick(vec![Effect::Reshow(id)]);
                    Io::Direct
                } else {
                    // counted like any cached open: the kernel puts the inode in caching mode for it
                    self.counted(id, self.choose_io(id, None, &|fd| reply.open_backing(fd)))
                };
                return self.reply_new(
                    reply,
                    Handle {
                        node: id,
                        io,
                        src: Src::Empty,
                    },
                );
            };
            let (ver, early) = match domain {
                GDomain::GitRo if !settled && ver.size <= EAGER_GIT_MAX => {
                    match self.git_small(id, ver, &path) {
                        Ok(r) => r,
                        Err(e) => return reply.error(e),
                    }
                }
                _ => (ver, None),
            };
            let view = match domain {
                GDomain::GitRo => self.git_view(ver, &path),
                _ => None,
            };
            let view = view.or(early);
            let page = view.as_ref().map_or(ver.hash, |b| *b.hash());
            let pin = match view {
                Some(_) => None,
                None => self.core.cache.open_hit(&ver.hash),
            };
            let cached = match pin {
                Some(_) => None,
                None => view.or_else(|| self.core.cache.get(&ver.hash).filter(|b| b.is_complete())),
            };
            let hit = pin.is_some() || cached.is_some();
            if !hit {
                self.core.cache.note(&ver.hash, &path, ver.size);
            }
            let cold = !hit && ver.size > 0;
            let c = if cold {
                &self.core.ctr.misses
            } else {
                &self.core.ctr.hits
            };
            c.fetch_add(1, Relaxed);
            if !cold && pin.is_none() {
                self.core.cache.note_open(&ver.hash);
            }
            // an edit to a file read before may be replaced again before it is fetched: a direct handle
            // can still move to the replacement before its first byte, a page cache cannot; one read
            // fetches a source file whole, a large file stays on the page cache
            direct = cold && seen && ver.size <= u64::from(IO_MAX);
            if direct && settled {
                self.uncache(id);
            }
            if !settled {
                keep = false;
                let (mut fresh, mut behind) = (false, false);
                let mut t = self.core.tw();
                if let Some(n) = t.get_mut(id) {
                    n.read_ver = Some(ver);
                    match (n.page, n.shown) {
                        (Some(_), Some(k)) if direct => behind = k != ver,
                        _ if direct => {}
                        // the page cache still serves open readers another version: this handle reads
                        // its own around it, so no reader ever mixes two
                        (Some(_), Some(k)) if k != ver || switching(id) || n.size_pending => {
                            (direct, behind) = (true, k != ver);
                        }
                        (Some(_), Some(_)) => keep = n.page.replace(page) == Some(page),
                        _ if n.cached.load(Relaxed) > 0 => direct = true,
                        // nothing the kernel holds is known to be a blob's: start it on this version
                        _ => {
                            n.page = Some(page);
                            n.shown = Some(ver);
                            fresh = true;
                        }
                    }
                    if !direct {
                        n.cached.fetch_add(1, Relaxed);
                    }
                }
                t.add_open(id);
                drop(t);
                if fresh && let Some(k) = self.core.inval.get() {
                    k.attrs(id);
                }
                if behind {
                    self.core.kick(vec![Effect::Reshow(id)]);
                }
            }
            // a warm open has nothing to prefetch, so it must not wake the prefetch thread
            if cold {
                self.core.prefetch.hint(Hint::Open {
                    dir: parent,
                    node: id,
                    cold,
                });
            }
            let blob = OnceLock::new();
            if let Some(b) = cached {
                let _ = blob.set(b);
            }
            Src::Blob {
                path,
                ver,
                blob,
                _pin: pin,
                swap: Mutex::new(None),
            }
        };
        let io = if direct {
            Io::Direct
        } else {
            match self.choose_io(id, Self::src_key(&src), &|fd| reply.open_backing(fd)) {
                Io::Cached if !keep => Io::Fresh,
                io => io,
            }
        };
        let io = match src {
            Src::Blob { .. } if !direct => self.counted(id, io),
            _ => io,
        };
        self.reply_new(reply, Handle { node: id, io, src });
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.core.ctr.op(Op::Read);
        let Some(h) = self.handle(fh.0) else {
            return reply.error(Errno::EBADF);
        };
        let want = size.min(IO_MAX) as usize;
        if let Some((cur, path)) = self.moved_on(&h) {
            let cur = match cur {
                Some(v) => Some(v),
                None => match self.core.version_or_new(h.node, Instant::now() + WAIT) {
                    Ok(v) => v,
                    Err(e) => return reply.error(e),
                },
            };
            return match cur {
                Some(v) => self.read_version(h.node, v, &path, offset, want, reply, None),
                None => reply.data(&[]),
            };
        }
        match &h.src {
            Src::Blob {
                path,
                ver,
                blob,
                swap,
                ..
            } => {
                // only a direct read from the start has no size or earlier bytes to disagree with
                let sw = (matches!(h.io, Io::Direct) && offset == 0).then_some(swap);
                let swapped = lock(swap).as_deref().cloned();
                if let Some((v, p)) = swapped {
                    return self.read_version(h.node, v, &p, offset, want, reply, sw);
                }
                if offset >= ver.size {
                    return reply.data(&[]);
                }
                let len = (ver.size - offset).min(want as u64) as usize;
                let fetched;
                let r: &BlobRef = match blob.get() {
                    Some(b) => b,
                    None => {
                        let deadline =
                            Instant::now() + WAIT + Duration::from_millis(ver.size >> 12);
                        let c = &self.core.ctr.inflight;
                        c.fetch_add(1, Relaxed);
                        let res = self
                            .core
                            .cache
                            .fetch_at(&ver.hash, path, ver.size, offset, len as u32, deadline);
                        c.fetch_sub(1, Relaxed);
                        match res {
                            Ok(b) => {
                                if b.is_complete() {
                                    self.core.cache.note_open(&ver.hash);
                                    let _ = blob.set(b.clone());
                                }
                                fetched = b;
                                &fetched
                            }
                            Err(e @ (libc::ESTALE | libc::EIO)) => {
                                return self
                                    .read_newer(h.node, *ver, path, offset, want, e, reply, sw);
                            }
                            Err(e) => return reply.error(en(e)),
                        }
                    }
                };
                read_into(len, |dst| r.read_at(dst, offset).map_err(en), reply);
            }
            Src::Staged { fd, .. } => read_into(
                want,
                |dst| pread_full(fd.as_fd(), dst, offset).map_err(|e| eio(&e)),
                reply,
            ),
            Src::Local { fd } => read_into(
                want,
                |dst| pread_full(fd.as_fd(), dst, offset).map_err(|e| eio(&e)),
                reply,
            ),
            Src::Empty => reply.data(&[]),
            Src::Dir(_) => reply.error(Errno::EISDIR),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        self.core.ctr.op(Op::Write);
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|e| e > FILE_MAX)
        {
            return reply.error(Errno::EFBIG);
        }
        let Some(h) = self.handle(fh.0) else {
            return reply.error(Errno::EBADF);
        };
        // a commit that failed after the last close leaves its error for the next write on the node
        if let Err(e) = self.core.take_werr(h.node) {
            return reply.error(e);
        }
        let r = match &h.src {
            Src::Staged { fd, .. } => pwrite_all(fd.as_fd(), data, offset),
            Src::Local { fd } => pwrite_all(fd.as_fd(), data, offset),
            // writeback cache may flush pages through any handle of the inode
            _ => match self.node_staging_fd(ino.0) {
                Some(fd) => pwrite_all(fd.as_fd(), data, offset),
                None => return reply.error(Errno::EBADF),
            },
        };
        match r {
            Ok(()) => reply.written(data.len() as u32),
            Err(e) => reply.error(eio(&e)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        self.core.ctr.op(Op::Flush);
        let Some(h) = self.handle(fh.0) else {
            return reply.ok();
        };
        let r = match &h.src {
            Src::Staged { id, .. } => {
                let _turn = self.core.stage_turn(h.node);
                self.core.finish(h.node, self.core.writer.flush(*id, false))
            }
            _ => Ok(()),
        };
        match r.and(self.core.take_werr(h.node)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.core.ctr.op(Op::Release);
        let Some(h) = lock(&self.handles).remove(&fh.0) else {
            return reply.ok();
        };
        if let Src::Staged { id, .. } = &h.src {
            let _turn = self.core.stage_turn(h.node);
            // an edit that failed on the last close is gone: drop pages that still show it. a new file's
            // commit is left to the settler, which keeps the staging copy and the node until the host answers
            if let Some(r) = self.core.writer.release_async(*id, h.node)
                && self.core.finish(h.node, r).is_err()
            {
                if let Some(n) = self.core.tw().get_mut(h.node) {
                    n.page = None;
                }
                self.core.kick(vec![Effect::InvalInode(h.node)]);
            }
            if self.core.writer.staging_fd(*id).is_none()
                && let Some(n) = self.core.tw().get_mut(h.node)
                && n.staging == Some(*id)
            {
                n.staging = None;
            }
        }
        let local = matches!(h.src, Src::Local { .. }).then_some(h.node);
        self.close_handle(h);
        // reply first: the host round trip of a promotion must not hold up the close
        reply.ok();
        if let Some(id) = local {
            self.core.promote_closed(id);
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.core.ctr.op(Op::Other);
        let Some(h) = self.handle(fh.0) else {
            return reply.ok();
        };
        let r = match &h.src {
            Src::Staged { id, .. } => {
                let _turn = self.core.stage_turn(h.node);
                self.core.finish(h.node, self.core.writer.flush(*id, true))
            }
            Src::Local { fd } => sys::fsync(fd.as_fd()).map_err(|e| eio(&e)),
            _ => Ok(()),
        };
        match r.and(self.core.take_werr(h.node)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        self.core.ctr.op(Op::Opendir);
        // the kernel then stops sending opendir and releasedir and caches listings by default
        if self.no_opendir {
            return reply.error(Errno::ENOSYS);
        }
        let list = match self.listing(ino.0) {
            Ok(l) => l,
            Err(e) => return reply.error(e),
        };
        let fh = self.add_handle(Handle {
            node: ino.0,
            io: Io::None,
            src: Src::Dir(list),
        });
        reply.opened(
            FileHandle(fh),
            FopenFlags::FOPEN_KEEP_CACHE | FopenFlags::FOPEN_CACHE_DIR,
        );
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        self.core.ctr.op(Op::Readdir);
        let list = match self.dir_list(ino.0, fh.0, offset) {
            Ok(l) => l,
            Err(e) => return reply.error(e),
        };
        let end;
        {
            let t = self.core.t();
            let Some(d) = t.get(ino.0) else {
                return reply.error(Errno::ENOENT);
            };
            let up = if ino.0 == ROOT || !d.attached() {
                ino.0
            } else {
                d.parent
            };
            let total = list.len() + 2;
            let mut i = usize::try_from(offset).unwrap_or(usize::MAX);
            while i < total {
                let next = i as u64 + 1;
                let full = match i {
                    0 => reply.add(ino, next, FileType::Directory, "."),
                    1 => reply.add(INodeNo(up), next, FileType::Directory, ".."),
                    k => match list.get(k - 2) {
                        Some((id, ghost)) => match t.get(*id) {
                            Some(n) if n.attached() => reply.add(
                                INodeNo(*id),
                                next,
                                node_type(n),
                                ghost.as_ref().unwrap_or(&n.name).as_str(),
                            ),
                            _ => false,
                        },
                        None => true,
                    },
                };
                if full {
                    break;
                }
                i += 1;
            }
            end = i >= total;
        }
        if end {
            self.dir_done(ino.0, fh.0, &list);
        }
        reply.ok();
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        self.core.ctr.op(Op::Readdir);
        let list = match self.dir_list(ino.0, fh.0, offset) {
            Ok(l) => l,
            Err(e) => return reply.error(e),
        };
        let end;
        {
            let t = self.core.t();
            let Some(d) = t.get(ino.0) else {
                return reply.error(Errno::ENOENT);
            };
            let up = if ino.0 == ROOT || !d.attached() {
                ino.0
            } else {
                d.parent
            };
            let total = list.len() + 2;
            let mut i = usize::try_from(offset).unwrap_or(usize::MAX);
            while i < total {
                let next = i as u64 + 1;
                let (full, added) = match i {
                    0 | 1 => {
                        let id = if i == 0 { ino.0 } else { up };
                        match t.get(id) {
                            Some(n) => (
                                reply.add(
                                    INodeNo(id),
                                    next,
                                    if i == 0 { "." } else { ".." },
                                    &ttl_of(n),
                                    &self.core.attr(id, n),
                                    Generation(n.r#gen),
                                ),
                                None,
                            ),
                            None => (false, None),
                        }
                    }
                    k => match list.get(k - 2) {
                        Some((id, ghost)) => match t.get(*id) {
                            Some(n) if n.attached() => {
                                let name = ghost.as_ref().unwrap_or(&n.name);
                                let full = reply.add(
                                    INodeNo(*id),
                                    next,
                                    name.as_str(),
                                    &ttl_of(n),
                                    &self.core.entry_attr(&t, *id, n),
                                    Generation(n.r#gen),
                                );
                                (full, (!full).then_some(*id))
                            }
                            _ => (false, None),
                        },
                        None => (true, None),
                    },
                };
                if let Some(id) = added {
                    t.add_lookup(id);
                }
                if full {
                    break;
                }
                i += 1;
            }
            end = i >= total;
        }
        if end {
            self.dir_done(ino.0, fh.0, &list);
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.core.ctr.op(Op::Releasedir);
        if let Some(h) = lock(&self.handles).remove(&fh.0) {
            self.close_handle(h);
        }
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.core.ctr.op(Op::Other);
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        self.core.ctr.op(Op::Other);
        let files = self.core.t().files();
        match rustix::fs::fstatvfs(&self.core.overlay) {
            Ok(s) => reply.statfs(
                s.f_blocks,
                s.f_bfree,
                s.f_bavail,
                files.saturating_add(s.f_ffree),
                s.f_ffree,
                s.f_bsize as u32,
                255,
                s.f_frsize as u32,
            ),
            Err(e) => reply.error(erx(e)),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        _kill_suid_gid: bool,
        _owner: Owner,
        reply: ReplyCreate,
    ) {
        self.core.ctr.op(Op::Create);
        let name = match name_of(name) {
            Ok(n) => n,
            Err(e) => return reply.error(e),
        };
        if self.is_inj(req) {
            let mut t = self.core.tw();
            let done = t.complete_create(parent.0, name.as_str());
            return match done.and_then(|id| {
                t.get(id)
                    .filter(|n| n.meta.kind == Kind::File)
                    .map(|n| (id, self.core.attr(id, n), n.r#gen))
            }) {
                Some((id, a, g)) => {
                    t.add_lookup(id);
                    reply.created(
                        &synced_ttl(),
                        &a,
                        Generation(g),
                        FileHandle(INJ_FH),
                        FopenFlags::FOPEN_DIRECT_IO,
                    )
                }
                None => reply.error(Errno::EEXIST),
            };
        }
        let perm = (mode & !umask & 0o7777) as u16;
        let (id, src) = match self.new_file(parent.0, &name, perm) {
            Ok(x) => x,
            Err(e) => return reply.error(e),
        };
        #[cfg(target_os = "macos")]
        coherence::PROBE.created(name.as_str(), parent.0, id, req.pid(), req.uid(), req.gid());
        let io = self.choose_io(id, Self::src_key(&src), &|fd| reply.open_backing(fd));
        let fh = self.add_handle(Handle { node: id, io, src });
        let (a, ttl, g) = match self.core.live_attr(id) {
            Ok(x) => x,
            Err(e) => return reply.error(e),
        };
        let Some(h) = self.handle(fh) else {
            return reply.error(Errno::EIO);
        };
        let nf = self.noflush(&h.src);
        match &h.io {
            Io::Pass(b) => {
                reply.created_passthrough(&ttl, &a, Generation(g), FileHandle(fh), nf, b)
            }
            io => reply.created(&ttl, &a, Generation(g), FileHandle(fh), fopen(io) | nf),
        }
    }

    // the reply names the same inode, so the kernel keeps one page cache and size for every name
    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        self.core.ctr.op(Op::Mutate);
        if self.is_inj(req) {
            return reply.error(Errno::EPERM);
        }
        match self.do_link(ino.0, newparent.0, newname) {
            Ok(id) => self.entry_reply(id, reply),
            Err(e) => reply.error(e),
        }
    }

    // the kernel writes back dirty pages in the range first and fixes its own i_size after
    fn fallocate(
        &self,
        req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        self.core.ctr.op(Op::Other);
        // the injector's modify event: nothing to allocate
        if self.is_inj(req) && fh.0 == INJ_FH && mode == KEEP_SIZE {
            return reply.ok();
        }
        let Some(h) = self.handle(fh.0) else {
            return reply.error(Errno::EBADF);
        };
        let grows = mode & KEEP_SIZE == 0;
        let r = match &h.src {
            Src::Local { fd } => fsops::fallocate(fd.as_fd(), mode, offset, length),
            Src::Staged { .. }
                if grows && offset.checked_add(length).is_none_or(|e| e > FILE_MAX) =>
            {
                Err(libc::EFBIG)
            }
            Src::Staged { fd, .. } => fsops::fallocate(fd.as_fd(), mode, offset, length),
            _ => Err(libc::EBADF),
        };
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(en(e)),
        }
    }

    // EOPNOTSUPP and EXDEV make the kernel copy through its own page cache instead
    fn copy_file_range(
        &self,
        _req: &Request,
        _ino_in: INodeNo,
        fh_in: FileHandle,
        offset_in: u64,
        _ino_out: INodeNo,
        fh_out: FileHandle,
        offset_out: u64,
        len: u64,
        _flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        self.core.ctr.op(Op::Other);
        let (Some(hi), Some(ho)) = (self.handle(fh_in.0), self.handle(fh_out.0)) else {
            return reply.error(Errno::EBADF);
        };
        let (dst, capped) = match &ho.src {
            Src::Local { fd } => (fd.as_fd(), false),
            Src::Staged { fd, .. } => (fd.as_fd(), true),
            _ => return reply.error(Errno::EBADF),
        };
        if self.moved_on(&hi).is_some() {
            return reply.error(Errno::EOPNOTSUPP);
        }
        let held;
        let (src, end) = match &hi.src {
            Src::Local { fd } => (fd.as_fd(), None),
            Src::Staged { fd, .. } => (fd.as_fd(), None),
            Src::Blob { ver, blob, .. } => {
                held = blob
                    .get()
                    .cloned()
                    .or_else(|| self.core.cache.get(&ver.hash).filter(|b| b.is_complete()));
                match &held {
                    Some(b) => (b.fd(), Some(ver.size)),
                    None => return reply.error(Errno::EOPNOTSUPP),
                }
            }
            Src::Empty => return reply.written(0),
            Src::Dir(_) => return reply.error(Errno::EISDIR),
        };
        // the reply carries a u32, so one call copies at most the largest page-aligned u32
        let mut want = len.min(u64::from(!0xfff_u32));
        if let Some(size) = end {
            want = want.min(size.saturating_sub(offset_in));
        }
        if want == 0 {
            return reply.written(0);
        }
        if capped && offset_out.checked_add(want).is_none_or(|e| e > FILE_MAX) {
            return reply.error(Errno::EFBIG);
        }
        match fsops::copy_range(src, offset_in, dst, offset_out, want as usize) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(en(e)),
        }
    }
}

pub struct Mounted {
    bg: Option<BackgroundSession>,
    inval: Inval,
    path: PathBuf,
}

#[cfg(target_os = "linux")]
fn lazy_unmount(at: &Path) -> bool {
    Command::new("fusermount3")
        .arg("-uz")
        .arg(at)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// kernel cache invalidations; inode and entry ones wait on locks a request may hold, so request threads send only attrs
#[derive(Clone)]
pub struct Inval(Notifier, Arc<Switch>);

// the node whose kernel cache is moving to a newer version, and the attr replies held until it has
#[derive(Default)]
pub struct Switch {
    node: AtomicU64,
    held: Mutex<Vec<ReplyAttr>>,
    // nodes whose page cache still serves open readers an older version, and when it moves regardless
    waiting: Mutex<FxHashMap<NodeId, Instant>>,
}

impl Inval {
    pub fn inode(&self, id: NodeId) {
        let _ = self.0.inval_inode(INodeNo(id), 0, 0);
    }

    // attributes only: takes no inode or page lock, so a request thread may send it
    pub fn attrs(&self, id: NodeId) {
        let _ = self.0.inval_inode(INodeNo(id), -1, 0);
    }

    pub fn entry(&self, parent: NodeId, name: &Name) {
        let _ = self
            .0
            .inval_entry(INodeNo(parent), OsStr::new(name.as_str()));
    }

    // a size the kernel learns while it still holds the old version's pages would cut or pad them
    fn hold(&self, id: NodeId, reply: ReplyAttr) -> Option<ReplyAttr> {
        if self.1.node.load(SeqCst) != id {
            return Some(reply);
        }
        let mut held = lock(&self.1.held);
        if self.1.node.load(SeqCst) != id {
            return Some(reply);
        }
        held.push(reply);
        None
    }

    fn switching(&self, id: NodeId) -> bool {
        self.1.node.load(SeqCst) == id
    }

    // when the notify thread must next move a page cache whose readers have not let go
    pub fn next_due(&self) -> Option<Instant> {
        lock(&self.1.waiting).values().min().copied()
    }

    pub fn take_due(&self, now: Instant) -> Vec<NodeId> {
        let mut w = lock(&self.1.waiting);
        let due: Vec<NodeId> = w
            .iter()
            .filter(|(_, t)| **t <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in &due {
            w.remove(id);
        }
        due
    }
}

impl Core {
    // the kernel's pages and size move to the current version together: replies naming the new size
    // wait until the invalidation has dropped every old page, and cached reads serve the new version from here
    // nothing else changed, so an inode whose cache already shows the current version is left alone
    pub fn reshow(&self, k: &Inval, id: NodeId) {
        let moved = self
            .t()
            .get(id)
            .is_some_and(|n| n.kernel_ver() != n.meta.version());
        if moved {
            self.reload(k, id, false);
        }
    }

    pub fn reload(&self, k: &Inval, id: NodeId, force: bool) {
        let (moved, busy) = self.t().get(id).map_or((false, false), |n| {
            (
                n.kernel_ver() != n.meta.version(),
                n.cached.load(Relaxed) > 0,
            )
        });
        if !moved {
            lock(&k.1.waiting).remove(&id);
            return k.inode(id);
        }
        // readers part way through the old version keep it, with its size and times, until they let go
        if busy && !force {
            lock(&k.1.waiting)
                .entry(id)
                .or_insert_with(|| Instant::now() + SHOW_LAG);
            return;
        }
        k.1.node.store(id, SeqCst);
        {
            let mut t = self.tw();
            let Some(n) = t.get_mut(id) else {
                k.1.node.store(0, SeqCst);
                return;
            };
            if !force && n.cached.load(Relaxed) > 0 {
                drop(t);
                k.1.node.store(0, SeqCst);
                return self.reload(k, id, false);
            }
            if !super::inject::SIZES_FROM_ATTRS.load(Relaxed) {
                n.size_pending = true;
                n.size_gen = n.size_gen.wrapping_add(1);
            }
            n.show_current();
        }
        lock(&k.1.waiting).remove(&id);
        k.inode(id);
        let held = {
            let mut g = lock(&k.1.held);
            k.1.node.store(0, SeqCst);
            std::mem::take(&mut *g)
        };
        for r in held {
            match self.live_attr(id) {
                Ok((a, ttl, _)) => r.attr(&ttl, &a),
                Err(e) => r.error(e),
            }
        }
        // writeback cache takes a size only from a truncate reply, and an earlier one carried the old version's
        if !super::inject::SIZES_FROM_ATTRS.load(Relaxed) {
            self.kick(vec![Effect::Synth(Synth::Modify { node: id })]);
        }
    }
}

impl Mounted {
    pub fn inval(&self) -> Inval {
        self.inval.clone()
    }

    // the backend this mount ended up on, for the status line and doctor
    #[cfg(target_os = "macos")]
    pub fn backend(&self) -> Option<BackendKind> {
        self.bg.as_ref().map(|b| b.backend().into())
    }

    pub fn unmount(mut self) -> io::Result<()> {
        let Some(bg) = self.bg.take() else {
            return Ok(());
        };
        match bg.umount_and_join() {
            Ok(()) => Ok(()),
            #[cfg(target_os = "linux")]
            Err(_) if lazy_unmount(&self.path) => Ok(()),
            #[cfg(target_os = "macos")]
            Err(_) if super::mount_mac::force_unmount(&self.path) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(target_os = "linux")]
fn unescape_mountinfo(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let oct = b
            .get(i + 1..i + 4)
            .filter(|o| b[i] == b'\\' && o.iter().all(|c| (b'0'..=b'7').contains(c)));
        match oct {
            Some(o) => {
                out.push(
                    o.iter()
                        .fold(0u8, |a, c| a.wrapping_mul(8).wrapping_add(c - b'0')),
                );
                i += 4;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// a csync mount listed in mountinfo at this path
#[cfg(target_os = "linux")]
fn csync_mounted_at(at: &Path) -> bool {
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    info.lines().any(|l| {
        let Some((pre, post)) = l.split_once(" - ") else {
            return false;
        };
        let mut post = post.split(' ');
        let (fstype, source) = (post.next().unwrap_or(""), post.next().unwrap_or(""));
        pre.split(' ')
            .nth(4)
            .is_some_and(|mp| Path::new(&unescape_mountinfo(mp)) == at)
            && (fstype == "fuse.csync" || (fstype.starts_with("fuse") && source == "csync"))
    })
}

// a killed session leaves a dead mount whose attributes the kernel still answers from cache; statfs always
// reaches the daemon, so ENOTCONN there proves nobody serves it and the lazy unmount is safe
#[cfg(target_os = "linux")]
pub fn clear_stale(at: &Path) {
    let stale = match std::fs::metadata(at) {
        Err(e) if e.raw_os_error() == Some(libc::ENOTCONN) => true,
        _ => {
            csync_mounted_at(at)
                && rustix::fs::statfs(at).is_err_and(|e| e == rustix::io::Errno::NOTCONN)
        }
    };
    if stale {
        lazy_unmount(at);
    }
}

#[cfg(target_os = "macos")]
pub fn clear_stale(at: &Path) {
    super::mount_mac::clear_stale(at);
}

#[cfg(target_os = "linux")]
pub fn mount(core: Arc<Core>, at: &Path, allow_other: bool) -> io::Result<Mounted> {
    clear_stale(at);
    let mut cfg = Config::default();
    cfg.mount_options = vec![
        MountOption::FSName("csync".into()),
        MountOption::Subtype("csync".into()),
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::NoAtime,
    ];
    cfg.acl = if allow_other {
        SessionACL::All
    } else {
        SessionACL::Owner
    };
    cfg.n_threads = Some(WORKERS);
    cfg.clone_fd = true;
    let session = Session::new(GuestFs::new(core.clone()), at, &cfg)?;
    let bg = session.spawn()?;
    let inval = Inval(bg.notifier(), Arc::default());
    let _ = core.inval.set(inval.clone());
    Ok(Mounted {
        bg: Some(bg),
        inval,
        path: at.to_path_buf(),
    })
}

// the volume is named for the project; the cache policy stays conservative until the self-test has run
#[cfg(target_os = "macos")]
pub fn mount(core: Arc<Core>, at: &Path, allow_other: bool, volname: &str) -> io::Result<Mounted> {
    clear_stale(at);
    fsops::init_umask();
    let bg = super::mount_mac::attach(&core, at, volname, allow_other)?;
    coherence::begin(bg.backend().into());
    let inval = Inval(bg.notifier(), Arc::default());
    let _ = core.inval.set(inval.clone());
    Ok(Mounted {
        bg: Some(bg),
        inval,
        path: at.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: u128 = 9;

    fn pending_meta(size: u64) -> Meta {
        Meta {
            kind: Kind::File,
            perm: 0o644,
            size,
            mtime_ns: 1,
            ctime_ns: 1,
            hash: None,
            link: None,
            git_ro: false,
        }
    }

    fn version(tag: u8, size: u64) -> Version {
        Version {
            hash: [tag; 32],
            size,
        }
    }

    fn path() -> RelPath {
        RelPath::new("a.rs").unwrap()
    }

    fn host_entry(tree: &RwLock<GTree>, meta: Meta, ver: Seq) {
        let up = Change::Upsert {
            path: path(),
            meta,
            ver,
        };
        tree.write().unwrap().apply(&up, &mut Vec::new());
    }

    fn tree_with(meta: Meta, ver: Seq) -> (RwLock<GTree>, NodeId) {
        let mut t = GTree::new();
        t.set_version(INDEX, 1);
        let tree = RwLock::new(t);
        host_entry(&tree, meta, ver);
        let id = tree.read().unwrap().resolve(&path()).unwrap();
        (tree, id)
    }

    fn learned(tree: &RwLock<GTree>, id: NodeId) -> Option<Hash32> {
        tree.read().unwrap().get(id).and_then(|n| n.meta.hash)
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn version_of_a_known_hash_asks_nobody() {
        let mut m = pending_meta(7);
        m.hash = Some([3; 32]);
        let (tree, id) = tree_with(m, 5);
        let got = resolve_node(&tree, id, soon(), |_, _, _, _| {
            panic!("resolved a known hash")
        });
        assert_eq!(got, Ok(version(3, 7)));
    }

    #[test]
    fn version_of_a_pending_file_resolves_then_learns() {
        let (tree, id) = tree_with(pending_meta(7), 5);
        let mut asked = Vec::new();
        let got = resolve_node(&tree, id, soon(), |p, key, inline, _| {
            asked.push((p.clone(), key, inline));
            Ok(version(4, 7))
        });
        assert_eq!(got, Ok(version(4, 7)));
        let key = VerKey {
            index: INDEX,
            ver: 5,
            size: 7,
        };
        assert_eq!(asked, vec![(path(), key, true)]);
        assert_eq!(learned(&tree, id), Some([4; 32]));
        let again = resolve_node(&tree, id, soon(), |_, _, _, _| panic!("asked twice"));
        assert_eq!(again, Ok(version(4, 7)));
    }

    #[test]
    fn a_file_too_big_to_inline_is_resolved_without_its_bytes() {
        let size = INLINE_MAX as u64 + 1;
        let (tree, id) = tree_with(pending_meta(size), 5);
        let mut inline = None;
        let got = resolve_node(&tree, id, soon(), |_, _, i, _| {
            inline = Some(i);
            Ok(version(4, size))
        });
        assert_eq!(got, Ok(version(4, size)));
        assert_eq!(inline, Some(false));
    }

    #[test]
    fn version_of_retries_when_the_host_entry_changes_meanwhile() {
        let (tree, id) = tree_with(pending_meta(7), 5);
        let mut asked = Vec::new();
        let got = resolve_node(&tree, id, soon(), |_, key, _, _| {
            asked.push(key.ver);
            if key.ver == 5 {
                host_entry(&tree, pending_meta(8), 6);
                return Ok(version(4, 7));
            }
            Ok(version(5, 8))
        });
        assert_eq!(got, Ok(version(5, 8)));
        assert_eq!(asked, vec![5, 6]);
        assert_eq!(learned(&tree, id), Some([5; 32]));
    }

    #[test]
    fn version_of_gives_up_after_its_retry_bound() {
        let (tree, id) = tree_with(pending_meta(7), 5);
        let mut calls = 0;
        let got = resolve_node(&tree, id, soon(), |_, key, _, _| {
            calls += 1;
            host_entry(&tree, pending_meta(7), key.ver + 1);
            Ok(version(4, 7))
        });
        assert_eq!(got, Err(Errno::ESTALE));
        assert_eq!(calls, RESOLVE_TRIES);
        assert_eq!(learned(&tree, id), None);
    }

    #[test]
    fn a_gone_answer_is_stale_unless_a_newer_entry_arrives() {
        let (tree, id) = tree_with(pending_meta(7), 5);
        let got = resolve_node(&tree, id, Instant::now(), |_, _, _, _| Err(libc::ESTALE));
        assert_eq!(got, Err(Errno::ESTALE));

        let mut asked = Vec::new();
        let got = resolve_node(&tree, id, soon(), |_, key, _, _| {
            asked.push(key.ver);
            if key.ver == 5 {
                host_entry(&tree, pending_meta(8), 6);
                return Err(libc::ESTALE);
            }
            Ok(version(5, 8))
        });
        assert_eq!(got, Ok(version(5, 8)));
        assert_eq!(asked, vec![5, 6]);
    }

    #[test]
    fn other_resolve_errors_pass_through() {
        let (tree, id) = tree_with(pending_meta(7), 5);
        let got = resolve_node(&tree, id, soon(), |_, _, _, _| Err(libc::EIO));
        assert_eq!(got, Err(Errno::EIO));
        assert_eq!(learned(&tree, id), None);
    }

    #[test]
    fn a_file_the_host_has_not_reported_has_no_version_to_resolve() {
        let (tree, id) = tree_with(pending_meta(0), 0);
        let got = resolve_node(&tree, id, soon(), |_, _, _, _| panic!("asked the host"));
        assert_eq!(got, Err(Errno::ENOENT));
    }

    #[test]
    fn a_directory_has_no_version() {
        let (tree, id) = tree_with(dir_meta(0o755), 5);
        let got = resolve_node(&tree, id, soon(), |_, _, _, _| panic!("asked the host"));
        assert_eq!(got, Err(Errno::EINVAL));
    }
}
