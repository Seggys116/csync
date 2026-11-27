pub mod apply;
pub mod commit;
pub mod hasher;
pub mod serve;

use crate::crypto::trust::{Identity, PeerKey, Trust, TrustEntry, ensure_private_dir, now_unix};
use crate::ignore::{
    repo,
    rules::{Class, Rules},
};
use crate::index::{
    persist, scan,
    tree::{Domain, StatKey, Tree},
};
use crate::net::conn::{
    CloseReason, Closed, In, Incoming, Link, Listener, NetError, PushError, Session,
};
use crate::net::discover;
use crate::proto::{
    BATCH_MAX, Body, Bye, Change, DeltaOp, ExcludeSrc, FRAME_MAX, FsTraits, Hash32, Hello,
    INLINE_MAX, IndexId, Kind, LinkTarget, Meta, Msg, Name, Notice, NoticeKind, Op, PROTO, Push,
    RelPath, Reply, ReqId, Seq, SnapEntry, UNACKED_PUSH_MAX, Welcome, WireErr,
    hs::{HsHello, PAIR_TIMEOUT_S, PairStep, Role},
    path::TMP_PREFIX,
};
use crate::sys::{self, WatchEvent, wflag};
use crate::tui::{ConnState, NOTICES_MAX, PairPrompt, PeerView, UiBus, UiCmd, UiSnapshot};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, at, bounded, never, select};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use rustix::fs::{AtFlags, Mode, OFlags};
use std::{
    cell::Cell,
    collections::VecDeque,
    fs::File,
    io::{self, Read},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_PORT: u16 = 47_474;
pub const INDEX_FILE: &str = "index.rkyv";

const GUESTS_MAX: usize = 16;
const EVENT_QUEUE: usize = 4_096;
const COMMIT_QUEUE: usize = 256;
const FETCH_QUEUE: usize = 1_024;
const FETCH_THREADS: usize = 4;
const LIGHT_THREADS: usize = 2;
const HASH_THREADS: usize = 2;
const VERIFY_BLOCK: usize = 4 << 20;
const PAR_VERIFY_MIN: u64 = 1 << 20;
pub(crate) const FETCH_INFLIGHT_MAX: usize = 128;
const UPLOADS_MAX: usize = 64;
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(30);
// the guest answers every ping, so this long without a single frame means the peer is gone
const PEER_SILENT: Duration = PING_EVERY.saturating_mul(3);
const UPLOAD_IDLE: Duration = Duration::from_secs(60);
const UPLOAD_REAP: Duration = Duration::from_secs(5);
const UI_EVERY: Duration = Duration::from_millis(200);
pub(crate) const RULE_MAX: u64 = 8 << 20;
// frame headroom: the encoder refuses anything above FRAME_MAX, so batches aim well below it
pub(crate) const PUSH_BYTES: usize = FRAME_MAX / 2;
const MDNS_HINT: &str = "mdns advertising failed: guests must join by address";
const PAIR_LIMIT_HINT: &str =
    "pairing is rate limited: too many recent pairing attempts, new requests are refused for now";

pub struct HostCfg {
    pub root: PathBuf,
    pub project: Option<Name>,
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub listen: SocketAddr,
    pub allow_pairing: bool,
    pub advertise: bool,
    pub all_ifaces: bool,
    pub ctl: Option<Receiver<HostCtl>>,
}

impl HostCfg {
    // state_dir must be private to this project root: it holds the persisted index
    pub fn new(root: PathBuf, config_dir: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            root,
            project: None,
            config_dir,
            state_dir,
            listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_PORT)),
            allow_pairing: true,
            advertise: true,
            all_ifaces: false,
            ctl: None,
        }
    }
}

pub enum HostCtl {
    Forget {
        selector: String,
        reply: Sender<io::Result<Vec<TrustEntry>>>,
    },
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn read<T>(m: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn write<T>(m: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    now_ns() / 1_000_000
}

pub(crate) fn wire(e: &io::Error) -> WireErr {
    match e.raw_os_error() {
        Some(libc::ENOENT) => WireErr::NotFound,
        Some(libc::EEXIST) => WireErr::Exists,
        Some(libc::ENOTEMPTY) => WireErr::NotEmpty,
        Some(libc::ENOTDIR) => WireErr::NotDir,
        Some(libc::EISDIR) => WireErr::IsDir,
        Some(libc::EROFS) => WireErr::ReadOnly,
        Some(libc::ELOOP | libc::EACCES | libc::EPERM | libc::EXDEV) => WireErr::Denied,
        Some(libc::ENOSPC | libc::EDQUOT | libc::EFBIG | libc::ENAMETOOLONG) => WireErr::TooLarge,
        Some(libc::EBUSY | libc::EAGAIN) => WireErr::Busy,
        _ => match e.kind() {
            io::ErrorKind::NotFound => WireErr::NotFound,
            io::ErrorKind::InvalidInput => WireErr::Invalid,
            _ => WireErr::Io,
        },
    }
}

pub(crate) fn wire_errno(e: rustix::io::Errno) -> WireErr {
    wire(&e.into())
}

pub(crate) fn perm_of(mode: u32) -> u16 {
    (mode & 0o7777) as u16
}

// these must build exactly what index::scan builds, or every echo of our own write would look like a change
pub(crate) fn file_meta(st: &StatKey, hash: Hash32, git_ro: bool) -> Meta {
    Meta {
        kind: Kind::File,
        perm: perm_of(st.mode),
        size: st.size,
        mtime_ns: st.mtime_ns,
        ctime_ns: st.ctime_ns,
        hash: Some(hash),
        link: None,
        git_ro,
    }
}

pub(crate) fn dir_meta(st: &StatKey, git_ro: bool) -> Meta {
    Meta {
        kind: Kind::Dir,
        perm: perm_of(st.mode),
        size: 0,
        mtime_ns: st.mtime_ns,
        ctime_ns: st.ctime_ns,
        hash: None,
        link: None,
        git_ro,
    }
}

pub(crate) fn link_meta(st: &StatKey, link: LinkTarget, git_ro: bool) -> Meta {
    let size = link.as_str().len() as u64;
    Meta {
        kind: Kind::Symlink,
        perm: perm_of(st.mode),
        size,
        mtime_ns: st.mtime_ns,
        ctime_ns: st.ctime_ns,
        hash: None,
        link: Some(link),
        git_ro,
    }
}

thread_local! {
    static HBUF: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

// hashes exactly `size` bytes from offset 0; a file that shrank underneath is an error
pub(crate) fn hash_fd(fd: BorrowedFd<'_>, size: u64) -> io::Result<Hash32> {
    let mut buf = HBUF.take();
    if buf.len() < scan::HASH_BUF {
        buf.resize(scan::HASH_BUF, 0);
    }
    let mut h = blake3::Hasher::new();
    let mut off = 0u64;
    let res = loop {
        if off >= size {
            break Ok(());
        }
        let want = (size - off).min(buf.len() as u64) as usize;
        match rustix::io::pread(fd, &mut buf[..want], off) {
            Ok(0) => break Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                h.update(&buf[..n]);
                off += n as u64;
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => break Err(e.into()),
        }
    };
    HBUF.set(buf);
    res.map(|()| *h.finalize().as_bytes())
}

thread_local! {
    static VBUF: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

#[cfg(test)]
type MidHook = Box<dyn FnOnce()>;

// a test's way to change the file after its bytes were read and before the re-stat
#[cfg(test)]
thread_local! {
    pub(crate) static MID_HASH: std::cell::RefCell<Option<MidHook>> =
        const { std::cell::RefCell::new(None) };
}

// the hash of the open file's first k1.size bytes, or None when the file is not provably the version k1 describes
pub(crate) fn hash_verified(fd: BorrowedFd<'_>, k1: &StatKey) -> io::Result<Option<Hash32>> {
    hash_verified_with(fd, k1, &mut || true, k1.size >= PAR_VERIFY_MIN)
}

// as hash_verified; pace runs before every read and returns false to give up
pub(crate) fn hash_verified_paced(
    fd: BorrowedFd<'_>,
    k1: &StatKey,
    pace: &mut dyn FnMut() -> bool,
) -> io::Result<Option<Hash32>> {
    hash_verified_with(fd, k1, pace, false)
}

// parallel spreads each block over the rayon pool; the digest is the same either way
fn hash_verified_with(
    fd: BorrowedFd<'_>,
    k1: &StatKey,
    pace: &mut dyn FnMut() -> bool,
    parallel: bool,
) -> io::Result<Option<Hash32>> {
    let mut buf = VBUF.take();
    let first = k1.size.min(VERIFY_BLOCK as u64) as usize;
    if buf.len() < first {
        buf.resize(first, 0);
    }
    let mut h = blake3::Hasher::new();
    let mut off = 0u64;
    let read = loop {
        if off >= k1.size {
            break Ok(true);
        }
        if !pace() {
            break Ok(false);
        }
        let n = (k1.size - off).min(VERIFY_BLOCK as u64) as usize;
        match rustix::io::pread(fd, &mut buf[..n], off) {
            // the file shrank under the read
            Ok(0) => break Ok(false),
            Ok(m) => {
                if parallel {
                    h.update_rayon(&buf[..m]);
                } else {
                    h.update(&buf[..m]);
                }
                off += m as u64;
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => break Err(io::Error::from(e)),
        }
    };
    VBUF.set(buf);
    if !read? {
        return Ok(None);
    }
    #[cfg(test)]
    {
        if let Some(hook) = MID_HASH.with(|m| m.borrow_mut().take()) {
            hook();
        }
    }
    let post = sys::stat_key(fd)?;
    let same = sys::same_version(&post, k1) && post.ctime_ns == k1.ctime_ns;
    Ok(same.then(|| *h.finalize().as_bytes()))
}

pub(crate) fn read_exact_at(fd: BorrowedFd<'_>, buf: &mut [u8], mut off: u64) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match rustix::io::pread(fd, &mut buf[done..], off) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                done += n;
                off += n as u64;
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(crate) fn write_all_at(fd: BorrowedFd<'_>, data: &[u8], mut off: u64) -> io::Result<()> {
    let mut done = 0;
    while done < data.len() {
        match rustix::io::pwrite(fd, &data[done..], off) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                done += n;
                off += n as u64;
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(crate) fn read_all(fd: BorrowedFd<'_>, size: u64) -> io::Result<Vec<u8>> {
    let n = usize::try_from(size).map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    let mut v = vec![0u8; n];
    read_exact_at(fd, &mut v, 0)?;
    Ok(v)
}

pub(crate) fn read_rule(root: BorrowedFd<'_>, p: &RelPath) -> Option<Vec<u8>> {
    let fd = sys::open_beneath(root, p, OFlags::RDONLY | OFlags::NONBLOCK).ok()?;
    let st = sys::stat_key(fd.as_fd()).ok()?;
    if sys::kind_of_mode(st.mode) != Some(Kind::File) {
        return None;
    }
    let mut v = Vec::new();
    File::from(fd).take(RULE_MAX + 1).read_to_end(&mut v).ok()?;
    (v.len() as u64 <= RULE_MAX).then_some(v)
}

pub(crate) fn change_cost(c: &Change) -> usize {
    match c {
        Change::Upsert { path, meta, .. } => {
            64 + path.as_str().len() + meta.link.as_ref().map_or(0, |l| l.as_str().len())
        }
        Change::Remove { path } => 16 + path.as_str().len(),
        Change::Rename { from, to } => 16 + from.as_str().len() + to.as_str().len(),
    }
}

// wire-sized batches, each tagged with the number of changes up to and including it
pub(crate) fn batches(changes: Vec<Change>) -> Vec<(usize, Vec<Change>)> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let (mut bytes, mut done) = (0usize, 0usize);
    for c in changes {
        let k = change_cost(&c);
        if !cur.is_empty() && (cur.len() == BATCH_MAX || bytes + k > PUSH_BYTES) {
            done += cur.len();
            out.push((done, std::mem::take(&mut cur)));
            bytes = 0;
        }
        bytes += k;
        cur.push(c);
    }
    if !cur.is_empty() {
        done += cur.len();
        out.push((done, cur));
    }
    out
}

// a guest that just received the tree can pull every hash it lacks once the host has none pending
fn send_hashes_done(link: &Link, tree: &Tree) {
    if tree.pending() == 0 {
        let _ = link.send(Msg::Push(Push::HashesDone {
            index: tree.index_id(),
        }));
    }
}

// pushed hashes in frames that stay under BATCH_MAX items and PUSH_BYTES
fn hash_parts(items: Vec<(RelPath, Seq, Hash32)>) -> Vec<Vec<(RelPath, Seq, Hash32)>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut bytes = 0usize;
    for item in items {
        let k = 48 + item.0.as_str().len();
        if !cur.is_empty() && (cur.len() == BATCH_MAX || bytes + k > PUSH_BYTES) {
            out.push(std::mem::take(&mut cur));
            bytes = 0;
        }
        bytes += k;
        cur.push(item);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn snap_cost(e: &SnapEntry) -> usize {
    64 + e.name.as_str().len() + e.meta.link.as_ref().map_or(0, |l| l.as_str().len())
}

pub(crate) fn send_snapshot(link: &Link, tree: &Tree) -> Result<(), Closed> {
    let (index, seq) = (tree.index_id(), tree.seq());
    let mut part = 0u32;
    let mut buf: Vec<SnapEntry> = Vec::with_capacity(tree.len().clamp(1, BATCH_MAX));
    let mut bytes = 0usize;
    let mut failed = false;
    tree.snapshot(&mut |e| {
        if failed {
            return;
        }
        let k = snap_cost(&e);
        if !buf.is_empty() && (buf.len() == BATCH_MAX || bytes + k > PUSH_BYTES) {
            let entries = std::mem::take(&mut buf);
            failed = link
                .send(Msg::Push(Push::Snapshot {
                    index,
                    seq,
                    part,
                    last: false,
                    entries,
                }))
                .is_err();
            part = part.wrapping_add(1);
            bytes = 0;
        }
        bytes += k;
        buf.push(e);
    });
    if failed {
        return Err(Closed);
    }
    link.send(Msg::Push(Push::Snapshot {
        index,
        seq,
        part,
        last: true,
        entries: buf,
    }))
}

#[derive(Default)]
pub(crate) struct Counters {
    pub(crate) fetches: AtomicU64,
    pub(crate) commits: AtomicU64,
    pub(crate) refused: AtomicU64,
    pub(crate) merged: AtomicU64,
    pub(crate) tx: AtomicU64,
    pub(crate) rx: AtomicU64,
}

struct Feed {
    sent: Seq,
    lagging: bool,
    live: bool,
    // replies that must follow the journal replay up to their seq
    replies: Vec<(Seq, ReqId, Reply)>,
}

impl Feed {
    fn release(&mut self, link: &Link) {
        let n = self.replies.iter().take_while(|r| r.0 <= self.sent).count();
        for (_, id, r) in self.replies.drain(..n) {
            let _ = link.send(Msg::Resp { id, res: Ok(r) });
        }
    }
}

pub(crate) struct Guest {
    pub(crate) id: u64,
    pub(crate) key: PeerKey,
    pub(crate) name: Name,
    pub(crate) link: Link,
    feed: Mutex<Feed>,
    // in-flight fetch ids, true once cancelled
    fetches: Mutex<FxHashMap<ReqId, bool>>,
}

impl Guest {
    fn new(id: u64, link: Link, name: Name) -> Self {
        let key = link.peer();
        Self {
            id,
            key,
            name,
            link,
            feed: Mutex::new(Feed {
                sent: 0,
                lagging: false,
                live: false,
                replies: Vec::new(),
            }),
            fetches: Mutex::new(FxHashMap::default()),
        }
    }

    pub(crate) fn reply(&self, id: ReqId, res: Result<Reply, WireErr>) {
        let _ = self.link.send(Msg::Resp { id, res });
    }

    // a reply the guest must see after every change up to seq, and before any later one
    pub(crate) fn reply_after(&self, seq: Seq, id: ReqId, r: Reply) {
        let mut f = lock(&self.feed);
        if f.lagging && f.sent < seq {
            f.replies.push((seq, id, r));
        } else {
            let _ = self.link.send(Msg::Resp { id, res: Ok(r) });
        }
    }

    fn begin_fetch(&self, id: ReqId) -> Result<(), WireErr> {
        let mut m = lock(&self.fetches);
        if m.contains_key(&id) {
            return Err(WireErr::Invalid);
        }
        if m.len() >= FETCH_INFLIGHT_MAX {
            return Err(WireErr::Busy);
        }
        m.insert(id, false);
        Ok(())
    }

    pub(crate) fn cancelled(&self, id: ReqId) -> bool {
        lock(&self.fetches).get(&id).copied().unwrap_or(true)
    }

    pub(crate) fn end_fetch(&self, id: ReqId) {
        lock(&self.fetches).remove(&id);
    }

    fn cancel_fetch(&self, id: ReqId) {
        if let Some(c) = lock(&self.fetches).get_mut(&id) {
            *c = true;
        }
    }
}

#[derive(Default)]
pub(crate) struct Hub {
    guests: Mutex<Vec<Arc<Guest>>>,
}

// held while a request is being served, so background hashing steps aside
pub(crate) struct FgGuard<'a>(&'a AtomicUsize);

impl Drop for FgGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) struct Core {
    pub(crate) root: OwnedFd,
    pub(crate) root_path: PathBuf,
    pub(crate) project: Name,
    pub(crate) tree: Mutex<Tree>,
    pub(crate) rules: Arc<RwLock<Rules>>,
    pub(crate) fs: FsTraits,
    pub(crate) hub: Hub,
    pub(crate) events: Sender<Vec<WatchEvent>>,
    pub(crate) echoes: Arc<sys::Echoes>,
    // paths the committer is changing on disk right now; it records them in the tree before letting go
    pub(crate) inflight: Mutex<Vec<RelPath>>,
    pub(crate) dirty: AtomicBool,
    pub(crate) stats: Counters,
    pub(crate) kept: serve::Kept,
    // jobs the serve pool and the committer are running right now; the hasher yields while it is above zero
    pub(crate) fg: AtomicUsize,
    pub(crate) hashing: hasher::Hub,
    ui: Option<Arc<UiBus>>,
    kick: Option<Sender<()>>,
    tmp_seed: u64,
    tmp_n: AtomicU64,
    root_id: (u64, u64),
    lost: AtomicBool,
}

impl Core {
    pub(crate) fn new(
        root_path: PathBuf,
        project: Name,
        tree: Tree,
        rules: Arc<RwLock<Rules>>,
        events: Sender<Vec<WatchEvent>>,
    ) -> io::Result<Self> {
        let root = rustix::fs::open(
            &root_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut seed = [0u8; 8];
        getrandom::fill(&mut seed).map_err(|_| io::Error::other("system random source failed"))?;
        let tmp_seed = u64::from_le_bytes(seed);
        let fs = detect_fs(root.as_fd(), tmp_seed);
        let st = rustix::fs::fstat(&root)?;
        Ok(Self {
            root_id: dev_ino(&st),
            lost: AtomicBool::new(false),
            root,
            root_path,
            project,
            tree: Mutex::new(tree),
            rules,
            fs,
            hub: Hub::default(),
            events,
            echoes: Arc::default(),
            inflight: Mutex::new(Vec::new()),
            dirty: AtomicBool::new(true),
            stats: Counters::default(),
            kept: serve::Kept::default(),
            fg: AtomicUsize::new(0),
            hashing: hasher::Hub::default(),
            ui: None,
            kick: None,
            tmp_seed,
            tmp_n: AtomicU64::new(0),
        })
    }

    // lock order everywhere: rules, then tree, then the hub, then a guest feed
    pub(crate) fn tree(&self) -> MutexGuard<'_, Tree> {
        lock(&self.tree)
    }

    pub(crate) fn rules_r(&self) -> RwLockReadGuard<'_, Rules> {
        read(&self.rules)
    }

    pub(crate) fn rules_w(&self) -> RwLockWriteGuard<'_, Rules> {
        write(&self.rules)
    }

    pub(crate) fn fg_guard(&self) -> FgGuard<'_> {
        self.fg.fetch_add(1, Ordering::AcqRel);
        FgGuard(&self.fg)
    }

    // records a hash computed for exactly this version of the entry, then tells guests; a stale hash is dropped
    pub(crate) fn learn_hash(&self, p: &RelPath, ver: Seq, stat: &StatKey, h: Hash32) {
        self.apply_hash(p, ver, stat, h);
    }

    pub(crate) fn apply_hash(&self, p: &RelPath, ver: Seq, stat: &StatKey, h: Hash32) -> bool {
        let applied = self.tree().set_hash(p, ver, stat, h);
        if applied {
            self.dirty.store(true, Ordering::Release);
            if self.hashing.add(p.clone(), ver, h) {
                self.flush_hashes(false);
            }
        }
        applied
    }

    // the directory is being read right now, so its pending siblings are hashed first
    pub(crate) fn hint_dir(&self, dir: &RelPath) {
        self.hashing.hint(dir);
    }

    // buffered hashes go to every live guest on the bulk queue; a guest whose queue is full misses them and
    // can ask for them with Op::Hashes
    pub(crate) fn flush_hashes(&self, force: bool) {
        let Some(items) = self.hashing.take(force) else {
            return;
        };
        let index = self.tree().index_id();
        let guests: Vec<Arc<Guest>> = lock(&self.hub.guests)
            .iter()
            .filter(|g| lock(&g.feed).live)
            .cloned()
            .collect();
        let parts = hash_parts(items);
        for g in &guests {
            for items in &parts {
                let push = Msg::Push(Push::Hashes {
                    index,
                    items: items.clone(),
                });
                if g.link.try_send_bulk(push).is_err() {
                    break;
                }
            }
        }
    }

    // nothing is pending any more: whatever hashes guests lack are available to pull
    pub(crate) fn hashes_done(&self) {
        self.flush_hashes(true);
        let index = self.tree().index_id();
        let guests: Vec<Arc<Guest>> = lock(&self.hub.guests)
            .iter()
            .filter(|g| lock(&g.feed).live)
            .cloned()
            .collect();
        for g in &guests {
            let _ = g.link.send(Msg::Push(Push::HashesDone { index }));
        }
    }

    pub(crate) fn tmp_name(&self) -> String {
        let n = self.tmp_n.fetch_add(1, Ordering::Relaxed);
        format!("{TMP_PREFIX}{:016x}{n:x}", self.tmp_seed)
    }

    // the path still names the directory we opened; false once it was moved, removed or replaced
    pub(crate) fn root_intact(&self) -> bool {
        if self.lost.load(Ordering::Acquire) {
            return false;
        }
        rustix::fs::stat(&self.root_path).is_ok_and(|s| dev_ino(&s) == self.root_id)
    }

    pub(crate) fn root_lost(&self) {
        if !self.lost.swap(true, Ordering::AcqRel) {
            self.kick();
        }
    }

    pub(crate) fn is_lost(&self) -> bool {
        self.lost.load(Ordering::Acquire)
    }

    pub(crate) fn kick(&self) {
        if let Some(k) = &self.kick {
            let _ = k.try_send(());
        }
    }

    pub(crate) fn ui(&self, f: impl FnOnce(&mut UiSnapshot)) {
        if let Some(u) = &self.ui {
            u.update(f);
        }
    }

    pub(crate) fn request_rescan(&self, p: &RelPath) {
        let _ = self.events.try_send(vec![WatchEvent {
            path: p.clone(),
            flags: wflag::MODIFIED,
            cookie: 0,
        }]);
    }

    pub(crate) fn notice(&self, n: Notice, to_guests: bool) {
        if to_guests {
            for g in lock(&self.hub.guests).iter() {
                if lock(&g.feed).live {
                    let _ = g.link.send(Msg::Push(Push::Notice(n.clone())));
                }
            }
        }
        let t = now_ms();
        self.ui(|s| {
            s.notices.push_back((t, n));
            while s.notices.len() > NOTICES_MAX {
                s.notices.pop_front();
            }
        });
    }

    // runs with the tree lock held so guests see batches in seq order
    pub(crate) fn publish_locked(&self, tree: &Tree, changes: Vec<Change>, origin: Option<u64>) {
        if tree.pending() > 0 || self.hashing.done_due() {
            self.hashing.wake();
        }
        self.dirty.store(true, Ordering::Release);
        self.kick();
        if changes.is_empty() {
            return;
        }
        let seq = tree.seq();
        let guests = lock(&self.hub.guests);
        if guests.is_empty() {
            return;
        }
        let n = changes.len();
        let parts = batches(changes);
        for g in guests.iter() {
            let mut f = lock(&g.feed);
            if !f.live || f.lagging {
                continue;
            }
            if origin == Some(g.id) {
                f.sent = seq;
                continue;
            }
            for (done, b) in &parts {
                let s = seq.saturating_sub((n - done) as u64).max(f.sent);
                match g.link.try_push(Push::Changes {
                    seq: s,
                    changes: b.clone(),
                }) {
                    Ok(()) => f.sent = s,
                    Err(PushError::Full(_)) => {
                        f.lagging = true;
                        break;
                    }
                    Err(PushError::Closed) => break,
                }
            }
        }
    }

    // a lagging guest is fed from the tree journal, so its backlog costs no host memory
    pub(crate) fn catch_up(&self, g: &Guest) {
        if !lock(&g.feed).lagging || g.link.unacked_pushes() > UNACKED_PUSH_MAX / 2 {
            return;
        }
        let tree = self.tree();
        let mut f = lock(&g.feed);
        if !f.lagging {
            return;
        }
        let target = tree.seq();
        let base = f.sent;
        let replay = tree
            .changes_since(base)
            .filter(|c| c.len() as u64 == target.saturating_sub(base));
        match replay {
            Some(ch) => {
                for (done, b) in batches(ch) {
                    let s = base + done as u64;
                    match g.link.try_push(Push::Changes { seq: s, changes: b }) {
                        Ok(()) => f.sent = s,
                        Err(_) => return f.release(&g.link),
                    }
                }
                f.sent = target;
                f.lagging = false;
                f.release(&g.link);
                send_hashes_done(&g.link, &tree);
            }
            None => {
                if send_snapshot(&g.link, &tree).is_err() {
                    return;
                }
                f.sent = target;
                f.lagging = false;
                f.release(&g.link);
                send_hashes_done(&g.link, &tree);
                drop(f);
                drop(tree);
                self.notice(
                    Notice {
                        kind: NoticeKind::Resynced,
                        path: RelPath::root(),
                    },
                    false,
                );
            }
        }
    }

    fn attach(&self, g: &Arc<Guest>, have: Option<(IndexId, Seq)>) -> Result<(), Closed> {
        let (mut repos, srcs) = {
            let r = self.rules_r();
            (r.repos(), r.exclude_srcs())
        };
        repos.truncate(BATCH_MAX);
        let mut budget = PUSH_BYTES;
        let excludes: Vec<ExcludeSrc> = srcs
            .into_iter()
            .take(BATCH_MAX)
            .filter(|x| {
                let k = x.text.0.len() + x.repo.as_str().len() + 16;
                let ok = k <= budget;
                if ok {
                    budget -= k;
                }
                ok
            })
            .collect();
        let tree = self.tree();
        let mut guests = lock(&self.hub.guests);
        g.link.send(Msg::Welcome(Welcome {
            proto: PROTO,
            project: self.project.clone(),
            index: tree.index_id(),
            seq: tree.seq(),
            fs: self.fs,
            repos,
            excludes,
            host_ns: now_ns(),
        }))?;
        let seq = tree.seq();
        let replay = have
            .filter(|(i, _)| *i == tree.index_id())
            .and_then(|(_, s)| {
                tree.changes_since(s)
                    .filter(|c| c.len() as u64 == seq.saturating_sub(s))
                    .map(|c| (s, c))
            });
        match replay {
            Some((_, ch)) if ch.is_empty() => g.link.send(Msg::Push(Push::Changes {
                seq,
                changes: Vec::new(),
            }))?,
            Some((s, ch)) => {
                for (done, b) in batches(ch) {
                    g.link.send(Msg::Push(Push::Changes {
                        seq: s + done as u64,
                        changes: b,
                    }))?;
                }
            }
            None => send_snapshot(&g.link, &tree)?,
        }
        *lock(&g.feed) = Feed {
            sent: seq,
            lagging: false,
            live: true,
            replies: Vec::new(),
        };
        guests.push(g.clone());
        send_hashes_done(&g.link, &tree);
        Ok(())
    }

    fn stats_to_ui(&self) {
        let files = self.tree().len() as u64;
        let st = &self.stats;
        let (fetches, commits, refused, merged, tx, rx) = (
            st.fetches.load(Ordering::Relaxed),
            st.commits.load(Ordering::Relaxed),
            st.refused.load(Ordering::Relaxed),
            st.merged.load(Ordering::Relaxed),
            st.tx.load(Ordering::Relaxed),
            st.rx.load(Ordering::Relaxed),
        );
        self.ui(|s| {
            s.stats.files = files;
            s.stats.fetches = fetches;
            s.stats.commits = commits;
            s.stats.refused = refused;
            s.stats.merged = merged;
            s.stats.tx = tx;
            s.stats.rx = rx;
        });
    }
}

// stat field widths differ by platform
#[allow(clippy::unnecessary_cast)]
fn dev_ino(s: &rustix::fs::Stat) -> (u64, u64) {
    (s.st_dev as u64, s.st_ino as u64)
}

// probes with an internal name, which watchers and scans never report
fn detect_fs(root: BorrowedFd<'_>, seed: u64) -> FsTraits {
    let name = format!("{TMP_PREFIX}probe{seed:x}\u{e9}");
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let Ok(fd) = rustix::fs::openat(root, name.as_str(), flags, Mode::from_bits_truncate(0o600))
    else {
        return FsTraits {
            case_fold: false,
            norm_fold: false,
        };
    };
    drop(fd);
    let case_fold = sys::stat_key_at(root, &name.to_uppercase()).is_ok();
    let norm_fold = sys::stat_key_at(root, &name.replace('\u{e9}', "e\u{301}")).is_ok();
    let _ = rustix::fs::unlinkat(root, name.as_str(), AtFlags::empty());
    FsTraits {
        case_fold,
        norm_fold,
    }
}

fn prime_rules(root_fd: BorrowedFd<'_>, root: &Path, rules: &mut Rules) {
    if root.join(".git").symlink_metadata().is_ok() {
        repo::register(rules, root, &RelPath::root());
    } else {
        repo::register_plain_root(rules, root);
    }
    if let Ok(p) = RelPath::new(".gitignore")
        && let Some(t) = read_rule(root_fd, &p)
    {
        rules.update_rule_file(&p, Some(&t));
    }
}

// rebuilds repo and rule registrations from a persisted index, so replayed events classify correctly
fn rules_from_tree(root_fd: BorrowedFd<'_>, root: &Path, tree: &Tree, rules: &mut Rules) {
    let mut repos: Vec<RelPath> = Vec::new();
    let mut files: Vec<RelPath> = Vec::new();
    apply::each_entry(tree, &mut |p, e| {
        if let Some((dir, name)) = p.split_last() {
            if name == ".git" {
                if let Ok(d) = RelPath::new(dir) {
                    repos.push(d);
                }
            } else if name == ".gitignore"
                && e.meta.kind == Kind::File
                && e.domain == Domain::Synced
            {
                files.push(p.clone());
            }
        }
    });
    if !repos.iter().any(RelPath::is_root) {
        repo::register_plain_root(rules, root);
    }
    for wt in &repos {
        repo::register(rules, root, wt);
    }
    for f in &files {
        let text = read_rule(root_fd, f);
        rules.update_rule_file(f, text.as_deref());
    }
}

// stale temps from a crashed run; only files older than this process are touched
fn sweep_temps(core: &Core, started: SystemTime) {
    let cutoff = started
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let mut dirs = vec![RelPath::root()];
    {
        let tree = core.tree();
        apply::each_entry(&tree, &mut |p, e| {
            if e.meta.kind == Kind::Dir && e.domain == Domain::Synced {
                dirs.push(p.clone());
            }
        });
    }
    dirs.par_iter().for_each(|d| {
        let Ok(fd) = sys::open_beneath(core.root.as_fd(), d, OFlags::RDONLY | OFlags::DIRECTORY)
        else {
            return;
        };
        let Ok(it) = rustix::fs::Dir::read_from(fd.as_fd()) else {
            return;
        };
        for ent in it.flatten() {
            let Ok(name) = ent.file_name().to_str() else {
                continue;
            };
            if !name.starts_with(TMP_PREFIX) {
                continue;
            }
            if let Ok(st) = sys::stat_key_at(fd.as_fd(), name)
                && sys::kind_of_mode(st.mode) == Some(Kind::File)
                && st.mtime_ns < cutoff
            {
                let _ = rustix::fs::unlinkat(fd.as_fd(), name, AtFlags::empty());
            }
        }
    });
}

fn spawn<F: FnOnce() + Send + 'static>(name: &str, f: F) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().name(name.into()).spawn(f)
}

pub fn run(mut cfg: HostCfg, ui: Arc<UiBus>, cmds: Receiver<UiCmd>) -> io::Result<()> {
    let started = SystemTime::now();
    sys::keep_dataless();
    let root_path = std::fs::canonicalize(&cfg.root)?;
    let project = match cfg.project.take() {
        Some(p) => p,
        None => root_path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| Name::new(n).ok())
            .map_or_else(
                || Name::new("project").map_err(|_| io::Error::other("project name")),
                Ok,
            )?,
    };
    let id = Arc::new(Identity::load_or_create(&cfg.config_dir)?);
    let trust = Arc::new(Trust::load(&cfg.config_dir)?);
    ensure_private_dir(&cfg.state_dir)?;
    let index_path = cfg.state_dir.join(INDEX_FILE);
    ui.update(|s| {
        s.role = Role::Host;
        s.project = Some(project.clone());
        s.peers.clear();
        s.pairing = None;
    });

    let root_fd = rustix::fs::open(
        &root_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let loaded = persist::load_index(&index_path);
    let mut rules = Rules::new(&[]);
    match &loaded {
        Some((t, _)) => rules_from_tree(root_fd.as_fd(), &root_path, t, &mut rules),
        None => prime_rules(root_fd.as_fd(), &root_path, &mut rules),
    }
    drop(root_fd);
    let rules = Arc::new(RwLock::new(rules));

    let (ev_tx, ev_rx) = bounded::<Vec<WatchEvent>>(EVENT_QUEUE);
    let filter: sys::DirFilter = {
        let r = rules.clone();
        Arc::new(move |d: &RelPath| {
            // the fsevents callback must never wait on a rescan holding the rules: fseventsd drops
            // a stalled client's events, which costs a full rescan; unfiltered events are classified later
            #[cfg(target_os = "macos")]
            let rules = match r.try_read() {
                Ok(g) => g,
                Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return true,
            };
            #[cfg(not(target_os = "macos"))]
            let rules = read(&r);
            matches!(rules.classify(d, true), Class::Synced | Class::GitRo)
        })
    };
    let resume = loaded.as_ref().and_then(|(_, r)| *r);
    // the watcher starts before the scan so nothing that changes during the walk is missed
    let echoes = Arc::new(sys::Echoes::default());
    let watcher = sys::start_watcher_echoes(
        &root_path,
        resume,
        ev_tx.clone(),
        Some(filter),
        echoes.clone(),
    )?;
    let replay = cfg!(target_os = "macos")
        && resume.is_some_and(|t| {
            t.event_id != 0 && watcher.resume_token().is_some_and(|w| w.volume == t.volume)
        });
    // after an unclean exit guests may hold seqs past the saved index, so its seq space is retired
    let clean = loaded
        .as_ref()
        .is_some_and(|(t, _)| persist::take_clean(&index_path, t));
    let stale = loaded.is_some() && !clean;
    let tree = {
        let mut r = write(&rules);
        let mut t = match loaded {
            Some((t, _)) if replay => t,
            Some((t, _)) => scan::rescan(&root_path, &mut r, t)?,
            None => scan::scan(&root_path, &mut r)?,
        };
        if stale {
            t.renew_index(scan::new_index_id()?);
        }
        t
    };

    let (kick_tx, kick_rx) = bounded::<()>(1);
    let mut core = Core::new(root_path, project.clone(), tree, rules, ev_tx)?;
    core.ui = Some(ui.clone());
    core.kick = Some(kick_tx);
    core.echoes = echoes;
    let core = Arc::new(core);
    core.stats_to_ui();

    let (stop_tx, stop_rx) = bounded::<()>(1);
    let applier = apply::Applier::new(core.clone(), watcher, ev_rx, stop_rx, index_path);
    let apply_h = spawn("csync-apply", move || applier.run())?;
    let (job_tx, job_rx) = bounded::<commit::Job>(COMMIT_QUEUE);
    let commit_h = {
        let c = core.clone();
        spawn("csync-commit", move || commit::run(&c, &job_rx))?
    };
    let (fetch_tx, fetch_rx) = bounded::<serve::FetchJob>(FETCH_QUEUE);
    let mut fetch_hs = Vec::with_capacity(FETCH_THREADS);
    for _ in 0..FETCH_THREADS {
        let (c, rx) = (core.clone(), fetch_rx.clone());
        fetch_hs.push(spawn("csync-fetch", move || serve::run(&c, &rx))?);
    }
    drop(fetch_rx);
    let (light_tx, light_rx) = bounded::<serve::FetchJob>(FETCH_QUEUE);
    let mut light_hs = Vec::with_capacity(LIGHT_THREADS);
    for _ in 0..LIGHT_THREADS {
        let (c, rx) = (core.clone(), light_rx.clone());
        light_hs.push(spawn("csync-light", move || serve::run(&c, &rx))?);
    }
    drop(light_rx);
    {
        let c = core.clone();
        spawn("csync-sweep", move || sweep_temps(&c, started))?;
    }
    let hasher = hasher::start(core.clone(), HASH_THREADS);

    let listener = Listener::bind(cfg.listen, id.clone(), trust.clone(), cfg.allow_pairing)?;
    listener.set_hello(HsHello {
        proto: PROTO,
        role: Role::Host,
        name: project.clone(),
    });
    let advert = if cfg.advertise {
        match discover::advertise(
            &project,
            listener.local_addr().port(),
            &id.public,
            cfg.all_ifaces,
        ) {
            Ok(a) => Some(a),
            Err(_) => {
                ui.update(|s| {
                    if !s.hints.contains(&MDNS_HINT) {
                        s.hints.push(MDNS_HINT);
                    }
                });
                None
            }
        }
    } else {
        None
    };

    let mut host = Host {
        core: core.clone(),
        trust,
        jobs: job_tx,
        fetch: fetch_tx,
        light: light_tx,
        next_id: 1,
        pending: None,
        sessions: Vec::new(),
    };
    let mut ctl_rx: Receiver<HostCtl> = cfg.ctl.take().unwrap_or_else(never);
    let mut ui_due: Option<Instant> = None;
    loop {
        let pair_rx = host
            .pending
            .as_ref()
            .map_or_else(never, |p| p.sess.inbox.clone());
        let pair_tick = host.pending.as_ref().map_or_else(never, |p| at(p.deadline));
        let ui_tick = ui_due.map_or_else(never, at);
        select! {
            recv(listener.incoming()) -> r => match r {
                Ok(Ok(inc)) => host.incoming(inc),
                Ok(Err(NetError::PairingLimited)) => core.ui(|s| s.hint(PAIR_LIMIT_HINT)),
                Ok(Err(_)) => {}
                Err(_) => break,
            },
            recv(cmds) -> c => match c {
                Ok(UiCmd::Quit) | Err(_) => break,
                Ok(c) => host.command(c),
            },
            recv(pair_rx) -> m => host.pairing_msg(m.ok()),
            recv(pair_tick) -> _ => host.pairing_end(true),
            recv(ctl_rx) -> m => match m {
                Ok(c) => host.ctl(c),
                Err(_) => ctl_rx = never(),
            },
            recv(kick_rx) -> _ => {
                if core.is_lost() {
                    break;
                }
                if ui_due.is_none() {
                    ui_due = Some(Instant::now() + UI_EVERY);
                }
            },
            recv(ui_tick) -> _ => {
                ui_due = None;
                core.stats_to_ui();
            },
        }
    }

    drop(advert);
    drop(listener);
    host.pairing_end(true);
    let live: Vec<Arc<Guest>> = lock(&core.hub.guests).clone();
    for g in &live {
        g.link.close(CloseReason::Local);
    }
    drop(live);
    let Host {
        jobs,
        fetch,
        light,
        sessions,
        ..
    } = host;
    for h in sessions {
        let _ = h.join();
    }
    drop(jobs);
    let _ = commit_h.join();
    drop(fetch);
    drop(light);
    for h in fetch_hs.into_iter().chain(light_hs) {
        let _ = h.join();
    }
    hasher.stop();
    let _ = stop_tx.send(());
    let _ = apply_h.join();
    core.ui(|s| {
        s.peers.clear();
        s.pairing = None;
    });
    if core.is_lost() {
        return Err(io::Error::other(
            "the project root was moved, removed or replaced; start csync again on the new tree",
        ));
    }
    Ok(())
}

struct Pairing {
    id: u64,
    sess: Session,
    deadline: Instant,
    host_ok: bool,
    guest_ok: bool,
    early: Option<Hello>,
}

struct Host {
    core: Arc<Core>,
    trust: Arc<Trust>,
    jobs: Sender<commit::Job>,
    fetch: Sender<serve::FetchJob>,
    light: Sender<serve::FetchJob>,
    next_id: u64,
    pending: Option<Pairing>,
    sessions: Vec<JoinHandle<()>>,
}

impl Host {
    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn full(&self) -> bool {
        self.sessions.iter().filter(|h| !h.is_finished()).count() >= GUESTS_MAX
    }

    fn incoming(&mut self, inc: Incoming) {
        match inc {
            Incoming::Known(sess, entry) => {
                if entry.role != Role::Guest || self.trust.get(&sess.link.peer()).is_none() {
                    sess.link.close(CloseReason::Revoked);
                    return;
                }
                self.start_session(sess, None);
            }
            Incoming::Pairing(sess) => {
                self.core.ui(|s| s.hints.retain(|h| *h != PAIR_LIMIT_HINT));
                let Some(sas) = sess.sas else {
                    sess.link
                        .close(CloseReason::Protocol("pairing without sas"));
                    return;
                };
                if self.pending.is_some() || self.full() {
                    let _ = sess.link.send(Msg::Pair(PairStep::Rejected));
                    sess.link.close(CloseReason::Local);
                    return;
                }
                let id = self.next_id();
                let prompt = PairPrompt {
                    peer: id,
                    name: sess.hello.name.clone(),
                    sas,
                    expires_ms: now_ms() + PAIR_TIMEOUT_S * 1000,
                };
                self.core.ui(|s| s.pairing = Some(prompt));
                let deadline = Instant::now() + Duration::from_secs(PAIR_TIMEOUT_S);
                self.pending = Some(Pairing {
                    id,
                    sess,
                    deadline,
                    host_ok: false,
                    guest_ok: false,
                    early: None,
                });
            }
        }
    }

    fn pairing_end(&mut self, tell: bool) {
        let Some(p) = self.pending.take() else { return };
        if tell {
            let _ = p.sess.link.send(Msg::Pair(PairStep::Rejected));
        }
        p.sess.link.close(CloseReason::Local);
        self.core.ui(|s| s.pairing = None);
    }

    fn pairing_msg(&mut self, m: Option<In>) {
        let Some(p) = self.pending.as_mut() else {
            return;
        };
        match m {
            Some(In::Msg(Msg::Pair(PairStep::GuestConfirmed))) => {
                p.guest_ok = true;
                self.finish_pairing();
            }
            Some(In::Msg(Msg::Hello(h))) if p.early.is_none() => p.early = Some(h),
            Some(In::Msg(Msg::Pair(PairStep::Rejected) | Msg::Bye(_)))
            | Some(In::Closed(_))
            | None => self.pairing_end(false),
            Some(_) => {
                p.sess
                    .link
                    .close(CloseReason::Protocol("unexpected message during pairing"));
                self.pairing_end(false);
            }
        }
    }

    fn finish_pairing(&mut self) {
        if !self
            .pending
            .as_ref()
            .is_some_and(|p| p.host_ok && p.guest_ok)
        {
            return;
        }
        let Some(p) = self.pending.take() else { return };
        self.core.ui(|s| s.pairing = None);
        let entry = TrustEntry {
            key: p.sess.link.peer(),
            role: Role::Guest,
            name: p.sess.hello.name.clone(),
            added_unix: now_unix(),
        };
        if self.trust.add(entry).is_err() {
            let _ = p.sess.link.send(Msg::Pair(PairStep::Rejected));
            p.sess.link.close(CloseReason::Local);
            return;
        }
        self.start_session(p.sess, p.early);
    }

    fn command(&mut self, c: UiCmd) {
        match c {
            UiCmd::Accept(id) => {
                if let Some(p) = self.pending.as_mut()
                    && p.id == id
                    && !p.host_ok
                {
                    p.host_ok = true;
                    let _ = p.sess.link.send(Msg::Pair(PairStep::HostAccepted));
                    self.finish_pairing();
                }
            }
            UiCmd::Reject(id) => {
                if self.pending.as_ref().is_some_and(|p| p.id == id) {
                    self.pairing_end(true);
                }
            }
            UiCmd::Revoke(id) => {
                let key = lock(&self.core.hub.guests)
                    .iter()
                    .find(|g| g.id == id)
                    .map(|g| g.key);
                if let Some(k) = key
                    && let Ok(gone) = self.trust.forget(&k.to_b64())
                {
                    self.drop_keys(&gone);
                }
            }
            UiCmd::Join(_) | UiCmd::Confirm(_) | UiCmd::Quit => {}
        }
    }

    fn ctl(&mut self, c: HostCtl) {
        match c {
            HostCtl::Forget { selector, reply } => {
                let r = self.trust.forget(&selector);
                if let Ok(gone) = &r {
                    self.drop_keys(gone);
                }
                let _ = reply.send(r);
            }
        }
    }

    fn drop_keys(&self, gone: &[TrustEntry]) {
        for g in lock(&self.core.hub.guests).iter() {
            if gone.iter().any(|e| e.key == g.key) {
                g.link.close(CloseReason::Revoked);
            }
        }
    }

    fn start_session(&mut self, sess: Session, early: Option<Hello>) {
        self.sessions.retain(|h| !h.is_finished());
        let Session {
            link, inbox, hello, ..
        } = sess;
        if self.sessions.len() >= GUESTS_MAX {
            let _ = link.send(Msg::Bye(Bye::Limit));
            link.close(CloseReason::Local);
            return;
        }
        let id = self.next_id();
        let g = Arc::new(Guest::new(id, link, hello.name));
        let view = PeerView {
            id,
            name: g.name.clone(),
            fpr: g.key.fpr(),
            state: ConnState::Handshaking,
            rtt_us: 0,
        };
        self.core.ui(|s| s.peers.push(view));
        let ctx = SessionCtx {
            core: self.core.clone(),
            g: g.clone(),
            inbox,
            jobs: self.jobs.clone(),
            fetch: self.fetch.clone(),
            light: self.light.clone(),
            uploads: FxHashMap::default(),
            order: VecDeque::new(),
            held: FxHashMap::default(),
            live: false,
            last_ping: Instant::now(),
        };
        match spawn("csync-guest", move || ctx.run(early)) {
            Ok(h) => self.sessions.push(h),
            Err(_) => {
                g.link.close(CloseReason::Local);
                self.core.ui(|s| s.peers.retain(|p| p.id != id));
            }
        }
    }
}

enum UpKind {
    Stream { hash: Hash32 },
    Delta { ops: Vec<DeltaOp> },
}

struct Upload {
    op: Op,
    kind: UpKind,
    sink: commit::Sink,
    want: u64,
    got: u64,
    at: Instant,
}

impl Upload {
    // Ok(true) once the final chunk has landed
    fn write(&mut self, off: u64, data: &[u8], last: bool) -> Result<bool, WireErr> {
        if off != self.got {
            return Err(WireErr::Invalid);
        }
        let end = self
            .got
            .checked_add(data.len() as u64)
            .filter(|&e| e <= self.want)
            .ok_or(WireErr::TooLarge)?;
        self.sink.put(data).map_err(|e| wire(&e))?;
        self.got = end;
        self.at = Instant::now();
        if last {
            return if self.got == self.want {
                Ok(true)
            } else {
                Err(WireErr::Invalid)
            };
        }
        Ok(false)
    }
}

struct SessionCtx {
    core: Arc<Core>,
    g: Arc<Guest>,
    inbox: Receiver<In>,
    jobs: Sender<commit::Job>,
    fetch: Sender<serve::FetchJob>,
    light: Sender<serve::FetchJob>,
    uploads: FxHashMap<ReqId, Upload>,
    // mutations not yet handed to the committer, in the order the guest sent them
    order: VecDeque<ReqId>,
    held: FxHashMap<ReqId, (Op, commit::Payload)>,
    live: bool,
    last_ping: Instant,
}

impl SessionCtx {
    fn run(mut self, early: Option<Hello>) {
        if self.handshake(early) {
            self.serve();
        }
        self.uploads.clear();
        let id = self.g.id;
        lock(&self.core.hub.guests).retain(|x| x.id != id);
        self.g.link.close(CloseReason::Local);
        self.core.ui(|s| s.peers.retain(|p| p.id != id));
    }

    fn set_state(&self, st: ConnState) {
        let id = self.g.id;
        self.core.ui(|s| {
            if let Some(p) = s.peers.iter_mut().find(|p| p.id == id) {
                p.state = st;
            }
        });
    }

    fn handshake(&mut self, early: Option<Hello>) -> bool {
        let hello = match early {
            Some(h) => h,
            None => loop {
                match self.inbox.recv_timeout(HELLO_TIMEOUT) {
                    Ok(In::Msg(Msg::Hello(h))) => break h,
                    Ok(In::Msg(Msg::Pair(_))) => {}
                    Ok(In::Msg(Msg::Bye(_)) | In::Closed(_)) | Err(_) => return false,
                    Ok(_) => {
                        self.g.link.close(CloseReason::Protocol("expected hello"));
                        return false;
                    }
                }
            },
        };
        if hello.proto != PROTO {
            let _ = self.g.link.send(Msg::Bye(Bye::ProtoMismatch));
            self.g.link.close(CloseReason::Local);
            return false;
        }
        let total = self.core.tree().len() as u64;
        self.set_state(ConnState::Syncing { done: 0, total });
        if self.core.attach(&self.g, hello.have).is_err() {
            return false;
        }
        self.set_state(ConnState::Syncing { done: total, total });
        self.ping();
        true
    }

    fn ping(&mut self) {
        self.last_ping = Instant::now();
        self.core.kept.prune();
        let _ = self.g.link.send(Msg::Ping { t_ns: now_ns() });
    }

    fn mark_live(&mut self) {
        if !self.live {
            self.live = true;
            self.set_state(ConnState::Live);
        }
    }

    fn serve(&mut self) {
        let mut last_rx = Instant::now();
        loop {
            let wait = if self.uploads.is_empty() {
                PING_EVERY
            } else {
                UPLOAD_REAP
            };
            match self.inbox.recv_timeout(wait) {
                Ok(In::Closed(_)) | Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => {
                    if last_rx.elapsed() >= PEER_SILENT {
                        self.g.link.close(CloseReason::Io(io::ErrorKind::TimedOut));
                        return;
                    }
                    self.reap();
                }
                Ok(In::Msg(m)) => {
                    last_rx = Instant::now();
                    if !self.on_msg(m) {
                        return;
                    }
                }
                Ok(In::Chunk {
                    id,
                    off,
                    last,
                    data,
                }) => {
                    last_rx = Instant::now();
                    self.on_chunk(id, off, last, &data);
                }
            }
            if self.last_ping.elapsed() >= PING_EVERY {
                self.ping();
            }
        }
    }

    fn reap(&mut self) {
        let stale: Vec<ReqId> = self
            .uploads
            .iter()
            .filter(|(_, u)| u.at.elapsed() >= UPLOAD_IDLE)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.uploads.remove(&id);
            self.fail(id, WireErr::Io);
        }
    }

    fn on_msg(&mut self, m: Msg) -> bool {
        match m {
            Msg::Req { id, op } => {
                self.mark_live();
                self.on_req(id, op);
            }
            Msg::Cancel { id } => {
                if self.uploads.remove(&id).is_some() {
                    self.fail(id, WireErr::Gone);
                } else {
                    self.g.cancel_fetch(id);
                }
            }
            Msg::Ack { .. } => {
                self.mark_live();
                self.core.catch_up(&self.g);
            }
            Msg::Pong { t_ns, .. } => {
                let rtt = (now_ns().saturating_sub(t_ns) / 1_000).min(u64::from(u32::MAX)) as u32;
                let id = self.g.id;
                self.core.ui(|s| {
                    if let Some(p) = s.peers.iter_mut().find(|p| p.id == id) {
                        p.rtt_us = rtt;
                    }
                });
            }
            Msg::Push(Push::Notice(n)) => match n.kind {
                NoticeKind::Refused
                | NoticeKind::Merged
                | NoticeKind::Promoted
                | NoticeKind::Discarded => {
                    let ctr = match n.kind {
                        NoticeKind::Refused => Some(&self.core.stats.refused),
                        NoticeKind::Merged => Some(&self.core.stats.merged),
                        _ => None,
                    };
                    if let Some(c) = ctr {
                        c.fetch_add(1, Ordering::Relaxed);
                        self.core.kick();
                    }
                    self.core.notice(n, false);
                }
                NoticeKind::Resynced | NoticeKind::IgnoreChanged => {}
            },
            Msg::Bye(_) | Msg::Ping { .. } | Msg::Rekey | Msg::Hello(_) | Msg::Pair(_) => {}
            Msg::Welcome(_) | Msg::Push(_) | Msg::Resp { .. } => {
                self.g
                    .link
                    .close(CloseReason::Protocol("unexpected message from guest"));
                return false;
            }
        }
        true
    }

    fn on_req(&mut self, id: ReqId, mut op: Op) {
        if matches!(
            op,
            Op::Fetch { .. } | Op::FetchMany { .. } | Op::Resolve { .. } | Op::Hashes { .. }
        ) {
            return self.queue_fetch(id, op);
        }
        let plan = match &mut op {
            Op::Fetch { .. } | Op::FetchMany { .. } => None,
            Op::Commit {
                path, new, body, ..
            } => Some((path.clone(), *new, std::mem::replace(body, Body::Empty))),
            Op::Rename { to, body, .. } => body
                .as_mut()
                .map(|(v, b)| (to.clone(), *v, std::mem::replace(b, Body::Empty))),
            Op::Mk { .. }
            | Op::Remove { .. }
            | Op::SetAttr { .. }
            | Op::Resolve { .. }
            | Op::Hashes { .. } => None,
        };
        let Some((target, ver, body)) = plan else {
            return self.ready(id, op, commit::Payload::None);
        };
        match body {
            Body::Empty => self.ready(id, op, commit::Payload::Bytes(Vec::new())),
            Body::Inline(b) => {
                self.core
                    .stats
                    .rx
                    .fetch_add(b.0.len() as u64, Ordering::Relaxed);
                self.ready(id, op, commit::Payload::Bytes(b.0));
            }
            Body::Stream { len } if len != ver.size => self.g.reply(id, Err(WireErr::Invalid)),
            Body::Stream { len: 0 } => self.ready(id, op, commit::Payload::Bytes(Vec::new())),
            Body::Stream { len } => {
                self.begin_upload(id, op, &target, len, UpKind::Stream { hash: ver.hash })
            }
            Body::Delta { ops, data_len: 0 } => self.ready(
                id,
                op,
                commit::Payload::Delta {
                    ops,
                    data_len: 0,
                    lits: None,
                },
            ),
            Body::Delta { ops, data_len } => {
                self.begin_upload(id, op, &target, data_len, UpKind::Delta { ops })
            }
        }
    }

    // the indexed size and whether the entry already has a hash, as a request for it would find them
    fn indexed(&self, path: &RelPath) -> Option<(u64, bool)> {
        self.core
            .tree()
            .get(path)
            .map(|e| (e.stat.size, e.meta.hash.is_some()))
    }

    // work that never streams a large file and never hashes one: it must not queue behind a long stream
    fn is_light(&self, op: &Op) -> bool {
        // a pending large file is hashed whole first, which is bulk work
        let cheap = |path: &RelPath| match self.indexed(path) {
            Some((size, hashed)) => hashed || size <= INLINE_MAX as u64,
            None => true,
        };
        match op {
            Op::Hashes { .. } | Op::FetchMany { .. } => true,
            Op::Resolve { path, .. } => cheap(path),
            Op::Fetch {
                path,
                range: Some(_),
                ..
            } => cheap(path),
            Op::Fetch {
                path, range: None, ..
            } => self
                .indexed(path)
                .is_some_and(|(size, _)| size <= INLINE_MAX as u64),
            _ => false,
        }
    }

    fn queue_fetch(&mut self, id: ReqId, op: Op) {
        if let Err(e) = self.g.begin_fetch(id) {
            return self.g.reply(id, Err(e));
        }
        let lane = if self.is_light(&op) {
            &self.light
        } else {
            &self.fetch
        };
        if lane
            .try_send(serve::FetchJob {
                guest: self.g.clone(),
                id,
                op,
            })
            .is_err()
        {
            self.g.end_fetch(id);
            self.g.reply(id, Err(WireErr::Busy));
        }
    }

    fn submit(&self, id: ReqId, op: Op, payload: commit::Payload) {
        if self
            .jobs
            .send(commit::Job {
                guest: self.g.clone(),
                id,
                op,
                payload,
            })
            .is_err()
        {
            self.g.reply(id, Err(WireErr::Io));
        }
    }

    // mutations run in the order the guest sent them, so one still uploading holds back the rest
    fn ready(&mut self, id: ReqId, op: Op, payload: commit::Payload) {
        if self.order.is_empty() {
            return self.submit(id, op, payload);
        }
        self.order.push_back(id);
        self.held.insert(id, (op, payload));
    }

    fn uploaded(&mut self, id: ReqId, op: Op, payload: commit::Payload) {
        self.held.insert(id, (op, payload));
        self.release_held();
    }

    fn fail(&mut self, id: ReqId, e: WireErr) {
        self.g.reply(id, Err(e));
        if let Some(i) = self.order.iter().position(|&x| x == id) {
            self.order.remove(i);
        }
        self.release_held();
    }

    fn release_held(&mut self) {
        while let Some(&id) = self.order.front() {
            let Some((op, payload)) = self.held.remove(&id) else {
                return;
            };
            self.order.pop_front();
            self.submit(id, op, payload);
        }
    }

    fn begin_upload(&mut self, id: ReqId, op: Op, target: &RelPath, len: u64, kind: UpKind) {
        if self.uploads.contains_key(&id) {
            return self.g.reply(id, Err(WireErr::Invalid));
        }
        if self.uploads.len() >= UPLOADS_MAX {
            return self.g.reply(id, Err(WireErr::Busy));
        }
        let staged = commit::writable(&self.core.rules_r(), target, false)
            .and_then(|()| commit::open_parent(&self.core, target))
            .and_then(|(dir, _)| {
                commit::Staged::create(&self.core, dir, 0o600).map_err(|e| wire(&e))
            });
        match staged {
            Ok(staged) => {
                let hash = matches!(kind, UpKind::Stream { .. });
                let up = Upload {
                    op,
                    kind,
                    sink: commit::Sink::new(staged, hash, len),
                    want: len,
                    got: 0,
                    at: Instant::now(),
                };
                self.order.push_back(id);
                self.uploads.insert(id, up);
            }
            Err(e) => self.g.reply(id, Err(e)),
        }
    }

    fn on_chunk(&mut self, id: ReqId, off: u64, last: bool, data: &[u8]) {
        let Some(u) = self.uploads.get_mut(&id) else {
            return;
        };
        match u.write(off, data, last) {
            Ok(false) => {}
            Ok(true) => {
                if let Some(u) = self.uploads.remove(&id) {
                    self.core.stats.rx.fetch_add(u.want, Ordering::Relaxed);
                    self.finish_upload(id, u);
                }
            }
            Err(e) => {
                self.uploads.remove(&id);
                self.fail(id, e);
            }
        }
    }

    fn finish_upload(&mut self, id: ReqId, u: Upload) {
        let Upload {
            op,
            kind,
            sink,
            want,
            ..
        } = u;
        let (staged, got) = match sink.finish() {
            Ok(x) => x,
            Err(e) => return self.fail(id, wire(&e)),
        };
        match kind {
            UpKind::Stream { hash } => {
                if got != Some(hash) {
                    return self.fail(id, WireErr::Invalid);
                }
                self.uploaded(id, op, commit::Payload::File(staged));
            }
            UpKind::Delta { ops } => self.uploaded(
                id,
                op,
                commit::Payload::Delta {
                    ops,
                    data_len: want,
                    lits: Some(staged),
                },
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::tree::Observed;
    use crate::proto::{Expect, Version};

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn session() -> (Tmp, SessionCtx, Receiver<commit::Job>, Session) {
        session_with(|_| {})
    }

    fn session_with(prep: impl FnOnce(&Path)) -> (Tmp, SessionCtx, Receiver<commit::Job>, Session) {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!(
            "csync-order-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        std::fs::create_dir_all(&p).unwrap();
        let root = std::fs::canonicalize(&p).unwrap();
        prep(&root);
        let mut rules = Rules::new(&[]);
        let tree = scan::scan(&root, &mut rules).unwrap();
        let (ev, _) = bounded(64);
        let core = Core::new(
            root.clone(),
            Name::new("t").unwrap(),
            tree,
            Arc::new(RwLock::new(rules)),
            ev,
        )
        .unwrap();
        let (guest_end, host_end) = crate::net::conn::tests::test_pair();
        let g = Arc::new(Guest::new(
            1,
            host_end.link.clone(),
            Name::new("g").unwrap(),
        ));
        let (jobs, jrx) = crossbeam_channel::unbounded();
        let (fetch, _) = bounded(4);
        let (light, _) = bounded(4);
        let ctx = SessionCtx {
            core: Arc::new(core),
            g,
            inbox: host_end.inbox,
            jobs,
            fetch,
            light,
            uploads: FxHashMap::default(),
            order: VecDeque::new(),
            held: FxHashMap::default(),
            live: true,
            last_ping: Instant::now(),
        };
        (Tmp(root), ctx, jrx, guest_end)
    }

    fn streamed(path: &str, body: &[u8]) -> Op {
        Op::Commit {
            path: RelPath::new(path).unwrap(),
            base: Expect::Absent,
            new: Version {
                hash: *blake3::hash(body).as_bytes(),
                size: body.len() as u64,
            },
            perm: Some(0o644),
            body: Body::Stream {
                len: body.len() as u64,
            },
            sync: false,
            mtime_ns: None,
        }
    }

    fn ids(rx: &Receiver<commit::Job>) -> Vec<ReqId> {
        rx.try_iter().map(|j| j.id).collect()
    }

    fn fetch_of(path: &str, range: Option<(u64, u32)>) -> Op {
        Op::Fetch {
            path: RelPath::new(path).unwrap(),
            want: None,
            have: None,
            range,
        }
    }

    #[test]
    fn only_work_that_cannot_stream_or_hash_a_large_file_takes_the_light_lane() {
        let (_t, mut s, _jobs, _peer) = session_with(|root| {
            std::fs::write(root.join("small"), b"hi").unwrap();
            std::fs::write(root.join("big"), vec![1u8; INLINE_MAX + 1]).unwrap();
        });
        let resolve = |p: &str| Op::Resolve {
            path: RelPath::new(p).unwrap(),
            at: crate::proto::VerKey {
                index: 0,
                ver: 0,
                size: 0,
            },
            inline: false,
        };
        assert!(s.is_light(&Op::Hashes {
            index: 0,
            items: Vec::new()
        }));
        assert!(s.is_light(&Op::FetchMany { items: Vec::new() }));
        assert!(s.is_light(&fetch_of("small", None)));
        assert!(!s.is_light(&fetch_of("big", None)));
        assert!(s.is_light(&fetch_of("small", Some((0, 1)))));
        assert!(!s.is_light(&fetch_of("big", Some((0, 1)))));
        assert!(s.is_light(&resolve("small")));
        assert!(!s.is_light(&resolve("big")));
        assert!(!s.is_light(&fetch_of("missing", None)));

        let (ftx, frx) = bounded(8);
        let (ltx, lrx) = bounded(8);
        s.fetch = ftx;
        s.light = ltx;
        s.queue_fetch(1, fetch_of("small", None));
        s.queue_fetch(2, fetch_of("big", None));
        assert_eq!(lrx.try_iter().map(|j| j.id).collect::<Vec<_>>(), vec![1]);
        assert_eq!(frx.try_iter().map(|j| j.id).collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn a_rename_waits_for_the_upload_it_follows() {
        let (_t, mut s, jobs, _peer) = session();
        let body = vec![7u8; 100_000];
        s.on_msg(Msg::Req {
            id: 1,
            op: streamed(".a.tmp", &body),
        });
        s.on_msg(Msg::Req {
            id: 2,
            op: Op::Rename {
                from: RelPath::new(".a.tmp").unwrap(),
                to: RelPath::new("a").unwrap(),
                from_expect: Expect::Any,
                to_expect: Expect::Absent,
                body: None,
            },
        });
        assert!(
            ids(&jobs).is_empty(),
            "nothing may run before the upload lands"
        );
        s.on_chunk(1, 0, true, &body);
        assert_eq!(ids(&jobs), vec![1, 2]);
    }

    #[test]
    fn a_failed_upload_releases_what_waited_behind_it() {
        let (_t, mut s, jobs, _peer) = session();
        let body = vec![1u8; 100_000];
        s.on_msg(Msg::Req {
            id: 3,
            op: streamed(".b.tmp", &body),
        });
        s.on_msg(Msg::Req {
            id: 4,
            op: Op::Remove {
                path: RelPath::new("x").unwrap(),
                expect: Expect::Any,
            },
        });
        s.on_msg(Msg::Cancel { id: 3 });
        assert_eq!(ids(&jobs), vec![4]);
        s.on_msg(Msg::Req {
            id: 5,
            op: Op::Remove {
                path: RelPath::new("y").unwrap(),
                expect: Expect::Any,
            },
        });
        assert_eq!(ids(&jobs), vec![5]);
    }

    #[test]
    fn a_guest_dir_move_tells_that_guest_what_the_host_changed_inside() {
        let (t, s, _jobs, peer) = session_with(|root| {
            std::fs::create_dir_all(root.join("d1")).unwrap();
            std::fs::write(root.join("d1/a.txt"), "a\n").unwrap();
            std::fs::write(root.join("d1/b.txt"), "b\n").unwrap();
        });
        {
            let mut f = lock(&s.g.feed);
            f.live = true;
            f.sent = s.core.tree().seq();
        }
        lock(&s.core.hub.guests).push(s.g.clone());
        // a host write the watcher has not reported yet
        std::fs::remove_file(t.0.join("d1/b.txt")).unwrap();
        std::fs::write(t.0.join("d1/c.txt"), "c\n").unwrap();
        let op = Op::Rename {
            from: RelPath::new("d1").unwrap(),
            to: RelPath::new("m2").unwrap(),
            from_expect: Expect::Dir,
            to_expect: Expect::Absent,
            body: None,
        };
        let asker = commit::Asker::new(&s.g, 9);
        assert!(commit::exec(&s.core, op, commit::Payload::None, Some(&asker)).is_ok());
        let mut seen = Vec::new();
        let mut replied = false;
        while let Ok(i) = peer.inbox.recv_timeout(Duration::from_secs(2)) {
            match i {
                In::Msg(Msg::Resp { id: 9, res }) => {
                    assert!(matches!(res, Ok(Reply::Done { .. })), "{res:?}");
                    replied = true;
                }
                // the guest moves its copy on the reply, so nothing under the new path may come first
                In::Msg(Msg::Push(Push::Changes { changes, .. })) => {
                    assert!(replied, "pushed before the reply: {changes:?}");
                    seen.extend(changes);
                }
                _ => {}
            }
            if seen.len() >= 2 {
                break;
            }
        }
        let b = RelPath::new("m2/b.txt").unwrap();
        let c = RelPath::new("m2/c.txt").unwrap();
        assert!(
            seen.iter()
                .any(|x| matches!(x, Change::Remove { path } if *path == b)),
            "{seen:?}"
        );
        assert!(
            seen.iter()
                .any(|x| matches!(x, Change::Upsert { path, .. } if *path == c)),
            "{seen:?}"
        );
        assert!(
            !seen.iter().any(|x| matches!(x, Change::Rename { .. })),
            "the origin already made the move itself: {seen:?}"
        );
    }

    fn scratch() -> Tmp {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!(
            "csync-verify-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }

    fn body(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn verified(path: &Path, hook: Option<MidHook>) -> Option<Hash32> {
        let f = File::open(path).unwrap();
        let k1 = sys::stat_key(f.as_fd()).unwrap();
        MID_HASH.with(|m| *m.borrow_mut() = hook);
        let r = hash_verified(f.as_fd(), &k1).unwrap();
        MID_HASH.with(|m| *m.borrow_mut() = None);
        r
    }

    #[test]
    fn hash_verified_is_the_blake3_of_the_whole_file() {
        let t = scratch();
        for n in [
            0,
            1,
            4096,
            PAR_VERIFY_MIN as usize - 1,
            PAR_VERIFY_MIN as usize,
            VERIFY_BLOCK - 1,
            VERIFY_BLOCK,
            VERIFY_BLOCK + 1,
            2 * VERIFY_BLOCK + 5,
        ] {
            let p = t.0.join(format!("f{n}"));
            let data = body(n);
            std::fs::write(&p, &data).unwrap();
            assert_eq!(
                verified(&p, None),
                Some(*blake3::hash(&data).as_bytes()),
                "{n}"
            );
        }
    }

    #[test]
    fn the_parallel_and_the_paced_hash_agree() {
        let t = scratch();
        let p = t.0.join("f");
        let data = body(2 * VERIFY_BLOCK + 12_345);
        std::fs::write(&p, &data).unwrap();
        let f = File::open(&p).unwrap();
        let k1 = sys::stat_key(f.as_fd()).unwrap();
        let want = Some(*blake3::hash(&data).as_bytes());
        assert_eq!(hash_verified(f.as_fd(), &k1).unwrap(), want);
        assert_eq!(
            hash_verified_paced(f.as_fd(), &k1, &mut || true).unwrap(),
            want
        );
    }

    #[test]
    fn hash_verified_refuses_a_file_that_changed_while_it_was_read() {
        use std::io::Write;
        let t = scratch();
        let p = t.0.join("f");
        let fresh = || std::fs::write(&p, body(3 << 20)).unwrap();
        let hook = |f: Box<dyn FnOnce()>| -> Option<MidHook> { Some(f) };

        fresh();
        assert!(verified(&p, None).is_some());

        fresh();
        let q = p.clone();
        let grow = hook(Box::new(move || {
            let mut f = std::fs::OpenOptions::new().append(true).open(&q).unwrap();
            f.write_all(b"tail").unwrap();
        }));
        assert_eq!(verified(&p, grow), None);

        fresh();
        let q = p.clone();
        let shrink = hook(Box::new(move || {
            let f = std::fs::OpenOptions::new().write(true).open(&q).unwrap();
            f.set_len(100).unwrap();
        }));
        assert_eq!(verified(&p, shrink), None);

        // same size, new mtime
        fresh();
        let q = p.clone();
        let touch = hook(Box::new(move || {
            let f = std::fs::OpenOptions::new().write(true).open(&q).unwrap();
            f.set_modified(UNIX_EPOCH + Duration::from_secs(1_000_000))
                .unwrap();
        }));
        assert_eq!(verified(&p, touch), None);

        // only the mode changes
        fresh();
        let q = p.clone();
        let chmod = hook(Box::new(move || {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o600)).unwrap();
        }));
        assert_eq!(verified(&p, chmod), None);

        // only ctime changes: a new hard link
        fresh();
        let (q, other) = (p.clone(), t.0.join("link"));
        let link = hook(Box::new(move || {
            thread::sleep(Duration::from_millis(30));
            std::fs::hard_link(&q, &other).unwrap();
        }));
        assert_eq!(verified(&p, link), None);

        fresh();
        assert_eq!(
            verified(&p, None),
            Some(*blake3::hash(&body(3 << 20)).as_bytes())
        );
    }

    #[test]
    fn hash_verified_paced_stops_when_the_pacer_says_so() {
        let t = scratch();
        let p = t.0.join("f");
        std::fs::write(&p, body(VERIFY_BLOCK + 1)).unwrap();
        let f = File::open(&p).unwrap();
        let k1 = sys::stat_key(f.as_fd()).unwrap();
        assert_eq!(
            hash_verified_paced(f.as_fd(), &k1, &mut || false).unwrap(),
            None
        );
        let mut calls = 0;
        let h = hash_verified_paced(f.as_fd(), &k1, &mut || {
            calls += 1;
            true
        })
        .unwrap();
        assert_eq!(h, Some(*blake3::hash(&body(VERIFY_BLOCK + 1)).as_bytes()));
        assert!(calls >= 2, "the pacer is asked before every read");
    }

    #[test]
    fn pushed_hashes_are_split_to_fit_a_frame() {
        let item = |p: &str, v: Seq| (RelPath::new(p).unwrap(), v, [v as u8; 32]);
        let small: Vec<_> = (0..2 * BATCH_MAX as u64 + 5)
            .map(|i| item(&format!("d/f{i}"), i))
            .collect();
        let parts = hash_parts(small.clone());
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.len() <= BATCH_MAX));
        assert_eq!(parts.concat(), small);

        let long = vec!["x".repeat(250); 16].join("/");
        assert!(long.len() > 4_000);
        let heavy: Vec<_> = (0..2_000u64).map(|i| item(&long, i)).collect();
        let parts = hash_parts(heavy.clone());
        assert!(parts.len() > 1);
        for p in &parts {
            let bytes: usize = p.iter().map(|i| 48 + i.0.as_str().len()).sum();
            assert!(bytes <= PUSH_BYTES);
        }
        assert_eq!(parts.concat(), heavy);
        assert!(hash_parts(Vec::new()).is_empty());
    }

    fn make_pending(core: &Core, p: &str) -> (Seq, StatKey) {
        let mut t = core.tree();
        let path = RelPath::new(p).unwrap();
        let (mut meta, stat, domain) = {
            let e = t.get(&path).unwrap();
            (e.meta.clone(), e.stat, e.domain)
        };
        meta.hash = None;
        t.observe(&path, Observed::Present { meta, stat, domain });
        (t.get(&path).unwrap().seq, stat)
    }

    // fills every pending hash from the file's own bytes, the way the background hasher does
    fn learn_pending(core: &Core) {
        let mut jobs = Vec::new();
        let mut cursor = 0;
        loop {
            cursor = core
                .tree()
                .pending_from(cursor, usize::MAX, &|_, _| true, &mut jobs);
            if cursor == 0 {
                break;
            }
        }
        for j in jobs {
            let data = std::fs::read(core.root_path.join(j.path.as_str())).unwrap();
            core.learn_hash(&j.path, j.ver, &j.stat, *blake3::hash(&data).as_bytes());
        }
        assert_eq!(core.tree().pending(), 0);
    }

    fn drain(peer: &Session) -> Vec<Msg> {
        let mut out = Vec::new();
        while let Ok(i) = peer.inbox.recv_timeout(Duration::from_millis(400)) {
            if let In::Msg(m) = i {
                out.push(m);
            }
        }
        out
    }

    fn done_count(msgs: &[Msg]) -> usize {
        msgs.iter()
            .filter(|m| matches!(m, Msg::Push(Push::HashesDone { .. })))
            .count()
    }

    #[test]
    fn learn_hash_records_only_the_exact_version_and_pushes_it_to_live_guests() {
        let (_t, s, _jobs, peer) = session_with(|root| {
            std::fs::write(root.join("a.txt"), "alpha\n").unwrap();
        });
        lock(&s.g.feed).live = true;
        lock(&s.core.hub.guests).push(s.g.clone());
        let (ver, stat) = make_pending(&s.core, "a.txt");
        let a = RelPath::new("a.txt").unwrap();
        let seq = s.core.tree().seq();
        s.core.dirty.store(false, Ordering::Release);

        let other = StatKey {
            size: stat.size + 1,
            ..stat
        };
        s.core.learn_hash(&a, ver, &other, [1; 32]);
        s.core.learn_hash(&a, ver + 1, &stat, [1; 32]);
        assert!(s.core.tree().get(&a).unwrap().is_pending());
        assert!(!s.core.dirty.load(Ordering::Acquire));
        assert!(s.core.hashing.take(true).is_none());

        s.core.learn_hash(&a, ver, &stat, [2; 32]);
        assert_eq!(s.core.tree().get(&a).unwrap().meta.hash, Some([2; 32]));
        assert_eq!(s.core.tree().seq(), seq);
        assert!(s.core.dirty.load(Ordering::Acquire));

        s.core.flush_hashes(true);
        let index = s.core.tree().index_id();
        let msgs = drain(&peer);
        let pushed: Vec<_> = msgs
            .iter()
            .filter_map(|m| match m {
                Msg::Push(Push::Hashes { index: i, items }) => Some((*i, items.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(pushed, vec![(index, vec![(a, ver, [2; 32])])]);
    }

    #[test]
    fn a_guest_that_is_not_live_gets_no_pushed_hashes() {
        let (_t, s, _jobs, peer) = session_with(|root| {
            std::fs::write(root.join("a.txt"), "alpha\n").unwrap();
        });
        lock(&s.core.hub.guests).push(s.g.clone());
        let (ver, stat) = make_pending(&s.core, "a.txt");
        s.core
            .learn_hash(&RelPath::new("a.txt").unwrap(), ver, &stat, [2; 32]);
        s.core.hashes_done();
        assert!(drain(&peer).is_empty());
    }

    #[test]
    fn attaching_reports_done_only_while_nothing_is_pending() {
        let (_t, s, _jobs, peer) = session_with(|root| {
            std::fs::write(root.join("a.txt"), "alpha\n").unwrap();
        });
        assert_eq!(s.core.tree().pending(), 1);
        learn_pending(&s.core);
        assert!(s.core.attach(&s.g, None).is_ok());
        let msgs = drain(&peer);
        assert_eq!(done_count(&msgs), 1);
        assert!(matches!(
            msgs.last(),
            Some(Msg::Push(Push::HashesDone { .. }))
        ));

        let (_t, s, _jobs, peer) = session_with(|root| {
            std::fs::write(root.join("a.txt"), "alpha\n").unwrap();
        });
        let (ver, stat) = make_pending(&s.core, "a.txt");
        assert!(s.core.attach(&s.g, None).is_ok());
        let msgs = drain(&peer);
        assert!(
            msgs.iter()
                .any(|m| matches!(m, Msg::Push(Push::Snapshot { .. })))
        );
        assert_eq!(done_count(&msgs), 0);

        // once the hash is known, a guest that reconnects with the current seq is told at once
        s.core
            .learn_hash(&RelPath::new("a.txt").unwrap(), ver, &stat, [3; 32]);
        let index = s.core.tree().index_id();
        let have = Some((index, s.core.tree().seq()));
        lock(&s.core.hub.guests).clear();
        assert!(s.core.attach(&s.g, have).is_ok());
        assert_eq!(done_count(&drain(&peer)), 1);
    }

    #[test]
    fn catching_up_reports_done_only_while_nothing_is_pending() {
        let (_t, s, _jobs, peer) = session_with(|root| {
            std::fs::write(root.join("a.txt"), "alpha\n").unwrap();
        });
        learn_pending(&s.core);
        assert!(s.core.attach(&s.g, None).is_ok());
        drain(&peer);
        let (ver, stat) = make_pending(&s.core, "a.txt");
        let lag = |s: &SessionCtx, behind: Seq| {
            let sent = s.core.tree().seq() - behind;
            let mut f = lock(&s.g.feed);
            f.lagging = true;
            f.sent = sent;
        };
        lag(&s, 1);
        s.core.catch_up(&s.g);
        let msgs = drain(&peer);
        assert!(
            msgs.iter()
                .any(|m| matches!(m, Msg::Push(Push::Changes { .. })))
        );
        assert_eq!(done_count(&msgs), 0);

        s.core
            .learn_hash(&RelPath::new("a.txt").unwrap(), ver, &stat, [3; 32]);
        lag(&s, 1);
        s.core.catch_up(&s.g);
        assert_eq!(done_count(&drain(&peer)), 1);
    }

    #[test]
    fn a_lagging_guest_gets_its_dir_move_reply_after_the_backlog() {
        let (_t, s, _jobs, peer) = session_with(|root| {
            std::fs::create_dir_all(root.join("d1")).unwrap();
            std::fs::write(root.join("d1/a.txt"), "a\n").unwrap();
        });
        {
            let mut f = lock(&s.g.feed);
            f.live = true;
            f.lagging = true;
            f.sent = s.core.tree().seq();
        }
        lock(&s.core.hub.guests).push(s.g.clone());
        let rm = Op::Remove {
            path: RelPath::new("d1/a.txt").unwrap(),
            expect: Expect::Any,
        };
        assert!(commit::exec(&s.core, rm, commit::Payload::None, None).is_ok());
        let mv = Op::Rename {
            from: RelPath::new("d1").unwrap(),
            to: RelPath::new("m2").unwrap(),
            from_expect: Expect::Dir,
            to_expect: Expect::Absent,
            body: None,
        };
        let asker = commit::Asker::new(&s.g, 4);
        assert!(commit::exec(&s.core, mv, commit::Payload::None, Some(&asker)).is_ok());
        // the remove under the old path is still in the journal, so the reply must wait for it
        assert!(
            peer.inbox.recv_timeout(Duration::from_millis(200)).is_err(),
            "nothing may reach a lagging guest before its catch-up"
        );
        s.core.catch_up(&s.g);
        let mut removed = false;
        loop {
            match peer.inbox.recv_timeout(Duration::from_secs(2)) {
                Ok(In::Msg(Msg::Push(Push::Changes { changes, .. }))) => {
                    removed |= changes.iter().any(
                        |c| matches!(c, Change::Remove { path } if path.as_str() == "d1/a.txt"),
                    );
                }
                Ok(In::Msg(Msg::Resp { id: 4, res })) => {
                    assert!(matches!(res, Ok(Reply::Done { .. })), "{res:?}");
                    break;
                }
                Ok(_) => {}
                Err(e) => panic!("no reply after the catch-up: {e:?}"),
            }
        }
        assert!(removed, "the reply overtook the backlog");
    }
}
