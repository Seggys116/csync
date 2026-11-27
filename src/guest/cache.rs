use crate::delta;
use crate::index::persist;
use crate::net::conn::Out;
use crate::net::rpc::{ChunkSink, Rpc, RpcError};
use crate::proto::{
    BATCH_MAX, BlobItem, Body, Bytes, ChunkSig, DELTA_MIN, DeltaOp, FILE_MAX, Hash32, IndexId,
    Kind, Op, RANGE_FILE_MIN, RANGE_UNIT, RelPath, Reply, ReqId, Seq, VerKey, Version, Want,
    WireErr,
};
use crate::sys;
use rustc_hash::FxHashMap;
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use std::collections::BTreeMap;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

const CAP_MAX: u64 = 10 << 30;
const CAP_MIN: u64 = 64 << 20;
const RECENT_PIN: Duration = Duration::from_secs(15 * 60);
pub const WAIT: Duration = Duration::from_secs(5);
pub(crate) const DELTA_CAP: u64 = 32 << 20;
const IO_BUF: usize = 256 << 10;
const PAR_BUF: usize = 4 << 20;
const PAR_HASH_MIN: u64 = 1 << 20;
const AHEAD: u64 = 4;
const HINTS_MAX: usize = 1 << 16;
const EVICT_SCAN: usize = 1 << 14;
const UNIT: u64 = RANGE_UNIT as u64;
const LRU_FILE: &str = "lru.bin";
const HEX: &[u8; 16] = b"0123456789abcdef";
const LANDERS: usize = 4;
const LAND_SPLIT: usize = 16;
// one FetchMany reply is a single frame the host builds before sending, so a part stays small
const VER_PART_BYTES: u64 = 1 << 20;
const VER_PART_ITEMS: usize = 512;

pub type Done = Box<dyn FnOnce(Result<Reply, RpcError>) + Send>;

// the request surface the guest data path needs; Rpc is the real one, tests use fakes
pub trait Remote: Send + Sync {
    fn call(&self, op: Op, deadline: Instant) -> Result<Reply, RpcError>;
    fn call_stream(
        &self,
        op: Op,
        sink: Box<dyn ChunkSink>,
        deadline: Instant,
    ) -> Result<Reply, RpcError>;
    fn submit(&self, op: Op, done: Done) -> Result<ReqId, RpcError>;
    fn submit_stream(
        &self,
        op: Op,
        sink: Box<dyn ChunkSink>,
        done: Done,
    ) -> Result<ReqId, RpcError>;
    fn send_chunk(&self, id: ReqId, off: u64, last: bool, data: Vec<u8>) -> Result<(), RpcError>;
    fn cancel(&self, id: ReqId);
}

impl Remote for Rpc {
    fn call(&self, op: Op, deadline: Instant) -> Result<Reply, RpcError> {
        Rpc::call(self, op, deadline)
    }
    fn call_stream(
        &self,
        op: Op,
        sink: Box<dyn ChunkSink>,
        deadline: Instant,
    ) -> Result<Reply, RpcError> {
        Rpc::call_stream(self, op, sink, deadline)
    }
    fn submit(&self, op: Op, done: Done) -> Result<ReqId, RpcError> {
        Rpc::submit(self, op, done)
    }
    fn submit_stream(
        &self,
        op: Op,
        sink: Box<dyn ChunkSink>,
        done: Done,
    ) -> Result<ReqId, RpcError> {
        Rpc::submit_stream(self, op, sink, done)
    }
    fn send_chunk(&self, id: ReqId, off: u64, last: bool, data: Vec<u8>) -> Result<(), RpcError> {
        self.link()
            .send_out(Out::Chunk {
                id,
                off,
                last,
                data,
            })
            .map_err(|_| RpcError::Closed)
    }
    fn cancel(&self, id: ReqId) {
        Rpc::cancel(self, id)
    }
}

// the live connection, swapped on reconnect; the generation lets callers wait for a fresh one
#[derive(Default)]
pub struct RemoteSlot {
    cur: Mutex<Cur>,
    cv: Condvar,
}

#[derive(Default)]
struct Cur {
    generation: u64,
    link: Option<Arc<dyn Remote>>,
    // no newer link will come, so nobody waits for one
    closed: bool,
}

impl RemoteSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set(&self, r: Option<Arc<dyn Remote>>) {
        {
            let mut g = lock(&self.cur);
            g.generation = g.generation.wrapping_add(1);
            g.link = r;
        }
        self.cv.notify_all();
    }

    pub fn current(&self) -> Option<Arc<dyn Remote>> {
        lock(&self.cur).link.clone()
    }

    // the session is ending: the current link stays usable, waits for another one fail at once
    pub fn close(&self) {
        lock(&self.cur).closed = true;
        self.cv.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        lock(&self.cur).closed
    }

    pub fn get(&self, deadline: Instant) -> Result<(u64, Arc<dyn Remote>), i32> {
        self.wait(None, deadline)
    }

    pub fn newer(&self, gen_seen: u64, deadline: Instant) -> Result<(u64, Arc<dyn Remote>), i32> {
        self.wait(Some(gen_seen), deadline)
    }

    fn wait(&self, after: Option<u64>, deadline: Instant) -> Result<(u64, Arc<dyn Remote>), i32> {
        let mut g = lock(&self.cur);
        loop {
            if after != Some(g.generation)
                && let Some(r) = &g.link
            {
                return Ok((g.generation, r.clone()));
            }
            if g.closed {
                return Err(libc::EIO);
            }
            let (ng, alive) = wait_until(&self.cv, g, deadline);
            g = ng;
            if !alive {
                return Err(libc::EIO);
            }
        }
    }
}

pub fn wire_errno(e: WireErr) -> i32 {
    match e {
        WireErr::NotFound => libc::ENOENT,
        WireErr::Exists => libc::EEXIST,
        WireErr::NotEmpty => libc::ENOTEMPTY,
        WireErr::NotDir => libc::ENOTDIR,
        WireErr::IsDir => libc::EISDIR,
        WireErr::ReadOnly => libc::EROFS,
        WireErr::Ignored => libc::EPERM,
        WireErr::Invalid => libc::EINVAL,
        WireErr::TooLarge => libc::EFBIG,
        WireErr::Busy => libc::EBUSY,
        WireErr::Io => libc::EIO,
        WireErr::Denied => libc::EACCES,
        WireErr::Gone => libc::ESTALE,
    }
}

pub fn rpc_errno(e: &RpcError) -> i32 {
    match e {
        RpcError::Wire(w) => wire_errno(*w),
        RpcError::Closed | RpcError::Timeout => libc::EIO,
        RpcError::Busy => libc::EAGAIN,
    }
}

pub(crate) fn io_errno(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn os(e: Errno) -> i32 {
    e.raw_os_error()
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// the bool is false once the deadline has passed
fn wait_until<'a, T>(
    cv: &Condvar,
    g: MutexGuard<'a, T>,
    deadline: Instant,
) -> (MutexGuard<'a, T>, bool) {
    let now = Instant::now();
    if now >= deadline {
        return (g, false);
    }
    let g = match cv.wait_timeout(g, deadline - now) {
        Ok((g, _)) => g,
        Err(e) => e.into_inner().0,
    };
    (g, Instant::now() < deadline)
}

pub(crate) fn pwrite_all(fd: BorrowedFd<'_>, mut data: &[u8], mut off: u64) -> io::Result<()> {
    while !data.is_empty() {
        match rustix::io::pwrite(fd, data, off) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                data = data.get(n..).unwrap_or_default();
                off += n as u64;
            }
            Err(Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(crate) fn pread_full(fd: BorrowedFd<'_>, buf: &mut [u8], off: u64) -> io::Result<usize> {
    let mut n = 0;
    while let Some(rest) = buf.get_mut(n..).filter(|r| !r.is_empty()) {
        match rustix::io::pread(fd, rest, off + n as u64) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}

pub(crate) fn read_len(fd: BorrowedFd<'_>, len: u64, cap: u64) -> Result<Vec<u8>, i32> {
    if len > cap {
        return Err(libc::EFBIG);
    }
    let n = usize::try_from(len).map_err(|_| libc::EFBIG)?;
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| libc::ENOMEM)?;
    v.resize(n, 0);
    if pread_full(fd, &mut v, 0).map_err(|e| io_errno(&e))? != n {
        return Err(libc::EIO);
    }
    Ok(v)
}

pub(crate) fn hash_fd(fd: BorrowedFd<'_>, len: u64) -> Result<Hash32, i32> {
    let mut h = blake3::Hasher::new();
    // big blobs are hashed on all cores; below the cutoff threading costs more than it saves
    let par = len >= PAR_HASH_MIN;
    let cap = if par { PAR_BUF } else { IO_BUF };
    let mut buf = vec![0u8; usize::try_from(len).unwrap_or(cap).clamp(1, cap)];
    let mut off = 0u64;
    while off < len {
        let want = (buf.len() as u64).min(len - off) as usize;
        let b = buf.get_mut(..want).ok_or(libc::EIO)?;
        if pread_full(fd, b, off).map_err(|e| io_errno(&e))? != want {
            return Err(libc::EIO);
        }
        if par {
            h.update_rayon(b);
        } else {
            h.update(b);
        }
        off += want as u64;
    }
    Ok(*h.finalize().as_bytes())
}

fn copy_range(
    src: BorrowedFd<'_>,
    mut at: u64,
    dst: BorrowedFd<'_>,
    mut to: u64,
    mut len: u64,
    buf: &mut [u8],
) -> Result<(), i32> {
    while len > 0 {
        let n = (buf.len() as u64).min(len) as usize;
        let b = buf.get_mut(..n).ok_or(libc::EIO)?;
        if pread_full(src, b, at).map_err(|e| io_errno(&e))? != n {
            return Err(libc::EIO);
        }
        pwrite_all(dst, b, to).map_err(|e| io_errno(&e))?;
        at += n as u64;
        to += n as u64;
        len -= n as u64;
    }
    Ok(())
}

// rebuilds a delta target from the base blob and the literal bytes that streamed into `lit`
fn apply_files(
    old: BorrowedFd<'_>,
    lit: BorrowedFd<'_>,
    out: BorrowedFd<'_>,
    ops: &[DeltaOp],
) -> Result<(), i32> {
    let mut buf = vec![0u8; IO_BUF];
    let (mut pos, mut loff) = (0u64, 0u64);
    for op in ops {
        let (src, at, len) = match *op {
            DeltaOp::Copy { off, len } => (old, off, u64::from(len)),
            DeltaOp::Data { len } => {
                let at = loff;
                loff += u64::from(len);
                (lit, at, u64::from(len))
            }
        };
        copy_range(src, at, out, pos, len, &mut buf)?;
        pos += len;
    }
    Ok(())
}

fn empty_hash() -> Hash32 {
    *blake3::hash(&[]).as_bytes()
}

fn fill_deadline(size: u64) -> Instant {
    Instant::now() + Duration::from_secs(30) + Duration::from_millis(size >> 12)
}

fn hex(h: &Hash32) -> [u8; 64] {
    let mut o = [0u8; 64];
    for ([hi, lo], b) in o.as_chunks_mut::<2>().0.iter_mut().zip(h) {
        *hi = HEX[usize::from(b >> 4)];
        *lo = HEX[usize::from(b & 15)];
    }
    o
}

fn hex_str(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap_or("")
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn unhex(s: &[u8]) -> Option<Hash32> {
    if s.len() != 64 {
        return None;
    }
    let mut h = [0u8; 32];
    for (o, [a, b]) in h.iter_mut().zip(s.as_chunks::<2>().0) {
        *o = (nibble(*a)? << 4) | nibble(*b)?;
    }
    Some(h)
}

fn bit(v: &[u64], i: u64) -> bool {
    v.get((i / 64) as usize)
        .is_some_and(|w| (w >> (i % 64)) & 1 == 1)
}

fn set_bit(v: &mut [u64], i: u64, on: bool) {
    if let Some(w) = v.get_mut((i / 64) as usize) {
        if on {
            *w |= 1 << (i % 64);
        } else {
            *w &= !(1 << (i % 64));
        }
    }
}

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub dir: PathBuf,
    pub cap: Option<u64>,
}

// foreground fetch counter; the prefetch thread parks on it while any foreground fetch runs
#[derive(Default)]
pub struct Gate {
    st: Mutex<(usize, bool)>,
    cv: Condvar,
    waker: OnceLock<Box<dyn Fn() + Send + Sync>>,
}

pub struct GateGuard<'a>(&'a Gate);

impl Gate {
    pub fn enter(&self) -> GateGuard<'_> {
        lock(&self.st).0 += 1;
        GateGuard(self)
    }

    pub fn busy(&self) -> bool {
        lock(&self.st).0 > 0
    }

    // called once the gate goes idle after a failed idle_or_arm
    pub fn set_waker(&self, f: Box<dyn Fn() + Send + Sync>) {
        let _ = self.waker.set(f);
    }

    pub fn idle_or_arm(&self) -> bool {
        let mut g = lock(&self.st);
        if g.0 == 0 {
            return true;
        }
        g.1 = true;
        false
    }

    pub fn wait_idle(&self) {
        let mut g = lock(&self.st);
        while g.0 > 0 {
            g.1 = true;
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        g.1 = false;
    }
}

impl Drop for GateGuard<'_> {
    fn drop(&mut self) {
        let mut g = lock(&self.0.st);
        g.0 = g.0.saturating_sub(1);
        if g.0 == 0 && g.1 {
            g.1 = false;
            drop(g);
            self.0.cv.notify_all();
            if let Some(w) = self.0.waker.get() {
                w();
            }
        }
    }
}

// a file in tmp/ that is unlinked on drop unless it was published
pub struct TmpBlob {
    dir: Arc<OwnedFd>,
    name: String,
    fd: Arc<OwnedFd>,
    ver: Option<Version>,
    live: bool,
    // a writer's staging file read in place: it is sent from but never published
    borrowed: bool,
}

impl TmpBlob {
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn is_borrowed(&self) -> bool {
        self.borrowed
    }

    pub fn version(&self) -> Option<Version> {
        self.ver
    }
}

impl Drop for TmpBlob {
    fn drop(&mut self) {
        if self.live {
            let _ = rustix::fs::unlinkat(&*self.dir, self.name.as_str(), AtFlags::empty());
        }
    }
}

struct Slot {
    size: u64,
    // blobs found on disk at startup are hashed once before first use; ones landed this run were verified already
    checked: bool,
    used: u64,
    path: Option<RelPath>,
    opened: Option<Instant>,
    fd: Weak<OwnedFd>,
}

#[derive(Default)]
struct Progress {
    got: AtomicU64,
    hash: Mutex<Option<Hash32>>,
}

impl Progress {
    fn got(&self) -> u64 {
        self.got.load(Ordering::Acquire)
    }
}

struct Ranges {
    have: Vec<u64>,
    req: Vec<u64>,
    n: u64,
    have_n: u64,
    err: Option<i32>,
    verifying: bool,
}

#[derive(Default)]
struct FillState {
    mark: u64,
    done: Option<Result<(), i32>>,
    waiting: u32,
    ranges: Option<Ranges>,
}

struct Fill {
    h: Hash32,
    path: RelPath,
    size: u64,
    // none for a batch fill: its verified bytes are written straight to the final name
    fd: Option<Arc<OwnedFd>>,
    tmp: Mutex<Option<TmpBlob>>,
    st: Mutex<FillState>,
    cv: Condvar,
    batch: bool,
}

impl Fill {
    fn fd(&self) -> Result<BorrowedFd<'_>, i32> {
        self.fd.as_deref().map(AsFd::as_fd).ok_or(libc::EIO)
    }
}

enum Join {
    Cached,
    Wait(Arc<Fill>),
    Lead(Arc<Fill>),
}

#[derive(Default)]
struct Inner {
    slots: FxHashMap<Hash32, Slot>,
    lru: BTreeMap<u64, Hash32>,
    pins: FxHashMap<Hash32, u32>,
    fills: FxHashMap<Hash32, Arc<Fill>>,
    hints: FxHashMap<Hash32, (RelPath, u64)>,
    recent: FxHashMap<RelPath, Hash32>,
    bytes: u64,
    tick: u64,
    dirty: bool,
}

impl Inner {
    fn touch(&mut self, h: &Hash32) {
        self.tick += 1;
        let t = self.tick;
        if let Some(s) = self.slots.get_mut(h) {
            let old = std::mem::replace(&mut s.used, t);
            self.lru.remove(&old);
            self.lru.insert(t, *h);
            self.dirty = true;
        }
    }

    fn add(&mut self, h: Hash32, size: u64, path: Option<RelPath>) {
        self.hints.remove(&h);
        if let Some(p) = &path {
            self.recent.insert(p.clone(), h);
        }
        if let Some(s) = self.slots.get_mut(&h) {
            if path.is_some() {
                s.path = path;
            }
            self.touch(&h);
            return;
        }
        self.tick += 1;
        self.lru.insert(self.tick, h);
        self.slots.insert(
            h,
            Slot {
                size,
                checked: true,
                used: self.tick,
                path,
                opened: None,
                fd: Weak::new(),
            },
        );
        self.bytes = self.bytes.saturating_add(size);
        self.dirty = true;
    }

    fn remove(&mut self, h: &Hash32) -> Option<Slot> {
        let s = self.slots.remove(h)?;
        self.lru.remove(&s.used);
        self.bytes = self.bytes.saturating_sub(s.size);
        if let Some(p) = &s.path
            && self.recent.get(p) == Some(h)
        {
            self.recent.remove(p);
        }
        self.dirty = true;
        Some(s)
    }

    fn pin(&mut self, h: &Hash32) {
        *self.pins.entry(*h).or_insert(0) += 1;
    }

    fn unpin(&mut self, h: &Hash32) {
        if let Some(n) = self.pins.get_mut(h) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.pins.remove(h);
            }
        }
    }
}

struct Shared {
    dir: PathBuf,
    _root: OwnedFd,
    tmp: Arc<OwnedFd>,
    shards: Vec<OwnedFd>,
    cap: u64,
    inner: Mutex<Inner>,
    remote: Arc<RemoteSlot>,
    gate: Gate,
    names: AtomicU64,
    pid: u32,
}

// writes streamed bytes at its own running offset, so absolute and range-relative chunk offsets both land right
struct FillSink {
    fill: Arc<Fill>,
    p: Arc<Progress>,
    base: u64,
    limit: u64,
    got: u64,
    marks: bool,
    hasher: Option<Box<blake3::Hasher>>,
}

impl FillSink {
    fn new(
        fill: Arc<Fill>,
        p: Arc<Progress>,
        base: u64,
        limit: u64,
        marks: bool,
        hash: bool,
    ) -> Self {
        Self {
            fill,
            p,
            base,
            limit,
            got: 0,
            marks,
            hasher: hash.then(|| Box::new(blake3::Hasher::new())),
        }
    }
}

impl ChunkSink for FillSink {
    fn chunk(&mut self, _off: u64, data: &[u8], last: bool) -> io::Result<()> {
        let end = self
            .got
            .checked_add(data.len() as u64)
            .filter(|&e| e <= self.limit)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let fd = self.fill.fd().map_err(io::Error::from_raw_os_error)?;
        pwrite_all(fd, data, self.base + self.got)?;
        if let Some(h) = self.hasher.as_mut() {
            h.update(data);
        }
        self.got = end;
        self.p.got.store(end, Ordering::Release);
        if last && let Some(h) = self.hasher.take() {
            *lock(&self.p.hash) = Some(*h.finalize().as_bytes());
        }
        if self.marks {
            let mut st = lock(&self.fill.st);
            st.mark = self.base + end;
            let wake = st.waiting > 0;
            drop(st);
            if wake {
                self.fill.cv.notify_all();
            }
        }
        Ok(())
    }
}

impl Shared {
    fn shard(&self, h: &Hash32) -> Result<&OwnedFd, i32> {
        self.shards.get(usize::from(h[0])).ok_or(libc::EIO)
    }

    fn tmp_name(&self) -> String {
        let n = self.names.fetch_add(1, Ordering::Relaxed);
        format!("{:x}-{n:x}", self.pid)
    }

    fn new_tmp(&self) -> Result<TmpBlob, i32> {
        let name = self.tmp_name();
        let fd = rustix::fs::openat(
            &*self.tmp,
            name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(os)?;
        Ok(TmpBlob {
            dir: self.tmp.clone(),
            name,
            fd: Arc::new(fd),
            ver: None,
            live: true,
            borrowed: false,
        })
    }

    fn borrow(&self, fd: Arc<OwnedFd>, v: Version) -> TmpBlob {
        TmpBlob {
            dir: self.tmp.clone(),
            name: String::new(),
            fd,
            ver: Some(v),
            live: false,
            borrowed: true,
        }
    }

    // a released staging file holding v becomes the blob; one that cannot be linked is copied
    fn adopt(&self, fd: BorrowedFd<'_>, v: Version, path: Option<&RelPath>) -> Result<(), i32> {
        if lock(&self.inner).slots.contains_key(&v.hash) {
            lock(&self.inner).add(v.hash, v.size, path.cloned());
            return Ok(());
        }
        let name = self.tmp_name();
        #[cfg(target_os = "linux")]
        let linked = {
            let proc = format!("/proc/self/fd/{}", fd.as_raw_fd());
            rustix::fs::linkat(
                rustix::fs::CWD,
                proc.as_str(),
                &*self.tmp,
                name.as_str(),
                AtFlags::SYMLINK_FOLLOW,
            )
        };
        // the staging file is anonymous here, so a copy-on-write clone stands in for linking it
        #[cfg(target_os = "macos")]
        let linked = sys::fs_unix::clone_fd_at(fd, self.tmp.as_fd(), name.as_str());
        let t = match linked {
            Ok(()) => {
                let own = rustix::fs::openat(
                    &*self.tmp,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                );
                let mut t = TmpBlob {
                    dir: self.tmp.clone(),
                    name,
                    fd: Arc::new(own.map_err(os)?),
                    ver: Some(v),
                    live: true,
                    borrowed: false,
                };
                if sys::stat_key(t.fd.as_fd()).map_err(|e| io_errno(&e))?.size != v.size {
                    t.ver = None;
                    return Err(libc::EIO);
                }
                t
            }
            Err(_) => {
                let mut t = self.new_tmp()?;
                sys::clone_or_copy(fd, t.fd.as_fd()).map_err(|e| io_errno(&e))?;
                t.ver = Some(v);
                t
            }
        };
        self.publish_tmp(t, path)
    }

    fn open_blob(&self, h: &Hash32) -> Result<OwnedFd, i32> {
        let name = hex(h);
        rustix::fs::openat(
            self.shard(h)?,
            hex_str(&name),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(os)
    }

    fn rename_in(&self, t: &mut TmpBlob, h: &Hash32) -> Result<(), i32> {
        let name = hex(h);
        rustix::fs::renameat(&*self.tmp, t.name.as_str(), self.shard(h)?, hex_str(&name))
            .map_err(os)?;
        t.live = false;
        Ok(())
    }

    fn unpin(&self, h: &Hash32) {
        lock(&self.inner).unpin(h);
    }

    fn get(self: &Arc<Self>, h: &Hash32) -> Option<BlobRef> {
        let (size, fd, checked) = {
            let mut guard = lock(&self.inner);
            let g = &mut *guard;
            let slot = g.slots.get(h)?;
            let found = (slot.size, slot.fd.upgrade(), slot.checked);
            g.touch(h);
            g.pin(h);
            found
        };
        let fd = match fd {
            Some(f) => f,
            None => match self.open_blob(h) {
                Ok(f) => {
                    let f = Arc::new(f);
                    if let Some(s) = lock(&self.inner).slots.get_mut(h) {
                        s.fd = Arc::downgrade(&f);
                    }
                    f
                }
                Err(_) => {
                    let mut g = lock(&self.inner);
                    g.unpin(h);
                    g.remove(h);
                    return None;
                }
            },
        };
        if !checked {
            // a torn or tampered blob is dropped so the caller fetches it again
            if hash_fd(fd.as_fd(), size).ok() != Some(*h) {
                let mut g = lock(&self.inner);
                g.unpin(h);
                if g.slots.get(h).is_some_and(|s| !s.checked) {
                    g.remove(h);
                    drop(g);
                    let name = hex(h);
                    if let Ok(dir) = self.shard(h) {
                        let _ = rustix::fs::unlinkat(dir, hex_str(&name), AtFlags::empty());
                    }
                }
                return None;
            }
            if let Some(s) = lock(&self.inner).slots.get_mut(h) {
                s.checked = true;
            }
        }
        Some(BlobRef {
            s: self.clone(),
            h: *h,
            size,
            fd,
            complete: true,
        })
    }

    fn publish_tmp(&self, mut t: TmpBlob, path: Option<&RelPath>) -> Result<(), i32> {
        if t.borrowed {
            return Err(libc::EINVAL);
        }
        let v = t.ver.ok_or(libc::EINVAL)?;
        if !lock(&self.inner).slots.contains_key(&v.hash) {
            self.rename_in(&mut t, &v.hash)?;
        }
        lock(&self.inner).add(v.hash, v.size, path.cloned());
        Ok(())
    }

    fn insert_bytes(&self, h: &Hash32, data: &[u8], path: Option<&RelPath>) -> Result<(), i32> {
        if data.len() as u64 > FILE_MAX {
            return Err(libc::EFBIG);
        }
        if blake3::hash(data).as_bytes() != h {
            return Err(libc::EIO);
        }
        if lock(&self.inner).slots.contains_key(h) {
            return Ok(());
        }
        let mut t = self.new_tmp()?;
        pwrite_all(t.fd.as_fd(), data, 0).map_err(|e| io_errno(&e))?;
        t.ver = Some(Version {
            hash: *h,
            size: data.len() as u64,
        });
        self.publish_tmp(t, path)
    }

    // one request on the live link, repeated once on a fresh link if the first one dropped; Gone is ESTALE, anything else EIO
    fn call(&self, op: Op, deadline: Instant) -> Result<Reply, i32> {
        let (mut gen_seen, mut remote) = self.remote.get(deadline)?;
        let mut retried = false;
        loop {
            match remote.call(op.clone(), deadline) {
                Ok(reply) => return Ok(reply),
                Err(RpcError::Closed) if !retried => {
                    retried = true;
                    (gen_seen, remote) = self.remote.newer(gen_seen, deadline)?;
                }
                Err(RpcError::Wire(WireErr::Gone)) => return Err(libc::ESTALE),
                Err(_) => return Err(libc::EIO),
            }
        }
    }

    // stores the bytes of a version-addressed reply only if they hash to what the host claims
    fn land_ver(
        &self,
        path: &RelPath,
        key: &VerKey,
        r: Result<(Hash32, Bytes), WireErr>,
    ) -> Result<Version, i32> {
        let (hash, bytes) = r.map_err(wire_errno)?;
        if bytes.0.len() as u64 != key.size {
            return Err(libc::EIO);
        }
        self.insert_bytes(&hash, &bytes.0, Some(path))?;
        Ok(Version {
            hash,
            size: key.size,
        })
    }

    // one FetchMany for a part; the host may answer only a prefix when the reply frame fills up
    fn many_ver(
        &self,
        part: &[(RelPath, VerKey)],
        deadline: Instant,
    ) -> Result<Vec<Result<Version, i32>>, i32> {
        let op = Op::FetchMany {
            items: part
                .iter()
                .map(|(p, k)| (p.clone(), Want::Ver(*k)))
                .collect(),
        };
        let Reply::Blobs { items } = self.call(op, deadline)? else {
            return Err(libc::EIO);
        };
        if items.len() > part.len() {
            return Err(libc::EIO);
        }
        Ok(part
            .iter()
            .zip(items)
            .map(|((path, key), (got, r))| {
                if got != *path {
                    return Err(libc::EIO);
                }
                self.land_ver(path, key, r)
            })
            .collect())
    }

    fn tmp_from_bytes(&self, data: &[u8]) -> Result<(TmpBlob, Version), i32> {
        if data.len() as u64 > FILE_MAX {
            return Err(libc::EFBIG);
        }
        let mut t = self.new_tmp()?;
        pwrite_all(t.fd.as_fd(), data, 0).map_err(|e| io_errno(&e))?;
        let v = Version {
            hash: *blake3::hash(data).as_bytes(),
            size: data.len() as u64,
        };
        t.ver = Some(v);
        Ok((t, v))
    }

    // the hash is taken from the written copy, so what gets published is exactly what was verified
    fn snapshot(&self, src: BorrowedFd<'_>) -> Result<(TmpBlob, Version), i32> {
        let mut t = self.copy_tmp(src)?;
        let size = sys::stat_key(t.fd.as_fd()).map_err(|e| io_errno(&e))?.size;
        if size > FILE_MAX {
            return Err(libc::EFBIG);
        }
        let v = Version {
            hash: hash_fd(t.fd.as_fd(), size)?,
            size,
        };
        t.ver = Some(v);
        Ok((t, v))
    }

    // a private writable copy of src in tmp/, cloned copy-on-write where the filesystem can
    fn copy_tmp(&self, src: BorrowedFd<'_>) -> Result<TmpBlob, i32> {
        #[cfg(target_os = "macos")]
        {
            if let Some(t) = self.clone_tmp(src) {
                return Ok(t);
            }
        }
        let t = self.new_tmp()?;
        sys::clone_or_copy(src, t.fd.as_fd()).map_err(|e| io_errno(&e))?;
        Ok(t)
    }

    // an open fd cannot be the target of a clone, so macos clones into a new name and opens that
    #[cfg(target_os = "macos")]
    fn clone_tmp(&self, src: BorrowedFd<'_>) -> Option<TmpBlob> {
        let name = self.tmp_name();
        sys::fs_unix::clone_fd_at(src, self.tmp.as_fd(), name.as_str()).ok()?;
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match rustix::fs::openat(&*self.tmp, name.as_str(), flags, Mode::empty()) {
            Ok(fd) => Some(TmpBlob {
                dir: self.tmp.clone(),
                name,
                fd: Arc::new(fd),
                ver: None,
                live: true,
                borrowed: false,
            }),
            Err(_) => {
                let _ = rustix::fs::unlinkat(&*self.tmp, name.as_str(), AtFlags::empty());
                None
            }
        }
    }

    // an anonymous staging file already holding the bytes of base
    fn staging_from(&self, base: BorrowedFd<'_>) -> Result<OwnedFd, i32> {
        #[cfg(target_os = "macos")]
        {
            if let Some(t) = self.clone_tmp(base) {
                let fd = t.fd.clone();
                drop(t);
                if let Ok(fd) = Arc::try_unwrap(fd) {
                    return Ok(fd);
                }
            }
        }
        let fd = self.staging()?;
        sys::clone_or_copy(base, fd.as_fd()).map_err(|e| io_errno(&e))?;
        Ok(fd)
    }

    fn staging(&self) -> Result<OwnedFd, i32> {
        let mode = Mode::from_bits_truncate(0o600);
        #[cfg(target_os = "linux")]
        {
            match rustix::fs::openat(
                &*self.tmp,
                ".",
                OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
                mode,
            ) {
                Ok(fd) => Ok(fd),
                Err(Errno::OPNOTSUPP | Errno::ISDIR | Errno::INVAL | Errno::NOENT) => {
                    self.staging_unlinked(mode)
                }
                Err(e) => Err(os(e)),
            }
        }
        // macos has no tmpfile open
        #[cfg(not(target_os = "linux"))]
        {
            self.staging_unlinked(mode)
        }
    }

    fn staging_unlinked(&self, mode: Mode) -> Result<OwnedFd, i32> {
        let name = format!(
            "s{:x}-{:x}",
            self.pid,
            self.names.fetch_add(1, Ordering::Relaxed)
        );
        let flags =
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = rustix::fs::openat(&*self.tmp, name.as_str(), flags, mode).map_err(os)?;
        rustix::fs::unlinkat(&*self.tmp, name.as_str(), AtFlags::empty()).map_err(os)?;
        Ok(fd)
    }

    fn join(self: &Arc<Self>, h: &Hash32) -> Result<Join, i32> {
        let (path, size) = {
            let mut g = lock(&self.inner);
            if g.slots.contains_key(h) {
                return Ok(Join::Cached);
            }
            if let Some(f) = g.fills.get(h).cloned() {
                g.pin(h);
                return Ok(Join::Wait(f));
            }
            g.hints.get(h).cloned().ok_or(libc::EIO)?
        };
        if size > FILE_MAX {
            return Err(libc::EFBIG);
        }
        let tmp = self.new_tmp()?;
        let mut st = FillState::default();
        if size >= RANGE_FILE_MIN {
            rustix::fs::ftruncate(&*tmp.fd, size).map_err(os)?;
            let n = size.div_ceil(UNIT);
            let words = usize::try_from(n.div_ceil(64)).map_err(|_| libc::EFBIG)?;
            st.ranges = Some(Ranges {
                have: vec![0; words],
                req: vec![0; words],
                n,
                have_n: 0,
                err: None,
                verifying: false,
            });
        }
        let fill = Arc::new(Fill {
            h: *h,
            path,
            size,
            fd: Some(tmp.fd.clone()),
            tmp: Mutex::new(Some(tmp)),
            st: Mutex::new(st),
            cv: Condvar::new(),
            batch: false,
        });
        let mut g = lock(&self.inner);
        if g.slots.contains_key(h) {
            return Ok(Join::Cached);
        }
        if let Some(f) = g.fills.get(h).cloned() {
            g.pin(h);
            return Ok(Join::Wait(f));
        }
        g.fills.insert(*h, fill.clone());
        g.pin(h);
        Ok(Join::Lead(fill))
    }

    fn fetch(
        self: &Arc<Self>,
        h: &Hash32,
        off: u64,
        len: u32,
        whole: bool,
        deadline: Instant,
    ) -> Result<BlobRef, i32> {
        loop {
            if let Some(r) = self.get(h) {
                return Ok(r);
            }
            let _busy = self.gate.enter();
            let fill = match self.join(h)? {
                Join::Cached => continue,
                Join::Wait(f) => f,
                Join::Lead(f) => {
                    self.evict();
                    self.start(&f, deadline);
                    f
                }
            };
            return match self.wait_fill(&fill, off, len, whole, deadline) {
                Ok(true) => {
                    let r = self.get(h).ok_or(libc::EIO);
                    self.unpin(h);
                    r
                }
                Ok(false) => match fill.fd.clone() {
                    Some(fd) => Ok(BlobRef {
                        s: self.clone(),
                        h: *h,
                        size: fill.size,
                        fd,
                        complete: false,
                    }),
                    None => {
                        self.unpin(h);
                        Err(libc::EIO)
                    }
                },
                Err(e) => {
                    self.unpin(h);
                    // a failed prefetch batch is not this reader's failure: fetch on its own
                    if fill.batch && Instant::now() < deadline {
                        continue;
                    }
                    Err(e)
                }
            };
        }
    }

    fn begin_batch(&self, items: &[(RelPath, Hash32, u64)]) -> Vec<Arc<Fill>> {
        let mut out = Vec::with_capacity(items.len());
        let mut g = lock(&self.inner);
        for (path, h, size) in items {
            if *size == 0
                || *size >= RANGE_FILE_MIN
                || g.slots.contains_key(h)
                || g.fills.contains_key(h)
            {
                continue;
            }
            let fill = Arc::new(Fill {
                h: *h,
                path: path.clone(),
                size: *size,
                fd: None,
                tmp: Mutex::new(None),
                st: Mutex::new(FillState::default()),
                cv: Condvar::new(),
                batch: true,
            });
            g.fills.insert(*h, fill.clone());
            out.push(fill);
        }
        out
    }

    // never lets bytes reach blobs/ unless they hash to what the fill was registered for
    fn land_one(&self, fill: &Arc<Fill>, data: &[u8]) -> bool {
        let r = if data.len() as u64 != fill.size || blake3::hash(data).as_bytes() != &fill.h {
            Err(libc::EIO)
        } else {
            self.write_final(&fill.h, data)
        };
        self.complete(fill, r);
        lock(&fill.st).done == Some(Ok(()))
    }

    // verified bytes go straight to the final name: a torn file left by a crash fails the startup size or hash check
    fn write_final(&self, h: &Hash32, data: &[u8]) -> Result<(), i32> {
        let name = hex(h);
        let dir = self.shard(h)?;
        let create = || {
            rustix::fs::openat(
                dir,
                hex_str(&name),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
        };
        let fd = match create() {
            Ok(fd) => fd,
            Err(Errno::EXIST) => {
                if lock(&self.inner).slots.contains_key(h) {
                    return Ok(());
                }
                // only one fill per hash runs, so a name nobody published is a leftover
                let _ = rustix::fs::unlinkat(dir, hex_str(&name), AtFlags::empty());
                create().map_err(os)?
            }
            Err(e) => return Err(os(e)),
        };
        if let Err(e) = pwrite_all(fd.as_fd(), data, 0) {
            drop(fd);
            let _ = rustix::fs::unlinkat(dir, hex_str(&name), AtFlags::empty());
            return Err(io_errno(&e));
        }
        Ok(())
    }

    fn start(self: &Arc<Self>, fill: &Arc<Fill>, deadline: Instant) {
        if fill.size == 0 {
            let r = if fill.h == empty_hash() {
                Ok(())
            } else {
                Err(libc::EIO)
            };
            return self.complete(fill, r);
        }
        if fill.size >= RANGE_FILE_MIN {
            return;
        }
        if let Some(old) = self.delta_base(fill) {
            let r = self.fetch_delta(fill, &old, deadline);
            return self.complete(fill, r);
        }
        self.fetch_stream(fill, deadline);
    }

    fn delta_base(self: &Arc<Self>, fill: &Fill) -> Option<BlobRef> {
        if fill.size < DELTA_MIN || fill.size > DELTA_CAP {
            return None;
        }
        let old = {
            let g = lock(&self.inner);
            let o = *g.recent.get(&fill.path)?;
            let s = g.slots.get(&o)?;
            (o != fill.h && s.size > 0 && s.size <= DELTA_CAP).then_some(o)?
        };
        self.get(&old)
    }

    fn fetch_delta(
        self: &Arc<Self>,
        fill: &Arc<Fill>,
        old: &BlobRef,
        deadline: Instant,
    ) -> Result<(), i32> {
        let have = delta::sigs(&old.read_all(DELTA_CAP)?);
        if have.is_empty() {
            return self.fetch_blocking(fill, None, deadline);
        }
        self.fetch_blocking(fill, Some((have, old)), deadline)
    }

    // runs on the calling thread; used for delta fetches and when the in-flight table is full
    fn fetch_blocking(
        self: &Arc<Self>,
        fill: &Arc<Fill>,
        have: Option<(Vec<ChunkSig>, &BlobRef)>,
        deadline: Instant,
    ) -> Result<(), i32> {
        let long = deadline.max(fill_deadline(fill.size));
        let (mut sigs, old) = match have {
            Some((s, o)) => (Some(s), Some(o)),
            None => (None, None),
        };
        let marks = old.is_none();
        let (mut gen_seen, mut remote) = self.remote.get(deadline)?;
        let mut retried = false;
        loop {
            let p = Arc::new(Progress::default());
            let sink = Box::new(FillSink::new(
                fill.clone(),
                p.clone(),
                0,
                fill.size,
                marks,
                true,
            ));
            let op = Op::Fetch {
                path: fill.path.clone(),
                want: Some(Want::Hash(fill.h)),
                have: sigs.take(),
                range: None,
            };
            match remote.call_stream(op, sink, long) {
                Ok(reply) => return self.land(fill, &p, reply, old),
                Err(RpcError::Closed) if !retried => {
                    retried = true;
                    (gen_seen, remote) = self.remote.newer(gen_seen, deadline)?;
                }
                Err(e) => return Err(rpc_errno(&e)),
            }
        }
    }

    fn fetch_stream(self: &Arc<Self>, fill: &Arc<Fill>, deadline: Instant) {
        let mut cur = match self.remote.get(deadline) {
            Ok(r) => r,
            Err(e) => return self.complete(fill, Err(e)),
        };
        let mut retried = false;
        loop {
            let (gen_seen, remote) = cur;
            let p = Arc::new(Progress::default());
            let sink = Box::new(FillSink::new(
                fill.clone(),
                p.clone(),
                0,
                fill.size,
                true,
                true,
            ));
            let op = Op::Fetch {
                path: fill.path.clone(),
                want: Some(Want::Hash(fill.h)),
                have: None,
                range: None,
            };
            let (s, f) = (self.clone(), fill.clone());
            let done: Done = Box::new(move |r: Result<Reply, RpcError>| {
                let r = r
                    .map_err(|e| rpc_errno(&e))
                    .and_then(|reply| s.land(&f, &p, reply, None));
                s.complete(&f, r);
            });
            match remote.submit_stream(op, sink, done) {
                Ok(_) => return,
                Err(RpcError::Busy) => {
                    let r = self.fetch_blocking(fill, None, deadline);
                    return self.complete(fill, r);
                }
                Err(RpcError::Closed) if !retried => {
                    retried = true;
                    match self.remote.newer(gen_seen, deadline) {
                        Ok(n) => cur = n,
                        Err(e) => return self.complete(fill, Err(e)),
                    }
                }
                Err(e) => return self.complete(fill, Err(rpc_errno(&e))),
            }
        }
    }

    // checks a fetch reply against the wanted hash; never lets unverified bytes reach blobs/
    fn land(
        &self,
        fill: &Fill,
        p: &Progress,
        reply: Reply,
        old: Option<&BlobRef>,
    ) -> Result<(), i32> {
        let Reply::Blob { body, .. } = reply else {
            return Err(libc::EIO);
        };
        let fd = fill.fd()?;
        let got = match body {
            Body::Empty if fill.size == 0 => empty_hash(),
            Body::Inline(b) if b.0.len() as u64 == fill.size => {
                pwrite_all(fd, &b.0, 0).map_err(|e| io_errno(&e))?;
                *blake3::hash(&b.0).as_bytes()
            }
            Body::Stream { len } if len == fill.size && p.got() == len => {
                if len == 0 {
                    empty_hash()
                } else {
                    lock(&p.hash).take().ok_or(libc::EIO)?
                }
            }
            Body::Delta { ops, data_len } => {
                let old = old.ok_or(libc::EIO)?;
                if p.got() != data_len {
                    return Err(libc::EIO);
                }
                let total =
                    delta::check(&ops, old.size, data_len, fill.size).map_err(|_| libc::EIO)?;
                if total != fill.size {
                    return Err(libc::EIO);
                }
                let mut out = self.new_tmp()?;
                apply_files(old.fd(), fd, out.fd(), &ops)?;
                if hash_fd(out.fd(), fill.size)? != fill.h {
                    return Err(libc::EIO);
                }
                out.ver = Some(Version {
                    hash: fill.h,
                    size: fill.size,
                });
                *lock(&fill.tmp) = Some(out);
                return Ok(());
            }
            _ => return Err(libc::EIO),
        };
        if got == fill.h {
            Ok(())
        } else {
            Err(libc::EIO)
        }
    }

    fn publish_fill(&self, fill: &Arc<Fill>) -> Result<(), i32> {
        let t = lock(&fill.tmp).take();
        match t {
            Some(mut t) => self.rename_in(&mut t, &fill.h)?,
            // a batch fill wrote its final name already
            None if fill.fd.is_none() => {}
            None => return Err(libc::EIO),
        }
        let mut g = lock(&self.inner);
        g.add(fill.h, fill.size, Some(fill.path.clone()));
        if g.fills.get(&fill.h).is_some_and(|f| Arc::ptr_eq(f, fill)) {
            g.fills.remove(&fill.h);
        }
        Ok(())
    }

    fn complete(&self, fill: &Arc<Fill>, r: Result<(), i32>) {
        if lock(&fill.st).done.is_some() {
            return;
        }
        let r = r.and_then(|()| self.publish_fill(fill));
        if r.is_err() {
            let dead = lock(&fill.tmp).take();
            {
                let mut g = lock(&self.inner);
                if g.fills.get(&fill.h).is_some_and(|f| Arc::ptr_eq(f, fill)) {
                    g.fills.remove(&fill.h);
                }
            }
            drop(dead);
        }
        let mut st = lock(&fill.st);
        if st.done.is_none() {
            st.done = Some(r);
        }
        let wake = st.waiting > 0;
        drop(st);
        if wake {
            fill.cv.notify_all();
        }
    }

    // Ok(false): the asked range is readable from the fill file; Ok(true): the blob is published
    fn wait_fill(
        self: &Arc<Self>,
        fill: &Arc<Fill>,
        off: u64,
        len: u32,
        whole: bool,
        deadline: Instant,
    ) -> Result<bool, i32> {
        let (start, end) = if whole {
            (0, fill.size)
        } else {
            (
                off.min(fill.size),
                off.saturating_add(u64::from(len)).min(fill.size),
            )
        };
        let mut asked = false;
        let mut st = lock(&fill.st);
        loop {
            if let Some(r) = st.done {
                return r.map(|()| true);
            }
            let mark = st.mark;
            match st.ranges.as_mut() {
                None => {
                    if !whole && fill.fd.is_some() && (start >= end || end <= mark) {
                        return Ok(false);
                    }
                }
                Some(rg) => {
                    if rg.have_n == rg.n {
                        if !rg.verifying {
                            rg.verifying = true;
                            drop(st);
                            let r = fill
                                .fd()
                                .and_then(|fd| hash_fd(fd, fill.size))
                                .and_then(|h| if h == fill.h { Ok(()) } else { Err(libc::EIO) });
                            self.complete(fill, r);
                            st = lock(&fill.st);
                            continue;
                        }
                    } else if start < end {
                        let (u0, u1) = (start / UNIT, (end - 1) / UNIT);
                        if !whole && (u0..=u1).all(|u| bit(&rg.have, u)) {
                            return Ok(false);
                        }
                        let mut need = Vec::new();
                        for u in u0..=u1 {
                            if !bit(&rg.have, u) && !bit(&rg.req, u) {
                                if asked {
                                    return Err(rg.err.unwrap_or(libc::EIO));
                                }
                                set_bit(&mut rg.req, u, true);
                                need.push(u);
                            }
                        }
                        let own = !need.is_empty();
                        // sequential readers find the next units already on the way
                        if !whole && rg.err.is_none() {
                            for u in u1 + 1..rg.n.min(u1 + 1 + AHEAD) {
                                if !bit(&rg.have, u) && !bit(&rg.req, u) {
                                    set_bit(&mut rg.req, u, true);
                                    need.push(u);
                                }
                            }
                        }
                        if !need.is_empty() {
                            asked |= own;
                            drop(st);
                            for u in need {
                                self.request_unit(fill, u, deadline);
                            }
                            st = lock(&fill.st);
                            continue;
                        }
                    } else {
                        return Ok(false);
                    }
                }
            }
            st.waiting += 1;
            let (g, alive) = wait_until(&fill.cv, st, deadline);
            st = g;
            st.waiting -= 1;
            if !alive {
                return Err(libc::EIO);
            }
        }
    }

    fn request_unit(self: &Arc<Self>, fill: &Arc<Fill>, u: u64, deadline: Instant) {
        let uoff = u * UNIT;
        let ulen = fill.size.saturating_sub(uoff).min(UNIT);
        let op = || Op::Fetch {
            path: fill.path.clone(),
            want: Some(Want::Hash(fill.h)),
            have: None,
            range: Some((uoff, ulen as u32)),
        };
        let issued = (|| -> Result<Option<Result<(), i32>>, i32> {
            let (_, remote) = self.remote.get(deadline)?;
            let p = Arc::new(Progress::default());
            let sink = Box::new(FillSink::new(
                fill.clone(),
                p.clone(),
                uoff,
                ulen,
                false,
                false,
            ));
            let (s, f) = (self.clone(), fill.clone());
            let done: Done = Box::new(move |r: Result<Reply, RpcError>| {
                let r = s.unit_result(&f, uoff, ulen, &p, r);
                s.unit_landed(&f, u, r);
            });
            match remote.submit_stream(op(), sink, done) {
                Ok(_) => Ok(None),
                Err(RpcError::Busy) => {
                    let p = Arc::new(Progress::default());
                    let sink = Box::new(FillSink::new(
                        fill.clone(),
                        p.clone(),
                        uoff,
                        ulen,
                        false,
                        false,
                    ));
                    let r = remote.call_stream(op(), sink, deadline.max(fill_deadline(ulen)));
                    Ok(Some(self.unit_result(fill, uoff, ulen, &p, r)))
                }
                Err(e) => Err(rpc_errno(&e)),
            }
        })();
        match issued {
            Ok(None) => {}
            Ok(Some(r)) => self.unit_landed(fill, u, r),
            Err(e) => self.unit_landed(fill, u, Err(e)),
        }
    }

    fn unit_result(
        &self,
        fill: &Fill,
        uoff: u64,
        ulen: u64,
        p: &Progress,
        r: Result<Reply, RpcError>,
    ) -> Result<(), i32> {
        match r.map_err(|e| rpc_errno(&e))? {
            Reply::Blob {
                body: Body::Stream { len },
                ..
            } if len == ulen && p.got() == ulen => Ok(()),
            Reply::Blob {
                body: Body::Inline(b),
                ..
            } if b.0.len() as u64 == ulen => fill
                .fd()
                .and_then(|fd| pwrite_all(fd, &b.0, uoff).map_err(|e| io_errno(&e))),
            _ => Err(libc::EIO),
        }
    }

    fn unit_landed(&self, fill: &Fill, u: u64, r: Result<(), i32>) {
        let mut st = lock(&fill.st);
        if let Some(rg) = st.ranges.as_mut() {
            set_bit(&mut rg.req, u, false);
            match r {
                Ok(()) => {
                    if !bit(&rg.have, u) {
                        set_bit(&mut rg.have, u, true);
                        rg.have_n += 1;
                    }
                }
                Err(e) => rg.err = Some(e),
            }
        }
        let wake = st.waiting > 0;
        drop(st);
        if wake {
            fill.cv.notify_all();
        }
    }

    // victims move aside by rename under the lock and are unlinked after it, so a re-fetch of the hash cannot lose its new file
    fn evict(&self) -> u64 {
        let mut doomed: Vec<String> = Vec::new();
        let mut dropped: Vec<Arc<Fill>> = Vec::new();
        let freed = {
            let mut guard = lock(&self.inner);
            let g = &mut *guard;
            if g.bytes <= self.cap {
                return 0;
            }
            let target = self.cap - self.cap / 20;
            let now = Instant::now();
            let mut victims = Vec::new();
            let mut left = g.bytes;
            // recently opened blobs go only when nothing else gets the cache under its cap
            for recent in [false, true] {
                for h in g.lru.values().take(EVICT_SCAN) {
                    if left <= target {
                        break;
                    }
                    if g.pins.contains_key(h) {
                        continue;
                    }
                    let Some(s) = g.slots.get(h) else { continue };
                    let fresh = s
                        .opened
                        .is_some_and(|o| now.saturating_duration_since(o) < RECENT_PIN);
                    if fresh != recent {
                        continue;
                    }
                    left = left.saturating_sub(s.size);
                    victims.push(*h);
                }
            }
            let mut freed = 0;
            for h in &victims {
                let name = hex(h);
                let Ok(dir) = self.shard(h) else { continue };
                let aside = self.tmp_name();
                match rustix::fs::renameat(dir, hex_str(&name), &*self.tmp, aside.as_str()) {
                    Ok(()) => doomed.push(aside),
                    Err(Errno::NOENT) => {}
                    Err(_) => continue,
                }
                if let Some(s) = g.remove(h) {
                    freed += s.size;
                }
            }
            // partial range fills hold disk too; idle ones go once slots alone cannot get under the cap
            if g.bytes > target {
                let idle: Vec<Hash32> = g
                    .fills
                    .iter()
                    .filter(|(h, f)| {
                        f.size >= RANGE_FILE_MIN
                            && !g.pins.contains_key(*h)
                            && Arc::strong_count(f) == 1
                    })
                    .map(|(h, _)| *h)
                    .collect();
                for h in idle {
                    dropped.extend(g.fills.remove(&h));
                }
            }
            freed
        };
        drop(dropped);
        for name in &doomed {
            let _ = rustix::fs::unlinkat(&*self.tmp, name.as_str(), AtFlags::empty());
        }
        freed
    }

    fn save(&self) -> io::Result<()> {
        let entries: Vec<(Hash32, u64, u64)> = {
            let mut g = lock(&self.inner);
            if !g.dirty {
                return Ok(());
            }
            g.dirty = false;
            g.lru
                .iter()
                .filter_map(|(&t, h)| g.slots.get(h).map(|s| (*h, s.size, t)))
                .collect()
        };
        let r = persist::save_lru(&self.dir.join(LRU_FILE), &entries);
        if r.is_err() {
            lock(&self.inner).dirty = true;
        }
        r
    }
}

fn subdir(parent: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    match rustix::fs::mkdirat(parent, name, Mode::from_bits_truncate(0o700)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

fn sweep(dir: &OwnedFd) -> io::Result<()> {
    let mut ents = Vec::new();
    sys::read_dir_plus(dir.as_fd(), &mut ents)?;
    for e in ents {
        let _ = rustix::fs::unlinkat(dir, e.name.as_str(), AtFlags::empty());
    }
    Ok(())
}

fn auto_cap(root: &OwnedFd, used: u64) -> u64 {
    match rustix::fs::fstatvfs(root) {
        Ok(v) => {
            let room = v.f_bavail.saturating_mul(v.f_frsize).saturating_add(used);
            // on a filesystem smaller than the usual floor the cap stays well inside it, or fills would hit ENOSPC
            (room / 5).clamp(CAP_MIN.min(room / 2), CAP_MAX)
        }
        Err(_) => CAP_MIN,
    }
}

// a FetchMany in flight; dropping it unlanded fails its fills so waiting readers fetch on their own
pub struct Batch {
    s: Arc<Shared>,
    fills: Vec<Arc<Fill>>,
}

impl Batch {
    pub fn is_empty(&self) -> bool {
        self.fills.is_empty()
    }

    pub fn len(&self) -> usize {
        self.fills.len()
    }

    pub fn request(&self) -> Vec<(RelPath, Want)> {
        self.fills
            .iter()
            .map(|f| (f.path.clone(), Want::Hash(f.h)))
            .collect()
    }

    // the host answers in request order and may stop early; anything unanswered or mismatched fails
    pub fn land(mut self, items: Vec<BlobItem>) -> usize {
        let fills = std::mem::take(&mut self.fills);
        let mut got = items.into_iter();
        let mut ok = Vec::with_capacity(fills.len());
        for f in fills {
            match got.next() {
                Some((p, Ok((h, b)))) if p == f.path && h == f.h => ok.push((f, b)),
                _ => self.s.complete(&f, Err(libc::EIO)),
            }
        }
        let s = &*self.s;
        let land = |part: &[(Arc<Fill>, Bytes)]| -> usize {
            part.iter()
                .map(|(f, b)| usize::from(s.land_one(f, &b.0)))
                .sum()
        };
        // hashing and writing a batch is the warm-up's critical path: big ones spread over short-lived scoped threads
        let n = ok.len().div_ceil(LANDERS).max(LAND_SPLIT);
        let mut parts = ok.chunks(n);
        let Some(first) = parts.next() else { return 0 };
        std::thread::scope(|sc| {
            let others: Vec<_> = parts
                .map(|p| {
                    (
                        p,
                        std::thread::Builder::new()
                            .name("csync-land".into())
                            .spawn_scoped(sc, move || land(p)),
                    )
                })
                .collect();
            let mut landed = land(first);
            for (p, h) in others {
                landed += match h {
                    Ok(h) => h.join().unwrap_or(0),
                    Err(_) => land(p),
                };
            }
            landed
        })
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        for f in std::mem::take(&mut self.fills) {
            self.s.complete(&f, Err(libc::EIO));
        }
    }
}

// holds a pin for as long as it lives, so eviction never removes a blob that is being read
pub struct BlobRef {
    s: Arc<Shared>,
    h: Hash32,
    size: u64,
    fd: Arc<OwnedFd>,
    complete: bool,
}

impl BlobRef {
    pub fn hash(&self) -> &Hash32 {
        &self.h
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn shared_fd(&self) -> Arc<OwnedFd> {
        self.fd.clone()
    }

    // false while the blob is still filling: only the range that was waited for is valid, never use it for passthrough
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn read_at(&self, buf: &mut [u8], off: u64) -> Result<usize, i32> {
        let room = self.size.saturating_sub(off).min(buf.len() as u64) as usize;
        let b = buf.get_mut(..room).unwrap_or_default();
        pread_full(self.fd(), b, off).map_err(|e| io_errno(&e))
    }

    pub fn read_all(&self, cap: u64) -> Result<Vec<u8>, i32> {
        if !self.complete {
            return Err(libc::EAGAIN);
        }
        read_len(self.fd(), self.size, cap)
    }
}

impl Clone for BlobRef {
    fn clone(&self) -> Self {
        lock(&self.s.inner).pin(&self.h);
        Self {
            s: self.s.clone(),
            h: self.h,
            size: self.size,
            fd: self.fd.clone(),
            complete: self.complete,
        }
    }
}

impl Drop for BlobRef {
    fn drop(&mut self) {
        self.s.unpin(&self.h);
    }
}

pub struct Pin {
    s: Arc<Shared>,
    h: Hash32,
}

impl Drop for Pin {
    fn drop(&mut self) {
        self.s.unpin(&self.h);
    }
}

pub struct BlobCache {
    s: Arc<Shared>,
}

impl BlobCache {
    pub fn open(cfg: &CacheConfig, remote: Arc<RemoteSlot>) -> io::Result<Self> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&cfg.dir)?;
        let root = rustix::fs::open(
            cfg.dir.as_path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        rustix::fs::flock(&root, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "the blob cache is in use by another csync process",
            )
        })?;
        let tmp = subdir(&root, "tmp")?;
        let blobs = subdir(&root, "blobs")?;
        sweep(&tmp)?;
        let mut shards = Vec::with_capacity(256);
        for i in 0..=255u8 {
            let name = [HEX[usize::from(i >> 4)], HEX[usize::from(i & 15)]];
            shards.push(subdir(&blobs, hex_str(&name))?);
        }
        let known: FxHashMap<Hash32, (u64, u64)> = persist::load_lru(&cfg.dir.join(LRU_FILE))
            .unwrap_or_default()
            .into_iter()
            .map(|(h, s, u)| (h, (s, u)))
            .collect();
        let mut found: Vec<(u64, Hash32, u64)> = Vec::new();
        let mut ents = Vec::new();
        for (i, dir) in shards.iter().enumerate() {
            ents.clear();
            sys::read_dir_plus(dir.as_fd(), &mut ents)?;
            for e in &ents {
                let h = unhex(e.name.as_str().as_bytes())
                    .filter(|h| usize::from(h[0]) == i && e.kind == Some(Kind::File));
                // a size that disagrees with the persisted lru means a torn write: drop it rather than serve it
                let keep = h.and_then(|h| match known.get(&h) {
                    Some(&(size, used)) if size == e.stat.size => Some((used, h, size)),
                    Some(_) => None,
                    None => Some((0, h, e.stat.size)),
                });
                match keep {
                    Some(k) => found.push(k),
                    None => {
                        let _ = rustix::fs::unlinkat(dir, e.name.as_str(), AtFlags::empty());
                    }
                }
            }
        }
        found.sort_unstable_by_key(|k| k.0);
        let mut inner = Inner::default();
        for (_, h, size) in found {
            inner.tick += 1;
            inner.lru.insert(inner.tick, h);
            inner.slots.insert(
                h,
                Slot {
                    size,
                    checked: false,
                    used: inner.tick,
                    path: None,
                    opened: None,
                    fd: Weak::new(),
                },
            );
            inner.bytes = inner.bytes.saturating_add(size);
        }
        let cap = cfg.cap.unwrap_or_else(|| auto_cap(&root, inner.bytes));
        let s = Shared {
            dir: cfg.dir.clone(),
            _root: root,
            tmp: Arc::new(tmp),
            shards,
            cap,
            inner: Mutex::new(inner),
            remote,
            gate: Gate::default(),
            names: AtomicU64::new(0),
            pid: std::process::id(),
        };
        Ok(Self { s: Arc::new(s) })
    }

    pub fn get(&self, h: &Hash32) -> Option<BlobRef> {
        self.s.get(h)
    }

    // needs a prior note() (or use fetch_at) so the cache knows which path serves the hash
    pub fn fetch_or_wait(
        &self,
        h: &Hash32,
        off: u64,
        len: u32,
        deadline: Instant,
    ) -> Result<BlobRef, i32> {
        self.s.fetch(h, off, len, false, deadline)
    }

    pub fn pin(&self, h: &Hash32) -> bool {
        let mut g = lock(&self.s.inner);
        if g.slots.contains_key(h) || g.fills.contains_key(h) {
            g.pin(h);
            true
        } else {
            false
        }
    }

    pub fn unpin(&self, h: &Hash32) {
        self.s.unpin(h);
    }

    pub fn note(&self, h: &Hash32, path: &RelPath, size: u64) {
        let mut g = lock(&self.s.inner);
        if g.slots.contains_key(h) {
            return;
        }
        if g.hints.len() >= HINTS_MAX && !g.hints.contains_key(h) {
            g.hints.clear();
        }
        g.hints.insert(*h, (path.clone(), size));
    }

    pub fn fetch_at(
        &self,
        h: &Hash32,
        path: &RelPath,
        size: u64,
        off: u64,
        len: u32,
        deadline: Instant,
    ) -> Result<BlobRef, i32> {
        if let Some(r) = self.s.get(h) {
            return Ok(r);
        }
        self.note(h, path, size);
        self.s.fetch(h, off, len, false, deadline)
    }

    pub fn fetch_whole(
        &self,
        h: &Hash32,
        path: &RelPath,
        size: u64,
        deadline: Instant,
    ) -> Result<BlobRef, i32> {
        if let Some(r) = self.s.get(h) {
            return Ok(r);
        }
        self.note(h, path, size);
        if size >= RANGE_FILE_MIN {
            let mut off = 0;
            while off < size {
                let r = self.s.fetch(h, off, RANGE_UNIT, false, deadline)?;
                if r.is_complete() {
                    return Ok(r);
                }
                off += UNIT;
            }
        }
        self.s.fetch(h, 0, 0, true, deadline)
    }

    // a verified blob pinned and marked opened under one lock without opening its file: page-cache hits never read
    pub fn open_hit(&self, h: &Hash32) -> Option<Pin> {
        let mut guard = lock(&self.s.inner);
        let g = &mut *guard;
        let s = g.slots.get_mut(h).filter(|s| s.checked)?;
        s.opened = Some(Instant::now());
        g.touch(h);
        g.pin(h);
        Some(Pin {
            s: self.s.clone(),
            h: *h,
        })
    }

    // marks the read_ver blob of an open so eviction keeps it for the atomic-save merge window
    pub fn note_open(&self, h: &Hash32) {
        if let Some(s) = lock(&self.s.inner).slots.get_mut(h) {
            s.opened = Some(Instant::now());
        }
    }

    pub fn contains(&self, h: &Hash32) -> bool {
        lock(&self.s.inner).slots.contains_key(h)
    }

    pub fn insert_bytes(&self, h: &Hash32, data: &[u8], path: Option<&RelPath>) -> Result<(), i32> {
        self.s.insert_bytes(h, data, path)
    }

    // names the version a pending host entry holds; inline bytes are stored only if they hash to the claimed hash
    pub fn resolve(
        &self,
        path: &RelPath,
        at: VerKey,
        inline: bool,
        deadline: Instant,
    ) -> Result<Version, i32> {
        let op = Op::Resolve {
            path: path.clone(),
            at,
            inline,
        };
        let Reply::Blob { meta, body } = self.s.call(op, deadline)? else {
            return Err(libc::EIO);
        };
        let hash = meta.hash.ok_or(libc::EIO)?;
        if meta.kind != Kind::File || meta.size != at.size {
            return Err(libc::EIO);
        }
        match body {
            Body::Inline(b) if b.0.len() as u64 == at.size => {
                self.s.insert_bytes(&hash, &b.0, Some(path))?;
            }
            Body::Empty if at.size == 0 => self.s.insert_bytes(&hash, &[], Some(path))?,
            // not inlined: only the hash is learned and the bytes are fetched by it later
            Body::Empty => {}
            _ => return Err(libc::EIO),
        }
        Ok(Version {
            hash,
            size: at.size,
        })
    }

    pub fn pull_hashes(
        &self,
        index: IndexId,
        items: &[(RelPath, Seq)],
        deadline: Instant,
    ) -> Result<Vec<Option<Hash32>>, i32> {
        let mut out = Vec::with_capacity(items.len());
        for part in items.chunks(BATCH_MAX) {
            let op = Op::Hashes {
                index,
                items: part.to_vec(),
            };
            let Reply::Hashes { items: got } = self.s.call(op, deadline)? else {
                return Err(libc::EIO);
            };
            if got.len() != part.len() {
                return Err(libc::EIO);
            }
            out.extend(got);
        }
        Ok(out)
    }

    // every blob is stored only after its bytes hash to what the host sent; one result per item, in order
    pub fn fetch_many_ver(
        &self,
        items: &[(RelPath, VerKey)],
        deadline: Instant,
    ) -> Vec<(RelPath, Result<Version, i32>)> {
        let mut out = Vec::with_capacity(items.len());
        let mut rest = items;
        while !rest.is_empty() {
            let (mut n, mut bytes) = (0, 0u64);
            for (_, k) in rest {
                let full = n >= VER_PART_ITEMS || bytes.saturating_add(k.size) > VER_PART_BYTES;
                if n > 0 && full {
                    break;
                }
                n += 1;
                bytes = bytes.saturating_add(k.size);
            }
            let Some((part, tail)) = rest.split_at_checked(n) else {
                break;
            };
            match self.s.many_ver(part, deadline) {
                // an early stop leaves the unanswered items for the next round
                Ok(results) if !results.is_empty() => {
                    let done = results.len();
                    out.extend(part.iter().zip(results).map(|((p, _), r)| (p.clone(), r)));
                    rest = rest.get(done..).unwrap_or_default();
                }
                Ok(_) => {
                    out.extend(part.iter().map(|(p, _)| (p.clone(), Err(libc::EIO))));
                    rest = tail;
                }
                Err(e) => {
                    out.extend(part.iter().map(|(p, _)| (p.clone(), Err(e))));
                    rest = tail;
                }
            }
        }
        out.extend(rest.iter().map(|(p, _)| (p.clone(), Err(libc::EIO))));
        out
    }

    // an anonymous O_TMPFILE on the cache filesystem: nothing is left on disk once the last fd closes
    pub fn staging(&self) -> Result<OwnedFd, i32> {
        self.s.staging()
    }

    // the same anonymous staging file, already holding the bytes of base
    pub fn staging_from(&self, base: BorrowedFd<'_>) -> Result<OwnedFd, i32> {
        self.s.staging_from(base)
    }

    pub fn snapshot(&self, src: BorrowedFd<'_>) -> Result<(TmpBlob, Version), i32> {
        self.s.snapshot(src)
    }

    pub fn tmp_from_bytes(&self, data: &[u8]) -> Result<(TmpBlob, Version), i32> {
        self.s.tmp_from_bytes(data)
    }

    pub fn publish(&self, t: TmpBlob, path: Option<&RelPath>) -> Result<(), i32> {
        self.s.publish_tmp(t, path)
    }

    pub fn borrow(&self, fd: Arc<OwnedFd>, v: Version) -> TmpBlob {
        self.s.borrow(fd, v)
    }

    // on a full disk a passthrough write may have been cut short unseen; such a file must not commit
    pub fn room_for(&self, size: u64) -> bool {
        rustix::fs::fstatvfs(&*self.s.tmp)
            .is_ok_and(|v| v.f_bavail.saturating_mul(v.f_frsize) >= size)
    }

    pub fn adopt(&self, fd: BorrowedFd<'_>, v: Version, path: Option<&RelPath>) -> Result<(), i32> {
        self.s.adopt(fd, v, path)
    }

    pub fn evict(&self) -> u64 {
        self.s.evict()
    }

    pub fn save(&self) -> io::Result<()> {
        self.s.save()
    }

    pub fn usage(&self) -> (u64, u64) {
        (lock(&self.s.inner).bytes, self.s.cap)
    }

    pub fn gate(&self) -> &Gate {
        &self.s.gate
    }

    pub fn remote(&self) -> &Arc<RemoteSlot> {
        &self.s.remote
    }

    pub fn dir(&self) -> &Path {
        &self.s.dir
    }

    // registers fills for the items not cached or in flight, so readers wait on the batch instead of fetching again
    pub fn begin_batch(&self, items: &[(RelPath, Hash32, u64)]) -> Batch {
        Batch {
            fills: self.s.begin_batch(items),
            s: self.s.clone(),
        }
    }

    #[cfg(test)]
    fn waiting(&self, h: &Hash32) -> u32 {
        let f = lock(&self.s.inner).fills.get(h).cloned();
        f.map_or(0, |f| lock(&f.st).waiting)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Bytes, INLINE_MAX, Meta};
    use std::sync::atomic::AtomicUsize;

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmpdir(tag: &str) -> Dir {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "csync-cache-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        Dir(p)
    }

    fn names(p: &Path) -> usize {
        std::fs::read_dir(p).unwrap().count()
    }

    fn blob_path(root: &Path, h: &Hash32) -> PathBuf {
        let x = hex(h);
        let name = hex_str(&x);
        root.join("blobs").join(&name[..2]).join(name)
    }

    fn file_meta(size: u64) -> Meta {
        Meta {
            kind: Kind::File,
            perm: 0o644,
            size,
            mtime_ns: 0,
            ctime_ns: 0,
            hash: None,
            link: None,
            git_ro: false,
        }
    }

    fn wait_for(f: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !f() {
            assert!(Instant::now() < end, "condition not reached");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    const FAKE_INDEX: IndexId = 77;

    // one host index entry as the fake host answers for it
    #[derive(Clone)]
    struct HostFile {
        path: RelPath,
        ver: Seq,
        data: Vec<u8>,
        known: Option<Hash32>,
        // bytes sent in place of data while the claimed hash stays the one of data
        forged: Option<Vec<u8>>,
        // size the reply meta claims instead of the real one
        meta_size: Option<u64>,
    }

    fn host_file(path: &str, ver: Seq, data: &[u8]) -> HostFile {
        HostFile {
            path: RelPath::new(path).unwrap(),
            ver,
            data: data.to_vec(),
            known: None,
            forged: None,
            meta_size: None,
        }
    }

    fn key_of(f: &HostFile) -> VerKey {
        VerKey {
            index: FAKE_INDEX,
            ver: f.ver,
            size: f.data.len() as u64,
        }
    }

    fn hash_of(data: &[u8]) -> Hash32 {
        *blake3::hash(data).as_bytes()
    }

    fn dl() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[derive(Default)]
    struct Fake {
        calls: AtomicUsize,
        rounds: AtomicUsize,
        parked: Mutex<Vec<(Box<dyn ChunkSink>, Done)>>,
        inline: Mutex<Option<Vec<u8>>>,
        files: Mutex<Vec<HostFile>>,
        // a FetchMany reply stops after this many items, as a full reply frame does
        many_limit: Mutex<Option<usize>>,
    }

    impl Fake {
        // the entry only while index, ver and (when asked) size still match: anything else is a stale reference
        fn find(
            &self,
            path: &RelPath,
            index: IndexId,
            ver: Seq,
            size: Option<u64>,
        ) -> Option<HostFile> {
            lock(&self.files)
                .iter()
                .find(|f| {
                    f.path == *path
                        && index == FAKE_INDEX
                        && f.ver == ver
                        && size.is_none_or(|s| s == f.data.len() as u64)
                })
                .cloned()
        }
    }

    impl Remote for Fake {
        fn call(&self, op: Op, _d: Instant) -> Result<Reply, RpcError> {
            self.rounds.fetch_add(1, Ordering::SeqCst);
            match op {
                Op::Resolve { path, at, inline } => {
                    let f = self
                        .find(&path, at.index, at.ver, Some(at.size))
                        .ok_or(RpcError::Wire(WireErr::Gone))?;
                    let mut meta = file_meta(f.meta_size.unwrap_or(f.data.len() as u64));
                    meta.hash = Some(hash_of(&f.data));
                    let body = if inline && !f.data.is_empty() && f.data.len() <= INLINE_MAX {
                        Body::Inline(Bytes(f.forged.unwrap_or(f.data)))
                    } else {
                        Body::Empty
                    };
                    Ok(Reply::Blob { meta, body })
                }
                Op::Hashes { index, items } => Ok(Reply::Hashes {
                    items: items
                        .iter()
                        .map(|(p, v)| self.find(p, index, *v, None).and_then(|f| f.known))
                        .collect(),
                }),
                Op::FetchMany { items } => {
                    let limit = (*lock(&self.many_limit)).unwrap_or(usize::MAX);
                    let items = items
                        .into_iter()
                        .take(limit)
                        .map(|(p, w)| {
                            let r = match w {
                                Want::Ver(k) => self
                                    .find(&p, k.index, k.ver, Some(k.size))
                                    .map(|f| (hash_of(&f.data), Bytes(f.forged.unwrap_or(f.data))))
                                    .ok_or(WireErr::Gone),
                                Want::Hash(_) => Err(WireErr::Invalid),
                            };
                            (p, r)
                        })
                        .collect();
                    Ok(Reply::Blobs { items })
                }
                _ => Err(RpcError::Closed),
            }
        }
        fn call_stream(
            &self,
            _op: Op,
            _sink: Box<dyn ChunkSink>,
            _d: Instant,
        ) -> Result<Reply, RpcError> {
            Err(RpcError::Closed)
        }
        fn submit(&self, _op: Op, _done: Done) -> Result<ReqId, RpcError> {
            Err(RpcError::Closed)
        }
        fn submit_stream(
            &self,
            _op: Op,
            sink: Box<dyn ChunkSink>,
            done: Done,
        ) -> Result<ReqId, RpcError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(b) = lock(&self.inline).clone() {
                done(Ok(Reply::Blob {
                    meta: file_meta(b.len() as u64),
                    body: Body::Inline(Bytes(b)),
                }));
                return Ok(1);
            }
            lock(&self.parked).push((sink, done));
            Ok(1)
        }
        fn send_chunk(
            &self,
            _id: ReqId,
            _off: u64,
            _last: bool,
            _data: Vec<u8>,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        fn cancel(&self, _id: ReqId) {}
    }

    fn open(d: &Dir, cap: u64, fake: &Arc<Fake>) -> BlobCache {
        let slot = RemoteSlot::new();
        slot.set(Some(fake.clone() as Arc<dyn Remote>));
        BlobCache::open(
            &CacheConfig {
                dir: d.0.clone(),
                cap: Some(cap),
            },
            slot,
        )
        .unwrap()
    }

    #[test]
    fn publish_is_atomic_and_rejects_hash_mismatch() {
        let d = tmpdir("pub");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let data = b"hello blob".to_vec();
        let h = *blake3::hash(&data).as_bytes();
        let wrong = *blake3::hash(b"tampered").as_bytes();
        let other = *blake3::hash(b"something else").as_bytes();

        assert_eq!(c.insert_bytes(&other, &data, None), Err(libc::EIO));
        assert!(!c.contains(&other));
        assert!(!blob_path(&d.0, &other).exists());
        assert_eq!(names(&d.0.join("tmp")), 0);

        // the host answers with bytes that do not hash to the requested id
        *lock(&fake.inline) = Some(b"TAMPERED".to_vec());
        let p = RelPath::new("a.txt").unwrap();
        let r = c.fetch_at(&wrong, &p, 8, 0, 8, Instant::now() + Duration::from_secs(5));
        assert_eq!(r.err(), Some(libc::EIO));
        assert!(!c.contains(&wrong));
        assert!(!blob_path(&d.0, &wrong).exists());
        assert_eq!(names(&d.0.join("tmp")), 0);

        c.insert_bytes(&h, &data, Some(&p)).unwrap();
        let b = c.get(&h).unwrap();
        assert!(b.is_complete());
        assert_eq!(b.read_all(1 << 20).unwrap(), data);
        assert_eq!(std::fs::read(blob_path(&d.0, &h)).unwrap(), data);
        assert_eq!(names(&d.0.join("tmp")), 0);
    }

    #[test]
    fn eviction_never_removes_pinned_blobs() {
        let d = tmpdir("evict");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 3000, &fake);
        let put = |i: u8| {
            let b = vec![i; 1000];
            let h = *blake3::hash(&b).as_bytes();
            c.insert_bytes(&h, &b, None).unwrap();
            h
        };
        let hs: Vec<Hash32> = (0..5).map(&put).collect();
        assert!(c.pin(&hs[0]));
        c.evict();
        assert!(c.contains(&hs[0]) && blob_path(&d.0, &hs[0]).exists());
        assert!(!c.contains(&hs[1]) && !c.contains(&hs[2]) && !c.contains(&hs[3]));
        assert!(!blob_path(&d.0, &hs[1]).exists());
        assert!(c.contains(&hs[4]));
        assert!(c.usage().0 <= 3000);

        c.unpin(&hs[0]);
        let held = c.get(&hs[4]).unwrap();
        let more: Vec<Hash32> = (5..7).map(&put).collect();
        c.evict();
        assert!(!c.contains(&hs[0]));
        assert!(c.contains(&hs[4]));
        assert_eq!(held.read_all(4096).unwrap(), vec![4u8; 1000]);
        assert!(c.contains(&more[1]));
        assert!(c.usage().0 <= 3000);
    }

    #[test]
    fn eviction_leaves_no_aside_files_and_an_evicted_blob_can_return() {
        let d = tmpdir("evict-aside");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 3000, &fake);
        let put = |i: u8| {
            let b = vec![i; 1000];
            let h = *blake3::hash(&b).as_bytes();
            c.insert_bytes(&h, &b, None).unwrap();
            h
        };
        let hs: Vec<Hash32> = (0..5).map(&put).collect();
        assert!(c.evict() > 0);
        assert!(!c.contains(&hs[0]) && !blob_path(&d.0, &hs[0]).exists());
        assert_eq!(names(&d.0.join("tmp")), 0);
        put(0);
        assert!(c.contains(&hs[0]));
        assert_eq!(
            std::fs::read(blob_path(&d.0, &hs[0])).unwrap(),
            vec![0u8; 1000]
        );
        assert_eq!(names(&d.0.join("tmp")), 0);
    }

    #[test]
    fn concurrent_readers_share_one_fetch() {
        let d = tmpdir("dedup");
        let fake = Arc::new(Fake::default());
        let c = Arc::new(open(&d, 1 << 30, &fake));
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let h = *blake3::hash(&data).as_bytes();
        let size = data.len() as u64;
        let p = RelPath::new("big.bin").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let spawn = |off: u64| {
            let (c, p) = (c.clone(), p.clone());
            std::thread::spawn(move || {
                c.fetch_at(&h, &p, size, off, 4096, deadline).map(|r| {
                    let mut b = vec![0; 4096];
                    let n = r.read_at(&mut b, off).unwrap();
                    b.truncate(n);
                    b
                })
            })
        };
        let a = spawn(0);
        wait_for(|| fake.calls.load(Ordering::SeqCst) == 1 && c.waiting(&h) == 1);
        let b = spawn(150_000);
        wait_for(|| c.waiting(&h) == 2);
        let (mut sink, done) = lock(&fake.parked).pop().unwrap();
        let mut off = 0u64;
        for part in data.chunks(64_000) {
            let last = off + part.len() as u64 == size;
            sink.chunk(off, part, last).unwrap();
            off += part.len() as u64;
        }
        drop(sink);
        done(Ok(Reply::Blob {
            meta: file_meta(size),
            body: Body::Stream { len: size },
        }));
        assert_eq!(a.join().unwrap().unwrap(), &data[..4096]);
        assert_eq!(b.join().unwrap().unwrap(), &data[150_000..154_096]);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        assert!(c.contains(&h));
        assert_eq!(std::fs::read(blob_path(&d.0, &h)).unwrap(), data);
        assert_eq!(names(&d.0.join("tmp")), 0);
    }

    #[test]
    fn batch_lands_only_verified_blobs_and_failures_fall_back() {
        let d = tmpdir("batch");
        let fake = Arc::new(Fake::default());
        let c = Arc::new(open(&d, 1 << 30, &fake));
        let item = |name: &str, body: &[u8]| {
            let p = RelPath::new(name).unwrap();
            (p, *blake3::hash(body).as_bytes(), body.len() as u64)
        };
        let (a, b, x) = (b"alpha".to_vec(), b"bravo".to_vec(), b"xray!".to_vec());
        let items = [item("a", &a), item("b", &b), item("x", &x)];
        let batch = c.begin_batch(&items);
        assert_eq!(batch.request().len(), 3);
        assert_eq!(c.begin_batch(&items).len(), 0);

        // a reader of x waits on the batch, then fetches on its own once the batch fails it
        *lock(&fake.inline) = Some(x.clone());
        let (cr, px, hx) = (c.clone(), items[2].0.clone(), items[2].1);
        let deadline = Instant::now() + Duration::from_secs(10);
        let reader = std::thread::spawn(move || {
            cr.fetch_at(&hx, &px, 5, 0, 5, deadline)
                .map(|r| r.read_all(64).unwrap())
        });
        wait_for(|| c.waiting(&hx) == 1);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);

        let landed = batch.land(vec![
            (items[0].0.clone(), Ok((items[0].1, Bytes(a.clone())))),
            (
                items[1].0.clone(),
                Ok((items[1].1, Bytes(b"BRAVO".to_vec()))),
            ),
        ]);
        assert_eq!(landed, 1);
        assert!(c.contains(&items[0].1));
        assert_eq!(std::fs::read(blob_path(&d.0, &items[0].1)).unwrap(), a);
        assert!(!c.contains(&items[1].1));
        assert!(!blob_path(&d.0, &items[1].1).exists());
        assert_eq!(reader.join().unwrap().unwrap(), x);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        assert_eq!(names(&d.0.join("tmp")), 0);
    }

    #[test]
    fn a_reader_outlives_two_failed_batches_in_a_row() {
        let d = tmpdir("batch-twice");
        let fake = Arc::new(Fake::default());
        let c = Arc::new(open(&d, 1 << 30, &fake));
        let x = b"xray!".to_vec();
        let items = [(RelPath::new("x").unwrap(), hash_of(&x), 5)];
        let hx = items[0].1;
        *lock(&fake.inline) = Some(x.clone());
        let first = c.begin_batch(&items);
        let (cr, px) = (c.clone(), items[0].0.clone());
        let deadline = Instant::now() + Duration::from_secs(10);
        let reader = std::thread::spawn(move || {
            cr.fetch_at(&hx, &px, 5, 0, 5, deadline)
                .map(|r| r.read_all(64).unwrap())
        });
        wait_for(|| c.waiting(&hx) == 1);

        // the next prefetch round registers its batch after the first failed and before the reader looks again
        let gate = lock(&c.s.gate.st);
        drop(first);
        let second = c.begin_batch(&items);
        assert_eq!(second.len(), 1);
        drop(gate);
        wait_for(|| c.waiting(&hx) == 1);
        drop(second);

        assert_eq!(reader.join().unwrap(), Ok(x));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        assert!(c.contains(&hx));
    }

    #[test]
    fn big_batch_lands_in_parallel_over_a_torn_leftover() {
        let d = tmpdir("bigbatch");
        let fake = Arc::new(Fake::default());
        let c = Arc::new(open(&d, 1 << 30, &fake));
        let bodies: Vec<Vec<u8>> = (0..100u32)
            .map(|i| format!("body {i}").into_bytes())
            .collect();
        let items: Vec<_> = bodies
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let p = RelPath::new(&format!("f{i}")).unwrap();
                (p, *blake3::hash(b).as_bytes(), b.len() as u64)
            })
            .collect();
        std::fs::write(blob_path(&d.0, &items[7].1), b"torn").unwrap();
        let batch = c.begin_batch(&items);
        let replies = items
            .iter()
            .zip(&bodies)
            .map(|(i, b)| (i.0.clone(), Ok((i.1, Bytes(b.clone())))))
            .collect();
        assert_eq!(batch.land(replies), 100);
        for (i, b) in items.iter().zip(&bodies) {
            assert!(c.contains(&i.1));
            assert_eq!(&std::fs::read(blob_path(&d.0, &i.1)).unwrap(), b);
        }
        assert_eq!(names(&d.0.join("tmp")), 0);
    }

    #[test]
    fn tampered_inline_resolve_is_rejected_and_stores_nothing() {
        let d = tmpdir("tamper");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let mut same_len = host_file("a", 1, b"original");
        same_len.forged = Some(b"TAMPERED".to_vec());
        let mut other_len = host_file("b", 1, b"original too");
        other_len.forged = Some(b"short".to_vec());
        let files = [same_len, other_len];
        *lock(&fake.files) = files.to_vec();
        for f in &files {
            let r = c.resolve(&f.path, key_of(f), true, dl());
            assert_eq!(r, Err(libc::EIO));
            assert!(!c.contains(&hash_of(&f.data)));
            assert!(!c.contains(&hash_of(f.forged.as_ref().unwrap())));
            assert!(!blob_path(&d.0, &hash_of(&f.data)).exists());
        }
        assert_eq!(c.usage().0, 0);
        assert_eq!(names(&d.0.join("tmp")), 0);
    }

    #[test]
    fn resolve_stores_verified_inline_bytes_and_maps_stale_to_estale() {
        let d = tmpdir("resolve");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let small = host_file("small", 4, b"small body");
        let empty = host_file("empty", 5, b"");
        let big = host_file("big", 6, &[7u8; INLINE_MAX + 1]);
        *lock(&fake.files) = vec![small.clone(), empty.clone(), big.clone()];

        let v = c.resolve(&small.path, key_of(&small), true, dl()).unwrap();
        assert_eq!(
            v,
            Version {
                hash: hash_of(&small.data),
                size: 10
            }
        );
        assert_eq!(c.get(&v.hash).unwrap().read_all(64).unwrap(), small.data);

        let v = c.resolve(&empty.path, key_of(&empty), true, dl()).unwrap();
        assert_eq!(v.hash, empty_hash());
        assert!(c.contains(&v.hash));

        // not inlined: the hash is learned but nothing is stored
        let v = c.resolve(&big.path, key_of(&big), true, dl()).unwrap();
        assert_eq!(v.hash, hash_of(&big.data));
        assert!(!c.contains(&v.hash));
        let other = host_file("other", 8, b"not asked inline");
        lock(&fake.files).push(other.clone());
        let v = c.resolve(&other.path, key_of(&other), false, dl()).unwrap();
        assert!(!c.contains(&v.hash));

        let mut stale = key_of(&small);
        stale.ver += 1;
        assert_eq!(c.resolve(&small.path, stale, true, dl()), Err(libc::ESTALE));
        let mut resized = key_of(&small);
        resized.size += 1;
        assert_eq!(
            c.resolve(&small.path, resized, true, dl()),
            Err(libc::ESTALE)
        );
        let mut elsewhere = key_of(&small);
        elsewhere.index += 1;
        assert_eq!(
            c.resolve(&small.path, elsewhere, true, dl()),
            Err(libc::ESTALE)
        );
        assert_eq!(names(&d.0.join("tmp")), 0);
    }

    #[test]
    fn resolve_rejects_a_reply_size_that_differs_from_the_asked_one() {
        let d = tmpdir("resolve-size");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let mut f = host_file("a", 1, b"twelve bytes");
        f.meta_size = Some(13);
        *lock(&fake.files) = vec![f.clone()];
        assert_eq!(c.resolve(&f.path, key_of(&f), true, dl()), Err(libc::EIO));
        assert!(!c.contains(&hash_of(&f.data)));
        assert_eq!(c.usage().0, 0);
    }

    #[test]
    fn resolve_without_a_link_fails_at_the_deadline() {
        let d = tmpdir("resolve-down");
        let c = BlobCache::open(
            &CacheConfig {
                dir: d.0.clone(),
                cap: Some(1 << 30),
            },
            RemoteSlot::new(),
        )
        .unwrap();
        let f = host_file("a", 1, b"x");
        let end = Instant::now() + Duration::from_millis(30);
        assert_eq!(c.resolve(&f.path, key_of(&f), true, end), Err(libc::EIO));
    }

    #[test]
    fn fetch_many_ver_verifies_each_item_and_the_rest_still_land() {
        let d = tmpdir("many-ver");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let good = host_file("good", 1, b"good bytes");
        let mut forged = host_file("forged", 2, b"genuine!!!");
        forged.forged = Some(b"forgeries!".to_vec());
        let mut short = host_file("short", 3, b"abcdef");
        short.forged = Some(b"abc".to_vec());
        let stale = host_file("stale", 4, b"stale bytes");
        let last = host_file("last", 5, b"last bytes");
        *lock(&fake.files) = vec![
            good.clone(),
            forged.clone(),
            short.clone(),
            stale.clone(),
            last.clone(),
        ];
        let mut old = key_of(&stale);
        old.ver -= 1;
        let missing = RelPath::new("missing").unwrap();
        let items = vec![
            (good.path.clone(), key_of(&good)),
            (forged.path.clone(), key_of(&forged)),
            (short.path.clone(), key_of(&short)),
            (stale.path.clone(), old),
            (missing.clone(), key_of(&last)),
            (last.path.clone(), key_of(&last)),
        ];
        let out = c.fetch_many_ver(&items, dl());
        let paths: Vec<&RelPath> = out.iter().map(|(p, _)| p).collect();
        assert_eq!(paths, items.iter().map(|(p, _)| p).collect::<Vec<_>>());
        let res: Vec<Result<Version, i32>> = out.into_iter().map(|(_, r)| r).collect();
        assert_eq!(
            res,
            vec![
                Ok(Version {
                    hash: hash_of(&good.data),
                    size: 10
                }),
                Err(libc::EIO),
                Err(libc::EIO),
                Err(libc::ESTALE),
                Err(libc::ESTALE),
                Ok(Version {
                    hash: hash_of(&last.data),
                    size: 10
                }),
            ]
        );
        assert!(c.contains(&hash_of(&good.data)) && c.contains(&hash_of(&last.data)));
        for f in [&forged, &short] {
            assert!(!c.contains(&hash_of(&f.data)));
            assert!(!c.contains(&hash_of(f.forged.as_ref().unwrap())));
            assert!(!blob_path(&d.0, &hash_of(&f.data)).exists());
        }
        assert_eq!(
            std::fs::read(blob_path(&d.0, &hash_of(&good.data))).unwrap(),
            good.data
        );
        assert_eq!(names(&d.0.join("tmp")), 0);
    }

    #[test]
    fn fetch_many_ver_continues_after_a_reply_that_stops_early() {
        let d = tmpdir("many-ver-early");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let files: Vec<HostFile> = (0..5u64)
            .map(|i| host_file(&format!("f{i}"), i + 1, format!("body {i}").as_bytes()))
            .collect();
        *lock(&fake.files) = files.clone();
        *lock(&fake.many_limit) = Some(2);
        let items: Vec<_> = files.iter().map(|f| (f.path.clone(), key_of(f))).collect();
        let out = c.fetch_many_ver(&items, dl());
        assert_eq!(out.len(), 5);
        for ((p, r), f) in out.iter().zip(&files) {
            assert_eq!(p, &f.path);
            assert_eq!(r.map(|v| v.hash), Ok(hash_of(&f.data)));
            assert!(c.contains(&hash_of(&f.data)));
        }
        assert_eq!(fake.rounds.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn fetch_many_ver_splits_a_long_list_into_parts() {
        let d = tmpdir("many-ver-parts");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let files: Vec<HostFile> = (0..600u64)
            .map(|i| host_file(&format!("f{i}"), i + 1, format!("body {i}").as_bytes()))
            .collect();
        *lock(&fake.files) = files.clone();
        let items: Vec<_> = files.iter().map(|f| (f.path.clone(), key_of(f))).collect();
        let out = c.fetch_many_ver(&items, dl());
        assert_eq!(out.len(), 600);
        assert!(out.iter().all(|(_, r)| r.is_ok()));
        assert_eq!(fake.rounds.load(Ordering::SeqCst), 2);
        assert!(c.fetch_many_ver(&[], dl()).is_empty());
        assert_eq!(fake.rounds.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn pull_hashes_keeps_order_and_none_entries() {
        let d = tmpdir("pull");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let mut a = host_file("a", 1, b"aaa");
        a.known = Some([1; 32]);
        let b = host_file("b", 2, b"bbb");
        let mut z = host_file("z", 3, b"zzz");
        z.known = Some([3; 32]);
        *lock(&fake.files) = vec![a.clone(), b.clone(), z.clone()];
        let ask = [
            (z.path.clone(), 3),
            (b.path.clone(), 2),
            (RelPath::new("unknown").unwrap(), 9),
            (a.path.clone(), 1),
            // a ver the host no longer holds has no known hash either
            (a.path.clone(), 2),
        ];
        let got = c.pull_hashes(FAKE_INDEX, &ask, dl()).unwrap();
        assert_eq!(got, vec![Some([3; 32]), None, None, Some([1; 32]), None]);
        assert_eq!(
            c.pull_hashes(FAKE_INDEX + 1, &ask[..1], dl()).unwrap(),
            vec![None]
        );
        assert!(c.pull_hashes(FAKE_INDEX, &[], dl()).unwrap().is_empty());
        assert_eq!(fake.rounds.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn pull_hashes_splits_past_the_batch_bound() {
        let d = tmpdir("pull-many");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let mut a = host_file("a", 1, b"aaa");
        a.known = Some([1; 32]);
        *lock(&fake.files) = vec![a.clone()];
        let ask: Vec<(RelPath, Seq)> = (0..=BATCH_MAX).map(|_| (a.path.clone(), 1)).collect();
        let got = c.pull_hashes(FAKE_INDEX, &ask, dl()).unwrap();
        assert_eq!(got.len(), BATCH_MAX + 1);
        assert!(got.iter().all(|h| *h == Some([1; 32])));
        assert_eq!(fake.rounds.load(Ordering::SeqCst), 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn staging_clone_adopt_and_snapshot_round_trip() {
        let d = tmpdir("adopt");
        let fake = Arc::new(Fake::default());
        let c = open(&d, 1 << 30, &fake);
        let base = b"base bytes of a file".to_vec();
        let bh = *blake3::hash(&base).as_bytes();
        c.insert_bytes(&bh, &base, None).unwrap();
        let blob = c.get(&bh).unwrap();

        let fd = c.staging_from(blob.fd()).unwrap();
        assert_eq!(names(&d.0.join("tmp")), 0);
        let mut got = vec![0u8; base.len()];
        assert_eq!(pread_full(fd.as_fd(), &mut got, 0).unwrap(), base.len());
        assert_eq!(got, base);

        let edited = b"base bytes of a file, edited".to_vec();
        pwrite_all(fd.as_fd(), &edited, 0).unwrap();
        assert_eq!(blob.read_all(1 << 20).unwrap(), base);
        assert_eq!(std::fs::read(blob_path(&d.0, &bh)).unwrap(), base);

        let v = Version {
            hash: *blake3::hash(&edited).as_bytes(),
            size: edited.len() as u64,
        };
        let p = RelPath::new("edited.txt").unwrap();
        c.adopt(fd.as_fd(), v, Some(&p)).unwrap();
        assert!(c.contains(&v.hash));
        assert_eq!(std::fs::read(blob_path(&d.0, &v.hash)).unwrap(), edited);
        assert_eq!(names(&d.0.join("tmp")), 0);

        pwrite_all(fd.as_fd(), b"LATER", 0).unwrap();
        assert_eq!(std::fs::read(blob_path(&d.0, &v.hash)).unwrap(), edited);

        let (t, sv) = c.snapshot(fd.as_fd()).unwrap();
        assert_eq!(names(&d.0.join("tmp")), 1);
        assert_eq!(sv.size, edited.len() as u64);
        assert_eq!(sv.hash, hash_fd(fd.as_fd(), sv.size).unwrap());
        drop(t);
        assert_eq!(names(&d.0.join("tmp")), 0);
    }

    #[test]
    fn closing_the_slot_ends_link_waits_and_keeps_the_current_link() {
        let fake = Arc::new(Fake::default());
        let slot = RemoteSlot::new();
        slot.set(Some(fake.clone() as Arc<dyn Remote>));
        let (seen, _) = slot.get(Instant::now()).unwrap();
        let s = slot.clone();
        let waiter = std::thread::spawn(move || {
            let t0 = Instant::now();
            (
                s.newer(seen, t0 + Duration::from_secs(30)).is_err(),
                t0.elapsed(),
            )
        });
        std::thread::sleep(Duration::from_millis(100));
        slot.close();
        let (failed, took) = waiter.join().unwrap();
        assert!(failed);
        assert!(took < Duration::from_secs(2), "waited {took:?}");
        assert!(slot.get(Instant::now()).is_ok());
        slot.set(None);
        let t0 = Instant::now();
        assert!(slot.get(t0 + Duration::from_secs(30)).is_err());
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    // the shutdown hang: prefetch batches waited out their deadline for a link the stopped dialer never brings
    #[test]
    fn a_batch_fetch_without_a_link_ends_once_the_slot_closes() {
        let d = tmpdir("slotclose");
        let fake = Arc::new(Fake::default());
        let c = Arc::new(open(&d, 1 << 30, &fake));
        c.remote().set(None);
        let items = vec![(
            RelPath::new("a").unwrap(),
            VerKey {
                index: FAKE_INDEX,
                ver: 1,
                size: 4,
            },
        )];
        let c2 = c.clone();
        let waiter = std::thread::spawn(move || {
            let t0 = Instant::now();
            let got = c2.fetch_many_ver(&items, t0 + Duration::from_secs(30));
            (got.iter().all(|(_, r)| r.is_err()), t0.elapsed())
        });
        std::thread::sleep(Duration::from_millis(100));
        c.remote().close();
        let (failed, took) = waiter.join().unwrap();
        assert!(failed);
        assert!(took < Duration::from_secs(2), "waited {took:?}");
        assert_eq!(fake.rounds.load(Ordering::SeqCst), 0);
    }
}
