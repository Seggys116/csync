use super::cache::{
    BlobCache, BlobRef, DELTA_CAP, RemoteSlot, TmpBlob, WAIT, hash_fd, io_errno, lock, pread_full,
    pwrite_all, read_len, rpc_errno, wire_errno,
};
use super::pipe::{Payload, Pipe, Tag, Ticket};
use super::tree::{GNode, Vis};
use crate::delta;
use crate::index::tree::StatKey;
use crate::merge::merge3;
use crate::net::rpc::RpcError;
use crate::proto::{
    Body, Bytes, DELTA_MIN, Expect, INLINE_MAX, IndexId, Kind, LinkTarget, MERGE_MAX, Meta, Mk,
    Notice, NoticeKind, Op, RelPath, Reply, Version, WireErr,
};
use crate::sys;
use rustc_hash::FxHashMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MERGE_TRIES: u32 = 3;
pub const REFUSED: i32 = libc::ECANCELED;
const RACY_NS: i64 = 100_000_000;
// a new file this large commits in place and waits for the host instead of pipelining a copy
const BORROW_MIN: u64 = 1 << 20;

pub type NoticeFn = Arc<dyn Fn(Notice) + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Flushed {
    Clean,
    // pipelined create: the host has not answered yet, release() settles it
    Sent(Version),
    Committed { meta: Meta, merged: bool },
}

// refused: the edit lost a CAS race and was discarded; restore the node to `current` and invalidate it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub errno: i32,
    pub refused: bool,
    pub current: Option<Meta>,
}

impl Refusal {
    fn err(errno: i32) -> Self {
        Self {
            errno,
            refused: false,
            current: None,
        }
    }
}

pub struct OpenW<'a> {
    pub path: &'a RelPath,
    pub base: Option<Version>,
    pub perm: u16,
    pub trunc: bool,
    pub staging: Option<u32>,
}

// local: the source is a Local overlay file being moved into the synced domain, with its perm
pub struct RenameReq<'a> {
    pub from: &'a RelPath,
    pub to: &'a RelPath,
    pub from_expect: Expect,
    pub to_expect: Expect,
    pub staging: Option<u32>,
    pub local: Option<(BorrowedFd<'a>, u16)>,
    // the source is this guest's own save: a refused rename discards it on both sides, as a staged one does
    pub discard: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolve {
    Merged(Vec<u8>),
    Refuse,
}

// a side that is None could not be loaded (missing, too large, unreadable) and forces a refusal
pub fn resolve(base: Option<&[u8]>, ours: Option<&[u8]>, theirs: Option<&[u8]>) -> Resolve {
    match (base, ours, theirs) {
        (Some(b), Some(o), Some(t)) => merge3(b, o, t).map_or(Resolve::Refuse, Resolve::Merged),
        _ => Resolve::Refuse,
    }
}

// a file only this guest has made has no host version yet, so it alone is not held to one
pub fn node_expect(n: &GNode, index: IndexId) -> Expect {
    if n.is_pending() && n.ver == 0 {
        Expect::Any
    } else {
        n.expect(index)
    }
}

// the CAS expectation for a rename target: the version last served to an open of it, else its current one
pub fn dest_expect(node: Option<&GNode>, index: IndexId) -> Expect {
    match node {
        None => Expect::Absent,
        Some(n) if n.vis == Vis::PendingDelete => Expect::Absent,
        Some(n) => match (n.meta.kind, n.read_ver) {
            (Kind::File, Some(v)) => Expect::Is(v),
            _ => node_expect(n, index),
        },
    }
}

type Mark = (StatKey, i64);

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

fn mark(stat: StatKey) -> Mark {
    (stat, now_ns())
}

// a stat taken within the timestamp granularity of a write cannot prove the content is unchanged
fn trusted(m: Option<&Mark>, cur: &StatKey) -> bool {
    m.is_some_and(|(s, at)| s == cur && s.mtime_ns.saturating_add(RACY_NS) < *at)
}

fn commit_deadline(size: u64) -> Instant {
    Instant::now() + WAIT * 2 + Duration::from_millis(size >> 12)
}

fn fetch_deadline(size: u64) -> Instant {
    Instant::now() + WAIT + Duration::from_millis(size >> 12)
}

fn overwrite(fd: BorrowedFd<'_>, data: &[u8]) -> Result<(), i32> {
    pwrite_all(fd, data, 0).map_err(|e| io_errno(&e))?;
    rustix::fs::ftruncate(fd, data.len() as u64).map_err(|e| e.raw_os_error())
}

#[derive(Default)]
struct Cell {
    r: Mutex<Option<Result<Reply, RpcError>>>,
    cv: Condvar,
    // answered, even after a waiter took the answer: a release waiting only for the reply must not miss it
    fired: std::sync::atomic::AtomicBool,
}

impl Cell {
    fn put(&self, r: Result<Reply, RpcError>) {
        let mut g = lock(&self.r);
        *g = Some(r);
        self.fired.store(true, std::sync::atomic::Ordering::Release);
        drop(g);
        self.cv.notify_all();
    }

    fn wait(&self, deadline: Instant) -> Option<Result<Reply, RpcError>> {
        let mut g = lock(&self.r);
        loop {
            if let Some(r) = g.take() {
                return Some(r);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            g = match self.cv.wait_timeout(g, deadline - now) {
                Ok((g, _)) => g,
                Err(e) => e.into_inner().0,
            };
        }
    }

    fn ready(&self, deadline: Instant) {
        let mut g = lock(&self.r);
        while g.is_none() && !self.fired.load(std::sync::atomic::Ordering::Acquire) {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            g = match self.cv.wait_timeout(g, deadline - now) {
                Ok((g, _)) => g,
                Err(e) => e.into_inner().0,
            };
        }
    }
}

struct Pending {
    ticket: Ticket,
    tmp: TmpBlob,
    ver: Version,
    stat: Mark,
    cell: Arc<Cell>,
}

struct Staged {
    path: RelPath,
    fd: Arc<OwnedFd>,
    base: Option<Version>,
    base_ref: Option<BlobRef>,
    perm: u16,
    synced: Option<Mark>,
    pending: Option<Pending>,
    // committed straight from the staging file: the cache gets it when the last handle goes
    unpublished: Option<Version>,
    handles: u32,
    refused: bool,
    // a truncate without a handle owns one handle count until an open adopts it or it is committed
    deferred: bool,
    // out of the table: a reopen racing the last release must not reuse it
    closed: bool,
    // its name was unlinked: open handles keep a private copy that is never committed
    unlinked: bool,
}

#[derive(Default)]
struct Table {
    map: FxHashMap<u32, Arc<Mutex<Staged>>>,
    next: u32,
}

enum Next {
    Merged(Vec<u8>, Version),
    Refuse(Option<Meta>, Option<(Version, Vec<u8>)>),
}

#[derive(Clone, Copy)]
enum Target<'a> {
    Rename {
        from: &'a RelPath,
        from_expect: Expect,
    },
    Commit {
        perm: Option<u16>,
    },
}

struct Written {
    meta: Meta,
    ver: Option<Version>,
    merged: Option<Vec<u8>>,
}

fn body_for(fd: BorrowedFd<'_>, size: u64, base: Option<&BlobRef>) -> Result<(Body, Payload), i32> {
    if size == 0 {
        return Ok((Body::Empty, Payload::None));
    }
    if size <= INLINE_MAX as u64 {
        return Ok((
            Body::Inline(Bytes(read_len(fd, size, INLINE_MAX as u64)?)),
            Payload::None,
        ));
    }
    if (DELTA_MIN..=DELTA_CAP).contains(&size)
        && let Some(b) = base.filter(|b| b.is_complete() && b.size() > 0 && b.size() <= DELTA_CAP)
    {
        let new = read_len(fd, size, DELTA_CAP)?;
        let sigs = delta::sigs(&b.read_all(DELTA_CAP)?);
        if let Some(e) = delta::encode(&new, &sigs) {
            return Ok((
                Body::Delta {
                    ops: e.ops.clone(),
                    data_len: e.data_len,
                },
                Payload::Literals {
                    new,
                    ops: e.ops,
                    data_len: e.data_len,
                },
            ));
        }
    }
    // the pipe sends the chunks after this returns, so it holds its own descriptor
    let fd = fd.try_clone_to_owned().map_err(|e| io_errno(&e))?;
    Ok((Body::Stream { len: size }, Payload::File { fd, len: size }))
}

// precondition for every method: the paths are Synced; Local and ignored paths never reach the host
pub struct Writer {
    cache: Arc<BlobCache>,
    remote: Arc<RemoteSlot>,
    pipe: Arc<Pipe>,
    notice: NoticeFn,
    table: Mutex<Table>,
}

impl Writer {
    pub fn new(cache: Arc<BlobCache>, pipe: Arc<Pipe>, notice: NoticeFn) -> Self {
        let remote = cache.remote().clone();
        Self {
            cache,
            remote,
            pipe,
            notice,
            table: Mutex::new(Table::default()),
        }
    }

    // no other handle can change the staging file, so it is hashed and sent in place, not copied
    fn snap_staged(&self, st: &Staged, size: u64, sync: bool) -> Result<(TmpBlob, Version), i32> {
        let waits = st.base.is_some() || sync || size >= BORROW_MIN;
        if size > INLINE_MAX as u64 && st.handles <= 1 && waits && self.cache.room_for(size) {
            let v = Version {
                hash: hash_fd(st.fd.as_fd(), size)?,
                size,
            };
            return Ok((self.cache.borrow(st.fd.clone(), v), v));
        }
        self.snap(st.fd.as_fd(), size)
    }

    // small content is read once and hashed in memory instead of being copied and read back
    fn snap(&self, fd: BorrowedFd<'_>, size: u64) -> Result<(TmpBlob, Version), i32> {
        if size <= INLINE_MAX as u64 {
            let mut b = vec![0u8; size as usize];
            if pread_full(fd, &mut b, 0).map_err(|e| io_errno(&e))? == b.len() {
                return self.cache.tmp_from_bytes(&b);
            }
        }
        self.cache.snapshot(fd)
    }

    fn entry(&self, id: u32) -> Option<Arc<Mutex<Staged>>> {
        lock(&self.table).map.get(&id).cloned()
    }

    fn say(&self, kind: NoticeKind, path: &RelPath) {
        (self.notice)(Notice {
            kind,
            path: path.clone(),
        });
    }

    pub fn staging_fd(&self, id: u32) -> Option<Arc<OwnedFd>> {
        self.entry(id).map(|e| lock(&e).fd.clone())
    }

    // base is the host version the handle opened (None for a new file); the staging copy is a reflink of it
    pub fn open_for_write(&self, o: OpenW<'_>) -> Result<(u32, Arc<OwnedFd>), i32> {
        if let Some(id) = o.staging
            && let Some(e) = self.entry(id)
        {
            let mut st = lock(&e);
            if !st.refused && !st.closed {
                if o.trunc {
                    rustix::fs::ftruncate(&*st.fd, 0).map_err(|e| e.raw_os_error())?;
                    st.synced = None;
                }
                if st.deferred {
                    st.deferred = false;
                } else {
                    st.handles += 1;
                }
                return Ok((id, st.fd.clone()));
            }
        }
        let mut base_ref = None;
        let mut cloned = None;
        if let Some(v) = o.base {
            if o.trunc {
                base_ref = self.cache.get(&v.hash);
            } else if v.size > 0 {
                let b = self
                    .cache
                    .fetch_whole(&v.hash, o.path, v.size, fetch_deadline(v.size))?;
                cloned = Some(self.cache.staging_from(b.fd())?);
                base_ref = Some(b);
            }
        }
        let fd = Arc::new(match cloned {
            Some(fd) => fd,
            None => self.cache.staging()?,
        });
        let mut synced = None;
        if let Some(v) = o.base
            && (!o.trunc || v.size == 0)
        {
            synced = Some(mark(sys::stat_key(fd.as_fd()).map_err(|e| io_errno(&e))?));
        }
        let st = Staged {
            path: o.path.clone(),
            fd: fd.clone(),
            base: o.base,
            base_ref,
            perm: o.perm,
            synced,
            pending: None,
            handles: 1,
            refused: false,
            deferred: false,
            closed: false,
            unlinked: false,
            unpublished: None,
        };
        let mut t = lock(&self.table);
        let id = loop {
            t.next = t.next.wrapping_add(1);
            if t.next != 0 && !t.map.contains_key(&t.next) {
                break t.next;
            }
        };
        t.map.insert(id, Arc::new(Mutex::new(st)));
        Ok((id, fd))
    }

    // called on every close (flush) and fsync (sync = true)
    pub fn flush(&self, id: u32, sync: bool) -> Result<Flushed, Refusal> {
        let e = self.entry(id).ok_or(Refusal::err(libc::EBADF))?;
        let mut st = lock(&e);
        // shell redirections close a dup of a fresh or truncated file before writing; that empty state is left to release
        if !sync
            && !st.refused
            && st.synced.is_none()
            && st.pending.is_none()
            && sys::stat_key(st.fd.as_fd()).is_ok_and(|k| k.size == 0)
        {
            return Ok(Flushed::Clean);
        }
        self.flush_locked(&mut st, sync)
    }

    // the content must reach the host before a following op on the path, but need not be durable: the
    // ordered stream carries a new file's commit ahead of it without a wait or an fsync
    pub fn flush_ordered(&self, id: u32) -> Result<Flushed, Refusal> {
        let e = self.entry(id).ok_or(Refusal::err(libc::EBADF))?;
        let mut st = lock(&e);
        self.flush_locked(&mut st, false)
    }

    // on the last handle: commits anything still dirty, settles a pipelined create, drops the staging
    pub fn release(&self, id: u32) -> Option<Result<Flushed, Refusal>> {
        let e = self.entry(id)?;
        let cell = {
            let mut st = lock(&e);
            st.handles = st.handles.saturating_sub(1);
            if st.handles > 0 {
                return None;
            }
            st.pending.as_ref().map(|p| (p.cell.clone(), p.ver.size))
        };
        // a concurrent rename may still use the entry, so wait for the host without holding it
        if let Some((c, size)) = cell {
            c.ready(commit_deadline(size));
        }
        let mut st = lock(&e);
        let mut settled = false;
        let out = if st.refused || st.handles > 0 {
            None
        } else {
            let r = match self.flush_locked(&mut st, false) {
                Ok(Flushed::Sent(_)) => self.settle(&mut st).map(|o| o.unwrap_or(Flushed::Clean)),
                r => r,
            };
            // nobody is left to retry a new file the host never took: the guest copy follows the host
            let r = match r {
                Err(e) if !e.refused && st.base.is_none() => self.give_up(&mut st, e),
                r => r,
            };
            settled = r.is_ok();
            (r != Ok(Flushed::Clean)).then_some(r)
        };
        let keep = st.handles > 0;
        st.closed = !keep;
        let unpublished = if keep { None } else { st.unpublished.take() };
        // the last flush proved the staging file holds exactly the committed version
        if let Some(v) = unpublished.filter(|v| settled && st.base == Some(*v)) {
            let _ = self.cache.adopt(st.fd.as_fd(), v, Some(&st.path));
        }
        drop(st);
        if !keep {
            lock(&self.table).map.remove(&id);
        }
        out
    }

    // the handle count taken by open_for_write now stands for a truncate that no handle holds yet
    pub fn defer(&self, id: u32) {
        if let Some(e) = self.entry(id) {
            lock(&e).deferred = true;
        }
    }

    pub fn end_deferred(&self, id: u32) -> Option<Result<Flushed, Refusal>> {
        let e = self.entry(id)?;
        {
            let mut st = lock(&e);
            if !st.deferred {
                return None;
            }
            st.deferred = false;
        }
        self.release(id)
    }

    // the name is gone but handles stay open: they keep reading and writing the copy, which is then dropped
    pub fn unlinked(&self, id: u32) {
        if let Some(e) = self.entry(id) {
            lock(&e).unlinked = true;
        }
    }

    // the file was removed or replaced: a truncate nobody adopted is dropped unsent
    pub fn cancel_deferred(&self, id: u32) {
        let Some(e) = self.entry(id) else { return };
        let mut st = lock(&e);
        if !st.deferred {
            return;
        }
        st.deferred = false;
        st.handles = st.handles.saturating_sub(1);
        if st.handles == 0 {
            st.closed = true;
            drop(st);
            lock(&self.table).map.remove(&id);
        }
    }

    pub fn staged_stat(&self, id: u32) -> Option<StatKey> {
        let e = self.entry(id)?;
        let st = e.try_lock().ok()?;
        sys::stat_key(st.fd.as_fd()).ok()
    }

    fn flush_locked(&self, st: &mut Staged, sync: bool) -> Result<Flushed, Refusal> {
        if st.refused {
            return Err(Refusal::err(REFUSED));
        }
        if st.unlinked {
            st.pending = None;
            return Ok(Flushed::Clean);
        }
        let settled = self.settle(st)?;
        let stat = sys::stat_key(st.fd.as_fd()).map_err(|e| Refusal::err(io_errno(&e)))?;
        if trusted(st.synced.as_ref(), &stat) {
            return Ok(settled.unwrap_or(Flushed::Clean));
        }
        let (tmp, ver) = self
            .snap_staged(st, stat.size, sync)
            .map_err(Refusal::err)?;
        if st.base == Some(ver) {
            st.synced = Some(mark(stat));
            return Ok(settled.unwrap_or(Flushed::Clean));
        }
        if st.base.is_none() && !sync && !tmp.is_borrowed() {
            self.send_async(st, tmp, ver, mark(stat))?;
            return Ok(Flushed::Sent(ver));
        }
        let borrowed = tmp.is_borrowed();
        match self.commit(st, tmp, ver, mark(stat), sync, None) {
            // the staging file changed while it was sent: commit a stable copy instead
            Err(e) if borrowed && !e.refused && e.errno == libc::EINVAL => {
                let stat = sys::stat_key(st.fd.as_fd()).map_err(|e| Refusal::err(io_errno(&e)))?;
                let (tmp, ver) = self.cache.snapshot(st.fd.as_fd()).map_err(Refusal::err)?;
                self.commit(st, tmp, ver, mark(stat), sync, None)
            }
            r => r,
        }
    }

    // a new file's first commit does not wait; the ordered stream lets a following rename rely on it
    fn send_async(
        &self,
        st: &mut Staged,
        tmp: TmpBlob,
        ver: Version,
        stat: Mark,
    ) -> Result<(), Refusal> {
        let deadline = commit_deadline(ver.size);
        let (body, payload) = body_for(tmp.fd(), ver.size, None).map_err(Refusal::err)?;
        let op = Op::Commit {
            path: st.path.clone(),
            base: Expect::Absent,
            new: ver,
            perm: Some(st.perm),
            body,
            sync: false,
            mtime_ns: None,
        };
        let cell = Arc::new(Cell::default());
        let c = cell.clone();
        let ticket = self
            .pipe
            .push_with(op, payload, deadline, Box::new(move |r| c.put(r)))
            .map_err(Refusal::err)?;
        st.pending = Some(Pending {
            ticket,
            tmp,
            ver,
            stat,
            cell,
        });
        Ok(())
    }

    fn settle(&self, st: &mut Staged) -> Result<Option<Flushed>, Refusal> {
        let Some(p) = st.pending.take() else {
            return Ok(None);
        };
        let r = match p.cell.wait(commit_deadline(p.ver.size)) {
            Some(r) => r,
            None => {
                self.pipe.cancel(p.ticket);
                Err(RpcError::Timeout)
            }
        };
        match r {
            Ok(reply @ (Reply::Done { .. } | Reply::Conflict { .. })) => self
                .commit(st, p.tmp, p.ver, p.stat, false, Some(reply))
                .map(Some),
            Ok(_) => Err(Refusal::err(libc::EIO)),
            // nothing landed, so it is sent again with the backoff every other busy commit gets
            Err(RpcError::Wire(WireErr::Busy)) => {
                self.commit(st, p.tmp, p.ver, p.stat, false, None).map(Some)
            }
            Err(RpcError::Wire(w)) => Err(Refusal::err(wire_errno(w))),
            // the link dropped under the pipelined create: replay it, the host answers Done if it already landed
            Err(_) => match self.commit(st, p.tmp, p.ver, p.stat, false, None) {
                Err(e) if !e.refused => self.give_up(st, e),
                r => r.map(Some),
            },
        }
    }

    // the host's current entry at path: Some(None) when it has nothing there, None when it cannot be asked
    fn host_meta(&self, path: &RelPath) -> Option<Option<Meta>> {
        let deadline = commit_deadline(0);
        let (_, remote) = self.remote.get(deadline).ok()?;
        let op = Op::Fetch {
            path: path.clone(),
            want: None,
            have: None,
            range: Some((0, 0)),
        };
        match remote.call(op, deadline) {
            Ok(Reply::Blob { meta, .. }) => Some(Some(meta)),
            Err(RpcError::Wire(WireErr::NotFound | WireErr::Ignored)) => Some(None),
            _ => None,
        }
    }

    // a new file the host never took: the guest copy is set to whatever the host holds, or kept when that is unknown
    fn give_up<T>(&self, st: &mut Staged, e: Refusal) -> Result<T, Refusal> {
        match self.host_meta(&st.path) {
            Some(current) => Err(self.refuse(st, current, None)),
            None => Err(e),
        }
    }

    // after a rename the pipelined create is only needed to publish its blob; true when it never reached the host
    fn drain_pending(&self, st: &mut Staged, path: &RelPath) -> bool {
        let Some(p) = st.pending.take() else {
            return false;
        };
        match p.cell.wait(commit_deadline(p.ver.size)) {
            Some(Ok(Reply::Done { .. })) => {
                let _ = self.cache.publish(p.tmp, Some(path));
                false
            }
            Some(Ok(_)) => false,
            Some(Err(_)) | None => true,
        }
    }

    fn send(
        &self,
        mk: &dyn Fn(Option<Body>) -> Option<Op>,
        content: Option<(BorrowedFd<'_>, u64, Option<&BlobRef>)>,
        deadline: Instant,
    ) -> Result<Reply, i32> {
        let (body, payload) = match content {
            Some((fd, size, base)) => {
                let (b, p) = body_for(fd, size, base)?;
                (Some(b), p)
            }
            None => (None, Payload::None),
        };
        // background warming yields the link while a write waits on the host
        let _busy = self.cache.gate().enter();
        let op = mk(body).ok_or(libc::EINVAL)?;
        // the pipe resends after a reconnect and on busy, in place
        let ticket = self.pipe.push(op, payload, Tag::Sync, deadline)?;
        self.pipe.wait(ticket, deadline).map_err(|e| rpc_errno(&e))
    }

    fn commit(
        &self,
        st: &mut Staged,
        mut tmp: TmpBlob,
        mut ver: Version,
        mut stat: Mark,
        sync: bool,
        mut first: Option<Reply>,
    ) -> Result<Flushed, Refusal> {
        let mut merged = false;
        let mut conflicts = 0;
        loop {
            let reply = match first.take() {
                Some(r) => r,
                None => {
                    let (path, base, perm) = (
                        st.path.clone(),
                        st.base.map_or(Expect::Absent, Expect::Is),
                        st.base.is_none().then_some(st.perm),
                    );
                    let mk = move |b: Option<Body>| {
                        Some(Op::Commit {
                            path: path.clone(),
                            base,
                            new: ver,
                            perm,
                            body: b?,
                            sync,
                            mtime_ns: None,
                        })
                    };
                    self.send(
                        &mk,
                        Some((tmp.fd(), ver.size, st.base_ref.as_ref())),
                        commit_deadline(ver.size),
                    )
                    .map_err(Refusal::err)?
                }
            };
            match reply {
                Reply::Done { meta } => {
                    // sent in place, so it is stamped once sent, as a copy is once copied
                    if tmp.is_borrowed() && sys::stat_key(st.fd.as_fd()).is_ok_and(|k| k == stat.0)
                    {
                        stat = mark(stat.0);
                    }
                    st.unpublished = tmp.is_borrowed().then_some(ver);
                    let _ = self.cache.publish(tmp, Some(&st.path));
                    st.base = Some(ver);
                    st.base_ref = self.cache.get(&ver.hash);
                    st.synced = Some(stat);
                    if merged {
                        self.say(NoticeKind::Merged, &st.path);
                    }
                    return Ok(Flushed::Committed { meta, merged });
                }
                Reply::Conflict { current, inline } => {
                    let base = st.base.map_or(Expect::Absent, Expect::Is);
                    match self.merge_next(
                        &st.path,
                        base,
                        st.base_ref.as_ref(),
                        &tmp,
                        ver.size,
                        current,
                        inline,
                        &mut conflicts,
                    ) {
                        Next::Merged(m, theirs) => {
                            overwrite(st.fd.as_fd(), &m).map_err(Refusal::err)?;
                            (tmp, ver) = self.cache.tmp_from_bytes(&m).map_err(Refusal::err)?;
                            stat = mark(
                                sys::stat_key(st.fd.as_fd())
                                    .map_err(|e| Refusal::err(io_errno(&e)))?,
                            );
                            st.base = Some(theirs);
                            st.base_ref = self.cache.get(&theirs.hash);
                            merged = true;
                        }
                        Next::Refuse(current, theirs) => {
                            drop(tmp);
                            return Err(self.refuse(st, current, theirs));
                        }
                    }
                }
                Reply::Blob { .. } | Reply::Blobs { .. } | Reply::Hashes { .. } => {
                    return Err(Refusal::err(libc::EIO));
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn merge_next(
        &self,
        path: &RelPath,
        base: Expect,
        base_ref: Option<&BlobRef>,
        ours: &TmpBlob,
        ours_size: u64,
        current: Option<Meta>,
        inline: Option<Bytes>,
        conflicts: &mut u32,
    ) -> Next {
        *conflicts += 1;
        let theirs = self.theirs(path, current.as_ref(), inline);
        if *conflicts > MERGE_TRIES {
            return Next::Refuse(current, theirs);
        }
        let b = match base {
            Expect::Absent => Some(Vec::new()),
            Expect::Is(v) => self.base_bytes(path, v, base_ref),
            Expect::Dir | Expect::Any | Expect::Ver(_) => None,
        };
        let o = read_len(ours.fd(), ours_size, MERGE_MAX).ok();
        match (
            resolve(
                b.as_deref(),
                o.as_deref(),
                theirs.as_ref().map(|t| t.1.as_slice()),
            ),
            theirs,
        ) {
            (Resolve::Merged(m), Some((tv, _))) => Next::Merged(m, tv),
            (_, theirs) => Next::Refuse(current, theirs),
        }
    }

    // the host's current content, verified and cached; None when it is not a mergeable file
    fn theirs(
        &self,
        path: &RelPath,
        current: Option<&Meta>,
        inline: Option<Bytes>,
    ) -> Option<(Version, Vec<u8>)> {
        let cur = current.filter(|m| m.kind == Kind::File)?;
        let v = cur.version()?;
        if let Some(b) = inline
            && b.0.len() as u64 == v.size
            && blake3::hash(&b.0).as_bytes() == &v.hash
        {
            let _ = self.cache.insert_bytes(&v.hash, &b.0, Some(path));
            return (v.size <= MERGE_MAX).then_some((v, b.0));
        }
        if v.size > MERGE_MAX {
            return None;
        }
        let r = self
            .cache
            .fetch_whole(&v.hash, path, v.size, fetch_deadline(v.size))
            .ok()?;
        Some((v, r.read_all(MERGE_MAX).ok()?))
    }

    fn base_bytes(&self, path: &RelPath, v: Version, r: Option<&BlobRef>) -> Option<Vec<u8>> {
        if v.size > MERGE_MAX {
            return None;
        }
        if let Some(b) = r.filter(|b| b.hash() == &v.hash && b.is_complete()) {
            return b.read_all(MERGE_MAX).ok();
        }
        let b = self
            .cache
            .fetch_whole(&v.hash, path, v.size, fetch_deadline(v.size))
            .ok()?;
        b.read_all(MERGE_MAX).ok()
    }

    // the later edit loses: staging takes the host's content, nothing of ours is kept anywhere
    fn refuse(
        &self,
        st: &mut Staged,
        current: Option<Meta>,
        theirs: Option<(Version, Vec<u8>)>,
    ) -> Refusal {
        st.refused = true;
        st.base_ref = None;
        st.pending = None;
        st.synced = None;
        let restored = match &theirs {
            Some((v, b)) => {
                let _ = self.cache.insert_bytes(&v.hash, b, Some(&st.path));
                overwrite(st.fd.as_fd(), b).is_ok()
            }
            None => false,
        };
        if !restored {
            let _ = rustix::fs::ftruncate(&*st.fd, 0);
        }
        self.say(NoticeKind::Refused, &st.path);
        Refusal {
            errno: REFUSED,
            refused: true,
            current,
        }
    }

    fn refuse_path(&self, path: &RelPath, current: Option<Meta>, inline: Option<Bytes>) -> Refusal {
        if let (Some(v), Some(b)) = (current.as_ref().and_then(Meta::version), inline)
            && blake3::hash(&b.0).as_bytes() == &v.hash
        {
            let _ = self.cache.insert_bytes(&v.hash, &b.0, Some(path));
        }
        self.say(NoticeKind::Refused, path);
        Refusal {
            errno: REFUSED,
            refused: true,
            current,
        }
    }

    fn load_ours(&self, at: &RelPath, v: Option<Version>) -> Option<(TmpBlob, Version)> {
        let v = v?;
        if v.size > MERGE_MAX {
            return None;
        }
        let b = self
            .cache
            .fetch_whole(&v.hash, at, v.size, fetch_deadline(v.size))
            .ok()?;
        self.cache.tmp_from_bytes(&b.read_all(MERGE_MAX).ok()?).ok()
    }

    // writes `content` (or moves `from`) onto `to` under CAS, merging into the host's version on conflict
    fn cas_write(
        &self,
        to: &RelPath,
        target: Target<'_>,
        ours_ver: Option<Version>,
        mut to_expect: Expect,
        mut content: Option<(TmpBlob, Version)>,
    ) -> Result<Written, Refusal> {
        let mut conflicts = 0;
        let mut merged = None;
        loop {
            let ver = content.as_ref().map(|c| c.1);
            let te = to_expect;
            let mk = move |b: Option<Body>| match target {
                Target::Rename { from, from_expect } => Some(Op::Rename {
                    from: from.clone(),
                    to: to.clone(),
                    from_expect,
                    to_expect: te,
                    body: ver.zip(b),
                }),
                Target::Commit { perm } => {
                    let (new, body) = ver.zip(b)?;
                    Some(Op::Commit {
                        path: to.clone(),
                        base: te,
                        new,
                        perm,
                        body,
                        sync: false,
                        mtime_ns: None,
                    })
                }
            };
            let src = content.as_ref().map(|(t, v)| (t.fd(), v.size, None));
            let reply = self
                .send(&mk, src, commit_deadline(ver.map_or(0, |v| v.size)))
                .map_err(Refusal::err)?;
            match reply {
                Reply::Done { meta } => {
                    let ver = match content {
                        Some((t, v)) => {
                            let _ = self.cache.publish(t, Some(to));
                            Some(v)
                        }
                        None => ours_ver,
                    };
                    if merged.is_some() {
                        self.say(NoticeKind::Merged, to);
                    }
                    return Ok(Written { meta, ver, merged });
                }
                Reply::Conflict { current, inline } => {
                    if content.is_none() {
                        let from = match target {
                            Target::Rename { from, .. } => from,
                            Target::Commit { .. } => to,
                        };
                        match self.load_ours(from, ours_ver) {
                            Some(c) => content = Some(c),
                            None => return Err(self.refuse_path(to, current, inline)),
                        }
                    }
                    let Some((tmp, v)) = content.as_ref() else {
                        return Err(Refusal::err(libc::EIO));
                    };
                    match self.merge_next(
                        to,
                        to_expect,
                        None,
                        tmp,
                        v.size,
                        current,
                        inline,
                        &mut conflicts,
                    ) {
                        Next::Merged(m, tv) => {
                            content = Some(self.cache.tmp_from_bytes(&m).map_err(Refusal::err)?);
                            merged = Some(m);
                            to_expect = Expect::Is(tv);
                        }
                        Next::Refuse(current, theirs) => {
                            if let Some((v, b)) = &theirs {
                                let _ = self.cache.insert_bytes(&v.hash, b, Some(to));
                            }
                            self.say(NoticeKind::Refused, to);
                            return Err(Refusal {
                                errno: REFUSED,
                                refused: true,
                                current,
                            });
                        }
                    }
                }
                Reply::Blob { .. } | Reply::Blobs { .. } | Reply::Hashes { .. } => {
                    return Err(Refusal::err(libc::EIO));
                }
            }
        }
    }

    // on refusal the caller removes `from` locally; the host copy of a pipelined tmp is removed here
    pub fn rename(&self, r: RenameReq<'_>) -> Result<Meta, Refusal> {
        let entry = r.staging.and_then(|id| self.entry(id));
        let mut guard = entry.as_ref().map(|e| lock(e));
        if let Some(st) = guard.as_deref_mut() {
            return self.rename_staged(st, &r);
        }
        if let Some((fd, perm)) = r.local {
            let (t, v) = self.cache.snapshot(fd).map_err(Refusal::err)?;
            let perm = (r.to_expect == Expect::Absent).then_some(perm);
            return self
                .cas_write(
                    r.to,
                    Target::Commit { perm },
                    None,
                    r.to_expect,
                    Some((t, v)),
                )
                .map(|w| w.meta);
        }
        let ours = match r.from_expect {
            Expect::Is(v) => Some(v),
            _ => None,
        };
        let out = self.cas_write(
            r.to,
            Target::Rename {
                from: r.from,
                from_expect: r.from_expect,
            },
            ours,
            r.to_expect,
            None,
        );
        if let (Err(e), true, Some(v)) = (&out, r.discard, ours)
            && e.refused
        {
            let from = r.from.clone();
            let rm = move |_: Option<Body>| {
                Some(Op::Remove {
                    path: from.clone(),
                    expect: Expect::Is(v),
                })
            };
            let _ = self.send(&rm, None, commit_deadline(0));
        }
        out.map(|w| w.meta)
    }

    fn rename_staged(&self, st: &mut Staged, r: &RenameReq<'_>) -> Result<Meta, Refusal> {
        if st.refused {
            return Err(Refusal::err(REFUSED));
        }
        let stat = sys::stat_key(st.fd.as_fd()).map_err(|e| Refusal::err(io_errno(&e)))?;
        let (mut host_ver, clean) = match &st.pending {
            Some(p) => (Some(p.ver), trusted(Some(&p.stat), &stat)),
            None => (st.base, trusted(st.synced.as_ref(), &stat)),
        };
        // content the host does not have yet travels inside the rename itself
        let mut content = None;
        if !clean || host_ver.is_none() {
            let (t, v) = self
                .snap_staged(st, stat.size, true)
                .map_err(Refusal::err)?;
            if Some(v) != host_ver {
                content = Some((t, v));
            }
        }
        let mut sent = content.as_ref().map(|c| c.1);
        let mut in_place = content.as_ref().is_some_and(|c| c.0.is_borrowed());
        let from_expect = host_ver.map_or(Expect::Absent, Expect::Is);
        let mut out = self.cas_write(
            r.to,
            Target::Rename {
                from: r.from,
                from_expect,
            },
            host_ver,
            r.to_expect,
            content,
        );
        // the pipelined create this rename relied on was lost with the link: send the content inside the rename
        if self.drain_pending(st, r.from) && out.is_err() {
            let (t, v) = self.cache.snapshot(st.fd.as_fd()).map_err(Refusal::err)?;
            sent = Some(v);
            host_ver = None;
            in_place = false;
            out = self.cas_write(
                r.to,
                Target::Rename {
                    from: r.from,
                    from_expect: Expect::Absent,
                },
                None,
                r.to_expect,
                Some((t, v)),
            );
        }
        match out {
            Ok(w) => {
                st.path = r.to.clone();
                if let Some(m) = &w.merged {
                    overwrite(st.fd.as_fd(), m).map_err(Refusal::err)?;
                }
                st.base = w.ver.or(sent).or(host_ver);
                st.unpublished = match (sent, &w.merged) {
                    (None, _) => st.unpublished,
                    (Some(_), None) if in_place => w.ver,
                    _ => None,
                };
                st.base_ref = st.base.and_then(|v| self.cache.get(&v.hash));
                st.synced = if w.merged.is_some() {
                    None
                } else {
                    Some(mark(stat))
                };
                Ok(w.meta)
            }
            Err(e) => {
                if e.refused {
                    if let Some(v) = host_ver {
                        let from = r.from.clone();
                        let rm = move |_: Option<Body>| {
                            Some(Op::Remove {
                                path: from.clone(),
                                expect: Expect::Is(v),
                            })
                        };
                        let _ = self.send(&rm, None, commit_deadline(0));
                    }
                    st.refused = true;
                    st.base_ref = None;
                    st.synced = None;
                    let _ = rustix::fs::ftruncate(&*st.fd, 0);
                }
                Err(e)
            }
        }
    }

    fn simple(&self, path: &RelPath, op: Op) -> Result<Meta, Refusal> {
        let mk = move |_: Option<Body>| Some(op.clone());
        match self
            .send(&mk, None, commit_deadline(0))
            .map_err(Refusal::err)?
        {
            Reply::Done { meta } => Ok(meta),
            Reply::Conflict { current, inline } => Err(self.refuse_path(path, current, inline)),
            Reply::Blob { .. } | Reply::Blobs { .. } | Reply::Hashes { .. } => {
                Err(Refusal::err(libc::EIO))
            }
        }
    }

    pub fn remove(&self, path: &RelPath, expect: Expect) -> Result<Meta, Refusal> {
        self.simple(
            path,
            Op::Remove {
                path: path.clone(),
                expect,
            },
        )
    }

    pub fn setattr(
        &self,
        path: &RelPath,
        expect: Expect,
        perm: Option<u16>,
        mtime_ns: Option<i64>,
    ) -> Result<Meta, Refusal> {
        self.simple(
            path,
            Op::SetAttr {
                path: path.clone(),
                expect,
                perm,
                mtime_ns,
            },
        )
    }

    pub fn mkdir(&self, path: &RelPath, perm: u16) -> Result<Meta, i32> {
        self.simple(
            path,
            Op::Mk {
                path: path.clone(),
                what: Mk::Dir { perm },
            },
        )
        .map_err(|e| if e.refused { libc::EEXIST } else { e.errno })
    }

    pub fn symlink(&self, path: &RelPath, target: &LinkTarget) -> Result<Meta, i32> {
        self.simple(
            path,
            Op::Mk {
                path: path.clone(),
                what: Mk::Symlink {
                    target: target.clone(),
                },
            },
        )
        .map_err(|e| if e.refused { libc::EEXIST } else { e.errno })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::cache::{CacheConfig, Done, Remote};
    use crate::guest::tree::{GTree, NodeId};
    use crate::net::rpc::ChunkSink;
    use crate::proto::{Change, ReqId, Seq, VerKey};
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct Script {
        replies: Mutex<VecDeque<Result<Reply, RpcError>>>,
        ops: Mutex<Vec<Op>>,
    }

    impl Script {
        fn next(&self, op: Op) -> Result<Reply, RpcError> {
            lock(&self.ops).push(op);
            lock(&self.replies)
                .pop_front()
                .unwrap_or(Err(RpcError::Closed))
        }
    }

    impl Remote for Script {
        fn call(&self, op: Op, _d: Instant) -> Result<Reply, RpcError> {
            self.next(op)
        }
        fn call_stream(
            &self,
            op: Op,
            _s: Box<dyn ChunkSink>,
            _d: Instant,
        ) -> Result<Reply, RpcError> {
            self.next(op)
        }
        fn submit(&self, op: Op, done: Done) -> Result<ReqId, RpcError> {
            done(self.next(op));
            Ok(1)
        }
        fn submit_stream(
            &self,
            op: Op,
            _s: Box<dyn ChunkSink>,
            done: Done,
        ) -> Result<ReqId, RpcError> {
            done(self.next(op));
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

    struct Rig {
        d: Dir,
        cache: Arc<BlobCache>,
        script: Arc<Script>,
        w: Writer,
        notes: Arc<Mutex<Vec<Notice>>>,
    }

    fn rig(tag: &str) -> Rig {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "csync-write-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        let slot = RemoteSlot::new();
        let script = Arc::new(Script::default());
        slot.set(Some(script.clone() as Arc<dyn Remote>));
        let (landed, _) = crossbeam_channel::unbounded();
        let pipe = Pipe::new(slot.clone(), landed).unwrap();
        let cache = Arc::new(
            BlobCache::open(
                &CacheConfig {
                    dir: p.clone(),
                    cap: Some(1 << 30),
                },
                slot,
            )
            .unwrap(),
        );
        let notes = Arc::new(Mutex::new(Vec::new()));
        let n = notes.clone();
        let w = Writer::new(
            cache.clone(),
            pipe,
            Arc::new(move |x: Notice| lock(&n).push(x)),
        );
        Rig {
            d: Dir(p),
            cache,
            script,
            w,
            notes,
        }
    }

    fn ver(b: &[u8]) -> Version {
        Version {
            hash: *blake3::hash(b).as_bytes(),
            size: b.len() as u64,
        }
    }

    fn meta(v: Version) -> Meta {
        Meta {
            kind: Kind::File,
            perm: 0o644,
            size: v.size,
            mtime_ns: 1,
            ctime_ns: 1,
            hash: Some(v.hash),
            link: None,
            git_ro: false,
        }
    }

    fn files(p: &Path) -> usize {
        std::fs::read_dir(p).map_or(0, |d| {
            d.filter_map(Result::ok)
                .map(|e| {
                    if e.path().is_dir() {
                        files(&e.path())
                    } else {
                        1
                    }
                })
                .sum()
        })
    }

    fn staged(fd: &OwnedFd) -> Vec<u8> {
        let len = sys::stat_key(fd.as_fd()).unwrap().size;
        read_len(fd.as_fd(), len, 1 << 20).unwrap()
    }

    fn open_edit(r: &Rig, p: &RelPath, base: &[u8], ours: &[u8]) -> (u32, Arc<OwnedFd>) {
        let vb = ver(base);
        r.cache.insert_bytes(&vb.hash, base, Some(p)).unwrap();
        let (id, fd) =
            r.w.open_for_write(OpenW {
                path: p,
                base: Some(vb),
                perm: 0o644,
                trunc: false,
                staging: None,
            })
            .unwrap();
        assert_eq!(staged(&fd), base);
        overwrite(fd.as_fd(), ours).unwrap();
        (id, fd)
    }

    #[test]
    fn conflict_merges_and_recommits_on_the_new_base() {
        let r = rig("merge");
        let p = RelPath::new("src/lib.rs").unwrap();
        let (base, ours, theirs) = (
            b"one\ntwo\nthree\nfour\n",
            b"ONE\ntwo\nthree\nfour\n",
            b"one\ntwo\nthree\nFOUR\n",
        );
        let merged = b"ONE\ntwo\nthree\nFOUR\n";
        let (id, fd) = open_edit(&r, &p, base, ours);
        let (vb, vt, vm) = (ver(base), ver(theirs), ver(merged));
        lock(&r.script.replies).push_back(Ok(Reply::Conflict {
            current: Some(meta(vt)),
            inline: Some(Bytes(theirs.to_vec())),
        }));
        lock(&r.script.replies).push_back(Ok(Reply::Done { meta: meta(vm) }));

        assert_eq!(
            r.w.flush(id, false),
            Ok(Flushed::Committed {
                meta: meta(vm),
                merged: true
            })
        );
        {
            let ops = lock(&r.script.ops);
            assert_eq!(ops.len(), 2);
            match &ops[0] {
                Op::Commit { base, new, .. } => {
                    assert_eq!((*base, *new), (Expect::Is(vb), ver(ours)))
                }
                o => panic!("unexpected {o:?}"),
            }
            match &ops[1] {
                Op::Commit {
                    base, new, body, ..
                } => {
                    assert_eq!((*base, *new), (Expect::Is(vt), vm));
                    assert_eq!(*body, Body::Inline(Bytes(merged.to_vec())));
                }
                o => panic!("unexpected {o:?}"),
            }
        }
        assert_eq!(staged(&fd), merged);
        assert!(r.cache.contains(&vm.hash) && r.cache.contains(&vt.hash));
        assert_eq!(
            *lock(&r.notes),
            vec![Notice {
                kind: NoticeKind::Merged,
                path: p.clone()
            }]
        );
        assert_eq!(r.w.release(id), None);
        assert_eq!(lock(&r.script.ops).len(), 2);
        assert_eq!(files(&r.d.0.join("tmp")), 0);
    }

    #[test]
    fn unmergeable_conflict_is_refused_and_leaves_nothing() {
        let r = rig("refuse");
        let p = RelPath::new("notes.txt").unwrap();
        let (base, ours, theirs) = (
            b"one\ntwo\nthree\n",
            b"one\nours\nthree\n",
            b"one\ntheirs\nthree\n",
        );
        let (id, fd) = open_edit(&r, &p, base, ours);
        let vt = ver(theirs);
        lock(&r.script.replies).push_back(Ok(Reply::Conflict {
            current: Some(meta(vt)),
            inline: Some(Bytes(theirs.to_vec())),
        }));

        assert_eq!(
            r.w.flush(id, false),
            Err(Refusal {
                errno: libc::ECANCELED,
                refused: true,
                current: Some(meta(vt))
            })
        );
        assert_eq!(lock(&r.script.ops).len(), 1);
        assert_eq!(
            *lock(&r.notes),
            vec![Notice {
                kind: NoticeKind::Refused,
                path: p.clone()
            }]
        );
        assert!(r.cache.contains(&vt.hash));
        assert!(!r.cache.contains(&ver(ours).hash));
        assert_eq!(staged(&fd), theirs);
        assert_eq!(files(&r.d.0.join("tmp")), 0);
        assert_eq!(files(&r.d.0.join("blobs")), 2);

        assert_eq!(
            r.w.flush(id, false).map_err(|e| e.errno),
            Err(libc::ECANCELED)
        );
        assert_eq!(r.w.release(id), None);
        assert_eq!(lock(&r.script.ops).len(), 1);
        assert_eq!(
            *lock(&r.notes),
            vec![Notice {
                kind: NoticeKind::Refused,
                path: p
            }]
        );
        assert_eq!(files(&r.d.0.join("tmp")), 0);
        assert_eq!(files(&r.d.0.join("blobs")), 2);
    }

    #[test]
    fn repeated_conflicts_stop_at_the_retry_bound() {
        let r = rig("bound");
        let p = RelPath::new("a.txt").unwrap();
        let (id, _fd) = open_edit(
            &r,
            &p,
            b"a\nb\nc\nd\ne\nf\ng\nh\ni\n",
            b"A\nb\nc\nd\ne\nf\ng\nh\ni\n",
        );
        let rounds: [&[u8]; 4] = [
            b"a\nb\nc\nd\ne\nf\ng\nh\nI\n",
            b"a\nb\nc\nd\ne\nf\nG\nh\nI\n",
            b"a\nb\nc\nd\nE\nf\nG\nh\nI\n",
            b"a\nb\nC\nd\nE\nf\nG\nh\nI\n",
        ];
        for t in rounds {
            lock(&r.script.replies).push_back(Ok(Reply::Conflict {
                current: Some(meta(ver(t))),
                inline: Some(Bytes(t.to_vec())),
            }));
        }
        let e = r.w.flush(id, false).unwrap_err();
        assert!(e.refused && e.errno == libc::ECANCELED);
        assert_eq!(lock(&r.script.ops).len(), MERGE_TRIES as usize + 1);
        assert_eq!(files(&r.d.0.join("tmp")), 0);
    }

    // a rename that took a pipelined create's answer must not leave the last release waiting out its deadline
    #[test]
    fn ready_sees_an_answer_already_taken() {
        let c = Cell::default();
        c.put(Err(RpcError::Closed));
        assert!(c.wait(Instant::now()).is_some());
        let t = Instant::now();
        c.ready(t + Duration::from_secs(5));
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    // busy means the host caught its own writer mid-flight and changed nothing: the save goes again
    #[test]
    fn busy_commit_is_sent_again_not_surfaced() {
        let r = rig("busy");
        let p = RelPath::new("busy.txt").unwrap();
        let (base, ours) = (b"one\ntwo\n", b"ONE\ntwo\n");
        let (id, _fd) = open_edit(&r, &p, base, ours);
        let (vb, vo) = (ver(base), ver(ours));
        for _ in 0..2 {
            lock(&r.script.replies).push_back(Err(RpcError::Wire(WireErr::Busy)));
        }
        lock(&r.script.replies).push_back(Ok(Reply::Done { meta: meta(vo) }));
        assert_eq!(
            r.w.flush(id, false),
            Ok(Flushed::Committed {
                meta: meta(vo),
                merged: false
            })
        );
        let ops = lock(&r.script.ops);
        assert_eq!(ops.len(), 3);
        for op in ops.iter() {
            match op {
                Op::Commit { base: b, new, .. } => assert_eq!((*b, *new), (Expect::Is(vb), vo)),
                o => panic!("unexpected {o:?}"),
            }
        }
    }

    // the pipelined create of a new file is replayed the same way once its busy answer arrives
    #[test]
    fn busy_pipelined_create_is_sent_again() {
        let r = rig("busynew");
        let p = RelPath::new("new.txt").unwrap();
        let (id, fd) =
            r.w.open_for_write(OpenW {
                path: &p,
                base: None,
                perm: 0o644,
                trunc: false,
                staging: None,
            })
            .unwrap();
        let body = b"fresh\n";
        overwrite(fd.as_fd(), body).unwrap();
        let v = ver(body);
        lock(&r.script.replies).push_back(Err(RpcError::Wire(WireErr::Busy)));
        lock(&r.script.replies).push_back(Ok(Reply::Done { meta: meta(v) }));
        assert_eq!(r.w.flush(id, false), Ok(Flushed::Sent(v)));
        assert_eq!(
            r.w.release(id),
            Some(Ok(Flushed::Committed {
                meta: meta(v),
                merged: false
            }))
        );
        let ops = lock(&r.script.ops);
        assert_eq!(ops.len(), 2);
        assert!(ops.iter().all(|o| matches!(o, Op::Commit {
            base: Expect::Absent,
            new,
            ..
        } if *new == v)));
    }

    fn held_truncate(r: &Rig, p: &RelPath, base: &[u8]) -> u32 {
        let vb = ver(base);
        r.cache.insert_bytes(&vb.hash, base, Some(p)).unwrap();
        let (id, fd) =
            r.w.open_for_write(OpenW {
                path: p,
                base: Some(vb),
                perm: 0o644,
                trunc: true,
                staging: None,
            })
            .unwrap();
        r.w.defer(id);
        assert!(staged(&fd).is_empty());
        id
    }

    #[test]
    fn held_truncate_folds_into_the_next_write() {
        let r = rig("hold");
        let p = RelPath::new("out.txt").unwrap();
        let base = b"old\ncontent\n";
        let id = held_truncate(&r, &p, base);
        let (again, fd) =
            r.w.open_for_write(OpenW {
                path: &p,
                base: Some(ver(base)),
                perm: 0o644,
                trunc: false,
                staging: Some(id),
            })
            .unwrap();
        assert_eq!(again, id);
        overwrite(fd.as_fd(), b"new\n").unwrap();
        let vn = ver(b"new\n");
        lock(&r.script.replies).push_back(Ok(Reply::Done { meta: meta(vn) }));
        assert_eq!(
            r.w.flush(id, false),
            Ok(Flushed::Committed {
                meta: meta(vn),
                merged: false
            })
        );
        assert_eq!(r.w.end_deferred(id), None);
        assert_eq!(r.w.release(id), None);
        assert!(r.w.staging_fd(id).is_none());
        let ops = lock(&r.script.ops);
        assert_eq!(ops.len(), 1, "the truncate and the write are one commit");
        match &ops[0] {
            Op::Commit { base: b, new, .. } => assert_eq!((*b, *new), (Expect::Is(ver(base)), vn)),
            o => panic!("unexpected {o:?}"),
        }
    }

    #[test]
    fn held_truncate_alone_commits_empty_and_cancel_sends_nothing() {
        let r = rig("hold-alone");
        let p = RelPath::new("log.txt").unwrap();
        let id = held_truncate(&r, &p, b"some lines\n");
        let ve = ver(b"");
        lock(&r.script.replies).push_back(Ok(Reply::Done { meta: meta(ve) }));
        assert_eq!(
            r.w.end_deferred(id),
            Some(Ok(Flushed::Committed {
                meta: meta(ve),
                merged: false
            }))
        );
        assert!(r.w.staging_fd(id).is_none());
        match &lock(&r.script.ops)[..] {
            [Op::Commit { new, body, .. }] => assert_eq!((*new, body), (ve, &Body::Empty)),
            o => panic!("unexpected {o:?}"),
        }

        let q = RelPath::new("gone.txt").unwrap();
        let id = held_truncate(&r, &q, b"x\n");
        r.w.cancel_deferred(id);
        assert!(r.w.staging_fd(id).is_none());
        assert_eq!(r.w.end_deferred(id), None);
        assert_eq!(lock(&r.script.ops).len(), 1);
    }

    #[test]
    fn large_commit_reads_the_staging_file_in_place() {
        let r = rig("in-place");
        let p = RelPath::new("big.bin").unwrap();
        let base: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let ours: Vec<u8> = (0..300_000u32).map(|i| (i % 241) as u8).collect();
        let (id, fd) = open_edit(&r, &p, &base, &ours);
        let vo = ver(&ours);
        lock(&r.script.replies).push_back(Ok(Reply::Done { meta: meta(vo) }));
        assert_eq!(
            r.w.flush(id, false),
            Ok(Flushed::Committed {
                meta: meta(vo),
                merged: false
            })
        );
        match &lock(&r.script.ops)[..] {
            [Op::Commit { new, body, .. }] => {
                assert_eq!((*new, body), (vo, &Body::Stream { len: vo.size }))
            }
            o => panic!("unexpected {o:?}"),
        }
        assert_eq!(files(&r.d.0.join("tmp")), 0, "no snapshot copy was made");
        assert!(!r.cache.contains(&vo.hash));
        assert_eq!(r.w.release(id), None);
        assert!(
            r.cache.contains(&vo.hash),
            "the released staging file became the blob"
        );
        let b = r.cache.get(&vo.hash).unwrap();
        assert_eq!(b.read_all(1 << 20).unwrap(), ours);
        assert_eq!(staged(&fd), ours);
        assert_eq!(lock(&r.script.ops).len(), 1);
    }

    #[test]
    fn resolve_decisions() {
        fn s(b: &[u8]) -> Option<&[u8]> {
            Some(b)
        }
        assert_eq!(
            resolve(s(b"a\nb\nc\n"), s(b"A\nb\nc\n"), s(b"a\nb\nC\n")),
            Resolve::Merged(b"A\nb\nC\n".to_vec())
        );
        assert_eq!(resolve(s(b"a\n"), s(b"b\n"), s(b"c\n")), Resolve::Refuse);
        assert_eq!(resolve(s(b"a\0"), s(b"b\0"), s(b"a\0")), Resolve::Refuse);
        assert_eq!(resolve(None, s(b"x\n"), s(b"y\n")), Resolve::Refuse);
        assert_eq!(resolve(s(b""), s(b"x\n"), None), Resolve::Refuse);
    }

    fn pending_meta(size: u64) -> Meta {
        Meta {
            hash: None,
            size,
            ..meta(ver(b""))
        }
    }

    fn tree_with(m: Meta, host_ver: Seq) -> (GTree, NodeId) {
        let mut t = GTree::new();
        t.set_version(9, 1);
        let p = RelPath::new("a.rs").unwrap();
        let up = Change::Upsert {
            path: p.clone(),
            meta: m,
            ver: host_ver,
        };
        t.apply(&up, &mut Vec::new());
        let id = t.resolve(&p).unwrap();
        (t, id)
    }

    #[test]
    fn dest_expect_holds_a_pending_file_to_its_host_entry() {
        let (t, id) = tree_with(pending_meta(7), 5);
        let key = VerKey {
            index: 9,
            ver: 5,
            size: 7,
        };
        assert_eq!(dest_expect(t.get(id), 9), Expect::Ver(key));
        assert_eq!(node_expect(t.get(id).unwrap(), 9), Expect::Ver(key));
    }

    #[test]
    fn dest_expect_prefers_the_version_last_served_over_a_pending_one() {
        let (mut t, id) = tree_with(pending_meta(7), 5);
        let served = ver(b"served");
        t.get_mut(id).unwrap().read_ver = Some(served);
        assert_eq!(dest_expect(t.get(id), 9), Expect::Is(served));
    }

    #[test]
    fn dest_expect_keeps_its_meaning_for_known_and_absent_nodes() {
        let v = ver(b"known");
        let (mut t, id) = tree_with(meta(v), 5);
        assert_eq!(dest_expect(t.get(id), 9), Expect::Is(v));
        assert_eq!(dest_expect(None, 9), Expect::Absent);
        t.get_mut(id).unwrap().vis = Vis::PendingDelete;
        assert_eq!(dest_expect(t.get(id), 9), Expect::Absent);
        let (t, id) = tree_with(
            Meta {
                kind: Kind::Dir,
                hash: None,
                ..meta(v)
            },
            5,
        );
        assert_eq!(dest_expect(t.get(id), 9), Expect::Dir);
    }

    #[test]
    fn a_file_only_this_guest_has_is_not_held_to_a_host_version() {
        let (t, id) = tree_with(pending_meta(0), 0);
        assert_eq!(dest_expect(t.get(id), 9), Expect::Any);
    }

    #[test]
    fn simple_mutations_reach_the_host_in_call_order() {
        let r = rig("order");
        let d = RelPath::new("d").unwrap();
        let l = RelPath::new("l").unwrap();
        let f = RelPath::new("f").unwrap();
        for _ in 0..4 {
            lock(&r.script.replies).push_back(Ok(Reply::Done {
                meta: meta(ver(b"")),
            }));
        }
        r.w.mkdir(&d, 0o755).unwrap();
        r.w.symlink(&l, &LinkTarget::new("d").unwrap()).unwrap();
        r.w.setattr(&f, Expect::Any, Some(0o600), None).unwrap();
        r.w.remove(&f, Expect::Any).unwrap();
        match &lock(&r.script.ops)[..] {
            [
                Op::Mk {
                    what: Mk::Dir { .. },
                    ..
                },
                Op::Mk {
                    what: Mk::Symlink { .. },
                    ..
                },
                Op::SetAttr { .. },
                Op::Remove { .. },
            ] => {}
            o => panic!("unexpected {o:?}"),
        }
    }

    #[test]
    fn a_busy_mutation_is_sent_again_before_the_next_one() {
        let r = rig("busy-mk");
        let d = RelPath::new("d").unwrap();
        let f = RelPath::new("f").unwrap();
        lock(&r.script.replies).push_back(Err(RpcError::Wire(WireErr::Busy)));
        for _ in 0..2 {
            lock(&r.script.replies).push_back(Ok(Reply::Done {
                meta: meta(ver(b"")),
            }));
        }
        r.w.mkdir(&d, 0o755).unwrap();
        r.w.remove(&f, Expect::Any).unwrap();
        match &lock(&r.script.ops)[..] {
            [Op::Mk { .. }, Op::Mk { .. }, Op::Remove { .. }] => {}
            o => panic!("unexpected {o:?}"),
        }
    }
}
