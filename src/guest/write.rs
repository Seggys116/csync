use super::cache::{
    BlobCache, BlobRef, DELTA_CAP, Done, Remote, RemoteSlot, TmpBlob, WAIT, io_errno, lock,
    pread_full, pwrite_all, read_len, rpc_errno, wire_errno,
};
use super::tree::{GNode, Vis};
use crate::delta;
use crate::index::tree::StatKey;
use crate::merge::merge3;
use crate::net::rpc::RpcError;
use crate::proto::{
    Body, Bytes, CHUNK_MAX, DELTA_MIN, DeltaOp, Expect, INLINE_MAX, Kind, LinkTarget, MERGE_MAX,
    Meta, Mk, Notice, NoticeKind, Op, RelPath, Reply, ReqId, Version, WireErr,
};
use crate::sys;
use rustc_hash::FxHashMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MERGE_TRIES: u32 = 3;
pub const REFUSED: i32 = libc::ECANCELED;
const RACY_NS: i64 = 100_000_000;

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

// the CAS expectation for a rename target: the version last served to an open of it, else its current one
pub fn dest_expect(node: Option<&GNode>) -> Expect {
    match node {
        None => Expect::Absent,
        Some(n) if n.vis == Vis::PendingDelete => Expect::Absent,
        Some(n) => match n.meta.kind {
            Kind::Dir => Expect::Dir,
            Kind::Symlink => Expect::Any,
            Kind::File => n
                .read_ver
                .or_else(|| n.meta.version())
                .map_or(Expect::Any, Expect::Is),
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
}

impl Cell {
    fn put(&self, r: Result<Reply, RpcError>) {
        *lock(&self.r) = Some(r);
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
        while g.is_none() {
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
    id: ReqId,
    remote: Arc<dyn Remote>,
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
    handles: u32,
    refused: bool,
}

#[derive(Default)]
struct Table {
    map: FxHashMap<u32, Arc<Mutex<Staged>>>,
    next: u32,
}

enum Chunks<'a> {
    None,
    File {
        fd: BorrowedFd<'a>,
        len: u64,
    },
    Literals {
        new: Vec<u8>,
        ops: Vec<DeltaOp>,
        data_len: u64,
    },
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

fn body_for<'a>(
    fd: BorrowedFd<'a>,
    size: u64,
    base: Option<&BlobRef>,
) -> Result<(Body, Chunks<'a>), i32> {
    if size == 0 {
        return Ok((Body::Empty, Chunks::None));
    }
    if size <= INLINE_MAX as u64 {
        return Ok((
            Body::Inline(Bytes(read_len(fd, size, INLINE_MAX as u64)?)),
            Chunks::None,
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
                Chunks::Literals {
                    new,
                    ops: e.ops,
                    data_len: e.data_len,
                },
            ));
        }
    }
    Ok((Body::Stream { len: size }, Chunks::File { fd, len: size }))
}

// chunk offsets count from the start of the body stream; the last chunk carries last=true
fn send_chunks(remote: &dyn Remote, id: ReqId, chunks: &Chunks<'_>) -> Result<(), RpcError> {
    match chunks {
        Chunks::None => Ok(()),
        Chunks::File { fd, len } => {
            let mut off = 0u64;
            while off < *len {
                let n = (*len - off).min(CHUNK_MAX as u64) as usize;
                let mut buf = vec![0u8; n];
                match pread_full(*fd, &mut buf, off) {
                    Ok(k) if k == n => {}
                    _ => return Err(RpcError::Wire(WireErr::Io)),
                }
                remote.send_chunk(id, off, off + n as u64 == *len, buf)?;
                off += n as u64;
            }
            Ok(())
        }
        Chunks::Literals { new, ops, data_len } => {
            let mut buf = Vec::with_capacity(CHUNK_MAX);
            let mut off = 0u64;
            for mut s in delta::literals(new, ops) {
                while !s.is_empty() {
                    let take = (CHUNK_MAX - buf.len()).min(s.len());
                    let (a, rest) = s.split_at(take);
                    buf.extend_from_slice(a);
                    s = rest;
                    if buf.len() == CHUNK_MAX {
                        let n = buf.len() as u64;
                        let full = std::mem::replace(&mut buf, Vec::with_capacity(CHUNK_MAX));
                        remote.send_chunk(id, off, off + n == *data_len, full)?;
                        off += n;
                    }
                }
            }
            if !buf.is_empty() {
                remote.send_chunk(id, off, true, buf)?;
            }
            Ok(())
        }
    }
}

fn submit_cell(
    remote: &dyn Remote,
    op: &Op,
    deadline: Instant,
) -> Result<(ReqId, Arc<Cell>), RpcError> {
    let cell = Arc::new(Cell::default());
    loop {
        let c = cell.clone();
        let done: Done = Box::new(move |r: Result<Reply, RpcError>| c.put(r));
        match remote.submit(op.clone(), done) {
            Ok(id) => return Ok((id, cell)),
            Err(RpcError::Busy) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) => return Err(e),
        }
    }
}

// precondition for every method: the paths are Synced; Local and ignored paths never reach the host
pub struct Writer {
    cache: Arc<BlobCache>,
    remote: Arc<RemoteSlot>,
    notice: NoticeFn,
    table: Mutex<Table>,
}

impl Writer {
    pub fn new(cache: Arc<BlobCache>, notice: NoticeFn) -> Self {
        let remote = cache.remote().clone();
        Self {
            cache,
            remote,
            notice,
            table: Mutex::new(Table::default()),
        }
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
            if !st.refused {
                if o.trunc {
                    rustix::fs::ftruncate(&*st.fd, 0).map_err(|e| e.raw_os_error())?;
                    st.synced = None;
                }
                st.handles += 1;
                return Ok((id, st.fd.clone()));
            }
        }
        let fd = Arc::new(self.cache.staging()?);
        let mut base_ref = None;
        let mut synced = None;
        if let Some(v) = o.base {
            if o.trunc {
                base_ref = self.cache.get(&v.hash);
            } else if v.size > 0 {
                let b = self
                    .cache
                    .fetch_whole(&v.hash, o.path, v.size, fetch_deadline(v.size))?;
                sys::clone_or_copy(b.fd(), fd.as_fd()).map_err(|e| io_errno(&e))?;
                base_ref = Some(b);
            }
            if !o.trunc || v.size == 0 {
                synced = Some(mark(sys::stat_key(fd.as_fd()).map_err(|e| io_errno(&e))?));
            }
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
        let out = if st.refused || st.handles > 0 {
            None
        } else {
            let r = match self.flush_locked(&mut st, false) {
                Ok(Flushed::Sent(_)) => self.settle(&mut st).map(|o| o.unwrap_or(Flushed::Clean)),
                r => r,
            };
            // nobody is left to retry a new file the host never took: the guest copy follows the host
            let r = match r {
                Err(e) if !e.refused && st.base.is_none() => Err(self.refuse(&mut st, None, None)),
                r => r,
            };
            (r != Ok(Flushed::Clean)).then_some(r)
        };
        let keep = st.handles > 0;
        drop(st);
        if !keep {
            lock(&self.table).map.remove(&id);
        }
        out
    }

    fn flush_locked(&self, st: &mut Staged, sync: bool) -> Result<Flushed, Refusal> {
        if st.refused {
            return Err(Refusal::err(REFUSED));
        }
        let settled = self.settle(st)?;
        let stat = sys::stat_key(st.fd.as_fd()).map_err(|e| Refusal::err(io_errno(&e)))?;
        if trusted(st.synced.as_ref(), &stat) {
            return Ok(settled.unwrap_or(Flushed::Clean));
        }
        let (tmp, ver) = self.cache.snapshot(st.fd.as_fd()).map_err(Refusal::err)?;
        if st.base == Some(ver) {
            st.synced = Some(mark(stat));
            return Ok(settled.unwrap_or(Flushed::Clean));
        }
        if st.base.is_none() && !sync {
            self.send_async(st, tmp, ver, mark(stat))?;
            return Ok(Flushed::Sent(ver));
        }
        self.commit(st, tmp, ver, mark(stat), sync, None)
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
        let (_, remote) = self.remote.get(deadline).map_err(Refusal::err)?;
        let (body, chunks) = body_for(tmp.fd(), ver.size, None).map_err(Refusal::err)?;
        let op = Op::Commit {
            path: st.path.clone(),
            base: Expect::Absent,
            new: ver,
            perm: Some(st.perm),
            body,
            sync: false,
        };
        let (id, cell) =
            submit_cell(&*remote, &op, deadline).map_err(|e| Refusal::err(rpc_errno(&e)))?;
        if let Err(e) = send_chunks(&*remote, id, &chunks) {
            remote.cancel(id);
            return Err(Refusal::err(rpc_errno(&e)));
        }
        drop(chunks);
        st.pending = Some(Pending {
            id,
            remote,
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
                p.remote.cancel(p.id);
                Err(RpcError::Timeout)
            }
        };
        match r {
            Ok(reply @ (Reply::Done { .. } | Reply::Conflict { .. })) => self
                .commit(st, p.tmp, p.ver, p.stat, false, Some(reply))
                .map(Some),
            Ok(_) => Err(Refusal::err(libc::EIO)),
            Err(RpcError::Wire(w)) => Err(Refusal::err(wire_errno(w))),
            // the link dropped under the pipelined create: replay it, the host answers Done if it already landed
            Err(_) => match self.commit(st, p.tmp, p.ver, p.stat, false, None) {
                Err(e) if !e.refused => Err(self.refuse(st, None, None)),
                r => r.map(Some),
            },
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
        let (body, chunks) = match content {
            Some((fd, size, base)) => {
                let (b, c) = body_for(fd, size, base)?;
                (Some(b), c)
            }
            None => (None, Chunks::None),
        };
        let (mut gen_seen, mut remote) = self.remote.get(deadline)?;
        let mut retried = false;
        loop {
            let op = mk(body.clone()).ok_or(libc::EINVAL)?;
            // replays are safe: the host answers Done when the current content already equals `new`
            match Self::exchange(&*remote, op, &chunks, deadline) {
                Err(RpcError::Closed) if !retried => {
                    retried = true;
                    (gen_seen, remote) = self.remote.newer(gen_seen, deadline)?;
                }
                r => return r.map_err(|e| rpc_errno(&e)),
            }
        }
    }

    fn exchange(
        remote: &dyn Remote,
        op: Op,
        chunks: &Chunks<'_>,
        deadline: Instant,
    ) -> Result<Reply, RpcError> {
        if matches!(chunks, Chunks::None) {
            return remote.call(op, deadline);
        }
        let (id, cell) = submit_cell(remote, &op, deadline)?;
        if let Err(e) = send_chunks(remote, id, chunks) {
            remote.cancel(id);
            return Err(e);
        }
        match cell.wait(deadline) {
            Some(r) => r,
            None => {
                remote.cancel(id);
                Err(RpcError::Timeout)
            }
        }
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
                            (tmp, ver) =
                                self.cache.snapshot(st.fd.as_fd()).map_err(Refusal::err)?;
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
                Reply::Blob { .. } | Reply::Blobs { .. } => return Err(Refusal::err(libc::EIO)),
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
            Expect::Dir | Expect::Any => None,
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
                Reply::Blob { .. } | Reply::Blobs { .. } => return Err(Refusal::err(libc::EIO)),
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
        self.cas_write(
            r.to,
            Target::Rename {
                from: r.from,
                from_expect: r.from_expect,
            },
            ours,
            r.to_expect,
            None,
        )
        .map(|w| w.meta)
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
            let (t, v) = self.cache.snapshot(st.fd.as_fd()).map_err(Refusal::err)?;
            if Some(v) != host_ver {
                content = Some((t, v));
            }
        }
        let mut sent = content.as_ref().map(|c| c.1);
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
            Reply::Blob { .. } | Reply::Blobs { .. } => Err(Refusal::err(libc::EIO)),
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
    use crate::guest::cache::CacheConfig;
    use crate::net::rpc::ChunkSink;
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
        let w = Writer::new(cache.clone(), Arc::new(move |x: Notice| lock(&n).push(x)));
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
}
