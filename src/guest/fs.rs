use super::cache::{BlobCache, BlobRef, WAIT, lock, pread_full, pwrite_all};
use super::inject::Injector;
use super::prefetch::{Hint, Prefetch};
use super::tree::{
    DETACHED, Effect, GDomain, GNode, GTree, NodeId, ROOT, Refuse, Synth, Vis, domain_for_new,
};
use super::write::{Flushed, NoticeFn, OpenW, Refusal, RenameReq, Writer, dest_expect};
use crate::ignore::rules::{Class, Rules};
use crate::index::tree::StatKey;
use crate::proto::{
    DEPTH_MAX, Expect, FILE_MAX, Hash32, Kind, LinkTarget, Meta, Name, Notice, NoticeKind,
    PathError, RelPath, Version,
};
use crate::sys;
use crossbeam_channel::Sender;
use fuser::{
    BackgroundSession, BackingId, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType,
    Filesystem, FopenFlags, Generation, INodeNo, InitFlags, KernelConfig, LockOwner, MountOption,
    Notifier, OpenAccMode, OpenFlags, Owner, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite,
    Request, Session, SessionACL, TimeOrNow, WriteFlags,
};
use rustc_hash::FxHashMap;
use rustix::fs::{AtFlags, Mode, OFlags, Timespec, Timestamps, UTIME_NOW, UTIME_OMIT};
use std::{
    cell::RefCell,
    ffi::OsStr,
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const TTL: Duration = Duration::from_secs(86_400);
// overlay files can change size behind a passthrough handle, so their attributes are kept short
const LOCAL_TTL: Duration = Duration::from_secs(1);
const INJ_FH: u64 = 0;
const IO_MAX: u32 = 1 << 20;
const BACKGROUND_MAX: u16 = 64;
const STALE_TRIES: u32 = 100;
const STALE_STEP: Duration = Duration::from_millis(10);
const WORKERS: usize = 8;
const CAP_SYS_ADMIN: u32 = 21;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const NS: i64 = 1_000_000_000;

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
    pub overlay: OwnedFd,
    pub uid: u32,
    pub gid: u32,
    pub ctr: Arc<Counters>,
    // effects from fuse workers; the channel only wakes the apply thread, so nothing is ever dropped
    pub kicked: Mutex<Vec<Effect>>,
    pub kick: Sender<()>,
    pub case_fold: AtomicBool,
    pub passthrough: AtomicBool,
    pub notice: NoticeFn,
}

fn en(e: i32) -> Errno {
    Errno::from_i32(e)
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

// with writeback cache the kernel keeps its own i_size for a written file and ignores the server's,
// so only the injected truncate (whose setattr reply the kernel always applies) restores the host length
fn host_content_won(node: NodeId) -> Vec<Effect> {
    vec![
        Effect::InvalInode(node),
        Effect::Synth(Synth::Modify { node }),
    ]
}

fn ttl_of(n: &GNode) -> Duration {
    if n.domain == GDomain::Local {
        LOCAL_TTL
    } else {
        TTL
    }
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

fn name_of(os: &OsStr) -> Result<Name, Errno> {
    let s = os.to_str().ok_or(Errno::EINVAL)?;
    Name::new(s).map_err(|e| match e {
        PathError::TooLong => Errno::ENAMETOOLONG,
        PathError::Reserved => Errno::EPERM,
        _ => Errno::EINVAL,
    })
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

impl Core {
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
            kind: file_type(m.kind),
            perm,
            nlink: if m.kind == Kind::Dir { 2 } else { 1 },
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
            _ => n.meta.size,
        };
        self.attr_with(id, n, size, n.meta.mtime_ns)
    }

    // a node being written reports its staging copy's size and mtime
    fn live_attr(&self, id: NodeId) -> Result<(FileAttr, Duration, u64), Errno> {
        let (domain, staging) = {
            let t = self.t();
            let n = t.get(id).ok_or(Errno::ENOENT)?;
            (n.domain, n.staging)
        };
        if domain == GDomain::Local {
            self.refresh_local(id)?;
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
        let fd = sys::open_beneath(self.overlay.as_fd(), &path, OFlags::PATH | OFlags::NOFOLLOW)
            .map_err(|e| eio(&e))?;
        let k = sys::stat_key(fd.as_fd()).map_err(|e| eio(&e))?;
        let mut t = self.tw();
        if let Some(n) = t.get_mut(id) {
            let link = n.meta.link.take();
            match meta_from_key(&k, link.clone()) {
                Some(m) => n.meta = m,
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
        let path = {
            let t = self.t();
            if t.local_loaded(dir) {
                return;
            }
            match t.get(dir) {
                Some(n) if n.is_dir() && n.attached() && n.domain != GDomain::GitRo => {}
                _ => return,
            }
            t.rel_path(dir)
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
        let mut t = self.tw();
        for e in ents {
            if t.child(dir, e.name.as_str()).is_some() {
                continue;
            }
            if let Some(meta) = meta_from_key(&e.stat, None) {
                t.insert(dir, e.name, meta, GDomain::Local, Vis::Live);
            }
        }
        t.set_local_loaded(dir);
    }

    fn classify_new(&self, parent: GDomain, path: &RelPath, dir: bool) -> Result<GDomain, Errno> {
        let class = self.rules().classify(path, dir);
        domain_for_new(parent, class).map_err(refuse_errno)
    }

    fn fold_clash(&self, t: &GTree, parent: NodeId, name: &Name) -> bool {
        if !self.case_fold.load(Relaxed) {
            return false;
        }
        let key = name.fold_key(true);
        t.get(parent)
            .and_then(|p| p.children.as_ref())
            .is_some_and(|k| {
                k.iter().any(|(n, &c)| {
                    n != name
                        && n.fold_key(true) == key
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
                    Some(n) if n.domain == GDomain::Local => cands.push(c),
                    Some(n) if n.domain == GDomain::Synced && n.is_dir() => stack.push(c),
                    _ => {}
                }
            }
        }
        for c in cands {
            self.promote_node(c, 0);
        }
    }

    fn promote_node(&self, id: NodeId, depth: usize) {
        let (path, kind, perm, parent, name) = {
            let t = self.t();
            let Some(n) = t
                .get(id)
                .filter(|n| n.domain == GDomain::Local && n.attached())
            else {
                return;
            };
            let Some(p) = t.rel_path(id) else { return };
            (p, n.meta.kind, n.meta.perm, n.parent, n.name.clone())
        };
        if depth > DEPTH_MAX || self.rules().classify(&path, kind == Kind::Dir) != Class::Synced {
            return;
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

    fn read_local_link(&self, path: &RelPath) -> Option<LinkTarget> {
        let fd =
            sys::open_beneath(self.overlay.as_fd(), path, OFlags::PATH | OFlags::NOFOLLOW).ok()?;
        let s = rustix::fs::readlinkat(&fd, "", Vec::new()).ok()?;
        LinkTarget::new(s.to_str().ok()?).ok()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BKey {
    Blob(Hash32),
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

enum Src {
    Dir(Listing),
    Empty,
    Blob {
        path: RelPath,
        ver: Version,
        blob: OnceLock<BlobRef>,
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

fn fopen(io: &Io) -> FopenFlags {
    match io {
        Io::Cached => FopenFlags::FOPEN_KEEP_CACHE,
        Io::Fresh => FopenFlags::empty(),
        Io::Direct => FopenFlags::FOPEN_DIRECT_IO,
        Io::None | Io::Pass(_) => FopenFlags::empty(),
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
        }
    }

    fn is_inj(&self, req: &Request) -> bool {
        self.core.inj.get().is_some_and(|i| i.is_self(req.pid()))
    }

    fn add_handle(&self, h: Handle) -> u64 {
        let fh = self.next.fetch_add(1, Relaxed);
        lock(&self.handles).insert(fh, Arc::new(h));
        fh
    }

    fn handle(&self, fh: u64) -> Option<Arc<Handle>> {
        lock(&self.handles).get(&fh).cloned()
    }

    // one backing file per inode at a time; a conflicting open falls back to direct io
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
        drop(h);
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
            self.core.tw().drop_open(node);
        }
    }

    // only staged handles act on flush, so the rest skip the close round trip
    fn noflush(&self, src: &Src) -> FopenFlags {
        if self.noflush && !matches!(src, Src::Staged { .. }) {
            FopenFlags::FOPEN_NOFLUSH
        } else {
            FopenFlags::empty()
        }
    }

    fn reply_open(&self, reply: ReplyOpen, fh: u64, h: &Handle) {
        let nf = self.noflush(&h.src);
        match &h.io {
            // the kernel fails a passthrough open with EIO for any flag outside its mask, KEEP_CACHE included
            Io::Pass(b) => reply.opened_passthrough(FileHandle(fh), nf, b),
            io => reply.opened(FileHandle(fh), fopen(io) | nf),
        }
    }

    // applies the outcome of a commit attempt to the node; refusals restore the host's metadata
    fn finish(&self, node: NodeId, r: Result<Flushed, Refusal>) -> Result<(), Errno> {
        match r {
            Ok(Flushed::Clean) => Ok(()),
            Ok(Flushed::Sent(v)) => {
                if let Some(n) = self.core.tw().get_mut(node) {
                    n.meta.hash = Some(v.hash);
                    n.meta.size = v.size;
                    n.meta.mtime_ns = now_ns();
                    n.read_ver = Some(v);
                }
                Ok(())
            }
            Ok(Flushed::Committed { meta, merged }) => {
                self.core.ctr.commits.fetch_add(1, Relaxed);
                let mut t = self.core.tw();
                if let Some(n) = t.get_mut(node) {
                    n.read_ver = meta.version();
                    n.meta = meta;
                }
                t.note_acked(node);
                drop(t);
                if merged {
                    self.core.kick(host_content_won(node));
                }
                Ok(())
            }
            Err(e) => {
                if e.refused {
                    let mut t = self.core.tw();
                    match e.current {
                        Some(m) => {
                            if let Some(n) = t.get_mut(node) {
                                n.meta = m;
                            }
                            drop(t);
                            self.core.kick(host_content_won(node));
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
                                self.core.kick(vec![
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

    // the host moved on before this version was fetched: serve what replaced it, or the same bytes
    // from where the file was moved to, as a local file would
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
    ) {
        let Some((cur, path)) = self.newer_place(id, old, at) else {
            return reply.error(en(err));
        };
        let Some(v) = cur else {
            return reply.data(&[]);
        };
        let len = v.size.saturating_sub(offset).min(want as u64) as usize;
        if len == 0 {
            return reply.data(&[]);
        }
        let deadline = Instant::now() + WAIT + Duration::from_millis(v.size >> 12);
        match self
            .core
            .cache
            .fetch_at(&v.hash, &path, v.size, offset, len as u32, deadline)
        {
            Ok(b) => read_into(len, |dst| b.read_at(dst, offset).map_err(en), reply),
            Err(e) => reply.error(en(e)),
        }
    }

    // the change that made the host refuse a fetch is on its way: wait for a new version or a new path
    fn newer_place(
        &self,
        id: NodeId,
        old: Version,
        at: &RelPath,
    ) -> Option<(Option<Version>, RelPath)> {
        for _ in 0..STALE_TRIES {
            {
                let t = self.core.t();
                let n = t.get(id)?;
                if n.meta.kind != Kind::File {
                    return None;
                }
                let v = n.meta.version();
                let p = t.rel_path(id);
                if v != Some(old) || p.as_ref() != Some(at) {
                    return Some((v, p?));
                }
            }
            std::thread::sleep(STALE_STEP);
        }
        None
    }

    // page cache and i_size belong to the inode, so a cached handle opened on an older version must
    // serve the current one: a short read at its old eof would shrink i_size until the attrs expire
    fn moved_on(&self, h: &Handle) -> Option<(Option<Version>, RelPath)> {
        let opened = match (&h.io, &h.src) {
            (Io::Cached | Io::Fresh, Src::Blob { ver, .. }) => Some(*ver),
            (Io::Cached | Io::Fresh, Src::Empty) => None,
            _ => return None,
        };
        let t = self.core.t();
        let n = t.get(h.node)?;
        if n.meta.kind != Kind::File || n.meta.version() == opened {
            return None;
        }
        Some((n.meta.version(), t.rel_path(h.node)?))
    }

    fn read_version(
        &self,
        node: NodeId,
        v: Version,
        path: &RelPath,
        offset: u64,
        want: usize,
        reply: ReplyData,
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
                self.read_newer(node, v, path, offset, want, e, reply)
            }
            Err(e) => reply.error(en(e)),
        }
    }

    fn open_staged(&self, id: NodeId, o: OpenW<'_>) -> Result<(u32, Arc<OwnedFd>), Errno> {
        let (path, trunc, staging, old) = (o.path, o.trunc, o.staging, o.base);
        let (sid, fd) = match self.core.writer.open_for_write(o) {
            Err(libc::ESTALE) if staging.is_none() => {
                let m = self.newer_meta(id, old).ok_or(Errno::ESTALE)?;
                self.core
                    .writer
                    .open_for_write(OpenW {
                        path,
                        base: m.version(),
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
        if flags & libc::O_APPEND != 0 {
            of |= OFlags::APPEND;
        }
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
        if dom == GDomain::Synced && self.core.fold_clash(&t, parent, name) {
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
            Some(n) => reply.entry(&ttl_of(n), &self.core.attr(id, n), Generation(n.r#gen)),
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
                    Mode::from_bits_truncate(u32::from(perm)),
                )
                .map_err(erx)?;
                let k = sys::stat_key(fd.as_fd()).map_err(|e| eio(&e))?;
                let meta = meta_from_key(&k, None).ok_or(Errno::EIO)?;
                let id = self.insert_new(parent, name, meta, GDomain::Local)?;
                self.core.tw().add_open(id);
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

    fn src_key<'a>(src: &'a Src) -> Option<(BKey, BorrowedFd<'a>)> {
        match src {
            Src::Staged { id, fd } => Some((BKey::Staged(*id), fd.as_fd())),
            Src::Local { fd } => Some((BKey::Local(true), fd.as_fd())),
            Src::Blob { ver, blob, .. } => blob.get().map(|b| (BKey::Blob(ver.hash), b.fd())),
            Src::Dir(_) | Src::Empty => None,
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
        let (id, domain, kind, ver, path, vis, empty) = {
            let t = self.core.t();
            let (id, n) = t.lookup(parent, name).ok_or(Errno::ENOENT)?;
            let mut l = Vec::new();
            let empty = !n.is_dir() || (t.list(id, &mut l) && l.is_empty());
            (
                id,
                n.domain,
                n.meta.kind,
                n.meta.version(),
                t.rel_path(id).ok_or(Errno::ENOENT)?,
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
                let expect = match kind {
                    Kind::Dir => Expect::Dir,
                    Kind::File => ver.map_or(Expect::Any, Expect::Is),
                    Kind::Symlink => Expect::Any,
                };
                match self.core.writer.remove(&path, expect) {
                    Ok(_) => {}
                    Err(e) if !e.refused && e.errno == libc::ENOENT => {}
                    Err(e) => return self.finish(id, Err(e)),
                }
                if dir {
                    self.core.remove_overlay(&path);
                }
            }
        }
        self.core.tw().remove(id);
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
        if flags.intersects(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT) {
            return Err(Errno::EINVAL);
        }
        let name = name.to_str().ok_or(Errno::ENOENT)?;
        let newname = name_of(newname)?;
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
            sver: Option<Version>,
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
            let from = t.rel_path(sid).ok_or(Errno::ENOENT)?;
            let to = t
                .rel_path(newparent)
                .ok_or(Errno::ENOENT)?
                .join(&newname)
                .map_err(|_| Errno::ENAMETOOLONG)?;
            let ddom = match dst {
                Some((_, d)) => d.domain,
                None => self.core.classify_new(np.domain, &to, s.is_dir())?,
            };
            if ddom == GDomain::Synced
                && dst.is_none()
                && self.core.fold_clash(&t, newparent, &newname)
            {
                return Err(Errno::EEXIST);
            }
            Plan {
                sid,
                skind: s.meta.kind,
                sdom: s.domain,
                sver: s.meta.version(),
                sperm: s.meta.perm,
                staging: s.staging,
                link: s.meta.link.clone(),
                from,
                to,
                ddom,
                dst: dst.map(|(i, _)| i),
                to_expect: dest_expect(dst.map(|(_, d)| d)),
            }
        };
        let p = plan;
        let dir = p.skind == Kind::Dir;
        let (fdir, fname) = p.from.split_last().ok_or(Errno::EBUSY)?;
        let (tdir, tname) = p.to.split_last().ok_or(Errno::EINVAL)?;
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
                let from_expect = match p.skind {
                    Kind::Dir => Expect::Dir,
                    Kind::File => p.sver.map_or(Expect::Any, Expect::Is),
                    Kind::Symlink => Expect::Any,
                };
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
                    return Err(Errno::EXDEV);
                }
                let dd = self.core.overlay_dir(tdir, true).map_err(|e| eio(&e))?;
                self.copy_out(
                    &p.from,
                    p.skind,
                    p.sver,
                    p.staging,
                    p.link.as_ref(),
                    p.sperm,
                    &dd,
                    tname,
                )?;
                let expect = match p.skind {
                    Kind::File => p.sver.map_or(Expect::Any, Expect::Is),
                    _ => Expect::Any,
                };
                match self.core.writer.remove(&p.from, expect) {
                    Ok(_) => {}
                    Err(e) if !e.refused && e.errno == libc::ENOENT => {}
                    Err(e) => {
                        let _ = rustix::fs::unlinkat(&dd, tname, AtFlags::empty());
                        return self.finish(p.sid, Err(e));
                    }
                }
                None
            }
            _ => return Err(Errno::EROFS),
        };
        let mut t = self.core.tw();
        if !t.relink(p.sid, newparent, newname) {
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
        ver: Option<Version>,
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
            Mode::from_bits_truncate(u32::from(perm)),
        )
        .map_err(erx)?;
        let staged = staging.and_then(|s| self.core.writer.staging_fd(s));
        let r = match (staged, ver) {
            (Some(fd), _) => sys::clone_or_copy(fd.as_fd(), out.as_fd()).map_err(|e| eio(&e)),
            (None, Some(v)) if v.size > 0 => {
                let deadline = Instant::now() + WAIT + Duration::from_millis(v.size >> 12);
                self.core
                    .cache
                    .fetch_whole(&v.hash, from, v.size, deadline)
                    .map_err(en)
                    .and_then(|b| sys::clone_or_copy(b.fd(), out.as_fd()).map_err(|e| eio(&e)))
            }
            _ => Ok(()),
        };
        drop(out);
        let r = r.and_then(|()| rustix::fs::renameat(dd, tmp.as_str(), dd, tname).map_err(erx));
        if r.is_err() {
            let _ = rustix::fs::unlinkat(dd, tmp.as_str(), AtFlags::empty());
        }
        r
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
        if uid.is_some_and(|u| u != self.core.uid) || gid.is_some_and(|g| g != self.core.gid) {
            return Err(Errno::EPERM);
        }
        let (domain, kind, meta, staging, path) = {
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
            None => return Err(Errno::ENOENT),
        };
        let handle = fh.and_then(|f| self.handle(f.0));
        match domain {
            GDomain::GitRo if changes => Err(Errno::EROFS),
            GDomain::GitRo => Ok(()),
            GDomain::Local => {
                let (dir, name) = path.split_last().ok_or(Errno::EINVAL)?;
                let d = self.core.overlay_dir(dir, false).map_err(|e| eio(&e))?;
                if let Some(m) = mode {
                    if kind == Kind::Symlink {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    rustix::fs::chmodat(
                        &d,
                        name,
                        Mode::from_bits_truncate(m & 0o7777),
                        AtFlags::empty(),
                    )
                    .map_err(erx)?;
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
                        None => {
                            let o = OpenW {
                                path: &path,
                                base: meta.version(),
                                perm: meta.perm,
                                trunc: sz == 0,
                                staging: None,
                            };
                            let (sid, fd) = self.core.writer.open_for_write(o).map_err(en)?;
                            let t = rustix::fs::ftruncate(&*fd, sz).map_err(erx);
                            let f = t
                                .and_then(|()| self.finish(id, self.core.writer.flush(sid, false)));
                            let r = self
                                .core
                                .writer
                                .release(sid)
                                .map_or(Ok(()), |r| self.finish(id, r));
                            f.and(r)?;
                        }
                    }
                }
                // writeback flushes carry the kernel's own mtime; a file being written commits on close instead
                let mtime = if staging.is_some() && mode.is_none() {
                    None
                } else {
                    mtime
                };
                if mode.is_some() || mtime.is_some() {
                    let perm = mode.map(|m| (m & 0o7777) as u16);
                    let mt = mtime.map(|t| match t {
                        TimeOrNow::SpecificTime(s) => ns_of(s),
                        TimeOrNow::Now => now_ns(),
                    });
                    let expect = match kind {
                        Kind::Dir => Expect::Dir,
                        Kind::File => meta.version().map_or(Expect::Any, Expect::Is),
                        Kind::Symlink => Expect::Any,
                    };
                    match self.core.writer.setattr(&path, expect, perm, mt) {
                        Ok(m) => {
                            if let Some(n) = self.core.tw().get_mut(id) {
                                n.meta.perm = m.perm;
                                n.meta.mtime_ns = m.mtime_ns;
                                n.meta.ctime_ns = m.ctime_ns;
                            }
                        }
                        Err(e) => return self.finish(id, Err(e)),
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
        let base = InitFlags::FUSE_ASYNC_READ
            | InitFlags::FUSE_PARALLEL_DIROPS
            | InitFlags::FUSE_DO_READDIRPLUS
            | InitFlags::FUSE_CACHE_SYMLINKS
            | InitFlags::FUSE_ATOMIC_O_TRUNC
            | InitFlags::FUSE_MAX_PAGES
            | InitFlags::FUSE_EXPLICIT_INVAL_DATA;
        let _ = cfg.add_capabilities(base & caps);
        // passthrough and writeback cache are mutually exclusive in the kernel
        self.pass = caps.contains(InitFlags::FUSE_PASSTHROUGH)
            && has_cap_sys_admin()
            && cfg.set_max_stack_depth(1).is_ok()
            && cfg.add_capabilities(InitFlags::FUSE_PASSTHROUGH).is_ok();
        let wb = !self.pass
            && caps.contains(InitFlags::FUSE_WRITEBACK_CACHE)
            && cfg
                .add_capabilities(InitFlags::FUSE_WRITEBACK_CACHE)
                .is_ok();
        // without writeback cache a read-only handle never holds dirty pages
        self.noflush = !wb;
        self.no_opendir = caps.contains(InitFlags::FUSE_NO_OPENDIR_SUPPORT);
        self.core.passthrough.store(self.pass, Relaxed);
        let _ = cfg.set_max_write(IO_MAX).or_else(|n| cfg.set_max_write(n));
        let _ = cfg
            .set_max_readahead(IO_MAX)
            .or_else(|n| cfg.set_max_readahead(n));
        let _ = cfg.set_max_background(BACKGROUND_MAX);
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        self.core.ctr.op(Op::Lookup);
        let Some(name) = name.to_str() else {
            return reply.error(Errno::ENOENT);
        };
        for pass in 0..2 {
            {
                let t = self.core.t();
                let found = t.lookup(parent.0, name).map(|(id, _)| id);
                if let Some(id) = found {
                    t.add_lookup(id);
                    if let Some(n) = t.get(id) {
                        return reply.entry(
                            &ttl_of(n),
                            &self.core.attr(id, n),
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
        reply.entry(&TTL, &neg, Generation(0));
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.core.ctr.op(Op::Forget);
        self.core.tw().forget(ino.0, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        self.core.ctr.op(Op::Getattr);
        match self.core.live_attr(ino.0) {
            Ok((a, ttl, _)) => reply.attr(&ttl, &a),
            Err(e) => reply.error(e),
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
        if !self.is_inj(req)
            && let Err(e) = self.do_setattr(ino.0, mode, uid, gid, size, atime, mtime, fh)
        {
            return reply.error(e);
        }
        match self.core.live_attr(ino.0) {
            Ok((a, ttl, _)) => reply.attr(&ttl, &a),
            Err(e) => reply.error(e),
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
        if mode & S_IFMT != S_IFREG {
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
        match self.new_file(parent.0, &name, perm) {
            Ok((id, src)) => {
                let r = match src {
                    Src::Staged { id: sid, .. } => {
                        let f = self.finish(id, self.core.writer.flush(sid, false));
                        let rel = self
                            .core
                            .writer
                            .release(sid)
                            .map_or(Ok(()), |r| self.finish(id, r));
                        if let Some(n) = self.core.tw().get_mut(id) {
                            n.staging = None;
                        }
                        f.and(rel)
                    }
                    _ => Ok(()),
                };
                self.core.tw().drop_open(id);
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
        let Ok(name) = name_of(name) else {
            return reply.error(Errno::EINVAL);
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
                    rustix::fs::mkdirat(&d, nm, Mode::from_bits_truncate(u32::from(perm)))
                        .map_err(erx)?;
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
        let Ok(name) = name_of(link_name) else {
            return reply.error(Errno::EINVAL);
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
            return reply.opened(FileHandle(INJ_FH), FopenFlags::FOPEN_DIRECT_IO);
        }
        let id = ino.0;
        let write = flags.acc_mode() != OpenAccMode::O_RDONLY;
        let trunc = flags.0 & libc::O_TRUNC != 0;
        let (domain, meta, staging, path, parent) = {
            let t = self.core.t();
            let Some(n) = t.get(id) else {
                return reply.error(Errno::ENOENT);
            };
            if n.meta.kind != Kind::File {
                return reply.error(if n.is_dir() {
                    Errno::EISDIR
                } else {
                    Errno::ELOOP
                });
            }
            (
                n.domain,
                n.meta.clone(),
                n.staging,
                t.rel_path(id),
                n.parent,
            )
        };
        let Some(path) = path else {
            return reply.error(Errno::ENOENT);
        };
        if domain == GDomain::GitRo && (write || trunc) {
            return reply.error(Errno::EROFS);
        }
        let mut keep = true;
        let src = if domain == GDomain::Local {
            match sys::open_beneath(self.core.overlay.as_fd(), &path, Self::local_flags(flags.0)) {
                Ok(fd) => {
                    self.core.tw().add_open(id);
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
            let Some(ver) = meta.version() else {
                if meta.size != 0 {
                    return reply.error(Errno::EIO);
                }
                self.core.tw().add_open(id);
                // counted like any cached open: the kernel puts the inode in caching mode for it
                let io = self.choose_io(id, None, &|fd| reply.open_backing(fd));
                let fh = self.add_handle(Handle {
                    node: id,
                    io,
                    src: Src::Empty,
                });
                return match self.handle(fh) {
                    Some(h) => self.reply_open(reply, fh, &h),
                    None => reply.error(Errno::EIO),
                };
            };
            let cached = self.core.cache.get(&ver.hash).filter(|b| b.is_complete());
            self.core.cache.note(&ver.hash, &path, ver.size);
            let cold = cached.is_none() && ver.size > 0;
            let c = if cold {
                &self.core.ctr.misses
            } else {
                &self.core.ctr.hits
            };
            c.fetch_add(1, Relaxed);
            if !cold {
                self.core.cache.note_open(&ver.hash);
            }
            keep = false;
            {
                let mut t = self.core.tw();
                if let Some(n) = t.get_mut(id) {
                    n.read_ver = Some(ver);
                    keep = n.page.replace(ver.hash) == Some(ver.hash);
                }
                t.add_open(id);
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
            Src::Blob { path, ver, blob }
        };
        let io = match self.choose_io(id, Self::src_key(&src), &|fd| reply.open_backing(fd)) {
            Io::Cached if !keep => Io::Fresh,
            io => io,
        };
        let fh = self.add_handle(Handle { node: id, io, src });
        match self.handle(fh) {
            Some(h) => self.reply_open(reply, fh, &h),
            None => reply.error(Errno::EIO),
        }
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
            return match cur {
                Some(v) => self.read_version(h.node, v, &path, offset, want, reply),
                None => reply.data(&[]),
            };
        }
        match &h.src {
            Src::Blob { path, ver, blob } => {
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
                                return self.read_newer(h.node, *ver, path, offset, want, e, reply);
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
            Src::Staged { id, .. } => self.finish(h.node, self.core.writer.flush(*id, false)),
            _ => Ok(()),
        };
        match r {
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
            // an edit that failed on the last close is gone: drop pages that still show it
            if let Some(r) = self.core.writer.release(*id)
                && self.finish(h.node, r).is_err()
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
        self.close_handle(h);
        reply.ok();
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
            Src::Staged { id, .. } => self.finish(h.node, self.core.writer.flush(*id, true)),
            Src::Local { fd } => sys::fsync(fd.as_fd()).map_err(|e| eio(&e)),
            _ => Ok(()),
        };
        match r {
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
                                file_type(n.meta.kind),
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
                                    &self.core.attr(*id, n),
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
                        &TTL,
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
}

pub struct Mounted {
    bg: Option<BackgroundSession>,
    notifier: Notifier,
    path: PathBuf,
}

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

impl Mounted {
    // notifications are only ever sent from the apply thread
    pub fn inval_inode(&self, id: NodeId) {
        let _ = self.notifier.inval_inode(INodeNo(id), 0, 0);
    }

    pub fn inval_entry(&self, parent: NodeId, name: &Name) {
        let _ = self
            .notifier
            .inval_entry(INodeNo(parent), OsStr::new(name.as_str()));
    }

    pub fn unmount(mut self) -> io::Result<()> {
        let Some(bg) = self.bg.take() else {
            return Ok(());
        };
        match bg.umount_and_join() {
            Ok(()) => Ok(()),
            Err(_) if lazy_unmount(&self.path) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

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
    let session = Session::new(GuestFs::new(core), at, &cfg)?;
    let bg = session.spawn()?;
    let notifier = bg.notifier();
    Ok(Mounted {
        bg: Some(bg),
        notifier,
        path: at.to_path_buf(),
    })
}
