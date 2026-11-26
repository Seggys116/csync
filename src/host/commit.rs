use super::{
    Core, Guest, RULE_MAX, apply::copy_subtree, dir_meta, file_meta, hash_fd, link_meta, read_all,
    read_exact_at, wire, wire_errno, write_all_at,
};
use crate::delta;
use crate::ignore::rules::{Class, Rules};
use crate::index::{
    scan,
    tree::{Domain, Observed, ROOT, StatKey},
};
use crate::proto::{
    Bytes, Change, DeltaOp, Expect, FILE_MAX, Hash32, INLINE_MAX, Kind, LinkTarget, Meta, Mk, Op,
    RelPath, Reply, ReqId, Version, WireErr,
};
use crate::sys::{self, Swap};
use crossbeam_channel::Receiver;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use rustix::io::Errno;
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{Arc, atomic::Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const COPY_BUF: usize = 1 << 20;

// a temp file in the destination directory, unlinked on drop unless the commit consumed its name
pub(crate) struct Staged {
    pub(crate) dir: OwnedFd,
    pub(crate) name: String,
    pub(crate) fd: OwnedFd,
    done: bool,
}

impl Staged {
    pub(crate) fn create(core: &Core, dir: OwnedFd, mode: u32) -> io::Result<Self> {
        let flags =
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        for _ in 0..8 {
            let name = core.tmp_name();
            match rustix::fs::openat(
                dir.as_fd(),
                name.as_str(),
                flags,
                Mode::from_bits_truncate(mode as _),
            ) {
                Ok(fd) => {
                    return Ok(Self {
                        dir,
                        name,
                        fd,
                        done: false,
                    });
                }
                Err(Errno::EXIST) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(io::ErrorKind::AlreadyExists.into())
    }

    fn consumed(&mut self) {
        self.done = true;
    }

    // after a failed swap: true when our inode still sits under the temp name
    fn still_named(&self) -> bool {
        match (
            sys::stat_key_at(self.dir.as_fd(), &self.name),
            sys::stat_key(self.fd.as_fd()),
        ) {
            (Ok(a), Ok(b)) => a.dev == b.dev && a.ino == b.ino,
            _ => false,
        }
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.done {
            let _ = rustix::fs::unlinkat(self.dir.as_fd(), self.name.as_str(), AtFlags::empty());
        }
    }
}

pub(crate) enum Payload {
    None,
    Bytes(Vec<u8>),
    File(Staged),
    Delta {
        ops: Vec<DeltaOp>,
        data_len: u64,
        lits: Option<Staged>,
    },
}

pub(crate) struct Job {
    pub(crate) guest: Arc<Guest>,
    pub(crate) id: ReqId,
    pub(crate) op: Op,
    pub(crate) payload: Payload,
}

pub(crate) fn run(core: &Core, rx: &Receiver<Job>) {
    for job in rx.iter() {
        let Job {
            guest,
            id,
            op,
            payload,
        } = job;
        // a root moved away mid-session is a detached tree: nothing may land there
        if !core.root_intact() {
            core.root_lost();
            guest.reply(id, Err(WireErr::Gone));
            continue;
        }
        let res = exec(core, op, payload, Some(guest.id));
        guest.reply(id, res);
    }
}

pub(crate) fn exec(
    core: &Core,
    op: Op,
    payload: Payload,
    origin: Option<u64>,
) -> Result<Reply, WireErr> {
    let r = match op {
        Op::Commit {
            path,
            base,
            new,
            perm,
            body: _,
            sync,
        } => commit(core, &path, base, new, perm, payload, sync, origin),
        Op::Mk { path, what } => mk(core, &path, &what, origin),
        Op::Remove { path, expect } => remove(core, &path, expect, origin),
        Op::Rename {
            from,
            to,
            from_expect,
            to_expect,
            body,
        } => {
            let body = body.map(|(v, _)| (v, payload));
            rename(core, &from, &to, from_expect, to_expect, body, origin)
        }
        Op::SetAttr {
            path,
            expect,
            perm,
            mtime_ns,
        } => set_attr(core, &path, expect, perm, mtime_ns, origin),
        Op::Fetch { .. } | Op::FetchMany { .. } => Err(WireErr::Invalid),
    };
    if let Ok(Reply::Done { .. }) = &r {
        core.stats.commits.fetch_add(1, Ordering::Relaxed);
        core.kick();
    }
    r
}

pub(crate) fn writable(rules: &Rules, p: &RelPath, is_dir: bool) -> Result<(), WireErr> {
    if p.is_root() {
        return Err(WireErr::Invalid);
    }
    match rules.classify(p, is_dir) {
        Class::Synced => Ok(()),
        Class::GitRo => Err(WireErr::ReadOnly),
        Class::Ignored | Class::Internal => Err(WireErr::Ignored),
    }
}

// both answers are fixed before anything on disk is looked at, so a refusal cannot reveal an ignored entry
struct Gate {
    file: Result<(), WireErr>,
    dir: Result<(), WireErr>,
}

impl Gate {
    fn new(rules: &Rules, p: &RelPath) -> Result<Self, WireErr> {
        let file = writable(rules, p, false);
        let dir = writable(rules, p, true);
        match (file, dir) {
            (Err(e), Err(_)) => Err(e),
            _ => Ok(Self { file, dir }),
        }
    }

    fn pass(&self, kind: Option<Kind>) -> Result<(), WireErr> {
        match kind {
            Some(Kind::Dir) => self.dir,
            Some(_) => self.file,
            None => {
                self.file?;
                self.dir?;
                Err(WireErr::NotFound)
            }
        }
    }
}

fn folds(core: &Core) -> bool {
    core.fs.case_fold || core.fs.norm_fold
}

// folding volumes resolve any spelling of an existing name, so the parent chain must be the indexed one byte for byte
fn indexed_dirs(core: &Core, dir: &str) -> Result<(), WireErr> {
    if dir.is_empty() || !folds(core) {
        return Ok(());
    }
    let tree = core.tree();
    let mut n = ROOT;
    for c in dir.split('/') {
        n = tree.child(n, c).ok_or(WireErr::NotFound)?;
        match tree.entry(n) {
            None => return Err(WireErr::NotFound),
            // open_beneath refuses a symlink or file in the chain with its own error
            Some(e) if e.meta.kind != Kind::Dir => return Ok(()),
            Some(_) => {}
        }
    }
    Ok(())
}

fn listed(dir: BorrowedFd<'_>, name: &str) -> bool {
    let mut ents = Vec::new();
    rustix::fs::openat(
        dir,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .is_ok_and(|fd| {
        sys::read_dir_plus(fd.as_fd(), &mut ents).is_ok()
            && ents.iter().any(|e| e.name.as_str() == name)
    })
}

// an existing last component on a folding volume must be the on-disk spelling: indexed, or listed under exactly this name
fn spelled(core: &Core, dir: BorrowedFd<'_>, path: &RelPath, name: &str) -> bool {
    !folds(core) || core.tree().get(path).is_some() || listed(dir, name)
}

fn kind_at(dir: BorrowedFd<'_>, name: &str) -> Result<Option<Kind>, WireErr> {
    match sys::stat_key_at(dir, name) {
        Ok(st) => Ok(Some(sys::kind_of_mode(st.mode).unwrap_or(Kind::File))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(wire(&e)),
    }
}

// the existing entry a remove, attribute change or rename source names, checked before it is opened or hashed
fn existing(
    core: &Core,
    dir: BorrowedFd<'_>,
    path: &RelPath,
    name: &str,
    gate: &Gate,
) -> Result<Cur, WireErr> {
    gate.pass(kind_at(dir, name)?)?;
    if !spelled(core, dir, path, name) {
        return Err(WireErr::NotFound);
    }
    let c = current(core, dir, path, name)?.ok_or(WireErr::NotFound)?;
    gate.pass(Some(c.kind))?;
    Ok(c)
}

// what a host read of this rule file will find once the guest's change lands
fn rule_key(size: u64, hash: Option<Hash32>) -> Option<Hash32> {
    hash.filter(|_| size <= RULE_MAX)
}

fn note_rule(core: &Core, path: &RelPath, keys: &[Option<Hash32>]) {
    if !core.rules_r().is_rule_file(path) {
        return;
    }
    let mut r = core.rules_w();
    for &k in keys {
        r.note_guest_rule(path, k);
    }
}

// a moved directory must not carry ignored entries out from under their rules, nor symlinks that would then climb out of the root
fn movable(core: &Core, from: &RelPath, to: &RelPath) -> Result<(), WireErr> {
    let rules = core.rules_r();
    let mut stack = vec![from.clone()];
    let mut ents = Vec::new();
    while let Some(d) = stack.pop() {
        let fd = sys::open_beneath(core.root.as_fd(), &d, OFlags::RDONLY | OFlags::DIRECTORY)
            .map_err(|e| wire(&e))?;
        ents.clear();
        sys::read_dir_plus(fd.as_fd(), &mut ents).map_err(|e| wire(&e))?;
        let depth = to.depth() + d.depth() - from.depth();
        let mut ctx = rules.dir_ctx(&d);
        for e in &ents {
            match rules.classify_in(&mut ctx, e.name.as_str(), e.kind == Some(Kind::Dir)) {
                Class::Synced => {}
                Class::GitRo | Class::Internal => continue,
                Class::Ignored => return Err(WireErr::Denied),
            }
            match e.kind {
                Some(Kind::Dir) => stack.push(d.join(&e.name).map_err(|_| WireErr::Denied)?),
                Some(Kind::Symlink) => {
                    let ok = rustix::fs::readlinkat(fd.as_fd(), e.name.as_str(), Vec::new())
                        .ok()
                        .and_then(|t| LinkTarget::new(t.to_str().ok()?).ok())
                        .is_some_and(|t| t.climbs_within(depth));
                    if !ok {
                        return Err(WireErr::Denied);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub(crate) fn open_parent<'p>(core: &Core, p: &'p RelPath) -> Result<(OwnedFd, &'p str), WireErr> {
    let (dir, name) = p.split_last().ok_or(WireErr::Invalid)?;
    indexed_dirs(core, dir)?;
    let dp = RelPath::new(dir).map_err(|_| WireErr::Invalid)?;
    let fd = sys::open_beneath(core.root.as_fd(), &dp, OFlags::RDONLY | OFlags::DIRECTORY)
        .map_err(|e| wire(&e))?;
    Ok((fd, name))
}

pub(crate) struct Cur {
    kind: Kind,
    stat: StatKey,
    fd: Option<OwnedFd>,
    hash: Option<Hash32>,
    link: Option<LinkTarget>,
}

impl Cur {
    fn meta(&self) -> Option<Meta> {
        Some(match self.kind {
            Kind::File => file_meta(&self.stat, self.hash?, false),
            Kind::Dir => dir_meta(&self.stat, false),
            Kind::Symlink => link_meta(&self.stat, self.link.clone()?, false),
        })
    }
}

// lstat without following, then for files an fd whose content hash is known (from the index when the stat key matches)
fn current(
    core: &Core,
    dir: BorrowedFd<'_>,
    path: &RelPath,
    name: &str,
) -> Result<Option<Cur>, WireErr> {
    let st = match sys::stat_key_at(dir, name) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(wire(&e)),
    };
    match sys::kind_of_mode(st.mode) {
        Some(Kind::File) => {
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let fd = rustix::fs::openat(dir, name, flags, Mode::empty()).map_err(wire_errno)?;
            let k1 = sys::stat_key(fd.as_fd()).map_err(|e| wire(&e))?;
            if sys::kind_of_mode(k1.mode) != Some(Kind::File) {
                return Err(WireErr::Busy);
            }
            let known = core
                .tree()
                .get(path)
                .filter(|e| e.stat == k1)
                .and_then(|e| e.meta.hash);
            let hash = match known {
                Some(h) => h,
                None => {
                    let h = hash_fd(fd.as_fd(), k1.size).map_err(|e| wire(&e))?;
                    let k2 = sys::stat_key(fd.as_fd()).map_err(|e| wire(&e))?;
                    if !sys::same_version(&k1, &k2) {
                        return Err(WireErr::Busy);
                    }
                    h
                }
            };
            Ok(Some(Cur {
                kind: Kind::File,
                stat: k1,
                fd: Some(fd),
                hash: Some(hash),
                link: None,
            }))
        }
        Some(Kind::Dir) => Ok(Some(Cur {
            kind: Kind::Dir,
            stat: st,
            fd: None,
            hash: None,
            link: None,
        })),
        Some(Kind::Symlink) => {
            let t = rustix::fs::readlinkat(dir, name, Vec::new()).map_err(wire_errno)?;
            let link = t
                .to_str()
                .ok()
                .and_then(|s| LinkTarget::new(s).ok())
                .ok_or(WireErr::Invalid)?;
            Ok(Some(Cur {
                kind: Kind::Symlink,
                stat: st,
                fd: None,
                hash: None,
                link: Some(link),
            }))
        }
        None => Err(WireErr::Invalid),
    }
}

fn matches_expect(cur: Option<&Cur>, e: Expect) -> bool {
    match e {
        Expect::Any => true,
        Expect::Absent => cur.is_none(),
        Expect::Dir => cur.is_some_and(|c| c.kind == Kind::Dir),
        Expect::Is(v) => cur.is_some_and(|c| {
            c.kind == Kind::File && c.hash == Some(v.hash) && c.stat.size == v.size
        }),
    }
}

// the current state, with the bytes inline when small, so the guest can merge without another round trip
fn conflict(cur: Option<&Cur>) -> Reply {
    let Some(c) = cur else {
        return Reply::Conflict {
            current: None,
            inline: None,
        };
    };
    let inline = match (&c.fd, c.kind) {
        (Some(fd), Kind::File) if c.stat.size <= INLINE_MAX as u64 => {
            read_all(fd.as_fd(), c.stat.size)
                .ok()
                .filter(|b| c.hash == Some(*blake3::hash(b).as_bytes()))
                .map(Bytes)
        }
        _ => None,
    };
    Reply::Conflict {
        current: c.meta(),
        inline,
    }
}

fn same_dir(a: BorrowedFd<'_>, b: BorrowedFd<'_>) -> Result<(), WireErr> {
    match (sys::stat_key(a), sys::stat_key(b)) {
        (Ok(x), Ok(y)) if x.dev == y.dev && x.ino == y.ino => Ok(()),
        _ => Err(WireErr::Busy),
    }
}

// case-folding volumes resolve a differently spelled name to an existing entry; that must not be written through
fn collides(core: &Core, dir: BorrowedFd<'_>, path: &RelPath, name: &str, exists: bool) -> bool {
    if !core.fs.case_fold && !core.fs.norm_fold {
        return false;
    }
    let Some(parent) = path.split_last().and_then(|(d, _)| RelPath::new(d).ok()) else {
        return false;
    };
    {
        let tree = core.tree();
        if tree.get(path).is_some() {
            return false;
        }
        if core.fs.case_fold {
            let want = name.to_lowercase();
            let mut hit = false;
            tree.for_children(&parent, &mut |n, _| {
                if !hit && n.as_str() != name && n.as_str().to_lowercase() == want {
                    hit = true;
                }
            });
            if hit {
                return true;
            }
        }
    }
    exists && !listed(dir, name)
}

fn record(
    core: &Core,
    path: &RelPath,
    obs: Observed,
    mut changes: Vec<Change>,
    origin: Option<u64>,
) {
    let mut tree = core.tree();
    changes.extend(tree.observe(path, obs));
    core.publish_locked(&tree, changes, origin);
}

fn dup(fd: &OwnedFd) -> Result<OwnedFd, WireErr> {
    rustix::io::dup(fd).map_err(wire_errno)
}

fn chmod(fd: BorrowedFd<'_>, perm: u32) -> Result<(), WireErr> {
    rustix::fs::fchmod(fd, Mode::from_bits_truncate((perm & 0o777) as _)).map_err(wire_errno)
}

#[allow(clippy::too_many_arguments)]
fn commit(
    core: &Core,
    path: &RelPath,
    base: Expect,
    new: Version,
    perm: Option<u16>,
    payload: Payload,
    sync: bool,
    origin: Option<u64>,
) -> Result<Reply, WireErr> {
    if new.size > FILE_MAX {
        return Err(WireErr::TooLarge);
    }
    let gate = Gate::new(&core.rules_r(), path)?;
    gate.file?;
    let (dir, name) = open_parent(core, path)?;
    match &payload {
        Payload::File(s) | Payload::Delta { lits: Some(s), .. } => {
            same_dir(dir.as_fd(), s.dir.as_fd())?
        }
        _ => {}
    }
    let kind = kind_at(dir.as_fd(), name)?;
    if kind == Some(Kind::Dir) {
        gate.dir?;
    }
    if collides(core, dir.as_fd(), path, name, kind.is_some()) {
        return Err(WireErr::Exists);
    }
    let cur = current(core, dir.as_fd(), path, name)?;
    if cur.as_ref().is_some_and(|c| c.kind == Kind::Dir) {
        gate.dir?;
    }
    if let Some(c) = &cur
        && c.kind == Kind::File
        && c.hash == Some(new.hash)
        && c.stat.size == new.size
    {
        return settle_same(core, path, c, perm, origin);
    }
    if !matches_expect(cur.as_ref(), base) {
        return Ok(conflict(cur.as_ref()));
    }
    match cur.as_ref().map(|c| c.kind) {
        Some(Kind::Dir) => return Err(WireErr::IsDir),
        Some(Kind::Symlink) => return Ok(conflict(cur.as_ref())),
        Some(Kind::File) | None => {}
    }
    let mode = perm
        .map(u32::from)
        .or(cur.as_ref().map(|c| c.stat.mode))
        .unwrap_or(0o644)
        & 0o777;
    let mut tmp = match payload {
        Payload::Bytes(b) => {
            if b.len() as u64 != new.size || *blake3::hash(&b).as_bytes() != new.hash {
                return Err(WireErr::Invalid);
            }
            let s = Staged::create(core, dup(&dir)?, 0o600).map_err(|e| wire(&e))?;
            write_all_at(s.fd.as_fd(), &b, 0).map_err(|e| wire(&e))?;
            s
        }
        Payload::File(s) => {
            if sys::stat_key(s.fd.as_fd()).map_err(|e| wire(&e))?.size != new.size {
                return Err(WireErr::Invalid);
            }
            s
        }
        Payload::Delta {
            ops,
            data_len,
            lits,
        } => {
            let Some(c) = cur.as_ref().filter(|_| matches!(base, Expect::Is(_))) else {
                return Err(WireErr::Invalid);
            };
            build_delta(core, dup(&dir)?, c, &ops, data_len, lits.as_ref(), new)?
        }
        Payload::None => return Err(WireErr::Invalid),
    };
    chmod(tmp.fd.as_fd(), mode)?;
    if sync {
        sys::full_fsync(tmp.fd.as_fd()).map_err(|e| wire(&e))?;
    }
    let key = rule_key(new.size, Some(new.hash));
    if mode & 0o400 == 0 {
        note_rule(core, path, &[key, None]);
    } else {
        note_rule(core, path, &[key]);
    }
    let pre = sys::stat_key(tmp.fd.as_fd()).map_err(|e| wire(&e))?;
    let swapped = match &cur {
        None => match sys::rename_noreplace(dir.as_fd(), &tmp.name, name) {
            Ok(()) => {
                tmp.consumed();
                true
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => false,
            Err(e) => return Err(wire(&e)),
        },
        Some(c) => {
            let old = c.fd.as_ref().ok_or(WireErr::Busy)?;
            match sys::exchange_checked(dir.as_fd(), &tmp.name, name, old.as_fd(), &c.stat) {
                Ok(Swap::Committed) => {
                    tmp.consumed();
                    true
                }
                Ok(Swap::Raced) => {
                    tmp.consumed();
                    false
                }
                Err(e) => {
                    if !tmp.still_named() {
                        tmp.consumed();
                    }
                    return Err(wire(&e));
                }
            }
        }
    };
    if !swapped {
        drop(tmp);
        let again = current(core, dir.as_fd(), path, name)?;
        return Ok(conflict(again.as_ref()));
    }
    if sync {
        let _ = sys::fsync(dir.as_fd());
    }
    // our inode is now the destination; a host write that landed after the swap means rehashing
    let post = sys::stat_key(tmp.fd.as_fd()).map_err(|e| wire(&e))?;
    let hash = if sys::same_version(&post, &pre) {
        new.hash
    } else {
        hash_fd(tmp.fd.as_fd(), post.size).map_err(|e| wire(&e))?
    };
    let meta = file_meta(&post, hash, false);
    record(
        core,
        path,
        Observed::Present {
            meta: meta.clone(),
            stat: post,
            domain: Domain::Synced,
        },
        Vec::new(),
        origin,
    );
    Ok(Reply::Done { meta })
}

// the content is already there (a replayed or duplicate commit); only the mode may differ
fn settle_same(
    core: &Core,
    path: &RelPath,
    c: &Cur,
    perm: Option<u16>,
    origin: Option<u64>,
) -> Result<Reply, WireErr> {
    let fd = c.fd.as_ref().ok_or(WireErr::Busy)?;
    let mut st = c.stat;
    if let Some(p) = perm
        && u32::from(p) & 0o777 != st.mode & 0o777
    {
        note_rule(core, path, &[None]);
        chmod(fd.as_fd(), u32::from(p))?;
        st = sys::stat_key(fd.as_fd()).map_err(|e| wire(&e))?;
    }
    let meta = file_meta(&st, c.hash.ok_or(WireErr::Busy)?, false);
    record(
        core,
        path,
        Observed::Present {
            meta: meta.clone(),
            stat: st,
            domain: Domain::Synced,
        },
        Vec::new(),
        origin,
    );
    Ok(Reply::Done { meta })
}

// streams base ranges and literal bytes into a fresh temp, never holding more than one buffer
fn build_delta(
    core: &Core,
    dir: OwnedFd,
    base: &Cur,
    ops: &[DeltaOp],
    data_len: u64,
    lits: Option<&Staged>,
    new: Version,
) -> Result<Staged, WireErr> {
    let base_fd = base.fd.as_ref().ok_or(WireErr::Busy)?;
    let total =
        delta::check(ops, base.stat.size, data_len, new.size).map_err(|_| WireErr::Invalid)?;
    if total != new.size {
        return Err(WireErr::Invalid);
    }
    if data_len > 0
        && lits.is_none_or(|l| sys::stat_key(l.fd.as_fd()).map(|s| s.size).unwrap_or(0) < data_len)
    {
        return Err(WireErr::Invalid);
    }
    let out = Staged::create(core, dir, 0o600).map_err(|e| wire(&e))?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![
        0u8;
        COPY_BUF
            .min(usize::try_from(new.size).unwrap_or(COPY_BUF))
            .max(1)
    ];
    let (mut o, mut lo) = (0u64, 0u64);
    for op in ops {
        let (src, mut soff, len) = match *op {
            DeltaOp::Copy { off, len } => (base_fd.as_fd(), off, u64::from(len)),
            DeltaOp::Data { len } => {
                let l = lits.ok_or(WireErr::Invalid)?;
                let s = lo;
                lo += u64::from(len);
                (l.fd.as_fd(), s, u64::from(len))
            }
        };
        let mut left = len;
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            read_exact_at(src, &mut buf[..n], soff).map_err(|_| WireErr::Invalid)?;
            h.update(&buf[..n]);
            write_all_at(out.fd.as_fd(), &buf[..n], o).map_err(|e| wire(&e))?;
            soff += n as u64;
            o += n as u64;
            left -= n as u64;
        }
    }
    if *h.finalize().as_bytes() != new.hash {
        return Err(WireErr::Invalid);
    }
    Ok(out)
}

fn mk(core: &Core, path: &RelPath, what: &Mk, origin: Option<u64>) -> Result<Reply, WireErr> {
    let is_dir = matches!(what, Mk::Dir { .. });
    writable(&core.rules_r(), path, is_dir)?;
    if let Mk::Symlink { target } = what
        && !target.stays_within(path)
    {
        return Err(WireErr::Denied);
    }
    let (dir, name) = open_parent(core, path)?;
    let existing = sys::stat_key_at(dir.as_fd(), name).ok();
    if collides(core, dir.as_fd(), path, name, existing.is_some()) {
        return Err(WireErr::Exists);
    }
    let (meta, stat) = match what {
        Mk::Dir { perm } => {
            match rustix::fs::mkdirat(dir.as_fd(), name, Mode::from_bits_truncate(0o700)) {
                Ok(()) => {
                    let flags =
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                    let d = rustix::fs::openat(dir.as_fd(), name, flags, Mode::empty())
                        .map_err(wire_errno)?;
                    chmod(d.as_fd(), u32::from(*perm))?;
                }
                Err(Errno::EXIST) => {}
                Err(e) => return Err(wire_errno(e)),
            }
            let st = sys::stat_key_at(dir.as_fd(), name).map_err(|e| wire(&e))?;
            if sys::kind_of_mode(st.mode) != Some(Kind::Dir) {
                return Err(WireErr::Exists);
            }
            (dir_meta(&st, false), st)
        }
        Mk::Symlink { target } => {
            match rustix::fs::symlinkat(target.as_str(), dir.as_fd(), name) {
                Ok(()) => {}
                Err(Errno::EXIST) => {
                    let same = rustix::fs::readlinkat(dir.as_fd(), name, Vec::new())
                        .is_ok_and(|t| t.to_str().is_ok_and(|s| s == target.as_str()));
                    if !same {
                        return Err(WireErr::Exists);
                    }
                }
                Err(e) => return Err(wire_errno(e)),
            }
            let st = sys::stat_key_at(dir.as_fd(), name).map_err(|e| wire(&e))?;
            if sys::kind_of_mode(st.mode) != Some(Kind::Symlink) {
                return Err(WireErr::Exists);
            }
            (link_meta(&st, target.clone(), false), st)
        }
    };
    record(
        core,
        path,
        Observed::Present {
            meta: meta.clone(),
            stat,
            domain: Domain::Synced,
        },
        Vec::new(),
        origin,
    );
    Ok(Reply::Done { meta })
}

fn remove(
    core: &Core,
    path: &RelPath,
    expect: Expect,
    origin: Option<u64>,
) -> Result<Reply, WireErr> {
    let gate = Gate::new(&core.rules_r(), path)?;
    let (dir, name) = open_parent(core, path)?;
    let c = existing(core, dir.as_fd(), path, name, &gate)?;
    if !matches_expect(Some(&c), expect) {
        return Ok(conflict(Some(&c)));
    }
    let meta = c.meta().ok_or(WireErr::Busy)?;
    if c.kind != Kind::Dir {
        note_rule(core, path, &[None]);
    }
    if c.kind == Kind::Dir {
        rustix::fs::unlinkat(dir.as_fd(), name, AtFlags::REMOVEDIR).map_err(wire_errno)?;
    } else {
        // move aside, verify it is still the inode we checked, then unlink; a racing replacement is put back
        let tmp = core.tmp_name();
        sys::rename_noreplace(dir.as_fd(), name, &tmp).map_err(|e| wire(&e))?;
        let moved = sys::stat_key_at(dir.as_fd(), &tmp).ok();
        let now = match &c.fd {
            Some(fd) => sys::stat_key(fd.as_fd()).ok(),
            None => moved,
        };
        let ok = matches!((moved, now), (Some(m), Some(n)) if m.dev == c.stat.dev && m.ino == c.stat.ino && sys::same_version(&n, &c.stat));
        if !ok {
            sys::rename_noreplace(dir.as_fd(), &tmp, name).map_err(|_| WireErr::Busy)?;
            let again = current(core, dir.as_fd(), path, name)?;
            return Ok(conflict(again.as_ref()));
        }
        rustix::fs::unlinkat(dir.as_fd(), tmp.as_str(), AtFlags::empty()).map_err(wire_errno)?;
    }
    record(core, path, Observed::Absent, Vec::new(), origin);
    Ok(Reply::Done { meta })
}

fn systime(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_nanos(ns.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

fn set_attr(
    core: &Core,
    path: &RelPath,
    expect: Expect,
    perm: Option<u16>,
    mtime_ns: Option<i64>,
    origin: Option<u64>,
) -> Result<Reply, WireErr> {
    let gate = Gate::new(&core.rules_r(), path)?;
    let (dir, name) = open_parent(core, path)?;
    let c = existing(core, dir.as_fd(), path, name, &gate)?;
    if !matches_expect(Some(&c), expect) {
        return Ok(conflict(Some(&c)));
    }
    if perm.is_some() {
        note_rule(core, path, &[None]);
    }
    let opened;
    let fd = match c.kind {
        Kind::File => c.fd.as_ref().ok_or(WireErr::Busy)?.as_fd(),
        Kind::Dir => {
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            opened =
                rustix::fs::openat(dir.as_fd(), name, flags, Mode::empty()).map_err(wire_errno)?;
            opened.as_fd()
        }
        Kind::Symlink => return Err(WireErr::Invalid),
    };
    if let Some(p) = perm {
        chmod(fd, u32::from(p))?;
    }
    if let Some(t) = mtime_ns {
        let f = std::fs::File::from(rustix::io::dup(fd).map_err(wire_errno)?);
        f.set_times(std::fs::FileTimes::new().set_modified(systime(t)))
            .map_err(|e| wire(&e))?;
    }
    let post = sys::stat_key(fd).map_err(|e| wire(&e))?;
    let meta = match c.kind {
        Kind::File => {
            let unchanged =
                post.dev == c.stat.dev && post.ino == c.stat.ino && post.size == c.stat.size;
            let hash = match c.hash.filter(|_| unchanged) {
                Some(h) => h,
                None => hash_fd(fd, post.size).map_err(|e| wire(&e))?,
            };
            file_meta(&post, hash, false)
        }
        _ => dir_meta(&post, false),
    };
    record(
        core,
        path,
        Observed::Present {
            meta: meta.clone(),
            stat: post,
            domain: Domain::Synced,
        },
        Vec::new(),
        origin,
    );
    Ok(Reply::Done { meta })
}

fn rename(
    core: &Core,
    from: &RelPath,
    to: &RelPath,
    fe: Expect,
    te: Expect,
    body: Option<(Version, Payload)>,
    origin: Option<u64>,
) -> Result<Reply, WireErr> {
    if from == to || from.is_root() || to.is_root() || to.starts_with(from) {
        return Err(WireErr::Invalid);
    }
    if let Some((ver, payload)) = body {
        // the guest never sent `from`, so its bytes ride along and land directly at `to`
        let r = commit(core, to, te, ver, None, payload, false, origin)?;
        if matches!(r, Reply::Done { .. })
            && fe != Expect::Absent
            && let Ok((d, n)) = open_parent(core, from)
            && sys::stat_key_at(d.as_fd(), n).is_ok()
        {
            let _ = remove(core, from, fe, origin);
        }
        return Ok(r);
    }
    let fgate = Gate::new(&core.rules_r(), from)?;
    let (fdir, fname) = open_parent(core, from)?;
    let (tdir, tname) = open_parent(core, to)?;
    let fc = existing(core, fdir.as_fd(), from, fname, &fgate)?;
    let is_dir = fc.kind == Kind::Dir;
    let tgate = Gate::new(&core.rules_r(), to)?;
    if is_dir { tgate.dir } else { tgate.file }?;
    if let Some(l) = &fc.link
        && !l.stays_within(to)
    {
        return Err(WireErr::Denied);
    }
    if !matches_expect(Some(&fc), fe) {
        return Ok(conflict(Some(&fc)));
    }
    let tkind = kind_at(tdir.as_fd(), tname)?;
    if tkind.is_some() {
        tgate.pass(tkind)?;
    }
    if collides(core, tdir.as_fd(), to, tname, tkind.is_some()) {
        return Err(WireErr::Exists);
    }
    let tc = current(core, tdir.as_fd(), to, tname)?;
    if !matches_expect(tc.as_ref(), te) {
        return Ok(conflict(tc.as_ref()));
    }
    if is_dir {
        movable(core, from, to)?;
    } else {
        note_rule(core, from, &[None]);
        let moved = match fc.kind {
            Kind::File => rule_key(fc.stat.size, fc.hash),
            _ => None,
        };
        note_rule(core, to, &[moved]);
    }
    match &tc {
        None => match rustix::fs::renameat_with(
            fdir.as_fd(),
            fname,
            tdir.as_fd(),
            tname,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                let again = current(core, tdir.as_fd(), to, tname)?;
                return Ok(conflict(again.as_ref()));
            }
            Err(e) => return Err(wire_errno(e)),
        },
        Some(t) if t.kind == Kind::File && !is_dir => {
            let old = t.fd.as_ref().ok_or(WireErr::Busy)?;
            rustix::fs::renameat_with(
                fdir.as_fd(),
                fname,
                tdir.as_fd(),
                tname,
                RenameFlags::EXCHANGE,
            )
            .map_err(wire_errno)?;
            let ok = match (
                sys::stat_key(old.as_fd()),
                sys::stat_key_at(fdir.as_fd(), fname),
            ) {
                (Ok(n), Ok(m)) => {
                    sys::same_version(&n, &t.stat) && m.dev == n.dev && m.ino == n.ino
                }
                _ => false,
            };
            if !ok {
                rustix::fs::renameat_with(
                    fdir.as_fd(),
                    fname,
                    tdir.as_fd(),
                    tname,
                    RenameFlags::EXCHANGE,
                )
                .map_err(wire_errno)?;
                let again = current(core, tdir.as_fd(), to, tname)?;
                return Ok(conflict(again.as_ref()));
            }
            rustix::fs::unlinkat(fdir.as_fd(), fname, AtFlags::empty()).map_err(wire_errno)?;
        }
        Some(t) if (t.kind == Kind::Dir) == is_dir && t.kind != Kind::File => {
            rustix::fs::renameat(fdir.as_fd(), fname, tdir.as_fd(), tname).map_err(wire_errno)?;
        }
        Some(t) if t.kind == Kind::Dir => return Err(WireErr::IsDir),
        Some(_) => return Err(WireErr::NotDir),
    }
    let st = sys::stat_key_at(tdir.as_fd(), tname).map_err(|e| wire(&e))?;
    let meta = match fc.kind {
        Kind::File => {
            let hash = match fc.hash.filter(|_| sys::same_version(&st, &fc.stat)) {
                Some(h) => h,
                None => {
                    let flags =
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
                    let fd = rustix::fs::openat(tdir.as_fd(), tname, flags, Mode::empty())
                        .map_err(wire_errno)?;
                    hash_fd(fd.as_fd(), st.size).map_err(|e| wire(&e))?
                }
            };
            file_meta(&st, hash, false)
        }
        Kind::Symlink => link_meta(&st, fc.link.clone().ok_or(WireErr::Io)?, false),
        Kind::Dir => dir_meta(&st, false),
    };
    let mut changes = vec![Change::Rename {
        from: from.clone(),
        to: to.clone(),
    }];
    let present = Observed::Present {
        meta: meta.clone(),
        stat: st,
        domain: Domain::Synced,
    };
    if is_dir {
        let mut rules = core.rules_w();
        let mut tree = core.tree();
        changes.extend(tree.observe(to, present));
        copy_subtree(&mut tree, &rules, from, to, &mut changes);
        changes.extend(tree.observe(from, Observed::Absent));
        // rule files and repos moved with the directory, so the new location is reconciled against disk
        let _ = scan::scan_subtree(&core.root_path, to, &mut rules, &mut tree, &mut changes);
        drop(rules);
        core.publish_locked(&tree, changes, origin);
    } else {
        let mut tree = core.tree();
        changes.extend(tree.observe(to, present));
        changes.extend(tree.observe(from, Observed::Absent));
        core.publish_locked(&tree, changes, origin);
    }
    Ok(Reply::Done { meta })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::tree::Tree;
    use crate::proto::Body;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::RwLock,
    };

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmpdir(tag: &str) -> Tmp {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!(
            "csync-commit-{tag}-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(&p).unwrap();
        Tmp(fs::canonicalize(&p).unwrap())
    }

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    fn core_at(root: &Path) -> (Core, crossbeam_channel::Receiver<Vec<sys::WatchEvent>>) {
        let mut rules = Rules::new(&[]);
        let tree: Tree = scan::scan(root, &mut rules).unwrap();
        let (tx, rx) = crossbeam_channel::bounded(64);
        let core = Core::new(
            root.to_path_buf(),
            crate::proto::Name::new("t").unwrap(),
            tree,
            Arc::new(RwLock::new(rules)),
            tx,
        )
        .unwrap();
        (core, rx)
    }

    fn ver(b: &[u8]) -> Version {
        Version {
            hash: *blake3::hash(b).as_bytes(),
            size: b.len() as u64,
        }
    }

    fn put(core: &Core, p: &str, base: Expect, data: &[u8]) -> Result<Reply, WireErr> {
        let op = Op::Commit {
            path: rp(p),
            base,
            new: ver(data),
            perm: None,
            body: Body::Empty,
            sync: false,
        };
        exec(core, op, Payload::Bytes(data.to_vec()), None)
    }

    fn temps(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with(crate::proto::path::TMP_PREFIX))
            .collect()
    }

    #[test]
    fn cas_commit_accepts_matching_expect_and_conflicts_otherwise() {
        let t = tmpdir("cas");
        fs::write(t.0.join("a.txt"), b"one\n").unwrap();
        let (core, _rx) = core_at(&t.0);

        assert!(matches!(
            put(&core, "a.txt", Expect::Absent, b"x"),
            Ok(Reply::Conflict { .. })
        ));
        match put(&core, "a.txt", Expect::Is(ver(b"stale")), b"two\n") {
            Ok(Reply::Conflict {
                current: Some(m),
                inline: Some(b),
            }) => {
                assert_eq!(m.hash, Some(ver(b"one\n").hash));
                assert_eq!(b.0, b"one\n");
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        assert_eq!(fs::read(t.0.join("a.txt")).unwrap(), b"one\n");

        match put(&core, "a.txt", Expect::Is(ver(b"one\n")), b"two\n") {
            Ok(Reply::Done { meta }) => assert_eq!(meta.hash, Some(ver(b"two\n").hash)),
            other => panic!("expected done, got {other:?}"),
        }
        assert_eq!(fs::read(t.0.join("a.txt")).unwrap(), b"two\n");
        assert_eq!(
            core.tree().get(&rp("a.txt")).and_then(|e| e.meta.hash),
            Some(ver(b"two\n").hash)
        );
        assert!(matches!(
            put(&core, "a.txt", Expect::Is(ver(b"one\n")), b"two\n"),
            Ok(Reply::Done { .. })
        ));

        assert!(matches!(
            put(&core, "new.txt", Expect::Absent, b"fresh"),
            Ok(Reply::Done { .. })
        ));
        assert_eq!(fs::read(t.0.join("new.txt")).unwrap(), b"fresh");
        assert!(core.tree().get(&rp("new.txt")).is_some());

        let bad = Op::Commit {
            path: rp("b.txt"),
            base: Expect::Absent,
            new: ver(b"claimed"),
            perm: None,
            body: Body::Empty,
            sync: false,
        };
        assert_eq!(
            exec(&core, bad, Payload::Bytes(b"actual".to_vec()), None),
            Err(WireErr::Invalid)
        );
        assert!(!t.0.join("b.txt").exists());

        let rm = Op::Remove {
            path: rp("new.txt"),
            expect: Expect::Is(ver(b"other")),
        };
        assert!(matches!(
            exec(&core, rm, Payload::None, None),
            Ok(Reply::Conflict { .. })
        ));
        let rm = Op::Remove {
            path: rp("new.txt"),
            expect: Expect::Is(ver(b"fresh")),
        };
        assert!(matches!(
            exec(&core, rm, Payload::None, None),
            Ok(Reply::Done { .. })
        ));
        assert!(!t.0.join("new.txt").exists());
        assert!(core.tree().get(&rp("new.txt")).is_none());
    }

    #[test]
    fn refuses_ignored_git_and_escaping_paths() {
        let t = tmpdir("refuse");
        let outside = tmpdir("outside");
        fs::write(t.0.join(".gitignore"), b"*.secret\nbuild/\n").unwrap();
        fs::create_dir(t.0.join(".git")).unwrap();
        fs::write(t.0.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::create_dir(t.0.join("build")).unwrap();
        std::os::unix::fs::symlink(&outside.0, t.0.join("esc")).unwrap();
        let (core, _rx) = core_at(&t.0);

        assert_eq!(
            put(&core, "x.secret", Expect::Absent, b"k"),
            Err(WireErr::Ignored)
        );
        assert_eq!(
            put(&core, "build/out.o", Expect::Absent, b"k"),
            Err(WireErr::Ignored)
        );
        assert_eq!(
            put(&core, ".git/config", Expect::Any, b"k"),
            Err(WireErr::ReadOnly)
        );
        let rm = Op::Remove {
            path: rp(".git/HEAD"),
            expect: Expect::Any,
        };
        assert_eq!(exec(&core, rm, Payload::None, None), Err(WireErr::ReadOnly));
        assert!(t.0.join(".git/HEAD").exists());

        assert!(RelPath::new("../x").is_err());
        assert!(RelPath::new("a/../../x").is_err());
        assert_eq!(
            put(&core, "esc/f", Expect::Absent, b"k"),
            Err(WireErr::Denied)
        );
        assert!(fs::read_dir(&outside.0).unwrap().next().is_none());

        let mk = Op::Mk {
            path: rp("l"),
            what: Mk::Symlink {
                target: LinkTarget::new("../../etc/passwd").unwrap(),
            },
        };
        assert_eq!(exec(&core, mk, Payload::None, None), Err(WireErr::Denied));
        let mk = Op::Mk {
            path: rp("l"),
            what: Mk::Symlink {
                target: LinkTarget::new("/etc/passwd").unwrap(),
            },
        };
        assert_eq!(exec(&core, mk, Payload::None, None), Err(WireErr::Denied));
        let mv = Op::Rename {
            from: rp(".gitignore"),
            to: rp("esc/x"),
            from_expect: Expect::Any,
            to_expect: Expect::Absent,
            body: None,
        };
        assert!(exec(&core, mv, Payload::None, None).is_err());
        assert!(t.0.join(".gitignore").exists());
        assert!(fs::read_dir(&outside.0).unwrap().next().is_none());
    }

    fn op_rm(p: &str) -> Op {
        Op::Remove {
            path: rp(p),
            expect: Expect::Any,
        }
    }

    fn op_mv(from: &str, to: &str) -> Op {
        Op::Rename {
            from: rp(from),
            to: rp(to),
            from_expect: Expect::Any,
            to_expect: Expect::Absent,
            body: None,
        }
    }

    fn op_link(p: &str, target: &str) -> Op {
        Op::Mk {
            path: rp(p),
            what: Mk::Symlink {
                target: LinkTarget::new(target).unwrap(),
            },
        }
    }

    // the host as on a default macos volume, whatever the test filesystem really does
    fn folding(core: &mut Core) {
        core.fs.case_fold = true;
        core.fs.norm_fold = true;
        core.rules_w().set_fs_fold(true, true);
    }

    #[test]
    fn case_variants_cannot_reach_git_or_ignored_files() {
        let t = tmpdir("fold");
        fs::create_dir_all(t.0.join(".git/hooks")).unwrap();
        fs::write(t.0.join(".git/config"), b"[core]\n").unwrap();
        fs::write(t.0.join(".gitignore"), b"secrets/\n.env\n").unwrap();
        fs::write(t.0.join(".env"), b"TOKEN=1\n").unwrap();
        fs::create_dir(t.0.join("secrets")).unwrap();
        fs::write(t.0.join("secrets/key.pem"), b"pem").unwrap();
        fs::create_dir(t.0.join("Docs")).unwrap();
        fs::write(t.0.join("Docs/a.txt"), b"doc").unwrap();
        fs::write(t.0.join("caf\u{e9}.txt"), b"nfc").unwrap();
        let (mut core, _rx) = core_at(&t.0);
        folding(&mut core);

        let hook = Op::Commit {
            path: rp(".GIT/hooks/post-checkout"),
            base: Expect::Any,
            new: ver(b"#!/bin/sh\n"),
            perm: Some(0o755),
            body: Body::Empty,
            sync: false,
        };
        assert_eq!(
            exec(&core, hook, Payload::Bytes(b"#!/bin/sh\n".to_vec()), None),
            Err(WireErr::ReadOnly)
        );
        assert!(!t.0.join(".git/hooks/post-checkout").exists());
        assert_eq!(
            put(&core, ".Git/config", Expect::Any, b"[core]\nfsmonitor=x\n"),
            Err(WireErr::ReadOnly)
        );
        assert_eq!(fs::read(t.0.join(".git/config")).unwrap(), b"[core]\n");

        assert_eq!(
            exec(&core, op_rm(".ENV"), Payload::None, None),
            Err(WireErr::Ignored)
        );
        assert_eq!(
            put(&core, ".ENV", Expect::Is(ver(b"stale")), b"x"),
            Err(WireErr::Ignored)
        );
        assert_eq!(
            exec(&core, op_mv("SECRETS/key.pem", "stolen.pem"), Payload::None, None),
            Err(WireErr::Ignored)
        );
        assert_eq!(fs::read(t.0.join(".env")).unwrap(), b"TOKEN=1\n");
        assert!(t.0.join("secrets/key.pem").exists());
        assert!(!t.0.join("stolen.pem").exists());

        // a parent spelled differently from the index is refused whether or not the kernel would resolve it
        assert_eq!(
            exec(&core, op_rm("docs/a.txt"), Payload::None, None),
            Err(WireErr::NotFound)
        );
        assert_eq!(
            put(&core, "docs/b.txt", Expect::Absent, b"x"),
            Err(WireErr::NotFound)
        );
        let attr = Op::SetAttr {
            path: rp("docs/a.txt"),
            expect: Expect::Any,
            perm: Some(0o600),
            mtime_ns: None,
        };
        assert_eq!(
            exec(&core, attr, Payload::None, None),
            Err(WireErr::NotFound)
        );
        assert_eq!(
            exec(&core, op_rm("cafe\u{301}.txt"), Payload::None, None),
            Err(WireErr::NotFound)
        );
        assert_eq!(fs::read(t.0.join("Docs/a.txt")).unwrap(), b"doc");
        assert!(!t.0.join("Docs/b.txt").exists());
        assert!(t.0.join("caf\u{e9}.txt").exists());

        // not yet indexed: a parent fails closed, a last component must be listed under exactly that name
        fs::create_dir(t.0.join("late")).unwrap();
        fs::write(t.0.join("Late.txt"), b"host").unwrap();
        assert_eq!(
            put(&core, "late/g.txt", Expect::Absent, b"x"),
            Err(WireErr::NotFound)
        );
        assert_eq!(
            exec(&core, op_rm("late.txt"), Payload::None, None),
            Err(WireErr::NotFound)
        );
        assert!(t.0.join("Late.txt").exists());
        assert!(matches!(
            exec(&core, op_rm("Late.txt"), Payload::None, None),
            Ok(Reply::Done { .. })
        ));
    }

    // what the applier does when the watcher reports the rule file
    fn reread(core: &Core, p: &str) {
        let text = super::super::read_rule(core.root.as_fd(), &rp(p));
        core.rules_w().update_rule_file(&rp(p), text.as_deref());
    }

    #[test]
    fn guest_rule_edits_cannot_unignore() {
        let t = tmpdir("rules");
        fs::write(t.0.join(".gitignore"), b".env\n").unwrap();
        fs::write(t.0.join(".env"), b"TOKEN=1\n").unwrap();
        fs::create_dir(t.0.join("sub")).unwrap();
        fs::write(t.0.join("sub/.env"), b"TOKEN=2\n").unwrap();
        let (core, _rx) = core_at(&t.0);
        let class = |p: &str| core.rules_r().classify(&rp(p), false);

        let text: &[u8] = b"!.env\n";
        assert!(matches!(
            put(&core, ".gitignore", Expect::Is(ver(b".env\n")), text),
            Ok(Reply::Done { .. })
        ));
        reread(&core, ".gitignore");
        assert_eq!(class(".env"), Class::Ignored);
        assert!(matches!(
            put(&core, "sub/.gitignore", Expect::Absent, text),
            Ok(Reply::Done { .. })
        ));
        reread(&core, "sub/.gitignore");
        assert_eq!(class("sub/.env"), Class::Ignored);

        assert!(matches!(
            exec(&core, op_rm(".gitignore"), Payload::None, None),
            Ok(Reply::Done { .. })
        ));
        reread(&core, ".gitignore");
        assert_eq!(class(".env"), Class::Ignored);

        assert!(matches!(
            exec(&core, op_mv("sub/.gitignore", ".gitignore"), Payload::None, None),
            Ok(Reply::Done { .. })
        ));
        reread(&core, ".gitignore");
        reread(&core, "sub/.gitignore");
        assert_eq!(class(".env"), Class::Ignored);
        assert_eq!(class("sub/.env"), Class::Ignored);

        // the host's own edit is trusted and may widen
        fs::write(t.0.join(".gitignore"), b"# none\n").unwrap();
        reread(&core, ".gitignore");
        assert_eq!(class(".env"), Class::Synced);
    }

    #[test]
    fn renames_keep_ignored_entries_and_links_in_place() {
        let t = tmpdir("mv");
        fs::write(t.0.join(".gitignore"), b"/app/secret.key\n").unwrap();
        fs::create_dir(t.0.join("app")).unwrap();
        fs::write(t.0.join("app/secret.key"), b"k").unwrap();
        fs::write(t.0.join("app/main.rs"), b"fn main() {}\n").unwrap();
        fs::create_dir_all(t.0.join("d/e")).unwrap();
        let (core, _rx) = core_at(&t.0);
        let done = |op| matches!(exec(&core, op, Payload::None, None), Ok(Reply::Done { .. }));

        assert_eq!(
            exec(&core, op_mv("app", "app2"), Payload::None, None),
            Err(WireErr::Denied)
        );
        assert!(t.0.join("app/secret.key").exists());
        assert!(!t.0.join("app2").exists());

        assert!(done(op_link("d/e/l", "../../x")));
        assert_eq!(
            exec(&core, op_mv("d/e/l", "l"), Payload::None, None),
            Err(WireErr::Denied)
        );
        assert_eq!(
            exec(&core, op_mv("d/e", "f"), Payload::None, None),
            Err(WireErr::Denied)
        );
        assert!(t.0.join("d/e/l").symlink_metadata().is_ok());
        assert!(done(op_mv("d", "g")));
        assert!(t.0.join("g/e/l").symlink_metadata().is_ok());

        assert!(done(op_link("a", ".")));
        assert_eq!(
            exec(&core, op_link("b", "a/a/../.."), Payload::None, None),
            Err(WireErr::Denied)
        );
        assert!(t.0.join("b").symlink_metadata().is_err());
    }

    #[test]
    fn temp_files_are_cleaned_up() {
        let t = tmpdir("temps");
        fs::write(t.0.join("a.txt"), b"base").unwrap();
        let (core, _rx) = core_at(&t.0);

        assert!(matches!(
            put(&core, "a.txt", Expect::Is(ver(b"base")), b"next"),
            Ok(Reply::Done { .. })
        ));
        assert!(matches!(
            put(&core, "a.txt", Expect::Is(ver(b"base")), b"lost"),
            Ok(Reply::Conflict { .. })
        ));
        let bad = Op::Commit {
            path: rp("a.txt"),
            base: Expect::Any,
            new: ver(b"x"),
            perm: None,
            body: Body::Empty,
            sync: false,
        };
        assert_eq!(
            exec(&core, bad, Payload::Bytes(b"y".to_vec()), None),
            Err(WireErr::Invalid)
        );
        assert!(temps(&t.0).is_empty(), "{:?}", temps(&t.0));

        let dir =
            rustix::fs::open(&t.0, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let s = Staged::create(&core, dir, 0o600).unwrap();
        write_all_at(s.fd.as_fd(), b"partial upload", 0).unwrap();
        assert_eq!(temps(&t.0).len(), 1);
        drop(s);
        assert!(temps(&t.0).is_empty());

        let dir =
            rustix::fs::open(&t.0, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let s = Staged::create(&core, dir, 0o600).unwrap();
        write_all_at(s.fd.as_fd(), b"streamed", 0).unwrap();
        let op = Op::Commit {
            path: rp("a.txt"),
            base: Expect::Is(ver(b"next")),
            new: ver(b"streamed"),
            perm: Some(0o640),
            body: Body::Empty,
            sync: true,
        };
        assert!(matches!(
            exec(&core, op, Payload::File(s), None),
            Ok(Reply::Done { .. })
        ));
        assert_eq!(fs::read(t.0.join("a.txt")).unwrap(), b"streamed");
        assert!(temps(&t.0).is_empty());

        let ops = vec![DeltaOp::Copy { off: 0, len: 6 }, DeltaOp::Data { len: 3 }];
        let dir =
            rustix::fs::open(&t.0, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let lits = Staged::create(&core, dir, 0o600).unwrap();
        write_all_at(lits.fd.as_fd(), b"!!!", 0).unwrap();
        let op = Op::Commit {
            path: rp("a.txt"),
            base: Expect::Is(ver(b"streamed")),
            new: ver(b"stream!!!"),
            perm: None,
            body: Body::Empty,
            sync: false,
        };
        assert!(matches!(
            exec(
                &core,
                op,
                Payload::Delta {
                    ops,
                    data_len: 3,
                    lits: Some(lits)
                },
                None
            ),
            Ok(Reply::Done { .. })
        ));
        assert_eq!(fs::read(t.0.join("a.txt")).unwrap(), b"stream!!!");
        assert!(temps(&t.0).is_empty());
    }
}
