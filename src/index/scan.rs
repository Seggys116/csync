use super::tree::{Domain, Observed, ROOT, StatKey, Tree};
use crate::ignore::{
    repo,
    rules::{Class, Rules},
};
use crate::proto::{Change, FILE_MAX, Hash32, IndexId, Kind, LinkTarget, Meta, Name, RelPath};
use crate::sys::{self, DirEntryPlus};
use rustc_hash::FxHashSet;
use rustix::fs::{Mode, OFlags};
use std::{
    cell::Cell,
    collections::VecDeque,
    fs::File,
    io::{self, Read},
    num::NonZeroUsize,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

pub const HASH_BUF: usize = 1 << 20;
pub const RAYON_MIN: u64 = 4 << 20;
const RULE_MAX: u64 = 8 << 20;
// more walkers only add system time, and a few directories are cheaper on the calling thread
const WALK_THREADS: usize = 8;
const SPAWN_AT: usize = 16;
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY);

thread_local! {
    static BUF: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

// how a task reaches its directory: relative to the parent that is still open, or from the root
enum Src {
    Path,
    Fd(OwnedFd),
    Under(Arc<OwnedFd>, Name),
}

struct Task {
    id: usize,
    path: RelPath,
    class: Class,
    // the directory's node in the tree as it was before this walk
    node: Option<u32>,
    src: Src,
}

struct RawEnt {
    name: Name,
    kind: Kind,
    stat: StatKey,
    link: Option<LinkTarget>,
}

#[derive(Default)]
struct Raw {
    ok: bool,
    ents: Vec<RawEnt>,
    ignore_text: Option<Vec<u8>>,
    has_git: bool,
}

struct Item {
    name: Name,
    meta: Meta,
    stat: StatKey,
    domain: Domain,
    // result slot of this directory's own task when it is walked
    child: Option<usize>,
}

struct Cooked {
    ok: bool,
    items: Vec<Item>,
}

impl Cooked {
    fn failed() -> Self {
        Self {
            ok: false,
            items: Vec::new(),
        }
    }
}

pub fn new_index_id() -> io::Result<IndexId> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| io::Error::other(format!("getrandom: {e}")))?;
    Ok(u128::from_le_bytes(b))
}

// a fresh tree; repos and rule files are registered into rules as the walk finds them
pub fn scan(root: &Path, rules: &mut Rules) -> io::Result<Tree> {
    let mut tree = Tree::new(new_index_id()?);
    tree.set_journaling(false);
    walk(root, &RelPath::root(), rules, &mut tree, None)?;
    tree.set_journaling(true);
    Ok(tree)
}

// a warm rescan over a persisted tree: unchanged stat keys reuse hashes, differences are journaled
pub fn rescan(root: &Path, rules: &mut Rules, mut prev: Tree) -> io::Result<Tree> {
    walk(root, &RelPath::root(), rules, &mut prev, None)?;
    Ok(prev)
}

// reconciles one subtree against disk, e.g. after a rule change or watcher overflow
pub fn scan_subtree(
    root: &Path,
    dir: &RelPath,
    rules: &mut Rules,
    tree: &mut Tree,
    out: &mut Vec<Change>,
) -> io::Result<()> {
    walk(root, dir, rules, tree, Some(out))
}

fn walk(
    root: &Path,
    dir: &RelPath,
    rules: &mut Rules,
    tree: &mut Tree,
    mut out: Option<&mut Vec<Change>>,
) -> io::Result<()> {
    let root_fd = rustix::fs::open(root, DIR_FLAGS, Mode::empty())?;
    let rfd = root_fd.as_fd();
    let dev = sys::stat_key(rfd)?.dev;
    let (start, node) = if dir.is_root() {
        let task = Task {
            id: 0,
            path: RelPath::root(),
            class: Class::Synced,
            node: Some(ROOT),
            src: Src::Path,
        };
        (task, ROOT)
    } else {
        match enter(rfd, dev, dir, rules, tree, &mut out)? {
            Some((class, node, fd)) => {
                let task = Task {
                    id: 0,
                    path: dir.clone(),
                    class,
                    node: Some(node),
                    src: Src::Fd(fd),
                };
                (task, node)
            }
            None => return Ok(()),
        }
    };
    let mut slots = {
        let walker = Walk {
            root,
            rfd,
            dev,
            rules: RwLock::new(&mut *rules),
            tree: &*tree,
            queue: Queue::default(),
            ids: AtomicUsize::new(1),
            done: Mutex::new(Vec::new()),
        };
        walker.drive(walk_threads(), start);
        walker.into_slots()
    };
    // applied breadth first from the root, the order a level-by-level walk would have used
    let mut next = VecDeque::from([(0usize, node)]);
    while let Some((id, n)) = next.pop_front() {
        if let Some(c) = slots.get_mut(id).and_then(Option::take) {
            apply(tree, n, c, &mut out, &mut next);
        }
    }
    Ok(())
}

fn walk_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, NonZeroUsize::get)
        .clamp(1, WALK_THREADS)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct QState {
    tasks: Vec<Task>,
    active: usize,
    waiting: usize,
}

// a shared stack of directories still to read: newest first keeps a worker inside one subtree
#[derive(Default)]
struct Queue {
    st: Mutex<QState>,
    cv: Condvar,
}

impl Queue {
    // blocks while the stack is empty but a running task may still add to it; None once the walk is over
    fn take(&self) -> Option<Task> {
        let mut g = lock(&self.st);
        loop {
            if let Some(t) = g.tasks.pop() {
                g.active += 1;
                return Some(t);
            }
            if g.active == 0 {
                return None;
            }
            g.waiting += 1;
            g = self.cv.wait(g).unwrap_or_else(PoisonError::into_inner);
            g.waiting -= 1;
        }
    }

    // ends a task and publishes the directories it found; returns how many are waiting
    fn finish(&self, kids: Vec<Task>) -> usize {
        let mut g = lock(&self.st);
        g.active -= 1;
        let added = kids.len();
        g.tasks.extend(kids);
        let queued = g.tasks.len();
        if queued == 0 {
            if g.active == 0 {
                self.cv.notify_all();
            }
        } else {
            for _ in 0..added.min(g.waiting) {
                self.cv.notify_one();
            }
        }
        queued
    }
}

// keeps the other workers from waiting forever on a task that panicked
struct Running<'a>(&'a Queue);

impl Running<'_> {
    fn finish(self, kids: Vec<Task>) -> usize {
        let q = self.0;
        std::mem::forget(self);
        q.finish(kids)
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.finish(Vec::new());
    }
}

struct Walk<'a> {
    root: &'a Path,
    rfd: BorrowedFd<'a>,
    dev: u64,
    rules: RwLock<&'a mut Rules>,
    // read only for the whole parallel phase; results are merged into it afterwards
    tree: &'a Tree,
    queue: Queue,
    ids: AtomicUsize,
    done: Mutex<Vec<(usize, Cooked)>>,
}

impl Walk<'_> {
    // the caller is the first worker; helper threads start once there is enough queued to share
    fn drive(&self, threads: usize, start: Task) {
        lock(&self.queue.st).tasks.push(start);
        let this = self;
        std::thread::scope(|s| {
            let mut grown = false;
            this.work(&mut |queued| {
                if grown || queued < SPAWN_AT {
                    return;
                }
                grown = true;
                for _ in 1..threads {
                    let spawned = std::thread::Builder::new()
                        .spawn_scoped(s, move || this.work(&mut |_| {}))
                        .is_ok();
                    if !spawned {
                        break;
                    }
                }
            });
        });
    }

    fn work(&self, grow: &mut dyn FnMut(usize)) {
        while let Some(task) = self.queue.take() {
            let running = Running(&self.queue);
            let kids = self.run(task);
            grow(running.finish(kids));
        }
    }

    fn into_slots(self) -> Vec<Option<Cooked>> {
        let mut slots: Vec<Option<Cooked>> = Vec::new();
        slots.resize_with(self.ids.load(Ordering::Relaxed), || None);
        let done = self
            .done
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        for (id, c) in done {
            slots[id] = Some(c);
        }
        slots
    }

    fn run(&self, t: Task) -> Vec<Task> {
        let Task {
            id,
            path,
            class,
            node,
            src,
        } = t;
        let fd = match src {
            Src::Fd(fd) => Some(fd),
            Src::Path => sys::open_beneath(self.rfd, &path, DIR_FLAGS).ok(),
            Src::Under(parent, name) => self.open_under(&parent, &name, &path),
        };
        let Some(fd) = fd.map(Arc::new) else {
            self.store(id, Cooked::failed());
            return Vec::new();
        };
        let raw = read_one(fd.as_fd(), self.dev, class);
        self.enroll(&path, class, &raw);
        let mut cooked = if raw.ok {
            let kept = {
                let g = self.rules.read().unwrap_or_else(PoisonError::into_inner);
                classify_all(&g, &path, raw.ents)
            };
            Cooked {
                ok: true,
                items: cook(self.tree, node, kept),
            }
        } else {
            Cooked::failed()
        };
        let kids = self.descend(&fd, &path, node, &mut cooked);
        self.store(id, cooked);
        kids
    }

    // never follows a symlink: a directory swapped for one since it was listed fails to open
    fn open_under(&self, parent: &OwnedFd, name: &Name, path: &RelPath) -> Option<OwnedFd> {
        let rel = RelPath::root().join(name).ok()?;
        match sys::open_beneath(parent.as_fd(), &rel, DIR_FLAGS) {
            Ok(fd) => Some(fd),
            // too many open directories along deep paths: reopen from the root instead
            Err(e) if matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) => {
                sys::open_beneath(self.rfd, path, DIR_FLAGS).ok()
            }
            Err(_) => None,
        }
    }

    // a directory's own .git and .gitignore must govern its children, so this runs before they are classified
    fn enroll(&self, path: &RelPath, class: Class, raw: &Raw) {
        let needed = {
            let g = self.rules.read().unwrap_or_else(PoisonError::into_inner);
            needs_register(&g, path, class, raw)
        };
        if needed {
            let mut g = self.rules.write().unwrap_or_else(PoisonError::into_inner);
            register(self.root, &mut g, path, raw);
        }
    }

    fn descend(
        &self,
        fd: &Arc<OwnedFd>,
        path: &RelPath,
        node: Option<u32>,
        cooked: &mut Cooked,
    ) -> Vec<Task> {
        let mut kids = Vec::new();
        for it in &mut cooked.items {
            if it.meta.kind != Kind::Dir {
                continue;
            }
            let Ok(child_path) = path.join(&it.name) else {
                continue;
            };
            let id = self.ids.fetch_add(1, Ordering::Relaxed);
            it.child = Some(id);
            kids.push(Task {
                id,
                path: child_path,
                class: if it.domain == Domain::GitRo {
                    Class::GitRo
                } else {
                    Class::Synced
                },
                node: node.and_then(|n| self.tree.child(n, it.name.as_str())),
                src: Src::Under(Arc::clone(fd), it.name.clone()),
            });
        }
        kids
    }

    fn store(&self, id: usize, c: Cooked) {
        lock(&self.done).push((id, c));
    }
}

// classifies and observes the subtree root itself; None when there is nothing to walk
fn enter(
    rfd: BorrowedFd<'_>,
    dev: u64,
    dir: &RelPath,
    rules: &Rules,
    tree: &mut Tree,
    out: &mut Option<&mut Vec<Change>>,
) -> io::Result<Option<(Class, u32, OwnedFd)>> {
    let mut removed = Vec::new();
    let class = rules.classify(dir, true);
    if matches!(class, Class::Ignored | Class::Internal) {
        tree.remove_subtree(dir, &mut removed);
        emit(out, removed);
        return Ok(None);
    }
    let fd = match sys::open_beneath(rfd, dir, DIR_FLAGS) {
        Ok(fd) => fd,
        Err(e) if is_gone(&e) => {
            tree.remove_subtree(dir, &mut removed);
            emit(out, removed);
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let stat = sys::stat_key(fd.as_fd())?;
    if stat.dev != dev {
        tree.remove_subtree(dir, &mut removed);
        emit(out, removed);
        return Ok(None);
    }
    let git_ro = class == Class::GitRo;
    let domain = if git_ro {
        Domain::GitRo
    } else {
        Domain::Synced
    };
    emit(
        out,
        tree.observe(
            dir,
            Observed::Present {
                meta: dir_meta(&stat, git_ro),
                stat,
                domain,
            },
        ),
    );
    Ok(tree.node_of(dir).map(|node| (class, node, fd)))
}

fn is_gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    ) || e.raw_os_error() == Some(libc::ELOOP)
        || e.raw_os_error() == Some(libc::ENOTDIR)
}

fn emit(out: &mut Option<&mut Vec<Change>>, changes: impl IntoIterator<Item = Change>) {
    if let Some(o) = out.as_mut() {
        o.extend(changes);
    }
}

// other filesystems mounted inside the project are not entered: the watcher never reports their changes
fn read_one(fd: BorrowedFd<'_>, dev: u64, class: Class) -> Raw {
    let mut raw = Raw::default();
    let mut ents: Vec<DirEntryPlus> = Vec::new();
    if sys::read_dir_plus(fd, &mut ents).is_err() {
        return raw;
    }
    raw.ok = true;
    raw.ents.reserve(ents.len());
    for e in ents {
        let Some(kind) = e.kind else { continue };
        if kind == Kind::Dir && e.stat.dev != dev {
            continue;
        }
        let link = match kind {
            Kind::Symlink => match read_link(fd, &e.name) {
                Some(l) => Some(l),
                None => continue,
            },
            _ => None,
        };
        if class == Class::Synced {
            match (e.name.as_str(), kind) {
                (".gitignore", Kind::File) => raw.ignore_text = read_rule(fd),
                (".git", Kind::File | Kind::Dir) => raw.has_git = true,
                _ => {}
            }
        }
        raw.ents.push(RawEnt {
            name: e.name,
            kind,
            stat: e.stat,
            link,
        });
    }
    raw
}

fn read_link(dir: BorrowedFd<'_>, name: &Name) -> Option<LinkTarget> {
    let target = rustix::fs::readlinkat(dir, name.as_str(), Vec::new()).ok()?;
    LinkTarget::new(target.to_str().ok()?).ok()
}

fn read_rule(dir: BorrowedFd<'_>) -> Option<Vec<u8>> {
    let fd = rustix::fs::openat(
        dir,
        ".gitignore",
        FILE_FLAGS | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .ok()?;
    let mut v = Vec::new();
    File::from(fd).take(RULE_MAX + 1).read_to_end(&mut v).ok()?;
    (v.len() as u64 <= RULE_MAX).then_some(v)
}

// whether register would change anything, so most directories never take the write lock
fn needs_register(rules: &Rules, path: &RelPath, class: Class, raw: &Raw) -> bool {
    raw.ok
        && class == Class::Synced
        && (raw.has_git
            || raw.ignore_text.is_some()
            || path.is_root()
            || rules.is_repo(path)
            || rules.has_dir_rules(path))
}

fn register(root: &Path, rules: &mut Rules, path: &RelPath, raw: &Raw) {
    if raw.has_git {
        repo::register(rules, root, path);
    } else {
        if rules.is_repo(path) {
            rules.remove_repo(path);
        }
        if path.is_root() {
            repo::register_plain_root(rules, root);
        }
    }
    if raw.ignore_text.is_some() || rules.has_dir_rules(path) {
        let file = if path.is_root() {
            RelPath::new(".gitignore")
        } else {
            RelPath::new(&format!("{}/.gitignore", path.as_str()))
        };
        if let Ok(file) = file {
            rules.update_rule_file(&file, raw.ignore_text.as_deref());
        }
    }
}

// the entries of one directory that sync, each with whether it is git read-only
fn classify_all(rules: &Rules, path: &RelPath, ents: Vec<RawEnt>) -> Vec<(RawEnt, bool)> {
    let mut ctx = rules.dir_ctx(path);
    ents.into_iter()
        .filter_map(
            |e| match rules.classify_in(&mut ctx, e.name.as_str(), e.kind == Kind::Dir) {
                Class::Synced => Some((e, false)),
                Class::GitRo => Some((e, true)),
                Class::Ignored | Class::Internal => None,
            },
        )
        .collect()
}

fn cook(tree: &Tree, node: Option<u32>, kept: Vec<(RawEnt, bool)>) -> Vec<Item> {
    let mut items = Vec::with_capacity(kept.len());
    for (e, git_ro) in kept {
        let domain = if git_ro {
            Domain::GitRo
        } else {
            Domain::Synced
        };
        let (meta, stat) = match e.kind {
            Kind::Dir => (dir_meta(&e.stat, git_ro), e.stat),
            Kind::Symlink => {
                let Some(link) = e.link else { continue };
                let size = link.as_str().len() as u64;
                (
                    Meta {
                        kind: Kind::Symlink,
                        perm: perm(e.stat.mode),
                        size,
                        mtime_ns: e.stat.mtime_ns,
                        ctime_ns: e.stat.ctime_ns,
                        hash: None,
                        link: Some(link),
                        git_ro,
                    },
                    e.stat,
                )
            }
            Kind::File => {
                if e.stat.size > FILE_MAX {
                    continue;
                }
                let cached = node
                    .and_then(|n| tree.child(n, e.name.as_str()))
                    .and_then(|n| tree.entry(n))
                    .filter(|x| x.stat == e.stat && x.meta.kind == Kind::File)
                    .and_then(|x| x.meta.hash);
                let hash = match cached {
                    Some(h) => Some(h),
                    None if e.stat.size == 0 => Some(*blake3::hash(&[]).as_bytes()),
                    None => None,
                };
                let stat = e.stat;
                let meta = Meta {
                    kind: Kind::File,
                    perm: perm(stat.mode),
                    size: stat.size,
                    mtime_ns: stat.mtime_ns,
                    ctime_ns: stat.ctime_ns,
                    hash,
                    link: None,
                    git_ro,
                };
                (meta, stat)
            }
        };
        items.push(Item {
            name: e.name,
            meta,
            stat,
            domain,
            child: None,
        });
    }
    items
}

// merges one directory's result into the tree and queues the results of its subdirectories
fn apply(
    tree: &mut Tree,
    node: u32,
    c: Cooked,
    out: &mut Option<&mut Vec<Change>>,
    next: &mut VecDeque<(usize, u32)>,
) {
    if !c.ok {
        return;
    }
    let want = out.is_some();
    let mut stale = Vec::new();
    {
        let present: FxHashSet<&str> = c.items.iter().map(|i| i.name.as_str()).collect();
        tree.children(node, &mut |n, name, _| {
            if !present.contains(name.as_str()) {
                stale.push(n);
            }
        });
    }
    for n in stale {
        emit(out, tree.remove_at(n, want));
    }
    for it in c.items {
        let o = Observed::Present {
            meta: it.meta,
            stat: it.stat,
            domain: it.domain,
        };
        emit(out, tree.observe_in(node, it.name.as_str(), o, None, want));
        if let Some(id) = it.child
            && let Some(child) = tree.child(node, it.name.as_str())
        {
            next.push_back((id, child));
        }
    }
}

fn perm(mode: u32) -> u16 {
    (mode & 0o7777) as u16
}

fn dir_meta(stat: &StatKey, git_ro: bool) -> Meta {
    Meta {
        kind: Kind::Dir,
        perm: perm(stat.mode),
        size: 0,
        mtime_ns: stat.mtime_ns,
        ctime_ns: stat.ctime_ns,
        hash: None,
        link: None,
        git_ro,
    }
}

pub fn hash_fd(fd: OwnedFd, size: u64) -> io::Result<Hash32> {
    let mut r = File::from(fd).take(size);
    // taken out of the slot so a nested rayon steal on this thread never shares it
    let mut buf = BUF.take();
    if buf.len() < HASH_BUF {
        buf.resize(HASH_BUF, 0);
    }
    let mut h = blake3::Hasher::new();
    let res = loop {
        match r.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if size >= RAYON_MIN {
                    h.update_rayon(&buf[..n]);
                } else {
                    h.update(&buf[..n]);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => break Err(e),
        }
    };
    BUF.set(buf);
    res.map(|()| *h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, fs, os::unix::fs::symlink};

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    struct Want {
        kind: Kind,
        size: u64,
        hash: Option<Hash32>,
        link: Option<String>,
    }

    fn expected(root: &Path, rel: &str, rules: &Rules, out: &mut HashMap<String, Want>) {
        let dir = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel)
        };
        for de in fs::read_dir(dir).unwrap() {
            let de = de.unwrap();
            let name = de.file_name().into_string().unwrap();
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let md = fs::symlink_metadata(de.path()).unwrap();
            let kind = if md.is_dir() {
                Kind::Dir
            } else if md.file_type().is_symlink() {
                Kind::Symlink
            } else {
                Kind::File
            };
            if matches!(
                rules.classify(&rp(&path), kind == Kind::Dir),
                Class::Ignored | Class::Internal
            ) {
                continue;
            }
            let want = match kind {
                Kind::Dir => Want {
                    kind,
                    size: 0,
                    hash: None,
                    link: None,
                },
                Kind::File => {
                    let data = fs::read(de.path()).unwrap();
                    Want {
                        kind,
                        size: data.len() as u64,
                        hash: Some(*blake3::hash(&data).as_bytes()),
                        link: None,
                    }
                }
                Kind::Symlink => {
                    let t = fs::read_link(de.path())
                        .unwrap()
                        .into_os_string()
                        .into_string()
                        .unwrap();
                    Want {
                        kind,
                        size: t.len() as u64,
                        hash: None,
                        link: Some(t),
                    }
                }
            };
            out.insert(path.clone(), want);
            if kind == Kind::Dir {
                expected(root, &path, rules, out);
            }
        }
    }

    // a scan leaves non-empty files pending; `learned` says the pending hashes were filled in since
    fn assert_matches_fs(root: &Path, rules: &Rules, tree: &Tree, learned: bool) {
        let mut want = HashMap::new();
        expected(root, "", rules, &mut want);
        assert_eq!(tree.len(), want.len());
        let mut pending = 0;
        for (p, w) in &want {
            let e = tree.get(&rp(p)).unwrap_or_else(|| panic!("missing {p}"));
            assert_eq!(e.meta.kind, w.kind, "{p}");
            assert_eq!(e.meta.size, w.size, "{p}");
            if w.kind == Kind::File && w.size > 0 && !learned {
                assert!(e.is_pending(), "{p}");
                pending += 1;
            } else {
                assert_eq!(e.meta.hash, w.hash, "{p}");
            }
            assert_eq!(
                e.meta.link.as_ref().map(|l| l.as_str().to_owned()),
                w.link,
                "{p}"
            );
            assert_eq!(
                e.domain == Domain::GitRo,
                p == ".git" || p.starts_with(".git/"),
                "{p}"
            );
        }
        assert_eq!(tree.pending(), pending);
    }

    // fills every pending hash from the file's own bytes, the way the host's hasher does
    fn learn_all(root: &Path, tree: &mut Tree) {
        let mut jobs = Vec::new();
        let mut cursor = 0;
        loop {
            cursor = tree.pending_from(cursor, usize::MAX, &|_, _| true, &mut jobs);
            if cursor == 0 {
                break;
            }
        }
        for j in jobs {
            let data = fs::read(root.join(j.path.as_str())).unwrap();
            let h = *blake3::hash(&data).as_bytes();
            assert!(
                tree.set_hash(&j.path, j.ver, &j.stat, h),
                "{}",
                j.path.as_str()
            );
        }
        assert_eq!(tree.pending(), 0);
    }

    #[test]
    fn scan_matches_std_fs_and_rescans_warm() {
        let root = std::env::temp_dir().join(format!("csync-scan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src/deep/er")).unwrap();
        fs::create_dir_all(root.join("build/out")).unwrap();
        fs::create_dir_all(root.join(".git/objects")).unwrap();
        fs::write(root.join(".gitignore"), "*.log\nbuild/\n").unwrap();
        fs::write(root.join("a.txt"), "hello").unwrap();
        fs::write(root.join("b.log"), "noise").unwrap();
        fs::write(root.join("build/out/x.bin"), vec![7u8; 1000]).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("src/empty"), "").unwrap();
        fs::write(
            root.join("src/deep/er/big.bin"),
            vec![3u8; RAYON_MIN as usize + 17],
        )
        .unwrap();
        fs::write(root.join("src/deep/.gitignore"), "*.tmp\n").unwrap();
        fs::write(root.join("src/deep/x.tmp"), "t").unwrap();
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(root.join(".git/objects/x.log"), "git owns this").unwrap();
        symlink("a.txt", root.join("link")).unwrap();

        let mut rules = Rules::new(&[]);
        let mut tree = scan(&root, &mut rules).unwrap();
        assert_matches_fs(&root, &rules, &tree, false);
        assert!(tree.get(&rp("b.log")).is_none());
        assert!(tree.get(&rp("build")).is_none());
        assert!(tree.get(&rp("src/deep/x.tmp")).is_none());
        assert!(tree.get(&rp(".git/objects/x.log")).is_some());
        assert_eq!(tree.get(&rp("a.txt")).unwrap().meta.hash, None);
        assert_eq!(
            tree.get(&rp("src/empty")).and_then(|e| e.meta.hash),
            Some(*blake3::hash(&[]).as_bytes())
        );

        learn_all(&root, &mut tree);
        assert_matches_fs(&root, &rules, &tree, true);
        assert_eq!(
            tree.get(&rp("a.txt")).and_then(|e| e.meta.hash),
            Some(*blake3::hash(b"hello").as_bytes())
        );

        let seq = tree.seq();
        let tree = rescan(&root, &mut rules, tree).unwrap();
        assert_eq!(tree.seq(), seq);
        assert_eq!(tree.changes_since(seq).unwrap().len(), 0);
        assert_matches_fs(&root, &rules, &tree, true);

        fs::write(root.join("src/main.rs"), "fn main() { println!(); }\n").unwrap();
        fs::remove_file(root.join("a.txt")).unwrap();
        let mut tree = rescan(&root, &mut rules, tree).unwrap();
        let changes = tree.changes_since(seq).unwrap();
        assert!(changes.iter().any(
            |c| matches!(c, Change::Upsert { path, meta, .. } if path.as_str() == "src/main.rs"
            && meta.hash.is_none() && meta.size == 26)
        ));
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, Change::Remove { path } if path.as_str() == "a.txt"))
        );
        assert_eq!(tree.pending(), 1);
        learn_all(&root, &mut tree);
        assert_eq!(
            tree.get(&rp("src/main.rs")).and_then(|e| e.meta.hash),
            Some(*blake3::hash(b"fn main() { println!(); }\n").as_bytes())
        );
        assert_matches_fs(&root, &rules, &tree, true);

        fs::write(root.join("src/deep/.gitignore"), "").unwrap();
        let mut out = Vec::new();
        scan_subtree(&root, &rp("src/deep"), &mut rules, &mut tree, &mut out).unwrap();
        assert!(out.iter().any(
            |c| matches!(c, Change::Upsert { path, .. } if path.as_str() == "src/deep/x.tmp")
        ));
        learn_all(&root, &mut tree);
        assert_matches_fs(&root, &rules, &tree, true);

        let _ = fs::remove_dir_all(&root);
    }

    // one directory at a time, each reopened from the root: the shape of the walk before it was parallel
    fn reference_walk(root: &Path, rules: &mut Rules, tree: &mut Tree) {
        let root_fd = rustix::fs::open(root, DIR_FLAGS, Mode::empty()).unwrap();
        let rfd = root_fd.as_fd();
        let dev = sys::stat_key(rfd).unwrap().dev;
        let mut level = vec![(RelPath::root(), ROOT, Class::Synced)];
        while !level.is_empty() {
            let mut next = Vec::new();
            for (path, node, class) in level {
                let Ok(fd) = sys::open_beneath(rfd, &path, DIR_FLAGS) else {
                    continue;
                };
                let raw = read_one(fd.as_fd(), dev, class);
                if !raw.ok {
                    continue;
                }
                if needs_register(rules, &path, class, &raw) {
                    register(root, rules, &path, &raw);
                }
                let kept = classify_all(rules, &path, raw.ents);
                let items = cook(tree, Some(node), kept);
                let mut stale = Vec::new();
                tree.children(node, &mut |n, name, _| {
                    if !items.iter().any(|i| i.name == *name) {
                        stale.push(n);
                    }
                });
                for n in stale {
                    let _ = tree.remove_at(n, false);
                }
                for it in items {
                    let is_dir = it.meta.kind == Kind::Dir;
                    let class = if it.domain == Domain::GitRo {
                        Class::GitRo
                    } else {
                        Class::Synced
                    };
                    let o = Observed::Present {
                        meta: it.meta,
                        stat: it.stat,
                        domain: it.domain,
                    };
                    let _ = tree.observe_in(node, it.name.as_str(), o, None, false);
                    if is_dir
                        && let Some(n) = tree.child(node, it.name.as_str())
                        && let Ok(p) = path.join(&it.name)
                    {
                        next.push((p, n, class));
                    }
                }
            }
            level = next;
        }
    }

    type Dump = Vec<(u32, String, Meta, StatKey, Domain, u64)>;

    fn dump(t: &Tree) -> Dump {
        let mut v = Vec::new();
        t.walk(&mut |parent, name, e| {
            v.push((
                parent,
                name.as_str().to_owned(),
                e.meta.clone(),
                e.stat,
                e.domain,
                e.seq,
            ))
        });
        v
    }

    fn repo_pairs(r: &Rules) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = r
            .repos()
            .into_iter()
            .map(|(a, b)| (a.as_str().to_owned(), b.as_str().to_owned()))
            .collect();
        v.sort();
        v
    }

    fn build_tree(root: &Path) {
        let _ = fs::remove_dir_all(root);
        for d in [
            ".git/objects",
            "src/deep",
            "build/out",
            "nested/.git",
            "nested/sub",
            "empty",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::write(root.join(".gitignore"), "*.log\nbuild/\n!keep.log\n").unwrap();
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(root.join(".git/objects/x.log"), "git owns this").unwrap();
        fs::write(root.join("a.txt"), "hello").unwrap();
        fs::write(root.join("b.log"), "noise").unwrap();
        fs::write(root.join("keep.log"), "kept").unwrap();
        fs::write(root.join("Case.txt"), "upper").unwrap();
        fs::write(root.join("case.txt"), "lower").unwrap();
        fs::write(root.join("build/out/x.bin"), vec![1u8; 100]).unwrap();
        fs::write(root.join("src/.gitignore"), "*.tmp\n").unwrap();
        fs::write(root.join("src/x.tmp"), "t").unwrap();
        fs::write(root.join("src/m.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("src/deep/z.rs"), "").unwrap();
        fs::write(root.join("nested/.git/HEAD"), "ref: refs/heads/dev\n").unwrap();
        fs::write(root.join("nested/.gitignore"), "*.o\n").unwrap();
        fs::write(root.join("nested/a.o"), "obj").unwrap();
        fs::write(root.join("nested/lib.c"), "int x;\n").unwrap();
        fs::write(root.join("nested/sub/k.txt"), "k").unwrap();
        symlink("a.txt", root.join("link")).unwrap();
        symlink("src", root.join("dirlink")).unwrap();
        symlink("missing", root.join("dangling")).unwrap();
        // enough directories at once for helper threads to start
        for i in 0..40 {
            for j in 0..3 {
                let d = root.join(format!("d{i}/s{j}"));
                fs::create_dir_all(&d).unwrap();
                fs::write(d.join("f.txt"), format!("{i}-{j}")).unwrap();
                fs::write(d.join("n.log"), "ignored").unwrap();
            }
        }
    }

    #[test]
    fn parallel_walk_equals_sequential_reference() {
        let root = std::env::temp_dir().join(format!("csync-scan-ref-{}", std::process::id()));
        build_tree(&root);

        let mut rules = Rules::new(&[]);
        let tree = scan(&root, &mut rules).unwrap();
        let mut ref_rules = Rules::new(&[]);
        let mut ref_tree = Tree::new(0);
        ref_tree.set_journaling(false);
        reference_walk(&root, &mut ref_rules, &mut ref_tree);
        ref_tree.set_journaling(true);

        assert!(tree.get(&rp("b.log")).is_none());
        assert!(tree.get(&rp("keep.log")).is_some());
        assert!(tree.get(&rp("src/x.tmp")).is_none());
        assert!(tree.get(&rp("nested/a.o")).is_none());
        assert!(tree.get(&rp("nested/lib.c")).is_some());
        assert!(tree.get(&rp("d39/s2/f.txt")).is_some());
        assert!(tree.get(&rp("d39/s2/n.log")).is_none());
        assert!(rules.is_repo(&rp("nested")));
        assert_eq!(
            tree.get(&rp("dirlink")).map(|e| e.meta.kind),
            Some(Kind::Symlink)
        );
        assert!(tree.get(&rp("dirlink/m.rs")).is_none());
        assert_eq!(dump(&tree), dump(&ref_tree));
        assert_eq!(repo_pairs(&rules), repo_pairs(&ref_rules));

        fs::write(root.join("src/m.rs"), "fn main() { 1; }\n").unwrap();
        fs::write(root.join("src/deep/z.rs"), "now full").unwrap();
        fs::write(root.join("src/.gitignore"), "*.tmp\n*.rs\n").unwrap();
        fs::remove_file(root.join("a.txt")).unwrap();
        fs::write(root.join("d3/s1/new.txt"), "new").unwrap();
        fs::remove_file(root.join("nested/lib.c")).unwrap();
        fs::remove_dir_all(root.join("d5")).unwrap();
        symlink("a.txt", root.join("d5")).unwrap();
        fs::remove_dir_all(root.join("d6/s0")).unwrap();

        let (seq, ref_seq) = (tree.seq(), ref_tree.seq());
        assert_eq!(seq, ref_seq);
        let tree = rescan(&root, &mut rules, tree).unwrap();
        reference_walk(&root, &mut ref_rules, &mut ref_tree);
        assert!(tree.get(&rp("src/m.rs")).is_none());
        assert!(tree.get(&rp("d3/s1/new.txt")).is_some());
        assert_eq!(dump(&tree), dump(&ref_tree));
        assert_eq!(tree.changes_since(seq), ref_tree.changes_since(ref_seq));
        assert!(!tree.changes_since(seq).unwrap().is_empty());

        let _ = fs::remove_dir_all(&root);
    }
}
