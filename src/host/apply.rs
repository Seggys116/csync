use super::{Core, RULE_MAX, dir_meta, file_meta, hash_fd, link_meta, read_rule};
use crate::ignore::{
    repo,
    rules::{Class, Rules},
};
use crate::index::{
    persist, scan,
    tree::{Domain, Entry, Observed, StatKey, Tree},
};
use crate::proto::{
    Change, FILE_MAX, Hash32, Kind, LinkTarget, Name, Notice, NoticeKind, RelPath, Seq,
};
use crate::sys::{self, WatchEvent, Watcher, wflag};
use crossbeam_channel::{Receiver, at, never, select};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use rustix::fs::{Mode, OFlags};
use std::{
    os::fd::{AsFd, BorrowedFd},
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

pub(crate) const QUIET: Duration = Duration::from_millis(1);
pub(crate) const MAX_WAIT: Duration = Duration::from_millis(50);
const LEAD_IDLE: Duration = Duration::from_millis(50);
const RETRY_DELAY: Duration = Duration::from_millis(20);
const RESCAN_QUIET: Duration = Duration::from_millis(200);
const RESCAN_MAX: Duration = Duration::from_secs(5);
const SAVE_EVERY: Duration = Duration::from_secs(60);
const EXC_DEBOUNCE: Duration = Duration::from_millis(200);
const RULE_SETTLE: Duration = Duration::from_millis(100);
const PATHS_MAX: usize = 1 << 18;
const COOKIES_MAX: usize = 4_096;
// below this a batch of stats is cheaper serial than waking and spinning the rayon pool
const PAR_MIN: usize = 256;
#[cfg(target_os = "macos")]
const EXCLUDES_MAX: usize = 8;
#[cfg(not(target_os = "macos"))]
const EXCLUDES_MAX: usize = usize::MAX;

const CHURN_DIRS: [&str; 11] = [
    "target",
    "node_modules",
    ".build",
    "build",
    "dist",
    ".next",
    "__pycache__",
    ".venv",
    "venv",
    ".gradle",
    "out",
];

#[derive(Default)]
pub(crate) struct Batch {
    pub(crate) paths: Vec<(RelPath, u32)>,
    pub(crate) pairs: Vec<(RelPath, RelPath)>,
    pub(crate) rescans: Vec<RelPath>,
    pub(crate) rescan_all: bool,
}

// merges watcher bursts: 1 ms of quiet or 50 ms after the first event, one entry per path;
// the first event after an idle spell is applied at once, since a lone edit has nothing to merge with
#[derive(Default)]
pub(crate) struct Coalescer {
    paths: FxHashMap<RelPath, u32>,
    cookies: FxHashMap<u32, RelPath>,
    pairs: Vec<(RelPath, RelPath)>,
    rescans: FxHashSet<RelPath>,
    rescan_all: bool,
    first: Option<Instant>,
    last: Option<Instant>,
    lead: bool,
    last_taken: Option<Instant>,
}

impl Coalescer {
    pub(crate) fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    pub(crate) fn add(&mut self, evs: Vec<WatchEvent>, now: Instant) {
        if evs.is_empty() {
            return;
        }
        if self.first.is_none() {
            self.first = Some(now);
            self.lead = self.last_taken.is_none_or(|t| now >= t + LEAD_IDLE);
        }
        self.last = Some(now);
        for e in evs {
            if e.flags & wflag::RESCAN != 0 {
                if e.path.is_root() {
                    self.rescan_all = true;
                } else {
                    self.rescans.insert(e.path);
                }
                continue;
            }
            if self.rescan_all {
                continue;
            }
            if e.flags & wflag::RENAMED != 0 && e.cookie != 0 {
                match self.cookies.remove(&e.cookie) {
                    Some(from) if from != e.path => self.pairs.push((from, e.path.clone())),
                    Some(_) => {}
                    None => {
                        if self.cookies.len() >= COOKIES_MAX {
                            self.cookies.clear();
                        }
                        self.cookies.insert(e.cookie, e.path.clone());
                    }
                }
            }
            *self.paths.entry(e.path).or_insert(0) |= e.flags;
        }
        if self.rescan_all || self.paths.len() > PATHS_MAX {
            self.rescan_all = true;
            self.paths = FxHashMap::default();
            self.pairs.clear();
            self.rescans.clear();
            self.cookies.clear();
        }
    }

    // a full rescan waits for the storm that caused it to settle, so one walk covers all of it
    pub(crate) fn deadline(&self) -> Option<Instant> {
        if self.rescan_all {
            return Some((self.last? + RESCAN_QUIET).min(self.first? + RESCAN_MAX));
        }
        if self.lead {
            return self.first;
        }
        Some((self.last? + QUIET).min(self.first? + MAX_WAIT))
    }

    pub(crate) fn take(&mut self) -> Batch {
        let mut paths: Vec<(RelPath, u32)> = std::mem::take(&mut self.paths).into_iter().collect();
        paths.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut rescans: Vec<RelPath> = std::mem::take(&mut self.rescans).into_iter().collect();
        rescans.sort_unstable();
        let b = Batch {
            paths,
            pairs: std::mem::take(&mut self.pairs),
            rescans,
            rescan_all: self.rescan_all,
        };
        self.cookies.clear();
        self.rescan_all = false;
        self.last_taken = self.last.or(self.last_taken);
        self.first = None;
        self.last = None;
        self.lead = false;
        b
    }
}

// visits every entry with its full path, parents before children
pub(crate) fn each_entry(tree: &Tree, f: &mut dyn FnMut(&RelPath, &Entry)) {
    let mut dirs: Vec<Option<RelPath>> = vec![Some(RelPath::root())];
    tree.walk(&mut |parent, name, e| {
        let p = dirs
            .get(parent as usize)
            .and_then(Option::as_ref)
            .and_then(|d| d.join(name).ok());
        if let Some(p) = &p {
            f(p, e);
        }
        dirs.push(if e.meta.kind == Kind::Dir { p } else { None });
    });
}

// copies the indexed subtree under `from` to `to` so a move reuses every hash; entries ignored at the destination are skipped
pub(crate) fn copy_subtree(
    tree: &mut Tree,
    rules: &Rules,
    from: &RelPath,
    to: &RelPath,
    out: &mut Vec<Change>,
) {
    let mut stack = vec![(from.clone(), to.clone())];
    let mut kids: Vec<(Name, Entry)> = Vec::new();
    while let Some((f, t)) = stack.pop() {
        kids.clear();
        tree.for_children(&f, &mut |n, e| kids.push((n.clone(), e.clone())));
        for (n, e) in kids.drain(..) {
            let (Ok(fc), Ok(tc)) = (f.join(&n), t.join(&n)) else {
                continue;
            };
            let is_dir = e.meta.kind == Kind::Dir;
            let domain = match rules.classify(&tc, is_dir) {
                Class::Synced => Domain::Synced,
                Class::GitRo => Domain::GitRo,
                Class::Ignored | Class::Internal => continue,
            };
            let mut meta = e.meta;
            meta.git_ro = domain == Domain::GitRo;
            out.extend(tree.observe(
                &tc,
                Observed::Present {
                    meta,
                    stat: e.stat,
                    domain,
                },
            ));
            if is_dir {
                stack.push((fc, tc));
            }
        }
    }
}

// first ancestor of p (or p) that the index lacks; a scan from there brings p in
fn top_missing(tree: &Tree, p: &RelPath) -> Option<RelPath> {
    let s = p.as_str();
    let mut end = 0;
    loop {
        let e = s[end..].find('/').map_or(s.len(), |i| end + i);
        let prefix = RelPath::new(&s[..e]).ok()?;
        if tree.get(&prefix).is_none() {
            return Some(prefix);
        }
        if e == s.len() {
            return None;
        }
        end = e + 1;
    }
}

fn rescan_all_event() -> WatchEvent {
    WatchEvent {
        path: RelPath::root(),
        flags: wflag::RESCAN | wflag::OVERFLOW,
        cookie: 0,
    }
}

fn parent_of(p: &RelPath) -> RelPath {
    p.split_last()
        .and_then(|(d, _)| RelPath::new(d).ok())
        .unwrap_or_else(RelPath::root)
}

// keeps only the outermost of nested directories
fn outermost(mut v: Vec<RelPath>) -> Vec<RelPath> {
    v.sort_unstable();
    v.dedup();
    let mut out: Vec<RelPath> = Vec::with_capacity(v.len());
    for p in v {
        if out.last().is_some_and(|q| p.starts_with(q)) {
            continue;
        }
        out.push(p);
    }
    out
}

// stat key, content hash, kind, seq and link target of the tree entry before the probe
type Prior = (StatKey, Option<Hash32>, Kind, Seq, Option<LinkTarget>);

struct Probe {
    path: RelPath,
    flags: u32,
    prior: Option<Prior>,
}

enum Seen {
    Absent,
    Skip,
    Raced,
    Present {
        kind: Kind,
        stat: StatKey,
        hash: Option<Hash32>,
        link: Option<LinkTarget>,
    },
}

fn gone_err(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    ) || matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR))
}

// a rule file that is there but cannot be read right now is not a removal; keeping its rules fails closed
fn unreadable(root: BorrowedFd<'_>, p: &RelPath) -> bool {
    let Some((d, n)) = p.split_last() else {
        return false;
    };
    let Ok(dp) = RelPath::new(d) else {
        return false;
    };
    match sys::open_beneath(root, &dp, OFlags::RDONLY | OFlags::DIRECTORY) {
        Err(e) => !gone_err(&e),
        Ok(fd) => match sys::stat_key_at(fd.as_fd(), n) {
            Err(e) => !gone_err(&e),
            Ok(st) => sys::kind_of_mode(st.mode) == Some(Kind::File) && st.size <= RULE_MAX,
        },
    }
}

fn rule_stat(root: BorrowedFd<'_>, p: &RelPath) -> Option<StatKey> {
    let (d, n) = p.split_last()?;
    let dp = RelPath::new(d).ok()?;
    let fd = sys::open_beneath(root, &dp, OFlags::RDONLY | OFlags::DIRECTORY).ok()?;
    sys::stat_key_at(fd.as_fd(), n).ok()
}

// probes arrive sorted, so siblings are adjacent: each parent directory is opened once per batch
#[derive(Clone, Copy)]
struct Vol {
    folds: bool,
    dev: u64,
}

fn look_all(root: BorrowedFd<'_>, probes: &[Probe], vol: Vol) -> Vec<Seen> {
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut start = 0;
    for i in 1..=probes.len() {
        let parent = |k: usize| probes[k].path.split_last().map(|(d, _)| d);
        if i == probes.len() || parent(i) != parent(start) {
            groups.push((start, i));
            start = i;
        }
    }
    let run = |&(a, b): &(usize, usize)| look_dir(root, &probes[a..b], vol);
    if probes.len() >= PAR_MIN && groups.len() > 1 {
        groups
            .par_iter()
            .map(run)
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect()
    } else {
        groups.iter().flat_map(run).collect()
    }
}

fn look_dir(root: BorrowedFd<'_>, probes: &[Probe], vol: Vol) -> Vec<Seen> {
    let dir = probes
        .first()
        .and_then(|p| p.path.split_last())
        .and_then(|(d, _)| RelPath::new(d).ok());
    let dfd = match dir.map(|d| sys::open_beneath(root, &d, OFlags::RDONLY | OFlags::DIRECTORY)) {
        Some(Ok(fd)) => fd,
        Some(Err(e)) if gone_err(&e) => return probes.iter().map(|_| Seen::Absent).collect(),
        Some(Err(e)) => return probes.iter().map(|_| skip(&e)).collect(),
        None => return probes.iter().map(|_| Seen::Skip).collect(),
    };
    probes
        .iter()
        .map(|p| {
            // a volume mounted inside the root is not synced; the watcher never sees into it
            match look(dfd.as_fd(), p) {
                // only directories: overlayfs reports files with the device of the layer holding them
                Seen::Present {
                    kind: Kind::Dir,
                    stat,
                    ..
                } if stat.dev != vol.dev => Seen::Absent,
                Seen::Present { .. } if vol.folds && respelled(dfd.as_fd(), p) => Seen::Absent,
                s => s,
            }
        })
        .collect()
}

// on folding volumes a name that changed only in case or normalisation still resolves; only a rename can cause that
fn respelled(dfd: BorrowedFd<'_>, p: &Probe) -> bool {
    if p.prior.is_some() && p.flags & (wflag::CREATED | wflag::RENAMED | wflag::REMOVED) == 0 {
        return false;
    }
    let Some((_, name)) = p.path.split_last() else {
        return false;
    };
    matches!(sys::spelled_at(dfd, name), Ok(false))
}

// fd or memory exhaustion and interrupted calls pass; anything else (permissions) leaves the path unsynced
fn skip(e: &std::io::Error) -> Seen {
    match e.raw_os_error() {
        Some(
            libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::EINTR | libc::EAGAIN | libc::EBUSY,
        ) => Seen::Raced,
        _ => Seen::Skip,
    }
}

// stats one path and hashes it only when its stat key says the content may have changed
fn look(dfd: BorrowedFd<'_>, p: &Probe) -> Seen {
    let Some((_, name)) = p.path.split_last() else {
        return Seen::Skip;
    };
    let st = match sys::stat_key_at(dfd, name) {
        Ok(s) => s,
        Err(e) if gone_err(&e) => return Seen::Absent,
        Err(e) => return skip(&e),
    };
    match sys::kind_of_mode(st.mode) {
        None => Seen::Absent,
        Some(Kind::Dir) => Seen::Present {
            kind: Kind::Dir,
            stat: st,
            hash: None,
            link: None,
        },
        Some(Kind::Symlink) => {
            let same = p
                .prior
                .as_ref()
                .filter(|x| x.2 == Kind::Symlink && sys::same_version(&x.0, &st))
                .and_then(|x| x.4.clone());
            let link = same.or_else(|| {
                let t = rustix::fs::readlinkat(dfd.as_fd(), name, Vec::new()).ok()?;
                LinkTarget::new(t.to_str().ok()?).ok()
            });
            match link {
                Some(l) => Seen::Present {
                    kind: Kind::Symlink,
                    stat: st,
                    hash: None,
                    link: Some(l),
                },
                None => Seen::Absent,
            }
        }
        Some(Kind::File) => {
            if st.size > FILE_MAX {
                return Seen::Absent;
            }
            if let Some((ps, Some(h), Kind::File, _, _)) = &p.prior
                && sys::same_version(ps, &st)
            {
                return Seen::Present {
                    kind: Kind::File,
                    stat: st,
                    hash: Some(*h),
                    link: None,
                };
            }
            if st.size == 0 {
                return Seen::Present {
                    kind: Kind::File,
                    stat: st,
                    hash: Some(*blake3::hash(&[]).as_bytes()),
                    link: None,
                };
            }
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let fd = match rustix::fs::openat(dfd.as_fd(), name, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(e) if gone_err(&e.into()) => return Seen::Raced,
                Err(e) => return skip(&e.into()),
            };
            let k1 = match sys::stat_key(fd.as_fd()) {
                Ok(k) => k,
                Err(e) => return skip(&e),
            };
            if sys::kind_of_mode(k1.mode) != Some(Kind::File) {
                return Seen::Raced;
            }
            let h = match hash_fd(fd.as_fd(), k1.size) {
                Ok(h) => h,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Seen::Raced,
                Err(e) => return skip(&e),
            };
            match sys::stat_key(fd.as_fd()) {
                Ok(k2) if sys::same_version(&k1, &k2) => Seen::Present {
                    kind: Kind::File,
                    stat: k2,
                    hash: Some(h),
                    link: None,
                },
                _ => Seen::Raced,
            }
        }
    }
}

pub(crate) struct Applier {
    core: Arc<Core>,
    watcher: Box<dyn Watcher>,
    rx: Receiver<Vec<WatchEvent>>,
    stop: Receiver<()>,
    index_path: PathBuf,
    excludes: Vec<RelPath>,
    exc: FxHashMap<RelPath, Vec<RelPath>>,
    exc_pending: FxHashSet<RelPath>,
    exc_due: Option<Instant>,
    rule_seen: FxHashMap<RelPath, (Option<StatKey>, Instant)>,
    retry: Vec<(RelPath, u32)>,
    retry_due: Option<Instant>,
    last_save: Instant,
}

impl Applier {
    pub(crate) fn new(
        core: Arc<Core>,
        watcher: Box<dyn Watcher>,
        rx: Receiver<Vec<WatchEvent>>,
        stop: Receiver<()>,
        index_path: PathBuf,
    ) -> Self {
        Self {
            core,
            watcher,
            rx,
            stop,
            index_path,
            excludes: Vec::new(),
            exc: FxHashMap::default(),
            exc_pending: FxHashSet::default(),
            exc_due: None,
            rule_seen: FxHashMap::default(),
            retry: Vec::new(),
            retry_due: None,
            last_save: Instant::now(),
        }
    }

    pub(crate) fn run(mut self) {
        let _ = self.recompute_excludes();
        let mut co = Coalescer::default();
        loop {
            let save_due = self
                .core
                .dirty
                .load(Ordering::Acquire)
                .then(|| self.last_save + SAVE_EVERY);
            let due = [co.deadline(), self.exc_due, self.retry_due, save_due]
                .into_iter()
                .flatten()
                .min();
            let tick = due.map_or_else(never, at);
            select! {
                recv(self.stop) -> _ => break,
                recv(self.rx) -> m => match m {
                    Ok(evs) => {
                        let now = Instant::now();
                        co.add(evs, now);
                        while let Ok(more) = self.rx.try_recv() {
                            co.add(more, now);
                        }
                        if self.watcher.take_overflow() {
                            co.add(vec![rescan_all_event()], now);
                        }
                        if co.rescan_all && !self.core.root_intact() {
                            self.core.root_lost();
                            break;
                        }
                    }
                    Err(_) => break,
                },
                recv(tick) -> _ => {}
            }
            let now = Instant::now();
            if self.retry_due.is_some_and(|d| d <= now) {
                let evs = self.take_retries();
                co.add(evs, now);
            }
            if co.deadline().is_some_and(|d| d <= now) {
                let b = co.take();
                self.process(b);
            }
            if self.exc_due.is_some_and(|d| d <= now) {
                self.refresh_exceptions();
            }
            // the resume token must not run ahead of what has been applied
            if save_due.is_some_and(|d| d <= now)
                && co.is_empty()
                && self.rx.is_empty()
                && self.retry.is_empty()
            {
                self.save();
            }
        }
        if self.core.is_lost() {
            return;
        }
        while let Ok(more) = self.rx.try_recv() {
            co.add(more, Instant::now());
        }
        for _ in 0..3 {
            let evs = self.take_retries();
            co.add(evs, Instant::now());
            if co.is_empty() {
                break;
            }
            let b = co.take();
            self.process(b);
        }
        // paths still racing a writer would leave the saved resume point ahead of the index
        if !self.retry.is_empty() {
            return;
        }
        self.save();
        if !self.core.dirty.load(Ordering::Acquire) {
            let _ = persist::mark_clean(&self.index_path, &self.core.tree());
        }
    }

    fn save(&mut self) {
        self.last_save = Instant::now();
        if !self.core.dirty.swap(false, Ordering::AcqRel) {
            return;
        }
        let token = self.watcher.resume_token();
        let tree = self.core.tree();
        if persist::save_index(&self.index_path, &tree, token).is_err() {
            self.core.dirty.store(true, Ordering::Release);
        }
    }

    // kept here rather than sent through the bounded event channel, where a full queue would drop them
    fn requeue(&mut self, paths: Vec<RelPath>) {
        if paths.is_empty() {
            return;
        }
        self.retry
            .extend(paths.into_iter().map(|p| (p, wflag::MODIFIED)));
        self.retry_due.get_or_insert(Instant::now() + RETRY_DELAY);
    }

    fn take_retries(&mut self) -> Vec<WatchEvent> {
        self.retry_due = None;
        self.retry
            .drain(..)
            .map(|(path, flags)| WatchEvent {
                path,
                flags,
                cookie: 0,
            })
            .collect()
    }

    fn rescan_dirs(&mut self, dirs: Vec<RelPath>) {
        let mut dirs = outermost(dirs);
        if dirs.is_empty() {
            return;
        }
        // armed before the walk, as at startup, so a write the walk has passed still raises an event;
        // outside the locks, since the watcher's dir filter reads the rules
        for d in &dirs {
            let _ = self.watcher.watch_dir(d);
        }
        let core = self.core.clone();
        let mut rules = core.rules_w();
        let mut tree = core.tree();
        // a committer mid-rename has moved the disk but not the index yet; holds only begin under the tree lock
        {
            let held = super::lock(&core.inflight);
            let before = self.retry.len();
            dirs.retain(|d| {
                let busy = held.iter().any(|h| h.starts_with(d) || d.starts_with(h));
                if busy {
                    self.retry.push((d.clone(), wflag::RESCAN));
                }
                !busy
            });
            if self.retry.len() > before {
                self.retry_due.get_or_insert(Instant::now() + RETRY_DELAY);
            }
        }
        let mut out = Vec::new();
        for d in &dirs {
            let _ = scan::scan_subtree(&core.root_path, d, &mut rules, &mut tree, &mut out);
        }
        drop(rules);
        core.publish_locked(&tree, out, None);
    }

    pub(crate) fn process(&mut self, b: Batch) {
        let core = self.core.clone();
        if b.rescan_all {
            self.rescan_dirs(vec![RelPath::root()]);
            // rules the walk changed may unhide excluded dirs, which the walk could not watch
            let back = self.recompute_excludes();
            self.rescan_dirs(back);
            return;
        }
        let (scopes, mut notices, unsettled) = self.rule_changes(&b.paths);
        let mut paths = b.paths;
        if !unsettled.is_empty() {
            paths.retain(|(p, _)| !unsettled.contains(p));
        }
        let mut moved: FxHashSet<RelPath> = FxHashSet::default();
        for (from, to) in &b.pairs {
            if self.rename_pair(from, to) {
                moved.insert(from.clone());
                moved.insert(to.clone());
            }
        }
        if !moved.is_empty() {
            paths.retain(|(p, _)| !moved.contains(p));
        }

        let mut dirs = scopes;
        // the new rules decide which dirs a watch may cover before the rescan arms it
        if !dirs.is_empty() {
            let back = self.recompute_excludes();
            dirs.extend(back);
        }
        dirs.extend(b.rescans);
        if !dirs.is_empty() {
            self.rescan_dirs(dirs);
        }

        let probes: Vec<Probe> = {
            let tree = core.tree();
            paths
                .into_iter()
                .filter(|(p, _)| !p.is_root())
                .map(|(path, flags)| {
                    let prior = tree
                        .get(&path)
                        .map(|e| (e.stat, e.meta.hash, e.meta.kind, e.seq, e.meta.link.clone()));
                    Probe { path, flags, prior }
                })
                .collect()
        };
        let seen = look_all(
            core.root.as_fd(),
            &probes,
            Vol {
                folds: core.fs.case_fold || core.fs.norm_fold,
                dev: core.root_id.0,
            },
        );

        let mut retry = Vec::new();
        let mut points = Vec::new();
        {
            let mut rules = core.rules_w();
            let mut tree = core.tree();
            let held = super::lock(&core.inflight);
            let mut out = Vec::new();
            for (p, s) in probes.iter().zip(seen) {
                // the committer touched this entry after we sampled it, or is still swapping it, so sample again
                if p.prior.as_ref().map(|x| x.3) != tree.get(&p.path).map(|e| e.seq)
                    || held.iter().any(|h| p.path.starts_with(h))
                {
                    retry.push(p.path.clone());
                    continue;
                }
                match s {
                    Seen::Skip => {}
                    Seen::Raced => retry.push(p.path.clone()),
                    Seen::Absent => out.extend(tree.observe(&p.path, Observed::Absent)),
                    Seen::Present {
                        kind,
                        stat,
                        hash,
                        link,
                    } => {
                        let domain = match rules.classify(&p.path, kind == Kind::Dir) {
                            Class::Synced => Domain::Synced,
                            Class::GitRo => Domain::GitRo,
                            Class::Ignored | Class::Internal => {
                                out.extend(tree.observe(&p.path, Observed::Absent));
                                continue;
                            }
                        };
                        let git_ro = domain == Domain::GitRo;
                        let meta = match (kind, hash, link) {
                            (Kind::File, Some(h), _) => file_meta(&stat, h, git_ro),
                            (Kind::Symlink, _, Some(l)) => link_meta(&stat, l, git_ro),
                            (Kind::Dir, _, _) => dir_meta(&stat, git_ro),
                            _ => continue,
                        };
                        out.extend(tree.observe(&p.path, Observed::Present { meta, stat, domain }));
                        if tree.get(&p.path).is_none() {
                            match top_missing(&tree, &p.path) {
                                Some(m) if m != p.path => points.push(m),
                                _ => points.push(parent_of(&p.path)),
                            }
                        } else if kind == Kind::Dir
                            && (p.prior.as_ref().is_none_or(|x| x.2 != Kind::Dir)
                                || p.flags & (wflag::CREATED | wflag::RENAMED) != 0)
                        {
                            points.push(p.path.clone());
                        }
                    }
                }
            }
            drop(held);
            // new directories go out in the same batch, so a guest never sees a ref before the object it names
            for d in outermost(points) {
                let _ = scan::scan_subtree(&core.root_path, &d, &mut rules, &mut tree, &mut out);
            }
            drop(rules);
            core.publish_locked(&tree, out, None);
        }
        self.requeue(retry);

        for n in notices.drain(..) {
            core.notice(n, true);
        }
    }

    // rule files, repo markers and git index files; returns rescoped subtrees and rule files still being written
    fn rule_changes(
        &mut self,
        paths: &[(RelPath, u32)],
    ) -> (Vec<RelPath>, Vec<Notice>, Vec<RelPath>) {
        let core = self.core.clone();
        let mut scopes = Vec::new();
        let mut notices = Vec::new();
        let mut unsettled = Vec::new();
        let repos = core.rules_r().repos();
        for (p, _) in paths {
            let Some((dir, name)) = p.split_last() else {
                continue;
            };
            if name == ".git" {
                let Ok(wt) = RelPath::new(dir) else { continue };
                if !matches!(core.rules_r().classify(&wt, true), Class::Synced) {
                    continue;
                }
                let exists =
                    sys::open_beneath(core.root.as_fd(), &wt, OFlags::RDONLY | OFlags::DIRECTORY)
                        .is_ok_and(|d| sys::stat_key_at(d.as_fd(), ".git").is_ok());
                let mut rules = core.rules_w();
                if exists {
                    repo::register(&mut rules, &core.root_path, &wt);
                } else {
                    rules.remove_repo(&wt);
                }
                scopes.push(wt);
                continue;
            }
            if let Some((wt, _)) = repos
                .iter()
                .find(|(_, gd)| name == "index" && dir == gd.as_str())
            {
                self.exc_pending.insert(wt.clone());
                self.exc_due.get_or_insert(Instant::now() + EXC_DEBOUNCE);
                continue;
            }
            let is_rule = {
                let r = core.rules_r();
                (name == ".gitignore" && r.classify(p, false) == Class::Synced) || r.is_rule_file(p)
            };
            if !is_rule {
                continue;
            }
            if !self.rule_settled(p) {
                unsettled.push(p.clone());
                continue;
            }
            let text = read_rule(core.root.as_fd(), p);
            if text.is_none() && unreadable(core.root.as_fd(), p) {
                continue;
            }
            if let Some(scope) = core.rules_w().update_rule_file(p, text.as_deref()) {
                notices.push(Notice {
                    kind: NoticeKind::IgnoreChanged,
                    path: scope.clone(),
                });
                scopes.push(scope);
            }
        }
        (scopes, notices, unsettled)
    }

    // a rule file written in place is briefly empty, so neither its rules nor its content go out until it is still
    fn rule_settled(&mut self, p: &RelPath) -> bool {
        let st = rule_stat(self.core.root.as_fd(), p);
        let now = Instant::now();
        let since = match self.rule_seen.get(p) {
            Some(&(seen, since)) if seen == st => since,
            _ => {
                self.rule_seen.insert(p.clone(), (st, now));
                now
            }
        };
        if now >= since + RULE_SETTLE {
            self.rule_seen.remove(p);
            return true;
        }
        self.retry.push((p.clone(), wflag::MODIFIED));
        let due = since + RULE_SETTLE;
        self.retry_due = Some(self.retry_due.map_or(due, |d| d.min(due)));
        false
    }

    // git rewrites its index on most commands; only a changed tracked-but-ignored set costs a rescan
    fn refresh_exceptions(&mut self) {
        self.exc_due = None;
        let pending: Vec<RelPath> = self.exc_pending.drain().collect();
        let mut dirs = Vec::new();
        for wt in pending {
            let abs = if wt.is_root() {
                self.core.root_path.clone()
            } else {
                self.core.root_path.join(wt.as_str())
            };
            let list = repo::tracked_ignored(&abs, &wt);
            let mut sorted = list.clone();
            sorted.sort_unstable();
            // the first refresh compares against what registration already applied, not an empty cache
            let same = match self.exc.get(&wt) {
                Some(v) => *v == sorted,
                None => {
                    let mut cur = self.core.rules_r().repo_exceptions(&wt);
                    cur.sort_unstable();
                    cur == sorted
                }
            };
            if same {
                self.exc.insert(wt, sorted);
                continue;
            }
            self.exc.insert(wt.clone(), sorted);
            self.core.rules_w().set_repo_exceptions(&wt, list);
            dirs.push(wt);
        }
        self.rescan_dirs(dirs);
    }

    fn rename_pair(&mut self, from: &RelPath, to: &RelPath) -> bool {
        let core = self.core.clone();
        let root = core.root.as_fd();
        let folds = core.fs.case_fold || core.fs.norm_fold;
        let lstat = |p: &RelPath| -> Option<StatKey> {
            let (d, n) = p.split_last()?;
            let dfd = sys::open_beneath(
                root,
                &RelPath::new(d).ok()?,
                OFlags::RDONLY | OFlags::DIRECTORY,
            )
            .ok()?;
            let st = sys::stat_key_at(dfd.as_fd(), n).ok()?;
            (!folds || sys::spelled_at(dfd.as_fd(), n).unwrap_or(true)).then_some(st)
        };
        if lstat(from).is_some() {
            return false;
        }
        let Some(st) = lstat(to) else { return false };
        let mut rules = core.rules_w();
        let mut tree = core.tree();
        if super::lock(&core.inflight)
            .iter()
            .any(|h| from.starts_with(h) || to.starts_with(h))
        {
            return false;
        }
        let Some(fe) = tree.get(from).cloned() else {
            return false;
        };
        let kind = fe.meta.kind;
        if fe.stat.dev != st.dev
            || fe.stat.ino != st.ino
            || sys::kind_of_mode(st.mode) != Some(kind)
        {
            return false;
        }
        let domain = match rules.classify(to, kind == Kind::Dir) {
            Class::Synced => Domain::Synced,
            Class::GitRo => Domain::GitRo,
            Class::Ignored | Class::Internal => return false,
        };
        let git_ro = domain == Domain::GitRo;
        let meta = match kind {
            Kind::File => match fe.meta.hash.filter(|_| sys::same_version(&fe.stat, &st)) {
                Some(h) => file_meta(&st, h, git_ro),
                None => return false,
            },
            Kind::Symlink => match fe.meta.link.clone() {
                Some(l) => link_meta(&st, l, git_ro),
                None => return false,
            },
            Kind::Dir => dir_meta(&st, git_ro),
        };
        if tree.get(&parent_of(to)).is_none() && !parent_of(to).is_root() {
            return false;
        }
        let mut changes = vec![Change::Rename {
            from: from.clone(),
            to: to.clone(),
        }];
        changes.extend(tree.observe(
            to,
            Observed::Present {
                meta,
                stat: st,
                domain,
            },
        ));
        if kind == Kind::Dir {
            copy_subtree(&mut tree, &rules, from, to, &mut changes);
        }
        changes.extend(tree.observe(from, Observed::Absent));
        if kind == Kind::Dir {
            let _ = scan::scan_subtree(&core.root_path, to, &mut rules, &mut tree, &mut changes);
        }
        drop(rules);
        core.publish_locked(&tree, changes, None);
        true
    }

    // the largest ignored top-level directories, which the watcher then skips entirely; returns the
    // ones now synced, which no watch covers until a rescan arms one
    fn recompute_excludes(&mut self) -> Vec<RelPath> {
        let core = self.core.clone();
        let Ok(rfd) = sys::open_beneath(
            core.root.as_fd(),
            &RelPath::root(),
            OFlags::RDONLY | OFlags::DIRECTORY,
        ) else {
            return Vec::new();
        };
        let mut ents = Vec::new();
        if sys::read_dir_plus(rfd.as_fd(), &mut ents).is_err() {
            return Vec::new();
        }
        let candidates: Vec<RelPath> = {
            let rules = core.rules_r();
            ents.iter()
                .filter(|e| e.kind == Some(Kind::Dir))
                .filter_map(|e| RelPath::new(e.name.as_str()).ok())
                .filter(|p| rules.classify(p, true) == Class::Ignored)
                .collect()
        };
        let mut sized: Vec<(usize, RelPath)> = candidates
            .into_iter()
            .map(|p| {
                let mut kids = Vec::new();
                let n =
                    sys::open_beneath(core.root.as_fd(), &p, OFlags::RDONLY | OFlags::DIRECTORY)
                        .ok()
                        .and_then(|fd| sys::read_dir_plus(fd.as_fd(), &mut kids).ok())
                        .map_or(0, |()| kids.len());
                (n, p)
            })
            .collect();
        // known build and dependency dirs churn hardest, whatever their entry count
        let rank = |p: &RelPath| !CHURN_DIRS.contains(&p.as_str());
        sized.sort_unstable_by(|a, b| {
            rank(&a.1)
                .cmp(&rank(&b.1))
                .then_with(|| b.0.cmp(&a.0))
                .then_with(|| a.1.cmp(&b.1))
        });
        let mut list: Vec<RelPath> = sized
            .into_iter()
            .take(EXCLUDES_MAX)
            .map(|(_, p)| p)
            .collect();
        list.sort_unstable();
        if list == self.excludes || self.watcher.set_excludes(&list).is_err() {
            return Vec::new();
        }
        let old = std::mem::replace(&mut self.excludes, list);
        let rules = core.rules_r();
        old.into_iter()
            .filter(|p| !self.excludes.contains(p) && rules.classify(p, true) != Class::Ignored)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    fn ev(p: &str, flags: u32, cookie: u32) -> WatchEvent {
        WatchEvent {
            path: rp(p),
            flags,
            cookie,
        }
    }

    #[test]
    fn coalescer_collapses_a_burst() {
        let mut c = Coalescer::default();
        assert!(c.is_empty() && c.deadline().is_none());
        let t0 = Instant::now();
        c.add(vec![ev("lone.rs", wflag::MODIFIED, 0)], t0);
        assert_eq!(c.deadline(), Some(t0));
        assert_eq!(c.take().paths.len(), 1);
        for round in 0..100u32 {
            let evs = (0..100)
                .map(|i| {
                    ev(
                        &format!("src/f{i}.rs"),
                        if round % 2 == 0 {
                            wflag::MODIFIED
                        } else {
                            wflag::ATTRIB
                        },
                        0,
                    )
                })
                .collect();
            c.add(evs, t0 + Duration::from_millis(u64::from(round) / 10));
        }
        c.add(
            vec![
                ev("old.rs", wflag::RENAMED, 7),
                ev("new.rs", wflag::RENAMED, 7),
            ],
            t0 + Duration::from_millis(10),
        );
        c.add(
            vec![ev("gen", wflag::RESCAN | wflag::IS_DIR, 0)],
            t0 + Duration::from_millis(10),
        );
        assert_eq!(c.deadline(), Some(t0 + Duration::from_millis(10) + QUIET));

        let b = c.take();
        assert!(c.is_empty());
        assert!(!b.rescan_all);
        assert_eq!(b.paths.len(), 102);
        assert!(b.paths.windows(2).all(|w| w[0].0 < w[1].0));
        let f0 = b
            .paths
            .iter()
            .find(|(p, _)| p.as_str() == "src/f0.rs")
            .unwrap();
        assert_eq!(f0.1, wflag::MODIFIED | wflag::ATTRIB);
        assert_eq!(b.pairs, vec![(rp("old.rs"), rp("new.rs"))]);
        assert_eq!(b.rescans, vec![rp("gen")]);

        let late = t0 + Duration::from_secs(1);
        c.add(vec![ev("x", wflag::MODIFIED, 0)], late);
        assert_eq!(c.deadline(), Some(late));
        c.take();
        for i in 1..=20u64 {
            c.add(
                vec![ev("x", wflag::MODIFIED, 0)],
                late + Duration::from_millis(i * 4),
            );
        }
        assert_eq!(
            c.deadline(),
            Some(late + Duration::from_millis(4) + MAX_WAIT)
        );
        let storm = late + Duration::from_millis(100);
        c.add(
            vec![WatchEvent {
                path: RelPath::root(),
                flags: wflag::RESCAN | wflag::OVERFLOW,
                cookie: 0,
            }],
            storm,
        );
        c.add(vec![ev("y", wflag::MODIFIED, 0)], storm);
        assert_eq!(c.deadline(), Some(storm + RESCAN_QUIET));
        let b = c.take();
        assert!(b.rescan_all && b.paths.is_empty());
    }

    #[test]
    fn outermost_and_top_missing() {
        assert_eq!(
            outermost(vec![rp("a/b"), rp("a"), rp("ab"), rp("a/b/c"), rp("ab")]),
            vec![rp("a"), rp("ab")]
        );
        let mut t = Tree::new(1);
        let st = StatKey::default();
        t.observe(
            &rp("a"),
            Observed::Present {
                meta: dir_meta(&st, false),
                stat: st,
                domain: Domain::Synced,
            },
        );
        assert_eq!(top_missing(&t, &rp("a/b/c")), Some(rp("a/b")));
        assert_eq!(top_missing(&t, &rp("a")), None);
        assert_eq!(top_missing(&t, &rp("z")), Some(rp("z")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_case_only_renames_replace_the_old_spelling() {
        use std::fs;
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let root = std::env::temp_dir().join(format!(
            "csync-respell-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(root.join("Src")).unwrap();
        fs::write(root.join("Src/main.c"), "m\n").unwrap();
        fs::write(root.join("foo.txt"), "foo\n").unwrap();
        fs::write(root.join("cafe\u{301}.txt"), "nfd\n").unwrap();
        let root = fs::canonicalize(&root).unwrap();
        struct Clean(PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
                let _ = fs::remove_file(&self.0);
            }
        }
        let _clean = Clean(root.clone());
        let rules = Arc::new(std::sync::RwLock::new(Rules::new(&[])));
        let (tx, rx) = crossbeam_channel::bounded(1024);
        let watcher = sys::start_watcher_filtered(&root, None, tx.clone(), None).unwrap();
        let tree = scan::scan(&root, &mut rules.write().unwrap()).unwrap();
        let core =
            Arc::new(Core::new(root.clone(), Name::new("t").unwrap(), tree, rules, tx).unwrap());
        if !core.fs.case_fold {
            return;
        }
        let (stop_tx, stop_rx) = crossbeam_channel::bounded(1);
        let idx = root.with_extension("index");
        let _clean_idx = Clean(idx.clone());
        let app = Applier::new(core.clone(), watcher, rx, stop_rx, idx);
        let h = std::thread::spawn(move || app.run());
        fs::rename(root.join("foo.txt"), root.join("FOO.txt")).unwrap();
        fs::rename(root.join("Src"), root.join("SRC")).unwrap();
        fs::rename(root.join("cafe\u{301}.txt"), root.join("caf\u{e9}.txt")).unwrap();
        fs::write(root.join(".DS_Store"), "finder").unwrap();
        fs::write(root.join("SRC/._main.c"), "appledouble").unwrap();
        let want = [
            ("FOO.txt", true),
            ("foo.txt", false),
            ("SRC/main.c", true),
            ("Src", false),
            ("Src/main.c", false),
            ("caf\u{e9}.txt", true),
            ("cafe\u{301}.txt", false),
        ];
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let ok = {
                let t = core.tree();
                want.iter()
                    .all(|&(p, there)| t.get(&rp(p)).is_some() == there)
            };
            if ok {
                break;
            }
            assert!(Instant::now() < deadline, "index kept an old spelling");
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(200));
        let t = core.tree();
        assert!(t.get(&rp(".DS_Store")).is_none());
        assert!(t.get(&rp("SRC/._main.c")).is_none());
        assert!(t.get(&rp("foo.txt")).is_none());
        drop(t);
        let _ = stop_tx.send(());
        h.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_writes_inside_a_dir_the_committer_moved_are_indexed() {
        use crate::host::commit::{Payload, exec};
        use crate::proto::{Expect, Op};
        use std::fs;
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let root = std::env::temp_dir().join(format!(
            "csync-moved-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(root.join("a/sub")).unwrap();
        fs::create_dir_all(root.join("b")).unwrap();
        fs::write(root.join("a/x.txt"), "x0\n").unwrap();
        fs::write(root.join("a/sub/f.txt"), "f\n").unwrap();
        let root = fs::canonicalize(&root).unwrap();
        struct Clean(PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
                let _ = fs::remove_file(&self.0);
            }
        }
        let _clean = Clean(root.clone());
        let rules = Arc::new(std::sync::RwLock::new(Rules::new(&[])));
        let (tx, rx) = crossbeam_channel::bounded(1024);
        let watcher = sys::start_watcher_filtered(&root, None, tx.clone(), None).unwrap();
        let tree = scan::scan(&root, &mut rules.write().unwrap()).unwrap();
        let core =
            Arc::new(Core::new(root.clone(), Name::new("t").unwrap(), tree, rules, tx).unwrap());
        let (stop_tx, stop_rx) = crossbeam_channel::bounded(1);
        let idx = root.with_extension("index");
        let _clean_idx = Clean(idx.clone());
        let app = Applier::new(core.clone(), watcher, rx, stop_rx, idx);
        let h = std::thread::spawn(move || app.run());
        let wait = |what: &str, f: &dyn Fn(&Tree) -> bool| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !f(&core.tree()) {
                assert!(Instant::now() < deadline, "index never showed {what}");
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let (mut from, mut to) = ("a", "b/m2");
        for i in 0..20u32 {
            let op = Op::Rename {
                from: rp(from),
                to: rp(to),
                from_expect: Expect::Dir,
                to_expect: Expect::Absent,
                body: None,
            };
            assert!(exec(&core, op, Payload::None, None).is_ok());
            if i % 2 == 1 {
                std::thread::sleep(Duration::from_millis(30));
            }
            let leaf = format!("{to}/sub/t{i}/leaf");
            fs::create_dir(root.join(format!("{to}/sub/t{i}"))).unwrap();
            fs::write(root.join(&leaf), "g\n").unwrap();
            let body = format!("x{i} changed\n");
            fs::write(root.join(format!("{to}/x.txt")), &body).unwrap();
            let want = *blake3::hash(body.as_bytes()).as_bytes();
            let xp = rp(&format!("{to}/x.txt"));
            wait(&leaf, &|t| t.get(&rp(&leaf)).is_some());
            wait(&format!("{to}/x.txt"), &|t| {
                t.get(&xp).and_then(|e| e.meta.hash) == Some(want)
            });
            assert!(core.tree().get(&rp(from)).is_none());
            std::mem::swap(&mut from, &mut to);
        }
        let _ = stop_tx.send(());
        h.join().unwrap();
    }

    // a sample taken mid-swap must not reach a guest the committer then leaves out of its own record
    #[test]
    fn applier_retries_paths_the_committer_holds() {
        use crate::host::commit::Hold;
        use std::fs;
        struct NoWatch;
        impl Watcher for NoWatch {
            fn set_excludes(&mut self, _: &[RelPath]) -> std::io::Result<()> {
                Ok(())
            }
            fn watch_dir(&mut self, _: &RelPath) -> std::io::Result<()> {
                Ok(())
            }
            fn unwatch_dir(&mut self, _: &RelPath) {}
            fn resume_token(&self) -> Option<sys::ResumeToken> {
                None
            }
        }
        struct Clean(PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let root = std::env::temp_dir().join(format!(
            "csync-hold-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(root.join("d")).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        let _clean = Clean(root.clone());
        fs::write(root.join("d/f.txt"), "old body\n").unwrap();
        fs::write(root.join("d/f.txt.tmp"), "new\n").unwrap();
        let rules = Arc::new(std::sync::RwLock::new(Rules::new(&[])));
        let (tx, rx) = crossbeam_channel::bounded(16);
        let tree = scan::scan(&root, &mut rules.write().unwrap()).unwrap();
        let core =
            Arc::new(Core::new(root.clone(), Name::new("t").unwrap(), tree, rules, tx).unwrap());
        let (_stop_tx, stop_rx) = crossbeam_channel::bounded(1);
        let mut app = Applier::new(
            core.clone(),
            Box::new(NoWatch),
            rx,
            stop_rx,
            root.join("index"),
        );
        let (f, tmp) = (rp("d/f.txt"), rp("d/f.txt.tmp"));
        let hash = |p: &RelPath| core.tree().get(p).and_then(|e| e.meta.hash);
        let batch = |paths: Vec<RelPath>| Batch {
            paths: paths.into_iter().map(|p| (p, wflag::MODIFIED)).collect(),
            pairs: Vec::new(),
            rescans: Vec::new(),
            rescan_all: false,
        };
        let (old, new) = (
            Some(*blake3::hash(b"old body\n").as_bytes()),
            Some(*blake3::hash(b"new\n").as_bytes()),
        );
        {
            let _hold = Hold::new(&core, [Some(&tmp), Some(&f)]);
            fs::write(root.join("d/f.txt.tmp"), "old body\n").unwrap();
            fs::write(root.join("d/f.txt"), "new\n").unwrap();
            app.process(batch(vec![tmp.clone(), f.clone()]));
            assert_eq!(hash(&tmp), new, "a held temp was indexed mid-swap");
            assert_eq!(hash(&f), old, "a held target was indexed mid-swap");
        }
        let again: Vec<RelPath> = app.take_retries().into_iter().map(|e| e.path).collect();
        assert_eq!(again.len(), 2);
        app.process(batch(again));
        assert_eq!((hash(&tmp), hash(&f)), (old, new));

        // cargo vendor: a rescan of a new subdirectory races the rename of its staging parent
        let (sx, vx, tests) = (rp("d/s"), rp("d/v"), rp("d/s/tests"));
        fs::create_dir_all(root.join("d/s/tests")).unwrap();
        fs::write(root.join("d/s/tests/t.rs"), "t\n").unwrap();
        app.process(Batch {
            rescans: vec![sx.clone()],
            ..batch(Vec::new())
        });
        assert!(core.tree().get(&rp("d/s/tests/t.rs")).is_some());
        {
            let _hold = Hold::new(&core, [Some(&sx), Some(&vx)]);
            fs::rename(root.join("d/s"), root.join("d/v")).unwrap();
            app.process(Batch {
                rescans: vec![tests.clone()],
                ..batch(Vec::new())
            });
            assert!(
                core.tree().get(&tests).is_some(),
                "a rescan dropped a subtree the committer is still moving"
            );
        }
        let again = app.take_retries();
        assert_eq!(
            again.iter().map(|e| (&e.path, e.flags)).collect::<Vec<_>>(),
            [(&tests, wflag::RESCAN)]
        );
    }

    #[test]
    fn a_dir_a_rule_stops_ignoring_is_watched_before_its_scan() {
        use std::fs;
        // a host write that lands as the watch on scratch/ arms is seen only by a scan that follows it
        struct Arming {
            root: PathBuf,
            rules: Arc<std::sync::RwLock<Rules>>,
            excludes: Vec<RelPath>,
            fired: bool,
        }
        impl Watcher for Arming {
            fn set_excludes(&mut self, dirs: &[RelPath]) -> std::io::Result<()> {
                self.excludes = dirs.to_vec();
                Ok(())
            }
            fn watch_dir(&mut self, dir: &RelPath) -> std::io::Result<()> {
                // the inotify watcher's dir filter reads the rules
                assert!(
                    self.rules.try_read().is_ok(),
                    "a watch armed under the rules lock"
                );
                let s = rp("scratch");
                if !self.fired
                    && s.starts_with(dir)
                    && !self.excludes.iter().any(|e| s.starts_with(e))
                {
                    self.fired = true;
                    fs::write(self.root.join("scratch/h.txt"), "new body\n")?;
                }
                Ok(())
            }
            fn unwatch_dir(&mut self, _: &RelPath) {}
            fn resume_token(&self) -> Option<sys::ResumeToken> {
                None
            }
        }
        struct Clean(PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let root = std::env::temp_dir().join(format!(
            "csync-unhide-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(root.join("scratch")).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        let _clean = Clean(root.clone());
        fs::write(root.join(".gitignore"), "scratch/\n").unwrap();
        fs::write(root.join("scratch/h.txt"), "old\n").unwrap();
        let rules = Arc::new(std::sync::RwLock::new(Rules::new(&[])));
        let (tx, rx) = crossbeam_channel::bounded(16);
        let tree = scan::scan(&root, &mut rules.write().unwrap()).unwrap();
        let core = Arc::new(
            Core::new(
                root.clone(),
                Name::new("t").unwrap(),
                tree,
                rules.clone(),
                tx,
            )
            .unwrap(),
        );
        let (_stop_tx, stop_rx) = crossbeam_channel::bounded(1);
        let watcher = Arming {
            root: root.clone(),
            rules,
            excludes: Vec::new(),
            fired: false,
        };
        let mut app = Applier::new(
            core.clone(),
            Box::new(watcher),
            rx,
            stop_rx,
            root.join("index"),
        );
        app.recompute_excludes();
        assert_eq!(app.excludes, [rp("scratch")]);
        assert!(core.tree().get(&rp("scratch/h.txt")).is_none());

        fs::write(root.join(".gitignore"), "# none\n").unwrap();
        app.process(Batch {
            paths: vec![(rp(".gitignore"), wflag::MODIFIED)],
            pairs: Vec::new(),
            rescans: Vec::new(),
            rescan_all: false,
        });
        std::thread::sleep(RULE_SETTLE);
        let again = app.take_retries();
        app.process(Batch {
            paths: again.into_iter().map(|e| (e.path, e.flags)).collect(),
            pairs: Vec::new(),
            rescans: Vec::new(),
            rescan_all: false,
        });
        assert!(app.excludes.is_empty());
        assert_eq!(
            core.tree()
                .get(&rp("scratch/h.txt"))
                .and_then(|e| e.meta.hash),
            Some(*blake3::hash(b"new body\n").as_bytes()),
            "a write made as the watch armed was never indexed"
        );
    }

    #[test]
    fn a_rule_file_caught_mid_write_unignores_nothing() {
        use std::fs;
        struct NoWatch;
        impl Watcher for NoWatch {
            fn set_excludes(&mut self, _: &[RelPath]) -> std::io::Result<()> {
                Ok(())
            }
            fn watch_dir(&mut self, _: &RelPath) -> std::io::Result<()> {
                Ok(())
            }
            fn unwatch_dir(&mut self, _: &RelPath) {}
            fn resume_token(&self) -> Option<sys::ResumeToken> {
                None
            }
        }
        struct Clean(PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let root = std::env::temp_dir().join(format!(
            "csync-midrule-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(root.join("target")).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        let _clean = Clean(root.clone());
        let full = "target/\n*.log\n";
        fs::write(root.join(".gitignore"), full).unwrap();
        fs::write(root.join("build.log"), "secret\n").unwrap();
        fs::write(root.join("target/out.o"), "obj\n").unwrap();
        let rules = Arc::new(std::sync::RwLock::new(Rules::new(&[])));
        let (tx, rx) = crossbeam_channel::bounded(16);
        let tree = scan::scan(&root, &mut rules.write().unwrap()).unwrap();
        let core =
            Arc::new(Core::new(root.clone(), Name::new("t").unwrap(), tree, rules, tx).unwrap());
        let (_stop_tx, stop_rx) = crossbeam_channel::bounded(1);
        let mut app = Applier::new(
            core.clone(),
            Box::new(NoWatch),
            rx,
            stop_rx,
            root.join("index"),
        );
        let batch = |paths: Vec<(RelPath, u32)>| Batch {
            paths,
            pairs: Vec::new(),
            rescans: Vec::new(),
            rescan_all: false,
        };
        let leaked = |core: &Core| {
            let t = core.tree();
            ["build.log", "target", "target/out.o"]
                .into_iter()
                .filter(|p| t.get(&rp(p)).is_some())
                .collect::<Vec<_>>()
        };
        let hash = |core: &Core| core.tree().get(&rp(".gitignore")).and_then(|e| e.meta.hash);
        let before = hash(&core);
        // fs::write truncates before it writes, and the watcher can wake in between
        fs::write(root.join(".gitignore"), "").unwrap();
        app.process(batch(vec![(rp(".gitignore"), wflag::MODIFIED)]));
        assert_eq!(
            leaked(&core),
            Vec::<&str>::new(),
            "a half-written rule file was applied"
        );
        assert_eq!(
            hash(&core),
            before,
            "a half-written rule file was published"
        );
        let edited = "target/\n*.log\n*.tmp\n";
        fs::write(root.join(".gitignore"), edited).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while hash(&core) == before || !app.retry.is_empty() {
            assert!(
                Instant::now() < deadline,
                "the settled rule file was never applied"
            );
            std::thread::sleep(RULE_SETTLE / 4);
            let again = app.take_retries();
            app.process(batch(
                again.into_iter().map(|e| (e.path, e.flags)).collect(),
            ));
            assert_eq!(
                leaked(&core),
                Vec::<&str>::new(),
                "a changing rule file was applied"
            );
        }
        assert_eq!(
            hash(&core),
            Some(*blake3::hash(edited.as_bytes()).as_bytes())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inotify_burst_is_indexed_and_renames_keep_hashes() {
        use std::fs;
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let root = std::env::temp_dir().join(format!(
            "csync-apply-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        struct Clean(PathBuf);
        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
                let _ = fs::remove_file(&self.0);
            }
        }
        let _clean = Clean(root.clone());
        fs::write(root.join(".gitignore"), "*.log\n").unwrap();

        let rules = Arc::new(std::sync::RwLock::new(Rules::new(&[])));
        let (tx, rx) = crossbeam_channel::bounded(1024);
        let watcher = sys::start_watcher_filtered(&root, None, tx.clone(), None).unwrap();
        let tree = scan::scan(&root, &mut rules.write().unwrap()).unwrap();
        let core =
            Arc::new(Core::new(root.clone(), Name::new("t").unwrap(), tree, rules, tx).unwrap());
        let (stop_tx, stop_rx) = crossbeam_channel::bounded(1);
        let idx = root.with_extension("index");
        let _clean_idx = Clean(idx.clone());
        let app = Applier::new(core.clone(), watcher, rx, stop_rx, idx);
        let h = std::thread::spawn(move || app.run());

        for i in 0..500 {
            fs::write(
                root.join(format!("src/f{i}.rs")),
                format!("fn f{i}() {{}}\n"),
            )
            .unwrap();
        }
        fs::write(root.join("src/noise.log"), "ignored").unwrap();
        let wait = |f: &dyn Fn(&Tree) -> bool| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !f(&core.tree()) {
                assert!(Instant::now() < deadline, "index did not converge");
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        wait(&|t| (0..500).all(|i| t.get(&rp(&format!("src/f{i}.rs"))).is_some()));
        let want = *blake3::hash(b"fn f7() {}\n").as_bytes();
        assert_eq!(
            core.tree().get(&rp("src/f7.rs")).and_then(|e| e.meta.hash),
            Some(want)
        );
        assert!(core.tree().get(&rp("src/noise.log")).is_none());

        fs::rename(root.join("src"), root.join("lib")).unwrap();
        wait(&|t| t.get(&rp("lib/f7.rs")).is_some() && t.get(&rp("src")).is_none());
        assert_eq!(
            core.tree().get(&rp("lib/f7.rs")).and_then(|e| e.meta.hash),
            Some(want)
        );

        fs::write(root.join(".gitignore"), "*.log\nlib/\n").unwrap();
        wait(&|t| t.get(&rp("lib")).is_none());

        let _ = stop_tx.send(());
        h.join().unwrap();
    }
}
