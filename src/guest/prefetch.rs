use super::cache::{Batch, BlobCache, lock};
use super::tree::{GDomain, GNode, GTree, NodeId, ROOT, Vis};
use crate::net::rpc::RpcError;
use crate::proto::{
    BATCH_MAX, Hash32, Kind, Op, RANGE_FILE_MIN, RelPath, Reply, Seq, VerKey, Version,
};
use rustc_hash::FxHashSet;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, RwLock, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const WARM_MAX: u64 = 1 << 20;
const SIBLING_MAX: u64 = 256 << 10;
const SIBLING_TOTAL: u64 = 4 << 20;
// what a cold open waits for: one FetchMany part, the rest of the directory follows from the prefetch thread
const OPEN_BATCH_BYTES: u64 = BATCH_BYTES;
// a FetchMany reply is one frame the host builds before sending, so batches stay small and several fly at once
const BATCH_BYTES: u64 = 1 << 20;
const BATCH_ITEMS: usize = 512;
// background batches in flight; scan-driven ones may use the larger window
const DEPTH: usize = 3;
const HOT_DEPTH: usize = 8;
// by-version batches are blocking round trips, so this many run side by side
const VER_PAR: usize = DEPTH;
const BURST_N: usize = 8;
const BURST_WINDOW: Duration = Duration::from_millis(50);
const HINTS_MAX: usize = 4096;
const HOT_MAX: usize = 64;
const SEEN_MAX: usize = 1 << 20;
const SIBS_MAX: usize = 4096;
const DIRS_PER_STEP: usize = 64;
const MANY_WAIT: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const NICE: i32 = 10;

const RULE_FILES: &[&str] = &[
    ".gitignore",
    ".ignore",
    ".gitattributes",
    ".gitmodules",
    ".editorconfig",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "tsconfig.json",
    "go.mod",
    "go.sum",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "Makefile",
    "CMakeLists.txt",
    "build.gradle",
    "pom.xml",
    "Gemfile",
    "Gemfile.lock",
];
const GIT_META: &[&str] = &[
    "HEAD",
    "config",
    "packed-refs",
    "index",
    "shallow",
    "commondir",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hint {
    // after every (re)connect: rule files and manifests first, then warm-all
    Start,
    Open {
        dir: NodeId,
        node: NodeId,
        cold: bool,
    },
    Lookup {
        dir: NodeId,
    },
    Warm(NodeId, Hash32),
    // a file whose hash the host has not computed yet: fetched by version key
    WarmPending(NodeId),
}

// skip: Local overlay or pending delete, never fetched from the host
// ver: set only for a pending file (no hash yet), naming the host version to fetch
// used: open now or read before, so a new version of it is wanted soon
#[derive(Clone, Debug)]
pub struct Item {
    pub node: NodeId,
    pub path: RelPath,
    pub dir: bool,
    pub hash: Option<Hash32>,
    pub ver: Option<VerKey>,
    pub size: u64,
    pub skip: bool,
    pub used: bool,
}

// the prefetcher's view of the guest tree; implemented for the usual lock wrappers of GTree
pub trait TreeView: Send + Sync {
    fn list(&self, dir: NodeId, out: &mut Vec<Item>) -> bool;
    // at least the children `eligible` could pass for a sibling fetch of `except`; the caller still filters
    fn list_fetchable(&self, dir: NodeId, except: NodeId, max: u64, out: &mut Vec<Item>) -> bool {
        let _ = (except, max);
        self.list(dir, out)
    }
    fn item(&self, node: NodeId) -> Option<Item>;
    fn files(&self) -> u64;
    // records the verified hash of a pending file fetched at host version `ver`; false when the node moved on
    fn learn(&self, node: NodeId, ver: Seq, hash: Hash32) -> bool;
}

fn gtree_item(t: &GTree, id: NodeId, path: RelPath) -> Option<Item> {
    let n = t.get(id)?;
    Some(Item {
        node: id,
        path,
        dir: n.meta.kind == Kind::Dir,
        hash: n.meta.hash,
        ver: if n.is_pending() {
            n.ver_key(t.index_id())
        } else {
            None
        },
        size: n.meta.size,
        skip: n.domain == GDomain::Local || n.vis == Vis::PendingDelete,
        used: n.open.load(Relaxed) > 0 || n.read_ver.is_some(),
    })
}

// a path is built only for the children `keep` passes
fn gtree_walk(
    t: &GTree,
    dir: NodeId,
    out: &mut Vec<Item>,
    keep: impl Fn(NodeId, &GNode) -> bool,
) -> bool {
    let Some(children) = t.get(dir).and_then(|d| d.children.as_ref()) else {
        return false;
    };
    let mut s = String::new();
    if !t.path_of(dir, &mut s) {
        return false;
    }
    let Ok(base) = RelPath::new(&s) else {
        return false;
    };
    for (name, &id) in children {
        if !t.get(id).is_some_and(|n| keep(id, n)) {
            continue;
        }
        let Ok(p) = base.join(name) else { continue };
        if let Some(i) = gtree_item(t, id, p) {
            out.push(i);
        }
    }
    true
}

fn gtree_list(t: &GTree, dir: NodeId, out: &mut Vec<Item>) -> bool {
    gtree_walk(t, dir, out, |_, _| true)
}

// mirrors `eligible` for everything but the cache lookup, which needs no tree lock
fn gtree_list_fetchable(
    t: &GTree,
    dir: NodeId,
    except: NodeId,
    max: u64,
    out: &mut Vec<Item>,
) -> bool {
    let index = t.index_id();
    gtree_walk(t, dir, out, |id, n| {
        id != except
            && n.meta.kind != Kind::Dir
            && n.domain != GDomain::Local
            && n.vis != Vis::PendingDelete
            && n.meta.size <= max
            && (n.meta.hash.is_some() || (n.is_pending() && n.ver_key(index).is_some()))
    })
}

fn gtree_node(t: &GTree, node: NodeId) -> Option<Item> {
    let mut s = String::new();
    if !t.path_of(node, &mut s) {
        return None;
    }
    gtree_item(t, node, RelPath::new(&s).ok()?)
}

impl TreeView for RwLock<GTree> {
    fn list(&self, dir: NodeId, out: &mut Vec<Item>) -> bool {
        gtree_list(&self.read().unwrap_or_else(|e| e.into_inner()), dir, out)
    }
    fn list_fetchable(&self, dir: NodeId, except: NodeId, max: u64, out: &mut Vec<Item>) -> bool {
        gtree_list_fetchable(
            &self.read().unwrap_or_else(|e| e.into_inner()),
            dir,
            except,
            max,
            out,
        )
    }
    fn item(&self, node: NodeId) -> Option<Item> {
        gtree_node(&self.read().unwrap_or_else(|e| e.into_inner()), node)
    }
    fn files(&self) -> u64 {
        self.read().unwrap_or_else(|e| e.into_inner()).files()
    }
    fn learn(&self, node: NodeId, ver: Seq, hash: Hash32) -> bool {
        self.write()
            .unwrap_or_else(|e| e.into_inner())
            .learn_hash(node, ver, hash)
    }
}

impl TreeView for Mutex<GTree> {
    fn list(&self, dir: NodeId, out: &mut Vec<Item>) -> bool {
        gtree_list(&lock(self), dir, out)
    }
    fn list_fetchable(&self, dir: NodeId, except: NodeId, max: u64, out: &mut Vec<Item>) -> bool {
        gtree_list_fetchable(&lock(self), dir, except, max, out)
    }
    fn item(&self, node: NodeId) -> Option<Item> {
        gtree_node(&lock(self), node)
    }
    fn files(&self) -> u64 {
        lock(self).files()
    }
    fn learn(&self, node: NodeId, ver: Seq, hash: Hash32) -> bool {
        lock(self).learn_hash(node, ver, hash)
    }
}

fn is_objects_dir(p: &RelPath) -> bool {
    let s = p.as_str();
    s == ".git/objects" || s.ends_with("/.git/objects")
}

fn is_pack_dir(p: &RelPath) -> bool {
    let s = p.as_str();
    s.ends_with("objects/pack") && (s.starts_with(".git/") || s.contains("/.git/"))
}

fn name_of(p: &RelPath) -> &str {
    p.split_last().map_or("", |(_, n)| n)
}

type Want = (RelPath, Hash32, u64);
type PendingWant = (NodeId, RelPath, VerKey);

// a sealed batch: by content hash, or by host version for files whose hash is not known yet
enum Job {
    Hash(Vec<Want>),
    Ver(Vec<PendingWant>),
}

// a batch reply for the worker to store, or the count a lander left once it stored one
enum Landed {
    Reply(Batch, Result<Reply, RpcError>),
    Stored { n: u64, closed: bool },
}

struct State {
    hints: VecDeque<(Instant, Hint)>,
    landed: Vec<Landed>,
    stop: bool,
    idle: bool,
}

fn lower_priority() {
    #[cfg(target_os = "linux")]
    {
        let _ = rustix::process::setpriority_process(Some(rustix::thread::gettid()), NICE);
    }
    #[cfg(target_os = "macos")]
    {
        crate::sys::fs_unix::lower_thread_priority();
    }
}

// verifies and writes a batch's blobs; (items asked, whether the link closed)
fn store(cache: &BlobCache, b: Batch, r: Result<Reply, RpcError>) -> (u64, bool) {
    let n = b.len() as u64;
    match r {
        Ok(Reply::Blobs { items }) => {
            b.land(items);
            cache.evict();
            (n, false)
        }
        Err(RpcError::Closed) => (n, true),
        _ => (n, false),
    }
}

impl PShared {
    fn wake(&self, st: std::sync::MutexGuard<'_, State>) {
        let w = st.idle;
        drop(st);
        if w {
            self.cv.notify_one();
        }
    }

    fn landed(&self, l: Landed) {
        let mut st = lock(&self.st);
        st.landed.push(l);
        self.wake(st);
    }
}

// files the current warm-all pass has dealt with, against the files in the tree; both 0 when no pass runs
#[derive(Default)]
pub struct Progress {
    pub done: AtomicU64,
    pub total: AtomicU64,
}

struct PShared {
    st: Mutex<State>,
    cv: Condvar,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Idle,
    Rules,
    Warm,
}

#[derive(Default)]
struct Walk {
    phase: Phase,
    queue: VecDeque<NodeId>,
    // git object stores, warmed after the working tree
    later: Vec<NodeId>,
    hot: VecDeque<NodeId>,
    batch: Vec<Want>,
    bytes: u64,
    hot_batch: bool,
    // pending files gathered for one FetchMany by version, with the same limits as `batch`
    vbatch: Vec<PendingWant>,
    vbytes: u64,
    vhot_batch: bool,
    // sealed batches waiting for a window; true when a scan or a host change asked for them
    ready: VecDeque<(Job, bool)>,
    big: Vec<Want>,
    seen: FxHashSet<Hash32>,
    seen_ver: FxHashSet<VerKey>,
    burst: VecDeque<(Instant, NodeId)>,
    sibs: FxHashSet<NodeId>,
    // a burst of cold opens means a scan wants everything: background batches use the wide window until then
    scan_until: Option<Instant>,
    // the walk has reached the git object stores, which no working-tree scan reads
    objects: bool,
    urgent: bool,
    saved: bool,
}

impl Walk {
    fn active(&self) -> bool {
        self.phase != Phase::Idle
            || !self.hot.is_empty()
            || !self.batch.is_empty()
            || !self.vbatch.is_empty()
            || !self.ready.is_empty()
            || !self.big.is_empty()
    }

    fn seal(&mut self) {
        self.seal_hash();
        self.seal_ver();
    }

    fn seal_hash(&mut self) {
        if !self.batch.is_empty() {
            let b = std::mem::take(&mut self.batch);
            self.ready
                .push_back((Job::Hash(b), std::mem::take(&mut self.hot_batch)));
        }
        self.bytes = 0;
    }

    fn seal_ver(&mut self) {
        if !self.vbatch.is_empty() {
            let b = std::mem::take(&mut self.vbatch);
            self.ready
                .push_back((Job::Ver(b), std::mem::take(&mut self.vhot_batch)));
        }
        self.vbytes = 0;
    }

    fn push(&mut self, item: (RelPath, Hash32, u64), hot: bool) {
        self.bytes += item.2;
        self.hot_batch |= hot;
        self.batch.push(item);
        if self.bytes >= BATCH_BYTES || self.batch.len() >= BATCH_ITEMS.min(BATCH_MAX) {
            self.seal_hash();
        }
    }

    fn push_ver(&mut self, item: PendingWant, hot: bool) {
        self.vbytes += item.2.size;
        self.vhot_batch |= hot;
        self.vbatch.push(item);
        if self.vbytes >= BATCH_BYTES || self.vbatch.len() >= BATCH_ITEMS.min(BATCH_MAX) {
            self.seal_ver();
        }
    }

    fn halt(&mut self) {
        self.phase = Phase::Idle;
        self.queue.clear();
        self.hot.clear();
        self.batch.clear();
        self.vbatch.clear();
        self.later.clear();
        self.ready.clear();
        self.hot_batch = false;
        self.vhot_batch = false;
        self.big.clear();
        self.bytes = 0;
        self.vbytes = 0;
        self.urgent = false;
        self.objects = false;
    }
}

struct Worker {
    sh: Arc<PShared>,
    cache: Arc<BlobCache>,
    tree: Arc<dyn TreeView>,
    walk: Walk,
    inflight: usize,
    prog: Arc<Progress>,
}

pub struct Prefetch {
    sh: Arc<PShared>,
    join: Mutex<Option<JoinHandle<()>>>,
    pub progress: Arc<Progress>,
    cache: Arc<BlobCache>,
    tree: Arc<dyn TreeView>,
}

impl Prefetch {
    pub fn start(cache: Arc<BlobCache>, tree: Arc<dyn TreeView>) -> io::Result<Self> {
        let sh = Arc::new(PShared {
            st: Mutex::new(State {
                hints: VecDeque::new(),
                landed: Vec::new(),
                stop: false,
                idle: false,
            }),
            cv: Condvar::new(),
        });
        let gsh = sh.clone();
        cache
            .gate()
            .set_waker(Box::new(move || gsh.wake(lock(&gsh.st))));
        let progress = Arc::new(Progress::default());
        let w = Worker {
            sh: sh.clone(),
            cache: cache.clone(),
            tree: tree.clone(),
            walk: Walk::default(),
            inflight: 0,
            prog: progress.clone(),
        };
        let join = std::thread::Builder::new()
            .name("csync-prefetch".into())
            .spawn(move || w.run())?;
        Ok(Self {
            sh,
            join: Mutex::new(Some(join)),
            progress,
            cache,
            tree,
        })
    }

    // a cold open fetches its small siblings with its own bytes and lands them, so their readers wait on one burst
    pub fn open_batch(&self, dir: NodeId, node: NodeId, deadline: Instant) {
        let Some(own) = self.tree.item(node) else {
            return;
        };
        if own.size == 0 || own.size > SIBLING_MAX || own.hash.is_some_and(|h| self.cache.held(&h))
        {
            return;
        }
        let mut items = Vec::new();
        if !self.tree.list_fetchable(dir, node, SIBLING_MAX, &mut items) {
            return;
        }
        let (mut hashed, mut pending, mut total) = (Vec::new(), Vec::new(), 0u64);
        let siblings = items
            .into_iter()
            .filter(|i| i.node != node && !i.dir && !i.skip);
        for i in std::iter::once(own).chain(siblings) {
            if hashed.len() + pending.len() >= BATCH_ITEMS.min(BATCH_MAX) {
                break;
            }
            if i.size == 0 || total + i.size > OPEN_BATCH_BYTES {
                continue;
            }
            match (i.hash, i.ver) {
                (Some(h), _) if !self.cache.contains(&h) => hashed.push((i.path, h, i.size)),
                (None, Some(k)) => pending.push((i.node, i.path, k)),
                _ => continue,
            }
            total += i.size;
        }
        if hashed.len() + pending.len() < 2 {
            return;
        }
        let (used, cap) = self.cache.usage();
        if used.saturating_add(total) > cap / 10 * 9 {
            return;
        }
        let Some(remote) = self.cache.remote().current() else {
            return;
        };
        let _busy = self.cache.gate().enter();
        let batch = self.cache.begin_batch(&hashed);
        let (tx, rx) = mpsc::sync_channel(1);
        // a batch dropped unsent fails its fills, and their readers fetch on their own
        let sent = !batch.is_empty() && {
            let op = Op::FetchMany {
                items: batch.request(),
            };
            let done = Box::new(move |r| {
                let _ = tx.send(r);
            });
            remote.submit(op, done).is_ok()
        };
        // files the host has not hashed yet come by version in the same burst and the tree learns their hashes
        if !pending.is_empty() {
            let want: Vec<(RelPath, VerKey)> =
                pending.iter().map(|(_, p, k)| (p.clone(), *k)).collect();
            let got = self.cache.fetch_many_ver(&want, deadline);
            for ((node, path, k), (p, r)) in pending.iter().zip(got) {
                if *path == p
                    && let Ok(v) = r
                {
                    self.tree.learn(*node, k.ver, v.hash);
                }
            }
        }
        let wait = deadline.saturating_duration_since(Instant::now());
        if sent && let Ok(Ok(Reply::Blobs { items })) = rx.recv_timeout(wait) {
            batch.land(items);
        }
        self.cache.evict();
    }

    // never blocks the caller; the worker is only woken when it is parked
    pub fn hint(&self, h: Hint) {
        let mut st = lock(&self.sh.st);
        if st.stop || st.hints.len() >= HINTS_MAX {
            return;
        }
        st.hints.push_back((Instant::now(), h));
        self.sh.wake(st);
    }

    pub fn stop(&self) {
        lock(&self.sh.st).stop = true;
        self.sh.cv.notify_one();
        if let Some(j) = lock(&self.join).take() {
            let _ = j.join();
        }
    }
}

impl Drop for Prefetch {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Worker {
    fn run(mut self) {
        lower_priority();
        let mut items = Vec::new();
        loop {
            let (hints, landed) = {
                let mut st = lock(&self.sh.st);
                loop {
                    if st.stop {
                        return;
                    }
                    st.idle = false;
                    if !st.hints.is_empty() || !st.landed.is_empty() {
                        break (
                            st.hints.drain(..).collect::<Vec<_>>(),
                            std::mem::take(&mut st.landed),
                        );
                    }
                    if self.can_step() {
                        break (Vec::new(), Vec::new());
                    }
                    if !self.walk.active() && self.inflight == 0 && !self.walk.saved {
                        drop(st);
                        let _ = self.cache.save();
                        self.walk.saved = true;
                        st = lock(&self.sh.st);
                        continue;
                    }
                    st.idle = true;
                    st = self.sh.cv.wait(st).unwrap_or_else(|e| e.into_inner());
                }
            };
            for l in landed {
                self.land(l);
            }
            for (t, h) in hints {
                self.on_hint(t, h, &mut items);
            }
            if self.can_step() {
                self.step(&mut items);
            }
        }
    }

    // background warming yields to foreground fetches; scan-driven and urgent work does not
    fn can_step(&self) -> bool {
        if !self.walk.active() {
            return false;
        }
        match self.walk.ready.front() {
            None => true,
            Some((_, true)) => self.inflight < HOT_DEPTH,
            Some((_, false)) => {
                if !self.walk.objects && self.walk.scan_until.is_some_and(|t| Instant::now() < t) {
                    return self.inflight < HOT_DEPTH;
                }
                self.inflight < DEPTH && self.cache.gate().idle_or_arm()
            }
        }
    }

    fn land(&mut self, l: Landed) {
        self.inflight = self.inflight.saturating_sub(1);
        let (n, closed) = match l {
            Landed::Reply(b, r) => store(&self.cache, b, r),
            Landed::Stored { n, closed } => (n, closed),
        };
        if closed {
            self.walk.halt();
        }
        if self.walk.phase == Phase::Warm {
            self.prog.done.fetch_add(n, Relaxed);
        }
    }

    // waits for every batch in flight, landing them; false when stopping
    fn drain(&mut self) -> bool {
        while self.inflight > 0 {
            let landed = {
                let mut st = lock(&self.sh.st);
                loop {
                    if st.stop {
                        return false;
                    }
                    if !st.landed.is_empty() {
                        break std::mem::take(&mut st.landed);
                    }
                    st.idle = true;
                    st = self.sh.cv.wait(st).unwrap_or_else(|e| e.into_inner());
                    st.idle = false;
                }
            };
            for l in landed {
                self.land(l);
            }
        }
        true
    }

    fn on_hint(&mut self, t: Instant, h: Hint, items: &mut Vec<Item>) {
        match h {
            Hint::Start => {
                let w = &mut self.walk;
                w.halt();
                self.prog.done.store(0, Relaxed);
                self.prog.total.store(0, Relaxed);
                w.phase = Phase::Rules;
                w.queue.push_back(ROOT);
                w.seen.clear();
                w.seen_ver.clear();
                w.sibs.clear();
                w.saved = false;
            }
            Hint::Open { dir, node, cold } => {
                if cold && self.inflight < HOT_DEPTH {
                    self.burst(t, dir);
                    self.siblings(dir, node, items);
                }
            }
            Hint::Lookup { dir } => self.burst(t, dir),
            Hint::Warm(node, h) => {
                if let Some(i) = self.tree.item(node)
                    && i.hash == Some(h)
                {
                    // a pushed hash of a file nobody reads only labels it: the walk fetches it in its turn
                    if i.used {
                        let _ = self.add(i, WARM_MAX, true);
                        self.walk.urgent = true;
                    } else if self.walk.phase == Phase::Idle {
                        let _ = self.add(i, WARM_MAX, false);
                    }
                }
            }
            Hint::WarmPending(node) => {
                if let Some(i) = self.tree.item(node)
                    && i.hash.is_none()
                    && i.ver.is_some()
                {
                    let _ = self.add(i, WARM_MAX, true);
                    self.walk.urgent = true;
                }
            }
        }
    }

    // a pending file has no hash to look up in the cache, so only its version key qualifies it
    fn eligible(&self, i: &Item, max: u64) -> bool {
        !i.dir
            && !i.skip
            && i.size <= max
            && match (i.hash, i.ver) {
                (Some(h), _) => !self.cache.contains(&h),
                (None, ver) => ver.is_some(),
            }
    }

    // true when the item was queued for a batch
    fn add(&mut self, i: Item, max: u64, hot: bool) -> bool {
        if !self.eligible(&i, max) {
            return false;
        }
        let Some(h) = i.hash else {
            return self.add_pending(i, hot);
        };
        if self.walk.seen.len() >= SEEN_MAX {
            self.walk.seen.clear();
        }
        if !self.walk.seen.insert(h) {
            return false;
        }
        if i.size == 0 {
            let _ = self.cache.insert_bytes(&h, &[], Some(&i.path));
            return false;
        }
        self.walk.push((i.path, h, i.size), hot);
        true
    }

    fn add_pending(&mut self, i: Item, hot: bool) -> bool {
        let Some(vk) = i.ver else { return false };
        if self.walk.seen_ver.len() >= SEEN_MAX {
            self.walk.seen_ver.clear();
        }
        if !self.walk.seen_ver.insert(vk) {
            return false;
        }
        self.walk.push_ver((i.node, i.path, vk), hot);
        true
    }

    // a rule file too big for one FetchMany reply is fetched on its own
    fn add_rule(&mut self, i: Item) {
        if i.size <= WARM_MAX {
            let _ = self.add(i, WARM_MAX, false);
            return;
        }
        let Some(h) = i.hash else { return };
        if !self.eligible(&i, RANGE_FILE_MIN) || !self.walk.seen.insert(h) {
            return;
        }
        self.walk.big.push((i.path, h, i.size));
    }

    // more than BURST_N cold accesses inside the window means a scan: warm those directories next
    fn burst(&mut self, t: Instant, dir: NodeId) {
        let w = &mut self.walk;
        while w
            .burst
            .front()
            .is_some_and(|&(t0, _)| t.saturating_duration_since(t0) > BURST_WINDOW)
        {
            w.burst.pop_front();
        }
        w.burst.push_back((t, dir));
        if w.burst.len() > BURST_N {
            w.scan_until = Some(t + BURST_WINDOW * 4);
            for (_, d) in w.burst.drain(..) {
                if w.hot.len() < HOT_MAX && !w.hot.contains(&d) {
                    w.hot.push_back(d);
                }
            }
        }
    }

    fn siblings(&mut self, dir: NodeId, node: NodeId, items: &mut Vec<Item>) {
        if self.walk.sibs.len() >= SIBS_MAX {
            self.walk.sibs.clear();
        }
        if !self.walk.sibs.insert(dir) {
            return;
        }
        items.clear();
        if !self.tree.list_fetchable(dir, node, SIBLING_MAX, items) {
            return;
        }
        let mut batch = Vec::new();
        let (mut total, mut bytes) = (0u64, 0u64);
        let mut pending = false;
        for i in items.drain(..) {
            if i.node == node || !self.eligible(&i, SIBLING_MAX) || total + i.size > SIBLING_TOTAL {
                continue;
            }
            let Some(h) = i.hash else {
                let size = i.size;
                if self.add_pending(i, true) {
                    total += size;
                    pending = true;
                }
                continue;
            };
            if !self.walk.seen.insert(h) {
                continue;
            }
            total += i.size;
            bytes += i.size;
            batch.push((i.path, h, i.size));
            if bytes >= BATCH_BYTES || batch.len() >= BATCH_ITEMS.min(BATCH_MAX) {
                bytes = 0;
                if !self.issue(std::mem::take(&mut batch), true) {
                    return self.walk.halt();
                }
            }
        }
        if !self.issue(batch, true) {
            return self.walk.halt();
        }
        // step seals and sends urgent batches without waiting for a window
        if pending {
            self.walk.urgent = true;
        }
    }

    fn git_meta(&mut self, git: NodeId, items: &mut Vec<Item>) {
        let mut info = None;
        items.clear();
        if !self.tree.list(git, items) {
            return;
        }
        let found = std::mem::take(items);
        for i in found {
            let name = name_of(&i.path);
            if i.dir && name == "info" {
                info = Some(i.node);
            } else if GIT_META.contains(&name) {
                self.add_rule(i);
            }
        }
        if let Some(n) = info
            && self.tree.list(n, items)
        {
            let found = std::mem::take(items);
            for i in found {
                if name_of(&i.path) == "exclude" {
                    self.add_rule(i);
                }
            }
        }
    }

    fn step(&mut self, items: &mut Vec<Item>) {
        let mut dirs = 0;
        while self.walk.ready.is_empty() && dirs < DIRS_PER_STEP && !self.walk.urgent {
            let (dir, hot) = match self.walk.hot.pop_front() {
                Some(d) => (d, true),
                None => match self.walk.queue.pop_front() {
                    Some(d) => (d, false),
                    None => break,
                },
            };
            dirs += 1;
            items.clear();
            if !self.tree.list(dir, items) {
                continue;
            }
            let phase = if hot { Phase::Warm } else { self.walk.phase };
            let mut found = std::mem::take(items);
            for i in found.drain(..) {
                self.visit(i, phase, hot, items);
            }
            // keep the larger buffer so the next listing reuses its capacity
            if found.capacity() > items.capacity() {
                *items = found;
            }
        }
        if self.walk.queue.is_empty()
            && self.walk.phase == Phase::Warm
            && !self.walk.later.is_empty()
        {
            self.walk.objects = true;
            self.walk.queue.extend(self.walk.later.drain(..));
        }
        let exhausted = self.walk.queue.is_empty() && self.walk.hot.is_empty();
        if self.walk.urgent || exhausted {
            self.walk.urgent = false;
            self.walk.seal();
        }
        while self.can_step() {
            let Some((job, hot)) = self.walk.ready.pop_front() else {
                break;
            };
            let sent = match job {
                Job::Hash(batch) => self.issue(batch, hot),
                Job::Ver(first) => {
                    let mut group = vec![first];
                    while group.len() < VER_PAR
                        && let Some((Job::Ver(_), _)) = self.walk.ready.front()
                        && let Some((Job::Ver(next), _)) = self.walk.ready.pop_front()
                    {
                        group.push(next);
                    }
                    self.issue_ver(&group)
                }
            };
            if !sent {
                return self.walk.halt();
            }
        }
        if exhausted
            && self.walk.ready.is_empty()
            && self.walk.batch.is_empty()
            && self.walk.vbatch.is_empty()
        {
            if !self.walk.big.is_empty() && !self.fetch_big() {
                return self.walk.halt();
            }
            match self.walk.phase {
                Phase::Rules => {
                    self.walk.phase = Phase::Warm;
                    self.walk.queue.push_back(ROOT);
                    self.prog.total.store(self.tree.files(), Relaxed);
                }
                Phase::Warm | Phase::Idle => {
                    self.walk.phase = Phase::Idle;
                    self.prog.done.store(0, Relaxed);
                    self.prog.total.store(0, Relaxed);
                }
            }
        }
    }

    fn visit(&mut self, i: Item, phase: Phase, hot: bool, items: &mut Vec<Item>) {
        if i.skip {
            return;
        }
        let name = name_of(&i.path);
        if i.dir {
            if hot {
                return;
            }
            if phase == Phase::Rules && name == ".git" {
                return self.git_meta(i.node, items);
            }
            // packs are fetched on demand only
            if is_objects_dir(&i.path) {
                self.walk.later.push(i.node);
            } else if !is_pack_dir(&i.path) {
                self.walk.queue.push_back(i.node);
            }
            return;
        }
        match phase {
            Phase::Rules => {
                if RULE_FILES.contains(&name) {
                    self.add_rule(i);
                }
            }
            Phase::Warm | Phase::Idle => {
                if !self.add(i, WARM_MAX, hot) && self.walk.phase == Phase::Warm {
                    self.prog.done.fetch_add(1, Relaxed);
                }
            }
        }
    }

    // rule files too big for a batch, fetched one at a time once the batches have landed
    fn fetch_big(&mut self) -> bool {
        if !self.drain() {
            return false;
        }
        for (p, h, size) in std::mem::take(&mut self.walk.big) {
            self.cache.gate().wait_idle();
            if self.cache.remote().current().is_none() {
                return false;
            }
            let _ = self.cache.fetch_whole(
                &h,
                &p,
                size,
                Instant::now() + MANY_WAIT + Duration::from_millis(size >> 12),
            );
        }
        true
    }

    // a file the host replaced fails its item and is dropped: its new version arrives as a change
    // false only when disconnected
    fn issue_ver(&mut self, group: &[Vec<PendingWant>]) -> bool {
        if self.cache.remote().current().is_none() {
            return false;
        }
        let (used, cap) = self.cache.usage();
        let bytes: u64 = group.iter().flatten().map(|w| w.2.size).sum();
        if used.saturating_add(bytes) > cap / 10 * 9 {
            return false;
        }
        let replies = self.fetch_ver(group);
        for (batch, got) in group.iter().zip(replies) {
            for ((node, path, vk), (p, r)) in batch.iter().zip(got) {
                if *path == p
                    && let Ok(v) = r
                {
                    self.tree.learn(*node, vk.ver, v.hash);
                }
            }
            if self.walk.phase == Phase::Warm {
                self.prog.done.fetch_add(batch.len() as u64, Relaxed);
            }
        }
        self.cache.evict();
        self.cache.remote().current().is_some()
    }

    fn fetch_ver(&self, group: &[Vec<PendingWant>]) -> Vec<Vec<(RelPath, Result<Version, i32>)>> {
        let deadline = Instant::now() + MANY_WAIT;
        let cache = &self.cache;
        let call = move |b: &[PendingWant]| {
            let items: Vec<(RelPath, VerKey)> = b.iter().map(|(_, p, k)| (p.clone(), *k)).collect();
            cache.fetch_many_ver(&items, deadline)
        };
        let Some((first, rest)) = group.split_first() else {
            return Vec::new();
        };
        std::thread::scope(|sc| {
            let others: Vec<_> = rest
                .iter()
                .map(|b| {
                    (
                        b,
                        std::thread::Builder::new()
                            .name("csync-prefetch-ver".into())
                            .spawn_scoped(sc, move || call(b)),
                    )
                })
                .collect();
            let mut out = vec![call(first)];
            for (b, h) in others {
                out.push(match h {
                    Ok(h) => h.join().unwrap_or_default(),
                    Err(_) => call(b),
                });
            }
            out
        })
    }

    // false only when disconnected; a lander stores the reply, at the readers' priority when hot
    fn issue(&mut self, items: Vec<Want>, hot: bool) -> bool {
        if items.is_empty() {
            return true;
        }
        let Some(remote) = self.cache.remote().current() else {
            return false;
        };
        // the walk stops once the cache would pass 90% of its cap
        let (used, cap) = self.cache.usage();
        let bytes: u64 = items.iter().map(|i| i.2).sum();
        if used.saturating_add(bytes) > cap / 10 * 9 {
            return false;
        }
        let warm = self.walk.phase == Phase::Warm;
        let batch = self.cache.begin_batch(&items);
        if warm {
            let skipped = (items.len() - batch.len()) as u64;
            self.prog.done.fetch_add(skipped, Relaxed);
        }
        if batch.is_empty() {
            return true;
        }
        let op = Op::FetchMany {
            items: batch.request(),
        };
        let (sh, cache) = (self.sh.clone(), self.cache.clone());
        let done = Box::new(move |r: Result<Reply, RpcError>| {
            // readers may wait on this batch, so it is stored off the network reader and the prefetch thread
            let job = Arc::new(Mutex::new(Some((batch, r))));
            let (lsh, ljob) = (sh.clone(), job.clone());
            let spawned = std::thread::Builder::new()
                .name("csync-land".into())
                .spawn(move || {
                    if !hot {
                        lower_priority();
                    }
                    if let Some((b, r)) = lock(&ljob).take() {
                        let (n, closed) = store(&cache, b, r);
                        lsh.landed(Landed::Stored { n, closed });
                    }
                });
            if spawned.is_err()
                && let Some((b, r)) = lock(&job).take()
            {
                sh.landed(Landed::Reply(b, r));
            }
        });
        match remote.submit(op, done) {
            Ok(_) => {
                self.inflight += 1;
                true
            }
            Err(RpcError::Closed) => false,
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::cache::{CacheConfig, Done, Remote, RemoteSlot};
    use super::*;
    use crate::net::rpc::ChunkSink;
    use crate::proto::{BlobItem, Bytes, ReqId, Want, WireErr};
    use rustc_hash::FxHashMap;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmpdir() -> Dir {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "csync-prefetch-{}-{}",
            std::process::id(),
            N.fetch_add(1, Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        Dir(p)
    }

    // a host holding file contents by version; a version it lacks was replaced since the scan
    #[derive(Default)]
    struct Host {
        vers: Mutex<FxHashMap<Seq, Vec<u8>>>,
        ver_rounds: Mutex<Vec<Vec<RelPath>>>,
        hash_rounds: AtomicUsize,
    }

    impl Host {
        fn answer(&self, items: Vec<(RelPath, Want)>) -> Reply {
            let vers = lock(&self.vers);
            let out: Vec<BlobItem> = items
                .into_iter()
                .map(|(p, w)| {
                    let found = match w {
                        Want::Ver(k) => vers.get(&k.ver),
                        Want::Hash(h) => vers.values().find(|b| *blake3::hash(b).as_bytes() == h),
                    };
                    match found {
                        Some(b) => (p, Ok((*blake3::hash(b).as_bytes(), Bytes(b.clone())))),
                        None => (p, Err(WireErr::Gone)),
                    }
                })
                .collect();
            Reply::Blobs { items: out }
        }

        fn serve(&self, op: Op) -> Result<Reply, RpcError> {
            let Op::FetchMany { items } = op else {
                return Err(RpcError::Closed);
            };
            if items.iter().any(|(_, w)| matches!(w, Want::Ver(_))) {
                lock(&self.ver_rounds).push(items.iter().map(|(p, _)| p.clone()).collect());
            } else {
                self.hash_rounds.fetch_add(1, Relaxed);
            }
            Ok(self.answer(items))
        }
    }

    impl Remote for Host {
        fn call(&self, op: Op, _d: Instant) -> Result<Reply, RpcError> {
            self.serve(op)
        }
        fn call_stream(
            &self,
            _op: Op,
            _sink: Box<dyn ChunkSink>,
            _d: Instant,
        ) -> Result<Reply, RpcError> {
            Err(RpcError::Closed)
        }
        fn submit(&self, op: Op, done: Done) -> Result<ReqId, RpcError> {
            done(self.serve(op));
            Ok(1)
        }
        fn submit_stream(
            &self,
            _op: Op,
            _sink: Box<dyn ChunkSink>,
            _done: Done,
        ) -> Result<ReqId, RpcError> {
            Err(RpcError::Closed)
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

    // every item sits directly under the root; learn follows the real tree's rules
    #[derive(Default)]
    struct Tree {
        items: Mutex<Vec<Item>>,
        learned: Mutex<Vec<(NodeId, Seq, Hash32)>>,
    }

    impl TreeView for Tree {
        fn list(&self, dir: NodeId, out: &mut Vec<Item>) -> bool {
            if dir != ROOT {
                return false;
            }
            out.extend(lock(&self.items).iter().cloned());
            true
        }
        fn item(&self, node: NodeId) -> Option<Item> {
            lock(&self.items).iter().find(|i| i.node == node).cloned()
        }
        fn files(&self) -> u64 {
            lock(&self.items).len() as u64
        }
        fn learn(&self, node: NodeId, ver: Seq, hash: Hash32) -> bool {
            let mut items = lock(&self.items);
            let Some(i) = items.iter_mut().find(|i| i.node == node) else {
                return false;
            };
            if i.hash.is_some() || i.ver.map(|k| k.ver) != Some(ver) {
                return false;
            }
            i.hash = Some(hash);
            i.ver = None;
            lock(&self.learned).push((node, ver, hash));
            true
        }
    }

    fn pending(node: NodeId, name: &str, ver: Seq, data: &[u8]) -> Item {
        Item {
            node,
            path: RelPath::new(name).unwrap(),
            dir: false,
            hash: None,
            ver: Some(VerKey {
                index: 7,
                ver,
                size: data.len() as u64,
            }),
            size: data.len() as u64,
            skip: false,
            used: false,
        }
    }

    fn known(node: NodeId, name: &str, data: &[u8]) -> Item {
        Item {
            hash: Some(*blake3::hash(data).as_bytes()),
            ver: None,
            ..pending(node, name, 0, data)
        }
    }

    fn hash_of(data: &[u8]) -> Hash32 {
        *blake3::hash(data).as_bytes()
    }

    struct Rig {
        w: Worker,
        tree: Arc<Tree>,
        host: Arc<Host>,
        _dir: Dir,
    }

    fn rig(items: Vec<Item>, files: &[(Seq, &[u8])]) -> Rig {
        let dir = tmpdir();
        let host = Arc::new(Host::default());
        for (v, b) in files {
            lock(&host.vers).insert(*v, b.to_vec());
        }
        let tree = Arc::new(Tree {
            items: Mutex::new(items),
            ..Tree::default()
        });
        let slot = RemoteSlot::new();
        slot.set(Some(host.clone() as Arc<dyn Remote>));
        let cache = Arc::new(
            BlobCache::open(
                &CacheConfig {
                    dir: dir.0.clone(),
                    cap: Some(1 << 30),
                },
                slot,
            )
            .unwrap(),
        );
        let sh = Arc::new(PShared {
            st: Mutex::new(State {
                hints: VecDeque::new(),
                landed: Vec::new(),
                stop: false,
                idle: false,
            }),
            cv: Condvar::new(),
        });
        let w = Worker {
            sh,
            cache,
            tree: tree.clone(),
            walk: Walk::default(),
            inflight: 0,
            prog: Arc::new(Progress::default()),
        };
        Rig {
            w,
            tree,
            host,
            _dir: dir,
        }
    }

    fn land_all(w: &mut Worker) {
        assert!(w.drain());
    }

    #[test]
    fn a_sibling_listing_builds_paths_only_for_children_that_could_be_fetched() {
        use super::super::tree::Effect;
        use crate::proto::{Change, Meta};
        let meta = |kind: Kind, size: u64, hash: Option<Hash32>| Meta {
            kind,
            perm: 0o644,
            size,
            mtime_ns: 1,
            ctime_ns: 0,
            hash,
            link: None,
            git_ro: false,
        };
        let mut t = GTree::new();
        let mut fx: Vec<Effect> = Vec::new();
        let kids = [
            ("d", meta(Kind::Dir, 0, None)),
            ("d/small", meta(Kind::File, 10, Some([1; 32]))),
            ("d/big", meta(Kind::File, 1000, Some([2; 32]))),
            ("d/sub", meta(Kind::Dir, 0, None)),
            ("d/self", meta(Kind::File, 10, Some([3; 32]))),
        ];
        for (p, m) in kids {
            let change = Change::Upsert {
                path: RelPath::new(p).unwrap(),
                meta: m,
                ver: 0,
            };
            t.apply(&change, &mut fx);
        }
        let id = |p: &str| t.resolve(&RelPath::new(p).unwrap()).unwrap();
        let mut all = Vec::new();
        assert!(gtree_list(&t, id("d"), &mut all));
        assert_eq!(all.len(), 4);
        let mut some = Vec::new();
        assert!(gtree_list_fetchable(
            &t,
            id("d"),
            id("d/self"),
            100,
            &mut some
        ));
        let names: Vec<&str> = some.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(names, ["d/small"]);
        let mut none = Vec::new();
        assert!(!gtree_list_fetchable(
            &t,
            id("d/small"),
            ROOT,
            100,
            &mut none
        ));
    }

    #[test]
    fn a_walk_fetches_rule_files_first_then_every_pending_file_by_version() {
        let (gi, a, b, c) = (
            &b"target/\n"[..],
            &b"alpha"[..],
            &b"beta"[..],
            &b"gamma"[..],
        );
        let mut r = rig(
            vec![
                pending(2, "a.txt", 1, a),
                pending(3, ".gitignore", 2, gi),
                pending(4, "b.txt", 3, b),
                pending(5, "c.txt", 4, c),
            ],
            &[(1, a), (2, gi), (3, b), (4, c)],
        );
        let mut items = Vec::new();
        r.w.on_hint(Instant::now(), Hint::Start, &mut items);
        for _ in 0..8 {
            if !r.w.walk.active() {
                break;
            }
            r.w.step(&mut items);
        }
        assert!(!r.w.walk.active());

        let rounds = lock(&r.host.ver_rounds).clone();
        let names = |v: &Vec<RelPath>| v.iter().map(|p| p.as_str().to_owned()).collect::<Vec<_>>();
        assert_eq!(rounds.len(), 2, "rule files first, the rest in one batch");
        assert_eq!(names(&rounds[0]), [".gitignore"]);
        let mut rest = names(&rounds[1]);
        rest.sort();
        assert_eq!(rest, ["a.txt", "b.txt", "c.txt"]);
        assert_eq!(r.host.hash_rounds.load(Relaxed), 0);

        let mut learned = lock(&r.tree.learned).clone();
        learned.sort();
        assert_eq!(
            learned,
            [
                (2, 1, hash_of(a)),
                (3, 2, hash_of(gi)),
                (4, 3, hash_of(b)),
                (5, 4, hash_of(c))
            ]
        );
        for d in [a, gi, b, c] {
            assert!(r.w.cache.contains(&hash_of(d)));
        }
    }

    #[test]
    fn a_pending_file_the_host_replaced_is_dropped_and_stays_pending() {
        let (a, b) = (&b"alpha"[..], &b"beta"[..]);
        let mut r = rig(
            vec![pending(2, "a.txt", 1, a), pending(3, "b.txt", 2, b)],
            &[(1, a)],
        );
        let mut items = Vec::new();
        for n in [2, 3] {
            r.w.on_hint(Instant::now(), Hint::WarmPending(n), &mut items);
        }
        r.w.step(&mut items);

        assert_eq!(lock(&r.host.ver_rounds).len(), 1);
        assert_eq!(*lock(&r.tree.learned), [(2, 1, hash_of(a))]);
        assert!(r.w.cache.contains(&hash_of(a)));
        assert!(!r.w.cache.contains(&hash_of(b)));
        assert!(r.tree.item(3).unwrap().hash.is_none());
    }

    #[test]
    fn pending_files_over_the_batch_limit_go_out_as_separate_batches() {
        let n = BATCH_ITEMS + 88;
        let data: Vec<Vec<u8>> = (0..n).map(|i| format!("file {i}").into_bytes()).collect();
        let items: Vec<Item> = data
            .iter()
            .enumerate()
            .map(|(i, d)| pending(i as u64 + 2, &format!("f{i}.txt"), i as u64 + 1, d))
            .collect();
        let files: Vec<(Seq, &[u8])> = data
            .iter()
            .enumerate()
            .map(|(i, d)| (i as u64 + 1, d.as_slice()))
            .collect();
        let mut r = rig(items, &files);
        let mut scratch = Vec::new();
        for i in 0..n {
            r.w.on_hint(
                Instant::now(),
                Hint::WarmPending(i as u64 + 2),
                &mut scratch,
            );
        }
        r.w.step(&mut scratch);

        let mut sizes: Vec<usize> = lock(&r.host.ver_rounds).iter().map(Vec::len).collect();
        sizes.sort();
        assert_eq!(sizes, [88, BATCH_ITEMS]);
        assert_eq!(lock(&r.tree.learned).len(), n);
    }

    #[test]
    fn pending_files_that_fail_the_warm_rules_are_not_fetched() {
        let (x, y, z) = (&b"x"[..], &b"y"[..], &b"z"[..]);
        let big = Item {
            size: WARM_MAX + 1,
            ..pending(2, "big.bin", 1, x)
        };
        let local = Item {
            skip: true,
            ..pending(3, "local.txt", 2, y)
        };
        let dir = Item {
            dir: true,
            ..pending(4, "d", 3, z)
        };
        let mut r = rig(vec![big, local, dir], &[(1, x), (2, y), (3, z)]);
        let mut items = Vec::new();
        for n in [2, 3, 4] {
            r.w.on_hint(Instant::now(), Hint::WarmPending(n), &mut items);
        }
        r.w.step(&mut items);
        assert!(lock(&r.host.ver_rounds).is_empty());
        assert!(lock(&r.tree.learned).is_empty());
    }

    #[test]
    fn a_known_hash_is_still_fetched_by_hash() {
        let a = &b"alpha"[..];
        let mut r = rig(vec![known(2, "a.txt", a)], &[(1, a)]);
        let mut items = Vec::new();
        r.w.on_hint(Instant::now(), Hint::Warm(2, hash_of(a)), &mut items);
        r.w.step(&mut items);
        land_all(&mut r.w);

        assert_eq!(r.host.hash_rounds.load(Relaxed), 1);
        assert!(lock(&r.host.ver_rounds).is_empty());
        assert!(lock(&r.tree.learned).is_empty());
        assert!(r.w.cache.contains(&hash_of(a)));
    }

    #[test]
    fn a_warm_hint_for_a_node_that_is_still_pending_fetches_nothing() {
        let a = &b"alpha"[..];
        let mut r = rig(vec![pending(2, "a.txt", 1, a)], &[(1, a)]);
        let mut items = Vec::new();
        r.w.on_hint(Instant::now(), Hint::Warm(2, hash_of(a)), &mut items);
        r.w.step(&mut items);
        land_all(&mut r.w);
        assert_eq!(r.host.hash_rounds.load(Relaxed), 0);
        assert!(lock(&r.host.ver_rounds).is_empty());
    }

    #[test]
    fn a_pushed_hash_of_an_unread_file_is_left_to_the_running_walk() {
        let (a, b) = (&b"alpha"[..], &b"bravo"[..]);
        let read = Item {
            used: true,
            ..known(3, "b.txt", b)
        };
        let mut r = rig(vec![known(2, "a.txt", a), read], &[(1, a), (2, b)]);
        let mut items = Vec::new();
        r.w.on_hint(Instant::now(), Hint::Start, &mut items);
        r.w.on_hint(Instant::now(), Hint::Warm(2, hash_of(a)), &mut items);
        assert!(r.w.walk.batch.is_empty());
        assert!(!r.w.walk.urgent);
        // a file a reader has seen is wanted again soon, so its new hash still jumps the queue
        r.w.on_hint(Instant::now(), Hint::Warm(3, hash_of(b)), &mut items);
        assert_eq!(r.w.walk.batch.len(), 1);
        assert!(r.w.walk.urgent && r.w.walk.hot_batch);
    }

    #[test]
    fn the_git_object_tail_never_takes_the_scan_window() {
        let a = &b"alpha"[..];
        let mut r = rig(vec![known(2, "a.txt", a)], &[(1, a)]);
        r.w.walk.phase = Phase::Warm;
        r.w.walk.ready.push_back((
            Job::Hash(vec![(RelPath::new("a.txt").unwrap(), hash_of(a), 5)]),
            false,
        ));
        r.w.walk.scan_until = Some(Instant::now() + Duration::from_secs(60));
        r.w.inflight = DEPTH;
        assert!(r.w.can_step());
        r.w.walk.objects = true;
        assert!(!r.w.can_step());
    }

    #[test]
    fn a_cold_open_lands_its_hashed_and_pending_siblings_in_one_burst() {
        let (a, b, c) = (&b"alpha"[..], &b"bravo"[..], &b"charlie"[..]);
        let items = vec![
            known(2, "a.txt", a),
            known(3, "b.txt", b),
            pending(4, "c.txt", 5, c),
        ];
        let r = rig(items, &[(1, a), (2, b), (5, c)]);
        let p = Prefetch::start(r.w.cache.clone(), r.tree.clone()).unwrap();
        p.open_batch(ROOT, 2, Instant::now() + Duration::from_secs(30));

        assert_eq!(r.host.hash_rounds.load(Relaxed), 1);
        assert_eq!(
            *lock(&r.host.ver_rounds),
            vec![vec![RelPath::new("c.txt").unwrap()]]
        );
        for d in [a, b, c] {
            assert!(r.w.cache.contains(&hash_of(d)));
        }
        assert_eq!(*lock(&r.tree.learned), vec![(4, 5, hash_of(c))]);
    }

    #[test]
    fn a_cold_open_with_nothing_to_share_leaves_its_file_to_the_read() {
        let a = &b"alpha"[..];
        let r = rig(vec![known(2, "a.txt", a)], &[(1, a)]);
        let p = Prefetch::start(r.w.cache.clone(), r.tree.clone()).unwrap();
        p.open_batch(ROOT, 2, Instant::now() + Duration::from_secs(30));
        assert_eq!(r.host.hash_rounds.load(Relaxed), 0);
        assert!(!r.w.cache.contains(&hash_of(a)));
    }
}
