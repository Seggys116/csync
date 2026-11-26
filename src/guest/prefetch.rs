use super::cache::{Batch, BlobCache, lock};
use super::tree::{GDomain, GTree, NodeId, ROOT, Vis};
use crate::net::rpc::RpcError;
use crate::proto::{BATCH_MAX, Hash32, Kind, Op, RANGE_FILE_MIN, RelPath, Reply};
use rustc_hash::FxHashSet;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const WARM_MAX: u64 = 1 << 20;
const SIBLING_MAX: u64 = 256 << 10;
const SIBLING_TOTAL: u64 = 4 << 20;
// a FetchMany reply is one frame the host builds before sending, so batches stay small and several fly at once
const BATCH_BYTES: u64 = 1 << 20;
const BATCH_ITEMS: usize = 512;
// background batches in flight; scan-driven ones may use the larger window
const DEPTH: usize = 3;
const HOT_DEPTH: usize = 8;
const BURST_N: usize = 8;
const BURST_WINDOW: Duration = Duration::from_millis(50);
const HINTS_MAX: usize = 4096;
const HOT_MAX: usize = 64;
const SEEN_MAX: usize = 1 << 20;
const SIBS_MAX: usize = 4096;
const DIRS_PER_STEP: usize = 64;
const MANY_WAIT: Duration = Duration::from_secs(30);
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
}

// skip: Local overlay or pending delete, never fetched from the host
#[derive(Clone, Debug)]
pub struct Item {
    pub node: NodeId,
    pub path: RelPath,
    pub dir: bool,
    pub hash: Option<Hash32>,
    pub size: u64,
    pub skip: bool,
}

// the prefetcher's read-only view of the guest tree; implemented for the usual lock wrappers of GTree
pub trait TreeView: Send + Sync {
    fn list(&self, dir: NodeId, out: &mut Vec<Item>) -> bool;
    fn item(&self, node: NodeId) -> Option<Item>;
    fn files(&self) -> u64;
}

fn gtree_item(t: &GTree, id: NodeId, path: RelPath) -> Option<Item> {
    let n = t.get(id)?;
    Some(Item {
        node: id,
        path,
        dir: n.meta.kind == Kind::Dir,
        hash: n.meta.hash,
        size: n.meta.size,
        skip: n.domain == GDomain::Local || n.vis == Vis::PendingDelete,
    })
}

fn gtree_list(t: &GTree, dir: NodeId, out: &mut Vec<Item>) -> bool {
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
        let Ok(p) = base.join(name) else { continue };
        if let Some(i) = gtree_item(t, id, p) {
            out.push(i);
        }
    }
    true
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
    fn item(&self, node: NodeId) -> Option<Item> {
        gtree_node(&self.read().unwrap_or_else(|e| e.into_inner()), node)
    }
    fn files(&self) -> u64 {
        self.read().unwrap_or_else(|e| e.into_inner()).files()
    }
}

impl TreeView for Mutex<GTree> {
    fn list(&self, dir: NodeId, out: &mut Vec<Item>) -> bool {
        gtree_list(&lock(self), dir, out)
    }
    fn item(&self, node: NodeId) -> Option<Item> {
        gtree_node(&lock(self), node)
    }
    fn files(&self) -> u64 {
        lock(self).files()
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

struct State {
    hints: VecDeque<(Instant, Hint)>,
    landed: Vec<(Batch, Result<Reply, RpcError>)>,
    stop: bool,
    idle: bool,
}

impl PShared {
    fn wake(&self, st: std::sync::MutexGuard<'_, State>) {
        let w = st.idle;
        drop(st);
        if w {
            self.cv.notify_one();
        }
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
    // sealed batches waiting for a window; true when a scan or a host change asked for them
    ready: VecDeque<(Vec<Want>, bool)>,
    big: Vec<Want>,
    seen: FxHashSet<Hash32>,
    burst: VecDeque<(Instant, NodeId)>,
    sibs: FxHashSet<NodeId>,
    // a burst of cold opens means a scan wants everything: background batches use the wide window until then
    scan_until: Option<Instant>,
    urgent: bool,
    saved: bool,
}

impl Walk {
    fn active(&self) -> bool {
        self.phase != Phase::Idle
            || !self.hot.is_empty()
            || !self.batch.is_empty()
            || !self.ready.is_empty()
            || !self.big.is_empty()
    }

    fn seal(&mut self) {
        if !self.batch.is_empty() {
            let b = std::mem::take(&mut self.batch);
            self.ready.push_back((b, std::mem::take(&mut self.hot_batch)));
        }
        self.bytes = 0;
    }

    fn push(&mut self, item: (RelPath, Hash32, u64), hot: bool) {
        self.bytes += item.2;
        self.hot_batch |= hot;
        self.batch.push(item);
        if self.bytes >= BATCH_BYTES || self.batch.len() >= BATCH_ITEMS.min(BATCH_MAX) {
            self.seal();
        }
    }

    fn halt(&mut self) {
        self.phase = Phase::Idle;
        self.queue.clear();
        self.hot.clear();
        self.batch.clear();
        self.later.clear();
        self.ready.clear();
        self.hot_batch = false;
        self.big.clear();
        self.bytes = 0;
        self.urgent = false;
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
            cache,
            tree,
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
        })
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
        let _ = rustix::process::setpriority_process(Some(rustix::thread::gettid()), NICE);
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
            for (b, r) in landed {
                self.land(b, r);
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
                if self.walk.scan_until.is_some_and(|t| Instant::now() < t) {
                    return self.inflight < HOT_DEPTH;
                }
                self.inflight == 0 || (self.inflight < DEPTH && self.cache.gate().idle_or_arm())
            }
        }
    }

    fn land(&mut self, b: Batch, r: Result<Reply, RpcError>) {
        self.inflight = self.inflight.saturating_sub(1);
        let n = b.len() as u64;
        match r {
            Ok(Reply::Blobs { items }) => {
                b.land(items);
                self.cache.evict();
            }
            Err(RpcError::Closed) => self.walk.halt(),
            _ => {}
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
            for (b, r) in landed {
                self.land(b, r);
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
                    let _ = self.add(i, WARM_MAX, true);
                    self.walk.urgent = true;
                }
            }
        }
    }

    fn eligible(&self, i: &Item, max: u64) -> bool {
        !i.dir && !i.skip && i.size <= max && i.hash.is_some_and(|h| !self.cache.contains(&h))
    }

    // true when the item was queued for a batch
    fn add(&mut self, i: Item, max: u64, hot: bool) -> bool {
        let Some(h) = i.hash else { return false };
        if !self.eligible(&i, max) {
            return false;
        }
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
        if !self.tree.list(dir, items) {
            return;
        }
        let mut batch = Vec::new();
        let (mut total, mut bytes) = (0u64, 0u64);
        for i in items.drain(..) {
            if i.node == node || !self.eligible(&i, SIBLING_MAX) || total + i.size > SIBLING_TOTAL {
                continue;
            }
            let Some(h) = i.hash else { continue };
            if !self.walk.seen.insert(h) {
                continue;
            }
            total += i.size;
            bytes += i.size;
            batch.push((i.path, h, i.size));
            if bytes >= BATCH_BYTES || batch.len() >= BATCH_ITEMS.min(BATCH_MAX) {
                bytes = 0;
                if !self.issue(std::mem::take(&mut batch)) {
                    return self.walk.halt();
                }
            }
        }
        if !self.issue(batch) {
            self.walk.halt();
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
        if self.walk.queue.is_empty() && self.walk.phase == Phase::Warm {
            self.walk.queue.extend(self.walk.later.drain(..));
        }
        let exhausted = self.walk.queue.is_empty() && self.walk.hot.is_empty();
        if self.walk.urgent || exhausted {
            self.walk.urgent = false;
            self.walk.seal();
        }
        while self.can_step() {
            let Some((batch, _)) = self.walk.ready.pop_front() else {
                break;
            };
            if !self.issue(batch) {
                return self.walk.halt();
            }
        }
        if exhausted && self.walk.ready.is_empty() && self.walk.batch.is_empty() {
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

    // false only when disconnected; the reply is landed by this thread, never on the network reader
    fn issue(&mut self, items: Vec<Want>) -> bool {
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
        let sh = self.sh.clone();
        let done = Box::new(move |r: Result<Reply, RpcError>| {
            let mut st = lock(&sh.st);
            st.landed.push((batch, r));
            sh.wake(st);
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
