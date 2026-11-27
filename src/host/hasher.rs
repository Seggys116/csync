use super::{Core, hash_verified_paced, lock};
use crate::index::tree::{Domain, Entry, HashJob};
use crate::proto::{BATCH_MAX, Hash32, Kind, Name, RelPath, Seq};
use crate::sys;
use rustc_hash::FxHashSet;
use rustix::fs::OFlags;
use std::{
    collections::VecDeque,
    os::fd::AsFd,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const HOT_MAX: usize = 1_024;
const HOT_BATCH: usize = 4_096;
const BATCH: usize = 64;
const SMALL_MAX: u64 = 1 << 20;
const TRIES: usize = 3;
const FG_WAIT: Duration = Duration::from_millis(50);
const FG_POLL: Duration = Duration::from_millis(2);
pub(crate) const PUSH_EVERY: Duration = Duration::from_millis(100);

// the files the guest prefetcher fetches first, so their hashes are wanted first
const MANIFESTS: &[&str] = &[
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
// info/exclude is a git rule file; the rest is what git reads first in a repository or submodule
const GIT_META: &[&str] = &[
    "HEAD",
    "config",
    "packed-refs",
    "index",
    "shallow",
    "commondir",
    "exclude",
];

#[derive(Default)]
struct State {
    epoch: u64,
    hot: VecDeque<RelPath>,
    hot_set: FxHashSet<RelPath>,
}

#[derive(Default)]
struct PushBuf {
    items: Vec<(RelPath, Seq, Hash32)>,
    since: Option<Instant>,
    done_due: bool,
}

pub(crate) enum Wait {
    Stop,
    Changed,
    Timeout,
}

// what the hasher threads and the code that feeds them share: wake-ups, hot directories and the push buffer
#[derive(Default)]
pub(crate) struct Hub {
    stop: AtomicBool,
    state: Mutex<State>,
    cv: Condvar,
    push: Mutex<PushBuf>,
}

impl Hub {
    pub(crate) fn wake(&self) {
        lock(&self.state).epoch += 1;
        self.cv.notify_all();
    }

    pub(crate) fn hint(&self, dir: &RelPath) {
        {
            let mut st = lock(&self.state);
            if st.hot.len() >= HOT_MAX || !st.hot_set.insert(dir.clone()) {
                return;
            }
            st.hot.push_back(dir.clone());
        }
        self.wake();
    }

    fn take_hot(&self) -> Option<RelPath> {
        let mut st = lock(&self.state);
        let d = st.hot.pop_front()?;
        st.hot_set.remove(&d);
        Some(d)
    }

    fn epoch(&self) -> u64 {
        lock(&self.state).epoch
    }

    pub(crate) fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn set_stop(&self, on: bool) {
        self.stop.store(on, Ordering::Release);
        self.wake();
    }

    // blocks until the epoch moves past `seen`, a stop, or the timeout
    fn wait(&self, seen: u64, timeout: Option<Duration>) -> Wait {
        let mut st = lock(&self.state);
        if self.stopped() {
            return Wait::Stop;
        }
        if st.epoch != seen {
            return Wait::Changed;
        }
        st = match timeout {
            Some(d) => {
                self.cv
                    .wait_timeout(st, d)
                    .unwrap_or_else(|e| e.into_inner())
                    .0
            }
            None => self.cv.wait(st).unwrap_or_else(|e| e.into_inner()),
        };
        if self.stopped() {
            Wait::Stop
        } else if st.epoch != seen {
            Wait::Changed
        } else {
            Wait::Timeout
        }
    }

    // true when the buffer is due to be sent
    pub(crate) fn add(&self, p: RelPath, ver: Seq, h: Hash32) -> bool {
        let (first, due) = {
            let mut b = lock(&self.push);
            let first = b.items.is_empty();
            if first {
                b.since = Some(Instant::now());
            }
            b.items.push((p, ver, h));
            b.done_due = true;
            let late = b.since.is_some_and(|s| s.elapsed() >= PUSH_EVERY);
            (first, late || b.items.len() >= BATCH_MAX)
        };
        if first {
            self.wake();
        }
        due
    }

    // everything buffered, once it is due or when forced
    pub(crate) fn take(&self, force: bool) -> Option<Vec<(RelPath, Seq, Hash32)>> {
        let mut b = lock(&self.push);
        if b.items.is_empty() {
            return None;
        }
        let late = b.since.is_none_or(|s| s.elapsed() >= PUSH_EVERY);
        if !force && !late && b.items.len() < BATCH_MAX {
            return None;
        }
        b.since = None;
        Some(std::mem::take(&mut b.items))
    }

    fn due_in(&self) -> Option<Duration> {
        let b = lock(&self.push);
        if b.items.is_empty() {
            return None;
        }
        let spent = b.since.map_or(PUSH_EVERY, |s| s.elapsed());
        Some(
            PUSH_EVERY
                .saturating_sub(spent)
                .max(Duration::from_millis(1)),
        )
    }

    // a hash was learned since guests were last told that none are missing
    pub(crate) fn done_due(&self) -> bool {
        lock(&self.push).done_due
    }

    fn take_done(&self) -> bool {
        std::mem::take(&mut lock(&self.push).done_due)
    }
}

struct Round {
    tier: u8,
    cursor: u32,
    // a full round hashed nothing: what is left cannot be hashed until something changes
    parked: bool,
}

impl Default for Round {
    fn default() -> Self {
        Self {
            tier: 1,
            cursor: 0,
            parked: false,
        }
    }
}

#[derive(Default)]
struct Plan {
    round: Mutex<Round>,
    hashed: AtomicUsize,
    inflight: Mutex<FxHashSet<RelPath>>,
}

fn tier1(name: &Name, e: &Entry) -> bool {
    let n = name.as_str();
    MANIFESTS.contains(&n) || (e.domain == Domain::GitRo && GIT_META.contains(&n))
}

fn tier2(_: &Name, e: &Entry) -> bool {
    e.meta.size <= SMALL_MAX
}

fn tier3(_: &Name, _: &Entry) -> bool {
    true
}

fn hot_siblings(core: &Core, dir: &RelPath, out: &mut Vec<HashJob>) {
    core.tree().for_children(dir, &mut |name, e| {
        if out.len() < HOT_BATCH
            && e.is_pending()
            && let Ok(path) = dir.join(name)
        {
            out.push(HashJob {
                path,
                ver: e.seq,
                stat: e.stat,
            });
        }
    });
}

// the next jobs in priority order: hot directories, then rule files and manifests, then small files, then the rest
fn next_batch(core: &Core, plan: &Plan) -> Vec<HashJob> {
    let mut out = Vec::new();
    while out.is_empty()
        && let Some(dir) = core.hashing.take_hot()
    {
        hot_siblings(core, &dir, &mut out);
        out.retain(|j| lock(&plan.inflight).insert(j.path.clone()));
    }
    if !out.is_empty() {
        return out;
    }
    let mut r = lock(&plan.round);
    while !r.parked && !core.hashing.stopped() {
        let keep: fn(&Name, &Entry) -> bool = match r.tier {
            1 => tier1,
            2 => tier2,
            _ => tier3,
        };
        let next = {
            let t = core.tree();
            if t.pending() == 0 {
                *r = Round::default();
                return out;
            }
            t.pending_from(r.cursor, BATCH, &keep, &mut out)
        };
        out.retain(|j| lock(&plan.inflight).insert(j.path.clone()));
        r.cursor = next;
        if next == 0 {
            if r.tier < 3 {
                r.tier += 1;
            } else {
                r.tier = 1;
                if plan.hashed.swap(0, Ordering::AcqRel) == 0 {
                    r.parked = true;
                }
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    out
}

// waits for requests being served to finish, but never longer than FG_WAIT; false once stopped
fn yield_fg(core: &Core) -> bool {
    if core.fg.load(Ordering::Acquire) > 0 {
        let end = Instant::now() + FG_WAIT;
        while core.fg.load(Ordering::Acquire) > 0 && Instant::now() < end && !core.hashing.stopped()
        {
            thread::sleep(FG_POLL);
        }
    }
    !core.hashing.stopped()
}

// true when the hash was recorded; a job whose file is not exactly the indexed version is dropped
fn run_job(core: &Core, job: &HashJob) -> bool {
    for _ in 0..TRIES {
        let Ok(fd) = sys::open_beneath(
            core.root.as_fd(),
            &job.path,
            OFlags::RDONLY | OFlags::NONBLOCK,
        ) else {
            return false;
        };
        let Ok(st) = sys::stat_key(fd.as_fd()) else {
            return false;
        };
        if st != job.stat || sys::kind_of_mode(st.mode) != Some(Kind::File) {
            return false;
        }
        match hash_verified_paced(fd.as_fd(), &st, &mut || yield_fg(core)) {
            Ok(Some(h)) => return core.apply_hash(&job.path, job.ver, &job.stat, h),
            Ok(None) if core.hashing.stopped() => return false,
            Ok(None) => {}
            Err(_) => return false,
        }
    }
    false
}

// sends what is buffered and, once nothing is pending, tells guests; returns false when stopped
fn idle(core: &Core, seen: u64) -> bool {
    let hub = &core.hashing;
    loop {
        core.flush_hashes(false);
        let drained = core.tree().pending() == 0;
        if drained && hub.take_done() {
            core.hashes_done();
        }
        match hub.wait(seen, hub.due_in()) {
            Wait::Stop => return false,
            Wait::Changed => return true,
            Wait::Timeout => {}
        }
    }
}

fn worker(core: &Core, plan: &Plan) {
    sys::lower_thread_priority();
    let hub = &core.hashing;
    loop {
        let seen = hub.epoch();
        if hub.stopped() {
            return;
        }
        let jobs = next_batch(core, plan);
        if jobs.is_empty() {
            if !idle(core, seen) {
                return;
            }
            *lock(&plan.round) = Round::default();
            continue;
        }
        for job in &jobs {
            let done = yield_fg(core) && run_job(core, job);
            lock(&plan.inflight).remove(&job.path);
            if done {
                plan.hashed.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

pub(crate) struct Hasher {
    core: Arc<Core>,
    handles: Vec<JoinHandle<()>>,
}

// background threads that fill in the hashes of pending entries at low priority
pub(crate) fn start(core: Arc<Core>, threads: usize) -> Hasher {
    core.hashing.set_stop(false);
    let plan = Arc::new(Plan::default());
    let mut handles = Vec::with_capacity(threads);
    for i in 0..threads {
        let (c, p) = (core.clone(), plan.clone());
        if let Ok(h) = thread::Builder::new()
            .name(format!("csync-hash-{i}"))
            .spawn(move || worker(&c, &p))
        {
            handles.push(h);
        }
    }
    Hasher { core, handles }
}

impl Hasher {
    pub(crate) fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.core.hashing.set_stop(true);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Guest, apply};
    use crate::ignore::rules::Rules;
    use crate::index::{
        scan,
        tree::{Observed, StatKey},
    };
    use crate::net::conn::In;
    use crate::proto::{Msg, Push};
    use crossbeam_channel::bounded;
    use std::{collections::HashMap, fs, path::PathBuf, sync::RwLock};

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    // a host core over a temp directory whose files are all pending, as a lazy scan leaves them
    fn rig(files: &[(&str, Vec<u8>)]) -> (Tmp, Arc<Core>) {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!(
            "csync-hash-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(&p).unwrap();
        let root = fs::canonicalize(&p).unwrap();
        for (name, body) in files {
            let f = root.join(name);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(&f, body).unwrap();
        }
        let mut rules = Rules::new(&[]);
        let mut tree = scan::scan(&root, &mut rules).unwrap();
        let mut found = Vec::new();
        apply::each_entry(&tree, &mut |p, e| {
            if e.meta.kind == Kind::File {
                found.push((p.clone(), e.meta.clone(), e.stat, e.domain));
            }
        });
        for (p, mut meta, stat, domain) in found {
            meta.hash = None;
            tree.observe(&p, Observed::Present { meta, stat, domain });
        }
        let (ev, _) = bounded(64);
        let core = Core::new(
            root.clone(),
            Name::new("t").unwrap(),
            tree,
            Arc::new(RwLock::new(rules)),
            ev,
        )
        .unwrap();
        (Tmp(root), Arc::new(core))
    }

    fn hash_of(core: &Core, p: &str) -> Option<Hash32> {
        core.tree().get(&rp(p)).and_then(|e| e.meta.hash)
    }

    fn job_for(core: &Core, p: &str) -> HashJob {
        let t = core.tree();
        let e = t.get(&rp(p)).unwrap();
        HashJob {
            path: rp(p),
            ver: e.seq,
            stat: e.stat,
        }
    }

    fn wait_until(what: &str, f: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(20);
        while !f() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn names(jobs: &[HashJob]) -> Vec<&str> {
        let mut v: Vec<&str> = jobs.iter().map(|j| j.path.as_str()).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn the_hasher_fills_in_every_pending_entry_without_touching_seq() {
        let big = noise((9 << 20) + 17);
        let files = [
            ("a.txt", b"alpha".to_vec()),
            ("d/b.txt", b"beta".to_vec()),
            ("d/deep/c.txt", b"gamma".to_vec()),
            ("big.bin", big.clone()),
            ("empty", Vec::new()),
        ];
        let (_t, core) = rig(&files);
        let (seq, pending) = {
            let t = core.tree();
            (t.seq(), t.pending())
        };
        assert_eq!(pending, files.len());
        let vers: Vec<Seq> = files
            .iter()
            .map(|(p, _)| core.tree().get(&rp(p)).unwrap().seq)
            .collect();

        let h = start(core.clone(), 2);
        wait_until("every hash", || core.tree().pending() == 0);
        h.stop();

        assert_eq!(core.tree().seq(), seq);
        for ((p, body), ver) in files.iter().zip(vers) {
            assert_eq!(
                hash_of(&core, p),
                Some(*blake3::hash(body).as_bytes()),
                "{p}"
            );
            assert_eq!(core.tree().get(&rp(p)).unwrap().seq, ver, "{p}");
        }
    }

    #[test]
    fn a_file_that_no_longer_matches_its_job_is_never_hashed() {
        let (t, core) = rig(&[
            ("a.txt", b"alpha".to_vec()),
            ("b.txt", b"beta".to_vec()),
            ("c.txt", b"gamma".to_vec()),
        ]);
        let (a, b, c) = (
            job_for(&core, "a.txt"),
            job_for(&core, "b.txt"),
            job_for(&core, "c.txt"),
        );

        fs::write(t.0.join("a.txt"), b"a longer replacement").unwrap();
        assert!(!run_job(&core, &a));
        assert_eq!(hash_of(&core, "a.txt"), None);
        assert!(core.hashing.take(true).is_none());

        let beta = *blake3::hash(b"beta").as_bytes();
        assert!(run_job(&core, &b));
        assert_eq!(hash_of(&core, "b.txt"), Some(beta));
        assert_eq!(
            core.hashing.take(true),
            Some(vec![(rp("b.txt"), b.ver, beta)])
        );

        // the same size and a new mtime is a new version too
        let mtime = fs::metadata(t.0.join("c.txt")).unwrap().modified().unwrap();
        let f = fs::OpenOptions::new()
            .write(true)
            .open(t.0.join("c.txt"))
            .unwrap();
        f.set_modified(mtime + Duration::from_secs(5)).unwrap();
        drop(f);
        assert!(!run_job(&core, &c));
        assert_eq!(hash_of(&core, "c.txt"), None);
        assert_eq!(core.tree().pending(), 2);
    }

    #[test]
    fn a_file_rewritten_while_it_is_hashed_leaves_the_entry_pending() {
        let (t, core) = rig(&[("a.txt", noise(3 << 20))]);
        let job = job_for(&core, "a.txt");
        let path = t.0.join("a.txt");
        crate::host::MID_HASH.with(|m| {
            *m.borrow_mut() = Some(Box::new(move || {
                fs::write(&path, noise((3 << 20) + 1)).unwrap();
            }));
        });
        assert!(!run_job(&core, &job));
        assert_eq!(hash_of(&core, "a.txt"), None);
        assert_eq!(core.tree().pending(), 1);
        assert!(core.hashing.take(true).is_none());
    }

    #[test]
    fn work_is_planned_hot_directories_first_then_rules_then_small_then_the_rest() {
        let (_t, core) = rig(&[
            (".gitignore", b"# none\n".to_vec()),
            ("Cargo.toml", b"[package]\n".to_vec()),
            ("src/lib.rs", b"fn x() {}\n".to_vec()),
            ("docs/readme.md", b"hi\n".to_vec()),
            ("hot/one.txt", b"1".to_vec()),
            ("hot/two.txt", b"2".to_vec()),
            ("big.bin", vec![1u8; (1 << 20) + 1]),
        ]);
        let plan = Plan::default();
        core.hint_dir(&rp("hot"));
        core.hint_dir(&rp("hot"));
        assert_eq!(lock(&core.hashing.state).hot.len(), 1);

        let batch = next_batch(&core, &plan);
        assert_eq!(names(&batch), vec!["hot/one.txt", "hot/two.txt"]);
        for j in &batch {
            assert!(run_job(&core, j));
            lock(&plan.inflight).remove(&j.path);
        }

        let batch = next_batch(&core, &plan);
        assert_eq!(names(&batch), vec![".gitignore", "Cargo.toml"]);
        for j in &batch {
            assert!(run_job(&core, j));
            lock(&plan.inflight).remove(&j.path);
        }

        let batch = next_batch(&core, &plan);
        assert_eq!(names(&batch), vec!["docs/readme.md", "src/lib.rs"]);
        for j in &batch {
            assert!(run_job(&core, j));
            lock(&plan.inflight).remove(&j.path);
        }

        let batch = next_batch(&core, &plan);
        assert_eq!(names(&batch), vec!["big.bin"]);
        for j in &batch {
            assert!(run_job(&core, j));
            lock(&plan.inflight).remove(&j.path);
        }
        assert!(next_batch(&core, &plan).is_empty());
        assert_eq!(core.tree().pending(), 0);
    }

    #[test]
    fn a_job_already_in_flight_is_not_handed_out_twice() {
        let (_t, core) = rig(&[("a.txt", b"a".to_vec()), ("b.txt", b"b".to_vec())]);
        let plan = Plan::default();
        let first = next_batch(&core, &plan);
        assert_eq!(first.len(), 2);
        assert!(next_batch(&core, &plan).is_empty());
        assert!(lock(&plan.round).parked);
        for j in &first {
            lock(&plan.inflight).remove(&j.path);
        }
        *lock(&plan.round) = Round::default();
        assert_eq!(next_batch(&core, &plan).len(), 2);
    }

    #[test]
    fn rule_files_and_git_metadata_are_first_tier() {
        let mut e = Entry {
            meta: crate::proto::Meta {
                kind: Kind::File,
                perm: 0o644,
                size: 1,
                mtime_ns: 0,
                ctime_ns: 0,
                hash: None,
                link: None,
                git_ro: false,
            },
            stat: StatKey::default(),
            domain: Domain::Synced,
            seq: 1,
        };
        for n in [
            "Cargo.toml",
            ".gitignore",
            "go.mod",
            "Makefile",
            "package.json",
        ] {
            assert!(tier1(&Name::new(n).unwrap(), &e), "{n}");
        }
        for n in ["HEAD", "config", "index", "packed-refs", "exclude"] {
            assert!(!tier1(&Name::new(n).unwrap(), &e), "{n} outside .git");
        }
        e.domain = Domain::GitRo;
        for n in ["HEAD", "config", "index", "packed-refs", "exclude"] {
            assert!(tier1(&Name::new(n).unwrap(), &e), "{n}");
        }
        assert!(!tier1(&Name::new("main.rs").unwrap(), &e));
    }

    #[test]
    fn hot_directories_are_a_bounded_set() {
        let (_t, core) = rig(&[("a", b"a".to_vec())]);
        for i in 0..HOT_MAX + 50 {
            core.hint_dir(&rp(&format!("d{i}")));
        }
        core.hint_dir(&rp("d0"));
        let st = lock(&core.hashing.state);
        assert_eq!(st.hot.len(), HOT_MAX);
        assert_eq!(st.hot_set.len(), HOT_MAX);
    }

    #[test]
    fn the_hasher_waits_for_foreground_work_but_never_longer_than_a_short_wait() {
        let (_t, core) = rig(&[("a", b"a".to_vec())]);
        let t0 = Instant::now();
        assert!(yield_fg(&core));
        assert!(t0.elapsed() < FG_WAIT);
        let g = core.fg_guard();
        assert_eq!(core.fg.load(Ordering::Acquire), 1);
        let t0 = Instant::now();
        assert!(yield_fg(&core));
        assert!(t0.elapsed() >= FG_WAIT);
        assert!(t0.elapsed() < Duration::from_secs(5));
        drop(g);
        assert_eq!(core.fg.load(Ordering::Acquire), 0);
        core.hashing.set_stop(true);
        let _g = core.fg_guard();
        assert!(!yield_fg(&core));
    }

    #[test]
    fn hashes_and_the_done_marker_reach_a_live_guest() {
        let (_t, core) = rig(&[("a.txt", b"alpha".to_vec()), ("d/b.txt", b"beta".to_vec())]);
        let (guest_end, host_end) = crate::net::conn::tests::test_pair();
        let g = Arc::new(Guest::new(
            1,
            host_end.link.clone(),
            Name::new("g").unwrap(),
        ));
        lock(&g.feed).live = true;
        lock(&core.hub.guests).push(g.clone());
        let mut want: HashMap<String, (Seq, Hash32)> = HashMap::new();
        for (p, body) in [("a.txt", &b"alpha"[..]), ("d/b.txt", &b"beta"[..])] {
            let ver = core.tree().get(&rp(p)).unwrap().seq;
            want.insert(p.to_owned(), (ver, *blake3::hash(body).as_bytes()));
        }
        let index = core.tree().index_id();

        let h = start(core.clone(), 2);
        let mut got: HashMap<String, (Seq, Hash32)> = HashMap::new();
        let mut done = false;
        let end = Instant::now() + Duration::from_secs(20);
        while got.len() < want.len() || !done {
            let left = end.saturating_duration_since(Instant::now());
            match guest_end.inbox.recv_timeout(left) {
                Ok(In::Msg(Msg::Push(Push::Hashes { index: i, items }))) => {
                    assert_eq!(i, index);
                    for (p, v, hash) in items {
                        got.insert(p.as_str().to_owned(), (v, hash));
                    }
                }
                Ok(In::Msg(Msg::Push(Push::HashesDone { index: i }))) => {
                    assert_eq!(i, index);
                    done = true;
                }
                Ok(_) => {}
                Err(e) => panic!("pushes did not arrive: {e:?}"),
            }
        }
        h.stop();
        assert_eq!(got, want);
    }
}
