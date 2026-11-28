use super::diff::DiffSource;
use crate::proto::{Hash32, Name, NoticeKind, RelPath, Seq};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

pub const FEED_MAX: usize = 256;
pub const FEED_PATH_BYTES: usize = 64 * 1024;
pub const COALESCE_MS: u64 = 2_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum What {
    Added,
    Modified,
    Removed,
    Renamed,
    DirAdded,
    DirRemoved,
    Link,
    // a batch too large to keep: the number of rows dropped
    Burst(u32),
    Notice(NoticeKind),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum By {
    // host side: the watcher or the applier
    Host,
    // host side: a guest's commit
    Guest { id: u64, name: Name },
    // guest side: a change that came from the host
    Remote,
    // guest side: this guest's own write
    Local,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    // assigned by the feed on push, never reused
    pub id: u64,
    pub ts_ms: u64,
    pub what: What,
    pub by: By,
    pub path: RelPath,
    // rename source
    pub from: Option<RelPath>,
    pub size: u64,
    // guest side only
    pub old: Option<Hash32>,
    pub new: Option<Hash32>,
    // host index seq at publish, 0 when unknown
    pub ver: Seq,
    pub merged: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn cost(e: &Entry) -> usize {
    e.path.as_str().len() + e.from.as_ref().map_or(0, |p| p.as_str().len())
}

#[derive(Debug, Default)]
pub struct Feed {
    ring: VecDeque<Entry>,
    path_bytes: usize,
    next_id: u64,
    version: u64,
}

impl Feed {
    pub fn push_batch(&mut self, entries: impl IntoIterator<Item = Entry>) {
        let mut batch: Vec<Entry> = entries.into_iter().collect();
        if batch.len() > FEED_MAX {
            let dropped = batch.len() - (FEED_MAX - 1);
            batch.drain(..dropped);
            if let Some(last) = batch.last() {
                let burst = Entry {
                    id: 0,
                    ts_ms: last.ts_ms,
                    what: What::Burst(u32::try_from(dropped).unwrap_or(u32::MAX)),
                    by: last.by.clone(),
                    path: RelPath::root(),
                    from: None,
                    size: 0,
                    old: None,
                    new: None,
                    ver: last.ver,
                    merged: false,
                };
                batch.push(burst);
            }
        }
        for e in batch {
            self.push_one(e);
        }
    }

    fn push_one(&mut self, mut e: Entry) {
        if e.what == What::Modified
            && let Some(last) = self.ring.back_mut()
            && last.what == What::Modified
            && last.path == e.path
            && last.by == e.by
            && last.ts_ms.abs_diff(e.ts_ms) <= COALESCE_MS
        {
            last.new = e.new;
            last.size = e.size;
            last.ts_ms = e.ts_ms;
            last.ver = e.ver;
            last.merged |= e.merged;
            self.version += 1;
            return;
        }
        self.next_id += 1;
        e.id = self.next_id;
        self.path_bytes += cost(&e);
        self.ring.push_back(e);
        while self.ring.len() > 1
            && (self.ring.len() > FEED_MAX || self.path_bytes > FEED_PATH_BYTES)
        {
            if let Some(old) = self.ring.pop_front() {
                self.path_bytes = self.path_bytes.saturating_sub(cost(&old));
            }
        }
        self.version += 1;
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    // ids ascend from the front, so the position is a binary search
    fn position(&self, id: u64) -> Option<usize> {
        self.ring.binary_search_by_key(&id, |e| e.id).ok()
    }

    pub fn get(&self, id: u64) -> Option<Entry> {
        self.position(id).and_then(|i| self.ring.get(i)).cloned()
    }

    // newest first; start = anchor index from newest minus rows - 1 (deep anchor is the last row); evicted anchor shows the oldest rows
    pub fn window(&self, anchor: Option<u64>, rows: usize) -> Vec<Entry> {
        if rows == 0 {
            return Vec::new();
        }
        let n = self.ring.len();
        let start = match anchor {
            None => 0,
            Some(id) => match self.position(id) {
                Some(pos) => (n - 1 - pos).saturating_sub(rows - 1),
                None if self.ring.front().is_some_and(|f| id < f.id) => n.saturating_sub(rows),
                None => 0,
            },
        };
        (start..n.min(start.saturating_add(rows)))
            .filter_map(|i| self.ring.get(n - 1 - i))
            .cloned()
            .collect()
    }
}

#[derive(Default)]
pub struct FeedSlot {
    on: AtomicBool,
    inner: Mutex<Feed>,
    source: Mutex<Option<Arc<dyn DiffSource>>>,
}

impl FeedSlot {
    pub fn enable(&self) {
        self.on.store(true, Ordering::Release);
    }

    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::Acquire)
    }

    pub fn push_batch(&self, entries: impl IntoIterator<Item = Entry>) {
        if !self.is_on() {
            return;
        }
        lock(&self.inner).push_batch(entries);
    }

    pub fn version(&self) -> u64 {
        lock(&self.inner).version()
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }

    pub fn is_empty(&self) -> bool {
        lock(&self.inner).is_empty()
    }

    pub fn window(&self, anchor: Option<u64>, rows: usize) -> Vec<Entry> {
        lock(&self.inner).window(anchor, rows)
    }

    pub fn get(&self, id: u64) -> Option<Entry> {
        lock(&self.inner).get(id)
    }

    pub fn set_source(&self, s: Arc<dyn DiffSource>) {
        *lock(&self.source) = Some(s);
    }

    pub fn source(&self) -> Option<Arc<dyn DiffSource>> {
        lock(&self.source).clone()
    }
}

// whether a diff could be offered for this row, without computing it
pub fn offer(e: &Entry, git: bool) -> bool {
    match e.what {
        What::Added | What::Modified | What::Removed => match e.by {
            By::Remote | By::Local => e.old.is_some() || e.new.is_some(),
            By::Host | By::Guest { .. } => git,
        },
        What::Renamed
        | What::DirAdded
        | What::DirRemoved
        | What::Link
        | What::Burst(_)
        | What::Notice(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::diff::{Side, Sides};
    use super::*;

    fn path(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    fn ent(p: &str, what: What, ts_ms: u64) -> Entry {
        Entry {
            id: 0,
            ts_ms,
            what,
            by: By::Host,
            path: path(p),
            from: None,
            size: 1,
            old: None,
            new: None,
            ver: 0,
            merged: false,
        }
    }

    fn ids(v: &[Entry]) -> Vec<u64> {
        v.iter().map(|e| e.id).collect()
    }

    #[test]
    fn ids_and_version_are_monotonic() {
        let mut f = Feed::default();
        assert_eq!(f.version(), 0);
        let mut last_version = 0;
        for i in 0..5 {
            f.push_batch([ent(&format!("f{i}"), What::Added, i)]);
            assert!(f.version() > last_version);
            last_version = f.version();
        }
        let w = f.window(None, 10);
        assert_eq!(ids(&w), vec![5, 4, 3, 2, 1]);
    }

    #[test]
    fn count_cap_evicts_oldest_first() {
        let mut f = Feed::default();
        let total = FEED_MAX + 10;
        for i in 0..total {
            f.push_batch([ent(&format!("f{i}"), What::Added, i as u64)]);
        }
        assert_eq!(f.len(), FEED_MAX);
        let w = f.window(None, FEED_MAX);
        assert_eq!(w.first().map(|e| e.id), Some(total as u64));
        assert_eq!(w.last().map(|e| e.id), Some(11));
        assert!(f.get(10).is_none());
        assert!(f.get(11).is_some());
    }

    #[test]
    fn path_byte_cap_evicts_oldest_first() {
        let mut f = Feed::default();
        let long = vec!["a".repeat(255); 15].join("/");
        assert_eq!(long.len(), 3839);
        for i in 0..20 {
            f.push_batch([ent(&long, What::Added, i)]);
        }
        assert!(f.path_bytes <= FEED_PATH_BYTES);
        assert_eq!(f.len(), 17);
        let w = f.window(None, 100);
        assert_eq!(w.first().map(|e| e.id), Some(20));
        assert_eq!(w.last().map(|e| e.id), Some(4));
    }

    #[test]
    fn path_bytes_count_the_rename_source() {
        let mut f = Feed::default();
        let mut e = ent("new", What::Renamed, 0);
        e.from = Some(path("older"));
        f.push_batch([e]);
        assert_eq!(f.path_bytes, 3 + 5);
    }

    #[test]
    fn newest_entry_is_never_evicted() {
        let mut f = Feed::default();
        let long = vec!["a".repeat(255); 15].join("/");
        let mut e = ent(&long, What::Renamed, 0);
        e.from = Some(path(&long));
        for _ in 0..30 {
            f.push_batch([e.clone()]);
        }
        assert!(!f.is_empty());
        assert_eq!(f.window(None, 1).first().map(|e| e.id), Some(30));
    }

    #[test]
    fn coalescing_keeps_id_and_original_old() {
        let mut f = Feed::default();
        let mut a = ent("x", What::Modified, 1_000);
        a.old = Some([1; 32]);
        a.new = Some([2; 32]);
        let mut b = ent("x", What::Modified, 2_500);
        b.old = Some([2; 32]);
        b.new = Some([3; 32]);
        b.size = 99;
        b.ver = 7;
        b.merged = true;
        f.push_batch([a, b]);
        assert_eq!(f.len(), 1);
        let e = f.window(None, 1).remove(0);
        assert_eq!(e.id, 1);
        assert_eq!(e.old, Some([1; 32]));
        assert_eq!(e.new, Some([3; 32]));
        assert_eq!(e.size, 99);
        assert_eq!(e.ts_ms, 2_500);
        assert_eq!(e.ver, 7);
        assert!(e.merged);
    }

    #[test]
    fn coalescing_ignores_other_paths_authors_kinds_and_gaps() {
        let mut f = Feed::default();
        f.push_batch([ent("x", What::Modified, 0)]);
        f.push_batch([ent("y", What::Modified, 1)]);
        let mut other_by = ent("y", What::Modified, 2);
        other_by.by = By::Local;
        f.push_batch([other_by]);
        f.push_batch([ent("y", What::Added, 3)]);
        f.push_batch([ent("y", What::Modified, 3 + COALESCE_MS + 1)]);
        assert_eq!(f.len(), 5);
    }

    #[test]
    fn coalescing_bumps_version_without_a_new_id() {
        let mut f = Feed::default();
        f.push_batch([ent("x", What::Modified, 0)]);
        let v = f.version();
        f.push_batch([ent("x", What::Modified, 10)]);
        assert!(f.version() > v);
        f.push_batch([ent("z", What::Added, 20)]);
        assert_eq!(f.window(None, 1)[0].id, 2);
    }

    #[test]
    fn oversized_batch_keeps_the_tail_and_a_burst_row() {
        let mut f = Feed::default();
        let n = FEED_MAX + 50;
        let batch: Vec<Entry> = (0..n)
            .map(|i| ent(&format!("f{i}"), What::Added, i as u64))
            .collect();
        f.push_batch(batch);
        assert_eq!(f.len(), FEED_MAX);
        let w = f.window(None, FEED_MAX);
        let burst = &w[0];
        assert_eq!(burst.what, What::Burst(51));
        assert!(burst.path.is_root());
        assert_eq!(w[1].path, path(&format!("f{}", n - 1)));
        assert_eq!(w.last().map(|e| e.path.clone()), Some(path("f51")));
    }

    #[test]
    fn batch_of_exactly_the_cap_has_no_burst() {
        let mut f = Feed::default();
        let batch: Vec<Entry> = (0..FEED_MAX)
            .map(|i| ent(&format!("f{i}"), What::Added, i as u64))
            .collect();
        f.push_batch(batch);
        assert_eq!(f.len(), FEED_MAX);
        assert!(
            f.window(None, FEED_MAX)
                .iter()
                .all(|e| !matches!(e.what, What::Burst(_)))
        );
    }

    #[test]
    fn empty_batch_changes_nothing() {
        let mut f = Feed::default();
        f.push_batch(Vec::new());
        assert_eq!(f.version(), 0);
        assert_eq!(f.len(), 0);
    }

    fn filled(n: usize) -> Feed {
        let mut f = Feed::default();
        for i in 0..n {
            f.push_batch([ent(&format!("f{i}"), What::Added, i as u64)]);
        }
        f
    }

    #[test]
    fn window_follow_returns_the_newest_rows() {
        let f = filled(10);
        assert_eq!(ids(&f.window(None, 3)), vec![10, 9, 8]);
        assert_eq!(ids(&f.window(None, 100)).len(), 10);
        assert!(f.window(None, 0).is_empty());
    }

    #[test]
    fn window_around_an_anchor() {
        let f = filled(10);
        assert_eq!(ids(&f.window(Some(9), 3)), vec![10, 9, 8]);
        assert_eq!(ids(&f.window(Some(8), 3)), vec![10, 9, 8]);
        assert_eq!(ids(&f.window(Some(5), 3)), vec![7, 6, 5]);
        assert_eq!(ids(&f.window(Some(1), 3)), vec![3, 2, 1]);
        assert_eq!(ids(&f.window(Some(1), 100)).len(), 10);
        assert!(f.window(Some(5), 0).is_empty());
    }

    #[test]
    fn window_with_an_evicted_anchor_shows_the_oldest_rows() {
        let f = filled(FEED_MAX + 5);
        assert!(f.get(2).is_none());
        let w = f.window(Some(2), 3);
        assert_eq!(ids(&w), vec![8, 7, 6]);
    }

    #[test]
    fn window_with_an_unknown_newer_anchor_follows() {
        let f = filled(10);
        assert_eq!(ids(&f.window(Some(999), 3)), vec![10, 9, 8]);
    }

    #[test]
    fn get_finds_by_id() {
        let f = filled(4);
        assert_eq!(f.get(3).map(|e| e.path), Some(path("f2")));
        assert!(f.get(0).is_none());
        assert!(f.get(5).is_none());
    }

    #[test]
    fn slot_is_off_until_enabled() {
        let slot = FeedSlot::default();
        assert!(!slot.is_on());
        let touched = std::cell::Cell::new(false);
        slot.push_batch(std::iter::from_fn(|| {
            touched.set(true);
            None::<Entry>
        }));
        assert!(!touched.get());
        slot.push_batch([ent("a", What::Added, 0)]);
        assert_eq!(slot.version(), 0);
        assert_eq!(slot.len(), 0);
        assert!(slot.window(None, 5).is_empty());

        slot.enable();
        assert!(slot.is_on());
        slot.push_batch([ent("a", What::Added, 0)]);
        assert_eq!(slot.len(), 1);
        assert!(slot.version() > 0);
        assert_eq!(slot.get(1).map(|e| e.path), Some(path("a")));
    }

    struct Fixed;
    impl DiffSource for Fixed {
        fn sides(&self, _: &Entry) -> Sides {
            Sides {
                label: "test",
                old: Side::Absent,
                new: Side::Absent,
                note: None,
            }
        }
    }

    #[test]
    fn slot_source_round_trips() {
        let slot = FeedSlot::default();
        assert!(slot.source().is_none());
        slot.set_source(Arc::new(Fixed));
        let s = slot.source().expect("source set");
        assert_eq!(s.sides(&ent("a", What::Added, 0)).label, "test");
    }

    #[test]
    fn offer_truth_table() {
        let hash = Some([9; 32]);
        let kinds = [What::Added, What::Modified, What::Removed];
        for what in kinds {
            for by in [By::Remote, By::Local] {
                let mut e = ent("a", what, 0);
                e.by = by;
                assert!(!offer(&e, true));
                assert!(!offer(&e, false));
                e.old = hash;
                assert!(offer(&e, false));
                e.old = None;
                e.new = hash;
                assert!(offer(&e, false));
            }
            for by in [
                By::Host,
                By::Guest {
                    id: 1,
                    name: Name::new("g").unwrap(),
                },
            ] {
                let mut e = ent("a", what, 0);
                e.by = by;
                assert!(offer(&e, true));
                assert!(!offer(&e, false));
            }
        }
        let others = [
            What::Renamed,
            What::DirAdded,
            What::DirRemoved,
            What::Link,
            What::Burst(3),
            What::Notice(NoticeKind::Refused),
        ];
        for what in others {
            let mut e = ent("a", what, 0);
            e.by = By::Local;
            e.old = hash;
            e.new = hash;
            assert!(!offer(&e, true));
            assert!(!offer(&e, false));
        }
    }
}
