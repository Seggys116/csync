use super::cache::{BlobCache, BlobRef};
use super::tree::GTree;
use crate::host::peek::{burst_entry, no_diff_reason, unavailable};
use crate::proto::{Change, Expect, Hash32, Kind, Meta, NoticeKind, RelPath, Seq, Version};
use crate::tui::diff::{DIFF_SIDE_MAX, DiffSource, Side, Sides};
use crate::tui::feed::{By, Entry, What};
use std::{
    sync::{Arc, RwLock, Weak},
    time::{Duration, Instant},
};

const FETCH_WAIT: Duration = Duration::from_secs(5);
const LABEL_CHANGE: &str = "this change";
const LABEL_NEW: &str = "new file";
const REFUSED_WHY: &str = "your edit was refused and rolled back; its content is not kept";
const NO_OLD: &str = "earlier version is no longer cached";
const NO_OLD_REMOVED: &str = "removed; earlier version not cached";
const NOT_HASHED: &str = "the host has not sent a hash for this version yet";
const LATEST_NOTE: &str =
    "the host had not hashed this version yet: shown against its current content";

pub(super) fn row(what: What, by: By, path: &RelPath, ts_ms: u64) -> Entry {
    Entry {
        id: 0,
        ts_ms,
        what,
        by,
        path: path.clone(),
        from: None,
        size: 0,
        old: None,
        new: None,
        ver: 0,
        merged: false,
    }
}

// a commit this guest made: old is the version it was based on, which after a merge is the host's
pub(super) fn commit_row(
    path: &RelPath,
    old: Option<Version>,
    new: Version,
    merged: bool,
    ts_ms: u64,
) -> Entry {
    let what = if old.is_none() && !merged {
        What::Added
    } else {
        What::Modified
    };
    Entry {
        size: new.size,
        old: old.map(|v| v.hash),
        new: Some(new.hash),
        merged,
        ..row(what, By::Local, path, ts_ms)
    }
}

pub(super) fn remove_row(path: &RelPath, expect: Expect, ts_ms: u64) -> Entry {
    let (what, old, size) = match expect {
        Expect::Dir => (What::DirRemoved, None, 0),
        Expect::Is(v) => (What::Removed, Some(v.hash), v.size),
        Expect::Absent | Expect::Ver(_) | Expect::Any => (What::Removed, None, 0),
    };
    Entry {
        size,
        old,
        ..row(what, By::Local, path, ts_ms)
    }
}

// a rename that moves content onto a path, or brings in a local file, is a write of that path; any other is a move
pub(super) fn rename_row(
    from: &RelPath,
    to: &RelPath,
    to_expect: Expect,
    local: bool,
    meta: &Meta,
    ts_ms: u64,
) -> Entry {
    let overwritten = match to_expect {
        Expect::Is(v) => Some(v.hash),
        _ => None,
    };
    if overwritten.is_none() && !local {
        return Entry {
            from: Some(from.clone()),
            size: meta.size,
            ..row(What::Renamed, By::Local, to, ts_ms)
        };
    }
    let what = if overwritten.is_some() {
        What::Modified
    } else {
        What::Added
    };
    Entry {
        size: meta.size,
        old: overwritten,
        new: meta.hash,
        ..row(what, By::Local, to, ts_ms)
    }
}

// the path whose state in the guest tree is read before a change lands
pub(super) fn prior_path(c: &Change) -> &RelPath {
    match c {
        Change::Upsert { path, .. } | Change::Remove { path } => path,
        Change::Rename { from, .. } => from,
    }
}

// prev is what the guest tree held at prior_path just before the change was applied
pub(super) fn remote_row(c: &Change, prev: Option<&Meta>, ts_ms: u64, seq: Seq) -> Option<Entry> {
    match c {
        Change::Upsert { path, meta, ver } => {
            let what = match (meta.kind, prev) {
                (Kind::File, Some(p)) if p.kind == Kind::File => {
                    if p.hash.is_some() && p.hash == meta.hash {
                        return None;
                    }
                    What::Modified
                }
                (Kind::File, _) => What::Added,
                (Kind::Dir, Some(p)) if p.kind == Kind::Dir => return None,
                (Kind::Dir, _) => What::DirAdded,
                (Kind::Symlink, Some(p)) if p.kind == Kind::Symlink && p.link == meta.link => {
                    return None;
                }
                (Kind::Symlink, _) => What::Link,
            };
            let old = prev
                .filter(|p| p.kind == Kind::File && what == What::Modified)
                .and_then(|p| p.hash);
            Some(Entry {
                size: meta.size,
                old,
                new: meta.hash,
                ver: *ver,
                ..row(what, By::Remote, path, ts_ms)
            })
        }
        Change::Remove { path } => {
            let p = prev?;
            let what = if p.kind == Kind::Dir {
                What::DirRemoved
            } else {
                What::Removed
            };
            Some(Entry {
                size: p.size,
                old: p.hash.filter(|_| p.kind == Kind::File),
                ver: seq,
                ..row(what, By::Remote, path, ts_ms)
            })
        }
        Change::Rename { from, to } => Some(Entry {
            from: Some(from.clone()),
            size: prev.map_or(0, |p| p.size),
            ver: seq,
            ..row(What::Renamed, By::Remote, to, ts_ms)
        }),
    }
}

// first changes were dropped without being read; prior holds the state read before each kept one was applied
pub(super) fn remote_rows(
    changes: &[Change],
    first: usize,
    prior: &[(usize, Option<Meta>)],
    ts_ms: u64,
    seq: Seq,
) -> Vec<Entry> {
    let mut rows: Vec<Entry> = prior
        .iter()
        .filter_map(|(i, p)| remote_row(changes.get(*i)?, p.as_ref(), ts_ms, seq))
        .collect();
    if first > 0 {
        let ver = rows.last().map_or(seq, |r| r.ver);
        rows.push(burst_entry(first, ts_ms, &By::Remote, ver));
    }
    rows
}

fn read_side(b: &BlobRef) -> Side {
    if !b.is_complete() {
        return Side::Gone("the cached copy is still being filled");
    }
    let cap = DIFF_SIDE_MAX as u64 + 1;
    let want = usize::try_from(b.size().min(cap)).unwrap_or(DIFF_SIDE_MAX + 1);
    let mut buf = vec![0u8; want];
    match b.read_at(&mut buf, 0) {
        Ok(n) => {
            buf.truncate(n);
            Side::Bytes(buf)
        }
        Err(_) => Side::Gone("the cached copy could not be read"),
    }
}

fn old_side(cache: &BlobCache, h: Option<Hash32>, missing: &'static str) -> Side {
    match h.and_then(|h| cache.get(&h)) {
        Some(b) => read_side(&b),
        None => Side::Gone(missing),
    }
}

// the cache first, then the host for a file small enough to show; the fetched blob stays in the session cache
fn fetch_side(cache: &BlobCache, h: &Hash32, path: &RelPath, size: u64) -> Side {
    if let Some(b) = cache.get(h) {
        return read_side(&b);
    }
    if size > DIFF_SIDE_MAX as u64 {
        return Side::Gone("not cached, and too large to fetch for a diff (over 1 MiB)");
    }
    match cache.fetch_whole(h, path, size, Instant::now() + FETCH_WAIT) {
        Ok(b) => read_side(&b),
        Err(libc::ESTALE | libc::ENOENT) => {
            Side::Gone("the host has a newer version; this one is gone")
        }
        Err(_) => Side::Gone("this version could not be fetched from the host"),
    }
}

// current is the hash and size the guest tree holds for a path now
fn sides_in(
    cache: &BlobCache,
    e: &Entry,
    current: &dyn Fn(&RelPath) -> Option<(Hash32, u64)>,
) -> Sides {
    if e.what == What::Notice(NoticeKind::Refused) {
        return unavailable(REFUSED_WHY);
    }
    if let Some(why) = no_diff_reason(e.what) {
        return unavailable(why);
    }
    let (label, old) = match e.what {
        What::Added => (LABEL_NEW, Side::Absent),
        What::Removed => (LABEL_CHANGE, old_side(cache, e.old, NO_OLD_REMOVED)),
        _ => (LABEL_CHANGE, old_side(cache, e.old, NO_OLD)),
    };
    if e.what == What::Removed {
        return Sides {
            label,
            old,
            new: Side::Absent,
            note: None,
        };
    }
    let mut target = e.new.map(|h| (h, e.size));
    let mut note = None;
    if target.is_none() {
        target = current(&e.path);
        note = target.map(|_| LATEST_NOTE);
    }
    let new = match target {
        Some((h, size)) => fetch_side(cache, &h, &e.path, size),
        None => Side::Gone(NOT_HASHED),
    };
    Sides {
        label,
        old,
        new,
        note,
    }
}

// the guest keeps blobs, not history: both sides come from the session cache or, for the new one, from the host
pub(super) struct GuestPeek {
    cache: Weak<BlobCache>,
    tree: Weak<RwLock<GTree>>,
}

impl GuestPeek {
    pub(super) fn new(cache: &Arc<BlobCache>, tree: &Arc<RwLock<GTree>>) -> Self {
        Self {
            cache: Arc::downgrade(cache),
            tree: Arc::downgrade(tree),
        }
    }

    fn current(&self, path: &RelPath) -> Option<(Hash32, u64)> {
        let tree = self.tree.upgrade()?;
        let t = tree.read().unwrap_or_else(|e| e.into_inner());
        let n = t.get(t.resolve(path)?)?;
        if n.meta.kind != Kind::File {
            return None;
        }
        n.meta.hash.map(|h| (h, n.meta.size))
    }
}

impl DiffSource for GuestPeek {
    fn sides(&self, e: &Entry) -> Sides {
        let Some(cache) = self.cache.upgrade() else {
            return unavailable("the session has ended");
        };
        sides_in(&cache, e, &|p| self.current(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::cache::{CacheConfig, Done, Remote, RemoteSlot};
    use crate::net::rpc::{ChunkSink, RpcError};
    use crate::proto::{ReqId, WireErr};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // every request is answered as a version the host no longer has
    struct GoneRemote;

    impl Remote for GoneRemote {
        fn call(&self, _: crate::proto::Op, _: Instant) -> Result<crate::proto::Reply, RpcError> {
            Err(RpcError::Wire(WireErr::Gone))
        }
        fn call_stream(
            &self,
            _: crate::proto::Op,
            _: Box<dyn ChunkSink>,
            _: Instant,
        ) -> Result<crate::proto::Reply, RpcError> {
            Err(RpcError::Wire(WireErr::Gone))
        }
        fn submit(&self, _: crate::proto::Op, _: Done) -> Result<ReqId, RpcError> {
            Err(RpcError::Wire(WireErr::Gone))
        }
        fn submit_stream(
            &self,
            _: crate::proto::Op,
            _: Box<dyn ChunkSink>,
            _: Done,
        ) -> Result<ReqId, RpcError> {
            Err(RpcError::Wire(WireErr::Gone))
        }
        fn send_chunk(&self, _: ReqId, _: u64, _: bool, _: Vec<u8>) -> Result<(), RpcError> {
            Ok(())
        }
        fn cancel(&self, _: ReqId) {}
    }

    fn cache(tag: &str) -> (Dir, Arc<BlobCache>) {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "csync-gpeek-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        let slot = RemoteSlot::new();
        slot.set(Some(Arc::new(GoneRemote) as Arc<dyn Remote>));
        let c = BlobCache::open(
            &CacheConfig {
                dir: p.clone(),
                cap: Some(1 << 30),
            },
            slot,
        )
        .unwrap();
        (Dir(p), Arc::new(c))
    }

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    fn hash(b: &[u8]) -> Hash32 {
        *blake3::hash(b).as_bytes()
    }

    fn put(c: &BlobCache, b: &[u8]) -> Hash32 {
        let h = hash(b);
        c.insert_bytes(&h, b, Some(&rp("f"))).unwrap();
        h
    }

    fn ent(what: What, old: Option<Hash32>, new: Option<Hash32>, size: u64) -> Entry {
        Entry {
            old,
            new,
            size,
            ..row(what, By::Remote, &rp("f"), 0)
        }
    }

    fn no_tree(_: &RelPath) -> Option<(Hash32, u64)> {
        None
    }

    fn bytes(s: &str) -> Side {
        Side::Bytes(s.as_bytes().to_vec())
    }

    fn file_meta(hash: Option<Hash32>, size: u64) -> Meta {
        Meta {
            kind: Kind::File,
            perm: 0o644,
            size,
            mtime_ns: 0,
            ctime_ns: 0,
            hash,
            link: None,
            git_ro: false,
        }
    }

    fn kind_meta(kind: Kind) -> Meta {
        Meta {
            kind,
            ..file_meta(None, 0)
        }
    }

    fn upsert(path: &str, meta: Meta) -> Change {
        Change::Upsert {
            path: rp(path),
            meta,
            ver: 7,
        }
    }

    #[test]
    fn cached_old_and_new_blobs_are_both_read() {
        let (_d, c) = cache("both");
        let (old, new) = (put(&c, b"one\n"), put(&c, b"two\n"));
        let s = sides_in(&c, &ent(What::Modified, Some(old), Some(new), 4), &no_tree);
        assert_eq!(s.label, "this change");
        assert_eq!(s.old, bytes("one\n"));
        assert_eq!(s.new, bytes("two\n"));
        assert_eq!(s.note, None);
    }

    #[test]
    fn an_evicted_old_blob_is_gone_with_its_reason() {
        let (_d, c) = cache("evicted");
        let new = put(&c, b"two\n");
        let old = hash(b"one\n");
        let s = sides_in(&c, &ent(What::Modified, Some(old), Some(new), 4), &no_tree);
        assert_eq!(s.old, Side::Gone("earlier version is no longer cached"));
        assert_eq!(s.new, bytes("two\n"));
        let s = sides_in(&c, &ent(What::Modified, None, Some(new), 4), &no_tree);
        assert_eq!(s.old, Side::Gone("earlier version is no longer cached"));
    }

    #[test]
    fn an_added_file_has_no_old_side() {
        let (_d, c) = cache("added");
        let new = put(&c, b"fresh\n");
        let s = sides_in(&c, &ent(What::Added, None, Some(new), 6), &no_tree);
        assert_eq!(s.label, "new file");
        assert_eq!(s.old, Side::Absent);
        assert_eq!(s.new, bytes("fresh\n"));
    }

    #[test]
    fn a_removed_file_shows_its_cached_content_against_nothing() {
        let (_d, c) = cache("removed");
        let old = put(&c, b"bye\n");
        let s = sides_in(&c, &ent(What::Removed, Some(old), None, 4), &no_tree);
        assert_eq!(s.old, bytes("bye\n"));
        assert_eq!(s.new, Side::Absent);
        let s = sides_in(
            &c,
            &ent(What::Removed, Some(hash(b"never cached")), None, 4),
            &no_tree,
        );
        assert_eq!(s.old, Side::Gone("removed; earlier version not cached"));
        assert_eq!(s.new, Side::Absent);
    }

    #[test]
    fn a_new_version_the_host_no_longer_has_is_gone() {
        let (_d, c) = cache("gone");
        let old = put(&c, b"one\n");
        let missing = hash(b"two\n");
        let s = sides_in(
            &c,
            &ent(What::Modified, Some(old), Some(missing), 4),
            &no_tree,
        );
        assert_eq!(s.old, bytes("one\n"));
        assert_eq!(
            s.new,
            Side::Gone("the host has a newer version; this one is gone")
        );
    }

    #[test]
    fn an_uncached_version_over_the_cap_is_not_fetched() {
        let (_d, c) = cache("toolarge");
        let missing = hash(b"big");
        let size = DIFF_SIDE_MAX as u64 + 1;
        let s = sides_in(&c, &ent(What::Added, None, Some(missing), size), &no_tree);
        assert!(matches!(s.new, Side::Gone(_)), "{:?}", s.new);
    }

    #[test]
    fn a_cached_blob_over_the_cap_is_read_one_byte_past_it() {
        let (_d, c) = cache("bigblob");
        let big = vec![b'a'; DIFF_SIDE_MAX + 10];
        let h = put(&c, &big);
        let s = sides_in(
            &c,
            &ent(What::Added, None, Some(h), big.len() as u64),
            &no_tree,
        );
        match s.new {
            Side::Bytes(b) => assert_eq!(b.len(), DIFF_SIDE_MAX + 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_version_without_a_hash_uses_the_trees_current_content() {
        let (_d, c) = cache("latest");
        let old = put(&c, b"one\n");
        let cur = put(&c, b"three\n");
        let e = ent(What::Modified, Some(old), None, 0);
        let s = sides_in(&c, &e, &|p| (p.as_str() == "f").then_some((cur, 6)));
        assert_eq!(s.new, bytes("three\n"));
        assert_eq!(s.note, Some(LATEST_NOTE));
        let s = sides_in(&c, &e, &no_tree);
        assert_eq!(s.new, Side::Gone(NOT_HASHED));
        assert_eq!(s.note, None);
    }

    #[test]
    fn the_peek_reads_the_current_hash_from_the_guest_tree() {
        let (_d, c) = cache("tree");
        let cur = put(&c, b"three\n");
        let tree = Arc::new(RwLock::new(GTree::new()));
        let mut fx = Vec::new();
        tree.write()
            .unwrap()
            .apply(&upsert("f", file_meta(Some(cur), 6)), &mut fx);
        let peek = GuestPeek::new(&c, &tree);
        assert_eq!(peek.current(&rp("f")), Some((cur, 6)));
        assert_eq!(peek.current(&rp("missing")), None);
        let s = peek.sides(&ent(What::Modified, None, None, 0));
        assert_eq!(s.new, bytes("three\n"));
    }

    #[test]
    fn a_refused_notice_says_why_nothing_is_kept() {
        let (_d, c) = cache("refused");
        let s = sides_in(
            &c,
            &ent(What::Notice(NoticeKind::Refused), None, None, 0),
            &no_tree,
        );
        assert_eq!(s.old, Side::Gone(REFUSED_WHY));
        assert_eq!(s.new, Side::Gone(REFUSED_WHY));
        for what in [
            What::Renamed,
            What::DirAdded,
            What::DirRemoved,
            What::Link,
            What::Burst(2),
            What::Notice(NoticeKind::Merged),
        ] {
            let s = sides_in(&c, &ent(what, None, None, 0), &no_tree);
            assert!(matches!(s.old, Side::Gone(_)), "{what:?}");
        }
    }

    #[test]
    fn a_dropped_session_leaves_nothing_to_show() {
        let (_d, c) = cache("dropped");
        let tree = Arc::new(RwLock::new(GTree::new()));
        let peek = GuestPeek::new(&c, &tree);
        drop(c);
        let s = peek.sides(&ent(What::Modified, None, None, 0));
        assert_eq!(s.old, Side::Gone("the session has ended"));
    }

    #[test]
    fn an_upsert_over_a_known_file_is_modified_with_both_hashes() {
        let (a, b) = ([1; 32], [2; 32]);
        let prev = file_meta(Some(a), 3);
        let e = remote_row(&upsert("x", file_meta(Some(b), 5)), Some(&prev), 9, 40).unwrap();
        assert_eq!((e.what, e.by), (What::Modified, By::Remote));
        assert_eq!(
            (e.old, e.new, e.size, e.ver, e.ts_ms),
            (Some(a), Some(b), 5, 7, 9)
        );
        assert_eq!(e.path.as_str(), "x");
    }

    #[test]
    fn an_upsert_of_an_unknown_path_is_added_and_a_same_content_upsert_is_skipped() {
        let h = [1; 32];
        let e = remote_row(&upsert("x", file_meta(Some(h), 3)), None, 0, 1).unwrap();
        assert_eq!((e.what, e.old, e.new), (What::Added, None, Some(h)));
        let prev = file_meta(Some(h), 3);
        assert!(remote_row(&upsert("x", file_meta(Some(h), 3)), Some(&prev), 0, 1).is_none());
        let pending = file_meta(None, 3);
        let e = remote_row(&upsert("x", file_meta(None, 4)), Some(&pending), 0, 1).unwrap();
        assert_eq!(e.what, What::Modified);
    }

    #[test]
    fn directories_and_links_only_show_when_new() {
        let dir = kind_meta(Kind::Dir);
        let e = remote_row(&upsert("d", dir.clone()), None, 0, 1).unwrap();
        assert_eq!(e.what, What::DirAdded);
        assert!(remote_row(&upsert("d", dir.clone()), Some(&dir), 0, 1).is_none());
        let link = kind_meta(Kind::Symlink);
        let e = remote_row(&upsert("l", link.clone()), None, 0, 1).unwrap();
        assert_eq!(e.what, What::Link);
        assert!(remote_row(&upsert("l", link.clone()), Some(&link), 0, 1).is_none());
    }

    #[test]
    fn removes_and_renames_map_with_what_the_tree_held() {
        let h = [3; 32];
        let prev = file_meta(Some(h), 8);
        let rm = Change::Remove { path: rp("x") };
        let e = remote_row(&rm, Some(&prev), 0, 12).unwrap();
        assert_eq!(
            (e.what, e.old, e.size, e.ver),
            (What::Removed, Some(h), 8, 12)
        );
        assert!(remote_row(&rm, None, 0, 12).is_none());
        let dir = kind_meta(Kind::Dir);
        assert_eq!(
            remote_row(&rm, Some(&dir), 0, 12).map(|e| e.what),
            Some(What::DirRemoved)
        );
        let mv = Change::Rename {
            from: rp("a"),
            to: rp("b"),
        };
        let e = remote_row(&mv, Some(&prev), 0, 12).unwrap();
        assert_eq!((e.what, e.size), (What::Renamed, 8));
        assert_eq!(e.path.as_str(), "b");
        assert_eq!(e.from, Some(rp("a")));
        assert_eq!(prior_path(&mv), &rp("a"));
        assert_eq!(prior_path(&rm), &rp("x"));
    }

    #[test]
    fn dropped_changes_become_one_burst_row_after_the_kept_ones() {
        let changes: Vec<Change> = (0..5)
            .map(|i| upsert(&format!("f{i}"), file_meta(Some([i; 32]), 1)))
            .collect();
        let prior = vec![(3, None), (4, None)];
        let rows = remote_rows(&changes, 3, &prior, 5, 9);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].path.as_str(), "f3");
        assert_eq!(rows[1].path.as_str(), "f4");
        assert_eq!(rows[2].what, What::Burst(3));
        assert_eq!(rows[2].by, By::Remote);
        let rows = remote_rows(&changes, 0, &[(0, None)], 5, 9);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn a_commit_row_carries_the_base_the_new_version_and_the_merge_flag() {
        let (a, b) = (
            Version {
                hash: [1; 32],
                size: 2,
            },
            Version {
                hash: [2; 32],
                size: 4,
            },
        );
        let e = commit_row(&rp("p"), Some(a), b, false, 3);
        assert_eq!((e.what, e.by.clone()), (What::Modified, By::Local));
        assert_eq!(
            (e.old, e.new, e.size, e.merged),
            (Some(a.hash), Some(b.hash), 4, false)
        );
        let e = commit_row(&rp("p"), None, b, false, 3);
        assert_eq!((e.what, e.old), (What::Added, None));
        let e = commit_row(&rp("p"), Some(a), b, true, 3);
        assert!(e.merged && e.what == What::Modified);
        let e = commit_row(&rp("p"), None, b, true, 3);
        assert_eq!(e.what, What::Modified);
    }

    #[test]
    fn remove_and_rename_rows_follow_what_the_expectations_say() {
        let v = Version {
            hash: [5; 32],
            size: 9,
        };
        let e = remove_row(&rp("p"), Expect::Is(v), 1);
        assert_eq!((e.what, e.old, e.size), (What::Removed, Some(v.hash), 9));
        assert_eq!(remove_row(&rp("p"), Expect::Dir, 1).what, What::DirRemoved);
        assert_eq!(remove_row(&rp("p"), Expect::Any, 1).old, None);

        let meta = file_meta(Some([6; 32]), 4);
        let e = rename_row(&rp("a"), &rp("b"), Expect::Absent, false, &meta, 1);
        assert_eq!((e.what, e.from.clone()), (What::Renamed, Some(rp("a"))));
        assert_eq!((e.old, e.new), (None, None));
        let e = rename_row(&rp("a"), &rp("b"), Expect::Is(v), false, &meta, 1);
        assert_eq!(
            (e.what, e.old, e.new),
            (What::Modified, Some(v.hash), Some([6; 32]))
        );
        assert_eq!(e.from, None);
        let e = rename_row(&rp("a"), &rp("b"), Expect::Absent, true, &meta, 1);
        assert_eq!((e.what, e.old, e.new), (What::Added, None, Some([6; 32])));
        assert_eq!(e.path.as_str(), "b");
    }
}
