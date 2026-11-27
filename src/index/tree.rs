use crate::proto::{
    Change, DEPTH_MAX, Hash32, IndexId, Kind, Meta, Name, PATH_MAX, RelPath, Seq, SnapEntry,
};
use rustc_hash::{FxHashMap, FxHasher};
use std::{collections::VecDeque, hash::Hasher};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StatKey {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub mode: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Domain {
    Synced,
    GitRo,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub meta: Meta,
    pub stat: StatKey,
    pub domain: Domain,
    pub seq: Seq,
}

impl Entry {
    // a file whose content hash has not been computed yet
    pub fn is_pending(&self) -> bool {
        self.meta.kind == Kind::File && self.meta.hash.is_none()
    }
}

// one pending file to hash: the entry version and stat key it was read at
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashJob {
    pub path: RelPath,
    pub ver: Seq,
    pub stat: StatKey,
}

// nodes looked at per pending_from call, so a caller holding the tree lock lets go regularly
pub(crate) const SCAN_NODES: usize = 4_096;

pub enum Observed {
    Present {
        meta: Meta,
        stat: StatKey,
        domain: Domain,
    },
    Absent,
}

pub const JOURNAL_MAX: usize = 262_144;

pub(crate) const ROOT: u32 = 0;
const NIL: u32 = u32::MAX;

fn fx(s: &str) -> u64 {
    let mut h = FxHasher::default();
    h.write(s.as_bytes());
    h.finish()
}

struct NameSlot {
    name: Option<Name>,
    hash: u64,
    refs: u32,
    next: u32,
}

// interned names: one allocation per distinct name, chained on full 64-bit hash collisions
#[derive(Default)]
struct Names {
    slots: Vec<NameSlot>,
    free: Vec<u32>,
    heads: FxHashMap<u64, u32>,
}

impl Names {
    fn find(&self, s: &str) -> Option<u32> {
        let mut i = *self.heads.get(&fx(s))?;
        while i != NIL {
            let slot = self.slots.get(i as usize)?;
            if slot.name.as_ref().is_some_and(|n| n.as_str() == s) {
                return Some(i);
            }
            i = slot.next;
        }
        None
    }

    fn get(&self, id: u32) -> Option<&Name> {
        self.slots.get(id as usize)?.name.as_ref()
    }

    fn intern(&mut self, s: &str) -> Option<u32> {
        if let Some(id) = self.find(s) {
            if let Some(slot) = self.slots.get_mut(id as usize) {
                slot.refs += 1;
            }
            return Some(id);
        }
        let name = Name::new(s).ok()?;
        let hash = fx(s);
        let next = self.heads.get(&hash).copied().unwrap_or(NIL);
        let slot = NameSlot {
            name: Some(name),
            hash,
            refs: 1,
            next,
        };
        let id = match self.free.pop() {
            Some(id) => {
                self.slots[id as usize] = slot;
                id
            }
            None => {
                if self.slots.len() >= NIL as usize {
                    return None;
                }
                self.slots.push(slot);
                (self.slots.len() - 1) as u32
            }
        };
        self.heads.insert(hash, id);
        Some(id)
    }

    fn release(&mut self, id: u32) {
        let Some(slot) = self.slots.get_mut(id as usize) else {
            return;
        };
        slot.refs = slot.refs.saturating_sub(1);
        if slot.refs > 0 || slot.name.is_none() {
            return;
        }
        slot.name = None;
        let (hash, next) = (slot.hash, slot.next);
        match self.heads.get(&hash).copied() {
            Some(head) if head == id => {
                if next == NIL {
                    self.heads.remove(&hash);
                } else {
                    self.heads.insert(hash, next);
                }
            }
            Some(mut i) => {
                while i != NIL {
                    let n = self.slots[i as usize].next;
                    if n == id {
                        self.slots[i as usize].next = next;
                        break;
                    }
                    i = n;
                }
            }
            None => {}
        }
        self.free.push(id);
    }
}

struct Node {
    parent: u32,
    name: u32,
    first: u32,
    next: u32,
    prev: u32,
    depth: u8,
    plen: u16,
    entry: Option<Entry>,
}

impl Node {
    fn vacant() -> Self {
        Self {
            parent: NIL,
            name: NIL,
            first: NIL,
            next: NIL,
            prev: NIL,
            depth: 0,
            plen: 0,
            entry: None,
        }
    }
    fn is_dir(&self) -> bool {
        matches!(&self.entry, Some(e) if e.meta.kind == Kind::Dir)
    }
}

pub struct Tree {
    index: IndexId,
    seq: Seq,
    nodes: Vec<Node>,
    free: Vec<u32>,
    names: Names,
    edges: FxHashMap<(u32, u32), u32>,
    journal: VecDeque<(Seq, Change)>,
    // changes_since(s) is answerable for floor <= s <= seq
    floor: Seq,
    journaling: bool,
    journal_max: usize,
    live: usize,
    pending: usize,
    scratch: Vec<u32>,
}

impl Tree {
    pub fn new(index: IndexId) -> Self {
        Self::restored(index, 0)
    }

    pub(crate) fn restored(index: IndexId, seq: Seq) -> Self {
        Self {
            index,
            seq,
            nodes: vec![Node::vacant()],
            free: Vec::new(),
            names: Names::default(),
            edges: FxHashMap::default(),
            journal: VecDeque::new(),
            floor: seq,
            journaling: true,
            journal_max: JOURNAL_MAX,
            live: 0,
            pending: 0,
            scratch: Vec::new(),
        }
    }

    pub fn index_id(&self) -> IndexId {
        self.index
    }

    // a new identity: no seq or journal entry of the old one is answerable any more
    pub fn renew_index(&mut self, index: IndexId) {
        self.index = index;
        self.journal.clear();
        self.floor = self.seq;
    }

    pub fn seq(&self) -> Seq {
        self.seq
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub fn set_journaling(&mut self, on: bool) {
        if self.journaling == on {
            return;
        }
        self.journaling = on;
        self.journal.clear();
        self.floor = self.seq;
    }

    pub(crate) fn child(&self, parent: u32, name: &str) -> Option<u32> {
        let nid = self.names.find(name)?;
        self.edges.get(&(parent, nid)).copied()
    }

    fn lookup(&self, path: &str) -> Option<u32> {
        let mut n = ROOT;
        for c in path.split('/').filter(|c| !c.is_empty()) {
            n = self.child(n, c)?;
        }
        Some(n)
    }

    pub(crate) fn node_of(&self, p: &RelPath) -> Option<u32> {
        self.lookup(p.as_str())
    }

    pub(crate) fn entry(&self, node: u32) -> Option<&Entry> {
        self.nodes.get(node as usize)?.entry.as_ref()
    }

    pub fn get(&self, p: &RelPath) -> Option<&Entry> {
        if p.is_root() {
            return None;
        }
        self.entry(self.node_of(p)?)
    }

    // files whose hash is still unknown
    pub fn pending(&self) -> usize {
        self.pending
    }

    // fills a pending file's hash if the entry is still the version and stat key the hash was computed for;
    // the entry keeps its seq and nothing is journaled, so guests learn the hash out of band
    pub fn set_hash(&mut self, p: &RelPath, ver: Seq, stat: &StatKey, h: Hash32) -> bool {
        if p.is_root() {
            return false;
        }
        let Some(n) = self.node_of(p) else {
            return false;
        };
        let Some(e) = self
            .nodes
            .get_mut(n as usize)
            .and_then(|x| x.entry.as_mut())
        else {
            return false;
        };
        if !e.is_pending() || e.seq != ver || e.stat != *stat {
            return false;
        }
        e.meta.hash = Some(h);
        self.pending -= 1;
        true
    }

    // looks at up to SCAN_NODES nodes from `cursor` in node order and pushes at most `max` pending files that
    // `keep` accepts; returns where to continue, or 0 once the pass reached the end of the tree
    pub fn pending_from(
        &self,
        cursor: u32,
        max: usize,
        keep: &dyn Fn(&Name, &Entry) -> bool,
        out: &mut Vec<HashJob>,
    ) -> u32 {
        if self.pending == 0 {
            return 0;
        }
        if max == 0 {
            return cursor;
        }
        let start = (cursor as usize).max(1);
        let end = self.nodes.len().min(start.saturating_add(SCAN_NODES));
        let mut taken = 0;
        let mut i = start;
        while i < end {
            let id = i as u32;
            i += 1;
            let x = &self.nodes[id as usize];
            let (Some(e), Some(name)) = (&x.entry, self.names.get(x.name)) else {
                continue;
            };
            if !e.is_pending() || !keep(name, e) {
                continue;
            }
            let Some(path) = self.path_of(id) else {
                continue;
            };
            out.push(HashJob {
                path,
                ver: e.seq,
                stat: e.stat,
            });
            taken += 1;
            if taken == max {
                break;
            }
        }
        if i >= self.nodes.len() { 0 } else { i as u32 }
    }

    // the parent directory must already be present; turning a directory into a non-directory drops its subtree
    pub fn observe(&mut self, p: &RelPath, o: Observed) -> Option<Change> {
        let (dir, name) = p.split_last()?;
        let parent = self.lookup(dir)?;
        self.observe_in(parent, name, o, Some(p), true)
    }

    pub(crate) fn observe_in(
        &mut self,
        parent: u32,
        name: &str,
        o: Observed,
        known: Option<&RelPath>,
        want: bool,
    ) -> Option<Change> {
        let record = want || self.journaling;
        match o {
            Observed::Absent => {
                let n = self.child(parent, name)?;
                let change = if record {
                    self.path_for(n, known).map(|path| Change::Remove { path })
                } else {
                    None
                };
                self.free_subtree(n);
                self.bump(change, want)
            }
            Observed::Present { meta, stat, domain } => {
                let seq = self.seq + 1;
                if let Some(n) = self.child(parent, name) {
                    let e = self.nodes.get_mut(n as usize)?.entry.as_mut()?;
                    if e.meta == meta && e.domain == domain {
                        e.stat = stat;
                        return None;
                    }
                    let drop_kids = e.meta.kind == Kind::Dir && meta.kind != Kind::Dir;
                    let copy = record.then(|| meta.clone());
                    let was = e.is_pending();
                    *e = Entry {
                        meta,
                        stat,
                        domain,
                        seq,
                    };
                    let now = e.is_pending();
                    self.pending = (self.pending + usize::from(now)) - usize::from(was);
                    if drop_kids {
                        self.free_children(n);
                    }
                    let change = copy.and_then(|meta| {
                        self.path_for(n, known).map(|path| Change::Upsert {
                            path,
                            meta,
                            ver: seq,
                        })
                    });
                    self.bump(change, want)
                } else {
                    let p = self.nodes.get(parent as usize)?;
                    if parent != ROOT && !p.is_dir() {
                        return None;
                    }
                    let copy = record.then(|| meta.clone());
                    let n = self.insert(
                        parent,
                        name,
                        Entry {
                            meta,
                            stat,
                            domain,
                            seq,
                        },
                    )?;
                    let change = copy.and_then(|meta| {
                        self.path_for(n, known).map(|path| Change::Upsert {
                            path,
                            meta,
                            ver: seq,
                        })
                    });
                    self.bump(change, want)
                }
            }
        }
    }

    pub(crate) fn remove_at(&mut self, n: u32, want: bool) -> Option<Change> {
        if n == ROOT || self.entry(n).is_none() {
            return None;
        }
        let change = if want || self.journaling {
            self.path_of(n).map(|path| Change::Remove { path })
        } else {
            None
        };
        self.free_subtree(n);
        self.bump(change, want)
    }

    pub fn remove_subtree(&mut self, dir: &RelPath, out: &mut Vec<Change>) {
        let Some(n) = self.node_of(dir) else { return };
        if n != ROOT {
            out.extend(self.remove_at(n, true));
            return;
        }
        let mut kids = Vec::new();
        let mut c = self.nodes[ROOT as usize].first;
        while c != NIL {
            kids.push(c);
            c = self.nodes[c as usize].next;
        }
        for k in kids {
            out.extend(self.remove_at(k, true));
        }
    }

    pub fn for_children(&self, dir: &RelPath, f: &mut dyn FnMut(&Name, &Entry)) {
        if let Some(n) = self.node_of(dir) {
            self.children(n, &mut |_, name, e| f(name, e));
        }
    }

    pub(crate) fn children(&self, node: u32, f: &mut dyn FnMut(u32, &Name, &Entry)) {
        let Some(p) = self.nodes.get(node as usize) else {
            return;
        };
        let mut c = p.first;
        while c != NIL {
            let x = &self.nodes[c as usize];
            if let (Some(e), Some(name)) = (&x.entry, self.names.get(x.name)) {
                f(c, name, e);
            }
            c = x.next;
        }
    }

    pub fn changes_since(&self, seq: Seq) -> Option<Vec<Change>> {
        if seq > self.seq || seq < self.floor {
            return None;
        }
        let skip = usize::try_from(seq - self.floor).ok()?;
        Some(
            self.journal
                .iter()
                .skip(skip)
                .map(|(_, c)| c.clone())
                .collect(),
        )
    }

    // entry k of the stream (0-based) has id k + 1; id 0 is the root, and parent < id always
    pub fn snapshot(&self, emit: &mut dyn FnMut(SnapEntry)) {
        self.walk(&mut |parent, name, e| {
            emit(SnapEntry {
                parent,
                name: name.clone(),
                meta: e.meta.clone(),
                ver: e.seq,
            })
        });
    }

    pub(crate) fn walk(&self, f: &mut dyn FnMut(u32, &Name, &Entry)) {
        let mut q: VecDeque<(u32, u32)> = VecDeque::new();
        q.push_back((ROOT, 0));
        let mut next: u32 = 1;
        while let Some((n, id)) = q.pop_front() {
            let mut c = self.nodes[n as usize].first;
            while c != NIL {
                let x = &self.nodes[c as usize];
                if let (Some(e), Some(name)) = (&x.entry, self.names.get(x.name)) {
                    f(id, name, e);
                    if x.first != NIL {
                        q.push_back((c, next));
                    }
                    next += 1;
                }
                c = x.next;
            }
        }
    }

    // rebuild from persisted state without touching seq or the journal
    pub(crate) fn restore_child(&mut self, parent: u32, name: &str, entry: Entry) -> Option<u32> {
        let p = self.nodes.get(parent as usize)?;
        if (parent != ROOT && !p.is_dir()) || self.child(parent, name).is_some() {
            return None;
        }
        self.insert(parent, name, entry)
    }

    pub(crate) fn path_of(&self, n: u32) -> Option<RelPath> {
        let mut chain = [NIL; DEPTH_MAX];
        let mut k = 0;
        let mut x = n;
        while x != ROOT {
            let node = self.nodes.get(x as usize)?;
            if k >= DEPTH_MAX || node.parent == NIL {
                return None;
            }
            chain[k] = node.name;
            k += 1;
            x = node.parent;
        }
        let mut s = String::with_capacity(self.nodes.get(n as usize)?.plen as usize);
        for &id in chain[..k].iter().rev() {
            if !s.is_empty() {
                s.push('/');
            }
            s.push_str(self.names.get(id)?.as_str());
        }
        RelPath::new(&s).ok()
    }

    fn path_for(&self, n: u32, known: Option<&RelPath>) -> Option<RelPath> {
        match known {
            Some(p) => Some(p.clone()),
            None => self.path_of(n),
        }
    }

    fn bump(&mut self, change: Option<Change>, want: bool) -> Option<Change> {
        self.seq += 1;
        if !self.journaling {
            self.floor = self.seq;
            return if want { change } else { None };
        }
        let Some(c) = change else {
            // a change that cannot be journaled leaves a gap, so older resumes must snapshot
            self.journal.clear();
            self.floor = self.seq;
            return None;
        };
        let ret = if want { Some(c.clone()) } else { None };
        self.journal.push_back((self.seq, c));
        while self.journal.len() > self.journal_max {
            if let Some((s, _)) = self.journal.pop_front() {
                self.floor = s;
            }
        }
        ret
    }

    fn insert(&mut self, parent: u32, name: &str, entry: Entry) -> Option<u32> {
        let p = self.nodes.get(parent as usize)?;
        let depth = p.depth as usize + 1;
        let plen = if parent == ROOT {
            name.len()
        } else {
            p.plen as usize + 1 + name.len()
        };
        let old_first = p.first;
        if depth > DEPTH_MAX || plen > PATH_MAX {
            return None;
        }
        let nid = self.names.intern(name)?;
        let pending = entry.is_pending();
        let node = Node {
            parent,
            name: nid,
            first: NIL,
            next: old_first,
            prev: NIL,
            depth: depth as u8,
            plen: plen as u16,
            entry: Some(entry),
        };
        let id = match self.free.pop() {
            Some(id) => {
                self.nodes[id as usize] = node;
                id
            }
            None => {
                if self.nodes.len() >= NIL as usize {
                    self.names.release(nid);
                    return None;
                }
                self.nodes.push(node);
                (self.nodes.len() - 1) as u32
            }
        };
        if old_first != NIL {
            self.nodes[old_first as usize].prev = id;
        }
        self.nodes[parent as usize].first = id;
        self.edges.insert((parent, nid), id);
        self.live += 1;
        self.pending += usize::from(pending);
        Some(id)
    }

    fn unlink(&mut self, n: u32) {
        let (parent, prev, next) = {
            let x = &self.nodes[n as usize];
            (x.parent, x.prev, x.next)
        };
        if prev != NIL {
            self.nodes[prev as usize].next = next;
        } else if parent != NIL {
            self.nodes[parent as usize].first = next;
        }
        if next != NIL {
            self.nodes[next as usize].prev = prev;
        }
    }

    fn free_subtree(&mut self, n: u32) {
        self.unlink(n);
        self.free_children(n);
        self.free_node(n);
    }

    fn free_children(&mut self, n: u32) {
        let mut stack = std::mem::take(&mut self.scratch);
        stack.clear();
        let mut c = self.nodes[n as usize].first;
        while c != NIL {
            stack.push(c);
            c = self.nodes[c as usize].next;
        }
        self.nodes[n as usize].first = NIL;
        while let Some(x) = stack.pop() {
            let mut c = self.nodes[x as usize].first;
            while c != NIL {
                stack.push(c);
                c = self.nodes[c as usize].next;
            }
            self.free_node(x);
        }
        self.scratch = stack;
    }

    fn free_node(&mut self, n: u32) {
        let node = std::mem::replace(&mut self.nodes[n as usize], Node::vacant());
        self.edges.remove(&(node.parent, node.name));
        self.names.release(node.name);
        self.free.push(n);
        if let Some(e) = &node.entry {
            self.live -= 1;
            self.pending -= usize::from(e.is_pending());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    fn meta(kind: Kind, size: u64, tag: u8) -> Meta {
        let hash = (kind == Kind::File).then_some([tag; 32]);
        Meta {
            kind,
            perm: 0o644,
            size,
            mtime_ns: i64::from(tag),
            ctime_ns: 0,
            hash,
            link: None,
            git_ro: false,
        }
    }

    fn put(t: &mut Tree, p: &str, kind: Kind, tag: u8) -> Option<Change> {
        let stat = StatKey {
            ino: u64::from(tag),
            ..StatKey::default()
        };
        t.observe(
            &rp(p),
            Observed::Present {
                meta: meta(kind, 1, tag),
                stat,
                domain: Domain::Synced,
            },
        )
    }

    #[test]
    fn journal_and_changes_since() {
        let mut t = Tree::new(7);
        assert!(put(&mut t, "a", Kind::Dir, 1).is_some());
        assert!(put(&mut t, "a/x", Kind::File, 2).is_some());
        assert!(put(&mut t, "b", Kind::File, 3).is_some());
        assert_eq!(t.seq(), 3);
        assert_eq!(t.get(&rp("a/x")).map(|e| e.seq), Some(2));

        assert!(put(&mut t, "b", Kind::File, 3).is_none());
        assert_eq!(t.seq(), 3);

        let new_stat = StatKey {
            ino: 99,
            ..StatKey::default()
        };
        assert!(
            t.observe(
                &rp("b"),
                Observed::Present {
                    meta: meta(Kind::File, 1, 3),
                    stat: new_stat,
                    domain: Domain::Synced
                }
            )
            .is_none()
        );
        assert_eq!(t.get(&rp("b")).map(|e| e.stat.ino), Some(99));
        assert_eq!(t.seq(), 3);

        let all = t.changes_since(0).unwrap();
        assert_eq!(all.len(), 3);
        assert!(matches!(&all[0], Change::Upsert { path, .. } if path.as_str() == "a"));
        let tail = t.changes_since(1).unwrap();
        assert_eq!(tail.len(), 2);
        assert!(matches!(&tail[0], Change::Upsert { path, .. } if path.as_str() == "a/x"));
        assert_eq!(t.changes_since(3).unwrap().len(), 0);
        assert!(t.changes_since(4).is_none());

        let rm = t.observe(&rp("a"), Observed::Absent);
        assert!(matches!(rm, Some(Change::Remove { ref path }) if path.as_str() == "a"));
        assert!(t.get(&rp("a/x")).is_none());
        assert_eq!(t.len(), 1);
        assert!(t.observe(&rp("a"), Observed::Absent).is_none());
        assert_eq!(t.changes_since(3).unwrap().len(), 1);
    }

    #[test]
    fn missing_parent_and_file_parent_are_refused() {
        let mut t = Tree::new(1);
        assert!(put(&mut t, "no/such", Kind::File, 1).is_none());
        put(&mut t, "f", Kind::File, 1);
        assert!(put(&mut t, "f/child", Kind::File, 2).is_none());
        assert_eq!(t.seq(), 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn kind_change_drops_subtree_and_names_are_reused() {
        let mut t = Tree::new(1);
        put(&mut t, "d", Kind::Dir, 1);
        put(&mut t, "d/e", Kind::Dir, 2);
        put(&mut t, "d/e/f", Kind::File, 3);
        assert!(matches!(
            put(&mut t, "d", Kind::File, 4),
            Some(Change::Upsert { .. })
        ));
        assert!(t.get(&rp("d/e")).is_none());
        assert!(t.get(&rp("d/e/f")).is_none());
        assert_eq!(t.len(), 1);
        put(&mut t, "e", Kind::Dir, 5);
        put(&mut t, "e/f", Kind::File, 6);
        let mut seen = Vec::new();
        t.for_children(&rp("e"), &mut |n, _| seen.push(n.as_str().to_owned()));
        assert_eq!(seen, vec!["f".to_owned()]);
        assert_eq!(t.get(&rp("e/f")).map(|e| e.meta.mtime_ns), Some(6));
    }

    #[test]
    fn journal_retention_is_bounded() {
        let mut t = Tree::new(1);
        t.journal_max = 4;
        for i in 0..10u8 {
            put(&mut t, "f", Kind::File, i);
        }
        assert_eq!(t.seq(), 10);
        assert!(t.changes_since(5).is_none());
        assert_eq!(t.changes_since(6).unwrap().len(), 4);
        assert_eq!(t.journal.len(), 4);
    }

    #[test]
    fn quiet_mode_forces_snapshot_for_older_seqs() {
        let mut t = Tree::new(1);
        put(&mut t, "a", Kind::File, 1);
        t.set_journaling(false);
        put(&mut t, "b", Kind::File, 2);
        t.set_journaling(true);
        assert!(t.changes_since(1).is_none());
        assert!(t.changes_since(0).is_none());
        assert_eq!(t.changes_since(2).unwrap().len(), 0);
        put(&mut t, "c", Kind::File, 3);
        assert_eq!(t.changes_since(2).unwrap().len(), 1);
    }

    #[test]
    fn remove_subtree_of_root_and_dir() {
        let mut t = Tree::new(1);
        put(&mut t, "a", Kind::Dir, 1);
        put(&mut t, "a/b", Kind::File, 2);
        put(&mut t, "c", Kind::File, 3);
        let mut out = Vec::new();
        t.remove_subtree(&rp("a"), &mut out);
        assert_eq!(out.len(), 1);
        assert!(t.get(&rp("a/b")).is_none());
        out.clear();
        t.remove_subtree(&RelPath::root(), &mut out);
        assert_eq!(out.len(), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn snapshot_is_parent_indexed_and_complete() {
        let mut t = Tree::new(1);
        let paths = [
            ("src", Kind::Dir),
            ("src/main.rs", Kind::File),
            ("src/a", Kind::Dir),
            ("src/a/b", Kind::Dir),
            ("src/a/b/c.rs", Kind::File),
            ("README", Kind::File),
            ("docs", Kind::Dir),
            ("docs/x", Kind::File),
            ("empty", Kind::Dir),
        ];
        for (i, (p, k)) in paths.iter().enumerate() {
            put(&mut t, p, *k, i as u8);
        }
        put(&mut t, "docs/x", Kind::File, 0);
        t.observe(&rp("src/a/b/c.rs"), Observed::Absent);
        put(&mut t, "src/a/b/c.rs", Kind::File, 9);

        let mut entries = Vec::new();
        t.snapshot(&mut |e| entries.push(e));
        assert_eq!(entries.len(), t.len());

        let mut full: Vec<String> = vec![String::new()];
        let mut kinds: Vec<Option<Kind>> = vec![Some(Kind::Dir)];
        for (k, e) in entries.iter().enumerate() {
            let id = k as u32 + 1;
            assert!(e.parent < id, "parent {} of entry {id}", e.parent);
            assert_eq!(kinds[e.parent as usize], Some(Kind::Dir));
            let parent = &full[e.parent as usize];
            let path = if parent.is_empty() {
                e.name.as_str().to_owned()
            } else {
                format!("{parent}/{}", e.name.as_str())
            };
            assert_eq!(t.get(&rp(&path)).map(|x| &x.meta), Some(&e.meta));
            full.push(path);
            kinds.push(Some(e.meta.kind));
        }
        let got: HashSet<&str> = full[1..].iter().map(String::as_str).collect();
        let want: HashSet<&str> = paths.iter().map(|(p, _)| *p).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn upserts_and_snapshots_carry_the_entry_seq_as_ver() {
        let mut t = Tree::new(1);
        put(&mut t, "a", Kind::Dir, 1);
        put(&mut t, "a/x", Kind::File, 2);
        put(&mut t, "a/x", Kind::File, 3);
        let ups: Vec<(String, Seq)> = t
            .changes_since(0)
            .unwrap()
            .into_iter()
            .filter_map(|c| match c {
                Change::Upsert { path, ver, .. } => Some((path.as_str().to_owned(), ver)),
                _ => None,
            })
            .collect();
        assert_eq!(
            ups,
            vec![
                ("a".to_owned(), 1),
                ("a/x".to_owned(), 2),
                ("a/x".to_owned(), 3)
            ]
        );
        assert_eq!(t.get(&rp("a/x")).map(|e| e.seq), Some(3));
        let mut vers = Vec::new();
        t.snapshot(&mut |e| vers.push((e.name.as_str().to_owned(), e.ver)));
        assert_eq!(vers, vec![("a".to_owned(), 1), ("x".to_owned(), 3)]);
    }

    fn stat_of(tag: u8) -> StatKey {
        StatKey {
            ino: u64::from(tag),
            ..StatKey::default()
        }
    }

    fn put_pending(t: &mut Tree, p: &str, tag: u8) -> Option<Change> {
        let mut m = meta(Kind::File, 1, tag);
        m.hash = None;
        t.observe(
            &rp(p),
            Observed::Present {
                meta: m,
                stat: stat_of(tag),
                domain: Domain::Synced,
            },
        )
    }

    fn recount(t: &Tree) -> usize {
        let mut n = 0;
        t.walk(&mut |_, _, e| n += usize::from(e.is_pending()));
        n
    }

    fn pending_paths(t: &Tree, keep: &dyn Fn(&Name, &Entry) -> bool, max: usize) -> Vec<HashJob> {
        let mut all = Vec::new();
        let mut cursor = 0;
        loop {
            let before = all.len();
            cursor = t.pending_from(cursor, max, keep, &mut all);
            assert!(all.len() - before <= max);
            if cursor == 0 {
                return all;
            }
        }
    }

    #[test]
    fn set_hash_applies_only_to_the_exact_pending_version() {
        let mut t = Tree::new(1);
        put(&mut t, "a", Kind::Dir, 1);
        put_pending(&mut t, "a/x", 2);
        put(&mut t, "known", Kind::File, 3);
        assert_eq!(t.pending(), 1);
        let (seq, ver) = (t.seq(), t.get(&rp("a/x")).unwrap().seq);
        let stat = stat_of(2);
        let h = [7u8; 32];

        assert!(!t.set_hash(&rp("a/x"), ver + 1, &stat, h));
        assert!(!t.set_hash(&rp("a/x"), ver - 1, &stat, h));
        assert!(!t.set_hash(&rp("a/x"), ver, &stat_of(9), h));
        let other_mtime = StatKey {
            mtime_ns: 5,
            ..stat
        };
        assert!(!t.set_hash(&rp("a/x"), ver, &other_mtime, h));
        let other_ctime = StatKey {
            ctime_ns: 5,
            ..stat
        };
        assert!(!t.set_hash(&rp("a/x"), ver, &other_ctime, h));
        assert!(!t.set_hash(&rp("a/missing"), ver, &stat, h));
        assert!(!t.set_hash(&rp("a"), 1, &stat_of(1), h));
        assert!(!t.set_hash(&RelPath::root(), 0, &StatKey::default(), h));
        assert!(!t.set_hash(&rp("known"), 3, &stat_of(3), h));
        assert_eq!(t.get(&rp("known")).unwrap().meta.hash, Some([3; 32]));
        assert_eq!(t.get(&rp("a/x")).unwrap().meta.hash, None);
        assert_eq!(t.pending(), 1);

        assert!(t.set_hash(&rp("a/x"), ver, &stat, h));
        assert_eq!(t.get(&rp("a/x")).unwrap().meta.hash, Some(h));
        assert_eq!(t.pending(), 0);
        assert_eq!(t.seq(), seq);
        assert_eq!(t.get(&rp("a/x")).unwrap().seq, ver);

        assert!(!t.set_hash(&rp("a/x"), ver, &stat, [8; 32]));
        assert_eq!(t.get(&rp("a/x")).unwrap().meta.hash, Some(h));

        // the journal still says the entry was pending, and nothing was added to it
        let journal = t.changes_since(0).unwrap();
        assert_eq!(journal.len() as u64, seq);
        assert!(journal.iter().any(|c| matches!(
            c,
            Change::Upsert { path, meta, .. } if path.as_str() == "a/x" && meta.hash.is_none()
        )));
    }

    #[test]
    fn a_changed_entry_refuses_the_hash_of_its_older_version() {
        let mut t = Tree::new(1);
        put_pending(&mut t, "f", 1);
        let old_ver = t.get(&rp("f")).unwrap().seq;
        let old_stat = t.get(&rp("f")).unwrap().stat;
        put_pending(&mut t, "f", 2);
        assert!(!t.set_hash(&rp("f"), old_ver, &old_stat, [1; 32]));
        let e = t.get(&rp("f")).unwrap();
        assert!(e.is_pending());
        let (ver, stat) = (e.seq, e.stat);
        assert!(ver > old_ver);
        assert!(!t.set_hash(&rp("f"), ver, &old_stat, [1; 32]));
        assert!(!t.set_hash(&rp("f"), old_ver, &stat, [1; 32]));
        assert!(t.set_hash(&rp("f"), ver, &stat, [1; 32]));
    }

    #[test]
    fn pending_counter_follows_insert_replace_remove_and_rename() {
        let mut t = Tree::new(1);
        let check = |t: &Tree, want: usize| {
            assert_eq!(t.pending(), want);
            assert_eq!(recount(t), want);
        };
        check(&t, 0);
        put(&mut t, "d", Kind::Dir, 1);
        put(&mut t, "d/sub", Kind::Dir, 2);
        put_pending(&mut t, "d/a", 3);
        put_pending(&mut t, "d/b", 4);
        put_pending(&mut t, "d/sub/c", 5);
        put(&mut t, "d/h", Kind::File, 6);
        check(&t, 3);

        // an unchanged observation is not a new entry
        assert!(put_pending(&mut t, "d/a", 3).is_none());
        check(&t, 3);

        // pending replaced by a hashed entry, and the other way round
        put(&mut t, "d/a", Kind::File, 7);
        check(&t, 2);
        put_pending(&mut t, "d/h", 8);
        check(&t, 3);

        // a hash learned out of band
        let e = t.get(&rp("d/b")).unwrap();
        let (ver, stat) = (e.seq, e.stat);
        assert!(t.set_hash(&rp("d/b"), ver, &stat, [9; 32]));
        check(&t, 2);

        // a file replaced by a directory and back
        put(&mut t, "d/h", Kind::Dir, 10);
        check(&t, 1);
        put_pending(&mut t, "d/h", 11);
        check(&t, 2);

        // a rename is a removal plus an insertion
        t.observe(&rp("d/sub/c"), Observed::Absent);
        check(&t, 1);
        put_pending(&mut t, "d/sub/c2", 12);
        check(&t, 2);

        // removing a directory drops the pending files below it
        let mut out = Vec::new();
        t.remove_subtree(&rp("d/sub"), &mut out);
        check(&t, 1);
        t.observe(&rp("d"), Observed::Absent);
        check(&t, 0);

        put(&mut t, "e", Kind::Dir, 20);
        put_pending(&mut t, "e/x", 21);
        put_pending(&mut t, "y", 22);
        check(&t, 2);
        put(&mut t, "e", Kind::File, 23);
        check(&t, 1);
        t.remove_subtree(&RelPath::root(), &mut out);
        check(&t, 0);
    }

    #[test]
    fn pending_from_honours_cursor_max_and_keep() {
        let mut t = Tree::new(1);
        put(&mut t, "d", Kind::Dir, 1);
        for (i, name) in ["a", "b", "c", "d", "e", "f"].iter().enumerate() {
            put_pending(&mut t, &format!("d/{name}"), 10 + i as u8);
        }
        put(&mut t, "d/hashed", Kind::File, 30);
        put(&mut t, "d/link", Kind::Symlink, 31);
        put_pending(&mut t, "top", 32);

        let all = pending_paths(&t, &|_, _| true, 2);
        let mut names: Vec<&str> = all.iter().map(|j| j.path.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["d/a", "d/b", "d/c", "d/d", "d/e", "d/f", "top"]);
        for j in &all {
            let e = t.get(&j.path).unwrap();
            assert_eq!((j.ver, j.stat), (e.seq, e.stat));
        }

        let few = pending_paths(&t, &|n, _| n.as_str() == "c" || n.as_str() == "top", 8);
        let mut names: Vec<&str> = few.iter().map(|j| j.path.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["d/c", "top"]);

        let mut one = Vec::new();
        let next = t.pending_from(0, 1, &|_, _| true, &mut one);
        assert_eq!(one.len(), 1);
        assert_ne!(next, 0);
        // resuming at the returned cursor never repeats a job
        let mut rest = Vec::new();
        let mut cur = next;
        while cur != 0 {
            cur = t.pending_from(cur, 1, &|_, _| true, &mut rest);
        }
        assert_eq!(rest.len(), all.len() - 1);
        assert!(!rest.contains(&one[0]));

        let mut none = Vec::new();
        assert_eq!(t.pending_from(u32::MAX, 4, &|_, _| true, &mut none), 0);
        assert!(none.is_empty());
        assert_eq!(t.pending_from(3, 0, &|_, _| true, &mut none), 3);
        assert!(none.is_empty());
    }

    #[test]
    fn pending_from_bounds_the_nodes_it_looks_at_per_call() {
        let mut t = Tree::new(1);
        for i in 0..(SCAN_NODES * 2 + 100) {
            put_pending(&mut t, &format!("f{i}"), 1);
        }
        let mut out = Vec::new();
        let first = t.pending_from(0, usize::MAX, &|_, _| false, &mut out);
        assert!(out.is_empty());
        assert_ne!(first, 0);
        assert!((first as usize) <= SCAN_NODES + 1);
        let mut calls = 1;
        let mut cur = first;
        while cur != 0 {
            cur = t.pending_from(cur, usize::MAX, &|_, _| false, &mut out);
            calls += 1;
        }
        assert_eq!(calls, 3);
        let mut all = Vec::new();
        let mut cur = 0;
        loop {
            cur = t.pending_from(cur, usize::MAX, &|_, _| true, &mut all);
            if cur == 0 {
                break;
            }
        }
        assert_eq!(all.len(), SCAN_NODES * 2 + 100);
    }

    #[test]
    fn pending_from_on_a_tree_with_nothing_pending_ends_the_pass() {
        let mut t = Tree::new(1);
        put(&mut t, "a", Kind::File, 1);
        let mut out = Vec::new();
        assert_eq!(t.pending_from(0, 8, &|_, _| true, &mut out), 0);
        assert!(out.is_empty());
    }
}
