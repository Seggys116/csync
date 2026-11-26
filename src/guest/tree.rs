use crate::ignore::rules::Class;
use crate::proto::{
    Change, DEPTH_MAX, Hash32, IndexId, Kind, Meta, Name, RelPath, Seq, SnapEntry, Version,
    check_snapshot_part,
};
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::{borrow::Borrow, collections::HashMap, collections::VecDeque};

pub type NodeId = u64;
pub const ROOT: NodeId = 1;
pub const DETACHED: NodeId = 0;
const SNAP_MAX: usize = 1 << 24;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GDomain {
    Synced,
    GitRo,
    Local,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Vis {
    Live,
    PendingCreate,
    PendingDelete,
}

pub type Children = HashMap<Name, NodeId, rustc_hash::FxBuildHasher>;

pub struct GNode {
    pub parent: NodeId,
    pub name: Name,
    pub meta: Meta,
    pub domain: GDomain,
    pub vis: Vis,
    pub r#gen: u64,
    // bumped under the read lock so lookups and readdirplus never take the write lock
    pub nlookup: AtomicU64,
    pub open: u32,
    pub read_ver: Option<Version>,
    // the blob the kernel page cache may hold for this inode; another one means the next open drops it
    pub page: Option<Hash32>,
    pub staging: Option<u32>,
    pub children: Option<Children>,
}

impl GNode {
    pub fn is_dir(&self) -> bool {
        self.meta.kind == Kind::Dir
    }

    pub fn attached(&self) -> bool {
        self.parent != DETACHED
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Synth {
    Create {
        parent: NodeId,
        name: Name,
        dir: bool,
    },
    Modify {
        node: NodeId,
    },
    Attrib {
        node: NodeId,
    },
    Delete {
        parent: NodeId,
        name: Name,
        dir: bool,
    },
    Move {
        from_parent: NodeId,
        from: Name,
        to_parent: NodeId,
        to: Name,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    InvalInode(NodeId),
    InvalEntry(NodeId, Name),
    Synth(Synth),
    Warm(NodeId, Hash32),
    Unpin(Hash32),
    ConflictPending(NodeId),
    LocalDiscarded(RelPath),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refuse {
    ReadOnly,
    Invalid,
}

// children maps are keyed by Name but probed with the &str the kernel hands us
impl Borrow<str> for Name {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

pub fn domain_of(meta: &Meta) -> GDomain {
    if meta.git_ro {
        GDomain::GitRo
    } else {
        GDomain::Synced
    }
}

// where a path the guest creates lives: host-synced, guest-only overlay, or refused
pub fn domain_for_new(parent: GDomain, class: Class) -> Result<GDomain, Refuse> {
    match (parent, class) {
        (GDomain::GitRo, _) | (_, Class::GitRo) => Err(Refuse::ReadOnly),
        (_, Class::Internal) => Err(Refuse::Invalid),
        (GDomain::Local, _) | (_, Class::Ignored) => Ok(GDomain::Local),
        (GDomain::Synced, Class::Synced) => Ok(GDomain::Synced),
    }
}

fn idx(id: NodeId) -> Option<usize> {
    usize::try_from(id.checked_sub(1)?).ok()
}

pub fn dir_meta(perm: u16) -> Meta {
    Meta {
        kind: Kind::Dir,
        perm,
        size: 0,
        mtime_ns: 0,
        ctime_ns: 0,
        hash: None,
        link: None,
        git_ro: false,
    }
}

struct Slot {
    node: Option<GNode>,
    r#gen: u64,
    mark: u32,
    local_loaded: AtomicBool,
}

pub struct GTree {
    slots: Vec<Slot>,
    free: Vec<usize>,
    index: IndexId,
    seq: Seq,
    attached: u64,
    mounted: bool,
    // old kernel-visible location of a host rename until the injector replays it
    ghosts: FxHashMap<(NodeId, Name), NodeId>,
    moving: FxHashMap<NodeId, (NodeId, Name)>,
    snap: Option<Vec<NodeId>>,
    // commits the host acknowledged on the current link; a snapshot taken before them must not revert them
    acked: rustc_hash::FxHashSet<NodeId>,
    epoch: u32,
    deferred: Vec<Effect>,
    stack: Vec<NodeId>,
}

impl Default for GTree {
    fn default() -> Self {
        Self::new()
    }
}

impl GTree {
    pub fn new() -> Self {
        let root = GNode {
            parent: ROOT,
            name: Name::new("root").expect("static name"),
            meta: dir_meta(0o755),
            domain: GDomain::Synced,
            vis: Vis::Live,
            r#gen: 1,
            nlookup: AtomicU64::new(1),
            open: 0,
            read_ver: None,
            page: None,
            staging: None,
            children: Some(Children::default()),
        };
        Self {
            slots: vec![Slot {
                node: Some(root),
                r#gen: 1,
                mark: 0,
                local_loaded: AtomicBool::new(false),
            }],
            free: Vec::new(),
            index: 0,
            seq: 0,
            attached: 0,
            mounted: false,
            ghosts: FxHashMap::default(),
            moving: FxHashMap::default(),
            snap: None,
            acked: rustc_hash::FxHashSet::default(),
            epoch: 0,
            deferred: Vec::new(),
            stack: Vec::new(),
        }
    }

    pub fn index_id(&self) -> IndexId {
        self.index
    }

    pub fn seq(&self) -> Seq {
        self.seq
    }

    pub fn set_version(&mut self, index: IndexId, seq: Seq) {
        self.index = index;
        self.seq = seq;
    }

    pub fn files(&self) -> u64 {
        self.attached
    }

    pub fn is_empty(&self) -> bool {
        self.attached == 0
    }

    // once mounted, host changes produce kernel invalidations and injected events
    pub fn set_mounted(&mut self, on: bool) {
        self.mounted = on;
    }

    pub fn mounted(&self) -> bool {
        self.mounted
    }

    pub fn set_root_meta(&mut self, perm: u16, mtime_ns: i64) {
        if let Some(r) = self.get_mut(ROOT) {
            r.meta.perm = perm;
            r.meta.mtime_ns = mtime_ns;
            r.meta.ctime_ns = mtime_ns;
        }
    }

    pub fn get(&self, id: NodeId) -> Option<&GNode> {
        self.slots.get(idx(id)?)?.node.as_ref()
    }

    pub fn get_mut(&mut self, id: NodeId) -> Option<&mut GNode> {
        self.slots.get_mut(idx(id)?)?.node.as_mut()
    }

    pub fn child(&self, parent: NodeId, name: &str) -> Option<NodeId> {
        self.get(parent)?.children.as_ref()?.get(name).copied()
    }

    fn hidden(&self, id: NodeId, n: &GNode) -> bool {
        n.vis == Vis::PendingCreate || self.moving.contains_key(&id)
    }

    pub fn lookup(&self, parent: NodeId, name: &str) -> Option<(NodeId, &GNode)> {
        if let Some(id) = self.child(parent, name)
            && let Some(n) = self.get(id)
            && !self.hidden(id, n)
        {
            return Some((id, n));
        }
        if self.ghosts.is_empty() {
            return None;
        }
        let key = (parent, Name::new(name).ok()?);
        let id = *self.ghosts.get(&key)?;
        self.get(id).map(|n| (id, n))
    }

    // kernel-visible children of dir; ghosts carry the name they are still visible under
    pub fn list(&self, dir: NodeId, out: &mut Vec<(NodeId, Option<Name>)>) -> bool {
        let Some(kids) = self.get(dir).and_then(|d| d.children.as_ref()) else {
            return false;
        };
        out.reserve(kids.len());
        for &id in kids.values() {
            if let Some(n) = self.get(id)
                && !self.hidden(id, n)
            {
                out.push((id, None));
            }
        }
        for ((p, name), &id) in &self.ghosts {
            if *p == dir {
                out.push((id, Some(name.clone())));
            }
        }
        true
    }

    pub fn path_of(&self, id: NodeId, out: &mut String) -> bool {
        self.path_with(id, out, false)
    }

    // the path as the kernel currently sees it, which differs from path_of during a pending move
    pub fn visible_path_of(&self, id: NodeId, out: &mut String) -> bool {
        self.path_with(id, out, true)
    }

    fn path_with(&self, id: NodeId, out: &mut String, visible: bool) -> bool {
        out.clear();
        let mut chain: [Option<&Name>; DEPTH_MAX] = [None; DEPTH_MAX];
        let mut k = 0;
        let mut cur = id;
        while cur != ROOT {
            let Some(n) = self.get(cur) else { return false };
            if visible && n.vis == Vis::PendingCreate {
                return false;
            }
            let (parent, name) = match self.moving.get(&cur) {
                Some((p, nm)) if visible => (*p, nm),
                _ => (n.parent, &n.name),
            };
            if parent == DETACHED || k >= DEPTH_MAX {
                return false;
            }
            chain[k] = Some(name);
            k += 1;
            cur = parent;
        }
        for (i, name) in chain[..k].iter().rev().flatten().enumerate() {
            if i > 0 {
                out.push('/');
            }
            out.push_str(name.as_str());
        }
        true
    }

    pub fn rel_path(&self, id: NodeId) -> Option<RelPath> {
        let mut s = String::new();
        if !self.path_of(id, &mut s) {
            return None;
        }
        RelPath::new(&s).ok()
    }

    pub fn resolve(&self, p: &RelPath) -> Option<NodeId> {
        let mut cur = ROOT;
        for c in p.components() {
            cur = self.child(cur, c)?;
        }
        Some(cur)
    }

    fn resolve_parent<'a>(&self, p: &'a RelPath) -> Option<(NodeId, &'a str)> {
        let (dir, name) = p.split_last()?;
        let mut cur = ROOT;
        for c in dir.split('/').filter(|c| !c.is_empty()) {
            cur = self.child(cur, c)?;
        }
        Some((cur, name))
    }

    // attached all the way up with no hidden ancestor, so the kernel can reach it by path
    fn reachable(&self, mut id: NodeId) -> bool {
        for _ in 0..=DEPTH_MAX {
            if id == ROOT {
                return true;
            }
            let Some(n) = self.get(id) else { return false };
            if !n.attached() || n.vis == Vis::PendingCreate {
                return false;
            }
            id = self.moving.get(&id).map_or(n.parent, |(p, _)| *p);
        }
        false
    }

    pub fn local_loaded(&self, id: NodeId) -> bool {
        idx(id)
            .and_then(|i| self.slots.get(i))
            .is_some_and(|s| s.local_loaded.load(Relaxed))
    }

    pub fn set_local_loaded(&self, id: NodeId) {
        if let Some(s) = idx(id).and_then(|i| self.slots.get(i)) {
            s.local_loaded.store(true, Relaxed);
        }
    }

    fn alloc(&mut self, mut node: GNode) -> NodeId {
        let mark = self.epoch;
        if let Some(i) = self.free.pop()
            && let Some(s) = self.slots.get_mut(i)
        {
            s.r#gen += 1;
            node.r#gen = s.r#gen;
            s.node = Some(node);
            s.mark = mark;
            *s.local_loaded.get_mut() = false;
            return i as NodeId + 1;
        }
        node.r#gen = 1;
        self.slots.push(Slot {
            node: Some(node),
            r#gen: 1,
            mark,
            local_loaded: AtomicBool::new(false),
        });
        self.slots.len() as NodeId
    }

    fn release_slot(&mut self, id: NodeId) {
        if id == ROOT {
            return;
        }
        if let Some(i) = idx(id)
            && let Some(s) = self.slots.get_mut(i)
            && s.node.take().is_some()
        {
            self.free.push(i);
        }
    }

    // returns DETACHED when parent is not an attached directory; an existing child of that name is replaced
    pub fn insert(
        &mut self,
        parent: NodeId,
        name: Name,
        meta: Meta,
        domain: GDomain,
        vis: Vis,
    ) -> NodeId {
        if !self
            .get(parent)
            .is_some_and(|p| p.attached() && p.children.is_some())
        {
            return DETACHED;
        }
        if let Some(old) = self.child(parent, name.as_str()) {
            let mut fx = std::mem::take(&mut self.deferred);
            self.detach(old, &mut fx);
            self.deferred = fx;
        }
        let children = (meta.kind == Kind::Dir).then(Children::default);
        let node = GNode {
            parent,
            name: name.clone(),
            meta,
            domain,
            vis,
            r#gen: 0,
            nlookup: AtomicU64::new(0),
            open: 0,
            read_ver: None,
            page: None,
            staging: None,
            children,
        };
        let id = self.alloc(node);
        if let Some(kids) = self.get_mut(parent).and_then(|p| p.children.as_mut()) {
            kids.insert(name, id);
        }
        self.attached += 1;
        id
    }

    // a guest mkdir the host answered after its own copy of the directory arrived keeps that node and its contents
    pub fn insert_dir(
        &mut self,
        parent: NodeId,
        name: Name,
        meta: Meta,
        domain: GDomain,
    ) -> NodeId {
        if let Some(id) = self.child(parent, name.as_str())
            && !self.moving.contains_key(&id)
            && let Some(n) = self.get_mut(id)
            && n.is_dir()
            && n.domain == domain
        {
            n.meta = meta;
            n.vis = Vis::Live;
            return id;
        }
        self.insert(parent, name, meta, domain, Vis::Live)
    }

    // unlinks id and its subtree; slots the kernel still references stay until forget
    fn detach(&mut self, id: NodeId, fx: &mut Vec<Effect>) {
        if id == ROOT {
            return;
        }
        let (parent, name) = match self.get(id) {
            Some(n) if n.attached() => (n.parent, n.name.clone()),
            _ => return,
        };
        if let Some(kids) = self.get_mut(parent).and_then(|p| p.children.as_mut())
            && kids.get(name.as_str()) == Some(&id)
        {
            kids.remove(name.as_str());
        }
        let mut stack = std::mem::take(&mut self.stack);
        stack.clear();
        stack.push(id);
        while let Some(x) = stack.pop() {
            if let Some(old) = self.moving.remove(&x) {
                self.ghosts.remove(&old);
            }
            let Some(n) = self.get_mut(x) else { continue };
            if !n.attached() {
                continue;
            }
            n.parent = DETACHED;
            n.vis = Vis::Live;
            let kids = n.children.as_mut().map(std::mem::take);
            if n.open == 0
                && let Some(v) = n.read_ver.take()
            {
                fx.push(Effect::Unpin(v.hash));
            }
            let free = *n.nlookup.get_mut() == 0 && n.open == 0;
            self.attached = self.attached.saturating_sub(1);
            if let Some(k) = kids {
                stack.extend(k.into_values());
            }
            if free {
                self.release_slot(x);
            }
        }
        self.stack = stack;
    }

    pub fn remove(&mut self, id: NodeId) {
        let mut fx = std::mem::take(&mut self.deferred);
        self.detach(id, &mut fx);
        self.deferred = fx;
    }

    pub fn take_deferred(&mut self, fx: &mut Vec<Effect>) {
        fx.append(&mut self.deferred);
    }

    pub fn forget(&mut self, id: NodeId, n: u64) {
        if id == ROOT {
            return;
        }
        let Some(node) = self.get_mut(id) else { return };
        let left = node.nlookup.get_mut();
        *left = left.saturating_sub(n);
        if *left == 0 && node.open == 0 && !node.attached() {
            self.release_slot(id);
        }
    }

    pub fn add_lookup(&self, id: NodeId) {
        if let Some(n) = self.get(id) {
            n.nlookup.fetch_add(1, Relaxed);
        }
    }

    pub fn add_open(&mut self, id: NodeId) {
        if let Some(n) = self.get_mut(id) {
            n.open = n.open.saturating_add(1);
        }
    }

    pub fn drop_open(&mut self, id: NodeId) {
        let Some(n) = self.get_mut(id) else { return };
        n.open = n.open.saturating_sub(1);
        if n.open == 0 && *n.nlookup.get_mut() == 0 && !n.attached() {
            self.release_slot(id);
        }
    }

    // guest-originated rename after the host (or the overlay) accepted it
    pub fn relink(&mut self, id: NodeId, to_parent: NodeId, to: Name) -> bool {
        if id == ROOT
            || !self
                .get(to_parent)
                .is_some_and(|p| p.attached() && p.children.is_some())
        {
            return false;
        }
        let (fp, fname) = match self.get(id) {
            Some(n) if n.attached() => (n.parent, n.name.clone()),
            _ => return false,
        };
        if self.is_within(to_parent, id) {
            return false;
        }
        let mut fx = std::mem::take(&mut self.deferred);
        self.finish_move(id, &mut fx);
        if let Some(old) = self.child(to_parent, to.as_str())
            && old != id
        {
            self.detach(old, &mut fx);
        }
        self.deferred = fx;
        if let Some(k) = self.get_mut(fp).and_then(|p| p.children.as_mut()) {
            k.remove(fname.as_str());
        }
        if let Some(k) = self.get_mut(to_parent).and_then(|p| p.children.as_mut()) {
            k.insert(to.clone(), id);
        }
        if let Some(n) = self.get_mut(id) {
            n.parent = to_parent;
            n.name = to;
        }
        true
    }

    // true when a equals b or lies inside b
    pub fn is_within(&self, mut a: NodeId, b: NodeId) -> bool {
        for _ in 0..=DEPTH_MAX {
            if a == b {
                return true;
            }
            if a == ROOT || a == DETACHED {
                return false;
            }
            match self.get(a) {
                Some(n) => a = n.parent,
                None => return false,
            }
        }
        true
    }

    fn finish_move(&mut self, id: NodeId, fx: &mut Vec<Effect>) {
        if let Some((p, name)) = self.moving.remove(&id) {
            self.ghosts.remove(&(p, name.clone()));
            fx.push(Effect::InvalEntry(p, name));
            fx.push(Effect::InvalInode(p));
        }
    }

    pub fn apply(&mut self, c: &Change, fx: &mut Vec<Effect>) {
        fx.append(&mut self.deferred);
        match c {
            Change::Upsert { path, meta } => {
                if let Some((p, name)) = self.resolve_parent(path) {
                    self.upsert_at(p, name, meta.clone(), fx);
                }
            }
            Change::Remove { path } => {
                if let Some(id) = self.resolve(path) {
                    self.remove_node(id, fx);
                }
            }
            Change::Rename { from, to } => self.rename(from, to, fx),
        }
    }

    fn upsert_at(
        &mut self,
        parent: NodeId,
        name: &str,
        meta: Meta,
        fx: &mut Vec<Effect>,
    ) -> Option<NodeId> {
        if !self
            .get(parent)
            .is_some_and(|p| p.attached() && p.children.is_some())
        {
            return None;
        }
        match self.child(parent, name) {
            Some(id) => self.update(id, parent, name, meta, fx),
            None => {
                let nm = Name::new(name).ok()?;
                let show = self.mounted && self.reachable(parent);
                let dir = meta.kind == Kind::Dir;
                let domain = domain_of(&meta);
                let vis = if show { Vis::PendingCreate } else { Vis::Live };
                let id = self.insert(parent, nm.clone(), meta, domain, vis);
                if id == DETACHED {
                    return None;
                }
                if self.mounted {
                    fx.push(Effect::InvalInode(parent));
                }
                if show {
                    fx.push(Effect::Synth(Synth::Create {
                        parent,
                        name: nm,
                        dir,
                    }));
                }
                Some(id)
            }
        }
    }

    fn update(
        &mut self,
        id: NodeId,
        parent: NodeId,
        name: &str,
        meta: Meta,
        fx: &mut Vec<Effect>,
    ) -> Option<NodeId> {
        let on = self.mounted;
        let n = self.get(id)?;
        if n.domain == GDomain::Local {
            // the host now has this path, so the guest-only copy loses
            let path = self.rel_path(id);
            self.detach(id, fx);
            if on {
                fx.push(Effect::InvalEntry(parent, Name::new(name).ok()?));
            }
            if let Some(p) = path {
                fx.push(Effect::LocalDiscarded(p));
            }
            return self.upsert_at(parent, name, meta, fx);
        }
        if n.meta.kind != meta.kind {
            self.detach(id, fx);
            let nm = Name::new(name).ok()?;
            if on {
                fx.push(Effect::InvalEntry(parent, nm.clone()));
                fx.push(Effect::InvalInode(parent));
            }
            let domain = domain_of(&meta);
            let nid = self.insert(parent, nm, meta, domain, Vis::Live);
            return (nid != DETACHED).then_some(nid);
        }
        let content =
            n.meta.hash != meta.hash || n.meta.size != meta.size || n.meta.link != meta.link;
        let perm = n.meta.perm != meta.perm;
        let times = n.meta.mtime_ns != meta.mtime_ns || n.meta.ctime_ns != meta.ctime_ns;
        let gitro = n.meta.git_ro != meta.git_ro;
        let was = n.vis;
        let warm = content && meta.kind == Kind::File && (n.open > 0 || n.read_ver.is_some());
        let conflict = content && n.staging.is_some();
        let show = on && was == Vis::Live && self.reachable(id);
        let kind = meta.kind;
        let hash = meta.hash;
        let n = self.get_mut(id)?;
        n.domain = domain_of(&meta);
        n.meta = meta;
        if was == Vis::PendingDelete {
            n.vis = Vis::Live;
        }
        if !on || !(content || perm || times || gitro || was == Vis::PendingDelete) {
            return Some(id);
        }
        fx.push(Effect::InvalInode(id));
        if show {
            match kind {
                Kind::File if content => fx.push(Effect::Synth(Synth::Modify { node: id })),
                Kind::File if perm || times => fx.push(Effect::Synth(Synth::Attrib { node: id })),
                Kind::Dir if perm => fx.push(Effect::Synth(Synth::Attrib { node: id })),
                _ => {}
            }
        }
        if warm && let Some(h) = hash {
            fx.push(Effect::Warm(id, h));
        }
        if conflict {
            fx.push(Effect::ConflictPending(id));
        }
        Some(id)
    }

    fn remove_node(&mut self, id: NodeId, fx: &mut Vec<Effect>) {
        if id == ROOT {
            return;
        }
        match self.get(id) {
            Some(n) if n.attached() && n.domain != GDomain::Local => {}
            _ => return,
        }
        self.finish_move(id, fx);
        let Some(n) = self.get(id) else { return };
        let (parent, vis, dir, name) = (n.parent, n.vis, n.is_dir(), n.name.clone());
        if vis == Vis::PendingDelete {
            return;
        }
        if self.mounted && vis == Vis::Live && self.reachable(id) {
            if let Some(n) = self.get_mut(id) {
                n.vis = Vis::PendingDelete;
            }
            fx.push(Effect::InvalInode(parent));
            fx.push(Effect::Synth(Synth::Delete { parent, name, dir }));
            return;
        }
        self.detach(id, fx);
        if self.mounted && vis != Vis::PendingCreate {
            fx.push(Effect::InvalEntry(parent, name));
            fx.push(Effect::InvalInode(parent));
        }
    }

    fn rename(&mut self, from: &RelPath, to: &RelPath, fx: &mut Vec<Effect>) {
        let Some(id) = self.resolve(from) else { return };
        if id == ROOT || to.starts_with(from) {
            return;
        }
        let target = self.resolve_parent(to).filter(|(tp, _)| {
            self.get(*tp)
                .is_some_and(|p| p.attached() && p.children.is_some())
        });
        let Some((tp, tname)) = target else {
            self.remove_node(id, fx);
            return;
        };
        let Ok(tname) = Name::new(tname) else { return };
        match self.get(id) {
            Some(n) if n.domain != GDomain::Local => {}
            _ => return,
        }
        self.finish_move(id, fx);
        let Some(n) = self.get_mut(id) else { return };
        let (fp, fname, vis) = (n.parent, n.name.clone(), n.vis);
        // a node the kernel never saw, or one already being deleted, just appears at the destination
        n.vis = Vis::Live;
        if fp == tp && fname == tname {
            return;
        }
        if let Some(r) = self.child(tp, tname.as_str())
            && r != id
        {
            self.detach(r, fx);
        }
        if let Some(k) = self.get_mut(fp).and_then(|p| p.children.as_mut()) {
            k.remove(fname.as_str());
        }
        if let Some(k) = self.get_mut(tp).and_then(|p| p.children.as_mut()) {
            k.insert(tname.clone(), id);
        }
        if let Some(n) = self.get_mut(id) {
            n.parent = tp;
            n.name = tname.clone();
        }
        if !self.mounted {
            return;
        }
        fx.push(Effect::InvalInode(fp));
        if tp != fp {
            fx.push(Effect::InvalInode(tp));
        }
        if vis == Vis::Live && self.reachable(fp) && self.reachable(tp) {
            let key = (fp, fname.clone());
            if let Some(prev) = self.ghosts.get(&key).copied() {
                self.finish_move(prev, fx);
            }
            self.ghosts.insert(key, id);
            self.moving.insert(id, (fp, fname.clone()));
            fx.push(Effect::Synth(Synth::Move {
                from_parent: fp,
                from: fname,
                to_parent: tp,
                to: tname,
            }));
        } else {
            fx.push(Effect::InvalEntry(fp, fname));
            fx.push(Effect::InvalEntry(tp, tname));
        }
    }

    // resolves whatever pending state s left behind when its event could not be injected
    pub fn settle(&mut self, s: &Synth, fx: &mut Vec<Effect>) {
        fx.append(&mut self.deferred);
        match s {
            Synth::Create { parent, name, .. } => {
                if let Some(id) = self.child(*parent, name.as_str())
                    && let Some(n) = self.get_mut(id)
                    && n.vis == Vis::PendingCreate
                {
                    n.vis = Vis::Live;
                    fx.push(Effect::InvalEntry(*parent, name.clone()));
                    fx.push(Effect::InvalInode(*parent));
                }
            }
            Synth::Delete { parent, name, .. } => {
                if let Some(id) = self.child(*parent, name.as_str())
                    && self.get(id).is_some_and(|n| n.vis == Vis::PendingDelete)
                {
                    self.detach(id, fx);
                    fx.push(Effect::InvalEntry(*parent, name.clone()));
                    fx.push(Effect::InvalInode(*parent));
                }
            }
            Synth::Move {
                from_parent,
                from,
                to_parent,
                to,
            } => {
                if let Some(&id) = self.ghosts.get(&(*from_parent, from.clone())) {
                    self.finish_move(id, fx);
                    fx.push(Effect::InvalEntry(*to_parent, to.clone()));
                }
            }
            Synth::Modify { .. } | Synth::Attrib { .. } => {}
        }
    }

    // the injector's own create reached the daemon: reveal the pending node
    pub fn complete_create(&mut self, parent: NodeId, name: &str) -> Option<NodeId> {
        let id = self.child(parent, name)?;
        let n = self.get_mut(id)?;
        if n.vis != Vis::PendingCreate {
            return None;
        }
        n.vis = Vis::Live;
        Some(id)
    }

    pub fn complete_delete(&mut self, parent: NodeId, name: &str) -> bool {
        let Some(id) = self.child(parent, name) else {
            return false;
        };
        if !self.get(id).is_some_and(|n| n.vis == Vis::PendingDelete) {
            return false;
        }
        self.remove(id);
        true
    }

    pub fn complete_move(
        &mut self,
        parent: NodeId,
        name: &str,
        new_parent: NodeId,
        new_name: &str,
    ) -> bool {
        let Ok(key) = Name::new(name).map(|n| (parent, n)) else {
            return false;
        };
        let Some(&id) = self.ghosts.get(&key) else {
            return false;
        };
        if !self
            .get(id)
            .is_some_and(|n| n.parent == new_parent && n.name.as_str() == new_name)
        {
            return false;
        }
        self.ghosts.remove(&key);
        self.moving.remove(&id);
        true
    }

    pub fn was_acked(&self, id: NodeId) -> bool {
        self.acked.contains(&id)
    }

    pub fn note_acked(&mut self, id: NodeId) {
        self.acked.insert(id);
    }

    // a new link: its snapshot is taken before any request on it is served
    pub fn clear_acked(&mut self) {
        self.acked.clear();
    }

    pub fn snapshot_reset(&mut self) {
        self.snap = None;
    }

    // part entries are numbered from 1 in stream order across parts, the root is 0
    pub fn apply_snapshot_part(
        &mut self,
        entries: &[SnapEntry],
        last: bool,
        fx: &mut Vec<Effect>,
    ) -> Result<(), &'static str> {
        fx.append(&mut self.deferred);
        let mut ids = match self.snap.take() {
            Some(ids) => ids,
            None => {
                self.epoch = self.epoch.wrapping_add(1);
                if let Some(s) = self.slots.get_mut(0) {
                    s.mark = self.epoch;
                }
                vec![ROOT]
            }
        };
        if ids.len().saturating_add(entries.len()) > SNAP_MAX {
            return Err("snapshot too large");
        }
        let first = u32::try_from(ids.len()).map_err(|_| "snapshot too large")?;
        check_snapshot_part(entries, first)?;
        for e in entries {
            let parent = ids.get(e.parent as usize).copied().unwrap_or(DETACHED);
            if !self.get(parent).is_some_and(|p| p.children.is_some()) {
                return Err("snapshot parent is not a directory");
            }
            let id = match self.child(parent, e.name.as_str()) {
                Some(id) if self.acked.contains(&id) => id,
                _ => self
                    .upsert_at(parent, e.name.as_str(), e.meta.clone(), fx)
                    .unwrap_or(DETACHED),
            };
            if let Some(s) = idx(id).and_then(|i| self.slots.get_mut(i)) {
                s.mark = self.epoch;
            }
            ids.push(id);
        }
        if last {
            self.sweep(fx);
            self.acked.clear();
        } else {
            self.snap = Some(ids);
        }
        Ok(())
    }

    fn sweep(&mut self, fx: &mut Vec<Effect>) {
        let ep = self.epoch;
        // a file with a write in flight may not be on the host yet; it and its directories stay until the commit settles
        let mut keep = rustc_hash::FxHashSet::default();
        for (i, s) in self.slots.iter().enumerate() {
            let id = i as NodeId + 1;
            if s.node
                .as_ref()
                .is_some_and(|n| n.attached() && (n.staging.is_some() || self.acked.contains(&id)))
            {
                let mut cur = i as NodeId + 1;
                while cur != ROOT && keep.insert(cur) {
                    match self.get(cur) {
                        Some(n) if n.attached() => cur = n.parent,
                        _ => break,
                    }
                }
            }
        }
        let stale: Vec<NodeId> = self
            .slots
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(i, s)| {
                s.mark != ep
                    && !keep.contains(&(*i as NodeId + 1))
                    && s.node
                        .as_ref()
                        .is_some_and(|n| n.attached() && n.domain != GDomain::Local)
            })
            .map(|(i, _)| i as NodeId + 1)
            .collect();
        for id in stale {
            self.remove_node(id, fx);
        }
    }

    // host-domain entries in parent-indexed order, for persisting and later diffing
    pub fn export(&self, emit: &mut dyn FnMut(SnapEntry)) {
        let mut q: VecDeque<(NodeId, u32)> = VecDeque::new();
        q.push_back((ROOT, 0));
        let mut next: u32 = 1;
        while let Some((id, at)) = q.pop_front() {
            let Some(kids) = self.get(id).and_then(|n| n.children.as_ref()) else {
                continue;
            };
            for &c in kids.values() {
                let Some(n) = self.get(c) else { continue };
                if n.domain == GDomain::Local || n.vis == Vis::PendingDelete {
                    continue;
                }
                emit(SnapEntry {
                    parent: at,
                    name: n.name.clone(),
                    meta: n.meta.clone(),
                });
                if n.children.is_some() {
                    q.push_back((c, next));
                }
                next = next.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    fn nm(s: &str) -> Name {
        Name::new(s).unwrap()
    }

    fn file(tag: u8) -> Meta {
        Meta {
            kind: Kind::File,
            perm: 0o644,
            size: u64::from(tag),
            mtime_ns: i64::from(tag),
            ctime_ns: 0,
            hash: Some([tag; 32]),
            link: None,
            git_ro: false,
        }
    }

    fn dir() -> Meta {
        dir_meta(0o755)
    }

    fn up(t: &mut GTree, p: &str, meta: Meta) -> Vec<Effect> {
        let mut fx = Vec::new();
        t.apply(&Change::Upsert { path: rp(p), meta }, &mut fx);
        fx
    }

    fn mounted_tree() -> GTree {
        let mut t = GTree::new();
        up(&mut t, "src", dir());
        up(&mut t, "src/a.rs", file(1));
        t.set_mounted(true);
        t
    }

    #[test]
    fn guest_mkdir_keeps_the_host_copy_that_raced_it() {
        let mut t = mounted_tree();
        let src = t.resolve(&rp("src")).unwrap();
        up(&mut t, "src/b", dir());
        up(&mut t, "src/b/c.rs", file(3));
        let host_b = t.resolve(&rp("src/b")).unwrap();
        let id = t.insert_dir(src, nm("b"), dir(), GDomain::Synced);
        assert_eq!(id, host_b);
        assert_eq!(t.lookup(src, "b").map(|(i, _)| i), Some(id));
        assert!(t.resolve(&rp("src/b/c.rs")).is_some());
        let fresh = t.insert_dir(src, nm("d"), dir(), GDomain::Synced);
        assert_eq!(t.lookup(src, "d").map(|(i, _)| i), Some(fresh));
    }

    #[test]
    fn upsert_create_is_hidden_until_injected() {
        let mut t = mounted_tree();
        let src = t.resolve(&rp("src")).unwrap();
        let fx = up(&mut t, "src/b.rs", file(2));
        assert_eq!(
            fx,
            vec![
                Effect::InvalInode(src),
                Effect::Synth(Synth::Create {
                    parent: src,
                    name: nm("b.rs"),
                    dir: false
                })
            ]
        );
        assert!(t.lookup(src, "b.rs").is_none());
        let mut l = Vec::new();
        t.list(src, &mut l);
        assert_eq!(l.len(), 1);
        let id = t.complete_create(src, "b.rs").unwrap();
        assert_eq!(t.lookup(src, "b.rs").map(|(i, _)| i), Some(id));
        assert!(t.complete_create(src, "b.rs").is_none());

        let fx = up(&mut t, "src/new", dir());
        assert!(matches!(
            fx.last(),
            Some(Effect::Synth(Synth::Create { dir: true, .. }))
        ));
        let fx = up(&mut t, "src/new/inner", file(3));
        assert!(
            !fx.iter().any(|e| matches!(e, Effect::Synth(_))),
            "children of a pending dir go straight to live"
        );
    }

    #[test]
    fn upsert_modify_and_attrib_effects() {
        let mut t = mounted_tree();
        let a = t.resolve(&rp("src/a.rs")).unwrap();
        t.get_mut(a).unwrap().read_ver = Some(Version {
            hash: [1; 32],
            size: 1,
        });
        t.get_mut(a).unwrap().staging = Some(7);
        let fx = up(&mut t, "src/a.rs", file(9));
        assert_eq!(
            fx,
            vec![
                Effect::InvalInode(a),
                Effect::Synth(Synth::Modify { node: a }),
                Effect::Warm(a, [9; 32]),
                Effect::ConflictPending(a)
            ]
        );
        let mut m = file(9);
        m.perm = 0o600;
        let fx = up(&mut t, "src/a.rs", m.clone());
        assert_eq!(
            fx,
            vec![
                Effect::InvalInode(a),
                Effect::Synth(Synth::Attrib { node: a })
            ]
        );
        assert!(up(&mut t, "src/a.rs", m).is_empty());
    }

    #[test]
    fn remove_is_visible_until_injected_then_settles() {
        let mut t = mounted_tree();
        let src = t.resolve(&rp("src")).unwrap();
        let a = t.resolve(&rp("src/a.rs")).unwrap();
        let mut fx = Vec::new();
        t.apply(
            &Change::Remove {
                path: rp("src/a.rs"),
            },
            &mut fx,
        );
        let synth = Synth::Delete {
            parent: src,
            name: nm("a.rs"),
            dir: false,
        };
        assert_eq!(
            fx,
            vec![Effect::InvalInode(src), Effect::Synth(synth.clone())]
        );
        assert_eq!(
            t.lookup(src, "a.rs").map(|(_, n)| n.vis),
            Some(Vis::PendingDelete)
        );
        fx.clear();
        t.settle(&synth, &mut fx);
        assert_eq!(
            fx,
            vec![Effect::InvalEntry(src, nm("a.rs")), Effect::InvalInode(src)]
        );
        assert!(t.lookup(src, "a.rs").is_none());
        assert!(t.get(a).is_none(), "an unreferenced node is freed");

        up(&mut t, "src/c.rs", file(4));
        t.complete_create(src, "c.rs");
        let mut fx = Vec::new();
        t.apply(
            &Change::Remove {
                path: rp("src/c.rs"),
            },
            &mut fx,
        );
        assert!(t.complete_delete(src, "c.rs"));
        assert!(t.lookup(src, "c.rs").is_none());
    }

    #[test]
    fn rename_keeps_old_name_visible_until_injected() {
        let mut t = mounted_tree();
        up(&mut t, "dst", dir());
        let root_fx = up(&mut t, "dst", dir());
        assert!(root_fx.is_empty());
        let dst = t.resolve(&rp("dst")).unwrap();
        t.complete_create(ROOT, "dst");
        let src = t.resolve(&rp("src")).unwrap();
        let a = t.resolve(&rp("src/a.rs")).unwrap();
        let mut fx = Vec::new();
        t.apply(
            &Change::Rename {
                from: rp("src/a.rs"),
                to: rp("dst/b.rs"),
            },
            &mut fx,
        );
        let mv = Synth::Move {
            from_parent: src,
            from: nm("a.rs"),
            to_parent: dst,
            to: nm("b.rs"),
        };
        assert_eq!(
            fx,
            vec![
                Effect::InvalInode(src),
                Effect::InvalInode(dst),
                Effect::Synth(mv.clone())
            ]
        );
        assert_eq!(t.lookup(src, "a.rs").map(|(i, _)| i), Some(a));
        assert!(t.lookup(dst, "b.rs").is_none());
        assert_eq!(t.rel_path(a).unwrap().as_str(), "dst/b.rs");
        let mut vis = String::new();
        assert!(t.visible_path_of(a, &mut vis));
        assert_eq!(vis, "src/a.rs");
        let mut l = Vec::new();
        t.list(src, &mut l);
        assert_eq!(l, vec![(a, Some(nm("a.rs")))]);

        assert!(!t.complete_move(src, "a.rs", dst, "other"));
        assert!(t.complete_move(src, "a.rs", dst, "b.rs"));
        assert!(t.lookup(src, "a.rs").is_none());
        assert_eq!(t.lookup(dst, "b.rs").map(|(i, _)| i), Some(a));

        let mut fx = Vec::new();
        t.apply(
            &Change::Rename {
                from: rp("dst/b.rs"),
                to: rp("src/z.rs"),
            },
            &mut fx,
        );
        fx.clear();
        t.settle(
            &Synth::Move {
                from_parent: dst,
                from: nm("b.rs"),
                to_parent: src,
                to: nm("z.rs"),
            },
            &mut fx,
        );
        assert!(fx.contains(&Effect::InvalEntry(dst, nm("b.rs"))));
        assert!(fx.contains(&Effect::InvalEntry(src, nm("z.rs"))));
        assert_eq!(t.lookup(src, "z.rs").map(|(i, _)| i), Some(a));
    }

    fn entry(parent: u32, name: &str, meta: Meta) -> SnapEntry {
        SnapEntry {
            parent,
            name: nm(name),
            meta,
        }
    }

    #[test]
    fn snapshot_rejects_forward_parents_and_file_parents() {
        let mut t = GTree::new();
        let mut fx = Vec::new();
        assert!(
            t.apply_snapshot_part(
                &[entry(0, "a", dir()), entry(2, "b", file(1))],
                true,
                &mut fx
            )
            .is_err()
        );
        t.snapshot_reset();
        assert!(
            t.apply_snapshot_part(
                &[entry(0, "a", dir()), entry(1, "b", file(1))],
                false,
                &mut fx
            )
            .is_ok()
        );
        assert!(
            t.apply_snapshot_part(&[entry(3, "c", file(1))], true, &mut fx)
                .is_err()
        );
        t.snapshot_reset();
        assert!(
            t.apply_snapshot_part(
                &[entry(0, "f", file(1)), entry(1, "x", file(2))],
                true,
                &mut fx
            )
            .is_err()
        );
    }

    #[test]
    fn snapshot_diff_removes_missing_and_keeps_local() {
        let mut t = GTree::new();
        let mut fx = Vec::new();
        let parts = [
            entry(0, "a", dir()),
            entry(1, "x", file(1)),
            entry(0, "gone", file(2)),
        ];
        t.apply_snapshot_part(&parts, true, &mut fx).unwrap();
        assert!(fx.is_empty(), "the first load is silent");
        assert_eq!(t.files(), 3);
        let a = t.resolve(&rp("a")).unwrap();
        let local = t.insert(a, nm("target"), dir(), GDomain::Local, Vis::Live);
        t.set_mounted(true);
        t.apply_snapshot_part(&[entry(0, "a", dir())], false, &mut fx)
            .unwrap();
        t.apply_snapshot_part(&[entry(1, "x", file(5))], true, &mut fx)
            .unwrap();
        let x = t.resolve(&rp("a/x")).unwrap();
        assert!(fx.contains(&Effect::Synth(Synth::Modify { node: x })));
        assert!(fx.contains(&Effect::Synth(Synth::Delete {
            parent: ROOT,
            name: nm("gone"),
            dir: false
        })));
        assert_eq!(t.lookup(a, "target").map(|(i, _)| i), Some(local));
        let mut out = Vec::new();
        t.export(&mut |e| out.push(e));
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|e| e.name.as_str() != "target" && e.name.as_str() != "gone")
        );
    }

    #[test]
    fn snapshot_never_reverts_a_commit_acked_on_the_same_link() {
        let mut t = GTree::new();
        let mut fx = Vec::new();
        t.apply_snapshot_part(&[entry(0, "a", file(1))], true, &mut fx)
            .unwrap();
        t.clear_acked();
        // guest commits: a new version of a, and a new file b the snapshot below predates
        let a = t.resolve(&rp("a")).unwrap();
        up(&mut t, "a", file(2));
        up(&mut t, "b", file(3));
        let b = t.resolve(&rp("b")).unwrap();
        t.note_acked(a);
        t.note_acked(b);
        t.snapshot_reset();
        t.apply_snapshot_part(&[entry(0, "a", file(1))], true, &mut fx)
            .unwrap();
        assert_eq!(t.get(a).map(|n| n.meta.hash), Some(file(2).hash));
        assert_eq!(t.resolve(&rp("b")), Some(b));
        // once that snapshot is in, later ones apply in full again
        t.snapshot_reset();
        t.apply_snapshot_part(&[entry(0, "a", file(1))], true, &mut fx)
            .unwrap();
        assert_eq!(t.get(a).map(|n| n.meta.hash), Some(file(1).hash));
        assert!(t.resolve(&rp("b")).is_none());
    }

    #[test]
    fn nodeids_are_reused_only_after_forget() {
        let mut t = GTree::new();
        up(&mut t, "f", file(1));
        let f = t.resolve(&rp("f")).unwrap();
        let g0 = t.get(f).unwrap().r#gen;
        t.add_lookup(f);
        let mut fx = Vec::new();
        t.apply(&Change::Remove { path: rp("f") }, &mut fx);
        assert!(t.resolve(&rp("f")).is_none());
        assert!(
            t.get(f).is_some_and(|n| !n.attached()),
            "kernel-referenced node survives removal"
        );
        up(&mut t, "g", file(2));
        let g = t.resolve(&rp("g")).unwrap();
        assert_ne!(g, f);
        let mut s = String::new();
        assert!(!t.path_of(f, &mut s));
        t.forget(f, 1);
        assert!(t.get(f).is_none());
        up(&mut t, "h", file(3));
        let h = t.resolve(&rp("h")).unwrap();
        assert_eq!(h, f);
        assert!(t.get(h).unwrap().r#gen > g0);
        t.forget(ROOT, 10);
        assert!(t.get(ROOT).is_some());
    }

    #[test]
    fn domains_follow_host_meta_and_guest_rules() {
        let mut t = GTree::new();
        up(
            &mut t,
            ".git",
            Meta {
                git_ro: true,
                ..dir()
            },
        );
        up(
            &mut t,
            ".git/HEAD",
            Meta {
                git_ro: true,
                ..file(1)
            },
        );
        up(&mut t, "src", dir());
        let git = t.resolve(&rp(".git")).unwrap();
        assert_eq!(t.get(git).unwrap().domain, GDomain::GitRo);
        assert_eq!(
            t.get(t.resolve(&rp(".git/HEAD")).unwrap()).unwrap().domain,
            GDomain::GitRo
        );
        assert_eq!(
            t.get(t.resolve(&rp("src")).unwrap()).unwrap().domain,
            GDomain::Synced
        );

        assert_eq!(
            domain_for_new(GDomain::Synced, Class::Synced),
            Ok(GDomain::Synced)
        );
        assert_eq!(
            domain_for_new(GDomain::Synced, Class::Ignored),
            Ok(GDomain::Local)
        );
        assert_eq!(
            domain_for_new(GDomain::Local, Class::Synced),
            Ok(GDomain::Local)
        );
        assert_eq!(
            domain_for_new(GDomain::GitRo, Class::Ignored),
            Err(Refuse::ReadOnly)
        );
        assert_eq!(
            domain_for_new(GDomain::Synced, Class::GitRo),
            Err(Refuse::ReadOnly)
        );
        assert_eq!(
            domain_for_new(GDomain::Synced, Class::Internal),
            Err(Refuse::Invalid)
        );

        let src = t.resolve(&rp("src")).unwrap();
        t.insert(src, nm("out"), dir(), GDomain::Local, Vis::Live);
        t.set_mounted(true);
        let fx = up(&mut t, "src/out", dir());
        assert!(fx.contains(&Effect::LocalDiscarded(rp("src/out"))));
        let out = t.resolve(&rp("src/out")).unwrap();
        assert_eq!(t.get(out).unwrap().domain, GDomain::Synced);
        assert_eq!(t.get(out).unwrap().vis, Vis::PendingCreate);
        let mut fx = Vec::new();
        t.apply(
            &Change::Remove {
                path: rp("src/out"),
            },
            &mut fx,
        );
        assert!(fx.is_empty(), "a node the kernel never saw leaves silently");
        assert!(t.resolve(&rp("src/out")).is_none());
    }
}
