use crate::ignore::rules::Class;
use crate::proto::{
    Change, DEPTH_MAX, Expect, Hash32, IndexId, Kind, Meta, Name, RelPath, Seq, SnapEntry, VerKey,
    Version, check_snapshot_part,
};
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
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

// a guest-only fifo or socket: the kernel serves it, the tree only names it
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Special {
    #[default]
    None,
    Fifo,
    Socket,
}

pub struct GNode {
    pub parent: NodeId,
    pub name: Name,
    pub meta: Meta,
    // the host index seq of the entry this node last came from; 0 when unknown
    pub ver: Seq,
    pub domain: GDomain,
    pub vis: Vis,
    pub r#gen: u64,
    // bumped under the read lock so lookups and readdirplus never take the write lock
    pub nlookup: AtomicU64,
    pub open: AtomicU32,
    // read-only opens served from the page cache; only with none left may it move to another version
    pub cached: AtomicU32,
    // the host changed this file while mounted, so a version of it may be replaced before it is fetched
    pub edited: bool,
    pub read_ver: Option<Version>,
    // the blob the kernel page cache may hold for this inode; another one means the next open drops it
    pub page: Option<Hash32>,
    // the version that page cache was loaded for; sizes and cached reads come from it until the kernel drops it
    pub shown: Option<Version>,
    // writeback cache only: the kernel's size lacks the version just shown until a truncate begun after it returns
    pub size_gen: u32,
    pub size_pending: bool,
    pub staging: Option<u32>,
    // errno of a commit that failed after its last handle closed, for the next flush, fsync or write; 0 when none
    pub werr: i32,
    // a directory or link this guest made that the host has not answered yet: the pipe ticket of its mk (0 until
    // the push returns). the guest is the truth for it meanwhile, so host removes and sweeps leave it alone
    pub unacked: Option<u64>,
    pub special: Special,
    pub children: Option<Children>,
}

impl GNode {
    pub fn is_dir(&self) -> bool {
        self.meta.kind == Kind::Dir
    }

    // the one version the kernel's i_size and page cache describe
    pub fn kernel_ver(&self) -> Option<Version> {
        match (self.page, self.shown) {
            (Some(_), Some(v)) if self.meta.kind == Kind::File => Some(v),
            _ => self.meta.version(),
        }
    }

    // only just before the kernel drops this inode's attributes and pages
    pub fn show_current(&mut self) {
        if self.shown.is_some() {
            self.shown = self.meta.version();
            self.page = self.meta.hash;
        }
    }

    pub fn kernel_size(&self) -> u64 {
        match (self.page, self.shown) {
            (Some(_), Some(v)) if self.meta.kind == Kind::File => v.size,
            _ => self.meta.size,
        }
    }

    pub fn attached(&self) -> bool {
        self.parent != DETACHED
    }

    // a file whose content hash the host has not computed yet
    pub fn is_pending(&self) -> bool {
        self.meta.kind == Kind::File && self.meta.hash.is_none()
    }

    pub fn ver_key(&self, index: IndexId) -> Option<VerKey> {
        self.is_pending().then_some(VerKey {
            index,
            ver: self.ver,
            size: self.meta.size,
        })
    }

    // what a host operation on this node must find; a file is never matched with Any
    pub fn expect(&self, index: IndexId) -> Expect {
        match self.meta.kind {
            Kind::Dir => Expect::Dir,
            Kind::Symlink => Expect::Any,
            Kind::File => match self.meta.version() {
                Some(v) => Expect::Is(v),
                None => Expect::Ver(VerKey {
                    index,
                    ver: self.ver,
                    size: self.meta.size,
                }),
            },
        }
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
    // the last reader of an older version's page cache let go: move it to the current one
    Reshow(NodeId),
    InvalEntry(NodeId, Name),
    Synth(Synth),
    Warm(NodeId, Hash32),
    // like Warm for a file whose hash is not known yet
    WarmPending(NodeId),
    Unpin(Hash32),
    ConflictPending(NodeId),
    LocalDiscarded(RelPath),
    // guest-only entries under this directory may now belong on the host
    Promote(RelPath),
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
    // a pending host rename that replaced an entry: readers see the new node under the target name at
    // once, while the injector finds the kernel-known node it replaces (with its gen), so the replayed
    // rename unlinks that one (IN_ATTRIB, IN_DELETE_SELF); keyed by the moving node
    shadows: FxHashMap<NodeId, Option<(NodeId, u64)>>,
    snap: Option<Vec<NodeId>>,
    // commits the host acknowledged on the current link; a snapshot taken before them must not revert them
    acked: rustc_hash::FxHashSet<NodeId>,
    epoch: u32,
    deferred: Vec<Effect>,
    stack: Vec<NodeId>,
    // overlay hard links: the names of a node beyond its own parent and name
    links: FxHashMap<NodeId, Vec<(NodeId, Name)>>,
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
            ver: 0,
            domain: GDomain::Synced,
            vis: Vis::Live,
            r#gen: 1,
            nlookup: AtomicU64::new(1),
            open: AtomicU32::new(0),
            cached: AtomicU32::new(0),
            edited: false,
            read_ver: None,
            page: None,
            shown: None,
            size_gen: 0,
            size_pending: false,
            staging: None,
            werr: 0,
            unacked: None,
            special: Special::None,
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
            shadows: FxHashMap::default(),
            snap: None,
            acked: rustc_hash::FxHashSet::default(),
            epoch: 0,
            deferred: Vec::new(),
            stack: Vec::new(),
            links: FxHashMap::default(),
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

    // a host-created entry the injector has not announced yet, for a process that asks for it by name
    pub fn pending_create(&self, parent: NodeId, name: &str) -> Option<NodeId> {
        let id = self.child(parent, name)?;
        let n = self.get(id)?;
        (n.vis == Vis::PendingCreate && !self.moving.contains_key(&id)).then_some(id)
    }

    pub fn lookup(&self, parent: NodeId, name: &str) -> Option<(NodeId, &GNode)> {
        self.lookup_as(parent, name, false)
    }

    pub fn lookup_as(&self, parent: NodeId, name: &str, inj: bool) -> Option<(NodeId, &GNode)> {
        if let Some(id) = self.child(parent, name)
            && let Some(n) = self.get(id)
        {
            if !self.hidden(id, n) {
                return Some((id, n));
            }
            match self.shadows.get(&id) {
                Some(_) if !inj => return Some((id, n)),
                Some(&Some((r, g))) => {
                    if let Some(rn) = self.get(r)
                        && rn.r#gen == g
                        && !rn.attached()
                    {
                        return Some((r, rn));
                    }
                }
                _ => {}
            }
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
        let linked = !self.links.is_empty();
        for (name, &id) in kids {
            if let Some(n) = self.get(id)
                && (!self.hidden(id, n) || self.shadows.contains_key(&id))
            {
                let alias = linked && (n.parent != dir || n.name != *name);
                out.push((id, alias.then(|| name.clone())));
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
            self.detach_at(old, parent, name.as_str(), &mut fx);
            self.deferred = fx;
        }
        let children = (meta.kind == Kind::Dir).then(Children::default);
        let node = GNode {
            parent,
            name: name.clone(),
            meta,
            ver: 0,
            domain,
            vis,
            r#gen: 0,
            nlookup: AtomicU64::new(0),
            open: AtomicU32::new(0),
            cached: AtomicU32::new(0),
            edited: false,
            read_ver: None,
            page: None,
            shown: None,
            size_gen: 0,
            size_pending: false,
            staging: None,
            werr: 0,
            unacked: None,
            special: Special::None,
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
                self.shadows.remove(&x);
            }
            let Some(n) = self.get_mut(x) else { continue };
            if !n.attached() {
                continue;
            }
            n.parent = DETACHED;
            n.vis = Vis::Live;
            let kids = n.children.as_mut().map(std::mem::take);
            if *n.open.get_mut() == 0
                && let Some(v) = n.read_ver.take()
            {
                fx.push(Effect::Unpin(v.hash));
            }
            let free = *n.nlookup.get_mut() == 0 && *n.open.get_mut() == 0;
            self.attached = self.attached.saturating_sub(1);
            self.drop_links(x);
            if let Some(k) = kids {
                for (name, kid) in k {
                    if !self.drop_alias(kid, x, name.as_str()) {
                        stack.push(kid);
                    }
                }
            }
            if free {
                self.release_slot(x);
            }
        }
        self.stack = stack;
    }

    // removes one name of a node; the node itself goes only with its last name
    fn detach_at(&mut self, id: NodeId, parent: NodeId, name: &str, fx: &mut Vec<Effect>) {
        if !self.drop_alias(id, parent, name) {
            self.detach(id, fx);
        }
    }

    pub fn remove_at(&mut self, id: NodeId, parent: NodeId, name: &str) {
        let mut fx = std::mem::take(&mut self.deferred);
        self.detach_at(id, parent, name, &mut fx);
        self.deferred = fx;
    }

    pub fn has_links(&self, id: NodeId) -> bool {
        self.links.contains_key(&id)
    }

    // a hard link in the overlay: one more name for an attached non-directory node
    pub fn add_link(&mut self, id: NodeId, parent: NodeId, name: Name) -> bool {
        let ok = self.get(id).is_some_and(|n| n.attached() && !n.is_dir())
            && self
                .get(parent)
                .is_some_and(|p| p.attached() && p.children.is_some())
            && self.child(parent, name.as_str()).is_none();
        if !ok {
            return false;
        }
        if let Some(k) = self.get_mut(parent).and_then(|p| p.children.as_mut()) {
            k.insert(name.clone(), id);
        }
        self.links.entry(id).or_default().push((parent, name));
        true
    }

    // true when (parent, name) was one of several names of id and only that name went away
    fn drop_alias(&mut self, id: NodeId, parent: NodeId, name: &str) -> bool {
        let Some(mut extra) = self.links.remove(&id) else {
            return false;
        };
        let primary = self
            .get(id)
            .is_some_and(|n| n.parent == parent && n.name.as_str() == name);
        let gone = if primary {
            // the first other name still present in its directory becomes the node's own
            let mut next = None;
            while !extra.is_empty() {
                let (p, nm) = extra.remove(0);
                if self.child(p, nm.as_str()) == Some(id)
                    && self.get(p).is_some_and(|d| d.attached())
                {
                    next = Some((p, nm));
                    break;
                }
            }
            match next {
                Some((p, nm)) => {
                    if let Some(n) = self.get_mut(id) {
                        n.parent = p;
                        n.name = nm;
                    }
                    true
                }
                None => false,
            }
        } else {
            let at = extra
                .iter()
                .position(|(p, nm)| *p == parent && nm.as_str() == name);
            at.map(|i| extra.remove(i)).is_some()
        };
        if gone
            && let Some(k) = self.get_mut(parent).and_then(|p| p.children.as_mut())
            && k.get(name) == Some(&id)
        {
            k.remove(name);
        }
        if !extra.is_empty() {
            self.links.insert(id, extra);
        }
        gone
    }

    // a node going away takes its other names with it
    fn drop_links(&mut self, id: NodeId) {
        let Some(extra) = self.links.remove(&id) else {
            return;
        };
        for (p, nm) in extra {
            if let Some(k) = self.get_mut(p).and_then(|d| d.children.as_mut())
                && k.get(nm.as_str()) == Some(&id)
            {
                k.remove(nm.as_str());
            }
        }
    }

    // renameat2(RENAME_EXCHANGE) of two overlay names
    pub fn exchange(&mut self, a: (NodeId, NodeId, &Name), b: (NodeId, NodeId, &Name)) -> bool {
        let ((ia, pa, na), (ib, pb, nb)) = (a, b);
        let ok = self.child(pa, na.as_str()) == Some(ia)
            && self.child(pb, nb.as_str()) == Some(ib)
            && ia != ib
            && !self.is_within(pb, ia)
            && !self.is_within(pa, ib);
        if !ok {
            return false;
        }
        if let Some(k) = self.get_mut(pa).and_then(|p| p.children.as_mut()) {
            k.insert(na.clone(), ib);
        }
        if let Some(k) = self.get_mut(pb).and_then(|p| p.children.as_mut()) {
            k.insert(nb.clone(), ia);
        }
        self.rename_name(ia, (pa, na), (pb, nb.clone()));
        self.rename_name(ib, (pb, nb), (pa, na.clone()));
        true
    }

    // points whichever name of id was (from) at (to); the children maps are the caller's
    fn rename_name(&mut self, id: NodeId, from: (NodeId, &Name), to: (NodeId, Name)) {
        if let Some(extra) = self.links.get_mut(&id)
            && let Some(e) = extra
                .iter_mut()
                .find(|(p, nm)| *p == from.0 && nm == from.1)
        {
            *e = to;
            return;
        }
        if let Some(n) = self.get_mut(id) {
            n.parent = to.0;
            n.name = to.1;
        }
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
        if *left == 0 && *node.open.get_mut() == 0 && !node.attached() {
            self.release_slot(id);
        }
    }

    // true when this forget took a node nothing else holds to zero; reap() then frees it under the write lock
    pub fn drop_lookups(&self, id: NodeId, n: u64) -> bool {
        if id == ROOT {
            return false;
        }
        let Some(node) = self.get(id) else {
            return false;
        };
        // fetch_update is deprecated and try_update is past the msrv
        let mut cur = node.nlookup.load(Relaxed);
        loop {
            match node
                .nlookup
                .compare_exchange_weak(cur, cur.saturating_sub(n), Relaxed, Relaxed)
            {
                Ok(_) => break,
                Err(seen) => cur = seen,
            }
        }
        cur.saturating_sub(n) == 0 && node.open.load(Relaxed) == 0 && !node.attached()
    }

    pub fn add_lookup(&self, id: NodeId) {
        if let Some(n) = self.get(id) {
            n.nlookup.fetch_add(1, Relaxed);
        }
    }

    // counted under the read lock like nlookup, so opens and closes never take the write lock
    pub fn add_open(&self, id: NodeId) {
        if let Some(n) = self.get(id) {
            n.open.fetch_add(1, Relaxed);
        }
    }

    // true when that was the last open of a node nothing else holds; reap() then frees it under the write lock
    pub fn drop_open(&self, id: NodeId) -> bool {
        let Some(n) = self.get(id) else { return false };
        let mut was = n.open.load(Relaxed);
        while was > 0 {
            match n.open.compare_exchange_weak(was, was - 1, Relaxed, Relaxed) {
                Ok(_) => break,
                Err(v) => was = v,
            }
        }
        was <= 1 && n.nlookup.load(Relaxed) == 0 && !n.attached()
    }

    pub fn reap(&mut self, id: NodeId) {
        let Some(n) = self.get_mut(id) else { return };
        if *n.open.get_mut() == 0 && *n.nlookup.get_mut() == 0 && !n.attached() {
            self.release_slot(id);
        }
    }

    // guest-originated rename of the name `from` after the host (or the overlay) accepted it
    pub fn relink(
        &mut self,
        id: NodeId,
        from: (NodeId, &str),
        to_parent: NodeId,
        to: Name,
    ) -> bool {
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
            self.detach_at(old, to_parent, to.as_str(), &mut fx);
        }
        self.deferred = fx;
        let alias = (fp, fname.as_str()) != from
            && self.links.get(&id).is_some_and(|v| {
                v.iter()
                    .any(|(p, nm)| *p == from.0 && nm.as_str() == from.1)
            });
        if alias {
            if let Some(k) = self.get_mut(from.0).and_then(|p| p.children.as_mut())
                && k.get(from.1) == Some(&id)
            {
                k.remove(from.1);
            }
            if let Some(k) = self.get_mut(to_parent).and_then(|p| p.children.as_mut()) {
                k.insert(to.clone(), id);
            }
            if let Some(e) = self.links.get_mut(&id).and_then(|v| {
                v.iter_mut()
                    .find(|(p, nm)| *p == from.0 && nm.as_str() == from.1)
            }) {
                *e = (to_parent, to);
            }
            return true;
        }
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
            self.shadows.remove(&id);
            fx.push(Effect::InvalEntry(p, name));
            fx.push(Effect::InvalInode(p));
        }
    }

    pub fn apply(&mut self, c: &Change, fx: &mut Vec<Effect>) {
        fx.append(&mut self.deferred);
        match c {
            Change::Upsert { path, meta, ver } => {
                if let Some((p, name)) = self.resolve_parent(path) {
                    self.upsert_at(p, name, meta.clone(), *ver, fx);
                }
            }
            // the guest's own mk lands after this remove, so the entry it made stays
            Change::Remove { path } => {
                if let Some(id) = self.resolve(path)
                    && !self.get(id).is_some_and(|n| n.unacked.is_some())
                {
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
        ver: Seq,
        fx: &mut Vec<Effect>,
    ) -> Option<NodeId> {
        let id = self.upsert_node(parent, name, meta, ver, fx)?;
        if let Some(n) = self.get_mut(id) {
            n.ver = ver;
        }
        Some(id)
    }

    fn upsert_node(
        &mut self,
        parent: NodeId,
        name: &str,
        meta: Meta,
        ver: Seq,
        fx: &mut Vec<Effect>,
    ) -> Option<NodeId> {
        if !self
            .get(parent)
            .is_some_and(|p| p.attached() && p.children.is_some())
        {
            return None;
        }
        match self.child(parent, name) {
            Some(id) => self.update(id, parent, name, meta, ver, fx),
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
                    if let Some(n) = self.get_mut(id) {
                        n.edited = true;
                    }
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
        mut meta: Meta,
        ver: Seq,
        fx: &mut Vec<Effect>,
    ) -> Option<NodeId> {
        let on = self.mounted;
        let n = self.get(id)?;
        if n.domain == GDomain::Local && n.is_dir() && meta.kind == Kind::Dir {
            // the host made the same directory: both sides' entries stay, and the guest's now-synced ones go up
            let path = self.rel_path(id);
            let n = self.get_mut(id)?;
            n.domain = domain_of(&meta);
            n.meta = meta;
            if on {
                fx.push(Effect::InvalInode(id));
            }
            if let Some(p) = path {
                fx.push(Effect::Promote(p));
            }
            return Some(id);
        }
        if n.domain == GDomain::Local {
            // the host now has this path, so the guest-only copy loses
            let path = Name::new(name)
                .ok()
                .and_then(|nm| self.rel_path(parent)?.join(&nm).ok());
            self.detach_at(id, parent, name, fx);
            if on {
                fx.push(Effect::InvalEntry(parent, Name::new(name).ok()?));
            }
            if let Some(p) = path {
                fx.push(Effect::LocalDiscarded(p));
            }
            return self.upsert_node(parent, name, meta, ver, fx);
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
        // the same host entry seen again without its hash is the content already learned
        if meta.hash.is_none() && ver != 0 && n.ver == ver && n.meta.size == meta.size {
            meta.hash = n.meta.hash;
        }
        let hash_moved = match (n.meta.hash, meta.hash) {
            (Some(a), Some(b)) => a != b,
            _ => meta.kind == Kind::File && n.ver != ver,
        };
        let content = hash_moved || n.meta.size != meta.size || n.meta.link != meta.link;
        let perm = n.meta.perm != meta.perm;
        let mtime = n.meta.mtime_ns != meta.mtime_ns;
        let times = mtime || n.meta.ctime_ns != meta.ctime_ns;
        let gitro = n.meta.git_ro != meta.git_ro;
        let was = n.vis;
        let warm = content
            && meta.kind == Kind::File
            && (n.open.load(Relaxed) > 0 || n.read_ver.is_some());
        let conflict = content && n.staging.is_some();
        let show = on && was == Vis::Live && self.reachable(id);
        let kind = meta.kind;
        let hash = meta.hash;
        let n = self.get_mut(id)?;
        n.domain = domain_of(&meta);
        n.meta = meta;
        n.edited |= on && content;
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
                // a ctime-only change (a rename, a link) raises no IN_ATTRIB natively either
                Kind::File if perm || mtime => fx.push(Effect::Synth(Synth::Attrib { node: id })),
                Kind::Dir if perm => fx.push(Effect::Synth(Synth::Attrib { node: id })),
                _ => {}
            }
        }
        if warm {
            match hash {
                Some(h) => fx.push(Effect::Warm(id, h)),
                None => fx.push(Effect::WarmPending(id)),
            }
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
            if dir {
                self.delete_known_kids(id, fx);
            }
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

    // a host subtree removal is deleted bottom-up like rm -r; a watch pins its inode, so only
    // directories the kernel knows can have watchers that would see their entries go
    fn delete_known_kids(&mut self, dir: NodeId, fx: &mut Vec<Effect>) {
        let mut found: Vec<(NodeId, NodeId, Name, bool)> = Vec::new();
        let mut walk = vec![dir];
        while let Some(d) = walk.pop() {
            let Some(n) = self.get(d) else { continue };
            if n.nlookup.load(Relaxed) == 0 {
                continue;
            }
            let Some(kids) = n.children.as_ref() else {
                continue;
            };
            for (name, &kid) in kids {
                let Some(k) = self.get(kid) else { continue };
                if k.vis != Vis::Live || k.parent != d || k.domain == GDomain::Local {
                    continue;
                }
                let isdir = k.is_dir();
                found.push((kid, d, name.clone(), isdir));
                if isdir {
                    walk.push(kid);
                }
            }
        }
        for (kid, parent, name, dir) in found.into_iter().rev() {
            if let Some(n) = self.get_mut(kid) {
                n.vis = Vis::PendingDelete;
            }
            fx.push(Effect::Synth(Synth::Delete { parent, name, dir }));
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
        let mut shadow = None;
        if let Some(r) = self.child(tp, tname.as_str())
            && r != id
        {
            shadow = Some(
                self.get(r)
                    .filter(|n| n.vis == Vis::Live && n.nlookup.load(Relaxed) > 0)
                    .map(|n| (r, n.r#gen)),
            );
            self.detach_at(r, tp, tname.as_str(), fx);
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
            if let Some(s) = shadow {
                self.shadows.insert(id, s);
            }
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
        self.shadows.remove(&id);
        true
    }

    // a pending file learning its hash is not a content change: no invalidation and no injected event
    pub fn learn_hash(&mut self, id: NodeId, ver: Seq, h: Hash32) -> bool {
        let Some(n) = self.get_mut(id) else {
            return false;
        };
        let fits = n.is_pending() && n.ver == ver && n.domain != GDomain::Local && n.attached();
        if fits {
            n.meta.hash = Some(h);
        }
        fits
    }

    pub fn pending_list(&self, max: usize) -> Vec<(NodeId, RelPath, Seq)> {
        let mut out = Vec::new();
        for (i, s) in self.slots.iter().enumerate() {
            if out.len() >= max {
                break;
            }
            let id = i as NodeId + 1;
            let Some(n) = s.node.as_ref() else { continue };
            if !n.is_pending() || !n.attached() || n.domain == GDomain::Local {
                continue;
            }
            if let Some(p) = self.rel_path(id) {
                out.push((id, p, n.ver));
            }
        }
        out
    }

    // only a node with an open handle has someone to tell; true when it had no error waiting before
    pub fn set_werr(&mut self, id: NodeId, errno: i32) -> bool {
        match self.get_mut(id) {
            Some(n) if n.open.load(std::sync::atomic::Ordering::Relaxed) > 0 => {
                let fresh = n.werr == 0;
                n.werr = errno;
                fresh
            }
            _ => false,
        }
    }

    // handed out once
    pub fn take_werr(&mut self, id: NodeId) -> i32 {
        self.get_mut(id).map_or(0, |n| std::mem::take(&mut n.werr))
    }

    // removes a refused entry with everything below it, bottom-up. returns the staging ids the writer must drop and
    // how many nodes with an open handle got errno as a late write error
    pub fn rollback(&mut self, id: NodeId, errno: i32, fx: &mut Vec<Effect>) -> (Vec<u32>, u32) {
        let mut order = Vec::new();
        let mut walk = vec![id];
        while let Some(x) = walk.pop() {
            let Some(n) = self.get(x) else { continue };
            order.push(x);
            for (name, &k) in n.children.iter().flatten() {
                if self
                    .get(k)
                    .is_some_and(|c| c.parent == x && c.name == *name)
                {
                    walk.push(k);
                }
            }
        }
        let (mut staging, mut told) = (Vec::new(), 0);
        for &x in order.iter().rev() {
            if self.set_werr(x, errno) {
                told += 1;
            }
            let Some(n) = self.get_mut(x) else { continue };
            n.unacked = None;
            if let Some(s) = n.staging.take() {
                staging.push(s);
            }
            if n.attached() {
                fx.push(Effect::InvalEntry(n.parent, n.name.clone()));
            }
            fx.push(Effect::InvalInode(x));
        }
        if let Some(n) = self.get(id).filter(|n| n.attached()) {
            fx.push(Effect::InvalInode(n.parent));
        }
        self.remove(id);
        (staging, told)
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
                Some(id)
                    if self.acked.contains(&id)
                        || self.get(id).is_some_and(|n| n.unacked.is_some()) =>
                {
                    id
                }
                _ => self
                    .upsert_at(parent, e.name.as_str(), e.meta.clone(), e.ver, fx)
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
        // a file with a write in flight, or a directory or link whose mk is unanswered, may not be on the host yet;
        // it and its directories stay until the host answers
        let mut keep = rustc_hash::FxHashSet::default();
        for (i, s) in self.slots.iter().enumerate() {
            let id = i as NodeId + 1;
            if s.node.as_ref().is_some_and(|n| {
                n.attached()
                    && (n.staging.is_some() || n.unacked.is_some() || self.acked.contains(&id))
            }) {
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
                    ver: n.ver,
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
        t.apply(
            &Change::Upsert {
                path: rp(p),
                meta,
                ver: 0,
            },
            &mut fx,
        );
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

    fn deletes(fx: &[Effect]) -> Vec<String> {
        fx.iter()
            .filter_map(|e| match e {
                Effect::Synth(Synth::Delete { name, .. }) => Some(name.as_str().to_owned()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn removed_dir_deletes_known_entries_bottom_up() {
        let mut t = mounted_tree();
        for (p, m) in [
            ("src/d", dir()),
            ("src/d/e", dir()),
            ("src/d/e/f", file(5)),
            ("src/d/g", file(6)),
            ("src/d/u", dir()),
            ("src/d/u/x", file(7)),
        ] {
            up(&mut t, p, m);
            let (dir, name) = rp(p)
                .split_last()
                .map(|(d, n)| (d.to_owned(), n.to_owned()))
                .unwrap();
            let parent = t.resolve(&rp(&dir)).unwrap();
            t.complete_create(parent, &name);
        }
        for p in ["src/d", "src/d/e"] {
            t.add_lookup(t.resolve(&rp(p)).unwrap());
        }
        let mut fx = Vec::new();
        t.apply(&Change::Remove { path: rp("src/d") }, &mut fx);
        let d = deletes(&fx);
        let at = |n: &str| {
            d.iter()
                .position(|x| x == n)
                .unwrap_or_else(|| panic!("{n}: {d:?}"))
        };
        assert!(at("f") < at("e") && at("e") < at("d") && at("g") < at("d") && at("u") < at("d"));
        assert!(
            !d.iter().any(|x| x == "x"),
            "a directory the kernel never looked up has no watchers"
        );
        let src = t.resolve(&rp("src")).unwrap();
        assert_eq!(
            t.lookup(src, "d").map(|(_, n)| n.vis),
            Some(Vis::PendingDelete)
        );
        let e = t.resolve(&rp("src/d/e")).unwrap();
        assert!(t.complete_delete(e, "f"));
        assert!(t.complete_delete(t.resolve(&rp("src/d")).unwrap(), "e"));
    }

    #[test]
    fn ctime_only_change_raises_no_attrib() {
        let mut t = mounted_tree();
        let mut m = file(1);
        m.ctime_ns = 99;
        let fx = up(&mut t, "src/a.rs", m.clone());
        assert!(!fx.iter().any(|e| matches!(e, Effect::Synth(_))), "{fx:?}");
        m.mtime_ns = 100;
        let fx = up(&mut t, "src/a.rs", m);
        assert!(
            fx.iter()
                .any(|e| matches!(e, Effect::Synth(Synth::Attrib { .. })))
        );
    }

    #[test]
    fn rename_over_keeps_the_replaced_node_visible_until_injected() {
        let mut t = mounted_tree();
        let src = t.resolve(&rp("src")).unwrap();
        up(&mut t, "src/b.rs", file(2));
        t.complete_create(src, "b.rs");
        let a = t.resolve(&rp("src/a.rs")).unwrap();
        let b = t.resolve(&rp("src/b.rs")).unwrap();
        t.add_lookup(b);
        let mut fx = Vec::new();
        t.apply(
            &Change::Rename {
                from: rp("src/a.rs"),
                to: rp("src/b.rs"),
            },
            &mut fx,
        );
        // readers get the new file at once; the injector's rename finds the inode it replaces
        assert_eq!(t.lookup(src, "b.rs").map(|(i, _)| i), Some(a));
        assert_eq!(t.lookup_as(src, "b.rs", true).map(|(i, _)| i), Some(b));
        assert_eq!(t.lookup(src, "a.rs").map(|(i, _)| i), Some(a));
        let mut l = Vec::new();
        t.list(src, &mut l);
        assert!(
            l.contains(&(a, None)) && l.contains(&(a, Some(nm("a.rs")))),
            "{l:?}"
        );
        assert!(t.complete_move(src, "a.rs", src, "b.rs"));
        assert_eq!(t.lookup_as(src, "b.rs", true).map(|(i, _)| i), Some(a));
    }

    fn entry(parent: u32, name: &str, meta: Meta) -> SnapEntry {
        SnapEntry {
            parent,
            name: nm(name),
            meta,
            ver: 0,
        }
    }

    #[test]
    fn upserts_and_snapshots_store_the_host_ver() {
        let mut t = GTree::new();
        let mut fx = Vec::new();
        let upsert = |t: &mut GTree, p: &str, meta: Meta, ver: Seq, fx: &mut Vec<Effect>| {
            t.apply(
                &Change::Upsert {
                    path: rp(p),
                    meta,
                    ver,
                },
                fx,
            );
        };
        upsert(&mut t, "src", dir(), 4, &mut fx);
        upsert(&mut t, "src/a.rs", file(1), 5, &mut fx);
        let a = t.resolve(&rp("src/a.rs")).unwrap();
        assert_eq!(
            t.get(t.resolve(&rp("src")).unwrap()).map(|n| n.ver),
            Some(4)
        );
        assert_eq!(t.get(a).map(|n| n.ver), Some(5));
        upsert(&mut t, "src/a.rs", file(2), 9, &mut fx);
        assert_eq!(t.get(a).map(|n| n.ver), Some(9));

        let mut out = Vec::new();
        t.export(&mut |e| out.push((e.name.as_str().to_owned(), e.ver)));
        assert_eq!(out, vec![("src".to_owned(), 4), ("a.rs".to_owned(), 9)]);

        let mut s = GTree::new();
        let mut snap = vec![entry(0, "d", dir()), entry(1, "f", file(3))];
        snap[0].ver = 11;
        snap[1].ver = 12;
        s.apply_snapshot_part(&snap, true, &mut fx).unwrap();
        let f = s.resolve(&rp("d/f")).unwrap();
        assert_eq!(s.get(f).map(|n| n.ver), Some(12));
        assert_eq!(s.get(s.resolve(&rp("d")).unwrap()).map(|n| n.ver), Some(11));
    }

    fn pending(tag: u8) -> Meta {
        Meta {
            hash: None,
            ..file(tag)
        }
    }

    fn upv(t: &mut GTree, p: &str, meta: Meta, ver: Seq) -> Vec<Effect> {
        let mut fx = Vec::new();
        t.apply(
            &Change::Upsert {
                path: rp(p),
                meta,
                ver,
            },
            &mut fx,
        );
        fx
    }

    #[test]
    fn learn_hash_needs_the_matching_ver_and_is_not_a_content_change() {
        let mut t = GTree::new();
        upv(&mut t, "f", pending(3), 7);
        let f = t.resolve(&rp("f")).unwrap();
        t.set_mounted(true);
        assert!(t.get(f).unwrap().is_pending());
        assert!(!t.learn_hash(f, 8, [3; 32]));
        assert!(t.get(f).unwrap().is_pending());
        assert!(!t.learn_hash(ROOT, 0, [3; 32]));
        assert!(!t.learn_hash(999, 7, [3; 32]));

        assert!(t.learn_hash(f, 7, [3; 32]));
        assert_eq!(t.get(f).unwrap().meta.hash, Some([3; 32]));
        assert!(!t.get(f).unwrap().is_pending());
        assert!(
            !t.learn_hash(f, 7, [9; 32]),
            "a known hash is never replaced"
        );
        assert_eq!(t.get(f).unwrap().meta.hash, Some([3; 32]));

        // the host announcing the same entry again, with or without the hash, changes nothing
        assert!(upv(&mut t, "f", pending(3), 7).is_empty());
        assert_eq!(t.get(f).unwrap().meta.hash, Some([3; 32]));
        assert!(upv(&mut t, "f", file(3), 7).is_empty());
    }

    #[test]
    fn a_pending_upsert_is_a_content_change_only_with_a_new_ver() {
        let mut t = GTree::new();
        upv(&mut t, "src", dir(), 1);
        upv(&mut t, "src/a", pending(3), 5);
        let a = t.resolve(&rp("src/a")).unwrap();
        t.set_mounted(true);

        assert!(upv(&mut t, "src/a", pending(3), 5).is_empty());
        assert!(
            upv(&mut t, "src/a", file(3), 5).is_empty(),
            "known hash, same ver"
        );
        let fx = upv(&mut t, "src/a", pending(3), 6);
        assert_eq!(
            fx,
            vec![
                Effect::InvalInode(a),
                Effect::Synth(Synth::Modify { node: a })
            ]
        );
        assert_eq!(t.get(a).unwrap().ver, 6);

        // an open reader gets a warm hint for the pending file instead of a hash
        t.get_mut(a).unwrap().read_ver = Some(Version {
            hash: [3; 32],
            size: 3,
        });
        let fx = upv(&mut t, "src/a", pending(3), 7);
        assert!(fx.contains(&Effect::WarmPending(a)), "{fx:?}");
        assert!(!fx.iter().any(|e| matches!(e, Effect::Warm(..))));

        // two known hashes still decide by hash alone
        let mut t = mounted_tree();
        let a = t.resolve(&rp("src/a.rs")).unwrap();
        assert!(upv(&mut t, "src/a.rs", file(1), 40).is_empty());
        assert!(upv(&mut t, "src/a.rs", file(2), 40).contains(&Effect::InvalInode(a)));
    }

    #[test]
    fn directory_upserts_with_a_new_ver_are_not_content_changes() {
        let mut t = GTree::new();
        upv(&mut t, "src", dir(), 1);
        t.set_mounted(true);
        assert!(upv(&mut t, "src", dir(), 2).is_empty());
    }

    #[test]
    fn expect_names_the_version_a_node_is_known_by() {
        let mut t = GTree::new();
        upv(&mut t, "known", file(1), 2);
        upv(&mut t, "pend", pending(4), 3);
        upv(&mut t, "d", dir(), 4);
        upv(
            &mut t,
            "s",
            Meta {
                kind: Kind::Symlink,
                ..file(1)
            },
            5,
        );
        let n = |name: &str| t.get(t.resolve(&rp(name)).unwrap()).unwrap();
        assert_eq!(
            n("known").expect(9),
            Expect::Is(Version {
                hash: [1; 32],
                size: 1
            })
        );
        let key = VerKey {
            index: 9,
            ver: 3,
            size: 4,
        };
        assert_eq!(n("pend").expect(9), Expect::Ver(key));
        assert_eq!(n("pend").ver_key(9), Some(key));
        assert_eq!(n("known").ver_key(9), None);
        assert_eq!(n("d").ver_key(9), None);
        assert_eq!(n("d").expect(9), Expect::Dir);
        assert_eq!(n("s").expect(9), Expect::Any);
        assert!(n("pend").is_pending() && !n("known").is_pending() && !n("d").is_pending());
        for f in ["known", "pend"] {
            assert_ne!(n(f).expect(9), Expect::Any);
        }
    }

    #[test]
    fn pending_list_is_in_node_order_bounded_and_skips_guest_only_files() {
        let mut t = GTree::new();
        upv(&mut t, "d", dir(), 1);
        upv(&mut t, "d/p1", pending(1), 10);
        upv(&mut t, "known", file(2), 11);
        upv(&mut t, "p2", pending(3), 12);
        upv(&mut t, "d/p3", pending(4), 13);
        let d = t.resolve(&rp("d")).unwrap();
        t.insert(d, nm("local"), pending(5), GDomain::Local, Vis::Live);
        let id = |p: &str| t.resolve(&rp(p)).unwrap();
        let all = t.pending_list(100);
        assert_eq!(
            all,
            vec![
                (id("d/p1"), rp("d/p1"), 10),
                (id("p2"), rp("p2"), 12),
                (id("d/p3"), rp("d/p3"), 13)
            ]
        );
        assert_eq!(t.pending_list(2), all[..2].to_vec());
        assert!(t.pending_list(0).is_empty());
    }

    #[test]
    fn snapshot_parts_keep_the_ver_of_pending_entries() {
        let mut t = GTree::new();
        let mut fx = Vec::new();
        let mut e = entry(0, "f", pending(2));
        e.ver = 21;
        t.apply_snapshot_part(&[e.clone()], true, &mut fx).unwrap();
        let f = t.resolve(&rp("f")).unwrap();
        assert_eq!(t.get(f).map(|n| (n.ver, n.is_pending())), Some((21, true)));
        assert!(t.learn_hash(f, 21, [2; 32]));
        t.snapshot_reset();
        t.apply_snapshot_part(&[e], true, &mut fx).unwrap();
        assert_eq!(t.get(f).unwrap().meta.hash, Some([2; 32]));
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

    // a commit that failed after the last close is told to the next flush, fsync or write, once
    #[test]
    fn a_late_write_error_is_handed_out_once() {
        let mut t = GTree::new();
        up(&mut t, "f", file(1));
        let f = t.resolve(&rp("f")).unwrap();
        t.add_open(f);
        assert!(t.set_werr(f, libc::ECANCELED));
        assert_eq!(t.take_werr(f), libc::ECANCELED);
        assert_eq!(t.take_werr(f), 0);
        assert!(
            t.set_werr(f, libc::EIO),
            "a taken error leaves room for the next"
        );
        assert!(
            !t.set_werr(f, libc::ECANCELED),
            "one still waiting is replaced"
        );
        assert_eq!(t.take_werr(f), libc::ECANCELED);
    }

    #[test]
    fn a_late_write_error_needs_a_handle_to_tell() {
        let mut t = GTree::new();
        up(&mut t, "f", file(1));
        let f = t.resolve(&rp("f")).unwrap();
        assert!(!t.set_werr(f, libc::ECANCELED));
        assert_eq!(t.take_werr(f), 0);
        assert!(!t.set_werr(DETACHED + 4096, libc::EIO));
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
    fn a_shared_forget_asks_for_the_slot_only_at_zero_unattached_and_unopened() {
        let mut t = GTree::new();
        up(&mut t, "f", file(1));
        let f = t.resolve(&rp("f")).unwrap();
        t.add_lookup(f);
        t.add_lookup(f);
        assert!(!t.drop_lookups(f, 1), "one lookup is still held");
        assert!(!t.drop_lookups(f, 1), "an attached node stays");
        assert!(t.get(f).is_some());
        t.add_lookup(f);
        t.add_open(f);
        let mut fx = Vec::new();
        t.apply(&Change::Remove { path: rp("f") }, &mut fx);
        assert!(t.get(f).is_some_and(|n| !n.attached()));
        assert!(!t.drop_lookups(f, 1), "an open handle keeps the slot");
        assert!(t.drop_open(f), "the last close asks for the slot");
        t.reap(f);
        assert!(t.get(f).is_none());

        up(&mut t, "g", file(2));
        let g = t.resolve(&rp("g")).unwrap();
        t.add_lookup(g);
        t.apply(&Change::Remove { path: rp("g") }, &mut fx);
        assert!(t.get(g).is_some());
        assert!(
            t.drop_lookups(g, 5),
            "an oversized forget saturates at zero"
        );
        t.reap(g);
        assert!(t.get(g).is_none());
        assert!(!t.drop_lookups(g, 1), "a freed slot is not asked for twice");
        assert!(!t.drop_lookups(ROOT, 10));
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

        // the host making a directory the guest has only locally merges the two: nothing guest-only is lost
        let src = t.resolve(&rp("src")).unwrap();
        let mine = t.insert(src, nm("mine"), dir(), GDomain::Local, Vis::Live);
        let kept = t.insert(mine, nm("g.txt"), file(9), GDomain::Local, Vis::Live);
        t.set_mounted(true);
        let fx = up(&mut t, "src/mine", dir());
        assert_eq!(t.resolve(&rp("src/mine")), Some(mine));
        assert_eq!(t.get(mine).unwrap().domain, GDomain::Synced);
        assert_eq!(t.resolve(&rp("src/mine/g.txt")), Some(kept));
        assert!(fx.contains(&Effect::Promote(rp("src/mine"))));
        assert!(!fx.iter().any(|e| matches!(e, Effect::LocalDiscarded(_))));

        // a guest-only file the host also makes loses to the host copy
        t.insert(src, nm("out"), file(3), GDomain::Local, Vis::Live);
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

    fn names(t: &GTree, dir: NodeId) -> Vec<(NodeId, String)> {
        let mut l = Vec::new();
        t.list(dir, &mut l);
        let mut v: Vec<_> = l
            .into_iter()
            .map(|(id, g)| {
                let n = g.unwrap_or_else(|| t.get(id).unwrap().name.clone());
                (id, n.as_str().to_owned())
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn overlay_links_share_one_node_until_the_last_name_goes() {
        let mut t = GTree::new();
        let tg = t.insert(ROOT, nm("target"), dir(), GDomain::Local, Vis::Live);
        let sub = t.insert(tg, nm("sub"), dir(), GDomain::Local, Vis::Live);
        let a = t.insert(tg, nm("a"), file(1), GDomain::Local, Vis::Live);
        assert!(t.add_link(a, sub, nm("b")));
        assert!(t.add_link(a, tg, nm("c")));
        assert!(!t.add_link(a, tg, nm("c")), "a taken name");
        assert!(!t.add_link(sub, tg, nm("d")), "directories have one name");
        assert_eq!(t.child(sub, "b"), Some(a));
        assert_eq!(names(&t, sub), vec![(a, "b".to_owned())]);
        assert_eq!(names(&t, tg).len(), 3);

        // the node's own name goes: another name takes its place
        t.remove_at(a, tg, "a");
        let n = t.get(a).unwrap();
        assert!(n.attached());
        assert_ne!((n.parent, n.name.as_str()), (tg, "a"));
        assert_eq!(t.child(tg, "a"), None);

        // renaming one name moves only that name
        assert!(t.relink(a, (sub, "b"), tg, nm("e")));
        assert_eq!(t.child(sub, "b"), None);
        assert_eq!(t.child(tg, "e"), Some(a));
        assert_eq!(t.child(tg, "c"), Some(a));

        // a host file replacing one name leaves the other
        let mut fx = Vec::new();
        t.detach_at(a, tg, "e", &mut fx);
        assert_eq!(t.child(tg, "c"), Some(a));
        assert!(!t.has_links(a));
        t.remove_at(a, tg, "c");
        assert!(t.get(a).is_none_or(|n| !n.attached()));
        assert_eq!(names(&t, tg), vec![(sub, "sub".to_owned())]);

        // removing a directory drops the names inside it and keeps the file reachable elsewhere
        let f = t.insert(tg, nm("f"), file(2), GDomain::Local, Vis::Live);
        assert!(t.add_link(f, sub, nm("g")));
        t.remove(sub);
        assert_eq!(t.child(tg, "f"), Some(f));
        assert!(!t.has_links(f));
        let f2 = t.insert(tg, nm("f2"), file(3), GDomain::Local, Vis::Live);
        let s2 = t.insert(tg, nm("s2"), dir(), GDomain::Local, Vis::Live);
        assert!(t.add_link(f2, s2, nm("h")));
        t.remove_at(f2, tg, "f2");
        t.remove(s2);
        assert!(t.get(f2).is_none_or(|n| !n.attached()));
    }

    #[test]
    fn exchange_swaps_two_overlay_names() {
        let mut t = GTree::new();
        let tg = t.insert(ROOT, nm("target"), dir(), GDomain::Local, Vis::Live);
        let a = t.insert(tg, nm("a"), file(1), GDomain::Local, Vis::Live);
        let d = t.insert(tg, nm("d"), dir(), GDomain::Local, Vis::Live);
        assert!(t.exchange((a, tg, &nm("a")), (d, tg, &nm("d"))));
        assert_eq!(t.child(tg, "a"), Some(d));
        assert_eq!(t.child(tg, "d"), Some(a));
        assert_eq!(t.get(a).unwrap().name.as_str(), "d");
        assert_eq!(t.rel_path(d).unwrap().as_str(), "target/a");
        let inner = t.insert(d, nm("x"), file(2), GDomain::Local, Vis::Live);
        assert!(
            !t.exchange((d, tg, &nm("a")), (inner, d, &nm("x"))),
            "a directory cannot swap with its own child"
        );
    }

    // a directory this guest made whose mk the host has not answered
    fn pending_dir(t: &mut GTree, parent: NodeId, name: &str, ticket: u64) -> NodeId {
        let id = t.insert_dir(parent, nm(name), dir(), GDomain::Synced);
        t.get_mut(id).unwrap().unacked = Some(ticket);
        id
    }

    #[test]
    fn a_host_remove_leaves_a_pending_directory_alone() {
        let mut t = mounted_tree();
        let src = t.resolve(&rp("src")).unwrap();
        let d = pending_dir(&mut t, src, "d", 7);
        let mut fx = Vec::new();
        t.apply(&Change::Remove { path: rp("src/d") }, &mut fx);
        assert!(fx.is_empty());
        assert_eq!(t.resolve(&rp("src/d")), Some(d));
        assert_eq!(t.get(d).unwrap().vis, Vis::Live);

        t.get_mut(d).unwrap().unacked = None;
        t.apply(&Change::Remove { path: rp("src/d") }, &mut fx);
        assert_eq!(t.get(d).unwrap().vis, Vis::PendingDelete);
    }

    #[test]
    fn a_host_entry_over_a_pending_directory_takes_its_meta_or_replaces_it() {
        let mut t = mounted_tree();
        let src = t.resolve(&rp("src")).unwrap();
        let d = pending_dir(&mut t, src, "d", 7);
        up(&mut t, "src/d", dir_meta(0o700));
        assert_eq!(t.resolve(&rp("src/d")), Some(d));
        assert_eq!(t.get(d).unwrap().meta.perm, 0o700);
        assert_eq!(
            t.get(d).unwrap().unacked,
            Some(7),
            "still waiting for its own"
        );

        up(&mut t, "src/d", file(4));
        let now = t.resolve(&rp("src/d")).unwrap();
        assert_eq!(t.get(now).unwrap().meta.kind, Kind::File);
        assert_eq!(t.get(now).unwrap().unacked, None);
    }

    #[test]
    fn a_snapshot_keeps_a_pending_directory_with_its_ancestors_and_its_own_meta() {
        let mut t = GTree::new();
        let mut fx = Vec::new();
        t.apply_snapshot_part(&[entry(0, "a", dir())], true, &mut fx)
            .unwrap();
        let a = t.resolve(&rp("a")).unwrap();
        let p = pending_dir(&mut t, a, "p", 3);
        let q = t.insert_dir(a, nm("q"), dir(), GDomain::Synced);
        let deep = pending_dir(&mut t, q, "deep", 4);

        t.apply_snapshot_part(&[entry(0, "a", dir())], true, &mut fx)
            .unwrap();
        assert_eq!(t.resolve(&rp("a/p")), Some(p));
        assert_eq!(t.resolve(&rp("a/q")), Some(q), "ancestor of a pending one");
        assert_eq!(t.resolve(&rp("a/q/deep")), Some(deep));

        t.get_mut(deep).unwrap().unacked = None;
        t.get_mut(p).unwrap().unacked = None;
        t.apply_snapshot_part(&[entry(0, "a", dir())], true, &mut fx)
            .unwrap();
        assert!(t.resolve(&rp("a/p")).is_none() && t.resolve(&rp("a/q")).is_none());

        let p = pending_dir(&mut t, a, "p", 5);
        let theirs = Meta {
            perm: 0o700,
            ..dir()
        };
        t.apply_snapshot_part(
            &[entry(0, "a", dir()), entry(1, "p", theirs)],
            true,
            &mut fx,
        )
        .unwrap();
        assert_eq!(t.get(p).unwrap().meta.perm, 0o755, "the guest is the truth");
    }

    #[test]
    fn rollback_removes_the_subtree_bottom_up_and_names_what_to_drop() {
        let mut t = GTree::new();
        let a = pending_dir(&mut t, ROOT, "a", 1);
        let b = pending_dir(&mut t, a, "b", 2);
        let f = t.insert(b, nm("f"), file(1), GDomain::Synced, Vis::Live);
        t.get_mut(f).unwrap().staging = Some(9);
        t.add_open(f);
        let g = t.insert(a, nm("g"), file(2), GDomain::Synced, Vis::Live);
        t.get_mut(g).unwrap().staging = Some(4);
        let keep = t.insert(ROOT, nm("keep"), dir(), GDomain::Synced, Vis::Live);

        let mut fx = Vec::new();
        let (mut staging, told) = t.rollback(a, libc::EIO, &mut fx);
        staging.sort_unstable();
        assert_eq!((staging, told), (vec![4, 9], 1));
        assert!(t.resolve(&rp("a")).is_none());
        assert_eq!(t.resolve(&rp("keep")), Some(keep));
        assert_eq!(t.take_werr(f), libc::EIO, "the open file is told");
        assert_eq!(t.take_werr(f), 0);
        assert!(
            t.get(f)
                .is_some_and(|n| !n.attached() && n.unacked.is_none())
        );

        let at = |e: Effect| fx.iter().position(|x| *x == e).unwrap();
        let (fb, ba, ar) = (
            at(Effect::InvalEntry(b, nm("f"))),
            at(Effect::InvalEntry(a, nm("b"))),
            at(Effect::InvalEntry(ROOT, nm("a"))),
        );
        assert!(fb < ba && ba < ar, "children go before their parent");
        assert!(fx.contains(&Effect::InvalInode(ROOT)));
        assert!(fx.contains(&Effect::InvalInode(f)));
    }
}
