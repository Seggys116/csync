use super::tree::{Domain, Observed, ROOT, StatKey, Tree};
use crate::ignore::{
    repo,
    rules::{Class, Rules},
};
use crate::proto::{Change, FILE_MAX, Hash32, IndexId, Kind, LinkTarget, Meta, Name, RelPath};
use crate::sys::{self, DirEntryPlus};
use rayon::prelude::*;
use rustc_hash::FxHashSet;
use rustix::fs::{Mode, OFlags};
use std::{
    cell::Cell,
    fs::File,
    io::{self, Read},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
};

pub const HASH_BUF: usize = 1 << 20;
pub const RAYON_MIN: u64 = 4 << 20;
const RULE_MAX: u64 = 8 << 20;
const PAR_LEVEL: usize = 4;
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

struct Pending {
    path: RelPath,
    node: u32,
    class: Class,
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
}

struct Cooked {
    ok: bool,
    items: Vec<Item>,
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
    let start = if dir.is_root() {
        Pending {
            path: RelPath::root(),
            node: ROOT,
            class: Class::Synced,
        }
    } else {
        match enter(rfd, dir, rules, tree, &mut out)? {
            Some(p) => p,
            None => return Ok(()),
        }
    };
    let mut level = vec![start];
    while !level.is_empty() {
        // a handful of directories is cheaper on this thread than a pool wakeup
        let par = level.len() >= PAR_LEVEL;
        let raws: Vec<Raw> = if par {
            level.par_iter().map(|p| read_one(rfd, p)).collect()
        } else {
            level.iter().map(|p| read_one(rfd, p)).collect()
        };
        for (p, raw) in level.iter().zip(&raws) {
            register(root, rules, p, raw);
        }
        let (r, t) = (&*rules, &*tree);
        let cooked: Vec<Cooked> = if par {
            level
                .par_iter()
                .zip(raws.into_par_iter())
                .map(|(p, raw)| cook(rfd, r, t, p, raw))
                .collect()
        } else {
            level
                .iter()
                .zip(raws)
                .map(|(p, raw)| cook(rfd, r, t, p, raw))
                .collect()
        };
        let mut next = Vec::new();
        for (p, c) in level.iter().zip(cooked) {
            apply(tree, p, c, &mut out, &mut next);
        }
        level = next;
    }
    Ok(())
}

// classifies and observes the subtree root itself; None when there is nothing to walk
fn enter(
    rfd: BorrowedFd<'_>,
    dir: &RelPath,
    rules: &Rules,
    tree: &mut Tree,
    out: &mut Option<&mut Vec<Change>>,
) -> io::Result<Option<Pending>> {
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
    Ok(tree.node_of(dir).map(|node| Pending {
        path: dir.clone(),
        node,
        class,
    }))
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

fn read_one(rfd: BorrowedFd<'_>, p: &Pending) -> Raw {
    let mut raw = Raw::default();
    let Ok(fd) = sys::open_beneath(rfd, &p.path, DIR_FLAGS) else {
        return raw;
    };
    let mut ents: Vec<DirEntryPlus> = Vec::new();
    if sys::read_dir_plus(fd.as_fd(), &mut ents).is_err() {
        return raw;
    }
    raw.ok = true;
    raw.ents.reserve(ents.len());
    for e in ents {
        let Some(kind) = e.kind else { continue };
        let link = match kind {
            Kind::Symlink => match read_link(fd.as_fd(), &e.name) {
                Some(l) => Some(l),
                None => continue,
            },
            _ => None,
        };
        if p.class == Class::Synced {
            match (e.name.as_str(), kind) {
                (".gitignore", Kind::File) => raw.ignore_text = read_rule(fd.as_fd()),
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

// runs between the parallel phases so a directory's own .git and .gitignore govern its children
fn register(root: &Path, rules: &mut Rules, p: &Pending, raw: &Raw) {
    if !raw.ok || p.class != Class::Synced {
        return;
    }
    if raw.has_git {
        repo::register(rules, root, &p.path);
    } else {
        if rules.is_repo(&p.path) {
            rules.remove_repo(&p.path);
        }
        if p.path.is_root() {
            repo::register_plain_root(rules, root);
        }
    }
    if raw.ignore_text.is_some() || rules.has_dir_rules(&p.path) {
        let file = if p.path.is_root() {
            RelPath::new(".gitignore")
        } else {
            RelPath::new(&format!("{}/.gitignore", p.path.as_str()))
        };
        if let Ok(file) = file {
            rules.update_rule_file(&file, raw.ignore_text.as_deref());
        }
    }
}

fn cook(rfd: BorrowedFd<'_>, rules: &Rules, tree: &Tree, p: &Pending, raw: Raw) -> Cooked {
    if !raw.ok {
        return Cooked {
            ok: false,
            items: Vec::new(),
        };
    }
    let mut ctx = rules.dir_ctx(&p.path);
    let mut items = Vec::with_capacity(raw.ents.len());
    let mut dfd: Option<io::Result<OwnedFd>> = None;
    for e in raw.ents {
        let git_ro = match rules.classify_in(&mut ctx, e.name.as_str(), e.kind == Kind::Dir) {
            Class::Synced => false,
            Class::GitRo => true,
            Class::Ignored | Class::Internal => continue,
        };
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
                let cached = tree
                    .child(p.node, e.name.as_str())
                    .and_then(|n| tree.entry(n))
                    .filter(|x| x.stat == e.stat && x.meta.kind == Kind::File)
                    .and_then(|x| x.meta.hash);
                let (hash, stat) = match cached {
                    Some(h) => (h, e.stat),
                    None if e.stat.size == 0 => (*blake3::hash(&[]).as_bytes(), e.stat),
                    None => {
                        let d =
                            dfd.get_or_insert_with(|| sys::open_beneath(rfd, &p.path, DIR_FLAGS));
                        let Ok(d) = d else { continue };
                        match hash_at(d.as_fd(), &e.name, &e.stat) {
                            Ok(v) => v,
                            Err(_) => continue,
                        }
                    }
                };
                let meta = Meta {
                    kind: Kind::File,
                    perm: perm(stat.mode),
                    size: stat.size,
                    mtime_ns: stat.mtime_ns,
                    ctime_ns: stat.ctime_ns,
                    hash: Some(hash),
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
        });
    }
    Cooked { ok: true, items }
}

fn apply(
    tree: &mut Tree,
    p: &Pending,
    c: Cooked,
    out: &mut Option<&mut Vec<Change>>,
    next: &mut Vec<Pending>,
) {
    if !c.ok {
        return;
    }
    let want = out.is_some();
    let mut stale = Vec::new();
    {
        let present: FxHashSet<&str> = c.items.iter().map(|i| i.name.as_str()).collect();
        tree.children(p.node, &mut |n, name, _| {
            if !present.contains(name.as_str()) {
                stale.push(n);
            }
        });
    }
    for n in stale {
        emit(out, tree.remove_at(n, want));
    }
    for it in c.items {
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
        emit(
            out,
            tree.observe_in(p.node, it.name.as_str(), o, None, want),
        );
        if is_dir
            && let Some(node) = tree.child(p.node, it.name.as_str())
            && let Ok(path) = p.path.join(&it.name)
        {
            next.push(Pending { path, node, class });
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

// keeps the directory-entry stat when the opened file is the same version, so warm scans compare like with like
fn hash_at(dir: BorrowedFd<'_>, name: &Name, seen: &StatKey) -> io::Result<(Hash32, StatKey)> {
    let fd = rustix::fs::openat(
        dir,
        name.as_str(),
        FILE_FLAGS | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let st = sys::stat_key(fd.as_fd())?;
    if sys::kind_of_mode(st.mode) != Some(Kind::File) || st.size > FILE_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    let stat = if sys::same_version(&st, seen) && st.ctime_ns == seen.ctime_ns {
        *seen
    } else {
        st
    };
    Ok((hash_fd(fd, stat.size)?, stat))
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

    fn assert_matches_fs(root: &Path, rules: &Rules, tree: &Tree) {
        let mut want = HashMap::new();
        expected(root, "", rules, &mut want);
        assert_eq!(tree.len(), want.len());
        for (p, w) in &want {
            let e = tree.get(&rp(p)).unwrap_or_else(|| panic!("missing {p}"));
            assert_eq!(e.meta.kind, w.kind, "{p}");
            assert_eq!(e.meta.size, w.size, "{p}");
            assert_eq!(e.meta.hash, w.hash, "{p}");
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
        let tree = scan(&root, &mut rules).unwrap();
        assert_matches_fs(&root, &rules, &tree);
        assert!(tree.get(&rp("b.log")).is_none());
        assert!(tree.get(&rp("build")).is_none());
        assert!(tree.get(&rp("src/deep/x.tmp")).is_none());
        assert!(tree.get(&rp(".git/objects/x.log")).is_some());
        assert_eq!(
            tree.get(&rp("a.txt")).and_then(|e| e.meta.hash),
            Some(*blake3::hash(b"hello").as_bytes())
        );

        let seq = tree.seq();
        let tree = rescan(&root, &mut rules, tree).unwrap();
        assert_eq!(tree.seq(), seq);
        assert_eq!(tree.changes_since(seq).unwrap().len(), 0);

        fs::write(root.join("src/main.rs"), "fn main() { println!(); }\n").unwrap();
        fs::remove_file(root.join("a.txt")).unwrap();
        let tree = rescan(&root, &mut rules, tree).unwrap();
        let changes = tree.changes_since(seq).unwrap();
        assert!(changes.iter().any(
            |c| matches!(c, Change::Upsert { path, meta } if path.as_str() == "src/main.rs"
            && meta.hash == Some(*blake3::hash(b"fn main() { println!(); }\n").as_bytes()))
        ));
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, Change::Remove { path } if path.as_str() == "a.txt"))
        );
        assert_matches_fs(&root, &rules, &tree);

        let mut tree = tree;
        fs::write(root.join("src/deep/.gitignore"), "").unwrap();
        let mut out = Vec::new();
        scan_subtree(&root, &rp("src/deep"), &mut rules, &mut tree, &mut out).unwrap();
        assert!(out.iter().any(
            |c| matches!(c, Change::Upsert { path, .. } if path.as_str() == "src/deep/x.tmp")
        ));
        assert_matches_fs(&root, &rules, &tree);

        let _ = fs::remove_dir_all(&root);
    }
}
