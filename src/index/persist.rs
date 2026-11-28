use super::tree::{Domain, Entry, ROOT, StatKey, Tree};
use crate::proto::{FILE_MAX, Hash32, IndexId, Kind, LinkTarget, Meta, Name, Seq, SnapEntry};
use crate::sys::ResumeToken;
use rkyv::{
    Archive,
    api::high::{HighDeserializer, HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    rancor,
    ser::allocator::ArenaHandle,
    util::AlignedVec,
};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const MAGIC: [u8; 6] = *b"CSYNC\0";
pub const FORMAT: u16 = 1;
const HEADER: usize = 64;
pub const LOAD_MAX: u64 = 2 << 30;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FileKind {
    Index = 1,
    GuestTree = 2,
    Lru = 3,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
pub struct DiskMeta {
    pub kind: u8,
    pub perm: u16,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub hash: Option<[u8; 32]>,
    pub link: Option<String>,
    pub git_ro: bool,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
pub struct DiskStat {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub mode: u32,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
pub struct DiskNode {
    pub parent: u32,
    pub name: String,
    pub meta: DiskMeta,
    pub stat: DiskStat,
    pub domain: u8,
    pub seq: u64,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
pub struct DiskResume {
    pub volume: [u8; 16],
    pub event_id: u64,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
pub struct DiskIndex {
    pub index: [u8; 16],
    pub seq: u64,
    pub resume: Option<DiskResume>,
    pub nodes: Vec<DiskNode>,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
pub struct DiskSnap {
    pub parent: u32,
    pub name: String,
    pub meta: DiskMeta,
    pub ver: u64,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
pub struct DiskGuest {
    pub index: [u8; 16],
    pub seq: u64,
    pub entries: Vec<DiskSnap>,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
pub struct DiskLru {
    pub hash: [u8; 32],
    pub size: u64,
    pub used: u64,
}

#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq)]
pub struct DiskLruFile {
    pub entries: Vec<DiskLru>,
}

fn kind_byte(k: Kind) -> u8 {
    match k {
        Kind::File => 0,
        Kind::Dir => 1,
        Kind::Symlink => 2,
    }
}

pub fn meta_to_disk(m: &Meta) -> DiskMeta {
    DiskMeta {
        kind: kind_byte(m.kind),
        perm: m.perm,
        size: m.size,
        mtime_ns: m.mtime_ns,
        ctime_ns: m.ctime_ns,
        hash: m.hash,
        link: m.link.as_ref().map(|l| l.as_str().to_owned()),
        git_ro: m.git_ro,
    }
}

// local files are still re-validated: a damaged file must cause a rescan, never a bad tree
pub fn meta_from_disk(d: &DiskMeta) -> Option<Meta> {
    let kind = match d.kind {
        0 => Kind::File,
        1 => Kind::Dir,
        2 => Kind::Symlink,
        _ => return None,
    };
    let link = match (&d.link, kind) {
        (Some(s), Kind::Symlink) => Some(LinkTarget::new(s).ok()?),
        (None, Kind::File | Kind::Dir) => None,
        _ => return None,
    };
    // a file without a hash is pending: its hash is learned after the entry was recorded
    if d.size > FILE_MAX || d.perm > 0o7777 || (kind != Kind::File && d.hash.is_some()) {
        return None;
    }
    Some(Meta {
        kind,
        perm: d.perm,
        size: d.size,
        mtime_ns: d.mtime_ns,
        ctime_ns: d.ctime_ns,
        hash: d.hash,
        link,
        git_ro: d.git_ro,
    })
}

pub fn save<T>(path: &Path, kind: FileKind, v: &T) -> io::Result<()>
where
    T: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>,
{
    let body = rkyv::to_bytes::<rancor::Error>(v)
        .map_err(|e| io::Error::other(format!("serialize: {e}")))?;
    let mut hdr = [0u8; HEADER];
    hdr[..6].copy_from_slice(&MAGIC);
    hdr[6] = kind as u8;
    hdr[8..10].copy_from_slice(&FORMAT.to_le_bytes());
    hdr[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
    hdr[24..56].copy_from_slice(blake3::hash(&body).as_bytes());
    write_atomic(path, &hdr, &body)
}

// None for a missing, foreign, outdated, truncated or corrupt file; the caller rescans
pub fn load<T>(path: &Path, kind: FileKind) -> Option<T>
where
    T: Archive,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + rkyv::Deserialize<T, HighDeserializer<rancor::Error>>,
{
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let md = f.metadata().ok()?;
    if !md.is_file() {
        return None;
    }
    let mut hdr = [0u8; HEADER];
    f.read_exact(&mut hdr).ok()?;
    if hdr[..6] != MAGIC || hdr[6] != kind as u8 || hdr[8..10] != FORMAT.to_le_bytes() {
        return None;
    }
    let len = u64::from_le_bytes(hdr[16..24].try_into().ok()?);
    if len > LOAD_MAX || Some(len) != md.len().checked_sub(HEADER as u64) {
        return None;
    }
    let mut body: AlignedVec = AlignedVec::with_capacity(usize::try_from(len).ok()?);
    body.extend_from_reader(&mut f.take(len)).ok()?;
    if body.len() as u64 != len || blake3::hash(&body).as_bytes()[..] != hdr[24..56] {
        return None;
    }
    rkyv::from_bytes::<T, rancor::Error>(&body).ok()
}

fn write_atomic(path: &Path, hdr: &[u8], body: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp_name = OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    let res = write_then_rename(&tmp, path, dir, hdr, body);
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

fn write_then_rename(
    tmp: &Path,
    path: &Path,
    dir: &Path,
    hdr: &[u8],
    body: &[u8],
) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(tmp)?;
    f.write_all(hdr)?;
    f.write_all(body)?;
    f.sync_all()?;
    drop(f);
    fs::rename(tmp, path)?;
    File::open(dir)?.sync_all()
}

fn domain_byte(d: Domain) -> u8 {
    match d {
        Domain::Synced => 0,
        Domain::GitRo => 1,
    }
}

pub fn save_index(path: &Path, tree: &Tree, resume: Option<ResumeToken>) -> io::Result<()> {
    write_index(path, &snapshot_index(tree, resume))
}

// everything that needs the tree, so the serialising and writing can happen after its lock is released
pub fn snapshot_index(tree: &Tree, resume: Option<ResumeToken>) -> DiskIndex {
    let mut nodes = Vec::with_capacity(tree.len());
    tree.walk(&mut |parent, name, e| {
        let s = &e.stat;
        nodes.push(DiskNode {
            parent,
            name: name.as_str().to_owned(),
            meta: meta_to_disk(&e.meta),
            stat: DiskStat {
                dev: s.dev,
                ino: s.ino,
                size: s.size,
                mtime_ns: s.mtime_ns,
                ctime_ns: s.ctime_ns,
                mode: s.mode,
            },
            domain: domain_byte(e.domain),
            seq: e.seq,
        });
    });
    DiskIndex {
        index: tree.index_id().to_le_bytes(),
        seq: tree.seq(),
        resume: resume.map(|r| DiskResume {
            volume: r.volume,
            event_id: r.event_id,
        }),
        nodes,
    }
}

pub fn write_index(path: &Path, d: &DiskIndex) -> io::Result<()> {
    save(path, FileKind::Index, d)
}

fn clean_path(index: &Path) -> PathBuf {
    let mut s = index.as_os_str().to_owned();
    s.push(".clean");
    PathBuf::from(s)
}

fn clean_stamp(tree: &Tree) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[..16].copy_from_slice(&tree.index_id().to_le_bytes());
    b[16..].copy_from_slice(&tree.seq().to_le_bytes());
    b
}

// written only after the final save of an orderly shutdown: the saved seq is then the last one any guest saw
pub fn mark_clean(index: &Path, tree: &Tree) -> io::Result<()> {
    write_atomic(&clean_path(index), &clean_stamp(tree), &[])
}

// consumes the marker, so a crash of this run is never mistaken for a clean exit
pub fn take_clean(index: &Path, tree: &Tree) -> bool {
    let p = clean_path(index);
    let mut got = Vec::new();
    let read = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&p)
        .and_then(|f| f.take(64).read_to_end(&mut got));
    if read.is_err() {
        return false;
    }
    let gone = fs::remove_file(&p).is_ok()
        && p.parent()
            .is_none_or(|d| File::open(d).and_then(|f| f.sync_all()).is_ok());
    gone && got[..] == clean_stamp(tree)[..]
}

pub fn load_index(path: &Path) -> Option<(Tree, Option<ResumeToken>)> {
    index_from_disk(load::<DiskIndex>(path, FileKind::Index)?)
}

pub fn index_from_disk(d: DiskIndex) -> Option<(Tree, Option<ResumeToken>)> {
    let mut t = Tree::restored(IndexId::from_le_bytes(d.index), d.seq);
    let mut map: Vec<u32> = Vec::with_capacity(d.nodes.len() + 1);
    map.push(ROOT);
    for (k, n) in d.nodes.iter().enumerate() {
        let parent = *map
            .get(n.parent as usize)
            .filter(|_| (n.parent as usize) <= k)?;
        let domain = match n.domain {
            0 => Domain::Synced,
            1 => Domain::GitRo,
            _ => return None,
        };
        let s = &n.stat;
        let stat = StatKey {
            dev: s.dev,
            ino: s.ino,
            size: s.size,
            mtime_ns: s.mtime_ns,
            ctime_ns: s.ctime_ns,
            mode: s.mode,
        };
        if n.seq > d.seq {
            return None;
        }
        let entry = Entry {
            meta: meta_from_disk(&n.meta)?,
            stat,
            domain,
            seq: n.seq,
        };
        map.push(t.restore_child(parent, &n.name, entry)?);
    }
    let resume = d.resume.map(|r| ResumeToken {
        volume: r.volume,
        event_id: r.event_id,
    });
    Some((t, resume))
}

pub fn save_guest_tree(
    path: &Path,
    index: IndexId,
    seq: Seq,
    entries: &[SnapEntry],
) -> io::Result<()> {
    let d = DiskGuest {
        index: index.to_le_bytes(),
        seq,
        entries: entries
            .iter()
            .map(|e| DiskSnap {
                parent: e.parent,
                name: e.name.as_str().to_owned(),
                meta: meta_to_disk(&e.meta),
                ver: e.ver,
            })
            .collect(),
    };
    save(path, FileKind::GuestTree, &d)
}

// entries keep the snapshot convention: entry k has id k + 1, id 0 is the root, parent < id
pub fn load_guest_tree(path: &Path) -> Option<(IndexId, Seq, Vec<SnapEntry>)> {
    let d = load::<DiskGuest>(path, FileKind::GuestTree)?;
    let mut dirs: Vec<bool> = Vec::with_capacity(d.entries.len() + 1);
    dirs.push(true);
    let mut out = Vec::with_capacity(d.entries.len());
    for (k, e) in d.entries.iter().enumerate() {
        if (e.parent as usize) > k || !dirs.get(e.parent as usize).copied().unwrap_or(false) {
            return None;
        }
        let meta = meta_from_disk(&e.meta)?;
        dirs.push(meta.kind == Kind::Dir);
        out.push(SnapEntry {
            parent: e.parent,
            name: Name::new(&e.name).ok()?,
            meta,
            ver: e.ver,
        });
    }
    Some((IndexId::from_le_bytes(d.index), d.seq, out))
}

pub fn save_lru(path: &Path, entries: &[(Hash32, u64, u64)]) -> io::Result<()> {
    let d = DiskLruFile {
        entries: entries
            .iter()
            .map(|&(hash, size, used)| DiskLru { hash, size, used })
            .collect(),
    };
    save(path, FileKind::Lru, &d)
}

pub fn load_lru(path: &Path) -> Option<Vec<(Hash32, u64, u64)>> {
    let d = load::<DiskLruFile>(path, FileKind::Lru)?;
    d.entries
        .iter()
        .map(|e| (e.size <= FILE_MAX).then_some((e.hash, e.size, e.used)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::tree::Observed;
    use crate::proto::RelPath;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    fn tmp_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "csync-persist-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample() -> Tree {
        let mut t = Tree::new(0x1234_5678_9abc_def0_1122_3344_5566_7788);
        let dir = Meta {
            kind: Kind::Dir,
            perm: 0o755,
            size: 0,
            mtime_ns: 1,
            ctime_ns: 2,
            hash: None,
            link: None,
            git_ro: false,
        };
        let file = Meta {
            kind: Kind::File,
            perm: 0o644,
            size: 5,
            mtime_ns: 3,
            ctime_ns: 4,
            hash: Some([9; 32]),
            link: None,
            git_ro: false,
        };
        let link = Meta {
            kind: Kind::Symlink,
            perm: 0o777,
            size: 5,
            mtime_ns: 5,
            ctime_ns: 6,
            hash: None,
            link: Some(LinkTarget::new("a.txt").unwrap()),
            git_ro: false,
        };
        let stat = StatKey {
            dev: 1,
            ino: 2,
            size: 5,
            mtime_ns: 3,
            ctime_ns: 4,
            mode: 0o100_644,
        };
        for (p, m, d) in [
            ("src", &dir, Domain::Synced),
            ("src/a.txt", &file, Domain::Synced),
            ("src/l", &link, Domain::Synced),
            (".git", &dir, Domain::GitRo),
            (".git/HEAD", &file, Domain::GitRo),
        ] {
            let mut m = m.clone();
            m.git_ro = d == Domain::GitRo;
            t.observe(
                &RelPath::new(p).unwrap(),
                Observed::Present {
                    meta: m,
                    stat,
                    domain: d,
                },
            );
        }
        t
    }

    fn snap(t: &Tree) -> Vec<SnapEntry> {
        let mut v = Vec::new();
        t.snapshot(&mut |e| v.push(e));
        v
    }

    // sibling order is not part of the format, so trees compare by full path
    fn by_path(t: &Tree) -> BTreeMap<String, Meta> {
        let mut full = vec![String::new()];
        let mut out = BTreeMap::new();
        for e in snap(t) {
            let parent = &full[e.parent as usize];
            let p = if parent.is_empty() {
                e.name.as_str().to_owned()
            } else {
                format!("{parent}/{}", e.name.as_str())
            };
            full.push(p.clone());
            out.insert(p, e.meta);
        }
        out
    }

    #[test]
    fn index_round_trip() {
        let d = tmp_dir();
        let p = d.join("index.rkyv");
        let t = sample();
        let tok = ResumeToken {
            volume: [7; 16],
            event_id: 42,
        };
        save_index(&p, &t, Some(tok)).unwrap();
        let (u, r) = load_index(&p).unwrap();
        assert_eq!(r, Some(tok));
        assert_eq!(u.index_id(), t.index_id());
        assert_eq!(u.seq(), t.seq());
        assert_eq!(by_path(&u), by_path(&t));
        assert_eq!(u.len(), t.len());
        let rp = RelPath::new("src/a.txt").unwrap();
        assert_eq!(
            u.get(&rp).map(|e| (e.stat, e.seq)),
            t.get(&rp).map(|e| (e.stat, e.seq))
        );
        assert_eq!(u.changes_since(u.seq()).map(|c| c.len()), Some(0));
        assert!(u.changes_since(0).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_snapshot_written_later_is_the_file_save_index_writes_and_ignores_later_edits() {
        let d = tmp_dir();
        let (direct, split) = (d.join("direct.rkyv"), d.join("split.rkyv"));
        let mut t = sample();
        let tok = ResumeToken {
            volume: [3; 16],
            event_id: 9,
        };
        save_index(&direct, &t, Some(tok)).unwrap();
        let snap_before = snapshot_index(&t, Some(tok));
        let before = by_path(&t);
        let seq = t.seq();

        t = with_pending(t);
        assert_ne!(t.seq(), seq);
        write_index(&split, &snap_before).unwrap();

        assert_eq!(fs::read(&direct).unwrap(), fs::read(&split).unwrap());
        let (u, r) = load_index(&split).unwrap();
        assert_eq!(r, Some(tok));
        assert_eq!(u.seq(), seq);
        assert_eq!(by_path(&u), before);
        let _ = fs::remove_dir_all(&d);
    }

    fn with_pending(mut t: Tree) -> Tree {
        let mut m = t
            .get(&RelPath::new("src/a.txt").unwrap())
            .unwrap()
            .meta
            .clone();
        m.hash = None;
        m.size = 77;
        let stat = StatKey {
            dev: 1,
            ino: 99,
            size: 77,
            mtime_ns: 3,
            ctime_ns: 4,
            mode: 0o100_644,
        };
        for p in ["src/pending.txt", ".git/pending-ref"] {
            let domain = if p.starts_with(".git") {
                Domain::GitRo
            } else {
                Domain::Synced
            };
            let mut m = m.clone();
            m.git_ro = domain == Domain::GitRo;
            t.observe(
                &RelPath::new(p).unwrap(),
                Observed::Present {
                    meta: m,
                    stat,
                    domain,
                },
            );
        }
        t
    }

    #[test]
    fn a_pending_entry_survives_a_save_and_load_and_stays_pending() {
        let d = tmp_dir();
        let p = d.join("index.rkyv");
        let t = with_pending(sample());
        assert_eq!(t.pending(), 2);
        save_index(&p, &t, None).unwrap();
        let (mut u, _) = load_index(&p).unwrap();
        assert_eq!(by_path(&u), by_path(&t));
        assert_eq!(u.pending(), 2);
        assert_eq!(u.seq(), t.seq());
        let rp = RelPath::new("src/pending.txt").unwrap();
        let (a, b) = (u.get(&rp).unwrap(), t.get(&rp).unwrap());
        assert!(a.is_pending());
        assert_eq!((a.stat, a.seq, a.domain), (b.stat, b.seq, b.domain));
        let (ver, stat) = (a.seq, a.stat);

        // the loaded tree can still learn the hash for the version it saved
        assert!(u.set_hash(&rp, ver, &stat, [5; 32]));
        assert_eq!(u.pending(), 1);

        let g = d.join("tree.rkyv");
        let entries = snap(&t);
        assert!(
            entries
                .iter()
                .any(|e| e.meta.hash.is_none() && e.meta.kind == Kind::File)
        );
        save_guest_tree(&g, 5, 9, &entries).unwrap();
        assert_eq!(load_guest_tree(&g), Some((5, 9, entries)));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn only_files_may_lack_a_hash_and_only_files_may_have_one() {
        let base = |kind: u8, hash: Option<[u8; 32]>, link: Option<&str>| DiskMeta {
            kind,
            perm: 0o644,
            size: 1,
            mtime_ns: 0,
            ctime_ns: 0,
            hash,
            link: link.map(str::to_owned),
            git_ro: false,
        };
        assert!(meta_from_disk(&base(0, None, None)).is_some_and(|m| m.hash.is_none()));
        assert_eq!(
            meta_from_disk(&base(0, Some([1; 32]), None)).and_then(|m| m.hash),
            Some([1; 32])
        );
        assert!(meta_from_disk(&base(1, Some([1; 32]), None)).is_none());
        assert!(meta_from_disk(&base(2, Some([1; 32]), Some("t"))).is_none());
        assert!(meta_from_disk(&base(1, None, None)).is_some());
        assert!(meta_from_disk(&base(2, None, Some("t"))).is_some());
        assert!(meta_from_disk(&base(0, None, Some("t"))).is_none());
    }

    #[test]
    fn clean_marker_is_single_use_and_bound_to_the_saved_seq() {
        let d = tmp_dir();
        let p = d.join("index.rkyv");
        let t = sample();
        assert!(!take_clean(&p, &t));
        mark_clean(&p, &t).unwrap();
        assert!(take_clean(&p, &t));
        assert!(!take_clean(&p, &t));
        mark_clean(&p, &t).unwrap();
        let mut later = sample();
        later.observe(
            &RelPath::new("src/b.txt").unwrap(),
            Observed::Present {
                meta: t
                    .get(&RelPath::new("src/a.txt").unwrap())
                    .unwrap()
                    .meta
                    .clone(),
                stat: StatKey::default(),
                domain: Domain::Synced,
            },
        );
        assert!(!take_clean(&p, &later));
        assert!(!take_clean(&p, &t));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn corrupt_files_mean_rescan() {
        let d = tmp_dir();
        let p = d.join("index.rkyv");
        assert!(load_index(&p).is_none());
        save_index(&p, &sample(), None).unwrap();
        let good = fs::read(&p).unwrap();

        let mut flipped = good.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x40;
        fs::write(&p, &flipped).unwrap();
        assert!(load_index(&p).is_none());

        fs::write(&p, &good[..good.len() - 3]).unwrap();
        assert!(load_index(&p).is_none());

        fs::write(&p, &good[..10]).unwrap();
        assert!(load_index(&p).is_none());

        let mut magic = good.clone();
        magic[0] = b'X';
        fs::write(&p, &magic).unwrap();
        assert!(load_index(&p).is_none());

        let mut version = good.clone();
        version[8] = version[8].wrapping_add(1);
        fs::write(&p, &version).unwrap();
        assert!(load_index(&p).is_none());

        // a valid header and checksum over bytes that are not a DiskIndex must fail validation
        let garbage = vec![0xffu8; 200];
        let mut forged = good[..HEADER].to_vec();
        forged[16..24].copy_from_slice(&(garbage.len() as u64).to_le_bytes());
        forged[24..56].copy_from_slice(blake3::hash(&garbage).as_bytes());
        forged.extend_from_slice(&garbage);
        fs::write(&p, &forged).unwrap();
        assert!(load_index(&p).is_none());

        fs::write(&p, &good).unwrap();
        assert!(load_guest_tree(&p).is_none());
        assert!(load_index(&p).is_some());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn structurally_invalid_trees_are_rejected() {
        let d = tmp_dir();
        let p = d.join("index.rkyv");
        let meta = meta_to_disk(&Meta {
            kind: Kind::Dir,
            perm: 0o755,
            size: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            hash: None,
            link: None,
            git_ro: false,
        });
        let stat = DiskStat {
            dev: 0,
            ino: 0,
            size: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            mode: 0,
        };
        let node = |parent: u32, name: &str| DiskNode {
            parent,
            name: name.to_owned(),
            meta: meta.clone(),
            stat: stat.clone(),
            domain: 0,
            seq: 1,
        };
        let cases = [
            vec![node(1, "a")],
            vec![node(0, "a"), node(5, "b")],
            vec![node(0, "a/b")],
            vec![node(0, "..")],
            vec![node(0, "a"), node(0, "a")],
        ];
        for nodes in cases {
            save(
                &p,
                FileKind::Index,
                &DiskIndex {
                    index: [0; 16],
                    seq: 1,
                    resume: None,
                    nodes,
                },
            )
            .unwrap();
            assert!(load_index(&p).is_none());
        }
        save(
            &p,
            FileKind::Index,
            &DiskIndex {
                index: [0; 16],
                seq: 1,
                resume: None,
                nodes: vec![node(0, "a"), node(1, "b")],
            },
        )
        .unwrap();
        assert_eq!(load_index(&p).map(|(t, _)| t.len()), Some(2));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn guest_tree_and_lru_round_trip() {
        let d = tmp_dir();
        let t = sample();
        let entries = snap(&t);
        assert!(entries.iter().all(|e| e.ver > 0));
        let g = d.join("tree.rkyv");
        save_guest_tree(&g, 5, 9, &entries).unwrap();
        assert_eq!(load_guest_tree(&g), Some((5, 9, entries)));
        let l = d.join("lru.bin");
        let items = vec![([1u8; 32], 10, 100), ([2u8; 32], 20, 200)];
        save_lru(&l, &items).unwrap();
        assert_eq!(load_lru(&l), Some(items));
        assert!(load_index(&l).is_none());
        let _ = fs::remove_dir_all(&d);
    }
}
