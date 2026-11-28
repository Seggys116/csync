use super::{Core, Guest, hash_verified, read_all, read_exact_at};
use crate::delta;
use crate::ignore::rules::Class;
use crate::index::tree::StatKey;
use crate::net::conn::{Out, Prio};
use crate::proto::{
    BATCH_MAX, Body, Bytes, CHUNK_MAX, ChunkSig, DELTA_MIN, FRAME_MAX, Hash32, INLINE_MAX, IndexId,
    Kind, Meta, Msg, Op, RelPath, Reply, ReqId, Seq, VerKey, Want, WireErr,
};
use crate::sys;
use crossbeam_channel::Receiver;
use rustix::fs::OFlags;
use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{Arc, Mutex, atomic::Ordering},
    time::{Duration, Instant},
};

// beyond this a delta would need the whole file in memory; such files use range fetches anyway
const DELTA_FILE_MAX: u64 = 64 << 20;
const MANY_ITEM_MAX: u64 = 1 << 20;
const MANY_SLACK: usize = 64 << 10;
const KEEP_MAX: usize = 16;
const KEEP_TTL: Duration = Duration::from_secs(60);

struct KeptFd {
    hash: Hash32,
    meta: Meta,
    stat: StatKey,
    fd: Arc<OwnedFd>,
    used: Instant,
}

// git keeps reading a pack it opened even after gc or repack deleted it; the last pack files served
// stay open here by hash, so a guest still reading one gets what a local reader would
#[derive(Default)]
pub(crate) struct Kept(Mutex<Vec<KeptFd>>);

impl Kept {
    fn keep(&self, hash: Hash32, meta: &Meta, stat: StatKey, fd: &Arc<OwnedFd>) {
        let now = Instant::now();
        let mut v = super::lock(&self.0);
        if let Some(k) = v.iter_mut().find(|k| k.hash == hash) {
            k.used = now;
            return;
        }
        v.retain(|k| now.duration_since(k.used) < KEEP_TTL);
        if v.len() >= KEEP_MAX
            && let Some(i) = (0..v.len()).min_by_key(|&i| v[i].used)
        {
            v.swap_remove(i);
        }
        v.push(KeptFd {
            hash,
            meta: meta.clone(),
            stat,
            fd: fd.clone(),
            used: now,
        });
    }

    fn find(&self, hash: &Hash32) -> Option<(Meta, StatKey, Arc<OwnedFd>)> {
        let mut v = super::lock(&self.0);
        let i = v.iter().position(|k| &k.hash == hash)?;
        if !unchanged(v[i].fd.as_fd(), &v[i].stat) {
            v.swap_remove(i);
            return None;
        }
        let k = &mut v[i];
        k.used = Instant::now();
        Some((k.meta.clone(), k.stat, k.fd.clone()))
    }

    pub(crate) fn prune(&self) {
        let now = Instant::now();
        super::lock(&self.0).retain(|k| now.duration_since(k.used) < KEEP_TTL);
    }
}

pub(crate) struct FetchJob {
    pub(crate) guest: Arc<Guest>,
    pub(crate) id: ReqId,
    pub(crate) op: Op,
}

pub(crate) fn run(core: &Core, rx: &Receiver<FetchJob>) {
    for job in rx.iter() {
        let FetchJob { guest, id, op } = job;
        let _fg = core.fg_guard();
        let res = if guest.cancelled(id) {
            Err(WireErr::Gone)
        } else {
            match op {
                Op::Fetch {
                    path,
                    want,
                    have,
                    range,
                } => fetch(core, &guest, id, &path, want, have.as_deref(), range),
                Op::FetchMany { items } => many(core, &guest, id, &items),
                Op::Resolve { path, at, inline } => resolve(core, &guest, id, &path, at, inline),
                Op::Hashes { index, items } => hashes(core, &guest, id, index, &items),
                _ => Err(WireErr::Invalid),
            }
        };
        if let Err(e) = res {
            reply_bulk(&guest, id, Err(e));
        }
        guest.end_fetch(id);
        core.stats.fetches.fetch_add(1, Ordering::Relaxed);
        core.kick();
    }
}

// on the bulk queue, so it can never overtake chunks already queued for the same request
fn reply_bulk(g: &Guest, id: ReqId, res: Result<Reply, WireErr>) {
    let _ = g.link.send_out(Out::Msg(Prio::Bulk, Msg::Resp { id, res }));
}

fn send_blob(g: &Guest, id: ReqId, meta: Meta, body: Body) -> Result<(), WireErr> {
    reply_bulk(g, id, Ok(Reply::Blob { meta, body }));
    Ok(())
}

// an index entry as served: its seq and the index it belongs to name the version a guest asks for by VerKey
struct Live {
    meta: Meta,
    stat: StatKey,
    seq: Seq,
    index: IndexId,
}

fn at_ver(l: &Live, k: &VerKey) -> Result<(), WireErr> {
    if l.index == k.index && l.seq == k.ver && l.stat.size == k.size {
        Ok(())
    } else {
        Err(WireErr::Gone)
    }
}

// only indexed files are served: ignored paths are never in the index and are refused again here
fn readable(core: &Core, path: &RelPath) -> Result<Live, WireErr> {
    if path.is_root() {
        return Err(WireErr::IsDir);
    }
    let rules = core.rules_r();
    match rules.classify(path, false) {
        Class::Synced | Class::GitRo => {}
        Class::Ignored | Class::Internal => return Err(WireErr::Ignored),
    }
    let tree = core.tree();
    let e = tree.get(path).ok_or(WireErr::NotFound)?;
    match e.meta.kind {
        Kind::File => Ok(Live {
            meta: e.meta.clone(),
            stat: e.stat,
            seq: e.seq,
            index: tree.index_id(),
        }),
        Kind::Dir => Err(WireErr::IsDir),
        Kind::Symlink => Err(WireErr::Invalid),
    }
}

fn gone(core: &Core, path: &RelPath) -> WireErr {
    core.request_rescan(path);
    WireErr::Gone
}

fn open_verified(core: &Core, path: &RelPath, stat: &StatKey) -> Result<OwnedFd, WireErr> {
    let fd = sys::open_beneath(core.root.as_fd(), path, OFlags::RDONLY | OFlags::NONBLOCK)
        .map_err(|_| gone(core, path))?;
    let st = sys::stat_key(fd.as_fd()).map_err(|_| gone(core, path))?;
    if sys::kind_of_mode(st.mode) != Some(Kind::File) || !sys::same_bytes(&st, stat) {
        return Err(gone(core, path));
    }
    Ok(fd)
}

fn unchanged(fd: BorrowedFd<'_>, stat: &StatKey) -> bool {
    sys::stat_key(fd).is_ok_and(|s| sys::same_bytes(&s, stat))
}

// the fd's current stat key, which must still describe the index entry's bytes
fn fresh_key(
    core: &Core,
    path: &RelPath,
    fd: BorrowedFd<'_>,
    stat: &StatKey,
) -> Result<StatKey, WireErr> {
    let k = sys::stat_key(fd).map_err(|_| gone(core, path))?;
    if !sys::same_bytes(&k, stat) {
        return Err(gone(core, path));
    }
    Ok(k)
}

// hashes a pending entry's file and tells the index; Gone unless the file held still while it was read
fn hash_entry(
    core: &Core,
    path: &RelPath,
    seq: Seq,
    stat: &StatKey,
    fd: BorrowedFd<'_>,
) -> Result<Hash32, WireErr> {
    let k1 = fresh_key(core, path, fd, stat)?;
    let h = hash_verified(fd, &k1)
        .ok()
        .flatten()
        .ok_or_else(|| gone(core, path))?;
    core.learn_hash(path, seq, stat, h);
    Ok(h)
}

// one read: the bytes and their hash, with the stat key checked before and after
fn read_hashed(
    core: &Core,
    path: &RelPath,
    fd: BorrowedFd<'_>,
    stat: &StatKey,
) -> Result<(Vec<u8>, Hash32), WireErr> {
    let k1 = fresh_key(core, path, fd, stat)?;
    let buf = read_all(fd, k1.size).map_err(|_| gone(core, path))?;
    let k2 = sys::stat_key(fd).map_err(|_| gone(core, path))?;
    if !sys::same_version(&k1, &k2) || k1.ctime_ns != k2.ctime_ns {
        return Err(gone(core, path));
    }
    let h = *blake3::hash(&buf).as_bytes();
    Ok((buf, h))
}

fn parent_of(path: &RelPath) -> Option<RelPath> {
    path.split_last().and_then(|(d, _)| RelPath::new(d).ok())
}

// Ok(false) when the guest cancelled part way
fn stream_fd(
    core: &Core,
    g: &Guest,
    id: ReqId,
    fd: BorrowedFd<'_>,
    start: u64,
    len: u64,
    mut h: Option<&mut blake3::Hasher>,
) -> Result<bool, WireErr> {
    let end = start.checked_add(len).ok_or(WireErr::Invalid)?;
    let mut off = start;
    while off < end {
        if g.cancelled(id) {
            return Ok(false);
        }
        let n = (end - off).min(CHUNK_MAX as u64) as usize;
        let mut buf = vec![0u8; n];
        read_exact_at(fd, &mut buf, off).map_err(|_| WireErr::Gone)?;
        if let Some(h) = h.as_deref_mut() {
            h.update(&buf);
        }
        let at = off;
        off += n as u64;
        g.link
            .send_out(Out::Chunk {
                id,
                off: at,
                last: off == end,
                data: buf,
            })
            .map_err(|_| WireErr::Io)?;
        core.stats.tx.fetch_add(n as u64, Ordering::Relaxed);
        g.tx.fetch_add(n as u64, Ordering::Relaxed);
    }
    Ok(true)
}

fn stream_parts<'a>(
    core: &Core,
    g: &Guest,
    id: ReqId,
    parts: impl Iterator<Item = &'a [u8]>,
    total: u64,
) {
    let mut off = 0u64;
    for part in parts {
        for piece in part.chunks(CHUNK_MAX) {
            if g.cancelled(id) {
                return;
            }
            let at = off;
            off += piece.len() as u64;
            if g.link
                .send_out(Out::Chunk {
                    id,
                    off: at,
                    last: off == total,
                    data: piece.to_vec(),
                })
                .is_err()
            {
                return;
            }
            core.stats
                .tx
                .fetch_add(piece.len() as u64, Ordering::Relaxed);
        }
    }
}

struct Src {
    // carries the hash the bytes are to be checked against
    meta: Meta,
    stat: StatKey,
    fd: Arc<OwnedFd>,
    hash: Hash32,
    // set while hash is only what the guest asked for, on an entry nothing has hashed yet
    unverified: Option<Seq>,
}

// the indexed file, or for a version the index no longer has, a .git file kept from an earlier fetch
fn source(core: &Core, path: &RelPath, want: Option<Want>) -> Result<Src, WireErr> {
    let live = readable(core, path).and_then(|l| {
        let asked = match want {
            Some(Want::Hash(h)) => {
                if l.meta.hash.is_some_and(|m| m != h) {
                    return Err(WireErr::Gone);
                }
                Some(h)
            }
            Some(Want::Ver(k)) => {
                at_ver(&l, &k)?;
                None
            }
            None => None,
        };
        let fd = Arc::new(open_verified(core, path, &l.stat)?);
        let (hash, unverified) = match (l.meta.hash, asked) {
            (Some(h), _) => (h, None),
            (None, Some(h)) => (h, Some(l.seq)),
            (None, None) => (hash_entry(core, path, l.seq, &l.stat, fd.as_fd())?, None),
        };
        Ok(Src {
            meta: Meta {
                hash: Some(hash),
                ..l.meta
            },
            stat: l.stat,
            fd,
            hash,
            unverified,
        })
    });
    match live {
        Ok(s) => {
            let packed = path.as_str().contains("/objects/pack/");
            if s.unverified.is_none() && s.meta.git_ro && packed {
                core.kept.keep(s.hash, &s.meta, s.stat, &s.fd);
            }
            Ok(s)
        }
        Err(e @ (WireErr::Gone | WireErr::NotFound)) => match want {
            Some(Want::Hash(h)) => core
                .kept
                .find(&h)
                .and_then(|(meta, stat, fd)| {
                    Some(Src {
                        hash: meta.hash?,
                        meta,
                        stat,
                        fd,
                        unverified: None,
                    })
                })
                .ok_or(e),
            _ => Err(e),
        },
        Err(e) => Err(e),
    }
}

// a range cannot be hashed on its own, so a hash the guest only asserted is checked against the whole file first
fn verify(core: &Core, path: &RelPath, s: &Src) -> Result<(), WireErr> {
    let Some(seq) = s.unverified else {
        return Ok(());
    };
    if hash_entry(core, path, seq, &s.stat, s.fd.as_fd())? != s.hash {
        return Err(gone(core, path));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn fetch(
    core: &Core,
    g: &Guest,
    id: ReqId,
    path: &RelPath,
    want: Option<Want>,
    have: Option<&[ChunkSig]>,
    range: Option<(u64, u32)>,
) -> Result<(), WireErr> {
    let src = source(core, path, want)?;
    let (meta, stat, hash, fd) = (src.meta.clone(), src.stat, src.hash, src.fd.clone());
    let size = meta.size;

    if let Some((off, len)) = range {
        if off > size {
            return Err(WireErr::Invalid);
        }
        verify(core, path, &src)?;
        let n = u64::from(len).min(size - off);
        if !stream_fd(core, g, id, fd.as_fd(), off, n, None)? {
            return Err(WireErr::Gone);
        }
        // a range cannot be hashed on its own, so the inode must not have changed while it was read
        if !unchanged(fd.as_fd(), &stat) {
            return Err(gone(core, path));
        }
        return send_blob(g, id, meta, Body::Stream { len: n });
    }

    let sigs = have.filter(|h| !h.is_empty() && (DELTA_MIN..=DELTA_FILE_MAX).contains(&size));
    if size <= INLINE_MAX as u64 || sigs.is_some() {
        let buf = read_all(fd.as_fd(), size).map_err(|_| gone(core, path))?;
        if *blake3::hash(&buf).as_bytes() != hash || !unchanged(fd.as_fd(), &stat) {
            return Err(gone(core, path));
        }
        if size <= INLINE_MAX as u64 {
            core.stats.tx.fetch_add(size, Ordering::Relaxed);
            g.tx.fetch_add(size, Ordering::Relaxed);
            let body = if buf.is_empty() {
                Body::Empty
            } else {
                Body::Inline(Bytes(buf))
            };
            return send_blob(g, id, meta, body);
        }
        if let Some(enc) = sigs.and_then(|s| delta::encode(&buf, s)) {
            send_blob(
                g,
                id,
                meta,
                Body::Delta {
                    ops: enc.ops.clone(),
                    data_len: enc.data_len,
                },
            )?;
            stream_parts(core, g, id, delta::literals(&buf, &enc.ops), enc.data_len);
            return Ok(());
        }
        send_blob(g, id, meta, Body::Stream { len: size })?;
        stream_parts(core, g, id, std::iter::once(&buf[..]), size);
        return Ok(());
    }

    // chunks go first and the reply last, so a hash mismatch can still be reported as Gone
    let mut h = blake3::Hasher::new();
    if !stream_fd(core, g, id, fd.as_fd(), 0, size, Some(&mut h))? {
        return Err(WireErr::Gone);
    }
    if *h.finalize().as_bytes() != hash || !unchanged(fd.as_fd(), &stat) {
        return Err(gone(core, path));
    }
    send_blob(g, id, meta, Body::Stream { len: size })
}

fn many_one(
    core: &Core,
    path: &RelPath,
    want: &Want,
    budget: &mut usize,
) -> Result<(Hash32, Bytes), WireErr> {
    let live = readable(core, path)?;
    let asked = match *want {
        Want::Hash(h) => {
            if live.meta.hash.is_some_and(|m| m != h) {
                return Err(WireErr::Gone);
            }
            Some(h)
        }
        Want::Ver(k) => {
            at_ver(&live, &k)?;
            None
        }
    };
    let (meta, stat) = (&live.meta, live.stat);
    if meta.size > MANY_ITEM_MAX {
        return Err(WireErr::TooLarge);
    }
    let cost = meta.size as usize + 16;
    if cost > *budget {
        return Err(WireErr::Busy);
    }
    let fd = open_verified(core, path, &stat)?;
    let want = match (meta.hash, asked) {
        (Some(h), _) | (None, Some(h)) => h,
        (None, None) => hash_entry(core, path, live.seq, &stat, fd.as_fd())?,
    };
    let buf = read_all(fd.as_fd(), meta.size).map_err(|_| gone(core, path))?;
    if *blake3::hash(&buf).as_bytes() != want || !unchanged(fd.as_fd(), &stat) {
        return Err(gone(core, path));
    }
    *budget -= cost;
    Ok((want, Bytes(buf)))
}

// items that do not fit the frame budget come back Busy, or are left out once even their path no longer fits
fn many(core: &Core, g: &Guest, id: ReqId, items: &[(RelPath, Want)]) -> Result<(), WireErr> {
    let mut budget = FRAME_MAX - MANY_SLACK;
    let mut out = Vec::with_capacity(items.len());
    let mut sent = 0u64;
    for (path, hash) in items {
        if g.cancelled(id) {
            return Err(WireErr::Gone);
        }
        let entry = path.as_str().len() + 16;
        if entry > budget {
            break;
        }
        budget -= entry;
        let r = many_one(core, path, hash, &mut budget);
        if let Ok((_, b)) = &r {
            sent += b.0.len() as u64;
        }
        out.push((path.clone(), r));
    }
    core.stats.tx.fetch_add(sent, Ordering::Relaxed);
    g.tx.fetch_add(sent, Ordering::Relaxed);
    reply_bulk(g, id, Ok(Reply::Blobs { items: out }));
    Ok(())
}

// the verified hash of one index entry, with the bytes when they were asked for and fit
fn resolve_blob(
    core: &Core,
    path: &RelPath,
    at: &VerKey,
    inline: bool,
) -> Result<(Meta, Body), WireErr> {
    let live = readable(core, path)?;
    at_ver(&live, at)?;
    let fd = open_verified(core, path, &live.stat)?;
    let (hash, body) = if inline && live.stat.size <= INLINE_MAX as u64 {
        let (buf, h) = read_hashed(core, path, fd.as_fd(), &live.stat)?;
        match live.meta.hash {
            Some(known) if known != h => return Err(gone(core, path)),
            Some(_) => {}
            None => core.learn_hash(path, live.seq, &live.stat, h),
        }
        core.stats.tx.fetch_add(buf.len() as u64, Ordering::Relaxed);
        let body = if buf.is_empty() {
            Body::Empty
        } else {
            Body::Inline(Bytes(buf))
        };
        (h, body)
    } else {
        let h = match live.meta.hash {
            Some(known) if unchanged(fd.as_fd(), &live.stat) => known,
            Some(_) => return Err(gone(core, path)),
            None => hash_entry(core, path, live.seq, &live.stat, fd.as_fd())?,
        };
        (h, Body::Empty)
    };
    if let Some(parent) = parent_of(path) {
        core.hint_dir(&parent);
    }
    let meta = Meta {
        hash: Some(hash),
        ..live.meta
    };
    Ok((meta, body))
}

fn resolve(
    core: &Core,
    g: &Guest,
    id: ReqId,
    path: &RelPath,
    at: VerKey,
    inline: bool,
) -> Result<(), WireErr> {
    let (meta, body) = resolve_blob(core, path, &at, inline)?;
    if let Body::Inline(b) = &body {
        g.tx.fetch_add(b.0.len() as u64, Ordering::Relaxed);
    }
    send_blob(g, id, meta, body)
}

// a pure index lookup: a hash comes back only for an entry at exactly that seq whose hash is already known
fn hash_lookup(
    core: &Core,
    index: IndexId,
    items: &[(RelPath, Seq)],
) -> Result<Vec<Option<Hash32>>, WireErr> {
    if items.len() > BATCH_MAX {
        return Err(WireErr::Invalid);
    }
    let rules = core.rules_r();
    let tree = core.tree();
    if index != tree.index_id() {
        return Err(WireErr::Gone);
    }
    Ok(items
        .iter()
        .map(|(p, seq)| {
            if p.is_root() || !matches!(rules.classify(p, false), Class::Synced | Class::GitRo) {
                return None;
            }
            tree.get(p)
                .filter(|e| e.seq == *seq && e.meta.kind == Kind::File)
                .and_then(|e| e.meta.hash)
        })
        .collect())
}

fn hashes(
    core: &Core,
    g: &Guest,
    id: ReqId,
    index: IndexId,
    items: &[(RelPath, Seq)],
) -> Result<(), WireErr> {
    let items = hash_lookup(core, index, items)?;
    reply_bulk(g, id, Ok(Reply::Hashes { items }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ignore::rules::Rules;
    use crate::index::scan;
    use crate::index::tree::{Domain, Observed};
    use crate::proto::Name;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::RwLock,
    };

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> (Tmp, Core, crossbeam_channel::Receiver<Vec<sys::WatchEvent>>) {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!(
            "csync-serve-pend-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(&p).unwrap();
        let root = fs::canonicalize(&p).unwrap();
        let mut rules = Rules::new(&[]);
        let tree = scan::scan(&root, &mut rules).unwrap();
        let (ev, rx) = crossbeam_channel::bounded(64);
        let core = Core::new(
            root.clone(),
            Name::new("t").unwrap(),
            tree,
            Arc::new(RwLock::new(rules)),
            ev,
        )
        .unwrap();
        (Tmp(root), core, rx)
    }

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    fn h(b: &[u8]) -> Hash32 {
        *blake3::hash(b).as_bytes()
    }

    // writes the file and indexes it by stat key and seq only, or with its hash when `hashed`
    fn index_file(core: &Core, root: &Path, name: &str, data: &[u8], hashed: bool) -> VerKey {
        fs::write(root.join(name), data).unwrap();
        let f = fs::File::open(root.join(name)).unwrap();
        let st = sys::stat_key(f.as_fd()).unwrap();
        let mut meta = crate::host::file_meta(&st, h(data), false);
        if !hashed {
            meta.hash = None;
        }
        let mut tree = core.tree();
        let _ = tree.observe(
            &rp(name),
            Observed::Present {
                meta,
                stat: st,
                domain: Domain::Synced,
            },
        );
        VerKey {
            index: tree.index_id(),
            ver: tree.get(&rp(name)).unwrap().seq,
            size: st.size,
        }
    }

    fn indexed_hash(core: &Core, name: &str) -> Option<Hash32> {
        core.tree().get(&rp(name)).unwrap().meta.hash
    }

    #[test]
    fn resolve_gives_the_true_hash_and_bytes_of_a_pending_file() {
        let (t, core, _rx) = fixture();
        let k = index_file(&core, &t.0, "a.txt", b"hello\n", false);
        let (meta, body) = resolve_blob(&core, &rp("a.txt"), &k, true).unwrap();
        assert_eq!(meta.hash, Some(h(b"hello\n")));
        assert_eq!(meta.size, 6);
        assert_eq!(body, Body::Inline(Bytes(b"hello\n".to_vec())));
        assert_eq!(indexed_hash(&core, "a.txt"), Some(h(b"hello\n")));

        let k = index_file(&core, &t.0, "b.txt", b"hello\n", false);
        let (meta, body) = resolve_blob(&core, &rp("b.txt"), &k, false).unwrap();
        assert_eq!(meta.hash, Some(h(b"hello\n")));
        assert_eq!(body, Body::Empty);

        let big = vec![7u8; INLINE_MAX + 1];
        let k = index_file(&core, &t.0, "big.bin", &big, false);
        let (meta, body) = resolve_blob(&core, &rp("big.bin"), &k, true).unwrap();
        assert_eq!(meta.hash, Some(h(&big)));
        assert_eq!(body, Body::Empty);

        let k = index_file(&core, &t.0, "known.txt", b"known\n", true);
        let (meta, body) = resolve_blob(&core, &rp("known.txt"), &k, true).unwrap();
        assert_eq!(meta.hash, Some(h(b"known\n")));
        assert_eq!(body, Body::Inline(Bytes(b"known\n".to_vec())));
    }

    #[test]
    fn resolve_is_gone_for_a_changed_file_or_a_version_the_index_does_not_hold() {
        let (t, core, _rx) = fixture();
        let a = rp("a.txt");
        let k = index_file(&core, &t.0, "a.txt", b"hello\n", false);
        for bad in [
            VerKey {
                ver: k.ver.wrapping_add(1),
                ..k
            },
            VerKey {
                index: k.index ^ 1,
                ..k
            },
            VerKey {
                size: k.size + 1,
                ..k
            },
        ] {
            assert_eq!(
                resolve_blob(&core, &a, &bad, true).err(),
                Some(WireErr::Gone)
            );
        }
        assert_eq!(indexed_hash(&core, "a.txt"), None);

        fs::write(t.0.join("a.txt"), b"hello, changed\n").unwrap();
        assert_eq!(resolve_blob(&core, &a, &k, true).err(), Some(WireErr::Gone));
        assert_eq!(
            resolve_blob(&core, &a, &k, false).err(),
            Some(WireErr::Gone)
        );
        assert_eq!(indexed_hash(&core, "a.txt"), None);

        // same size and mtime, other bytes: an entry with a known hash must still not hand them out
        let k = index_file(&core, &t.0, "k.txt", b"known\n", true);
        let mtime = fs::metadata(t.0.join("k.txt")).unwrap().modified().unwrap();
        fs::write(t.0.join("k.txt"), b"other\n").unwrap();
        fs::File::options()
            .write(true)
            .open(t.0.join("k.txt"))
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        assert_eq!(
            resolve_blob(&core, &rp("k.txt"), &k, true).err(),
            Some(WireErr::Gone)
        );
    }

    #[test]
    fn hashes_never_hash_and_answer_only_for_known_entries_at_that_seq() {
        let (t, core, _rx) = fixture();
        let known = index_file(&core, &t.0, "known.txt", b"known\n", true);
        let pend = index_file(&core, &t.0, "pend.txt", b"pend\n", false);
        let items = vec![
            (rp("known.txt"), known.ver),
            (rp("pend.txt"), pend.ver),
            (rp("known.txt"), known.ver.wrapping_add(1)),
            (rp("missing.txt"), 1),
        ];
        let got = hash_lookup(&core, known.index, &items).unwrap();
        assert_eq!(got, vec![Some(h(b"known\n")), None, None, None]);
        assert_eq!(indexed_hash(&core, "pend.txt"), None);
        assert_eq!(
            hash_lookup(&core, known.index ^ 1, &items).err(),
            Some(WireErr::Gone)
        );
    }

    #[test]
    fn a_wanted_hash_the_bytes_of_a_pending_entry_do_not_have_serves_nothing() {
        let (t, core, _rx) = fixture();
        let wrong = Want::Hash(h(b"other bytes\n"));
        let right = Want::Hash(h(b"real bytes\n"));
        let mut budget = FRAME_MAX;

        index_file(&core, &t.0, "range.txt", b"real bytes\n", false);
        let s = source(&core, &rp("range.txt"), Some(wrong)).unwrap();
        assert!(s.unverified.is_some());
        assert_eq!(
            verify(&core, &rp("range.txt"), &s).err(),
            Some(WireErr::Gone)
        );

        index_file(&core, &t.0, "range2.txt", b"real bytes\n", false);
        let s = source(&core, &rp("range2.txt"), Some(right)).unwrap();
        assert_eq!(verify(&core, &rp("range2.txt"), &s), Ok(()));
        assert_eq!(indexed_hash(&core, "range2.txt"), Some(h(b"real bytes\n")));

        index_file(&core, &t.0, "many.txt", b"real bytes\n", false);
        assert_eq!(
            many_one(&core, &rp("many.txt"), &wrong, &mut budget).err(),
            Some(WireErr::Gone)
        );
        index_file(&core, &t.0, "many2.txt", b"real bytes\n", false);
        let (got, bytes) = many_one(&core, &rp("many2.txt"), &right, &mut budget).unwrap();
        assert_eq!(
            (got, bytes.0),
            (h(b"real bytes\n"), b"real bytes\n".to_vec())
        );
    }

    #[test]
    fn fetching_by_ver_hashes_first_and_a_stale_ver_is_gone() {
        let (t, core, _rx) = fixture();
        let k = index_file(&core, &t.0, "a.txt", b"one\n", false);
        let s = source(&core, &rp("a.txt"), Some(Want::Ver(k))).unwrap();
        assert_eq!(s.hash, h(b"one\n"));
        assert_eq!(s.meta.hash, Some(h(b"one\n")));
        assert!(s.unverified.is_none());
        let stale = VerKey {
            ver: k.ver.wrapping_add(1),
            ..k
        };
        assert_eq!(
            source(&core, &rp("a.txt"), Some(Want::Ver(stale))).err(),
            Some(WireErr::Gone)
        );

        // a probe with no want also hashes a pending entry instead of failing
        index_file(&core, &t.0, "p.txt", b"probe\n", false);
        let s = source(&core, &rp("p.txt"), None).unwrap();
        assert_eq!(s.meta.hash, Some(h(b"probe\n")));
    }

    #[test]
    fn many_by_ver_returns_the_verified_hash_per_item() {
        let (t, core, _rx) = fixture();
        let mut budget = FRAME_MAX;
        let ka = index_file(&core, &t.0, "a.txt", b"alpha\n", false);
        let kb = index_file(&core, &t.0, "b.txt", b"beta\n", false);
        let kc = index_file(&core, &t.0, "c.txt", b"gamma\n", true);
        for (n, k, data) in [
            ("a.txt", ka, &b"alpha\n"[..]),
            ("b.txt", kb, &b"beta\n"[..]),
            ("c.txt", kc, &b"gamma\n"[..]),
        ] {
            let (got, bytes) = many_one(&core, &rp(n), &Want::Ver(k), &mut budget).unwrap();
            assert_eq!((got, bytes.0.as_slice()), (h(data), data));
        }
        assert_eq!(indexed_hash(&core, "a.txt"), Some(h(b"alpha\n")));
        let stale = VerKey {
            ver: kb.ver.wrapping_add(1),
            ..kb
        };
        assert_eq!(
            many_one(&core, &rp("b.txt"), &Want::Ver(stale), &mut budget).err(),
            Some(WireErr::Gone)
        );
    }

    #[test]
    fn a_chmod_does_not_make_unchanged_bytes_gone() {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!(
            "csync-serve-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(&p).unwrap();
        let root = fs::canonicalize(&p).unwrap();
        fs::write(root.join("a.txt"), "same bytes\n").unwrap();
        let mut rules = Rules::new(&[]);
        let tree = scan::scan(&root, &mut rules).unwrap();
        let (ev, _rx) = crossbeam_channel::bounded(64);
        let core = Core::new(
            root.clone(),
            Name::new("t").unwrap(),
            tree,
            Arc::new(RwLock::new(rules)),
            ev,
        )
        .unwrap();
        let a = RelPath::new("a.txt").unwrap();
        let stat = core.tree().get(&a).unwrap().stat;
        fs::set_permissions(root.join("a.txt"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open_verified(&core, &a, &stat).is_ok());
        fs::write(root.join("a.txt"), "other bytes, longer\n").unwrap();
        assert_eq!(open_verified(&core, &a, &stat).err(), Some(WireErr::Gone));
        let _ = fs::remove_dir_all(&root);
    }
}
