use super::{Core, Guest, read_all, read_exact_at};
use crate::delta;
use crate::ignore::rules::Class;
use crate::index::tree::StatKey;
use crate::net::conn::{Out, Prio};
use crate::proto::{
    Body, Bytes, CHUNK_MAX, ChunkSig, DELTA_MIN, FRAME_MAX, Hash32, INLINE_MAX, Kind, Meta, Msg,
    Op, RelPath, Reply, ReqId, WireErr,
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

// only indexed files are served: ignored paths are never in the index and are refused again here
fn readable(core: &Core, path: &RelPath) -> Result<(Meta, StatKey), WireErr> {
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
        Kind::File => Ok((e.meta.clone(), e.stat)),
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

// the indexed file, or for a version the index no longer has, a .git file kept from an earlier fetch
fn source(
    core: &Core,
    path: &RelPath,
    want: Option<Hash32>,
) -> Result<(Meta, StatKey, Arc<OwnedFd>), WireErr> {
    let live = readable(core, path).and_then(|(meta, stat)| {
        if want.is_some_and(|h| meta.hash != Some(h)) {
            return Err(WireErr::Gone);
        }
        Ok((meta, stat, Arc::new(open_verified(core, path, &stat)?)))
    });
    match live {
        Ok((meta, stat, fd)) => {
            let packed = path.as_str().contains("/objects/pack/");
            if let Some(h) = meta.hash.filter(|_| meta.git_ro && packed) {
                core.kept.keep(h, &meta, stat, &fd);
            }
            Ok((meta, stat, fd))
        }
        Err(e @ (WireErr::Gone | WireErr::NotFound)) => {
            want.and_then(|h| core.kept.find(&h)).ok_or(e)
        }
        Err(e) => Err(e),
    }
}

#[allow(clippy::too_many_arguments)]
fn fetch(
    core: &Core,
    g: &Guest,
    id: ReqId,
    path: &RelPath,
    want: Option<Hash32>,
    have: Option<&[ChunkSig]>,
    range: Option<(u64, u32)>,
) -> Result<(), WireErr> {
    let (meta, stat, fd) = source(core, path, want)?;
    let hash = meta.hash.ok_or(WireErr::Invalid)?;
    let size = meta.size;

    if let Some((off, len)) = range {
        if off > size {
            return Err(WireErr::Invalid);
        }
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
    want: &Hash32,
    budget: &mut usize,
) -> Result<Bytes, WireErr> {
    let (meta, stat) = readable(core, path)?;
    if meta.hash != Some(*want) {
        return Err(WireErr::Gone);
    }
    if meta.size > MANY_ITEM_MAX {
        return Err(WireErr::TooLarge);
    }
    let cost = meta.size as usize + 16;
    if cost > *budget {
        return Err(WireErr::Busy);
    }
    let fd = open_verified(core, path, &stat)?;
    let buf = read_all(fd.as_fd(), meta.size).map_err(|_| gone(core, path))?;
    if blake3::hash(&buf).as_bytes() != want || !unchanged(fd.as_fd(), &stat) {
        return Err(gone(core, path));
    }
    *budget -= cost;
    Ok(Bytes(buf))
}

// items that do not fit the frame budget come back Busy, or are left out once even their path no longer fits
fn many(core: &Core, g: &Guest, id: ReqId, items: &[(RelPath, Hash32)]) -> Result<(), WireErr> {
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
        if let Ok(b) = &r {
            sent += b.0.len() as u64;
        }
        out.push((path.clone(), r));
    }
    core.stats.tx.fetch_add(sent, Ordering::Relaxed);
    reply_bulk(g, id, Ok(Reply::Blobs { items: out }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ignore::rules::Rules;
    use crate::index::scan;
    use crate::proto::Name;
    use std::{fs, os::unix::fs::PermissionsExt, sync::RwLock};

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
