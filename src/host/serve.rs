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
    sync::{Arc, atomic::Ordering},
};

// beyond this a delta would need the whole file in memory; such files use range fetches anyway
const DELTA_FILE_MAX: u64 = 64 << 20;
const MANY_ITEM_MAX: u64 = 1 << 20;
const MANY_SLACK: usize = 64 << 10;

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
    if sys::kind_of_mode(st.mode) != Some(Kind::File) || !sys::same_version(&st, stat) {
        return Err(gone(core, path));
    }
    Ok(fd)
}

fn unchanged(fd: BorrowedFd<'_>, stat: &StatKey) -> bool {
    sys::stat_key(fd).is_ok_and(|s| sys::same_version(&s, stat))
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
    let (meta, stat) = readable(core, path)?;
    if want.is_some_and(|h| meta.hash != Some(h)) {
        return Err(WireErr::Gone);
    }
    let hash = meta.hash.ok_or(WireErr::Invalid)?;
    let fd = open_verified(core, path, &stat)?;
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
