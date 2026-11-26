use crate::{
    proto::RelPath,
    sys::{DirFilter, ResumeToken, WatchEvent, Watcher, invalid, lock, strictly_under, wflag},
};
use crossbeam_channel::{Sender, TrySendError};
use dispatch2::{DispatchQueue, DispatchRetained};
use objc2_core_foundation::{CFArray, CFRetained, CFString};
use objc2_core_services::{
    ConstFSEventStreamRef, FSEventStreamContext, FSEventStreamCreateRelativeToDevice,
    FSEventStreamEventFlags, FSEventStreamEventId, FSEventStreamGetLatestEventId,
    FSEventStreamInvalidate, FSEventStreamRef, FSEventStreamRelease, FSEventStreamSetDispatchQueue,
    FSEventStreamSetExclusionPaths, FSEventStreamStart, FSEventStreamStop,
    FSEventsCopyUUIDForDevice, FSEventsGetCurrentEventId, kFSEventStreamCreateFlagFileEvents,
    kFSEventStreamCreateFlagMarkSelf, kFSEventStreamCreateFlagNoDefer,
    kFSEventStreamCreateFlagWatchRoot, kFSEventStreamEventFlagEventIdsWrapped,
    kFSEventStreamEventFlagHistoryDone, kFSEventStreamEventFlagItemChangeOwner,
    kFSEventStreamEventFlagItemCloned, kFSEventStreamEventFlagItemCreated,
    kFSEventStreamEventFlagItemFinderInfoMod, kFSEventStreamEventFlagItemInodeMetaMod,
    kFSEventStreamEventFlagItemIsDir, kFSEventStreamEventFlagItemModified,
    kFSEventStreamEventFlagItemRemoved, kFSEventStreamEventFlagItemRenamed,
    kFSEventStreamEventFlagItemXattrMod, kFSEventStreamEventFlagKernelDropped,
    kFSEventStreamEventFlagMount, kFSEventStreamEventFlagMustScanSubDirs,
    kFSEventStreamEventFlagOwnEvent, kFSEventStreamEventFlagRootChanged,
    kFSEventStreamEventFlagUnmount, kFSEventStreamEventFlagUserDropped,
    kFSEventStreamEventIdSinceNow,
};
use rustix::fs::{Mode, OFlags};
use std::{
    ffi::{CStr, c_char, c_void},
    io,
    path::Path,
    ptr::NonNull,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

const LATENCY: f64 = 0.01;
const MAX_EXCLUDES: usize = 8;

type Callback = unsafe extern "C-unwind" fn(
    ConstFSEventStreamRef,
    *mut c_void,
    usize,
    NonNull<c_void>,
    NonNull<FSEventStreamEventFlags>,
    NonNull<FSEventStreamEventId>,
);

struct Filt {
    excludes: Vec<RelPath>,
    muted: Vec<RelPath>,
    accept: Option<DirFilter>,
}

impl Filt {
    fn blocks(&self, path: &RelPath, cache: &mut Option<(RelPath, bool)>) -> bool {
        if strictly_under(path, &self.excludes) || strictly_under(path, &self.muted) {
            return true;
        }
        let Some(accept) = &self.accept else {
            return false;
        };
        let Some((parent, _)) = path.split_last() else {
            return false;
        };
        if parent.is_empty() {
            return false;
        }
        if let Some((p, ok)) = cache
            && p.as_str() == parent
        {
            return !*ok;
        }
        let Ok(pr) = RelPath::new(parent) else {
            return false;
        };
        let ok = accept(&pr);
        *cache = Some((pr, ok));
        !ok
    }
}

struct Shared {
    last_id: AtomicU64,
    overflowed: AtomicBool,
    filt: Mutex<Filt>,
}

struct Ctx {
    tx: Sender<Vec<WatchEvent>>,
    shared: Arc<Shared>,
    prefixes: Arc<[Box<[u8]>]>,
}

fn rescan_root() -> WatchEvent {
    WatchEvent {
        path: RelPath::root(),
        flags: wflag::RESCAN | wflag::OVERFLOW,
        cookie: 0,
    }
}

fn map_flags(f: u32) -> u32 {
    let mut w = 0;
    if f & kFSEventStreamEventFlagItemCreated != 0 {
        w |= wflag::CREATED;
    }
    if f & kFSEventStreamEventFlagItemRemoved != 0 {
        w |= wflag::REMOVED;
    }
    if f & kFSEventStreamEventFlagItemRenamed != 0 {
        w |= wflag::RENAMED;
    }
    if f & (kFSEventStreamEventFlagItemModified | kFSEventStreamEventFlagItemCloned) != 0 {
        w |= wflag::MODIFIED;
    }
    if f & (kFSEventStreamEventFlagItemInodeMetaMod
        | kFSEventStreamEventFlagItemChangeOwner
        | kFSEventStreamEventFlagItemXattrMod
        | kFSEventStreamEventFlagItemFinderInfoMod)
        != 0
    {
        w |= wflag::ATTRIB;
    }
    if f & kFSEventStreamEventFlagItemIsDir != 0 {
        w |= wflag::IS_DIR;
    }
    if f & kFSEventStreamEventFlagOwnEvent != 0 {
        w |= wflag::OWN;
    }
    w
}

// event paths are device relative; absolute forms are accepted too in case the kernel reports them
fn relativise<'a>(prefixes: &[Box<[u8]>], raw: &'a [u8]) -> Option<&'a str> {
    let mut r = raw;
    while let [b'/', rest @ ..] = r {
        r = rest;
    }
    while let [rest @ .., b'/'] = r {
        r = rest;
    }
    for p in prefixes {
        if p.is_empty() {
            return std::str::from_utf8(r).ok();
        }
        if let Some(tail) = r.strip_prefix(&p[..]) {
            if tail.is_empty() {
                return Some("");
            }
            if let Some(t) = tail.strip_prefix(b"/") {
                return std::str::from_utf8(t).ok();
            }
        }
    }
    None
}

impl Ctx {
    fn handle(
        &self,
        paths: &[*const c_char],
        flags: &[FSEventStreamEventFlags],
        ids: &[FSEventStreamEventId],
    ) {
        let mut out = Vec::with_capacity(paths.len());
        let mut max_id = 0u64;
        let mut wrapped = false;
        let mut prev_rename: Option<(u64, u32)> = None;
        let mut parent_cache: Option<(RelPath, bool)> = None;
        {
            let filt = lock(&self.shared.filt);
            for ((&p, &f), &id) in paths.iter().zip(flags).zip(ids) {
                if f & kFSEventStreamEventFlagEventIdsWrapped != 0 {
                    wrapped = true;
                    out.push(rescan_root());
                    continue;
                }
                max_id = max_id.max(id);
                if f & kFSEventStreamEventFlagHistoryDone != 0 {
                    continue;
                }
                // the root was moved or replaced: the caller checks what the path now names
                if f & kFSEventStreamEventFlagRootChanged != 0 {
                    out.push(rescan_root());
                    continue;
                }
                if f & (kFSEventStreamEventFlagUserDropped | kFSEventStreamEventFlagKernelDropped)
                    != 0
                {
                    out.push(rescan_root());
                    continue;
                }
                if p.is_null() {
                    continue;
                }
                // SAFETY: every non-null entry is a nul-terminated path that lives for the whole callback.
                let raw = unsafe { CStr::from_ptr(p) }.to_bytes();
                let Some(rel) = relativise(&self.prefixes, raw) else {
                    continue;
                };
                let path = if rel.is_empty() {
                    RelPath::root()
                } else {
                    match RelPath::new(rel) {
                        Ok(p) => p,
                        Err(_) => continue,
                    }
                };
                if !path.is_root() && filt.blocks(&path, &mut parent_cache) {
                    continue;
                }
                if f & (kFSEventStreamEventFlagMustScanSubDirs
                    | kFSEventStreamEventFlagMount
                    | kFSEventStreamEventFlagUnmount)
                    != 0
                {
                    out.push(WatchEvent {
                        path,
                        flags: wflag::RESCAN | wflag::IS_DIR,
                        cookie: 0,
                    });
                    continue;
                }
                let mut cookie = 0;
                if f & kFSEventStreamEventFlagItemRenamed != 0 {
                    cookie = match prev_rename {
                        Some((pid, c)) if id == pid.wrapping_add(1) => {
                            prev_rename = None;
                            c
                        }
                        _ => {
                            let c = (id as u32).max(1);
                            prev_rename = Some((id, c));
                            c
                        }
                    };
                } else {
                    prev_rename = None;
                }
                out.push(WatchEvent {
                    path,
                    flags: map_flags(f),
                    cookie,
                });
            }
        }
        if wrapped {
            if let Some(&last) = ids.last() {
                self.shared.last_id.store(last, Ordering::Release);
            }
        } else if max_id != 0 {
            self.shared.last_id.fetch_max(max_id, Ordering::AcqRel);
        }
        deliver(&self.tx, &self.shared, out);
    }
}

// never blocks the dispatch queue: a full channel degrades into one later rescan request
fn deliver(tx: &Sender<Vec<WatchEvent>>, shared: &Shared, out: Vec<WatchEvent>) {
    if out.is_empty() {
        return;
    }
    if shared.overflowed.load(Ordering::Acquire) {
        match tx.try_send(vec![rescan_root()]) {
            Ok(()) => shared.overflowed.store(false, Ordering::Release),
            Err(_) => return,
        }
    }
    if let Err(TrySendError::Full(_)) = tx.try_send(out) {
        shared.overflowed.store(true, Ordering::Release);
    }
}

unsafe extern "C-unwind" fn on_events(
    _stream: ConstFSEventStreamRef,
    info: *mut c_void,
    n: usize,
    paths: NonNull<c_void>,
    flags: NonNull<FSEventStreamEventFlags>,
    ids: NonNull<FSEventStreamEventId>,
) {
    if info.is_null() || n == 0 {
        return;
    }
    // SAFETY: info is the ctx box registered for this stream; it is freed only after invalidate and a queue drain.
    let ctx = unsafe { &*info.cast::<Ctx>() };
    // SAFETY: without kFSEventStreamCreateFlagUseCFTypes fsevents passes n c-string pointers, n flags and n ids.
    let (paths, flags, ids) = unsafe {
        (
            std::slice::from_raw_parts(paths.as_ptr().cast::<*const c_char>(), n),
            std::slice::from_raw_parts(flags.as_ptr(), n),
            std::slice::from_raw_parts(ids.as_ptr(), n),
        )
    };
    ctx.handle(paths, flags, ids);
}

struct Stream {
    s: FSEventStreamRef,
    ctx: *mut Ctx,
}

// SAFETY: the stream is only touched on its serial queue or after that queue is drained, and ctx is only freed then.
unsafe impl Send for Stream {}

struct SendPtr(FSEventStreamRef);

// SAFETY: the pointer is handed to the stream's own serial queue and used there exclusively.
unsafe impl Send for SendPtr {}

impl SendPtr {
    fn get(self) -> FSEventStreamRef {
        self.0
    }
}

fn stop_stream(queue: &DispatchQueue, st: Stream, shared: &Shared) {
    let Stream { s, ctx } = st;
    let sp = SendPtr(s);
    let mut latest = 0u64;
    let lp = &mut latest;
    queue.exec_sync(move || {
        let s = sp.get();
        // SAFETY: s is a live stream we created; running on its own serial queue excludes a concurrent callback.
        unsafe {
            FSEventStreamStop(s);
            *lp = FSEventStreamGetLatestEventId(s.cast_const());
            FSEventStreamInvalidate(s);
            FSEventStreamRelease(s);
        }
    });
    queue.exec_sync(|| {});
    if latest != 0 && latest != kFSEventStreamEventIdSinceNow {
        shared.last_id.fetch_max(latest, Ordering::AcqRel);
    }
    // SAFETY: the stream is released and its queue drained, so no callback can still reach ctx.
    drop(unsafe { Box::from_raw(ctx) });
}

pub struct FsEventsWatcher {
    queue: DispatchRetained<DispatchQueue>,
    stream: Option<Stream>,
    shared: Arc<Shared>,
    tx: Sender<Vec<WatchEvent>>,
    dev: libc::dev_t,
    volume: Option<[u8; 16]>,
    rel_root: String,
    prefixes: Arc<[Box<[u8]>]>,
}

fn device_relative<'a>(canon: &'a str, mnt: &str) -> &'a str {
    let rest = if mnt == "/" {
        canon
    } else {
        match canon.strip_prefix(mnt) {
            Some(r) if r.is_empty() || r.starts_with('/') => r,
            // firmlinked into the data volume: /Users/x lives at <data>/Users/x
            _ => canon,
        }
    };
    rest.trim_matches('/')
}

impl FsEventsWatcher {
    pub fn start(
        root: &Path,
        resume: Option<ResumeToken>,
        tx: Sender<Vec<WatchEvent>>,
        accept: Option<DirFilter>,
    ) -> io::Result<Self> {
        let canon = std::fs::canonicalize(root)?;
        let canon = canon
            .to_str()
            .ok_or_else(|| invalid("watch root is not utf-8"))?
            .to_owned();
        let fd = rustix::fs::open(
            canon.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let dev = rustix::fs::fstat(&fd)?.st_dev;
        let sfs = rustix::fs::fstatfs(&fd)?;
        let mnt: Vec<u8> = sfs
            .f_mntonname
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        let mnt = String::from_utf8(mnt).map_err(|_| invalid("mount point is not utf-8"))?;
        let rel_root = device_relative(&canon, &mnt).to_owned();

        let mut prefixes: Vec<Box<[u8]>> = vec![rel_root.as_bytes().into()];
        let abs = canon.trim_matches('/');
        let mnt_rel = format!("{}/{}", mnt.trim_matches('/'), rel_root);
        for p in [abs, mnt_rel.trim_matches('/')] {
            if !prefixes.iter().any(|x| &x[..] == p.as_bytes()) {
                prefixes.push(p.as_bytes().into());
            }
        }

        // SAFETY: a plain query by device number with no pointer arguments.
        let volume =
            unsafe { FSEventsCopyUUIDForDevice(dev) }.map(|u| <[u8; 16]>::from(u.uuid_bytes()));
        // SAFETY: takes no arguments and only reads fseventsd state.
        let now = unsafe { FSEventsGetCurrentEventId() };
        let (since, start_id, rescan) = match (resume, volume) {
            (Some(t), Some(v)) if t.volume == v && t.event_id != 0 => {
                (t.event_id, t.event_id, false)
            }
            (Some(_), _) => (kFSEventStreamEventIdSinceNow, now, true),
            (None, _) => (kFSEventStreamEventIdSinceNow, now, false),
        };
        let shared = Arc::new(Shared {
            last_id: AtomicU64::new(start_id),
            overflowed: AtomicBool::new(false),
            filt: Mutex::new(Filt {
                excludes: Vec::new(),
                muted: Vec::new(),
                accept,
            }),
        });
        let mut w = Self {
            queue: DispatchQueue::new("csync.fsevents", None),
            stream: None,
            shared,
            tx,
            dev,
            volume,
            rel_root,
            prefixes: prefixes.into(),
        };
        if rescan {
            deliver(&w.tx, &w.shared, vec![rescan_root()]);
        }
        w.stream = Some(w.open_stream(since)?);
        Ok(w)
    }

    fn dev_path(&self, p: &RelPath) -> String {
        if self.rel_root.is_empty() {
            p.as_str().to_owned()
        } else {
            format!("{}/{}", self.rel_root, p.as_str())
        }
    }

    fn open_stream(&self, since: u64) -> io::Result<Stream> {
        let excludes: Vec<CFRetained<CFString>> = {
            let f = lock(&self.shared.filt);
            f.excludes
                .iter()
                .filter(|e| !e.is_root())
                .take(MAX_EXCLUDES)
                .map(|e| CFString::from_str(&self.dev_path(e)))
                .collect()
        };
        let ctx = Box::into_raw(Box::new(Ctx {
            tx: self.tx.clone(),
            shared: self.shared.clone(),
            prefixes: self.prefixes.clone(),
        }));
        let mut c = FSEventStreamContext {
            version: 0,
            info: ctx.cast(),
            retain: None,
            release: None,
            copyDescription: None,
        };
        let watch = CFArray::from_retained_objects(&[CFString::from_str(&self.rel_root)]);
        let flags = kFSEventStreamCreateFlagFileEvents
            | kFSEventStreamCreateFlagNoDefer
            | kFSEventStreamCreateFlagMarkSelf
            | kFSEventStreamCreateFlagWatchRoot;
        let cb: Callback = on_events;
        // SAFETY: the callback matches FSEventStreamCallback, the context struct is copied by the call, and the array holds cfstrings.
        let s = unsafe {
            FSEventStreamCreateRelativeToDevice(
                None,
                Some(cb),
                &mut c,
                self.dev,
                watch.as_opaque(),
                since,
                LATENCY,
                flags,
            )
        };
        if s.is_null() {
            // SAFETY: no stream was created, so nothing else holds ctx.
            drop(unsafe { Box::from_raw(ctx) });
            return Err(io::Error::other(
                "FSEventStreamCreateRelativeToDevice failed",
            ));
        }
        if !excludes.is_empty() {
            let arr = CFArray::from_retained_objects(&excludes);
            // SAFETY: s is a valid, not yet started stream and the array holds cfstrings.
            unsafe { FSEventStreamSetExclusionPaths(s, arr.as_opaque()) };
        }
        // SAFETY: s is valid and the queue outlives the stream, which is torn down before the watcher drops the queue.
        unsafe { FSEventStreamSetDispatchQueue(s, Some(&*self.queue)) };
        let st = Stream { s, ctx };
        // SAFETY: s is valid and scheduled on a queue.
        if !unsafe { FSEventStreamStart(s) } {
            stop_stream(&self.queue, st, &self.shared);
            return Err(io::Error::other("FSEventStreamStart failed"));
        }
        Ok(st)
    }

    fn restart(&mut self) -> io::Result<()> {
        if let Some(st) = self.stream.take() {
            stop_stream(&self.queue, st, &self.shared);
        }
        let since = match self.shared.last_id.load(Ordering::Acquire) {
            0 => kFSEventStreamEventIdSinceNow,
            id => id,
        };
        self.stream = Some(self.open_stream(since)?);
        Ok(())
    }
}

impl Watcher for FsEventsWatcher {
    fn set_excludes(&mut self, dirs: &[RelPath]) -> io::Result<()> {
        {
            let mut f = lock(&self.shared.filt);
            if f.excludes == dirs {
                return Ok(());
            }
            f.excludes = dirs.to_vec();
        }
        self.restart()
    }

    fn watch_dir(&mut self, dir: &RelPath) -> io::Result<()> {
        lock(&self.shared.filt)
            .muted
            .retain(|m| !m.starts_with(dir));
        Ok(())
    }

    fn unwatch_dir(&mut self, dir: &RelPath) {
        let mut f = lock(&self.shared.filt);
        if f.muted.iter().any(|m| dir.starts_with(m)) {
            return;
        }
        f.muted.retain(|m| !m.starts_with(dir));
        f.muted.push(dir.clone());
    }

    fn take_overflow(&self) -> bool {
        self.shared.overflowed.swap(false, Ordering::AcqRel)
    }

    fn resume_token(&self) -> Option<ResumeToken> {
        let event_id = self.shared.last_id.load(Ordering::Acquire);
        self.volume
            .filter(|_| event_id != 0)
            .map(|volume| ResumeToken { volume, event_id })
    }
}

impl Drop for FsEventsWatcher {
    fn drop(&mut self) {
        if let Some(st) = self.stream.take() {
            stop_stream(&self.queue, st, &self.shared);
        }
    }
}
