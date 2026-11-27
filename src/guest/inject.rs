use super::tree::{Effect, GTree, NodeId, Synth, Vis};
use crate::proto::{Kind, Name};
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded, select_biased};
use rustc_hash::FxHashSet;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use std::{
    io,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicBool, AtomicI32, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

// set when the kernel takes file sizes from attribute replies: a truncate would then only hold back
// every size it learns until its own reply, so a modify is raised another way
pub static SIZES_FROM_ATTRS: AtomicBool = AtomicBool::new(false);

// TRACE: set while the injector thread runs a syscall through the mount
pub static BUSY: AtomicBool = AtomicBool::new(false);

pub const QUEUE_MAX: usize = 4_096;
const BACK_MAX: usize = 1_024;
const OFFER_WAIT: Duration = Duration::from_secs(1);

#[cfg(target_os = "linux")]
const ROOT_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
#[cfg(target_os = "macos")]
const ROOT_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

// runs on the injector thread before its first event with the mount root, if it could be opened;
// false when events must not be replayed through the mount
#[cfg(target_os = "macos")]
pub type Boot = Box<dyn FnOnce(Option<&OwnedFd>) -> bool + Send>;

struct Shared {
    tid: AtomicI32,
    stalled: AtomicBool,
    #[cfg(target_os = "macos")]
    off: AtomicBool,
    queued: Mutex<FxHashSet<(bool, NodeId)>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct Injector {
    tx: Sender<Synth>,
    sh: Arc<Shared>,
}

pub struct InjectorThread {
    stop: Sender<()>,
    join: Option<JoinHandle<()>>,
}

impl InjectorThread {
    pub fn stop(mut self) {
        let _ = self.stop.try_send(());
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for InjectorThread {
    fn drop(&mut self) {
        let _ = self.stop.try_send(());
    }
}

impl Injector {
    // the returned receiver carries settle effects for events that could not be replayed
    #[cfg(target_os = "linux")]
    pub fn start(
        mount: &Path,
        tree: Arc<RwLock<GTree>>,
    ) -> io::Result<(Arc<Injector>, InjectorThread, Receiver<Vec<Effect>>)> {
        Self::spawn(mount, tree)
    }

    // as start, with the startup self-test run on the injector thread before any event
    #[cfg(target_os = "macos")]
    pub fn start_probed(
        mount: &Path,
        tree: Arc<RwLock<GTree>>,
        boot: Boot,
    ) -> io::Result<(Arc<Injector>, InjectorThread, Receiver<Vec<Effect>>)> {
        Self::spawn(mount, tree, boot)
    }

    fn spawn(
        mount: &Path,
        tree: Arc<RwLock<GTree>>,
        #[cfg(target_os = "macos")] boot: Boot,
    ) -> io::Result<(Arc<Injector>, InjectorThread, Receiver<Vec<Effect>>)> {
        let (tx, rx) = bounded(QUEUE_MAX);
        let (stop_tx, stop_rx) = bounded(1);
        let (back_tx, back_rx) = bounded(BACK_MAX);
        let sh = Arc::new(Shared {
            tid: AtomicI32::new(0),
            stalled: AtomicBool::new(false),
            #[cfg(target_os = "macos")]
            off: AtomicBool::new(false),
            queued: Mutex::new(FxHashSet::default()),
        });
        let w = Worker {
            rx,
            stop: stop_rx,
            sh: sh.clone(),
            mount: mount.to_path_buf(),
            tree,
            back: back_tx,
        };
        #[cfg(target_os = "linux")]
        let job = move || w.run();
        #[cfg(target_os = "macos")]
        let job = move || w.run(boot);
        let join = thread::Builder::new()
            .name("csync-inject".into())
            .spawn(job)?;
        Ok((
            Arc::new(Injector { tx, sh }),
            InjectorThread {
                stop: stop_tx,
                join: Some(join),
            },
            back_rx,
        ))
    }

    // a full queue applies backpressure, so a burst reaches watchers as events or as their own queue
    // overflow; false (settle without an event) only once the injector has been stuck for OFFER_WAIT
    pub fn offer(&self, s: Synth) -> bool {
        #[cfg(target_os = "macos")]
        if self.sh.off.load(Ordering::Acquire) {
            return false;
        }
        let key = match &s {
            Synth::Modify { node } => Some((true, *node)),
            Synth::Attrib { node } => Some((false, *node)),
            _ => None,
        };
        if let Some(k) = key
            && !lock(&self.sh.queued).insert(k)
        {
            return true;
        }
        let s = match self.tx.try_send(s) {
            Ok(()) => return true,
            Err(TrySendError::Full(s)) if !self.sh.stalled.load(Ordering::Acquire) => s,
            Err(_) => return self.unqueue(key),
        };
        match self.tx.send_timeout(s, OFFER_WAIT) {
            Ok(()) => true,
            Err(_) => {
                self.sh.stalled.store(true, Ordering::Release);
                self.unqueue(key)
            }
        }
    }

    fn unqueue(&self, key: Option<(bool, NodeId)>) -> bool {
        if let Some(k) = key {
            lock(&self.sh.queued).remove(&k);
        }
        false
    }

    pub fn is_self(&self, req_pid: u32) -> bool {
        let t = self.sh.tid.load(Ordering::Acquire);
        t > 0 && t as u32 == req_pid
    }

    pub fn backlog(&self) -> usize {
        self.tx.len()
    }
}

struct Worker {
    rx: Receiver<Synth>,
    stop: Receiver<()>,
    sh: Arc<Shared>,
    mount: PathBuf,
    tree: Arc<RwLock<GTree>>,
    back: Sender<Vec<Effect>>,
}

fn push_name(path: &mut String, name: &Name) {
    if !path.is_empty() {
        path.push('/');
    }
    path.push_str(name.as_str());
}

fn mode(perm: u16) -> Mode {
    Mode::from_bits_truncate((u32::from(perm) & 0o7777) as _)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn nocache(fd: &OwnedFd) -> i32 {
    use std::os::fd::AsRawFd;
    // SAFETY: fcntl on a descriptor this function borrows, with an integer argument
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_NOCACHE, 1) }
}

fn open_root(mount: &Path) -> Option<OwnedFd> {
    rustix::fs::open(mount, ROOT_FLAGS, Mode::empty()).ok()
}

impl Worker {
    fn run(self, #[cfg(target_os = "macos")] boot: Boot) {
        #[cfg(target_os = "linux")]
        let me = rustix::thread::gettid().as_raw_pid();
        // requests carry the process id here, so this must stay the only csync thread that touches the mount
        #[cfg(target_os = "macos")]
        let me = i32::try_from(std::process::id()).unwrap_or(0);
        self.sh.tid.store(me, Ordering::Release);
        #[cfg(target_os = "linux")]
        let mut root: Option<OwnedFd> = None;
        #[cfg(target_os = "macos")]
        let mut root = open_root(&self.mount);
        #[cfg(target_os = "macos")]
        let replay = boot(root.as_ref());
        #[cfg(target_os = "macos")]
        if !replay {
            self.sh.off.store(true, Ordering::Release);
        }
        let (mut a, mut b) = (String::new(), String::new());
        loop {
            let next = select_biased! {
                recv(self.stop) -> _ => None,
                recv(self.rx) -> m => m.ok(),
            };
            let Some(s) = next else { break };
            if self.sh.stalled.load(Ordering::Relaxed) && self.rx.len() < QUEUE_MAX / 2 {
                self.sh.stalled.store(false, Ordering::Release);
            }
            if let Synth::Modify { node } | Synth::Attrib { node } = &s {
                lock(&self.sh.queued).remove(&(matches!(s, Synth::Modify { .. }), *node));
            }
            if root.is_none() {
                root = open_root(&self.mount);
            }
            let begun = match &s {
                Synth::Modify { node } => {
                    let t = self.tree.read().unwrap_or_else(|e| e.into_inner());
                    t.get(*node).map(|n| (*node, n.size_gen))
                }
                _ => None,
            };
            #[cfg(target_os = "linux")]
            let target = root.as_ref();
            // events that cannot be told from a user's requests are settled without touching the mount
            #[cfg(target_os = "macos")]
            let target = root.as_ref().filter(|_| replay);
            let watch = match &s {
                Synth::Create { name, .. } => super::coherence::watched(name.as_str()),
                _ => false,
            };
            if watch {
                super::coherence::trace(format_args!(
                    "injector got {s:?} target_present={}",
                    target.is_some()
                ));
            }
            if let Some(r) = target {
                let t0 = std::time::Instant::now();
                BUSY.store(true, Ordering::SeqCst);
                let res = self.inject(r, &s, &mut a, &mut b);
                BUSY.store(false, Ordering::SeqCst);
                if watch {
                    super::coherence::trace(format_args!(
                        "injector done {s:?} path={a:?} result={res:?} took={:?}",
                        t0.elapsed()
                    ));
                }
            }
            let mut fx = Vec::new();
            let mut t = self.tree.write().unwrap_or_else(|e| e.into_inner());
            // a truncate begun after the version was shown has returned: the kernel's size is that version's
            if let Some((node, gen_)) = begun
                && let Some(n) = t.get_mut(node)
                && n.size_gen == gen_
                && n.kernel_ver() == n.meta.version()
            {
                n.size_pending = false;
            }
            t.settle(&s, &mut fx);
            drop(t);
            if !fx.is_empty() && self.back.send(fx).is_err() {
                break;
            }
        }
        self.sh.tid.store(0, Ordering::Release);
    }

    // TRACE diagnostics, never to be merged: extra operations through the mount after a create, chosen by env
    #[cfg(target_os = "macos")]
    fn trace_nudge(&self, root: &OwnedFd, parent: NodeId, name: &str, full: &str) {
        use super::coherence::{trace, watched};
        use rustix::fs::{Dir, Timespec, Timestamps, UTIME_NOW};
        if !watched(name) {
            return;
        }
        let Ok(kinds) = std::env::var("CSYNC_TRACE_NUDGE") else {
            return;
        };
        if kinds.is_empty() {
            return;
        }
        let mut p = String::new();
        {
            let t = self.tree.read().unwrap_or_else(|e| e.into_inner());
            t.visible_path_of(parent, &mut p);
        }
        let pp = if p.is_empty() { ".".to_owned() } else { p };
        let lists = |label: &str| {
            let r = rustix::fs::openat(
                root,
                pp.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            );
            let res = r.map_err(io::Error::from).and_then(|fd| {
                let mut d = Dir::read_from(&fd)?;
                let mut found = false;
                while let Some(e) = d.read() {
                    if e?.file_name().to_bytes() == name.as_bytes() {
                        found = true;
                    }
                }
                Ok(found)
            });
            trace(format_args!("nudge {label}: readdir of {pp:?} through the mount lists {name}: {res:?}"));
        };
        lists("before");
        for k in kinds.split(',') {
            let t0 = std::time::Instant::now();
            match k {
                "utimes" => {
                    let now = Timespec { tv_sec: 0, tv_nsec: UTIME_NOW as _ };
                    let ts = Timestamps { last_access: now, last_modification: now };
                    let r = rustix::fs::utimensat(root, pp.as_str(), &ts, AtFlags::empty());
                    trace(format_args!("nudge utimes parent: {r:?} {:?}", t0.elapsed()));
                }
                "rename" => {
                    let r = rustix::fs::renameat(root, full, root, full);
                    trace(format_args!("nudge rename self: {r:?} {:?}", t0.elapsed()));
                }
                "stat" => {
                    let a = rustix::fs::statat(root, full, AtFlags::SYMLINK_NOFOLLOW).map(|s| s.st_ino);
                    let b = rustix::fs::statat(root, pp.as_str(), AtFlags::empty()).map(|s| s.st_mtime);
                    trace(format_args!("nudge stat: new {a:?} parent mtime {b:?} {:?}", t0.elapsed()));
                }
                "nocache" => {
                    let r = rustix::fs::openat(
                        root,
                        pp.as_str(),
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                        Mode::empty(),
                    );
                    let res = r.map(|fd| nocache(&fd));
                    trace(format_args!("nudge nocache parent dir: {res:?} {:?}", t0.elapsed()));
                }
                _ => {}
            }
            lists(k);
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn trace_nudge(&self, _root: &OwnedFd, _parent: NodeId, _name: &str, _full: &str) {}

    // paths are computed under the read lock, the syscalls run with no lock held
    fn inject(&self, root: &OwnedFd, s: &Synth, a: &mut String, b: &mut String) -> io::Result<()> {
        match s {
            Synth::Create { parent, name, .. } => {
                let (kind, perm, link, size) = {
                    let t = self.tree.read().unwrap_or_else(|e| e.into_inner());
                    let Some(n) = t.child(*parent, name.as_str()).and_then(|id| t.get(id)) else {
                        return Ok(());
                    };
                    if n.vis != Vis::PendingCreate || !t.visible_path_of(*parent, a) {
                        return Ok(());
                    }
                    (n.meta.kind, n.meta.perm, n.meta.link.clone(), n.meta.size)
                };
                push_name(a, name);
                match kind {
                    Kind::Dir => rustix::fs::mkdirat(root, a.as_str(), mode(perm))?,
                    Kind::Symlink => {
                        let Some(l) = link else { return Ok(()) };
                        rustix::fs::symlinkat(l.as_str(), root, a.as_str())?
                    }
                    Kind::File => {
                        let flags = OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::WRONLY
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC;
                        let fd = rustix::fs::openat(root, a.as_str(), flags, mode(perm))?;
                        // a file born with content also shows IN_MODIFY before its close, as natively
                        if size > 0 {
                            rustix::fs::ftruncate(&fd, size)?;
                        }
                    }
                }
                self.trace_nudge(root, *parent, name.as_str(), a.as_str());
            }
            Synth::Modify { node } | Synth::Attrib { node } => {
                let (kind, perm, size) = {
                    let t = self.tree.read().unwrap_or_else(|e| e.into_inner());
                    let Some(n) = t.get(*node) else { return Ok(()) };
                    if n.vis != Vis::Live || !t.visible_path_of(*node, a) {
                        return Ok(());
                    }
                    (n.meta.kind, n.meta.perm, n.meta.size)
                };
                if kind == Kind::Symlink {
                    return Ok(());
                }
                if matches!(s, Synth::Modify { .. }) && kind == Kind::File && perm & 0o200 != 0 {
                    // truncating to the current size raises IN_MODIFY without touching content
                    match rustix::fs::openat(
                        root,
                        a.as_str(),
                        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    ) {
                        // macos has no fallocate, so a modify there is always the truncate
                        #[cfg(target_os = "linux")]
                        Ok(fd) if SIZES_FROM_ATTRS.load(Ordering::Relaxed) => {
                            let keep = rustix::fs::FallocateFlags::KEEP_SIZE;
                            return Ok(rustix::fs::fallocate(&fd, keep, 0, 1)?);
                        }
                        Ok(fd) => return Ok(rustix::fs::ftruncate(&fd, size)?),
                        Err(Errno::ACCESS | Errno::PERM | Errno::ROFS | Errno::TXTBSY) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                rustix::fs::chmodat(root, a.as_str(), mode(perm), AtFlags::empty())?;
            }
            Synth::Delete { parent, name, dir } => {
                {
                    let t = self.tree.read().unwrap_or_else(|e| e.into_inner());
                    let pending = t
                        .child(*parent, name.as_str())
                        .and_then(|id| t.get(id))
                        .is_some_and(|n| n.vis == Vis::PendingDelete);
                    if !pending || !t.visible_path_of(*parent, a) {
                        return Ok(());
                    }
                }
                push_name(a, name);
                let flags = if *dir {
                    AtFlags::REMOVEDIR
                } else {
                    AtFlags::empty()
                };
                rustix::fs::unlinkat(root, a.as_str(), flags)?;
            }
            Synth::Move {
                from_parent,
                from,
                to_parent,
                to,
            } => {
                {
                    let t = self.tree.read().unwrap_or_else(|e| e.into_inner());
                    if !t.visible_path_of(*from_parent, a) || !t.visible_path_of(*to_parent, b) {
                        return Ok(());
                    }
                }
                push_name(a, from);
                push_name(b, to);
                rustix::fs::renameat(root, a.as_str(), root, b.as_str())?;
            }
        }
        Ok(())
    }
}
