#[cfg(target_os = "macos")]
use super::coherence::Ident;
#[cfg(target_os = "macos")]
use super::mount_mac;
use super::tree::{Effect, GTree, NodeId, Synth, Vis};
use crate::proto::{Kind, Name};
#[cfg(target_os = "macos")]
use crossbeam_channel::RecvTimeoutError;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded, select_biased};
use rustc_hash::FxHashSet;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicU8, AtomicU64};
#[cfg(target_os = "macos")]
use std::time::Instant;
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

pub const QUEUE_MAX: usize = 4_096;
const BACK_MAX: usize = 1_024;
const OFFER_WAIT: Duration = Duration::from_secs(1);

#[cfg(target_os = "linux")]
const ROOT_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
#[cfg(target_os = "macos")]
const ROOT_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

#[cfg(target_os = "macos")]
const ROOT_POLL: Duration = Duration::from_millis(20);
#[cfg(target_os = "macos")]
const ROOT_WAIT: Duration = Duration::from_secs(30);
#[cfg(target_os = "macos")]
const FAULT_UNSEEN: u8 = 1;
#[cfg(target_os = "macos")]
const FAULT_ROOT: u8 = 2;
#[cfg(target_os = "macos")]
const IDENT_PID: u8 = 1;
#[cfg(target_os = "macos")]
const IDENT_WINDOW: u8 = 2;

#[cfg(target_os = "macos")]
pub const UNSEEN_HINT: &str = "host changes are not replayed through the mount: its volume did not appear in time, so watchers will not see them";
#[cfg(target_os = "macos")]
pub const ROOT_HINT: &str =
    "some host changes were not replayed through the mount because its root could not be verified";

// runs on the injector thread before its first event with the mount root once it is verified to be the mounted
// volume, or None when it never was; the identification decided is what the handlers will recognise requests by,
// and Claim means events must not be replayed through the mount
#[cfg(target_os = "macos")]
pub type Boot = Box<dyn FnOnce(Option<&OwnedFd>) -> Ident + Send>;

struct Shared {
    tid: AtomicI32,
    stalled: AtomicBool,
    #[cfg(target_os = "macos")]
    off: AtomicBool,
    #[cfg(target_os = "macos")]
    ident: AtomicU8,
    #[cfg(target_os = "macos")]
    window: Window,
    #[cfg(target_os = "macos")]
    fault: AtomicU8,
    #[cfg(target_os = "macos")]
    skipped: AtomicU64,
    queued: Mutex<FxHashSet<(bool, NodeId)>>,
}

impl Shared {
    fn new() -> Self {
        Shared {
            tid: AtomicI32::new(0),
            stalled: AtomicBool::new(false),
            #[cfg(target_os = "macos")]
            off: AtomicBool::new(false),
            #[cfg(target_os = "macos")]
            ident: AtomicU8::new(0),
            #[cfg(target_os = "macos")]
            window: Window::new(),
            #[cfg(target_os = "macos")]
            fault: AtomicU8::new(0),
            #[cfg(target_os = "macos")]
            skipped: AtomicU64::new(0),
            queued: Mutex::new(FxHashSet::default()),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// what a request asks the filesystem to do, or what the injector is about to ask of the kernel. names are the
// bytes the kernel carries; a name operation is keyed by its parent inode and name, an inode operation by its inode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act<'a> {
    Lookup(NodeId, &'a [u8]),
    Create(NodeId, &'a [u8]),
    Mknod(NodeId, &'a [u8]),
    Mkdir(NodeId, &'a [u8]),
    Symlink(NodeId, &'a [u8]),
    Unlink(NodeId, &'a [u8]),
    Rmdir(NodeId, &'a [u8]),
    // source parent and name, then target parent and name; both must match
    Rename(NodeId, &'a [u8], NodeId, &'a [u8]),
    // the new parent and the new name
    Link(NodeId, &'a [u8]),
    // false when the open is for reading only: the injector always opens for writing
    Open(NodeId, bool),
    // false when the request carries a file handle that is not an injected one
    Setattr(NodeId, bool),
    // false when the handle is not an injected one
    Fallocate(NodeId, bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Lookup,
    Create,
    Mknod,
    Mkdir,
    Symlink,
    Unlink,
    Rmdir,
    Rename,
    Link,
    Open,
    Setattr,
    Fallocate,
}

type Key<'a> = (Class, NodeId, &'a [u8], NodeId, &'a [u8]);
type Held = (Class, NodeId, Vec<u8>, NodeId, Vec<u8>);

impl<'a> Act<'a> {
    fn key(&self) -> Option<Key<'a>> {
        const NO: &[u8] = &[];
        Some(match *self {
            Act::Lookup(p, n) => (Class::Lookup, p, n, 0, NO),
            Act::Create(p, n) => (Class::Create, p, n, 0, NO),
            Act::Mknod(p, n) => (Class::Mknod, p, n, 0, NO),
            Act::Mkdir(p, n) => (Class::Mkdir, p, n, 0, NO),
            Act::Symlink(p, n) => (Class::Symlink, p, n, 0, NO),
            Act::Unlink(p, n) => (Class::Unlink, p, n, 0, NO),
            Act::Rmdir(p, n) => (Class::Rmdir, p, n, 0, NO),
            Act::Rename(p, n, q, m) => (Class::Rename, p, n, q, m),
            Act::Link(q, m) => (Class::Link, q, m, 0, NO),
            Act::Open(i, ours) => return ours.then_some((Class::Open, i, NO, 0, NO)),
            Act::Setattr(i, ours) => return ours.then_some((Class::Setattr, i, NO, 0, NO)),
            Act::Fallocate(i, ours) => return ours.then_some((Class::Fallocate, i, NO, 0, NO)),
        })
    }
}

// the exact operations the injector has in flight. a request is the injector's only while the very same operation
// is armed, so a user's request that arrives meanwhile is never taken for one
pub struct Window {
    on: AtomicBool,
    held: Mutex<Vec<Held>>,
}

impl Default for Window {
    fn default() -> Self {
        Self::new()
    }
}

impl Window {
    pub const fn new() -> Self {
        Window {
            on: AtomicBool::new(false),
            held: Mutex::new(Vec::new()),
        }
    }

    // armed until the returned guard drops, which is after the syscall has returned
    pub fn arm(&self, acts: &[Act<'_>]) -> Armed<'_> {
        let mut held = lock(&self.held);
        held.clear();
        held.extend(
            acts.iter()
                .filter_map(Act::key)
                .map(|(c, a, n, b, m)| (c, a, n.to_vec(), b, m.to_vec())),
        );
        drop(held);
        self.on.store(true, Ordering::Release);
        Armed(self)
    }

    pub fn matches(&self, act: &Act<'_>) -> bool {
        if !self.on.load(Ordering::Acquire) {
            return false;
        }
        let Some((c, a, n, b, m)) = act.key() else {
            return false;
        };
        lock(&self.held)
            .iter()
            .any(|h| h.0 == c && h.1 == a && h.2.as_slice() == n && h.3 == b && h.4.as_slice() == m)
    }
}

pub struct Armed<'a>(&'a Window);

impl Drop for Armed<'_> {
    fn drop(&mut self) {
        self.0.on.store(false, Ordering::Release);
        lock(&self.0.held).clear();
    }
}

// linux tells requests apart by thread id and arms nothing
#[cfg(target_os = "linux")]
struct Idle;

#[cfg(target_os = "macos")]
enum Wait<T> {
    Ready(T),
    Timeout,
    Stopped,
}

// polls until the thing is there, the limit passes, or the caller is told to stop; the first poll is always made
#[cfg(target_os = "macos")]
fn wait_until<T>(
    limit: Duration,
    mut ready: impl FnMut() -> Option<T>,
    mut stopped: impl FnMut() -> bool,
) -> Wait<T> {
    let end = Instant::now() + limit;
    loop {
        if let Some(v) = ready() {
            return Wait::Ready(v);
        }
        if Instant::now() >= end {
            return Wait::Timeout;
        }
        if stopped() {
            return Wait::Stopped;
        }
    }
}

// waits one poll; true when the injector is being stopped
#[cfg(target_os = "macos")]
fn stop_requested(stop: &Receiver<()>) -> bool {
    !matches!(stop.recv_timeout(ROOT_POLL), Err(RecvTimeoutError::Timeout))
}

// the mount root as the injector uses it: an fd that has to name the mounted volume and not the directory under it
#[cfg(target_os = "macos")]
struct Root {
    fd: Option<OwnedFd>,
    mount: PathBuf,
    vol: u64,
    before: Option<u64>,
}

#[cfg(target_os = "macos")]
fn fd_dev(fd: &OwnedFd) -> Option<u64> {
    rustix::fs::fstat(fd).ok().map(|s| s.st_dev as u64)
}

#[cfg(target_os = "macos")]
fn on_volume(fd: &OwnedFd, vol: u64, before: Option<u64>) -> bool {
    fd_dev(fd).is_some_and(|d| d == vol && Some(d) != before)
}

// the root once the mount is visible: opened only after the volume shows, then checked to be on it
#[cfg(target_os = "macos")]
fn find_root(mount: &Path, before: Option<u64>) -> Option<Root> {
    let vol = mount_mac::volume_dev(mount, before)?;
    let fd = open_root(mount).filter(|f| on_volume(f, vol, before))?;
    Some(Root {
        fd: Some(fd),
        mount: mount.to_path_buf(),
        vol,
        before,
    })
}

#[cfg(target_os = "macos")]
impl Root {
    // the open root while it still names the volume, reopened once when it does not; None means do not inject
    fn verified(&mut self) -> Option<&OwnedFd> {
        if !self
            .fd
            .as_ref()
            .is_some_and(|f| on_volume(f, self.vol, self.before))
        {
            self.fd = open_root(&self.mount).filter(|f| on_volume(f, self.vol, self.before));
        }
        self.fd.as_ref()
    }
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

    // as start, with the startup self-test run on the injector thread before any event. `before` is the device that
    // was under the mount point before the mount: the thread waits for the volume to show before it opens the root
    #[cfg(target_os = "macos")]
    pub fn start_probed(
        mount: &Path,
        tree: Arc<RwLock<GTree>>,
        before: Option<u64>,
        boot: Boot,
    ) -> io::Result<(Arc<Injector>, InjectorThread, Receiver<Vec<Effect>>)> {
        Self::spawn(mount, tree, before, boot)
    }

    fn spawn(
        mount: &Path,
        tree: Arc<RwLock<GTree>>,
        #[cfg(target_os = "macos")] before: Option<u64>,
        #[cfg(target_os = "macos")] boot: Boot,
    ) -> io::Result<(Arc<Injector>, InjectorThread, Receiver<Vec<Effect>>)> {
        let (tx, rx) = bounded(QUEUE_MAX);
        let (stop_tx, stop_rx) = bounded(1);
        let (back_tx, back_rx) = bounded(BACK_MAX);
        let sh = Arc::new(Shared::new());
        let w = Worker {
            rx,
            stop: stop_rx,
            sh: sh.clone(),
            mount: mount.to_path_buf(),
            #[cfg(target_os = "macos")]
            before,
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

    // whether a request for `act` is the injector's, by the identification the self-test decided: until then and
    // under Claim nothing is
    #[cfg(target_os = "macos")]
    pub fn recognises(&self, req_pid: u32, act: &Act<'_>) -> bool {
        match self.sh.ident.load(Ordering::Acquire) {
            IDENT_PID => self.is_self(req_pid),
            IDENT_WINDOW => self.sh.window.matches(act),
            _ => false,
        }
    }

    // why host changes are, or were, not replayed through the mount, for the status line
    #[cfg(target_os = "macos")]
    pub fn fault(&self) -> Option<&'static str> {
        match self.sh.fault.load(Ordering::Acquire) {
            FAULT_UNSEEN => Some(UNSEEN_HINT),
            FAULT_ROOT => Some(ROOT_HINT),
            _ => None,
        }
    }

    // events skipped because the root no longer named the mounted volume
    #[cfg(target_os = "macos")]
    pub fn skipped(&self) -> u64 {
        self.sh.skipped.load(Ordering::Relaxed)
    }
}

struct Worker {
    rx: Receiver<Synth>,
    stop: Receiver<()>,
    sh: Arc<Shared>,
    mount: PathBuf,
    #[cfg(target_os = "macos")]
    before: Option<u64>,
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

// TRACE: what the kernel reports for a descriptor the injector holds
#[cfg(target_os = "macos")]
fn trace_view(label: &str, fd: &OwnedFd) {
    let r = rustix::fs::fstat(fd).map(|s| (s.st_size, s.st_mtime, s.st_mtime_nsec, s.st_ino));
    super::coherence::trace(format_args!("injector view {label}: size/mtime/mtime_ns/ino {r:?}"));
}

#[cfg(not(target_os = "macos"))]
fn trace_view(_label: &str, _fd: &OwnedFd) {}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn nocache(fd: &OwnedFd) -> i32 {
    use std::os::fd::AsRawFd;
    // SAFETY: fcntl on a descriptor this function borrows, with an integer argument
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_NOCACHE, 1) }
}

// TRACE: map the file and ask the kernel to drop its cached pages
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn msync_invalidate(fd: &OwnedFd, len: usize) -> String {
    use std::os::fd::AsRawFd;
    if len == 0 {
        return "empty".to_owned();
    }
    // SAFETY: a private read-only mapping of a descriptor this function borrows, unmapped before returning
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        );
        if p == libc::MAP_FAILED {
            return format!("mmap {}", std::io::Error::last_os_error());
        }
        let r = libc::msync(p, len, libc::MS_INVALIDATE);
        let e = std::io::Error::last_os_error();
        libc::munmap(p, len);
        format!("msync {r} {e}")
    }
}

// TRACE: extra operations through the mount after the injected truncate, chosen by CSYNC_TRACE_NUDGE
#[cfg(target_os = "macos")]
fn nudges(root: &OwnedFd, fd: &OwnedFd, path: &str, size: u64, perm: u16, node: NodeId, w: &Worker) {
    use rustix::fs::{Timespec, Timestamps, UTIME_NOW};
    let Ok(kinds) = std::env::var("CSYNC_TRACE_NUDGE") else {
        return;
    };
    for k in kinds.split(',').filter(|k| !k.is_empty()) {
        let t0 = std::time::Instant::now();
        let _w = w.arm(&[Act::Setattr(node, true), Act::Open(node, true)]);
        let res: String = match k {
            "plus" => {
                let a = rustix::fs::ftruncate(fd, size + 1);
                let b = rustix::fs::ftruncate(fd, size);
                format!("{a:?} {b:?}")
            }
            "utimes" => {
                let now = Timespec { tv_sec: 0, tv_nsec: UTIME_NOW as _ };
                let ts = Timestamps { last_access: now, last_modification: now };
                format!("{:?}", rustix::fs::futimens(fd, &ts))
            }
            "nocache" => format!("{}", nocache(fd)),
            "zero" => {
                let a = rustix::fs::ftruncate(fd, 0);
                let b = rustix::fs::ftruncate(fd, size);
                format!("{a:?} {b:?}")
            }
            "msync" => {
                let r = rustix::fs::openat(
                    root,
                    path,
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                );
                match r {
                    Ok(f) => msync_invalidate(&f, usize::try_from(size).unwrap_or(0)),
                    Err(e) => format!("open {e:?}"),
                }
            }
            "fsync" => format!("{:?}", rustix::fs::fsync(fd)),
            "chmod" => format!(
                "{:?}",
                rustix::fs::chmodat(root, path, mode(perm), AtFlags::empty())
            ),
            "renameself" => format!("{:?}", rustix::fs::renameat(root, path, root, path)),
            "readthrough" => {
                let r = rustix::fs::openat(
                    root,
                    path,
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                );
                match r {
                    Ok(f) => {
                        let mut buf = [0u8; 64];
                        let n = rustix::io::read(&f, &mut buf);
                        format!("{n:?} {:?}", String::from_utf8_lossy(&buf[..n.unwrap_or(0)]))
                    }
                    Err(e) => format!("open {e:?}"),
                }
            }
            _ => "unknown".to_owned(),
        };
        super::coherence::trace(format_args!("nudge {k}: {res} in {:?}", t0.elapsed()));
        trace_view(&format!("after {k}"), fd);
    }
}

#[cfg(not(target_os = "macos"))]
fn nudges(_: &OwnedFd, _: &OwnedFd, _: &str, _: u64, _: u16, _: NodeId, _: &Worker) {}

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
        // the volume can show well after the mount call returns; a root opened before it names the directory under it
        #[cfg(target_os = "macos")]
        let mut root = match wait_until(
            ROOT_WAIT,
            || find_root(&self.mount, self.before),
            || stop_requested(&self.stop),
        ) {
            Wait::Ready(r) => Some(r),
            Wait::Timeout => {
                self.sh.fault.store(FAULT_UNSEEN, Ordering::Release);
                None
            }
            Wait::Stopped => {
                self.sh.tid.store(0, Ordering::Release);
                return;
            }
        };
        #[cfg(target_os = "macos")]
        let ident = boot(root.as_ref().and_then(|r| r.fd.as_ref()));
        #[cfg(target_os = "macos")]
        let replay = ident != Ident::Claim;
        #[cfg(target_os = "macos")]
        self.sh.ident.store(
            match ident {
                Ident::Pid => IDENT_PID,
                Ident::Window => IDENT_WINDOW,
                Ident::Claim => 0,
            },
            Ordering::Release,
        );
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
            #[cfg(target_os = "linux")]
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
            // events that cannot be told from a user's requests are settled without touching the mount, and so is
            // one whose root no longer names the mounted volume
            #[cfg(target_os = "macos")]
            let target = if replay {
                root.as_mut().and_then(Root::verified)
            } else {
                None
            };
            #[cfg(target_os = "macos")]
            if replay && target.is_none() {
                self.sh.skipped.fetch_add(1, Ordering::Relaxed);
                self.sh.fault.store(FAULT_ROOT, Ordering::Release);
            }
            if let Some(r) = target {
                let _ = self.inject(r, &s, &mut a, &mut b);
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
        #[cfg(target_os = "macos")]
        self.sh.ident.store(0, Ordering::Release);
    }

    #[cfg(target_os = "macos")]
    fn arm(&self, acts: &[Act<'_>]) -> Armed<'_> {
        self.sh.window.arm(acts)
    }

    #[cfg(target_os = "linux")]
    #[inline(always)]
    fn arm(&self, _acts: &[Act<'_>]) -> Idle {
        Idle
    }

    // paths are computed under the read lock, the syscalls run with no lock held
    fn inject(&self, root: &OwnedFd, s: &Synth, a: &mut String, b: &mut String) -> io::Result<()> {
        match s {
            Synth::Create { parent, name, .. } => {
                let (id, kind, perm, link, size) = {
                    let t = self.tree.read().unwrap_or_else(|e| e.into_inner());
                    let Some(id) = t.child(*parent, name.as_str()) else {
                        return Ok(());
                    };
                    let Some(n) = t.get(id) else { return Ok(()) };
                    if n.vis != Vis::PendingCreate || !t.visible_path_of(*parent, a) {
                        return Ok(());
                    }
                    (
                        id,
                        n.meta.kind,
                        n.meta.perm,
                        n.meta.link.clone(),
                        n.meta.size,
                    )
                };
                push_name(a, name);
                let nm = name.as_str().as_bytes();
                match kind {
                    Kind::Dir => {
                        let _w = self.arm(&[Act::Lookup(*parent, nm), Act::Mkdir(*parent, nm)]);
                        rustix::fs::mkdirat(root, a.as_str(), mode(perm))?
                    }
                    Kind::Symlink => {
                        let Some(l) = link else { return Ok(()) };
                        let _w = self.arm(&[Act::Lookup(*parent, nm), Act::Symlink(*parent, nm)]);
                        rustix::fs::symlinkat(l.as_str(), root, a.as_str())?
                    }
                    Kind::File => {
                        let flags = OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::WRONLY
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC;
                        let fd = {
                            let _w = self.arm(&[
                                Act::Lookup(*parent, nm),
                                Act::Create(*parent, nm),
                                Act::Open(id, true),
                            ]);
                            rustix::fs::openat(root, a.as_str(), flags, mode(perm))?
                        };
                        // a file born with content also shows IN_MODIFY before its close, as natively
                        if size > 0 {
                            let _w = self.arm(&[Act::Setattr(id, true)]);
                            rustix::fs::ftruncate(&fd, size)?;
                        }
                    }
                }
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
                super::coherence::trace(format_args!(
                    "injector modify node={node} path={a:?} kind={kind:?} perm={perm:o} size={size}"
                ));
                if matches!(s, Synth::Modify { .. }) && kind == Kind::File && perm & 0o200 != 0 {
                    // truncating to the current size raises IN_MODIFY without touching content
                    let opened = {
                        let _w = self.arm(&[Act::Open(*node, true)]);
                        rustix::fs::openat(
                            root,
                            a.as_str(),
                            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                    };
                    match opened {
                        // macos has no fallocate, so a modify there is always the truncate
                        #[cfg(target_os = "linux")]
                        Ok(fd) if SIZES_FROM_ATTRS.load(Ordering::Relaxed) => {
                            let keep = rustix::fs::FallocateFlags::KEEP_SIZE;
                            return Ok(rustix::fs::fallocate(&fd, keep, 0, 1)?);
                        }
                        Ok(fd) => {
                            let _w = self.arm(&[Act::Setattr(*node, true)]);
                            let watch = a
                                .rsplit('/')
                                .next()
                                .is_some_and(super::coherence::watched);
                            if watch {
                                trace_view("before ftruncate", &fd);
                            }
                            let t0 = std::time::Instant::now();
                            let r = rustix::fs::ftruncate(&fd, size);
                            if watch {
                                super::coherence::trace(format_args!(
                                    "injector ftruncate node={node} size={size} -> {r:?} in {:?}",
                                    t0.elapsed()
                                ));
                                trace_view("after ftruncate", &fd);
                                nudges(root, &fd, a.as_str(), size, perm, *node, self);
                            }
                            // TRACE experiment: truncating to 0 and back drops the kernel's pages on FSKit
                            #[cfg(target_os = "macos")]
                            if r.is_ok() && size > 0 && super::coherence::fix("zeroinval") {
                                let _ = rustix::fs::ftruncate(&fd, 0);
                                let _ = rustix::fs::ftruncate(&fd, size);
                            }
                            return Ok(r?);
                        }
                        Err(Errno::ACCESS | Errno::PERM | Errno::ROFS | Errno::TXTBSY) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                let _w = self.arm(&[Act::Setattr(*node, true)]);
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
                let nm = name.as_str().as_bytes();
                let (flags, last) = if *dir {
                    (AtFlags::REMOVEDIR, Act::Rmdir(*parent, nm))
                } else {
                    (AtFlags::empty(), Act::Unlink(*parent, nm))
                };
                let _w = self.arm(&[Act::Lookup(*parent, nm), last]);
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
                let (src, dst) = (from.as_str().as_bytes(), to.as_str().as_bytes());
                let _w = self.arm(&[
                    Act::Lookup(*from_parent, src),
                    Act::Lookup(*to_parent, dst),
                    Act::Rename(*from_parent, src, *to_parent, dst),
                ]);
                rustix::fs::renameat(root, a.as_str(), root, b.as_str())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_armed_operations_match() {
        let w = Window::new();
        let _g = w.arm(&[Act::Lookup(5, b"a"), Act::Create(5, b"a")]);
        assert!(w.matches(&Act::Lookup(5, b"a")));
        assert!(w.matches(&Act::Create(5, b"a")));
        assert!(!w.matches(&Act::Lookup(5, b"b")));
        assert!(!w.matches(&Act::Lookup(6, b"a")));
        assert!(!w.matches(&Act::Mkdir(5, b"a")));
        assert!(!w.matches(&Act::Unlink(5, b"a")));
        assert!(!w.matches(&Act::Open(5, true)));
    }

    #[test]
    fn a_user_request_arriving_during_an_injection_is_not_taken_for_it() {
        let w = Window::new();
        let injected = Act::Create(7, b"new.txt");
        let user = Act::Create(7, b"other.txt");
        let guard = w.arm(&[injected]);
        thread::scope(|s| {
            let (w, i, u) = (&w, &injected, &user);
            let from_injection = s.spawn(move || w.matches(i));
            let from_user = s.spawn(move || w.matches(u));
            assert!(from_injection.join().unwrap());
            assert!(!from_user.join().unwrap());
        });
        drop(guard);
    }

    #[test]
    fn a_disarmed_window_matches_nothing() {
        let w = Window::new();
        let acts = [
            Act::Lookup(1, b"a"),
            Act::Open(2, true),
            Act::Setattr(2, true),
            Act::Rename(1, b"a", 1, b"b"),
        ];
        for a in &acts {
            assert!(!w.matches(a), "{a:?} matched before anything was armed");
        }
        {
            let _g = w.arm(&acts);
            for a in &acts {
                assert!(w.matches(a), "{a:?} did not match while armed");
            }
        }
        for a in &acts {
            assert!(!w.matches(a), "{a:?} matched after the guard dropped");
        }
    }

    #[test]
    fn arming_again_leaves_nothing_of_the_last_operation() {
        let w = Window::new();
        drop(w.arm(&[Act::Unlink(3, b"x")]));
        let _g = w.arm(&[Act::Rmdir(3, b"y")]);
        assert!(!w.matches(&Act::Unlink(3, b"x")));
        assert!(w.matches(&Act::Rmdir(3, b"y")));
    }

    #[test]
    fn a_rename_matches_only_when_both_ends_do() {
        let w = Window::new();
        let _g = w.arm(&[Act::Rename(1, b"a", 2, b"b")]);
        assert!(w.matches(&Act::Rename(1, b"a", 2, b"b")));
        assert!(!w.matches(&Act::Rename(1, b"a", 2, b"c")));
        assert!(!w.matches(&Act::Rename(1, b"a", 3, b"b")));
        assert!(!w.matches(&Act::Rename(2, b"a", 2, b"b")));
        assert!(!w.matches(&Act::Rename(1, b"x", 2, b"b")));
    }

    #[test]
    fn inode_operations_need_the_injector_s_kind_of_handle_and_open() {
        let w = Window::new();
        let _g = w.arm(&[Act::Open(9, true), Act::Setattr(9, true)]);
        assert!(w.matches(&Act::Open(9, true)));
        assert!(w.matches(&Act::Setattr(9, true)));
        assert!(!w.matches(&Act::Open(9, false)));
        assert!(!w.matches(&Act::Setattr(9, false)));
        assert!(!w.matches(&Act::Open(10, true)));
        assert!(!w.matches(&Act::Fallocate(9, true)));
        assert!(!w.matches(&Act::Link(9, b"n")));
        assert!(!w.matches(&Act::Mknod(9, b"n")));
    }

    #[test]
    fn an_operation_that_can_never_be_the_injector_s_is_not_held() {
        let w = Window::new();
        let _g = w.arm(&[Act::Setattr(4, false), Act::Open(4, false)]);
        assert!(!w.matches(&Act::Setattr(4, true)));
        assert!(!w.matches(&Act::Open(4, true)));
        assert!(!w.matches(&Act::Setattr(4, false)));
    }

    #[cfg(target_os = "macos")]
    mod mac {
        use super::*;

        fn bare() -> Injector {
            let (tx, _rx) = bounded(1);
            Injector {
                tx,
                sh: Arc::new(Shared::new()),
            }
        }

        fn scratch() -> (PathBuf, u64) {
            let dir = std::env::temp_dir();
            let dev = fd_dev(&open_root(&dir).unwrap()).unwrap();
            (dir, dev)
        }

        #[test]
        fn the_wait_ends_when_the_volume_shows_in_a_fake_mount_table() {
            let table = [("apfs", 5u64), ("apfs", 5), ("fskit", 9)];
            let mut polls = 0usize;
            let got = wait_until(
                Duration::from_secs(60),
                || {
                    let (ty, dev) = table[polls.min(table.len() - 1)];
                    polls += 1;
                    mount_mac::shows_volume(ty, dev, Some(5)).then_some(dev)
                },
                || false,
            );
            assert!(matches!(got, Wait::Ready(9)));
            assert_eq!(polls, 3);
        }

        #[test]
        fn a_volume_that_never_shows_times_out_without_waiting_past_the_limit() {
            let got = wait_until(Duration::ZERO, || None::<u64>, || panic!("slept"));
            assert!(matches!(got, Wait::Timeout));
            let seen = wait_until(Duration::ZERO, || Some(1u8), || panic!("slept"));
            assert!(matches!(seen, Wait::Ready(1)));
        }

        #[test]
        fn a_stop_request_ends_the_wait() {
            let got = wait_until(Duration::from_secs(60), || None::<u8>, || true);
            assert!(matches!(got, Wait::Stopped));
            let (tx, rx) = bounded::<()>(1);
            assert!(!stop_requested(&rx));
            tx.send(()).unwrap();
            assert!(stop_requested(&rx));
        }

        #[test]
        fn a_root_opened_before_the_volume_showed_is_not_accepted() {
            let (dir, dev) = scratch();
            assert!(find_root(&dir, Some(dev)).is_none());
            assert!(find_root(&dir, Some(dev ^ 1)).is_some());
        }

        #[test]
        fn a_verified_root_is_used_and_a_missing_one_is_reopened() {
            let (dir, dev) = scratch();
            let mut r = Root {
                fd: open_root(&dir),
                mount: dir.clone(),
                vol: dev,
                before: Some(dev ^ 1),
            };
            assert!(r.verified().is_some());
            r.fd = None;
            assert!(r.verified().is_some());
        }

        #[test]
        fn a_root_on_the_pre_mount_device_is_never_used() {
            let (dir, dev) = scratch();
            let mut r = Root {
                fd: open_root(&dir),
                mount: dir,
                vol: dev,
                before: Some(dev),
            };
            assert!(r.verified().is_none());
            assert!(r.fd.is_none());
        }

        #[test]
        fn a_root_that_is_not_on_the_volume_is_refused_even_after_reopening() {
            let (dir, dev) = scratch();
            let mut r = Root {
                fd: open_root(&dir),
                mount: dir,
                vol: dev ^ 1,
                before: None,
            };
            assert!(r.verified().is_none());
        }

        #[test]
        fn the_injector_starts_only_once_the_volume_shows_and_hands_the_root_to_the_self_test() {
            let (dir, dev) = scratch();
            let tree = Arc::new(RwLock::new(GTree::new()));
            let (seen_tx, seen_rx) = bounded(1);
            let boot: Boot = Box::new(move |root| {
                seen_tx.send(root.is_some()).unwrap();
                Ident::Claim
            });
            let (inj, thread, _back) =
                Injector::start_probed(&dir, tree, Some(dev ^ 1), boot).unwrap();
            assert_eq!(seen_rx.recv_timeout(Duration::from_secs(5)), Ok(true));
            thread.stop();
            assert_eq!(inj.fault(), None);
            assert_eq!(inj.skipped(), 0);
        }

        #[test]
        fn a_stop_while_the_volume_has_not_shown_never_runs_the_self_test() {
            let (dir, dev) = scratch();
            let tree = Arc::new(RwLock::new(GTree::new()));
            let (seen_tx, seen_rx) = bounded(1);
            let boot: Boot = Box::new(move |_| {
                let _ = seen_tx.send(());
                Ident::Claim
            });
            let (_inj, thread, _back) =
                Injector::start_probed(&dir, tree, Some(dev), boot).unwrap();
            thread.stop();
            assert!(seen_rx.try_recv().is_err());
        }

        #[test]
        fn nothing_is_recognised_until_an_identification_is_decided() {
            let inj = bare();
            inj.sh.tid.store(42, Ordering::Release);
            let act = Act::Lookup(2, b"f");
            let _g = inj.sh.window.arm(&[act]);
            assert!(!inj.recognises(42, &act));
            assert!(!inj.recognises(0, &act));
        }

        #[test]
        fn under_the_window_only_the_armed_operation_is_recognised_whatever_the_pid() {
            let inj = bare();
            inj.sh.ident.store(IDENT_WINDOW, Ordering::Release);
            let act = Act::Unlink(2, b"f");
            assert!(!inj.recognises(0, &act));
            let g = inj.sh.window.arm(&[act]);
            assert!(inj.recognises(0, &act));
            assert!(!inj.recognises(0, &Act::Unlink(2, b"g")));
            drop(g);
            assert!(!inj.recognises(0, &act));
        }

        #[test]
        fn under_the_pid_identification_the_window_is_ignored() {
            let inj = bare();
            inj.sh.ident.store(IDENT_PID, Ordering::Release);
            inj.sh.tid.store(42, Ordering::Release);
            let act = Act::Mkdir(2, b"d");
            assert!(inj.recognises(42, &act));
            assert!(!inj.recognises(0, &act));
            let _g = inj.sh.window.arm(&[act]);
            assert!(!inj.recognises(0, &act));
        }
    }
}
