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

pub const QUEUE_MAX: usize = 4_096;
const BACK_MAX: usize = 1_024;
const OFFER_WAIT: Duration = Duration::from_secs(1);

struct Shared {
    tid: AtomicI32,
    stalled: AtomicBool,
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
    pub fn start(
        mount: &Path,
        tree: Arc<RwLock<GTree>>,
    ) -> io::Result<(Arc<Injector>, InjectorThread, Receiver<Vec<Effect>>)> {
        let (tx, rx) = bounded(QUEUE_MAX);
        let (stop_tx, stop_rx) = bounded(1);
        let (back_tx, back_rx) = bounded(BACK_MAX);
        let sh = Arc::new(Shared {
            tid: AtomicI32::new(0),
            stalled: AtomicBool::new(false),
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
        let join = thread::Builder::new()
            .name("csync-inject".into())
            .spawn(move || w.run())?;
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
    Mode::from_bits_truncate(u32::from(perm) & 0o7777)
}

impl Worker {
    fn run(self) {
        self.sh
            .tid
            .store(rustix::thread::gettid().as_raw_pid(), Ordering::Release);
        let mut root: Option<OwnedFd> = None;
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
                root = rustix::fs::open(
                    self.mount.as_path(),
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .ok();
            }
            let begun = match &s {
                Synth::Modify { node } => {
                    let t = self.tree.read().unwrap_or_else(|e| e.into_inner());
                    t.get(*node).map(|n| (*node, n.size_gen))
                }
                _ => None,
            };
            if let Some(r) = &root {
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
    }

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
