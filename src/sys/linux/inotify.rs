use crate::{
    proto::RelPath,
    sys::{
        DirFilter, ResumeToken, WatchEvent, Watcher, fs_unix::open_beneath, linux::dir::subdirs,
        lock, strictly_under, wflag,
    },
};
use ::inotify::{EventMask, Inotify, WatchDescriptor, WatchMask, Watches};
use crossbeam_channel::{SendTimeoutError, Sender};
use rustix::fs::{Mode, OFlags};
use std::{
    collections::HashMap,
    ffi::OsStr,
    io,
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

const READ_BUF: usize = 64 << 10;
const SEND_POLL: Duration = Duration::from_millis(100);

fn mask() -> WatchMask {
    WatchMask::CREATE
        | WatchMask::DELETE
        | WatchMask::MOVED_FROM
        | WatchMask::MOVED_TO
        | WatchMask::MODIFY
        | WatchMask::CLOSE_WRITE
        | WatchMask::ATTRIB
        | WatchMask::ONLYDIR
        | WatchMask::DONT_FOLLOW
        | WatchMask::EXCL_UNLINK
}

fn max_user_watches() -> usize {
    std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(8192)
}

fn is_gone(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOENT) | Some(libc::ENOTDIR) | Some(libc::ELOOP)
    )
}

struct Table {
    root: PathBuf,
    root_fd: OwnedFd,
    watches: Watches,
    by_wd: HashMap<WatchDescriptor, RelPath>,
    by_path: HashMap<RelPath, WatchDescriptor>,
    excludes: Vec<RelPath>,
    accept: Option<DirFilter>,
}

impl Table {
    fn allowed(&self, dir: &RelPath) -> bool {
        !self.excludes.iter().any(|e| dir.starts_with(e))
            && self.accept.as_ref().is_none_or(|f| f(dir))
    }

    fn add_one(&mut self, dir: &RelPath) -> io::Result<()> {
        let abs = if dir.is_root() {
            self.root.clone()
        } else {
            self.root.join(dir.as_str())
        };
        let m = if dir.is_root() {
            mask() | WatchMask::MOVE_SELF | WatchMask::DELETE_SELF
        } else {
            mask()
        };
        let wd = self.watches.add(&abs, m)?;
        if let Some(prev) = self.by_wd.insert(wd.clone(), dir.clone())
            && prev != *dir
            && self.by_path.get(&prev) == Some(&wd)
        {
            self.by_path.remove(&prev);
        }
        self.by_path.insert(dir.clone(), wd);
        Ok(())
    }

    // watches dir itself, then every accepted directory below it
    fn add_tree(&mut self, dir: &RelPath) -> io::Result<()> {
        self.add_one(dir)?;
        let mut stack = vec![dir.clone()];
        let mut names = Vec::new();
        while let Some(d) = stack.pop() {
            let fd =
                match open_beneath(self.root_fd.as_fd(), &d, OFlags::RDONLY | OFlags::DIRECTORY) {
                    Ok(fd) => fd,
                    Err(e) if is_gone(&e) => continue,
                    Err(e) => return Err(e),
                };
            names.clear();
            match subdirs(fd.as_fd(), &mut names) {
                Ok(()) => {}
                Err(e) if is_gone(&e) => continue,
                Err(e) => return Err(e),
            }
            for n in names.drain(..) {
                let Ok(child) = d.join(&n) else { continue };
                if !self.allowed(&child) {
                    continue;
                }
                match self.add_one(&child) {
                    Ok(()) => stack.push(child),
                    Err(e) if is_gone(&e) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    fn remove_tree(&mut self, dir: &RelPath) {
        let gone: Vec<RelPath> = self
            .by_path
            .keys()
            .filter(|p| p.starts_with(dir))
            .cloned()
            .collect();
        for p in gone {
            if let Some(wd) = self.by_path.remove(&p) {
                self.by_wd.remove(&wd);
                let _ = self.watches.remove(wd);
            }
        }
    }

    fn rename_tree(&mut self, from: &RelPath, to: &RelPath) {
        let moved: Vec<RelPath> = self
            .by_path
            .keys()
            .filter(|p| p.starts_with(from))
            .cloned()
            .collect();
        for old in moved {
            let Some(wd) = self.by_path.remove(&old) else {
                continue;
            };
            let new = if old == *from {
                Ok(to.clone())
            } else {
                RelPath::new(&format!(
                    "{}{}",
                    to.as_str(),
                    &old.as_str()[from.as_str().len()..]
                ))
            };
            match new {
                Ok(new) => {
                    self.by_wd.insert(wd.clone(), new.clone());
                    self.by_path.insert(new, wd);
                }
                Err(_) => {
                    self.by_wd.remove(&wd);
                    let _ = self.watches.remove(wd);
                }
            }
        }
    }

    fn forget(&mut self, wd: &WatchDescriptor) -> Option<RelPath> {
        let p = self.by_wd.remove(wd)?;
        if self.by_path.get(&p) == Some(wd) {
            self.by_path.remove(&p);
        }
        Some(p)
    }
}

struct Shared {
    table: Mutex<Table>,
    stop: AtomicBool,
    limit: usize,
}

pub struct InotifyWatcher {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl InotifyWatcher {
    pub fn start(
        root: &Path,
        tx: Sender<Vec<WatchEvent>>,
        accept: Option<DirFilter>,
    ) -> io::Result<Self> {
        let root = std::fs::canonicalize(root)?;
        let ino = Inotify::init()?;
        let root_fd = rustix::fs::open(
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut table = Table {
            root,
            root_fd,
            watches: ino.watches(),
            by_wd: HashMap::new(),
            by_path: HashMap::new(),
            excludes: Vec::new(),
            accept,
        };
        table.add_tree(&RelPath::root())?;
        let shared = Arc::new(Shared {
            table: Mutex::new(table),
            stop: AtomicBool::new(false),
            limit: max_user_watches(),
        });
        let sh = shared.clone();
        let thread = std::thread::Builder::new()
            .name("csync-inotify".into())
            .spawn(move || reader(ino, &sh, &tx))?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }
}

impl Watcher for InotifyWatcher {
    fn set_excludes(&mut self, dirs: &[RelPath]) -> io::Result<()> {
        let mut t = lock(&self.shared.table);
        t.excludes = dirs.to_vec();
        for d in dirs {
            t.remove_tree(d);
        }
        Ok(())
    }

    fn watch_dir(&mut self, dir: &RelPath) -> io::Result<()> {
        lock(&self.shared.table).add_tree(dir)
    }

    fn unwatch_dir(&mut self, dir: &RelPath) {
        lock(&self.shared.table).remove_tree(dir);
    }

    fn resume_token(&self) -> Option<ResumeToken> {
        None
    }

    fn watch_usage(&self) -> Option<(usize, usize)> {
        Some((lock(&self.shared.table).by_wd.len(), self.shared.limit))
    }
}

impl Drop for InotifyWatcher {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        // removing the watches queues in_ignored events, which wakes the blocked reader
        {
            let mut t = lock(&self.shared.table);
            let all: Vec<WatchDescriptor> = t.by_wd.keys().cloned().collect();
            t.by_wd.clear();
            t.by_path.clear();
            for wd in all {
                let _ = t.watches.remove(wd);
            }
            // guarantees a wakeup even when no watch was left to remove
            if let Ok(wd) = t.watches.add("/", WatchMask::ATTRIB | WatchMask::ONLYDIR) {
                let _ = t.watches.remove(wd);
            }
        }
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

fn child_path(scratch: &mut String, dir: &RelPath, name: &OsStr) -> Option<RelPath> {
    let name = name.to_str()?;
    scratch.clear();
    if !dir.is_root() {
        scratch.push_str(dir.as_str());
        scratch.push('/');
    }
    scratch.push_str(name);
    if name.contains('/') {
        return None;
    }
    RelPath::new(scratch).ok()
}

fn ev_flags(m: EventMask) -> u32 {
    let mut f = 0;
    if m.contains(EventMask::ISDIR) {
        f |= wflag::IS_DIR;
    }
    if m.contains(EventMask::CREATE) {
        f |= wflag::CREATED;
    }
    if m.contains(EventMask::DELETE) {
        f |= wflag::REMOVED;
    }
    if m.intersects(EventMask::MOVED_FROM | EventMask::MOVED_TO) {
        f |= wflag::RENAMED;
    }
    if m.intersects(EventMask::MODIFY | EventMask::CLOSE_WRITE) {
        f |= wflag::MODIFIED;
    }
    if m.contains(EventMask::ATTRIB) {
        f |= wflag::ATTRIB;
    }
    f
}

fn deliver(tx: &Sender<Vec<WatchEvent>>, stop: &AtomicBool, mut batch: Vec<WatchEvent>) -> bool {
    loop {
        match tx.send_timeout(batch, SEND_POLL) {
            Ok(()) => return true,
            Err(SendTimeoutError::Disconnected(_)) => return false,
            Err(SendTimeoutError::Timeout(b)) => {
                if stop.load(Ordering::Acquire) {
                    return false;
                }
                batch = b;
            }
        }
    }
}

fn reader(mut ino: Inotify, sh: &Shared, tx: &Sender<Vec<WatchEvent>>) {
    let mut buf = vec![0u8; READ_BUF];
    let mut scratch = String::new();
    let mut moved_from: Vec<(u32, RelPath)> = Vec::new();
    let mut fresh: Vec<RelPath> = Vec::new();
    loop {
        let events = match ino.read_events_blocking(&mut buf) {
            Ok(ev) => ev,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if !sh.stop.load(Ordering::Acquire) {
                    let ev = WatchEvent {
                        path: RelPath::root(),
                        flags: wflag::RESCAN | wflag::OVERFLOW,
                        cookie: 0,
                    };
                    let _ = deliver(tx, &sh.stop, vec![ev]);
                }
                return;
            }
        };
        if sh.stop.load(Ordering::Acquire) {
            return;
        }
        let mut out = Vec::new();
        {
            let mut t = lock(&sh.table);
            for ev in events {
                if ev.mask.contains(EventMask::Q_OVERFLOW) {
                    out.push(WatchEvent {
                        path: RelPath::root(),
                        flags: wflag::RESCAN | wflag::OVERFLOW,
                        cookie: 0,
                    });
                    continue;
                }
                if ev.mask.contains(EventMask::IGNORED) {
                    if t.forget(&ev.wd).is_some_and(|p| p.is_root()) {
                        out.push(WatchEvent {
                            path: RelPath::root(),
                            flags: wflag::RESCAN | wflag::OVERFLOW,
                            cookie: 0,
                        });
                    }
                    continue;
                }
                // the root itself moved or vanished: the caller checks what the path now names
                if ev
                    .mask
                    .intersects(EventMask::MOVE_SELF | EventMask::DELETE_SELF)
                {
                    if t.by_wd.get(&ev.wd).is_some_and(RelPath::is_root) {
                        out.push(WatchEvent {
                            path: RelPath::root(),
                            flags: wflag::RESCAN | wflag::OVERFLOW,
                            cookie: 0,
                        });
                    }
                    continue;
                }
                let Some(name) = ev.name else { continue };
                let Some(dir) = t.by_wd.get(&ev.wd) else {
                    continue;
                };
                let Some(path) = child_path(&mut scratch, dir, name) else {
                    continue;
                };
                if ev.mask.contains(EventMask::ISDIR) {
                    if ev.mask.contains(EventMask::MOVED_FROM) {
                        moved_from.push((ev.cookie, path.clone()));
                    } else if ev.mask.contains(EventMask::MOVED_TO) {
                        match moved_from.iter().position(|(c, _)| *c == ev.cookie) {
                            Some(i) if t.by_path.contains_key(&moved_from[i].1) => {
                                let (_, from) = moved_from.swap_remove(i);
                                if t.allowed(&path) {
                                    t.rename_tree(&from, &path);
                                } else {
                                    t.remove_tree(&from);
                                }
                            }
                            other => {
                                if let Some(i) = other {
                                    moved_from.swap_remove(i);
                                }
                                if t.allowed(&path) {
                                    fresh.push(path.clone());
                                }
                            }
                        }
                    } else if ev.mask.contains(EventMask::CREATE) && t.allowed(&path) {
                        fresh.push(path.clone());
                    }
                }
                out.push(WatchEvent {
                    flags: ev_flags(ev.mask),
                    cookie: ev.cookie,
                    path,
                });
            }
            for (_, from) in moved_from.drain(..) {
                t.remove_tree(&from);
            }
            // the directory may have filled before its watch existed, so the caller rescans it
            for dir in fresh.drain(..) {
                let flags = match t.add_tree(&dir) {
                    Ok(()) => wflag::RESCAN | wflag::IS_DIR,
                    Err(e) if is_gone(&e) => continue,
                    Err(_) => wflag::RESCAN | wflag::IS_DIR | wflag::OVERFLOW,
                };
                out.push(WatchEvent {
                    path: dir,
                    flags,
                    cookie: 0,
                });
            }
            out.retain(|e| e.path.is_root() || !strictly_under(&e.path, &t.excludes));
        }
        if !out.is_empty() && !deliver(tx, &sh.stop, out) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::start_watcher;
    use crossbeam_channel::Receiver;
    use std::{fs, time::Instant};

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmp(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!("csync-sys-ino-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Tmp(std::fs::canonicalize(p).unwrap())
    }

    fn wait(
        rx: &Receiver<Vec<WatchEvent>>,
        seen: &mut Vec<WatchEvent>,
        pred: impl Fn(&WatchEvent) -> bool,
    ) -> WatchEvent {
        if let Some(e) = seen.iter().find(|e| pred(e)) {
            return e.clone();
        }
        let end = Instant::now() + Duration::from_secs(10);
        while let Some(left) = end.checked_duration_since(Instant::now()) {
            if let Ok(batch) = rx.recv_timeout(left) {
                seen.extend(batch);
                if let Some(e) = seen.iter().find(|e| pred(e)) {
                    return e.clone();
                }
            }
        }
        panic!("event not delivered; saw {seen:?}");
    }

    fn is(e: &WatchEvent, path: &str, flag: u32) -> bool {
        e.path.as_str() == path && e.flags & flag == flag
    }

    #[test]
    fn delivers_create_modify_rename_delete_and_new_dirs() {
        let t = tmp("basic");
        fs::create_dir(t.0.join("pre")).unwrap();
        let (tx, rx) = crossbeam_channel::unbounded();
        let w = start_watcher(&t.0, None, tx).unwrap();
        let mut seen = Vec::new();

        fs::write(t.0.join("a.txt"), b"1").unwrap();
        wait(&rx, &mut seen, |e| is(e, "a.txt", wflag::CREATED));
        fs::write(t.0.join("pre/in.txt"), b"1").unwrap();
        wait(&rx, &mut seen, |e| is(e, "pre/in.txt", wflag::CREATED));

        seen.clear();
        fs::OpenOptions::new()
            .append(true)
            .open(t.0.join("a.txt"))
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"2"))
            .unwrap();
        wait(&rx, &mut seen, |e| is(e, "a.txt", wflag::MODIFIED));

        seen.clear();
        fs::rename(t.0.join("a.txt"), t.0.join("b.txt")).unwrap();
        let from = wait(&rx, &mut seen, |e| is(e, "a.txt", wflag::RENAMED));
        let to = wait(&rx, &mut seen, |e| is(e, "b.txt", wflag::RENAMED));
        assert_ne!(from.cookie, 0);
        assert_eq!(from.cookie, to.cookie);

        seen.clear();
        fs::remove_file(t.0.join("b.txt")).unwrap();
        wait(&rx, &mut seen, |e| is(e, "b.txt", wflag::REMOVED));

        seen.clear();
        fs::create_dir(t.0.join("new")).unwrap();
        wait(&rx, &mut seen, |e| {
            is(e, "new", wflag::CREATED | wflag::IS_DIR)
        });
        wait(&rx, &mut seen, |e| {
            is(e, "new", wflag::RESCAN | wflag::IS_DIR)
        });
        fs::create_dir(t.0.join("new/deep")).unwrap();
        wait(&rx, &mut seen, |e| {
            is(e, "new/deep", wflag::RESCAN | wflag::IS_DIR)
        });
        fs::write(t.0.join("new/deep/x"), b"1").unwrap();
        wait(&rx, &mut seen, |e| is(e, "new/deep/x", wflag::CREATED));

        seen.clear();
        fs::rename(t.0.join("new"), t.0.join("moved")).unwrap();
        wait(&rx, &mut seen, |e| {
            is(e, "moved", wflag::RENAMED | wflag::IS_DIR)
        });
        fs::write(t.0.join("moved/deep/y"), b"1").unwrap();
        wait(&rx, &mut seen, |e| is(e, "moved/deep/y", wflag::CREATED));

        let (used, limit) = w.watch_usage().unwrap();
        assert!(used >= 4 && limit > 0);
        drop(w);
    }

    #[test]
    fn filter_and_excludes_skip_directories() {
        let t = tmp("filter");
        fs::create_dir_all(t.0.join("keep")).unwrap();
        fs::create_dir_all(t.0.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(t.0.join("target")).unwrap();
        let (tx, rx) = crossbeam_channel::unbounded();
        let accept: DirFilter =
            Arc::new(|p: &RelPath| !p.components().any(|c| c == "node_modules"));
        let mut w = crate::sys::start_watcher_filtered(&t.0, None, tx, Some(accept)).unwrap();
        w.set_excludes(&[RelPath::new("target").unwrap()]).unwrap();
        let mut seen = Vec::new();

        fs::write(t.0.join("node_modules/pkg/a"), b"1").unwrap();
        fs::write(t.0.join("target/b"), b"1").unwrap();
        fs::write(t.0.join("keep/c"), b"1").unwrap();
        wait(&rx, &mut seen, |e| is(e, "keep/c", wflag::CREATED));
        assert!(
            !seen
                .iter()
                .any(|e| e.path.as_str().starts_with("node_modules/")
                    || e.path.as_str().starts_with("target/"))
        );
        drop(w);
    }

    #[test]
    fn queue_overflow_requests_rescan() {
        let t = tmp("overflow");
        let max_q: usize = fs::read_to_string("/proc/sys/fs/inotify/max_queued_events")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(16384);
        let (tx, rx) = crossbeam_channel::bounded(1);
        let w = start_watcher(&t.0, None, tx).unwrap();
        fs::write(t.0.join("first"), b"1").unwrap();
        let start = Instant::now();
        while rx.is_empty() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(5));
        }
        // the channel is full and the reader is parked in send, so the kernel queue fills up
        for i in 0..(max_q + 4096) {
            fs::write(t.0.join(format!("f{i}")), b"").unwrap();
        }
        let mut seen = Vec::new();
        wait(&rx, &mut seen, |e| {
            e.path.is_root()
                && e.flags & (wflag::RESCAN | wflag::OVERFLOW) == wflag::RESCAN | wflag::OVERFLOW
        });
        drop(w);
    }
}
