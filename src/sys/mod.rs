use crate::{
    index::tree::StatKey,
    proto::{Kind, Name, RelPath},
};
use crossbeam_channel::Sender;
use std::{
    io,
    os::fd::{BorrowedFd, OwnedFd},
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

#[cfg(unix)]
pub mod fs_unix;
#[cfg(unix)]
pub mod signal;
#[cfg(unix)]
pub use signal::signals;

#[cfg(target_os = "macos")]
pub mod macos {
    pub mod dir;
    pub mod fsevents;
}

#[cfg(target_os = "linux")]
pub mod linux {
    pub mod dir;
    pub mod inotify;
}

#[cfg(unix)]
pub use fs_unix::{
    Swap, clone_at, exchange_checked, fdatasync, fsync, full_fsync, open_beneath_mode, peer_uid,
    probe_fold, rename_noreplace, same_version, stat_key_at,
};

#[derive(Clone, Debug)]
pub struct DirEntryPlus {
    pub name: Name,
    pub kind: Option<Kind>,
    pub stat: StatKey,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResumeToken {
    pub volume: [u8; 16],
    pub event_id: u64,
}

pub mod wflag {
    pub const CREATED: u32 = 1;
    pub const REMOVED: u32 = 2;
    pub const RENAMED: u32 = 4;
    pub const MODIFIED: u32 = 8;
    pub const ATTRIB: u32 = 16;
    pub const IS_DIR: u32 = 32;
    pub const OWN: u32 = 64;
    pub const RESCAN: u32 = 128;
    pub const OVERFLOW: u32 = 256;
}
#[derive(Clone, Debug)]
pub struct WatchEvent {
    pub path: RelPath,
    pub flags: u32,
    pub cookie: u32,
}

pub type DirFilter = Arc<dyn Fn(&RelPath) -> bool + Send + Sync>;

pub trait Watcher: Send {
    fn set_excludes(&mut self, dirs: &[RelPath]) -> io::Result<()>;
    fn watch_dir(&mut self, dir: &RelPath) -> io::Result<()>;
    fn unwatch_dir(&mut self, dir: &RelPath);
    fn resume_token(&self) -> Option<ResumeToken>;
    fn watch_usage(&self) -> Option<(usize, usize)> {
        None
    }
    // true once since the watcher last had to drop a batch on a full channel
    fn take_overflow(&self) -> bool {
        false
    }
}

pub fn start_watcher(
    root: &Path,
    resume: Option<ResumeToken>,
    tx: Sender<Vec<WatchEvent>>,
) -> io::Result<Box<dyn Watcher>> {
    start_watcher_filtered(root, resume, tx, None)
}

pub fn start_watcher_filtered(
    root: &Path,
    resume: Option<ResumeToken>,
    tx: Sender<Vec<WatchEvent>>,
    accept: Option<DirFilter>,
) -> io::Result<Box<dyn Watcher>> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::fsevents::FsEventsWatcher::start(
            root, resume, tx, accept,
        )?))
    }
    #[cfg(target_os = "linux")]
    {
        let _ = resume;
        Ok(Box::new(linux::inotify::InotifyWatcher::start(
            root, tx, accept,
        )?))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (root, resume, tx, accept);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no file watcher on this platform",
        ))
    }
}

pub fn read_dir_plus(dir: BorrowedFd<'_>, out: &mut Vec<DirEntryPlus>) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::dir::read_dir_plus(dir, out)
    }
    #[cfg(target_os = "linux")]
    {
        linux::dir::read_dir_plus(dir, out)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (dir, out);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "read_dir_plus is not available on this platform",
        ))
    }
}

pub fn open_beneath(
    root: BorrowedFd<'_>,
    p: &RelPath,
    flags: rustix::fs::OFlags,
) -> io::Result<OwnedFd> {
    fs_unix::open_beneath(root, p, flags)
}

pub fn exchange(dir: BorrowedFd<'_>, a: &str, b: &str) -> io::Result<()> {
    fs_unix::exchange(dir, a, b)
}

pub fn clone_or_copy(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> io::Result<()> {
    fs_unix::clone_or_copy(src, dst)
}

pub fn stat_key(fd: BorrowedFd<'_>) -> io::Result<StatKey> {
    fs_unix::stat_key(fd)
}

pub(crate) const S_IFMT: u32 = 0o170_000;
pub(crate) const S_IFREG: u32 = 0o100_000;
pub(crate) const S_IFDIR: u32 = 0o040_000;
pub(crate) const S_IFLNK: u32 = 0o120_000;

pub fn kind_of_mode(mode: u32) -> Option<Kind> {
    match mode & S_IFMT {
        S_IFREG => Some(Kind::File),
        S_IFDIR => Some(Kind::Dir),
        S_IFLNK => Some(Kind::Symlink),
        _ => None,
    }
}

pub(crate) fn ts_ns(sec: i64, nsec: i64) -> i64 {
    sec.saturating_mul(1_000_000_000).saturating_add(nsec)
}

// directory sizes are filesystem bookkeeping, so every stat key reports them as 0
pub(crate) fn key_size(mode: u32, size: u64) -> u64 {
    if mode & S_IFMT == S_IFDIR { 0 } else { size }
}

pub(crate) fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what)
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// true when path lies strictly inside one of dirs
pub(crate) fn strictly_under(path: &RelPath, dirs: &[RelPath]) -> bool {
    dirs.iter().any(|d| path != d && path.starts_with(d))
}
