use crate::{
    index::tree::StatKey,
    proto::{Kind, Name, RelPath},
};
use crossbeam_channel::Sender;
use rustc_hash::FxHashMap;
use std::{
    io,
    os::fd::{BorrowedFd, OwnedFd},
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
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
    probe_fold, rename_noreplace, same_bytes, same_version, stat_key_at,
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
const ECHO_TTL: Duration = Duration::from_secs(2);
const ECHO_PURGE: usize = 1_024;

struct Echo {
    tmp: String,
    left: u8,
    until: Instant,
}

// the committer's renames from its own temp names: a watcher drops exactly these, nothing else
#[derive(Default)]
pub struct Echoes {
    on: AtomicBool,
    m: Mutex<FxHashMap<RelPath, Echo>>,
}

impl Echoes {
    pub fn enable(&self) {
        self.on.store(true, Ordering::Release);
    }

    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::Acquire)
    }

    // moves: how many rename events name `path` (two for an exchange)
    pub fn expect(&self, path: &RelPath, tmp: &str, moves: u8) {
        if !self.on.load(Ordering::Acquire) {
            return;
        }
        let now = Instant::now();
        let mut m = lock(&self.m);
        if m.len() >= ECHO_PURGE {
            m.retain(|_, e| e.until > now);
        }
        m.insert(
            path.clone(),
            Echo {
                tmp: tmp.to_owned(),
                left: moves,
                until: now + ECHO_TTL,
            },
        );
    }

    // true when this rename of `path` paired with `tmp` is the one expected; consumes it
    pub fn take(&self, path: &RelPath, tmp: &str) -> bool {
        let mut m = lock(&self.m);
        let Some(e) = m.get_mut(path) else {
            return false;
        };
        if e.tmp != tmp || e.until <= Instant::now() {
            return false;
        }
        e.left = e.left.saturating_sub(1);
        if e.left == 0 {
            m.remove(path);
        }
        true
    }
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
    start_watcher_echoes(root, resume, tx, accept, Arc::default())
}

pub fn start_watcher_echoes(
    root: &Path,
    resume: Option<ResumeToken>,
    tx: Sender<Vec<WatchEvent>>,
    accept: Option<DirFilter>,
    echoes: Arc<Echoes>,
) -> io::Result<Box<dyn Watcher>> {
    #[cfg(target_os = "macos")]
    {
        let _ = echoes;
        Ok(Box::new(macos::fsevents::FsEventsWatcher::start(
            root, resume, tx, accept,
        )?))
    }
    #[cfg(target_os = "linux")]
    {
        let _ = resume;
        Ok(Box::new(linux::inotify::InotifyWatcher::start(
            root, tx, accept, echoes,
        )?))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (root, resume, tx, accept, echoes);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no file watcher on this platform",
        ))
    }
}

// (filesystem type, on a local disk, case sensitive) of the volume holding path
#[cfg(target_os = "macos")]
pub fn volume_of(path: &Path) -> io::Result<(String, bool, bool)> {
    let st = rustix::fs::statfs(path)?;
    let ty: Vec<u8> = st
        .f_fstypename
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    let local = st.f_flags & libc::MNT_LOCAL as u32 != 0;
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: c is a valid nul-terminated path for the duration of the call.
    let cs = unsafe { libc::pathconf(c.as_ptr(), libc::_PC_CASE_SENSITIVE) };
    Ok((String::from_utf8_lossy(&ty).into_owned(), local, cs == 1))
}

// icloud drive and file provider placeholders (dataless files) fail to read instead of downloading on scan or hash
pub fn keep_dataless() {
    #[cfg(target_os = "macos")]
    {
        const IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES: libc::c_int = 3;
        const IOPOL_SCOPE_PROCESS: libc::c_int = 0;
        const IOPOL_MATERIALIZE_DATALESS_FILES_OFF: libc::c_int = 1;
        unsafe extern "C" {
            fn setiopolicy_np(
                iotype: libc::c_int,
                scope: libc::c_int,
                policy: libc::c_int,
            ) -> libc::c_int;
        }
        // SAFETY: setiopolicy_np takes three plain ints and only changes this process's io policy.
        unsafe {
            setiopolicy_np(
                IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
                IOPOL_SCOPE_PROCESS,
                IOPOL_MATERIALIZE_DATALESS_FILES_OFF,
            );
        }
    }
}

// a replacement written through a temp keeps the old file's extended attributes and acl (tags, quarantine, forks)
pub fn copy_xattrs(from: BorrowedFd<'_>, to: BorrowedFd<'_>) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: both fds are open for the call and a null state is allowed by fcopyfile.
        let r = unsafe {
            libc::fcopyfile(
                from.as_raw_fd(),
                to.as_raw_fd(),
                std::ptr::null_mut(),
                libc::COPYFILE_XATTR | libc::COPYFILE_ACL,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        // linux caps a name list and a value at 64 KiB each
        const XATTR_MAX: usize = 1 << 16;
        let mut names = vec![0u8; XATTR_MAX];
        let got = rustix::fs::flistxattr(from, &mut names[..])?;
        if got == 0 {
            return Ok(());
        }
        let mut rest = &names[..got.min(XATTR_MAX)];
        let mut val = vec![0u8; XATTR_MAX];
        while let Ok(n) = std::ffi::CStr::from_bytes_until_nul(rest) {
            rest = &rest[n.to_bytes_with_nul().len()..];
            // security and trusted names may be refused to an unprivileged host; the rest still copy
            if let Ok(l) = rustix::fs::fgetxattr(from, n, &mut val[..]) {
                let v = &val[..l.min(XATTR_MAX)];
                let _ = rustix::fs::fsetxattr(to, n, v, rustix::fs::XattrFlags::empty());
            }
        }
        Ok(())
    }
}

// whether an entry that resolves under `name` is stored under exactly that spelling (folding volumes resolve others too)
pub fn spelled_at(dir: BorrowedFd<'_>, name: &str) -> io::Result<bool> {
    #[cfg(target_os = "macos")]
    if macos::dir::stored_name_at(dir, name)? == name.as_bytes() {
        return Ok(true);
    }
    // the slow path also settles hard links, whose stored name may be another link's
    let d = rustix::fs::openat(
        dir,
        ".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let mut ents = Vec::new();
    read_dir_plus(std::os::fd::AsFd::as_fd(&d), &mut ents)?;
    Ok(ents.iter().any(|e| e.name.as_str() == name))
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
