// syscalls behind the optional fuse operations
use super::tree::Special;
use crate::index::tree::StatKey;
use crate::proto::{LinkTarget, RelPath};
use rustix::fs::{AtFlags, Gid, Mode, OFlags, Stat, Uid};
#[cfg(target_os = "linux")]
use rustix::fs::{FallocateFlags, FileType};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::{
    io,
    os::fd::{AsFd, BorrowedFd},
    sync::OnceLock,
};

// the modes the kernel forwards: plain allocation, keep size, punch hole, zero range
#[cfg(target_os = "linux")]
pub fn fallocate(fd: BorrowedFd<'_>, mode: i32, offset: u64, len: u64) -> Result<(), i32> {
    let known = FallocateFlags::KEEP_SIZE | FallocateFlags::PUNCH_HOLE | FallocateFlags::ZERO_RANGE;
    let flags = u32::try_from(mode)
        .ok()
        .and_then(FallocateFlags::from_bits)
        .filter(|f| known.contains(*f))
        .ok_or(libc::EOPNOTSUPP)?;
    rustix::fs::fallocate(fd, flags, offset, len).map_err(|e| e.raw_os_error())
}

// only plain allocation exists on macos; keep size, punch hole and zero range are refused
#[cfg(target_os = "macos")]
pub fn fallocate(fd: BorrowedFd<'_>, mode: i32, offset: u64, len: u64) -> Result<(), i32> {
    if mode != 0 {
        return Err(libc::EOPNOTSUPP);
    }
    crate::sys::fs_unix::extend_allocated(fd, offset, len)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

// copies inside the kernel, without crossing the fuse channel
#[cfg(target_os = "linux")]
pub fn copy_range(
    src: BorrowedFd<'_>,
    mut off_in: u64,
    dst: BorrowedFd<'_>,
    mut off_out: u64,
    len: usize,
) -> Result<usize, i32> {
    rustix::fs::copy_file_range(src, Some(&mut off_in), dst, Some(&mut off_out), len)
        .map_err(|e| e.raw_os_error())
}

// macos has no copy_file_range: the caller falls back to reading and writing through the fuse channel
#[cfg(target_os = "macos")]
pub fn copy_range(
    _src: BorrowedFd<'_>,
    _off_in: u64,
    _dst: BorrowedFd<'_>,
    _off_out: u64,
    _len: usize,
) -> Result<usize, i32> {
    Err(libc::EOPNOTSUPP)
}

pub fn mknod(dir: BorrowedFd<'_>, name: &str, kind: Special, perm: u32) -> Result<(), i32> {
    #[cfg(target_os = "linux")]
    {
        let ft = match kind {
            Special::Fifo => FileType::Fifo,
            Special::Socket => FileType::Socket,
            Special::None => return Err(libc::EPERM),
        };
        rustix::fs::mknodat(dir, name, ft, Mode::from_bits_truncate(perm), 0)
            .map_err(|e| e.raw_os_error())?;
    }
    #[cfg(target_os = "macos")]
    {
        let ty = match kind {
            Special::Fifo => libc::S_IFIFO,
            Special::Socket => libc::S_IFSOCK,
            Special::None => return Err(libc::EPERM),
        };
        crate::sys::fs_unix::mknod_at(dir, name, u32::from(ty) | (perm & 0o7777))
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    }
    fix_special_mode(dir, name, perm)
}

// the daemon's own umask, read once; the kernel already applied the caller's to every mode it sends
fn umask() -> u32 {
    static M: OnceLock<u32> = OnceLock::new();
    *M.get_or_init(read_umask)
}

#[cfg(target_os = "linux")]
fn read_umask() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Umask:"))
                .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
        })
        .unwrap_or(0o777)
}

// umask can only be read by setting it: another thread creating a file in this window sees mask 0
#[cfg(target_os = "macos")]
fn read_umask() -> u32 {
    let old = rustix::process::umask(Mode::empty());
    rustix::process::umask(old);
    u32::from(old.bits())
}

// reads the umask now, so the first use cannot land in the middle of other threads creating files
pub fn init_umask() {
    let _ = umask();
}

fn masked(perm: u32) -> bool {
    perm & 0o7777 & umask() != 0
}

// restores the bits the daemon's umask took from a node it just created
pub fn fix_mode(fd: BorrowedFd<'_>, perm: u32) -> Result<(), i32> {
    if !masked(perm) {
        return Ok(());
    }
    rustix::fs::fchmod(fd, Mode::from_bits_truncate((perm & 0o7777) as _))
        .map_err(|e| e.raw_os_error())
}

pub fn mkdir(dir: BorrowedFd<'_>, name: &str, perm: u32) -> Result<(), i32> {
    let mode = Mode::from_bits_truncate((perm & 0o7777) as _);
    rustix::fs::mkdirat(dir, name, mode).map_err(|e| e.raw_os_error())?;
    if !masked(perm) {
        return Ok(());
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(dir, name, flags, Mode::empty()).map_err(|e| e.raw_os_error())?;
    fix_mode(fd.as_fd(), perm)
}

fn fix_special_mode(dir: BorrowedFd<'_>, name: &str, perm: u32) -> Result<(), i32> {
    if !masked(perm) {
        return Ok(());
    }
    chmod_at(dir, name, perm)
}

// chmod that never follows a symlink swapped in at name: an O_PATH handle is reached through procfs,
// which also covers fifos and sockets that cannot be opened for fchmod
#[cfg(target_os = "linux")]
pub fn chmod_at(dir: BorrowedFd<'_>, name: &str, perm: u32) -> Result<(), i32> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.raw_os_error())?;
    let mode = Mode::from_bits_truncate(perm & 0o7777);
    let at = format!("/proc/self/fd/{}", fd.as_raw_fd());
    match rustix::fs::chmod(at.as_str(), mode) {
        // no procfs: a regular file or directory can still be opened without following
        Err(rustix::io::Errno::NOENT) => {
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let f = rustix::fs::openat(dir, name, flags, Mode::empty())
                .map_err(|e| e.raw_os_error())?;
            rustix::fs::fchmod(&f, mode).map_err(|e| e.raw_os_error())
        }
        r => r.map_err(|e| e.raw_os_error()),
    }
}

// fchmodat takes AT_SYMLINK_NOFOLLOW natively here, fifos and sockets included
#[cfg(target_os = "macos")]
pub fn chmod_at(dir: BorrowedFd<'_>, name: &str, perm: u32) -> Result<(), i32> {
    let mode = Mode::from_bits_truncate((perm & 0o7777) as _);
    rustix::fs::chmodat(dir, name, mode, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.raw_os_error())
}

// what an overlay node reports, straight from its backing inode
pub struct LStat {
    pub size: u64,
    pub blocks: u64,
    pub atime_ns: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
}

// the stat field types differ between architectures
fn wide<T: TryInto<i64>>(v: T) -> i64 {
    v.try_into().unwrap_or(0)
}

fn narrow<T: TryInto<u32>>(v: T) -> u32 {
    v.try_into().unwrap_or(u32::MAX)
}

fn ns(sec: i64, nsec: i64) -> i64 {
    sec.saturating_mul(1_000_000_000).saturating_add(nsec)
}

fn lstat(st: &Stat) -> LStat {
    LStat {
        size: u64::try_from(wide(st.st_size)).unwrap_or(0),
        blocks: u64::try_from(wide(st.st_blocks)).unwrap_or(0),
        atime_ns: ns(wide(st.st_atime), wide(st.st_atime_nsec)),
        mtime_ns: ns(wide(st.st_mtime), wide(st.st_mtime_nsec)),
        ctime_ns: ns(wide(st.st_ctime), wide(st.st_ctime_nsec)),
        mode: narrow(st.st_mode),
        nlink: narrow(st.st_nlink),
        uid: narrow(st.st_uid),
        gid: narrow(st.st_gid),
    }
}

pub fn stat_fd(fd: BorrowedFd<'_>) -> Result<LStat, i32> {
    rustix::fs::fstat(fd)
        .map(|s| lstat(&s))
        .map_err(|e| e.raw_os_error())
}

// stats name itself, never what a symlink there points at
pub fn stat_nofollow_at(dir: BorrowedFd<'_>, name: &str) -> Result<LStat, i32> {
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
        .map(|s| lstat(&s))
        .map_err(|e| e.raw_os_error())
}

// None unless name is a symlink with a target the protocol accepts
pub fn read_link_at(dir: BorrowedFd<'_>, name: &str) -> Option<LinkTarget> {
    let s = rustix::fs::readlinkat(dir, name, Vec::new()).ok()?;
    LinkTarget::new(s.to_str().ok()?).ok()
}

// o_path does not exist on macos, so the leaf is reached through its parent directory instead
#[cfg(target_os = "macos")]
fn parent_beneath<'a>(
    root: BorrowedFd<'_>,
    path: &'a RelPath,
) -> Result<(std::os::fd::OwnedFd, &'a str), i32> {
    let (dir, name) = path.split_last().ok_or(libc::EINVAL)?;
    let dir = if dir.is_empty() {
        RelPath::root()
    } else {
        RelPath::new(dir).map_err(|_| libc::EINVAL)?
    };
    let fd = crate::sys::open_beneath(root, &dir, OFlags::RDONLY | OFlags::DIRECTORY)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    Ok((fd, name))
}

#[cfg(target_os = "linux")]
pub fn stat_beneath(root: BorrowedFd<'_>, path: &RelPath) -> Result<LStat, i32> {
    let fd = crate::sys::open_beneath(root, path, OFlags::PATH | OFlags::NOFOLLOW)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    rustix::fs::fstat(&fd)
        .map(|s| lstat(&s))
        .map_err(|e| e.raw_os_error())
}

#[cfg(target_os = "macos")]
pub fn stat_beneath(root: BorrowedFd<'_>, path: &RelPath) -> Result<LStat, i32> {
    if path.is_root() {
        let fd = crate::sys::open_beneath(root, path, OFlags::RDONLY | OFlags::DIRECTORY)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        return stat_fd(fd.as_fd());
    }
    let (dir, name) = parent_beneath(root, path)?;
    stat_nofollow_at(dir.as_fd(), name)
}

// the index key of the node at path, without following a symlink there
#[cfg(target_os = "linux")]
pub fn stat_key_beneath(root: BorrowedFd<'_>, path: &RelPath) -> io::Result<StatKey> {
    let fd = crate::sys::open_beneath(root, path, OFlags::PATH | OFlags::NOFOLLOW)?;
    crate::sys::stat_key(fd.as_fd())
}

#[cfg(target_os = "macos")]
pub fn stat_key_beneath(root: BorrowedFd<'_>, path: &RelPath) -> io::Result<StatKey> {
    if path.is_root() {
        let fd = crate::sys::open_beneath(root, path, OFlags::RDONLY | OFlags::DIRECTORY)?;
        return crate::sys::stat_key(fd.as_fd());
    }
    let (dir, name) = parent_beneath(root, path).map_err(io::Error::from_raw_os_error)?;
    crate::sys::stat_key_at(dir.as_fd(), name)
}

// the target of the symlink at path; None for anything else
#[cfg(target_os = "linux")]
pub fn read_link_beneath(root: BorrowedFd<'_>, path: &RelPath) -> Option<LinkTarget> {
    let fd = crate::sys::open_beneath(root, path, OFlags::PATH | OFlags::NOFOLLOW).ok()?;
    let s = rustix::fs::readlinkat(&fd, "", Vec::new()).ok()?;
    LinkTarget::new(s.to_str().ok()?).ok()
}

#[cfg(target_os = "macos")]
pub fn read_link_beneath(root: BorrowedFd<'_>, path: &RelPath) -> Option<LinkTarget> {
    let (dir, name) = parent_beneath(root, path).ok()?;
    read_link_at(dir.as_fd(), name)
}

pub fn chown_at(
    dir: BorrowedFd<'_>,
    name: &str,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), i32> {
    // -1 means unchanged in chown(2), so it is never a real id
    let uid = uid.filter(|u| *u != u32::MAX).map(Uid::from_raw);
    let gid = gid.filter(|g| *g != u32::MAX).map(Gid::from_raw);
    rustix::fs::chownat(dir, name, uid, gid, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| e.raw_os_error())
}

pub fn special_of_mode(mode: u32) -> Special {
    match mode & 0o170_000 {
        0o010_000 => Special::Fifo,
        0o140_000 => Special::Socket,
        _ => Special::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmp(tag: &str) -> Tmp {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "csync-fsops-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }

    fn open_dir(p: &std::path::Path) -> OwnedFd {
        rustix::fs::open(
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn rel(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    #[test]
    fn symlink_leaf_is_statted_and_read_without_following() {
        let t = tmp("link");
        fs::create_dir(t.0.join("sub")).unwrap();
        fs::write(t.0.join("sub/real"), b"twelve bytes").unwrap();
        symlink("real", t.0.join("sub/ln")).unwrap();
        symlink("sub", t.0.join("dirln")).unwrap();
        let root = open_dir(&t.0);
        let sub = open_dir(&t.0.join("sub"));

        let st = stat_nofollow_at(sub.as_fd(), "ln").unwrap();
        assert_eq!(st.mode & 0o170_000, 0o120_000);
        assert_eq!(st.size, 4);
        let st = stat_nofollow_at(sub.as_fd(), "real").unwrap();
        assert_eq!(st.mode & 0o170_000, 0o100_000);
        assert_eq!(st.size, 12);
        assert_eq!(
            stat_nofollow_at(sub.as_fd(), "missing").err(),
            Some(libc::ENOENT)
        );
        assert_eq!(read_link_at(sub.as_fd(), "ln").unwrap().as_str(), "real");
        assert!(read_link_at(sub.as_fd(), "real").is_none());

        let st = stat_beneath(root.as_fd(), &rel("sub/ln")).unwrap();
        assert_eq!(st.mode & 0o170_000, 0o120_000);
        let k = stat_key_beneath(root.as_fd(), &rel("sub/ln")).unwrap();
        assert_eq!(k.mode & 0o170_000, 0o120_000);
        let k = stat_key_beneath(root.as_fd(), &rel("sub/real")).unwrap();
        assert_eq!(k.size, 12);
        assert_eq!(
            read_link_beneath(root.as_fd(), &rel("sub/ln"))
                .unwrap()
                .as_str(),
            "real"
        );
        assert_eq!(
            read_link_beneath(root.as_fd(), &rel("dirln"))
                .unwrap()
                .as_str(),
            "sub"
        );
        assert!(read_link_beneath(root.as_fd(), &rel("sub/real")).is_none());
        assert!(read_link_beneath(root.as_fd(), &rel("dirln/ln")).is_none());
        assert!(stat_beneath(root.as_fd(), &rel("dirln/real")).is_err());
        assert!(stat_key_beneath(root.as_fd(), &rel("dirln/real")).is_err());
        let st = stat_beneath(root.as_fd(), &RelPath::root()).unwrap();
        assert_eq!(st.mode & 0o170_000, 0o040_000);
        assert!(stat_key_beneath(root.as_fd(), &RelPath::root()).is_ok());
    }

    #[test]
    fn chmod_at_changes_the_name_and_not_a_symlink_target() {
        let t = tmp("chmod");
        fs::write(t.0.join("file"), b"x").unwrap();
        fs::set_permissions(t.0.join("file"), fs::Permissions::from_mode(0o600)).unwrap();
        let d = open_dir(&t.0);
        chmod_at(d.as_fd(), "file", 0o640).unwrap();
        let mode = |n: &str| {
            fs::symlink_metadata(t.0.join(n))
                .unwrap()
                .permissions()
                .mode()
        };
        assert_eq!(mode("file") & 0o7777, 0o640);
        symlink("file", t.0.join("ln")).unwrap();
        let _ = chmod_at(d.as_fd(), "ln", 0o777);
        assert_eq!(mode("file") & 0o7777, 0o640);
        assert_eq!(chmod_at(d.as_fd(), "missing", 0o600), Err(libc::ENOENT));
    }

    #[test]
    fn mknod_creates_a_fifo_with_the_requested_permissions() {
        let t = tmp("fifo");
        let d = open_dir(&t.0);
        mknod(d.as_fd(), "pipe", Special::Fifo, 0o666).unwrap();
        let st = stat_nofollow_at(d.as_fd(), "pipe").unwrap();
        assert_eq!(special_of_mode(st.mode), Special::Fifo);
        assert_eq!(st.mode & 0o7777, 0o666);
        assert_eq!(
            mknod(d.as_fd(), "pipe", Special::Fifo, 0o600),
            Err(libc::EEXIST)
        );
        assert_eq!(
            mknod(d.as_fd(), "plain", Special::None, 0o600),
            Err(libc::EPERM)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fallocate_plain_grows_a_file_and_other_modes_are_refused() {
        let t = tmp("falloc");
        fs::write(t.0.join("f"), b"abc").unwrap();
        let d = open_dir(&t.0);
        let f = rustix::fs::openat(d.as_fd(), "f", OFlags::RDWR, Mode::empty()).unwrap();
        fallocate(f.as_fd(), 0, 0, 8192).unwrap();
        assert_eq!(fs::metadata(t.0.join("f")).unwrap().len(), 8192);
        fallocate(f.as_fd(), 0, 0, 10).unwrap();
        assert_eq!(fs::metadata(t.0.join("f")).unwrap().len(), 8192);
        for mode in [1, 2, 3, 0x10, -1] {
            assert_eq!(fallocate(f.as_fd(), mode, 0, 4096), Err(libc::EOPNOTSUPP));
        }
        assert_eq!(fs::metadata(t.0.join("f")).unwrap().len(), 8192);
        assert_eq!(
            copy_range(f.as_fd(), 0, f.as_fd(), 0, 1),
            Err(libc::EOPNOTSUPP)
        );
    }
}
