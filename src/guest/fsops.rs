// syscalls behind the optional fuse operations
use super::tree::Special;
use crate::proto::RelPath;
use rustix::fs::{AtFlags, FallocateFlags, FileType, Gid, Mode, OFlags, Stat, Uid};
use std::{
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    sync::OnceLock,
};

// the modes the kernel forwards: plain allocation, keep size, punch hole, zero range
pub fn fallocate(fd: BorrowedFd<'_>, mode: i32, offset: u64, len: u64) -> Result<(), i32> {
    let known = FallocateFlags::KEEP_SIZE | FallocateFlags::PUNCH_HOLE | FallocateFlags::ZERO_RANGE;
    let flags = u32::try_from(mode)
        .ok()
        .and_then(FallocateFlags::from_bits)
        .filter(|f| known.contains(*f))
        .ok_or(libc::EOPNOTSUPP)?;
    rustix::fs::fallocate(fd, flags, offset, len).map_err(|e| e.raw_os_error())
}

// copies inside the kernel, without crossing the fuse channel
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

pub fn mknod(dir: BorrowedFd<'_>, name: &str, kind: Special, perm: u32) -> Result<(), i32> {
    let ft = match kind {
        Special::Fifo => FileType::Fifo,
        Special::Socket => FileType::Socket,
        Special::None => return Err(libc::EPERM),
    };
    rustix::fs::mknodat(dir, name, ft, Mode::from_bits_truncate(perm), 0)
        .map_err(|e| e.raw_os_error())?;
    fix_special_mode(dir, name, perm)
}

// the daemon's own umask, read once; the kernel already applied the caller's to every mode it sends
fn umask() -> u32 {
    static M: OnceLock<u32> = OnceLock::new();
    *M.get_or_init(|| {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Umask:"))
                    .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
            })
            .unwrap_or(0o777)
    })
}

fn masked(perm: u32) -> bool {
    perm & 0o7777 & umask() != 0
}

// restores the bits the daemon's umask took from a node it just created
pub fn fix_mode(fd: BorrowedFd<'_>, perm: u32) -> Result<(), i32> {
    if !masked(perm) {
        return Ok(());
    }
    rustix::fs::fchmod(fd, Mode::from_bits_truncate(perm & 0o7777)).map_err(|e| e.raw_os_error())
}

pub fn mkdir(dir: BorrowedFd<'_>, name: &str, perm: u32) -> Result<(), i32> {
    let mode = Mode::from_bits_truncate(perm & 0o7777);
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

pub fn stat_beneath(root: BorrowedFd<'_>, path: &RelPath) -> Result<LStat, i32> {
    let fd = crate::sys::open_beneath(root, path, OFlags::PATH | OFlags::NOFOLLOW)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    rustix::fs::fstat(&fd)
        .map(|s| lstat(&s))
        .map_err(|e| e.raw_os_error())
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
