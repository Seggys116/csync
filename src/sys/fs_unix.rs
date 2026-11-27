use super::{invalid, key_size, ts_ns};
use crate::{
    index::tree::StatKey,
    proto::{NAME_MAX, RelPath, path::TMP_PREFIX},
};
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use rustix::io::Errno;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

const COPY_BUF: usize = 1 << 20;
#[cfg(target_os = "macos")]
const CLONE_NOFOLLOW: u32 = 0x0001;

pub(crate) fn check_component(c: &str) -> io::Result<()> {
    let b = c.as_bytes();
    if b.is_empty()
        || c == "."
        || c == ".."
        || b.len() > NAME_MAX
        || b.iter().any(|&x| x == b'/' || x == 0)
    {
        return Err(invalid("path component is not a plain name"));
    }
    Ok(())
}

fn creating(flags: OFlags) -> bool {
    #[cfg(target_os = "linux")]
    {
        // tmpfile includes o_directory, so it must match in full
        flags.contains(OFlags::CREATE) || flags.contains(OFlags::TMPFILE)
    }
    #[cfg(not(target_os = "linux"))]
    {
        flags.contains(OFlags::CREATE)
    }
}

pub fn open_beneath(root: BorrowedFd<'_>, p: &RelPath, flags: OFlags) -> io::Result<OwnedFd> {
    open_beneath_mode(root, p, flags, Mode::from_bits_truncate(0o666))
}

pub fn open_beneath_mode(
    root: BorrowedFd<'_>,
    p: &RelPath,
    flags: OFlags,
    mode: Mode,
) -> io::Result<OwnedFd> {
    let mode = if creating(flags) { mode } else { Mode::empty() };
    if let Some(r) = open_fast(root, p.as_str(), flags, mode) {
        return r;
    }
    open_walk(root, p.as_str(), flags, mode)
}

#[cfg(target_os = "linux")]
fn open_fast(
    root: BorrowedFd<'_>,
    p: &str,
    flags: OFlags,
    mode: Mode,
) -> Option<io::Result<OwnedFd>> {
    use rustix::fs::ResolveFlags;
    use std::sync::atomic::{AtomicBool, Ordering};
    static NO_OPENAT2: AtomicBool = AtomicBool::new(false);
    if NO_OPENAT2.load(Ordering::Relaxed) {
        return None;
    }
    let path = if p.is_empty() { "." } else { p };
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    for _ in 0..4 {
        match rustix::fs::openat2(root, path, flags | OFlags::CLOEXEC, mode, resolve) {
            Ok(fd) => return Some(Ok(fd)),
            Err(Errno::NOSYS) => {
                NO_OPENAT2.store(true, Ordering::Relaxed);
                return None;
            }
            // a concurrent rename or mount inside the tree; the kernel asks for a retry
            Err(Errno::AGAIN) | Err(Errno::INTR) => continue,
            Err(e) => return Some(Err(e.into())),
        }
    }
    None
}

// o_nofollow_any (macos 11+) refuses a symlink in any component, one syscall
#[cfg(target_os = "macos")]
fn open_fast(
    root: BorrowedFd<'_>,
    p: &str,
    flags: OFlags,
    mode: Mode,
) -> Option<io::Result<OwnedFd>> {
    let path = if p.is_empty() { "." } else { p };
    for c in path.split('/') {
        if c == ".." || c.is_empty() {
            return Some(Err(invalid("path component is not a plain name")));
        }
    }
    loop {
        match rustix::fs::openat(
            root,
            path,
            flags | OFlags::CLOEXEC | OFlags::NOFOLLOW_ANY,
            mode,
        ) {
            Ok(fd) => return Some(Ok(fd)),
            Err(Errno::INTR) => continue,
            Err(e) => return Some(Err(e.into())),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_fast(
    _root: BorrowedFd<'_>,
    _p: &str,
    _flags: OFlags,
    _mode: Mode,
) -> Option<io::Result<OwnedFd>> {
    None
}

pub(crate) fn open_walk(
    root: BorrowedFd<'_>,
    p: &str,
    flags: OFlags,
    mode: Mode,
) -> io::Result<OwnedFd> {
    if p.is_empty() {
        return Ok(rustix::fs::openat(
            root,
            ".",
            flags | OFlags::CLOEXEC,
            mode,
        )?);
    }
    let (parent, last) = p.rsplit_once('/').unwrap_or(("", p));
    #[cfg(target_os = "linux")]
    let dir_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut cur: Option<OwnedFd> = None;
    if !parent.is_empty() {
        for c in parent.split('/') {
            check_component(c)?;
            let base = cur.as_ref().map_or(root, |f| f.as_fd());
            let next = rustix::fs::openat(base, c, dir_flags, Mode::empty())?;
            cur = Some(next);
        }
    }
    check_component(last)?;
    let base = cur.as_ref().map_or(root, |f| f.as_fd());
    Ok(rustix::fs::openat(
        base,
        last,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
    )?)
}

pub fn exchange(dir: BorrowedFd<'_>, a: &str, b: &str) -> io::Result<()> {
    check_component(a)?;
    check_component(b)?;
    Ok(rustix::fs::renameat_with(
        dir,
        a,
        dir,
        b,
        RenameFlags::EXCHANGE,
    )?)
}

pub fn rename_noreplace(dir: BorrowedFd<'_>, from: &str, to: &str) -> io::Result<()> {
    check_component(from)?;
    check_component(to)?;
    Ok(rustix::fs::renameat_with(
        dir,
        from,
        dir,
        to,
        RenameFlags::NOREPLACE,
    )?)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Swap {
    Committed,
    Raced,
}

// ctime is excluded: the exchange itself bumps ctime on both inodes
pub fn same_version(a: &StatKey, b: &StatKey) -> bool {
    a.dev == b.dev
        && a.ino == b.ino
        && a.size == b.size
        && a.mtime_ns == b.mtime_ns
        && a.mode == b.mode
}

// the bytes are those of `b`: a chmod alone changes the version but not the content
pub fn same_bytes(a: &StatKey, b: &StatKey) -> bool {
    a.dev == b.dev && a.ino == b.ino && a.size == b.size && a.mtime_ns == b.mtime_ns
}

pub fn exchange_checked(
    dir: BorrowedFd<'_>,
    tmp: &str,
    dest: &str,
    old: BorrowedFd<'_>,
    k1: &StatKey,
) -> io::Result<Swap> {
    exchange(dir, tmp, dest)?;
    let ok = match (stat_key(old), stat_key_at(dir, tmp)) {
        (Ok(now), Ok(moved)) => {
            same_version(&now, k1) && moved.dev == now.dev && moved.ino == now.ino
        }
        _ => false,
    };
    if ok {
        // a leftover tmp name is swept at host start, the commit itself is already in place
        let _ = rustix::fs::unlinkat(dir, tmp, AtFlags::empty());
        return Ok(Swap::Committed);
    }
    exchange(dir, tmp, dest)?;
    rustix::fs::unlinkat(dir, tmp, AtFlags::empty())?;
    Ok(Swap::Raced)
}

pub fn fsync(fd: BorrowedFd<'_>) -> io::Result<()> {
    loop {
        match rustix::fs::fsync(fd) {
            Err(Errno::INTR) => continue,
            r => return Ok(r?),
        }
    }
}

pub fn fdatasync(fd: BorrowedFd<'_>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        loop {
            match rustix::fs::fdatasync(fd) {
                Err(Errno::INTR) => continue,
                r => return Ok(r?),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        fsync(fd)
    }
}

// a real media flush on macos; plain fsync only reaches the drive cache there
pub fn full_fsync(fd: BorrowedFd<'_>) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        match rustix::fs::fcntl_fullfsync(fd) {
            Ok(()) => Ok(()),
            Err(Errno::NOTSUP) | Err(Errno::OPNOTSUPP) | Err(Errno::INVAL) => fsync(fd),
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        fsync(fd)
    }
}

#[cfg(target_os = "linux")]
const STATX_MASK: rustix::fs::StatxFlags = rustix::fs::StatxFlags::TYPE
    .union(rustix::fs::StatxFlags::MODE)
    .union(rustix::fs::StatxFlags::INO)
    .union(rustix::fs::StatxFlags::SIZE)
    .union(rustix::fs::StatxFlags::MTIME)
    .union(rustix::fs::StatxFlags::CTIME);

#[cfg(target_os = "linux")]
pub(crate) fn statx_at<P: rustix::path::Arg>(
    dir: BorrowedFd<'_>,
    name: P,
    flags: AtFlags,
) -> io::Result<rustix::fs::Statx> {
    Ok(rustix::fs::statx(
        dir,
        name,
        flags | AtFlags::STATX_DONT_SYNC,
        STATX_MASK,
    )?)
}

#[cfg(target_os = "linux")]
pub(crate) fn key_from_statx(st: &rustix::fs::Statx) -> StatKey {
    let mode = u32::from(st.stx_mode);
    StatKey {
        dev: rustix::fs::makedev(st.stx_dev_major, st.stx_dev_minor),
        ino: st.stx_ino,
        size: key_size(mode, st.stx_size),
        mtime_ns: ts_ns(st.stx_mtime.tv_sec, i64::from(st.stx_mtime.tv_nsec)),
        ctime_ns: ts_ns(st.stx_ctime.tv_sec, i64::from(st.stx_ctime.tv_nsec)),
        mode,
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn key_from_stat(st: &rustix::fs::Stat) -> StatKey {
    let mode = u32::from(st.st_mode);
    StatKey {
        dev: st.st_dev as u64,
        ino: st.st_ino,
        size: key_size(mode, st.st_size as u64),
        mtime_ns: ts_ns(st.st_mtime, st.st_mtime_nsec),
        ctime_ns: ts_ns(st.st_ctime, st.st_ctime_nsec),
        mode,
    }
}

pub fn stat_key(fd: BorrowedFd<'_>) -> io::Result<StatKey> {
    #[cfg(target_os = "linux")]
    {
        Ok(key_from_statx(&statx_at(fd, c"", AtFlags::EMPTY_PATH)?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(key_from_stat(&rustix::fs::fstat(fd)?))
    }
}

pub fn stat_key_at(dir: BorrowedFd<'_>, name: &str) -> io::Result<StatKey> {
    check_component(name)?;
    #[cfg(target_os = "linux")]
    {
        Ok(key_from_statx(&statx_at(
            dir,
            name,
            AtFlags::SYMLINK_NOFOLLOW,
        )?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(key_from_stat(&rustix::fs::statat(
            dir,
            name,
            AtFlags::SYMLINK_NOFOLLOW,
        )?))
    }
}

#[cfg(target_os = "linux")]
fn clone_unsupported(e: Errno) -> bool {
    matches!(
        e,
        Errno::OPNOTSUPP
            | Errno::XDEV
            | Errno::INVAL
            | Errno::NOTTY
            | Errno::NOSYS
            | Errno::BADF
            | Errno::PERM
    )
}

pub fn clone_or_copy(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        match rustix::fs::ioctl_ficlone(dst, src) {
            Ok(()) => return Ok(()),
            Err(e) if clone_unsupported(e) => {}
            Err(e) => return Err(e.into()),
        }
        let (mut off_in, mut off_out) = (0u64, 0u64);
        loop {
            match rustix::fs::copy_file_range(
                src,
                Some(&mut off_in),
                dst,
                Some(&mut off_out),
                1 << 30,
            ) {
                Ok(0) => break,
                Ok(_) => {}
                Err(Errno::INTR) => {}
                Err(e) if off_out == 0 && clone_unsupported(e) => return copy_rw(src, dst),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(rustix::fs::ftruncate(dst, off_out)?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        copy_rw(src, dst)
    }
}

pub(crate) fn copy_rw(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> io::Result<()> {
    let mut buf = vec![0u8; COPY_BUF];
    let mut off = 0u64;
    loop {
        let n = match rustix::io::pread(src, &mut buf[..], off) {
            Ok(0) => break,
            Ok(n) => n,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        };
        let mut done = 0;
        while done < n {
            match rustix::io::pwrite(dst, &buf[done..n], off + done as u64) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(w) => done += w,
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        off += n as u64;
    }
    Ok(rustix::fs::ftruncate(dst, off)?)
}

// path-based clone: clonefileat on apfs, ficlone or a copy elsewhere; dst must not exist
pub fn clone_at(
    src_dir: BorrowedFd<'_>,
    src: &str,
    dst_dir: BorrowedFd<'_>,
    dst: &str,
) -> io::Result<()> {
    check_component(src)?;
    check_component(dst)?;
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        let s = CString::new(src).map_err(|_| invalid("nul in name"))?;
        let d = CString::new(dst).map_err(|_| invalid("nul in name"))?;
        // SAFETY: both names are valid nul-terminated strings and both fds are open for the call.
        let r = unsafe {
            libc::clonefileat(
                src_dir.as_raw_fd(),
                s.as_ptr(),
                dst_dir.as_raw_fd(),
                d.as_ptr(),
                CLONE_NOFOLLOW,
            )
        };
        if r == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENOTSUP) | Some(libc::EXDEV) => {}
            _ => return Err(e),
        }
    }
    let s = rustix::fs::openat(
        src_dir,
        src,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let perm = stat_key(s.as_fd())?.mode & 0o7777;
    let d = rustix::fs::openat(
        dst_dir,
        dst,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(perm as _),
    )?;
    match clone_or_copy(s.as_fd(), d.as_fd()) {
        Ok(()) => Ok(()),
        Err(e) => {
            drop(d);
            let _ = rustix::fs::unlinkat(dst_dir, dst, AtFlags::empty());
            Err(e)
        }
    }
}

// clones an open file into a new name beside dir; dst must not exist, and the clone is isolated from later writes to src
#[cfg(target_os = "macos")]
pub fn clone_fd_at(src: BorrowedFd<'_>, dst_dir: BorrowedFd<'_>, dst: &str) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    check_component(dst)?;
    let d = CString::new(dst).map_err(|_| invalid("nul in name"))?;
    // SAFETY: the name is a valid nul-terminated string and both fds are open for the call.
    let r = unsafe { libc::fclonefileat(src.as_raw_fd(), dst_dir.as_raw_fd(), d.as_ptr(), 0) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// fallocate mode 0: blocks are reserved and the size grows to offset+len, but a larger file never shrinks
#[cfg(target_os = "macos")]
pub fn extend_allocated(fd: BorrowedFd<'_>, offset: u64, len: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if len == 0 {
        return Err(Errno::INVAL.into());
    }
    let end = offset
        .checked_add(len)
        .and_then(|e| i64::try_from(e).ok())
        .ok_or(Errno::FBIG)?;
    let cur = rustix::fs::fstat(fd)?.st_size;
    if end <= cur {
        return Ok(());
    }
    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATEALL,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: end - cur,
        fst_bytesalloc: 0,
    };
    // SAFETY: store is a valid fstore_t for the call and fd is open.
    let r = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_PREALLOCATE, &raw mut store) };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(rustix::fs::ftruncate(fd, end.unsigned_abs())?)
}

// rustix has no mknodat on apple targets; mode carries the file type bits
#[cfg(target_os = "macos")]
pub fn mknod_at(dir: BorrowedFd<'_>, name: &str, mode: u32) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    check_component(name)?;
    let n = CString::new(name).map_err(|_| invalid("nul in name"))?;
    // SAFETY: the name is a valid nul-terminated string and dir is open for the call.
    let r = unsafe { libc::mknodat(dir.as_raw_fd(), n.as_ptr(), mode as libc::mode_t, 0) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// lowers the calling thread alone; the rest of the process keeps its priority
#[cfg(target_os = "macos")]
pub fn lower_thread_priority() {
    // SAFETY: the call only changes the scheduling class of the calling thread.
    let _ = unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0) };
}

// nice 10 and the lowest best-effort io level for the calling thread alone; both are best effort
#[cfg(target_os = "linux")]
pub fn lower_thread_priority() {
    const NICE: i32 = 10;
    const IOPRIO_WHO_PROCESS: libc::c_long = 1;
    const IOPRIO_CLASS_BE: libc::c_long = 2;
    const IOPRIO_CLASS_SHIFT: u32 = 13;
    const IOPRIO_LOWEST: libc::c_long = 7;
    let tid = rustix::thread::gettid();
    let _ = rustix::process::setpriority_process(Some(tid), NICE);
    let prio = (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | IOPRIO_LOWEST;
    // SAFETY: ioprio_set takes three plain integers and only changes the io priority of the thread named by tid.
    let _ = unsafe {
        libc::syscall(
            libc::SYS_ioprio_set,
            IOPRIO_WHO_PROCESS,
            libc::c_long::from(tid.as_raw_pid()),
            prio,
        )
    };
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn lower_thread_priority() {}

// (case_fold, norm_fold) of the volume holding dir, learned from an internal probe name that is removed again
pub fn probe_fold(dir: BorrowedFd<'_>) -> io::Result<(bool, bool)> {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|_| io::Error::other("system random source failed"))?;
    let name = format!("{TMP_PREFIX}fold{:016x}\u{e9}", u64::from_le_bytes(r));
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    drop(rustix::fs::openat(
        dir,
        name.as_str(),
        flags,
        Mode::from_bits_truncate(0o600),
    )?);
    let case = stat_key_at(dir, &name.to_uppercase()).is_ok();
    let norm = stat_key_at(dir, &name.replace('\u{e9}', "e\u{301}")).is_ok();
    let _ = rustix::fs::unlinkat(dir, name.as_str(), AtFlags::empty());
    Ok((case, norm))
}

pub fn peer_uid(fd: BorrowedFd<'_>) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: cred and len are valid for writes and len holds the exact size of cred.
        let r = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &mut len,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != std::mem::size_of::<libc::ucred>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short SO_PEERCRED reply",
            ));
        }
        Ok(cred.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
        // SAFETY: uid and gid are valid for writes for the duration of the call.
        let r = unsafe { libc::getpeereid(fd.as_raw_fd(), &mut uid, &mut gid) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;
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
            "csync-sys-{tag}-{}-{}",
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
    fn open_beneath_refuses_symlink_escape_and_dotdot() {
        let t = tmp("beneath");
        let outside = tmp("outside");
        fs::create_dir(t.0.join("real")).unwrap();
        fs::write(t.0.join("real/file"), b"ok").unwrap();
        fs::write(outside.0.join("secret"), b"no").unwrap();
        symlink(t.0.join("real"), t.0.join("dirlink")).unwrap();
        symlink(outside.0.join("secret"), t.0.join("esc")).unwrap();
        symlink(&outside.0, t.0.join("escdir")).unwrap();
        let root = open_dir(&t.0);
        let r = root.as_fd();

        assert!(open_beneath(r, &rel("real/file"), OFlags::RDONLY).is_ok());
        assert!(open_beneath(r, &RelPath::root(), OFlags::RDONLY | OFlags::DIRECTORY).is_ok());
        assert!(open_beneath(r, &rel("esc"), OFlags::RDONLY).is_err());
        assert!(open_beneath(r, &rel("escdir/secret"), OFlags::RDONLY).is_err());
        assert!(open_beneath(r, &rel("dirlink/file"), OFlags::RDONLY).is_err());
        assert!(open_beneath(r, &rel("escdir"), OFlags::RDONLY | OFlags::DIRECTORY).is_err());

        assert!(open_walk(r, "real/file", OFlags::RDONLY, Mode::empty()).is_ok());
        assert!(open_walk(r, "escdir/secret", OFlags::RDONLY, Mode::empty()).is_err());
        assert!(open_walk(r, "dirlink/file", OFlags::RDONLY, Mode::empty()).is_err());
        assert!(open_walk(r, "esc", OFlags::RDONLY, Mode::empty()).is_err());
        for bad in [
            "../x",
            "real/../real/file",
            "/etc/passwd",
            "real//file",
            "./real/file",
            "real/.",
        ] {
            let e = open_walk(r, bad, OFlags::RDONLY, Mode::empty()).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad}");
        }
    }

    #[test]
    fn peer_uid_reports_own_uid() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let me = rustix::process::geteuid().as_raw();
        assert_eq!(peer_uid(a.as_fd()).unwrap(), me);
        assert_eq!(peer_uid(b.as_fd()).unwrap(), me);
        let f = fs::File::open(std::env::temp_dir()).unwrap();
        assert!(peer_uid(f.as_fd()).is_err());
    }

    #[test]
    fn exchange_swaps_atomically() {
        let t = tmp("xchg");
        fs::write(t.0.join("a"), b"AAA").unwrap();
        fs::write(t.0.join("b"), b"B").unwrap();
        let d = open_dir(&t.0);
        exchange(d.as_fd(), "a", "b").unwrap();
        assert_eq!(fs::read(t.0.join("a")).unwrap(), b"B");
        assert_eq!(fs::read(t.0.join("b")).unwrap(), b"AAA");
        assert!(exchange(d.as_fd(), "a", "../b").is_err());
        assert!(exchange(d.as_fd(), "a", "missing").is_err());
        assert_eq!(fs::read(t.0.join("a")).unwrap(), b"B");
    }

    #[test]
    fn exchange_checked_commits_or_rolls_back() {
        let t = tmp("cas");
        let d = open_dir(&t.0);
        fs::write(t.0.join("dest"), b"old").unwrap();
        fs::write(t.0.join("tmp1"), b"new").unwrap();
        let old = rustix::fs::openat(
            d.as_fd(),
            "dest",
            OFlags::RDONLY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let k1 = stat_key(old.as_fd()).unwrap();
        assert_eq!(
            exchange_checked(d.as_fd(), "tmp1", "dest", old.as_fd(), &k1).unwrap(),
            Swap::Committed
        );
        assert_eq!(fs::read(t.0.join("dest")).unwrap(), b"new");
        assert!(!t.0.join("tmp1").exists());

        fs::write(t.0.join("tmp2"), b"mine").unwrap();
        let old = rustix::fs::openat(
            d.as_fd(),
            "dest",
            OFlags::RDWR | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let k1 = stat_key(old.as_fd()).unwrap();
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(t.0.join("dest"))
            .unwrap();
        f.write_all(b" plus a host write").unwrap();
        drop(f);
        assert_eq!(
            exchange_checked(d.as_fd(), "tmp2", "dest", old.as_fd(), &k1).unwrap(),
            Swap::Raced
        );
        assert_eq!(
            fs::read(t.0.join("dest")).unwrap(),
            b"new plus a host write"
        );
        assert!(!t.0.join("tmp2").exists());
    }

    #[test]
    fn clone_and_copy_match_source() {
        let t = tmp("clone");
        let data: Vec<u8> = (0..(3 * COPY_BUF + 17)).map(|i| (i % 251) as u8).collect();
        fs::write(t.0.join("src"), &data).unwrap();
        fs::write(t.0.join("dst"), vec![9u8; 5 * COPY_BUF]).unwrap();
        let d = open_dir(&t.0);
        let s = rustix::fs::openat(d.as_fd(), "src", OFlags::RDONLY, Mode::empty()).unwrap();
        let o = rustix::fs::openat(d.as_fd(), "dst", OFlags::RDWR, Mode::empty()).unwrap();
        clone_or_copy(s.as_fd(), o.as_fd()).unwrap();
        assert_eq!(fs::read(t.0.join("dst")).unwrap(), data);
        clone_at(d.as_fd(), "src", d.as_fd(), "dst2").unwrap();
        assert_eq!(fs::read(t.0.join("dst2")).unwrap(), data);
        assert!(clone_at(d.as_fd(), "src", d.as_fd(), "dst2").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rename_noreplace_refuses_an_existing_target() {
        let t = tmp("noreplace");
        fs::write(t.0.join("from"), b"new").unwrap();
        fs::write(t.0.join("to"), b"old").unwrap();
        let d = open_dir(&t.0);
        let e = rename_noreplace(d.as_fd(), "from", "to").unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EEXIST));
        assert_eq!(fs::read(t.0.join("to")).unwrap(), b"old");
        assert_eq!(fs::read(t.0.join("from")).unwrap(), b"new");
        rename_noreplace(d.as_fd(), "from", "fresh").unwrap();
        assert_eq!(fs::read(t.0.join("fresh")).unwrap(), b"new");
        assert!(!t.0.join("from").exists());
        assert!(rename_noreplace(d.as_fd(), "fresh", "../x").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn clone_fd_at_isolates_the_clone_from_the_source() {
        let t = tmp("clonefd");
        fs::write(t.0.join("src"), b"original bytes").unwrap();
        let d = open_dir(&t.0);
        let s = rustix::fs::openat(d.as_fd(), "src", OFlags::RDWR, Mode::empty()).unwrap();
        clone_fd_at(s.as_fd(), d.as_fd(), "copy").unwrap();
        assert_eq!(fs::read(t.0.join("copy")).unwrap(), b"original bytes");
        rustix::io::pwrite(&s, b"CHANGED", 0).unwrap();
        assert_eq!(fs::read(t.0.join("copy")).unwrap(), b"original bytes");
        assert!(clone_fd_at(s.as_fd(), d.as_fd(), "copy").is_err());
        assert!(clone_fd_at(s.as_fd(), d.as_fd(), "../escape").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn extend_allocated_grows_and_never_shrinks() {
        let t = tmp("alloc");
        fs::write(t.0.join("f"), b"0123456789").unwrap();
        let d = open_dir(&t.0);
        let f = rustix::fs::openat(d.as_fd(), "f", OFlags::RDWR, Mode::empty()).unwrap();
        extend_allocated(f.as_fd(), 0, 3 * 4096).unwrap();
        assert_eq!(stat_key(f.as_fd()).unwrap().size, 3 * 4096);
        extend_allocated(f.as_fd(), 0, 100).unwrap();
        assert_eq!(stat_key(f.as_fd()).unwrap().size, 3 * 4096);
        extend_allocated(f.as_fd(), 4096, 3 * 4096).unwrap();
        assert_eq!(stat_key(f.as_fd()).unwrap().size, 4 * 4096);
        let e = extend_allocated(f.as_fd(), 0, 0).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
        let e = extend_allocated(f.as_fd(), u64::MAX, 2).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EFBIG));
        assert_eq!(fs::read(t.0.join("f")).unwrap()[..10], *b"0123456789");
    }
}
