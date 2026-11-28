// removal of one host's local guest state: nothing is followed, locked directories are opened up on the way down
// and anything on another device is left alone
use super::fsops;
use crate::config::{Dirs, write_private};
use crate::crypto::trust::{PeerKey, now_unix};
use rustix::{
    fs::{
        AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, Stat, fchmod, flock, fstat, openat,
        statat, unlinkat,
    },
    io::Errno,
};
use std::{
    ffi::{CStr, CString, OsStr},
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};

pub const MARKER: &str = "session.live";

#[derive(Debug)]
pub struct Failure {
    pub path: PathBuf,
    pub error: io::Error,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub removed: u64,
    // sizes of the regular files removed
    pub bytes: u64,
    pub failures: Vec<Failure>,
    // directories that are mount points or sit on another device, never entered
    pub other_devices: Vec<PathBuf>,
}

impl Summary {
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty() && self.other_devices.is_empty()
    }

    pub fn problem(&self) -> Option<String> {
        if let Some(f) = self.failures.first() {
            return Some(format!("{}: {}", f.path.display(), f.error));
        }
        self.other_devices
            .first()
            .map(|p| format!("{} is on another device and was left alone", p.display()))
    }

    fn merge(&mut self, other: Summary) {
        self.removed += other.removed;
        self.bytes += other.bytes;
        self.failures.extend(other.failures);
        self.other_devices.extend(other.other_devices);
    }
}

// the two directories one host owns on this machine, with the roots they must sit directly under
pub struct HostPaths {
    fpr: String,
    state_root: PathBuf,
    state: PathBuf,
    cache_root: PathBuf,
    cache: PathBuf,
}

impl HostPaths {
    pub fn new(dirs: &Dirs, host: &PeerKey) -> Self {
        Self {
            fpr: host.fpr_hex(),
            state_root: dirs.host_state_root(),
            state: dirs.host_state_dir(host),
            cache_root: dirs.cache.clone(),
            cache: dirs.blob_cache_dir(host),
        }
    }

    pub fn state(&self) -> &Path {
        &self.state
    }

    pub fn cache(&self) -> &Path {
        &self.cache
    }

    // the cache goes first: its directory lock refuses the whole wipe while a csync process still has it open
    pub fn wipe(&self) -> io::Result<Summary> {
        let mut sum = wipe_host_dir(&self.cache_root, &self.fpr, &self.cache)?;
        sum.merge(wipe_host_dir(&self.state_root, &self.fpr, &self.state)?);
        Ok(sum)
    }
}

fn marker_body(pid: u32, started_unix: u64) -> String {
    format!("pid {pid}\nstarted {started_unix}\n")
}

// present for as long as a session owns the state directory; only a wipe removes it
pub fn mark_live(state: &Path) -> io::Result<()> {
    write_private(
        state,
        MARKER,
        marker_body(std::process::id(), now_unix()).as_bytes(),
    )
}

pub fn marker_present(state: &Path) -> bool {
    std::fs::symlink_metadata(state.join(MARKER)).is_ok()
}

// stat field widths differ by platform
#[allow(clippy::unnecessary_cast)]
fn dev_of(st: &Stat) -> u64 {
    st.st_dev as u64
}

// the directory's own permission bits with the owner's rwx added
#[allow(clippy::unnecessary_cast)]
fn perm_of(st: &Stat) -> u32 {
    (st.st_mode as u32 & 0o7777) | 0o700
}

fn same_node(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

pub fn device_of(at: &Path) -> Option<u64> {
    rustix::fs::stat(at).ok().map(|s| dev_of(&s))
}

// whether something is mounted at `at` now that was not there before: `before` is the device under it earlier.
// a path that cannot be inspected counts as mounted, since a dead mount answers with an error
pub fn is_mounted_over(at: &Path, before: Option<u64>) -> bool {
    let own = match rustix::fs::stat(at) {
        Ok(s) => s,
        Err(Errno::NOENT | Errno::NOTDIR) => return false,
        Err(_) => return true,
    };
    match before {
        Some(dev) => dev_of(&own) != dev,
        None => match rustix::fs::stat(at.join("..")) {
            Ok(up) => dev_of(&up) != dev_of(&own),
            Err(_) => true,
        },
    }
}

fn refuse(target: &Path, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("refusing to wipe {}: {why}", target.display()),
    )
}

// only `<root>/<fpr>` is ever removed: a direct child of the root, named exactly the host fingerprint
fn check_target(root: &Path, fpr: &str, target: &Path) -> io::Result<()> {
    if fpr.is_empty() || !fpr.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(refuse(target, "the host fingerprint is not hex"));
    }
    if !root.is_absolute() || !target.is_absolute() {
        return Err(refuse(target, "the paths are not absolute"));
    }
    if root
        .components()
        .chain(target.components())
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(refuse(target, "a path contains .."));
    }
    if target.parent() != Some(root) {
        return Err(refuse(
            target,
            &format!("it is not directly inside {}", root.display()),
        ));
    }
    if target.file_name() != Some(OsStr::new(fpr)) {
        return Err(refuse(target, "its name is not the host fingerprint"));
    }
    Ok(())
}

fn names_in(dir: &OwnedFd) -> io::Result<Vec<CString>> {
    let mut out = Vec::new();
    for e in Dir::read_from(dir)? {
        let e = e?;
        let n = e.file_name();
        if n != c"." && n != c".." {
            out.push(n.to_owned());
        }
    }
    Ok(out)
}

fn file_bytes(st: &Stat) -> u64 {
    if FileType::from_raw_mode(st.st_mode).is_file() {
        u64::try_from(st.st_size).unwrap_or(0)
    } else {
        0
    }
}

struct Walker {
    // the device of the root; a directory on any other one is not entered
    dev: u64,
    rel: PathBuf,
    sum: Summary,
}

impl Walker {
    fn fail(&mut self, error: impl Into<io::Error>) -> bool {
        self.sum.failures.push(Failure {
            path: self.rel.clone(),
            error: error.into(),
        });
        false
    }

    fn unlink(&mut self, parent: &OwnedFd, name: &CStr, flags: AtFlags, bytes: u64) -> bool {
        match unlinkat(parent, name, flags) {
            Ok(()) => {
                self.sum.removed += 1;
                self.sum.bytes += bytes;
                true
            }
            Err(Errno::NOENT) => true,
            Err(e) => self.fail(e),
        }
    }

    // opens a directory without following links, first making it listable and writable for its owner
    fn open_dir(&mut self, parent: &OwnedFd, name: &CStr, st: &Stat) -> Option<OwnedFd> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let opened = match openat(parent, name, flags, Mode::empty()) {
            Err(Errno::ACCESS) => name
                .to_str()
                .map_err(|_| Errno::INVAL)
                .and_then(|n| {
                    fsops::chmod_at(parent.as_fd(), n, perm_of(st))
                        .map_err(Errno::from_raw_os_error)
                })
                .and_then(|()| openat(parent, name, flags, Mode::empty())),
            r => r,
        };
        let fd = match opened {
            Ok(fd) => fd,
            Err(e) => {
                self.fail(e);
                return None;
            }
        };
        let cur = match fstat(&fd) {
            Ok(c) => c,
            Err(e) => {
                self.fail(e);
                return None;
            }
        };
        if !same_node(&cur, st) {
            self.fail(io::Error::other("replaced while it was being wiped"));
            return None;
        }
        let mode = Mode::from_raw_mode(cur.st_mode);
        if mode & Mode::RWXU != Mode::RWXU
            && let Err(e) = fchmod(&fd, mode | Mode::RWXU)
        {
            self.fail(e);
            return None;
        }
        Some(fd)
    }

    // true when the directory is empty afterwards; everything that could not go is recorded and skipped
    fn clear(&mut self, dir: &OwnedFd) -> bool {
        let names = match names_in(dir) {
            Ok(n) => n,
            Err(e) => return self.fail(e),
        };
        let mut empty = true;
        for n in &names {
            empty &= self.entry(dir, n);
        }
        empty
    }

    fn entry(&mut self, parent: &OwnedFd, name: &CStr) -> bool {
        self.rel.push(OsStr::from_bytes(name.to_bytes()));
        let gone = self.entry_inner(parent, name);
        self.rel.pop();
        gone
    }

    fn entry_inner(&mut self, parent: &OwnedFd, name: &CStr) -> bool {
        let st = match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::NOENT) => return true,
            Err(e) => return self.fail(e),
        };
        if !FileType::from_raw_mode(st.st_mode).is_dir() {
            return self.unlink(parent, name, AtFlags::empty(), file_bytes(&st));
        }
        if dev_of(&st) != self.dev {
            self.sum.other_devices.push(self.rel.clone());
            return false;
        }
        let Some(fd) = self.open_dir(parent, name, &st) else {
            return false;
        };
        let empty = self.clear(&fd);
        drop(fd);
        empty && self.unlink(parent, name, AtFlags::REMOVEDIR, 0)
    }
}

// removes `target` (which must be `<root>/<fpr>`) with everything under it. a symlink is deleted as a link and never
// entered. an exclusive lock on the directory is taken first, so a cache another csync process holds is refused
pub fn wipe_host_dir(root: &Path, fpr: &str, target: &Path) -> io::Result<Summary> {
    check_target(root, fpr, target)?;
    let root_fd = match rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(Summary::default()),
        Err(e) => return Err(e.into()),
    };
    let name = CString::new(fpr).map_err(|_| refuse(target, "the host fingerprint is not hex"))?;
    let st = match statat(&root_fd, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Ok(Summary::default()),
        Err(e) => return Err(e.into()),
    };
    let mut w = Walker {
        dev: dev_of(&fstat(&root_fd)?),
        rel: target.to_path_buf(),
        sum: Summary::default(),
    };
    if !FileType::from_raw_mode(st.st_mode).is_dir() {
        w.entry_inner(&root_fd, name.as_c_str());
        return Ok(w.sum);
    }
    if dev_of(&st) != w.dev {
        w.sum.other_devices.push(target.to_path_buf());
        return Ok(w.sum);
    }
    let Some(fd) = w.open_dir(&root_fd, name.as_c_str(), &st) else {
        return Ok(w.sum);
    };
    if let Err(e) = flock(&fd, FlockOperation::NonBlockingLockExclusive) {
        return Err(if e == Errno::WOULDBLOCK {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{} is in use by another csync process", target.display()),
            )
        } else {
            e.into()
        });
    }
    if w.clear(&fd) {
        w.unlink(&root_fd, name.as_c_str(), AtFlags::REMOVEDIR, 0);
    }
    Ok(w.sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU32, Ordering},
    };

    const FPR: &str = "00112233aabbccdd";

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "csync-wipe-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }

        // the root that holds host directories, and the host directory inside it (not created)
        fn host(&self, fpr: &str) -> (PathBuf, PathBuf) {
            let root = self.path("hosts");
            fs::create_dir_all(&root).unwrap();
            let target = root.join(fpr);
            (root, target)
        }
    }

    // a failed test can leave directories nobody may enter
    fn unlock(p: &Path) {
        let Ok(m) = fs::symlink_metadata(p) else {
            return;
        };
        if !m.is_dir() {
            return;
        }
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                unlock(&e.path());
            }
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            unlock(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn put(p: &Path, body: &[u8], mode: u32) {
        fs::write(p, body).unwrap();
        chmod(p, mode);
    }

    fn chmod(p: &Path, mode: u32) {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn gone(p: &Path) -> bool {
        fs::symlink_metadata(p).is_err()
    }

    #[test]
    fn a_nested_tree_with_locked_directories_and_read_only_files_is_removed() {
        let t = Tmp::new();
        let (root, target) = t.host(FPR);
        fs::create_dir_all(target.join("overlay/ro")).unwrap();
        fs::create_dir_all(target.join("overlay/none/deep")).unwrap();
        put(&target.join("overlay/file.txt"), b"hello", 0o444);
        put(&target.join("overlay/ro/inner.txt"), b"inner", 0o444);
        put(&target.join("overlay/none/deep/f.bin"), &[7u8; 100], 0o400);
        put(&target.join("tree.rkyv"), b"abc", 0o600);
        put(&target.join(MARKER), b"live", 0o600);
        chmod(&target.join("overlay/none/deep"), 0o500);
        chmod(&target.join("overlay/none"), 0o000);
        chmod(&target.join("overlay/ro"), 0o555);

        let sum = wipe_host_dir(&root, FPR, &target).unwrap();

        assert!(sum.is_clean(), "{sum:?}");
        // five directories and five files
        assert_eq!(sum.removed, 10);
        assert_eq!(sum.bytes, 5 + 5 + 100 + 3 + 4);
        assert!(gone(&target));
        assert!(root.is_dir());
    }

    #[test]
    fn symlinks_are_deleted_as_links_and_their_targets_survive() {
        let t = Tmp::new();
        let (root, target) = t.host(FPR);
        let outside = t.path("outside");
        fs::create_dir_all(&outside).unwrap();
        put(&outside.join("precious.txt"), b"keep", 0o644);
        fs::create_dir_all(target.join("overlay")).unwrap();
        symlink(&outside, target.join("overlay/dirlink")).unwrap();
        symlink(outside.join("precious.txt"), target.join("filelink")).unwrap();
        symlink("missing", target.join("dangling")).unwrap();

        let sum = wipe_host_dir(&root, FPR, &target).unwrap();

        assert!(sum.is_clean(), "{sum:?}");
        // the host directory, overlay and three links
        assert_eq!(sum.removed, 5);
        assert_eq!(sum.bytes, 0);
        assert!(gone(&target));
        assert_eq!(fs::read(outside.join("precious.txt")).unwrap(), b"keep");
    }

    #[test]
    fn a_symlink_standing_where_the_host_directory_belongs_is_not_followed() {
        let t = Tmp::new();
        let (root, target) = t.host(FPR);
        let outside = t.path("outside");
        fs::create_dir_all(&outside).unwrap();
        put(&outside.join("precious.txt"), b"keep", 0o644);
        symlink(&outside, &target).unwrap();

        let sum = wipe_host_dir(&root, FPR, &target).unwrap();

        assert!(sum.is_clean(), "{sum:?}");
        assert_eq!(sum.removed, 1);
        assert!(gone(&target));
        assert_eq!(fs::read(outside.join("precious.txt")).unwrap(), b"keep");
    }

    #[test]
    fn paths_outside_the_root_or_with_the_wrong_name_are_refused() {
        let t = Tmp::new();
        let (root, target) = t.host(FPR);
        for p in [
            "other/00112233aabbccdd",
            "hosts/00112233aabbccdd/sub",
            "hosts/ffffffffffffffff",
        ] {
            fs::create_dir_all(t.path(p)).unwrap();
            put(&t.path(p).join("keep"), b"x", 0o644);
        }
        let refused = |root: &Path, fpr: &str, target: &Path| {
            let e = wipe_host_dir(root, fpr, target).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{target:?}: {e}");
        };

        refused(&root, FPR, &t.path("other/00112233aabbccdd"));
        refused(&root, FPR, &target.join("sub"));
        refused(&root, FPR, &root.join("ffffffffffffffff"));
        refused(&root, FPR, &root);
        refused(&root, FPR, &root.join("x").join("..").join(FPR));
        refused(&root, "", &root.join(""));
        refused(&root, "../hosts", &root.join("../hosts"));
        refused(&root, "zz", &root.join("zz"));
        refused(Path::new("hosts"), FPR, &Path::new("hosts").join(FPR));

        for p in [
            "other/00112233aabbccdd",
            "hosts/00112233aabbccdd/sub",
            "hosts/ffffffffffffffff",
        ] {
            assert!(t.path(p).join("keep").is_file(), "{p}");
        }
    }

    #[test]
    fn a_directory_that_does_not_exist_is_nothing_to_wipe() {
        let t = Tmp::new();
        let (root, target) = t.host(FPR);
        let sum = wipe_host_dir(&root, FPR, &target).unwrap();
        assert!(sum.is_clean() && sum.removed == 0);
        let sum = wipe_host_dir(&t.path("absent"), FPR, &t.path("absent").join(FPR)).unwrap();
        assert!(sum.is_clean() && sum.removed == 0);
    }

    #[test]
    fn a_directory_another_process_holds_locked_is_refused_untouched() {
        let t = Tmp::new();
        let (root, target) = t.host(FPR);
        fs::create_dir_all(&target).unwrap();
        put(&target.join("keep"), b"x", 0o644);
        let held = rustix::fs::open(
            &target,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        flock(&held, FlockOperation::NonBlockingLockExclusive).unwrap();

        let e = wipe_host_dir(&root, FPR, &target).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock, "{e}");
        assert!(target.join("keep").is_file());

        drop(held);
        let sum = wipe_host_dir(&root, FPR, &target).unwrap();
        assert!(sum.is_clean(), "{sum:?}");
        assert!(gone(&target));
    }

    #[test]
    fn a_directory_on_another_device_is_left_alone_and_reported() {
        let t = Tmp::new();
        let (_, target) = t.host(FPR);
        fs::create_dir_all(target.join("sub")).unwrap();
        put(&target.join("sub/f"), b"x", 0o644);
        put(&target.join("plain"), b"y", 0o644);
        let fd = rustix::fs::open(
            &target,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        // no mount can be made without privileges, so the walk is told every directory sits on another device
        let mut w = Walker {
            dev: dev_of(&fstat(&fd).unwrap()) ^ 1,
            rel: target.clone(),
            sum: Summary::default(),
        };

        assert!(!w.clear(&fd));

        assert!(gone(&target.join("plain")));
        assert!(target.join("sub/f").is_file());
        assert_eq!(w.sum.other_devices, [target.join("sub")]);
        assert!(!w.sum.is_clean());
        assert!(w.sum.problem().unwrap().contains("another device"));
    }

    #[test]
    fn a_failure_is_recorded_and_the_rest_is_still_removed() {
        let t = Tmp::new();
        let (_, target) = t.host(FPR);
        fs::create_dir_all(target.join("a")).unwrap();
        put(&target.join("a/f"), b"x", 0o644);
        put(&target.join("b"), b"y", 0o644);
        let fd = rustix::fs::open(
            &target,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let mut w = Walker {
            dev: dev_of(&fstat(&fd).unwrap()),
            rel: target.clone(),
            sum: Summary::default(),
        };
        // an entry that cannot be statted is recorded, not fatal
        let name = CString::new("a".repeat(300)).unwrap();
        assert!(!w.entry(&fd, &name));
        assert_eq!(w.sum.failures.len(), 1);
        assert!(w.sum.problem().unwrap().contains(&"a".repeat(300)));

        assert!(w.clear(&fd));
        assert!(gone(&target.join("a")) && gone(&target.join("b")));
        assert_eq!(w.sum.failures.len(), 1);
    }

    #[test]
    fn the_marker_names_this_process_and_is_found_until_a_wipe_removes_it() {
        assert_eq!(marker_body(7, 1_700_000_000), "pid 7\nstarted 1700000000\n");
        let t = Tmp::new();
        let (root, target) = t.host(FPR);
        crate::config::ensure_private_dir(&target).unwrap();
        assert!(!marker_present(&target));
        mark_live(&target).unwrap();
        assert!(marker_present(&target));
        let body = fs::read_to_string(target.join(MARKER)).unwrap();
        assert!(
            body.starts_with(&format!("pid {}\n", std::process::id())),
            "{body}"
        );

        wipe_host_dir(&root, FPR, &target).unwrap();
        assert!(!marker_present(&target));
    }

    #[test]
    fn host_paths_wipe_state_and_cache_and_nothing_else() {
        let t = Tmp::new();
        let dirs = Dirs::under(&t.0);
        let key = PeerKey([3; 32]);
        let paths = HostPaths::new(&dirs, &key);
        assert_eq!(paths.state(), dirs.host_state_dir(&key));
        assert_eq!(paths.cache(), dirs.blob_cache_dir(&key));

        crate::config::ensure_private_dir(&paths.state().join("overlay")).unwrap();
        mark_live(paths.state()).unwrap();
        put(&paths.state().join("overlay/work.txt"), b"w", 0o644);
        put(&paths.state().join("tree.rkyv"), b"t", 0o644);
        fs::create_dir_all(paths.cache().join("blobs/ab")).unwrap();
        put(&paths.cache().join("blobs/ab/blob"), b"b", 0o644);

        let other_state = dirs.host_state_root().join("ffffffffffffffff");
        let other_cache = dirs.cache.join("ffffffffffffffff");
        crate::config::ensure_private_dir(&dirs.config).unwrap();
        put(&dirs.config.join("identity"), b"secret", 0o600);
        put(&dirs.config.join("peers"), b"trusted", 0o600);
        for d in [&other_state, &other_cache] {
            fs::create_dir_all(d).unwrap();
            put(&d.join("keep"), b"k", 0o644);
        }

        let sum = paths.wipe().unwrap();

        assert!(sum.is_clean(), "{sum:?}");
        assert!(gone(paths.state()) && gone(paths.cache()));
        assert!(other_state.join("keep").is_file() && other_cache.join("keep").is_file());
        assert_eq!(fs::read(dirs.config.join("identity")).unwrap(), b"secret");
        assert_eq!(fs::read(dirs.config.join("peers")).unwrap(), b"trusted");
        assert!(paths.wipe().unwrap().is_clean());
    }

    #[test]
    fn a_mount_point_is_told_from_a_plain_directory() {
        let t = Tmp::new();
        let dir = t.path("mnt");
        fs::create_dir_all(&dir).unwrap();
        let dev = device_of(&dir).unwrap();
        assert!(!is_mounted_over(&dir, Some(dev)));
        assert!(!is_mounted_over(&dir, None));
        assert!(is_mounted_over(&dir, Some(dev ^ 1)));
        assert!(!is_mounted_over(&t.path("absent"), Some(dev)));
        assert_eq!(device_of(&t.path("absent")), None);
    }
}
