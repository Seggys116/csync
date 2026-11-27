// the macfuse mount: backend choice, finding a csync mount in the mount table, and removing a dead one
use super::{
    fs::{Core, GuestFs, IO_MAX},
    fuse::{Backend, BackgroundSession, MountOpts, mount},
};
use std::{
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

// the longest a macfuse kernel accepts; handler waits scale with file size and can pass it, a mount that stalls that long is dead
const DAEMON_TIMEOUT_S: u32 = 600;
const UNMOUNT_DEADLINE: Duration = Duration::from_secs(10);
const FS_NAMES: [&str; 3] = ["macfuse", "fskit", "osxfuse"];

// tries the fskit backend first and the kernel extension only when that mount fails
pub fn attach(
    core: &Arc<Core>,
    at: &Path,
    volname: &str,
    allow_other: bool,
) -> io::Result<BackgroundSession> {
    let opts = MountOpts {
        volname: volname.to_owned(),
        allow_other,
        daemon_timeout: DAEMON_TIMEOUT_S,
        iosize: IO_MAX,
    };
    let fskit = match mount(GuestFs::new(core.clone()), at, &opts, Backend::FsKit) {
        Ok(bg) => return Ok(bg),
        Err(e) => e,
    };
    match mount(GuestFs::new(core.clone()), at, &opts, Backend::Kext) {
        Ok(bg) => Ok(bg),
        Err(kext) => Err(failure(&fskit, &kext)),
    }
}

fn failure(fskit: &io::Error, kext: &io::Error) -> io::Error {
    io::Error::other(format!(
        "the FSKit mount failed ({fskit}) and so did the kernel extension mount ({kext})"
    ))
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    from: String,
    on: PathBuf,
    fstype: String,
}

// one line of mount(8): `from on /path (fstype, option, ...)`
fn parse_line(l: &str) -> Option<Entry> {
    let (from, rest) = l.split_once(" on ")?;
    let (on, opts) = rest.rsplit_once(" (")?;
    let fstype = opts.trim_end_matches(')').split(',').next()?.trim();
    Some(Entry {
        from: from.to_owned(),
        on: PathBuf::from(on),
        fstype: fstype.to_owned(),
    })
}

fn is_csync(e: &Entry, at: &Path) -> bool {
    let ty = e.fstype.to_ascii_lowercase();
    e.on == at && e.from.starts_with("csync") && FS_NAMES.iter().any(|n| ty.contains(n))
}

// the kernel resolves symlinks in a mount point, so the table names it by its real path; the leaf may be dead
fn real(at: &Path) -> PathBuf {
    match (at.parent(), at.file_name()) {
        (Some(dir), Some(leaf)) => std::fs::canonicalize(dir)
            .map(|d| d.join(leaf))
            .unwrap_or_else(|_| at.to_path_buf()),
        _ => at.to_path_buf(),
    }
}

// mount(8) lists without a per-filesystem call, so a mount whose daemon is gone cannot stall it
fn csync_mounted_at(at: &Path) -> bool {
    let Ok(out) = Command::new("/sbin/mount").stdin(Stdio::null()).output() else {
        return false;
    };
    let at = real(at);
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(parse_line)
        .any(|e| is_csync(&e, &at))
}

fn run_bounded(program: &str, args: &[&OsStr]) -> bool {
    let spawned = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        return false;
    };
    let end = Instant::now() + UNMOUNT_DEADLINE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < end => thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

// true once nothing csync is mounted there any more
pub fn force_unmount(at: &Path) -> bool {
    let path = at.as_os_str();
    run_bounded(
        "diskutil",
        &[OsStr::new("unmount"), OsStr::new("force"), path],
    );
    if !csync_mounted_at(at) {
        return true;
    }
    run_bounded("umount", &[OsStr::new("-f"), path]);
    !csync_mounted_at(at)
}

fn dead(errno: i32) -> bool {
    errno == libc::ENOTCONN || errno == libc::ENXIO
}

// a killed daemon leaves a mount the kernel still lists; statfs reaches the daemon, so a dead answer there proves
// nobody serves it. only a csync mount is ever touched, since ENXIO also means a vanished disk
pub fn clear_stale(at: &Path) {
    if !csync_mounted_at(at) {
        return;
    }
    let gone = std::fs::metadata(at).is_err_and(|e| e.raw_os_error().is_some_and(dead))
        || rustix::fs::statfs(at).is_err_and(|e| dead(e.raw_os_error()));
    if gone {
        force_unmount(at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mount_line_splits_into_source_path_and_type() {
        let e = parse_line(
            "csync@macfuse0 on /private/tmp/proj (macfuse, nodev, nosuid, mounted by me)",
        )
        .unwrap();
        assert_eq!(e.from, "csync@macfuse0");
        assert_eq!(e.on, Path::new("/private/tmp/proj"));
        assert_eq!(e.fstype, "macfuse");
    }

    #[test]
    fn a_path_with_spaces_and_parentheses_stays_whole() {
        let e = parse_line("csync on /Volumes/my proj (x) (fskit, nobrowse)").unwrap();
        assert_eq!(e.on, Path::new("/Volumes/my proj (x)"));
        assert_eq!(e.fstype, "fskit");
    }

    #[test]
    fn lines_that_are_not_mounts_are_skipped() {
        assert!(parse_line("").is_none());
        assert!(parse_line("map auto_home on /System/Volumes/Data/home").is_none());
    }

    #[test]
    fn only_a_csync_fuse_mount_at_the_path_counts() {
        let at = Path::new("/private/tmp/proj");
        let line = |s| parse_line(s).unwrap();
        assert!(is_csync(
            &line("csync@macfuse0 on /private/tmp/proj (macfuse, nodev)"),
            at
        ));
        assert!(is_csync(
            &line("csync on /private/tmp/proj (FSKit, nodev)"),
            at
        ));
        assert!(!is_csync(
            &line("sshfs@macfuse1 on /private/tmp/proj (macfuse)"),
            at
        ));
        assert!(!is_csync(
            &line("csync@macfuse0 on /private/tmp/other (macfuse)"),
            at
        ));
        assert!(!is_csync(
            &line("csync on /private/tmp/proj (apfs, local)"),
            at
        ));
    }

    #[test]
    fn a_mount_point_is_compared_by_its_real_parent() {
        let tmp = std::env::temp_dir();
        let want = std::fs::canonicalize(&tmp)
            .unwrap()
            .join("csync-no-such-mount");
        assert_eq!(real(&tmp.join("csync-no-such-mount")), want);
        assert_eq!(real(Path::new("/")), Path::new("/"));
    }

    #[test]
    fn nothing_is_mounted_at_a_made_up_path() {
        assert!(!csync_mounted_at(Path::new("/csync-no-such-mount-point")));
    }

    #[test]
    fn both_dead_mount_errors_are_recognised() {
        assert!(dead(libc::ENOTCONN) && dead(libc::ENXIO));
        assert!(!dead(libc::ENOENT) && !dead(libc::ETIMEDOUT));
    }

    #[test]
    fn a_failed_pair_of_mounts_names_both_causes() {
        let e = failure(&io::Error::other("one"), &io::Error::other("two"));
        let s = e.to_string();
        assert!(s.contains("FSKit") && s.contains("one") && s.contains("two"));
    }

    #[test]
    fn a_bounded_run_reports_success_failure_and_a_missing_program() {
        assert!(run_bounded("true", &[]));
        assert!(!run_bounded("false", &[]));
        assert!(!run_bounded("csync-no-such-program", &[]));
    }
}
