use super::Core;
use crate::ignore::repo::run_git;
use crate::proto::{RelPath, Seq};
use crate::sys;
use crate::tui::diff::{DIFF_SIDE_MAX, DiffSource, Side, Sides};
use crate::tui::feed::{By, Entry, FEED_MAX, What};
use rustix::fs::OFlags;
use std::{
    fs::{self, File},
    io::{self, Read},
    os::fd::{AsFd, BorrowedFd},
    path::{Path, PathBuf},
    sync::{Arc, Weak},
};

const LABEL_HEAD: &str = "working tree vs git HEAD";
const LABEL_NEW: &str = "new file";
const LABEL_NONE: &str = "no diff";
const NOT_GIT: &str = "the host keeps no earlier version (not a git repository)";
const CHANGED_AGAIN: &str = "file changed again since this event";

// the host keeps no history of its own, so the only earlier version is the one in git HEAD
pub(crate) struct HostPeek {
    core: Weak<Core>,
}

impl HostPeek {
    pub(crate) fn new(core: &Arc<Core>) -> Self {
        Self {
            core: Arc::downgrade(core),
        }
    }
}

impl DiffSource for HostPeek {
    fn sides(&self, e: &Entry) -> Sides {
        let Some(core) = self.core.upgrade() else {
            return unavailable("the host has stopped");
        };
        if let Some(why) = no_diff_reason(e.what) {
            return unavailable(why);
        }
        let current = core.tree().get(&e.path).map(|en| en.seq);
        sides_for(core.root.as_fd(), &core.root_path, e, current)
    }
}

// why a row of this kind has no content to compare, shared with the guest adapter
pub(crate) fn no_diff_reason(what: What) -> Option<&'static str> {
    match what {
        What::Added | What::Modified | What::Changed | What::Removed => None,
        What::Renamed => Some("renamed; contents not changed by this event"),
        What::DirAdded | What::DirRemoved => Some("a directory has no text to compare"),
        What::Link => Some("a symlink has no text to compare"),
        What::Burst(_) => Some("several changes were folded into one row"),
        What::Notice(_) => Some("notice only"),
    }
}

// how many of len rows are left out so that the rest plus one Burst row fill the feed exactly
pub(crate) fn rows_dropped(len: usize) -> usize {
    if len > FEED_MAX {
        len - (FEED_MAX - 1)
    } else {
        0
    }
}

// the row that stands for dropped ones, last in its batch like the feed's own
pub(crate) fn burst_entry(dropped: usize, ts_ms: u64, by: &By, ver: Seq) -> Entry {
    Entry {
        id: 0,
        ts_ms,
        what: What::Burst(u32::try_from(dropped).unwrap_or(u32::MAX)),
        by: by.clone(),
        path: RelPath::root(),
        from: None,
        size: 0,
        old: None,
        new: None,
        ver,
        merged: false,
    }
}

pub(crate) fn unavailable(why: &'static str) -> Sides {
    Sides {
        label: LABEL_NONE,
        old: Side::Gone(why),
        new: Side::Gone(why),
        note: None,
    }
}

// the nearest directory that still exists, and the rest of the path relative to it
fn git_anchor(root_path: &Path, path: &RelPath) -> (PathBuf, String) {
    let full = path.as_str();
    for (i, _) in full.match_indices('/').rev() {
        let abs = root_path.join(&full[..i]);
        if fs::symlink_metadata(&abs).is_ok_and(|m| m.is_dir()) {
            return (abs, full[i + 1..].to_owned());
        }
    }
    (root_path.to_path_buf(), full.to_owned())
}

fn in_repo(dir: &Path) -> Result<bool, &'static str> {
    match run_git(dir, &["rev-parse", "--is-inside-work-tree"], 16) {
        Ok((0, out)) => Ok(out.trim_ascii() == b"true"),
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err("git is not installed on the host"),
        Err(_) => Err("git could not be run on the host"),
    }
}

// cat-file only: git diff would honour textconv, external diff and fsmonitor settings from the repository
fn head_side(dir: &Path, rest: &str) -> Side {
    let spec = format!("HEAD:./{rest}");
    match run_git(dir, &["cat-file", "blob", &spec], DIFF_SIDE_MAX + 1) {
        Ok((0, bytes)) => Side::Bytes(bytes),
        Ok((128, _)) => Side::Absent,
        Ok(_) => Side::Gone("git could not read this file from HEAD"),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            Side::Gone("the version in git HEAD is over 1 MiB: too large to diff")
        }
        Err(_) => Side::Gone("git could not be run on the host"),
    }
}

// a regular file under the root, never through a symlink, at most one byte past the cap
fn work_side(root: BorrowedFd<'_>, path: &RelPath) -> Side {
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match sys::open_beneath(root, path, flags) {
        Ok(fd) => fd,
        Err(e) => {
            return match e.raw_os_error() {
                Some(libc::ENOENT | libc::ENOTDIR) => Side::Absent,
                Some(libc::ELOOP | libc::EMLINK) => Side::Gone("a symlink now: it is not followed"),
                _ => Side::Gone("the file could not be opened"),
            };
        }
    };
    let file = File::from(fd);
    match file.metadata() {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Side::Gone("not a regular file now"),
        Err(_) => return Side::Gone("the file could not be read"),
    }
    let mut buf = Vec::new();
    match file.take(DIFF_SIDE_MAX as u64 + 1).read_to_end(&mut buf) {
        Ok(_) => Side::Bytes(buf),
        Err(_) => Side::Gone("the file could not be read"),
    }
}

// current is the index seq of the path now; it is what tells whether the file moved on since the event
pub(crate) fn sides_for(
    root: BorrowedFd<'_>,
    root_path: &Path,
    e: &Entry,
    current: Option<Seq>,
) -> Sides {
    if let Some(why) = no_diff_reason(e.what) {
        return unavailable(why);
    }
    let (dir, rest) = git_anchor(root_path, &e.path);
    match in_repo(&dir) {
        Ok(true) => {}
        Ok(false) => return unavailable(NOT_GIT),
        Err(why) => return unavailable(why),
    }
    let old = head_side(&dir, &rest);
    let new = work_side(root, &e.path);
    let moved = e.ver != 0
        && if e.what == What::Removed {
            current.is_some()
        } else {
            current != Some(e.ver)
        };
    let label = if old == Side::Absent && matches!(new, Side::Bytes(_)) {
        LABEL_NEW
    } else {
        LABEL_HEAD
    };
    Sides {
        label,
        old,
        new,
        note: moved.then_some(CHANGED_AGAIN),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::NoticeKind;
    use rustix::fs::Mode;
    use std::process::Command;

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmpdir(tag: &str) -> Tmp {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!(
            "csync-peek-{tag}-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(r)
        ));
        fs::create_dir_all(&p).unwrap();
        Tmp(fs::canonicalize(&p).unwrap())
    }

    fn have_git() -> bool {
        Command::new("git").arg("--version").output().is_ok()
    }

    fn git(dir: &Path, args: &[&str]) {
        let o = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("LC_ALL", "C")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }

    fn commit_all(dir: &Path) {
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-q", "-m", "c"]);
    }

    fn entry(path: &str, what: What) -> Entry {
        Entry {
            id: 1,
            ts_ms: 0,
            what,
            by: By::Host,
            path: RelPath::new(path).unwrap(),
            from: None,
            size: 0,
            old: None,
            new: None,
            ver: 5,
            merged: false,
        }
    }

    fn peek(root: &Path, e: &Entry, current: Option<Seq>) -> Sides {
        let fd = rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        sides_for(fd.as_fd(), root, e, current)
    }

    fn bytes(s: &str) -> Side {
        Side::Bytes(s.as_bytes().to_vec())
    }

    #[test]
    fn a_modified_tracked_file_is_compared_with_head() {
        if !have_git() {
            return;
        }
        let t = tmpdir("modified");
        git(&t.0, &["init", "-q"]);
        fs::write(t.0.join("a.txt"), "one\n").unwrap();
        commit_all(&t.0);
        fs::write(t.0.join("a.txt"), "two\n").unwrap();
        let s = peek(&t.0, &entry("a.txt", What::Modified), Some(5));
        assert_eq!(s.label, "working tree vs git HEAD");
        assert_eq!(s.old, bytes("one\n"));
        assert_eq!(s.new, bytes("two\n"));
        assert_eq!(s.note, None);
    }

    #[test]
    fn a_file_in_a_subdirectory_is_found_relative_to_its_parent() {
        if !have_git() {
            return;
        }
        let t = tmpdir("subdir");
        git(&t.0, &["init", "-q"]);
        fs::create_dir_all(t.0.join("d/e")).unwrap();
        fs::write(t.0.join("d/e/f.txt"), "one\n").unwrap();
        commit_all(&t.0);
        fs::write(t.0.join("d/e/f.txt"), "two\n").unwrap();
        let s = peek(&t.0, &entry("d/e/f.txt", What::Modified), Some(5));
        assert_eq!(s.old, bytes("one\n"));
        assert_eq!(s.new, bytes("two\n"));
    }

    #[test]
    fn an_untracked_file_has_no_old_side() {
        if !have_git() {
            return;
        }
        let t = tmpdir("untracked");
        git(&t.0, &["init", "-q"]);
        fs::write(t.0.join("kept"), "x\n").unwrap();
        commit_all(&t.0);
        fs::write(t.0.join("fresh.txt"), "new\n").unwrap();
        let s = peek(&t.0, &entry("fresh.txt", What::Added), Some(5));
        assert_eq!(s.label, "new file");
        assert_eq!(s.old, Side::Absent);
        assert_eq!(s.new, bytes("new\n"));
    }

    #[test]
    fn an_unborn_head_has_no_old_side() {
        if !have_git() {
            return;
        }
        let t = tmpdir("unborn");
        git(&t.0, &["init", "-q"]);
        fs::write(t.0.join("a.txt"), "one\n").unwrap();
        let s = peek(&t.0, &entry("a.txt", What::Modified), Some(5));
        assert_eq!(s.old, Side::Absent);
        assert_eq!(s.new, bytes("one\n"));
    }

    #[test]
    fn a_removed_file_shows_its_head_version_against_nothing() {
        if !have_git() {
            return;
        }
        let t = tmpdir("removed");
        git(&t.0, &["init", "-q"]);
        fs::write(t.0.join("a.txt"), "one\n").unwrap();
        commit_all(&t.0);
        fs::remove_file(t.0.join("a.txt")).unwrap();
        let s = peek(&t.0, &entry("a.txt", What::Removed), None);
        assert_eq!(s.label, "working tree vs git HEAD");
        assert_eq!(s.old, bytes("one\n"));
        assert_eq!(s.new, Side::Absent);
        assert_eq!(s.note, None);
    }

    #[test]
    fn a_file_in_a_removed_directory_is_still_found_in_head() {
        if !have_git() {
            return;
        }
        let t = tmpdir("gonedir");
        git(&t.0, &["init", "-q"]);
        fs::create_dir_all(t.0.join("d/e")).unwrap();
        fs::write(t.0.join("d/e/f.txt"), "one\n").unwrap();
        commit_all(&t.0);
        fs::remove_dir_all(t.0.join("d")).unwrap();
        let s = peek(&t.0, &entry("d/e/f.txt", What::Removed), None);
        assert_eq!(s.old, bytes("one\n"));
        assert_eq!(s.new, Side::Absent);
    }

    #[test]
    fn a_directory_that_is_not_a_repository_has_no_earlier_version() {
        if !have_git() {
            return;
        }
        let t = tmpdir("nogit");
        fs::write(t.0.join("a.txt"), "one\n").unwrap();
        let s = peek(&t.0, &entry("a.txt", What::Modified), Some(5));
        assert_eq!(s.old, Side::Gone(NOT_GIT));
        assert_eq!(s.new, Side::Gone(NOT_GIT));
    }

    #[test]
    fn a_changed_index_seq_adds_the_changed_again_note() {
        if !have_git() {
            return;
        }
        let t = tmpdir("note");
        git(&t.0, &["init", "-q"]);
        fs::write(t.0.join("a.txt"), "one\n").unwrap();
        let e = entry("a.txt", What::Modified);
        assert_eq!(peek(&t.0, &e, Some(5)).note, None);
        assert_eq!(peek(&t.0, &e, Some(9)).note, Some(CHANGED_AGAIN));
        assert_eq!(peek(&t.0, &e, None).note, Some(CHANGED_AGAIN));
        let mut gone = entry("a.txt", What::Removed);
        gone.ver = 5;
        assert_eq!(peek(&t.0, &gone, Some(9)).note, Some(CHANGED_AGAIN));
        let mut unknown = entry("a.txt", What::Modified);
        unknown.ver = 0;
        assert_eq!(peek(&t.0, &unknown, Some(9)).note, None);
    }

    #[test]
    fn a_fifo_is_rejected_without_blocking() {
        if !have_git() {
            return;
        }
        let t = tmpdir("fifo");
        git(&t.0, &["init", "-q"]);
        let made = Command::new("mkfifo").arg(t.0.join("pipe")).status();
        if !made.is_ok_and(|s| s.success()) {
            return;
        }
        let s = peek(&t.0, &entry("pipe", What::Modified), Some(5));
        assert!(matches!(s.new, Side::Gone(_)), "{:?}", s.new);
    }

    #[test]
    fn a_symlink_is_rejected_not_followed() {
        if !have_git() {
            return;
        }
        let t = tmpdir("link");
        git(&t.0, &["init", "-q"]);
        fs::write(t.0.join("real"), "secret\n").unwrap();
        std::os::unix::fs::symlink("real", t.0.join("link")).unwrap();
        let s = peek(&t.0, &entry("link", What::Modified), Some(5));
        assert!(matches!(s.new, Side::Gone(_)), "{:?}", s.new);
    }

    #[test]
    fn a_directory_where_a_file_was_is_rejected() {
        if !have_git() {
            return;
        }
        let t = tmpdir("dirnow");
        git(&t.0, &["init", "-q"]);
        fs::create_dir(t.0.join("was_file")).unwrap();
        let s = peek(&t.0, &entry("was_file", What::Modified), Some(5));
        assert!(matches!(s.new, Side::Gone(_)), "{:?}", s.new);
    }

    #[test]
    fn a_working_tree_file_over_the_cap_is_read_one_byte_past_it() {
        if !have_git() {
            return;
        }
        let t = tmpdir("big");
        git(&t.0, &["init", "-q"]);
        fs::write(t.0.join("big.txt"), vec![b'a'; DIFF_SIDE_MAX + 100]).unwrap();
        let s = peek(&t.0, &entry("big.txt", What::Modified), Some(5));
        match s.new {
            Side::Bytes(b) => assert_eq!(b.len(), DIFF_SIDE_MAX + 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_head_version_over_the_cap_is_not_read_in_full() {
        if !have_git() {
            return;
        }
        let t = tmpdir("bighead");
        git(&t.0, &["init", "-q"]);
        fs::write(t.0.join("big.txt"), vec![b'a'; DIFF_SIDE_MAX + 100]).unwrap();
        commit_all(&t.0);
        let s = peek(&t.0, &entry("big.txt", What::Modified), Some(5));
        assert!(matches!(s.old, Side::Gone(_)), "{:?}", s.old);
    }

    #[test]
    fn kinds_without_content_are_unavailable_without_touching_git() {
        let t = tmpdir("kinds");
        for what in [
            What::Renamed,
            What::DirAdded,
            What::DirRemoved,
            What::Link,
            What::Burst(3),
            What::Notice(NoticeKind::Refused),
        ] {
            let s = peek(&t.0, &entry("a", what), Some(5));
            assert_eq!(s.label, "no diff");
            assert!(matches!(s.old, Side::Gone(_)), "{what:?}");
            assert!(matches!(s.new, Side::Gone(_)), "{what:?}");
        }
    }

    #[test]
    fn the_anchor_is_the_nearest_directory_that_exists() {
        let t = tmpdir("anchor");
        fs::create_dir_all(t.0.join("d")).unwrap();
        let p = RelPath::new("d/e/f.txt").unwrap();
        assert_eq!(git_anchor(&t.0, &p), (t.0.join("d"), "e/f.txt".to_owned()));
        let p = RelPath::new("x/y").unwrap();
        assert_eq!(git_anchor(&t.0, &p), (t.0.clone(), "x/y".to_owned()));
        let p = RelPath::new("top").unwrap();
        assert_eq!(git_anchor(&t.0, &p), (t.0.clone(), "top".to_owned()));
    }
}
