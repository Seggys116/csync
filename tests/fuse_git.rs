// git on the guest against a live host: the index view that keeps status clean without config, ignore
// edits made on the guest, host git runs that a guest reader must see in order, git read commands over
// packs and loose objects, a read-only .git that refuses every write, and git under host commits

#[test]
fn fuse_git() {
    #[cfg(target_os = "linux")]
    git::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE git test runs on Linux only");
}

#[test]
fn git_read_commands_work_through_the_mount() {
    #[cfg(target_os = "linux")]
    git::read_commands();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE git test runs on Linux only");
}

#[test]
fn git_write_commands_are_refused_and_change_nothing() {
    #[cfg(target_os = "linux")]
    git::write_commands_refused();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE git test runs on Linux only");
}

#[test]
fn git_stays_healthy_while_the_host_commits() {
    #[cfg(target_os = "linux")]
    git::healthy_under_host_commits();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE git test runs on Linux only");
}

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod git {
    use super::common::*;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        io::Read,
        os::unix::{fs::MetadataExt, process::ExitStatusExt},
        path::{Path, PathBuf},
        process::{Command, Output, Stdio},
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    const SYNC: Duration = Duration::from_secs(20);

    fn git_command(dir: &Path, args: &[&str]) -> Command {
        let mut c = Command::new("git");
        c.arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "safe.directory=*",
            ])
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("LC_ALL", "C")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE");
        c
    }

    fn run_git(dir: &Path, args: &[&str]) -> Output {
        git_command(dir, args)
            .output()
            .unwrap_or_else(|e| panic!("git {args:?}: {e}"))
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let o = run_git(dir, args);
        assert!(
            o.status.success(),
            "git {args:?} in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    fn populate(p: &Path) {
        fs::create_dir_all(p.join("src")).unwrap();
        for i in 0..40 {
            fs::write(
                p.join(format!("src/f{i}.rs")),
                format!("pub fn f{i}() {{}}\n"),
            )
            .unwrap();
        }
        fs::write(p.join("README.md"), "hello\n").unwrap();
        fs::write(p.join(".gitignore"), "target/\n").unwrap();
        git(p, &["init", "-q", "-b", "main"]);
        git(p, &["add", "-A"]);
        git(p, &["commit", "-qm", "init"]);
    }

    pub fn run() {
        if bin().is_none() {
            return;
        }
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skip: git is not installed");
            return;
        }
        let mut w = World::new("git", populate);
        let g = w.guest("g");
        let _host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        let m = g.mnt.clone();
        eventually("the repository on the guest", SYNC, || {
            m.join(".git/index").exists()
        });

        index_view(&m, &w.proj);
        own_ignore_edit(&m, &w.proj);
        commits_in_order(&m, &w.proj);
        guest.quit(Duration::from_secs(30));
    }

    fn ls_debug(m: &Path, path: &str) -> (u64, u64) {
        let out = git(m, &["ls-files", "--debug", path]);
        let field = |key: &str| -> u64 {
            out.split_whitespace()
                .skip_while(|w| *w != key)
                .nth(1)
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("no {key} in {out}"))
        };
        (field("ino:"), field("uid:"))
    }

    // the host index records the host's inodes; git on the guest must read the mount's, or it rehashes
    // every file on every status
    fn index_view(m: &Path, proj: &Path) {
        let md = fs::metadata(m.join("src/f3.rs")).unwrap();
        let (ino, uid) = ls_debug(m, "src/f3.rs");
        assert_eq!(
            ino,
            md.ino() & 0xffff_ffff,
            "index inode is the host's, not the mount's"
        );
        assert_eq!(uid, u64::from(md.uid()), "index owner is not the mount's");
        assert_eq!(
            git(m, &["status", "--porcelain"]),
            "",
            "status of a clean tree"
        );
        fs::write(m.join("src/f4.rs"), "pub fn changed() {}\n").unwrap();
        fs::write(proj.join("src/f5.rs"), "pub fn host_changed() {}\n").unwrap();
        eventually("the host edit on the guest", SYNC, || {
            read(&m.join("src/f5.rs")).as_deref() == Some("pub fn host_changed() {}\n")
        });
        let st = git(m, &["status", "--porcelain"]);
        assert_eq!(
            st, " M src/f4.rs\n M src/f5.rs\n",
            "guest status after edits"
        );
        // the host's own index refresh changes the index; the guest view follows it
        git(proj, &["add", "-A"]);
        git(proj, &["commit", "-qm", "edits"]);
        eventually("the host commit on the guest", SYNC, || {
            run_git(m, &["status", "--porcelain"]).stdout.is_empty()
        });
        let md = fs::metadata(m.join("src/f4.rs")).unwrap();
        let (ino, _) = ls_debug(m, "src/f4.rs");
        assert_eq!(ino, md.ino() & 0xffff_ffff, "view after a host commit");
    }

    // a rule the guest writes governs the guest's next file at once, so the file stays on the guest
    fn own_ignore_edit(m: &Path, proj: &Path) {
        for (i, dir) in ["fresh", "src"].iter().enumerate() {
            fs::create_dir_all(m.join(dir)).unwrap();
            let rule = format!("*.tmp{i}\n");
            let name = format!("{dir}/a.tmp{i}");
            fs::write(m.join(format!("{dir}/.gitignore")), &rule).unwrap();
            fs::write(m.join(&name), "scratch\n").unwrap();
            eventually("the rule file on the host", SYNC, || {
                read(&proj.join(format!("{dir}/.gitignore"))).as_deref() == Some(rule.as_str())
            });
            thread::sleep(Duration::from_millis(500));
            assert!(!proj.join(&name).exists(), "{name} reached the host");
            assert_eq!(
                read(&m.join(&name)).as_deref(),
                Some("scratch\n"),
                "{name} vanished from the guest"
            );
            let ci = git(m, &["check-ignore", "-v", &name]);
            assert!(ci.contains(&rule.trim().to_string()), "check-ignore: {ci}");
        }
    }

    // a ref the guest can read names an object the guest can read, through gc and pack-refs too
    fn commits_in_order(m: &Path, proj: &Path) {
        let mut bad = Vec::new();
        for i in 0..40 {
            fs::write(proj.join("README.md"), format!("hello {i}\n")).unwrap();
            git(proj, &["commit", "-qam", &format!("c{i}")]);
            match i % 10 {
                4 => {
                    git(proj, &["pack-refs", "--all", "--prune"]);
                }
                9 => {
                    git(proj, &["gc", "-q", "--prune=now"]);
                }
                _ => {}
            }
            let new = git(proj, &["rev-parse", "HEAD"]).trim().to_owned();
            let end = Instant::now() + SYNC;
            loop {
                let o = run_git(m, &["rev-parse", "-q", "--verify", "refs/heads/main"]);
                if String::from_utf8_lossy(&o.stdout).trim() == new {
                    break;
                }
                assert!(Instant::now() < end, "commit {i} never reached the guest");
                thread::sleep(Duration::from_millis(2));
            }
            for args in [
                &["cat-file", "-t", new.as_str()][..],
                &["log", "--oneline", "-3"][..],
            ] {
                let o = run_git(m, args);
                if !o.status.success() {
                    bad.push(format!(
                        "commit {i}, git {args:?}: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "guest saw a ref before its object: {bad:#?}"
        );
    }

    // git must never print any of these on a healthy repository, whatever the command
    const BAD_OUTPUT: &[&str] = &[
        "corrupt",
        "bad object",
        "bad signature",
        "bad index",
        "inflate",
        "Bus error",
        "missing",
    ];

    // what a refused write says: EROFS as root, EACCES or EPERM when the kernel stops a normal user first
    const REFUSED: &[&str] = &[
        "Read-only",
        "read-only",
        "Permission denied",
        "Operation not permitted",
        "insufficient permission",
    ];

    fn find_bad(text: &str, words: &[&'static str]) -> Option<&'static str> {
        words.iter().copied().find(|w| text.contains(*w))
    }

    fn clip(b: &[u8]) -> String {
        String::from_utf8_lossy(b).chars().take(1500).collect()
    }

    fn describe(o: &Output) -> String {
        format!(
            "exit {:?}, signal {:?}\nstdout: {}\nstderr: {}",
            o.status.code(),
            o.status.signal(),
            clip(&o.stdout),
            clip(&o.stderr)
        )
    }

    // runs git, requires exit 0 and no bad word on stderr (and on stdout unless it carries binary content)
    fn good_with(dir: &Path, args: &[&str], scan_stdout: bool) -> Output {
        let o = run_git(dir, args);
        assert!(
            o.status.success(),
            "git {args:?} in {} failed: {}",
            dir.display(),
            describe(&o)
        );
        let mut text = String::from_utf8_lossy(&o.stderr).into_owned();
        if scan_stdout {
            text.push_str(&String::from_utf8_lossy(&o.stdout));
        }
        if let Some(w) = find_bad(&text, BAD_OUTPUT) {
            panic!(
                "git {args:?} in {} printed {w:?}: {}",
                dir.display(),
                describe(&o)
            );
        }
        o
    }

    fn good(dir: &Path, args: &[&str]) -> Output {
        good_with(dir, args, true)
    }

    fn out(dir: &Path, args: &[&str]) -> String {
        String::from_utf8_lossy(&good(dir, args).stdout).into_owned()
    }

    fn same_as_host(m: &Path, proj: &Path, args: &[&str]) -> String {
        let on_guest = out(m, args);
        let on_host = out(proj, args);
        assert_eq!(
            on_guest, on_host,
            "git {args:?} differs between the guest and the host"
        );
        on_guest
    }

    fn ready() -> bool {
        if bin().is_none() {
            return false;
        }
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skip: git is not installed");
            return false;
        }
        true
    }

    // fields drop in order: the guest process goes first, then the host, then the world with its unmounts
    struct Rig {
        guest: Proc,
        _host: Proc,
        w: World,
        m: PathBuf,
    }

    fn rig(tag: &str, populate: impl FnOnce(&Path)) -> Rig {
        let mut w = World::new(tag, populate);
        let g = w.guest("g");
        let host = w.spawn_host();
        let guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        let m = g.mnt.clone();
        eventually("the repository on the guest", SYNC, || {
            m.join(".git/index").exists()
        });
        Rig {
            guest,
            _host: host,
            w,
            m,
        }
    }

    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut rng = Rng::new(seed);
        let mut v = Vec::with_capacity(len + 8);
        while v.len() < len {
            v.extend_from_slice(&rng.next().to_le_bytes());
        }
        v.truncate(len);
        v
    }

    const BIG: usize = 200_000;

    // two branches, a lightweight and an annotated tag, a file above the eager-fetch size, a binary file,
    // a nested directory, packs from a gc and loose objects from the commit after it
    fn read_fixture(p: &Path) {
        fs::create_dir_all(p.join("src/nested/deep")).unwrap();
        fs::create_dir_all(p.join("data")).unwrap();
        let big = noise(7, BIG);
        let mut blob = vec![0u8, 1, 2, 0, 255, 254, 0, 0];
        blob.extend(noise(9, 3000));
        fs::write(p.join("README.md"), "hello world\n").unwrap();
        fs::write(p.join(".gitignore"), "target/\n").unwrap();
        fs::write(p.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(p.join("src/nested/deep/mod.rs"), "pub fn deep() {}\n").unwrap();
        fs::write(p.join("data/big.bin"), &big).unwrap();
        fs::write(p.join("data/blob.bin"), &blob).unwrap();
        git(p, &["init", "-q", "-b", "main"]);
        git(p, &["add", "-A"]);
        git(p, &["commit", "-qm", "init"]);
        git(p, &["tag", "v0.1"]);
        fs::write(
            p.join("README.md"),
            "hello world\nthe needle-word is here\n",
        )
        .unwrap();
        fs::write(p.join("src/main.rs"), "fn main() { println!(\"two\"); }\n").unwrap();
        git(p, &["commit", "-qam", "second"]);
        git(p, &["tag", "-a", "v1.0", "-m", "release"]);
        git(p, &["checkout", "-q", "-b", "feature"]);
        let mut big2 = big;
        for b in &mut big2[1000..2000] {
            *b ^= 0xff;
        }
        fs::write(p.join("data/big.bin"), &big2).unwrap();
        fs::write(p.join("src/feature.rs"), "pub fn feature() {}\n").unwrap();
        git(p, &["add", "-A"]);
        git(p, &["commit", "-qm", "feature work"]);
        git(p, &["checkout", "-q", "main"]);
        fs::write(p.join("src/nested/deep/mod.rs"), "pub fn deep() { 1 }\n").unwrap();
        git(p, &["commit", "-qam", "main work"]);
        git(p, &["gc", "-q"]);
        fs::write(p.join("after_gc.txt"), "after gc\n").unwrap();
        fs::write(
            p.join("README.md"),
            "hello world\nthe needle-word is here\nlast line\n",
        )
        .unwrap();
        git(p, &["add", "-A"]);
        git(p, &["commit", "-qm", "after gc"]);
    }

    // the entries of an uncompressed tar stream: name and size of every regular file
    fn tar_files(tar: &[u8]) -> Vec<(String, usize)> {
        let mut found = Vec::new();
        let mut at = 0;
        while at + 512 <= tar.len() {
            let h = &tar[at..at + 512];
            if h.iter().all(|b| *b == 0) {
                break;
            }
            let end = h[..100].iter().position(|b| *b == 0).unwrap_or(100);
            let name = String::from_utf8_lossy(&h[..end]).into_owned();
            let size_text = String::from_utf8_lossy(&h[124..136]).into_owned();
            let size =
                usize::from_str_radix(size_text.trim_matches(|c: char| c == '\0' || c == ' '), 8)
                    .unwrap_or_else(|e| panic!("tar size {size_text:?} of {name}: {e}"));
            if h[156] == b'0' || h[156] == 0 {
                found.push((name, size));
            }
            at += 512 + size.div_ceil(512) * 512;
        }
        found
    }

    fn count_field(text: &str, key: &str) -> u64 {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("no {key:?} in {text}"))
    }

    pub fn read_commands() {
        if !ready() {
            return;
        }
        let mut rig = rig("gitread", read_fixture);
        let (m, proj) = (rig.m.clone(), rig.w.proj.clone());
        let paths = [
            ".gitignore",
            "README.md",
            "after_gc.txt",
            "data/big.bin",
            "data/blob.bin",
            "src/main.rs",
            "src/nested/deep/mod.rs",
        ];

        assert_eq!(
            out(&m, &["status", "--porcelain"]),
            "",
            "status of a clean tree"
        );

        let subjects = out(&m, &["log", "--format=%s"]);
        assert_eq!(
            subjects.lines().collect::<Vec<_>>(),
            ["after gc", "main work", "second", "init"],
            "log subjects"
        );
        let oneline = out(&m, &["log", "--oneline"]);
        assert_eq!(oneline.lines().count(), 4, "log --oneline: {oneline}");

        let show = same_as_host(&m, &proj, &["show", "HEAD", "--stat"]);
        assert!(
            show.contains("after gc")
                && show.contains("after_gc.txt")
                && show.contains("README.md"),
            "show HEAD --stat: {show}"
        );
        let stat = same_as_host(&m, &proj, &["diff", "HEAD~1", "--stat"]);
        assert!(
            stat.contains("after_gc.txt")
                && stat.contains("README.md")
                && stat.contains("2 files changed"),
            "diff HEAD~1 --stat: {stat}"
        );

        let listed = out(&m, &["ls-files"]);
        assert_eq!(listed.lines().collect::<Vec<_>>(), paths, "ls-files");
        let tree = same_as_host(&m, &proj, &["ls-tree", "-r", "HEAD"]);
        let tree_paths: Vec<&str> = tree.lines().filter_map(|l| l.split('\t').nth(1)).collect();
        assert_eq!(tree_paths, paths, "ls-tree -r HEAD: {tree}");
        assert!(
            tree.lines().all(|l| l.starts_with("100644 blob ")),
            "ls-tree modes: {tree}"
        );

        let commit = same_as_host(&m, &proj, &["cat-file", "-p", "HEAD"]);
        assert!(
            commit.starts_with("tree ")
                && commit.contains("\nparent ")
                && commit.contains("after gc"),
            "cat-file -p HEAD: {commit}"
        );
        for file in ["data/big.bin", "data/blob.bin"] {
            let spec = format!("HEAD:{file}");
            let o = good_with(&m, &["cat-file", "-p", &spec], false);
            assert!(
                o.stdout == fs::read(proj.join(file)).unwrap(),
                "cat-file -p {spec} differs from the host's file ({} bytes read)",
                o.stdout.len()
            );
        }

        assert_eq!(out(&m, &["rev-list", "--all", "--count"]), "5\n");
        assert_eq!(
            same_as_host(&m, &proj, &["branch", "-a"]),
            "  feature\n* main\n"
        );
        assert_eq!(same_as_host(&m, &proj, &["tag", "-l"]), "v0.1\nv1.0\n");
        let described = out(&m, &["describe", "--tags"]);
        assert!(
            described.starts_with("v1.0-2-g"),
            "describe --tags: {described}"
        );

        let blame = same_as_host(&m, &proj, &["blame", "README.md"]);
        assert_eq!(blame.lines().count(), 3, "blame README.md: {blame}");
        assert!(blame.contains("needle-word"), "blame README.md: {blame}");
        assert_eq!(
            out(&m, &["grep", "needle-word"]),
            "README.md:the needle-word is here\n"
        );

        let archive = good_with(&m, &["archive", "HEAD"], false);
        let mut entries = tar_files(&archive.stdout);
        entries.sort();
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, paths, "git archive HEAD members");
        assert!(
            entries.contains(&("data/big.bin".to_owned(), BIG)),
            "git archive HEAD: data/big.bin is not {BIG} bytes: {entries:?}"
        );

        let counts = out(&m, &["count-objects", "-v"]);
        let host_counts = out(&proj, &["count-objects", "-v"]);
        for key in ["count: ", "in-pack: ", "packs: "] {
            assert_eq!(
                count_field(&counts, key),
                count_field(&host_counts, key),
                "count-objects -v {key}guest {counts} host {host_counts}"
            );
        }
        assert!(
            count_field(&counts, "count: ") >= 1,
            "no loose objects: {counts}"
        );
        assert!(count_field(&counts, "packs: ") >= 1, "no packs: {counts}");
        assert_eq!(count_field(&counts, "garbage: "), 0, "garbage: {counts}");

        let mut idx: Vec<PathBuf> = fs::read_dir(m.join(".git/objects/pack"))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "idx"))
            .collect();
        idx.sort();
        assert!(!idx.is_empty(), "no pack index under .git/objects/pack");
        let idx_arg = idx[0].to_str().unwrap();
        let verified = good(&m, &["verify-pack", "-v", idx_arg]);
        let verified_text = String::from_utf8_lossy(&verified.stdout).into_owned();
        let first = verified_text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or("");
        assert!(
            matches!(first.len(), 40 | 64) && first.bytes().all(|b| b.is_ascii_hexdigit()),
            "verify-pack -v {idx_arg} did not list objects: {verified_text}"
        );

        good(&m, &["fsck", "--full", "--strict"]);

        let edited = "fn main() { println!(\"host edit\"); }\n";
        fs::write(proj.join("src/main.rs"), edited).unwrap();
        eventually("the host edit on the guest", SYNC, || {
            read(&m.join("src/main.rs")).as_deref() == Some(edited)
        });
        assert_eq!(
            out(&m, &["status", "--porcelain"]),
            " M src/main.rs\n",
            "guest status after the host edit"
        );
        let diff = out(&m, &["diff"]);
        assert_eq!(
            diff.lines()
                .filter(|l| l.starts_with("diff --git "))
                .count(),
            1,
            "diff: {diff}"
        );
        assert!(
            diff.contains("+++ b/src/main.rs")
                && diff.contains("-fn main() { println!(\"two\"); }")
                && diff.contains("+fn main() { println!(\"host edit\"); }"),
            "diff: {diff}"
        );
        rig.guest.quit(Duration::from_secs(30));
    }

    // every file, directory and symlink under a git directory with its size, content hash, mode and mtime
    fn git_dir_snapshot(git_dir: &Path) -> BTreeMap<String, String> {
        let stamp = |md: &fs::Metadata| {
            format!(
                "mode={:o} mtime={}.{:09}",
                md.mode(),
                md.mtime(),
                md.mtime_nsec()
            )
        };
        let mut found = BTreeMap::new();
        let root = fs::symlink_metadata(git_dir).unwrap();
        found.insert(".".to_owned(), format!("dir {}", stamp(&root)));
        let mut stack = vec![(git_dir.to_path_buf(), String::new())];
        while let Some((dir, rel)) = stack.pop() {
            let rd =
                fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
            for e in rd {
                let e = e.unwrap();
                let name = e.file_name().to_string_lossy().into_owned();
                let r = if rel.is_empty() {
                    name
                } else {
                    format!("{rel}/{name}")
                };
                let p = e.path();
                let md = fs::symlink_metadata(&p)
                    .unwrap_or_else(|e| panic!("stat {}: {e}", p.display()));
                let ft = md.file_type();
                let desc = if ft.is_symlink() {
                    let target = fs::read_link(&p).unwrap();
                    format!("link -> {} {}", target.display(), stamp(&md))
                } else if ft.is_dir() {
                    stack.push((p.clone(), r.clone()));
                    format!("dir {}", stamp(&md))
                } else if ft.is_file() {
                    let data = fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
                    format!(
                        "file size={} blake3={} {}",
                        md.len(),
                        blake3::hash(&data).to_hex(),
                        stamp(&md)
                    )
                } else {
                    format!("other {}", stamp(&md))
                };
                found.insert(r, desc);
            }
        }
        found
    }

    fn snapshot_diff(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> Vec<String> {
        let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
        keys.into_iter()
            .filter_map(|k| match (a.get(k), b.get(k)) {
                (Some(x), Some(y)) if x == y => None,
                (x, y) => Some(format!("{k}: before {x:?}, after {y:?}")),
            })
            .take(30)
            .collect()
    }

    // how strictly a refused command must say so
    #[derive(Clone, Copy, PartialEq)]
    enum Want {
        // exit non-zero and name a read-only file system or a permission error
        Text,
        // exit non-zero; git words some failures without the system error
        Fail,
        // may exit 0 when it finds nothing to remove; only the host snapshot proves it changed nothing
        Any,
    }

    struct Cmd {
        prog: &'static str,
        args: &'static [&'static str],
        want: Want,
    }

    const REFUSALS: &[Cmd] = &[
        Cmd {
            prog: "git",
            args: &["commit", "--allow-empty", "-m", "x"],
            want: Want::Text,
        },
        Cmd {
            prog: "git",
            args: &["add", "src/a.txt"],
            want: Want::Text,
        },
        Cmd {
            prog: "git",
            args: &["checkout", "-b", "nb"],
            want: Want::Text,
        },
        Cmd {
            prog: "git",
            args: &["branch", "nb2"],
            want: Want::Text,
        },
        Cmd {
            prog: "git",
            args: &["tag", "t9"],
            want: Want::Text,
        },
        Cmd {
            prog: "git",
            args: &["reset", "--hard", "HEAD~1"],
            want: Want::Text,
        },
        Cmd {
            prog: "git",
            args: &["config", "--local", "user.name", "x"],
            want: Want::Text,
        },
        Cmd {
            prog: "git",
            args: &["update-ref", "refs/heads/zz", "HEAD"],
            want: Want::Text,
        },
        Cmd {
            prog: "git",
            args: &["stash", "push", "-m", "s"],
            want: Want::Fail,
        },
        Cmd {
            prog: "git",
            args: &["gc"],
            want: Want::Fail,
        },
        Cmd {
            prog: "git",
            args: &["repack", "-ad"],
            want: Want::Fail,
        },
        Cmd {
            prog: "git",
            args: &["prune"],
            want: Want::Any,
        },
        Cmd {
            prog: "git",
            args: &["commit-graph", "write"],
            want: Want::Fail,
        },
        Cmd {
            prog: "touch",
            args: &[".git/zzfile"],
            want: Want::Text,
        },
        Cmd {
            prog: "mkdir",
            args: &[".git/zzdir"],
            want: Want::Text,
        },
        Cmd {
            prog: "ln",
            args: &["-s", "x", ".git/zzlink"],
            want: Want::Text,
        },
        Cmd {
            prog: "rm",
            args: &[".git/HEAD"],
            want: Want::Text,
        },
        Cmd {
            prog: "mv",
            args: &[".git/HEAD", ".git/HEAD2"],
            want: Want::Text,
        },
        Cmd {
            prog: "sh",
            args: &["-c", "echo x >> .git/config"],
            want: Want::Text,
        },
        Cmd {
            prog: "chmod",
            args: &["777", ".git/HEAD"],
            want: Want::Text,
        },
        Cmd {
            prog: "truncate",
            args: &["-s", "0", ".git/index"],
            want: Want::Text,
        },
    ];

    fn exec(dir: &Path, c: &Cmd) -> Output {
        let mut cmd = if c.prog == "git" {
            git_command(dir, c.args)
        } else {
            let mut x = Command::new(c.prog);
            x.args(c.args).current_dir(dir).env("LC_ALL", "C");
            x
        };
        cmd.stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("{} {:?}: {e}", c.prog, c.args))
    }

    // a problem is recorded instead of panicking so one run reports every failure together
    fn expect_ok(dir: &Path, args: &[&str], problems: &mut Vec<String>) -> String {
        let o = run_git(dir, args);
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        if !o.status.success() {
            problems.push(format!(
                "git {args:?} in {} failed: {}",
                dir.display(),
                describe(&o)
            ));
        } else if let Some(w) = find_bad(&all, BAD_OUTPUT) {
            problems.push(format!(
                "git {args:?} in {} printed {w:?}: {}",
                dir.display(),
                describe(&o)
            ));
        }
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    fn ro_fixture(p: &Path) {
        fs::create_dir_all(p.join("src")).unwrap();
        fs::write(p.join("README.md"), "one\n").unwrap();
        fs::write(p.join("src/a.txt"), "a\n").unwrap();
        fs::write(p.join("src/b.txt"), "b\n").unwrap();
        git(p, &["init", "-q", "-b", "main"]);
        git(p, &["add", "-A"]);
        git(p, &["commit", "-qm", "c1"]);
        fs::write(p.join("src/a.txt"), "a2\n").unwrap();
        git(p, &["commit", "-qam", "c2"]);
        git(p, &["gc", "-q"]);
        fs::write(p.join("src/b.txt"), "b3\n").unwrap();
        git(p, &["commit", "-qam", "c3"]);
        // an unreachable loose object that prune would delete if it could
        fs::write(p.join("orphan.tmp"), "orphan\n").unwrap();
        git(p, &["hash-object", "-w", "orphan.tmp"]);
        fs::remove_file(p.join("orphan.tmp")).unwrap();
    }

    pub fn write_commands_refused() {
        if !ready() {
            return;
        }
        let mut rig = rig("gitro", ro_fixture);
        let (m, proj) = (rig.m.clone(), rig.w.proj.clone());
        let head = out(&proj, &["rev-parse", "HEAD"]);
        let orphan_src = rig.w.tmp.0.join("orphan.txt");
        fs::write(&orphan_src, "orphan\n").unwrap();
        let orphan = out(&proj, &["hash-object", orphan_src.to_str().unwrap()])
            .trim()
            .to_owned();
        assert_eq!(
            out(&proj, &["cat-file", "-t", &orphan]),
            "blob\n",
            "the fixture's unreachable object is missing from the host"
        );

        // writes outside .git still work, and they are what stash and add would have picked up
        let edited = "edited on the guest\n";
        fs::write(m.join("src/a.txt"), edited).unwrap();
        fs::write(m.join("new.txt"), "new\n").unwrap();
        eventually("the guest edits on the host", SYNC, || {
            read(&proj.join("src/a.txt")).as_deref() == Some(edited)
                && read(&proj.join("new.txt")).as_deref() == Some("new\n")
        });

        let before = git_dir_snapshot(&proj.join(".git"));
        let mut problems: Vec<String> = Vec::new();
        for c in REFUSALS {
            let label = format!("{} {}", c.prog, c.args.join(" "));
            let o = exec(&m, c);
            let all = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            if o.status.code().is_none() {
                problems.push(format!("{label} was killed: {}", describe(&o)));
                continue;
            }
            if let Some(w) = find_bad(&all, &["corrupt", "bad object", "bad index", "Bus error"]) {
                problems.push(format!("{label} printed {w:?}: {}", describe(&o)));
            }
            if c.want != Want::Any && o.status.success() {
                problems.push(format!(
                    "{label} succeeded on a read-only .git: {}",
                    describe(&o)
                ));
            }
            if c.want == Want::Text && !o.status.success() && find_bad(&all, REFUSED).is_none() {
                problems.push(format!(
                    "{label} failed without naming a read-only or permission error: {}",
                    describe(&o)
                ));
            }
        }
        let after = git_dir_snapshot(&proj.join(".git"));
        for l in snapshot_diff(&before, &after) {
            problems.push(format!("the host .git changed: {l}"));
        }

        expect_ok(&proj, &["fsck", "--full", "--strict"], &mut problems);
        let host_status = expect_ok(&proj, &["status", "--porcelain"], &mut problems);
        if host_status != " M src/a.txt\n?? new.txt\n" {
            problems.push(format!("host status: {host_status:?}"));
        }
        let host_orphan = run_git(&proj, &["cat-file", "-t", &orphan]);
        if String::from_utf8_lossy(&host_orphan.stdout) != "blob\n" {
            problems.push(format!(
                "the unreachable object was pruned from the host: {}",
                describe(&host_orphan)
            ));
        }
        if out(&proj, &["rev-parse", "HEAD"]) != head {
            problems.push("the host HEAD moved".to_owned());
        }
        for (path, want) in [("src/a.txt", edited), ("new.txt", "new\n")] {
            if read(&proj.join(path)).as_deref() != Some(want) {
                problems.push(format!("{path} on the host is not what the guest wrote"));
            }
        }

        let guest_status = expect_ok(&m, &["status", "--porcelain"], &mut problems);
        if guest_status != " M src/a.txt\n?? new.txt\n" {
            problems.push(format!("guest status afterwards: {guest_status:?}"));
        }
        let guest_log = expect_ok(&m, &["log", "--oneline"], &mut problems);
        if guest_log.lines().count() != 3 {
            problems.push(format!("guest log afterwards: {guest_log:?}"));
        }
        let guest_head = expect_ok(&m, &["rev-parse", "HEAD"], &mut problems);
        if guest_head != head {
            problems.push(format!(
                "guest HEAD {guest_head:?} is not the host's {head:?}"
            ));
        }

        assert!(problems.is_empty(), "{problems:#?}");
        rig.guest.quit(Duration::from_secs(30));
    }

    fn big_text(n: usize) -> String {
        (0..200 + n * 13)
            .map(|l| format!("line {l} of the big file\n"))
            .collect()
    }

    fn churn_fixture(p: &Path) {
        for i in 0..4 {
            fs::write(p.join(format!("f{i}.txt")), format!("file {i}\n")).unwrap();
        }
        fs::write(p.join("big.txt"), big_text(0)).unwrap();
        git(p, &["init", "-q", "-b", "main"]);
        git(p, &["add", "-A"]);
        git(p, &["commit", "-qm", "base"]);
    }

    // runs a command to the end or kills it at the limit, which shows up as a signal exit
    fn run_bounded(mut cmd: Command, limit: Duration) -> Output {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn git");
        let mut so = child.stdout.take().expect("stdout");
        let mut se = child.stderr.take().expect("stderr");
        let t_out = thread::spawn(move || {
            let mut v = Vec::new();
            let _ = so.read_to_end(&mut v);
            v
        });
        let t_err = thread::spawn(move || {
            let mut v = Vec::new();
            let _ = se.read_to_end(&mut v);
            v
        });
        let end = Instant::now() + limit;
        let status = loop {
            if let Some(st) = child.try_wait().expect("wait for git") {
                break st;
            }
            if Instant::now() >= end {
                let _ = child.kill();
                break child.wait().expect("wait for git");
            }
            thread::sleep(Duration::from_millis(5));
        };
        Output {
            status,
            stdout: t_out.join().unwrap_or_default(),
            stderr: t_err.join().unwrap_or_default(),
        }
    }

    struct Stop<'a>(&'a AtomicBool);

    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    const STRESS_BAD: &[&str] = &[
        "corrupt",
        "bad object",
        "bad signature",
        "bad index",
        "index file smaller",
        "inflate",
        "Bus error",
        "unable to read",
        "cannot be accessed",
        "does not point to a valid object",
    ];

    // a guest command may exit non-zero only when it lost a race for the index lock to the host's own git
    const ALLOWED_FAILURE: &[&str] = &["index.lock"];

    const GUEST_CMDS: &[&[&str]] = &[
        &["status", "--porcelain"],
        &["log", "--oneline", "-n", "5"],
        &["cat-file", "-p", "HEAD"],
        &["rev-parse", "HEAD"],
        &["ls-files"],
        &["diff", "--stat"],
    ];

    pub fn healthy_under_host_commits() {
        if !ready() {
            return;
        }
        let mut rig = rig("gitchurn", churn_fixture);
        let (m, proj) = (rig.m.clone(), rig.w.proj.clone());
        let done = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(240);
        let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let total = AtomicUsize::new(0);
        let overlapped = AtomicUsize::new(0);
        thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    loop {
                        for args in GUEST_CMDS {
                            let live = !done.load(Ordering::SeqCst);
                            let o = run_bounded(git_command(&m, args), Duration::from_secs(90));
                            total.fetch_add(1, Ordering::SeqCst);
                            if live {
                                overlapped.fetch_add(1, Ordering::SeqCst);
                            }
                            let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
                            let mut why = Vec::new();
                            if let Some(sig) = o.status.signal() {
                                why.push(format!("killed by signal {sig}"));
                            }
                            if let Some(w) = find_bad(&stderr, STRESS_BAD) {
                                why.push(format!("stderr has {w:?}"));
                            }
                            if o.status.code() != Some(0)
                                && !ALLOWED_FAILURE.iter().any(|a| stderr.contains(*a))
                            {
                                why.push(format!("exit {:?}", o.status.code()));
                            }
                            if !why.is_empty() {
                                failures.lock().unwrap().push(format!(
                                    "git {args:?}: {}: {}",
                                    why.join(", "),
                                    clip(&o.stderr)
                                ));
                            }
                        }
                        if done.load(Ordering::SeqCst) || Instant::now() >= deadline {
                            break;
                        }
                    }
                });
            }
            let _stop = Stop(&done);
            for i in 0..25usize {
                fs::write(
                    proj.join(format!("f{}.txt", i % 4)),
                    format!("rev {i}\n{}", "x".repeat(i * 3)),
                )
                .unwrap();
                fs::write(
                    proj.join(format!("f{}.txt", (i + 1) % 4)),
                    format!("other {i}\n{}", "y".repeat(i * 5 + 1)),
                )
                .unwrap();
                fs::write(proj.join("big.txt"), big_text(i + 1)).unwrap();
                if i % 2 == 0 {
                    fs::write(
                        proj.join(format!("extra{}.txt", i % 6)),
                        format!("extra {i}\n"),
                    )
                    .unwrap();
                }
                git(&proj, &["add", "-A"]);
                git(&proj, &["commit", "-qm", &format!("n{i}")]);
                if i % 8 == 7 {
                    git(&proj, &["gc", "-q"]);
                }
                thread::sleep(Duration::from_millis(150));
            }
        });

        let failures = failures.into_inner().unwrap();
        assert!(
            failures.is_empty(),
            "{} guest git commands failed while the host committed ({} ran, {} of them during the commits):\n{failures:#?}",
            failures.len(),
            total.load(Ordering::SeqCst),
            overlapped.load(Ordering::SeqCst)
        );
        assert!(
            overlapped.load(Ordering::SeqCst) >= 24,
            "only {} guest git commands ran during the host commits",
            overlapped.load(Ordering::SeqCst)
        );

        let want = out(&proj, &["rev-parse", "HEAD"]);
        eventually("the guest HEAD follows the host's", SYNC, || {
            String::from_utf8_lossy(&run_git(&m, &["rev-parse", "HEAD"]).stdout).trim()
                == want.trim()
        });
        good(&m, &["fsck", "--full"]);
        eventually("a clean guest status after the last commit", SYNC, || {
            let o = run_git(&m, &["status", "--porcelain"]);
            o.status.success() && o.stdout.is_empty()
        });
        rig.guest.quit(Duration::from_secs(30));
    }
}
