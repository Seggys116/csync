// git on the guest against a live host: the index view that keeps status clean without config, ignore
// edits made on the guest, and host git runs that a guest reader must see in order

#[test]
fn fuse_git() {
    #[cfg(target_os = "linux")]
    git::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE git test runs on Linux only");
}

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod git {
    use super::common::*;
    use std::{
        fs,
        os::unix::fs::MetadataExt,
        path::Path,
        process::{Command, Output},
        thread,
        time::{Duration, Instant},
    };

    const SYNC: Duration = Duration::from_secs(20);

    fn run_git(dir: &Path, args: &[&str]) -> Output {
        Command::new("git")
            .arg("-C")
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
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
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
}
