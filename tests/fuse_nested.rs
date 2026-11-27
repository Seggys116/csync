// nested repositories inside a synced project: a submodule, a plain nested repo and a repo two levels down.
// each is its own ignore root, its .git is read-only on the guest, and edits flow both ways inside it

#[test]
fn fuse_nested() {
    #[cfg(target_os = "linux")]
    nested::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE nested repository test runs on Linux only");
}

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod nested {
    use super::common::*;
    use rustix::{
        fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags},
        io::Errno,
    };
    use std::{
        collections::HashMap,
        fs::{self, OpenOptions},
        mem::MaybeUninit,
        os::fd::OwnedFd,
        path::Path,
        process::{Command, Output},
        thread,
        time::{Duration, Instant},
    };

    const SUB: &str = "libs/sub";
    const PLAIN: &str = "tools/plain";
    const DEEP: &str = "libs/sub/ext/deep";
    const REPOS: [&str; 3] = [SUB, PLAIN, DEEP];

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
                "-c",
                "protocol.file.allow=always",
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

    fn seed(dir: &Path, tag: &str) {
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join(".gitignore"), "build/\n*.tmp\n").unwrap();
        fs::create_dir_all(dir.join("build")).unwrap();
        fs::write(dir.join("build/kept.txt"), format!("{tag} kept base\n")).unwrap();
        fs::write(dir.join("pinned.tmp"), format!("{tag} pinned base\n")).unwrap();
        fs::write(dir.join("src/a.rs"), format!("fn {tag}() {{}}\n")).unwrap();
        for f in [
            "tracked",
            "rename_me",
            "delete_me",
            "atomic",
            "host_edit",
            "host_commit",
        ] {
            fs::write(dir.join(format!("{f}.txt")), format!("{tag} {f} base\n")).unwrap();
        }
        git(dir, &["init", "-q", "-b", "main"]);
        git(dir, &["add", "-A"]);
        git(dir, &["add", "-f", "build/kept.txt", "pinned.tmp"]);
        git(dir, &["commit", "-qm", &format!("{tag} init")]);
    }

    fn populate(p: &Path) {
        let origin = p.parent().unwrap().join("origin-sub");
        fs::create_dir_all(&origin).unwrap();
        seed(&origin, "sub");
        fs::write(p.join(".gitignore"), "vendored/\n*.parentonly\n").unwrap();
        fs::write(p.join("README.md"), "parent\n").unwrap();
        git(p, &["init", "-q", "-b", "main"]);
        git(
            p,
            &["submodule", "add", "-q", origin.to_str().unwrap(), SUB],
        );
        let deep = p.join(DEEP);
        fs::create_dir_all(&deep).unwrap();
        seed(&deep, "deep");
        git(&p.join(SUB), &["add", "-A"]);
        git(&p.join(SUB), &["commit", "-qm", "sub gains deep"]);
        let plain = p.join(PLAIN);
        fs::create_dir_all(&plain).unwrap();
        seed(&plain, "plain");
        let inner = p.join("vendored/inner");
        fs::create_dir_all(&inner).unwrap();
        seed(&inner, "vendored");
        fs::write(p.join("vendored/top.txt"), "ignored by the parent\n").unwrap();
        git(p, &["add", "-A"]);
        git(p, &["commit", "-qm", "parent init"]);
    }

    fn host_has(p: &Path, want: &str) -> bool {
        read(p).as_deref() == Some(want)
    }

    fn refused<T>(r: &std::io::Result<T>, what: &str) {
        let e = errno(r);
        assert!(
            matches!(e, Some(libc::EROFS | libc::EACCES | libc::EPERM)),
            "{what} was not refused: {e:?}"
        );
    }

    struct Watch {
        fd: OwnedFd,
        wds: HashMap<i32, String>,
        buf: Vec<MaybeUninit<u8>>,
    }

    impl Watch {
        fn new() -> Self {
            Self {
                fd: inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC).unwrap(),
                wds: HashMap::new(),
                buf: vec![MaybeUninit::uninit(); 1 << 16],
            }
        }

        fn add(&mut self, m: &Path, rel: &str) {
            let mask = WatchFlags::CREATE
                | WatchFlags::MODIFY
                | WatchFlags::ATTRIB
                | WatchFlags::CLOSE_WRITE
                | WatchFlags::MOVED_TO;
            let wd = inotify::add_watch(&self.fd, m.join(rel), mask)
                .unwrap_or_else(|e| panic!("watch {rel}: {e}"));
            self.wds.insert(wd, rel.to_owned());
        }

        fn wait(&mut self, mut wants: Vec<(String, ReadFlags)>, timeout: Duration) {
            let end = Instant::now() + timeout;
            while !wants.is_empty() && Instant::now() < end {
                let mut r = inotify::Reader::new(&self.fd, &mut self.buf);
                loop {
                    match r.next() {
                        Ok(e) => {
                            let base = self.wds.get(&e.wd()).cloned().unwrap_or_default();
                            let name = e.file_name().map(|n| n.to_string_lossy().into_owned());
                            let path = format!("{base}/{}", name.unwrap_or_default());
                            wants.retain(|(p, f)| !(*p == path && e.events().intersects(*f)));
                        }
                        Err(Errno::AGAIN) => break,
                        Err(e) => panic!("inotify read: {e}"),
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
            assert!(wants.is_empty(), "no event on the guest for {wants:?}");
        }
    }

    pub fn run() {
        if bin().is_none() {
            return;
        }
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skip: git is not installed");
            return;
        }
        let mut w = World::new("nested", populate);
        let g = w.guest("g");
        let _host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        let (m, proj) = (g.mnt.clone(), w.proj.clone());
        eventually("the deepest repository on the guest", SYNC, || {
            host_has(&m.join(DEEP).join("tracked.txt"), "deep tracked base\n")
        });

        tracked_files_and_git(&m, &proj);
        ignore_roots(&m, &proj);
        guest_edits(&m, &proj);
        host_edits(&m, &proj);
        git_dirs_read_only(&m, &proj);
        host_commits(&m, &proj);
        ignored_parent_directory(&m, &proj);
        guest.quit(Duration::from_secs(30));
    }

    fn tag(repo: &str) -> &'static str {
        match repo {
            SUB => "sub",
            PLAIN => "plain",
            _ => "deep",
        }
    }

    fn tracked_files_and_git(m: &Path, proj: &Path) {
        for repo in REPOS {
            let t = tag(repo);
            for f in ["tracked", "rename_me", "delete_me", "atomic", "host_edit"] {
                let p = m.join(repo).join(format!("{f}.txt"));
                assert_eq!(read(&p), Some(format!("{t} {f} base\n")), "{repo} {f}");
            }
            assert_eq!(
                read(&m.join(repo).join("build/kept.txt")),
                Some(format!("{t} kept base\n")),
                "{repo} tracked file under an ignored directory"
            );
            assert_eq!(
                read(&m.join(repo).join("pinned.tmp")),
                Some(format!("{t} pinned base\n")),
                "{repo} tracked file matching an ignore rule"
            );
            assert_eq!(
                read(&m.join(repo).join("src/a.rs")),
                Some(format!("fn {t}() {{}}\n"))
            );
            assert_eq!(
                git(&m.join(repo), &["status", "--porcelain"]),
                "",
                "guest status of {repo}"
            );
            let log = git(&m.join(repo), &["log", "--oneline"]);
            assert_eq!(log, git(&proj.join(repo), &["log", "--oneline"]), "{repo}");
            assert!(log.contains(&format!("{t} ")), "{repo} log: {log}");
        }
        assert!(
            read(&m.join(SUB).join(".git"))
                .unwrap()
                .starts_with("gitdir: "),
            "the submodule gitlink file"
        );
        assert_eq!(
            read(&m.join(".git/modules/libs/sub/HEAD")).as_deref(),
            Some("ref: refs/heads/main\n")
        );
        assert_eq!(
            git(m, &["status", "--porcelain"]),
            "",
            "guest status of the parent"
        );
        assert!(git(m, &["submodule", "status", "--", SUB]).contains(SUB));
    }

    // an ignored file stays where it was made; a file git does not ignore crosses
    fn ignore_roots(m: &Path, proj: &Path) {
        for repo in REPOS {
            let (gd, hd) = (m.join(repo), proj.join(repo));
            fs::write(gd.join("build/g.o"), "guest object\n").unwrap();
            fs::write(gd.join("g_flow.parentonly"), "guest parent rule\n").unwrap();
            fs::write(gd.join("g.tmp"), "guest scratch\n").unwrap();
            fs::write(gd.join("g_flow.txt"), "guest flow\n").unwrap();
            eventually("a guest file in a nested repo on the host", SYNC, || {
                host_has(&hd.join("g_flow.txt"), "guest flow\n")
                    && host_has(&hd.join("g_flow.parentonly"), "guest parent rule\n")
            });

            fs::write(hd.join("build/h.o"), "host object\n").unwrap();
            fs::write(hd.join("h_flow.parentonly"), "host parent rule\n").unwrap();
            fs::write(hd.join("h.tmp"), "host scratch\n").unwrap();
            fs::write(hd.join("h_flow.txt"), "host flow\n").unwrap();
            eventually("a host file in a nested repo on the guest", SYNC, || {
                host_has(&gd.join("h_flow.txt"), "host flow\n")
                    && host_has(&gd.join("h_flow.parentonly"), "host parent rule\n")
            });

            thread::sleep(Duration::from_millis(500));
            assert!(
                !hd.join("build/g.o").exists(),
                "{repo}: guest build/ reached the host"
            );
            assert!(
                !hd.join("g.tmp").exists(),
                "{repo}: guest *.tmp reached the host"
            );
            assert!(
                !gd.join("build/h.o").exists(),
                "{repo}: host build/ reached the guest"
            );
            assert!(
                !gd.join("h.tmp").exists(),
                "{repo}: host *.tmp reached the guest"
            );
            assert_eq!(
                read(&gd.join("build/g.o")).as_deref(),
                Some("guest object\n")
            );
            assert_eq!(read(&gd.join("g.tmp")).as_deref(), Some("guest scratch\n"));
            let ci = git(&gd, &["check-ignore", "-v", "build/g.o", "g.tmp"]);
            assert!(
                ci.contains("build/") && ci.contains("*.tmp"),
                "{repo}: {ci}"
            );
            assert_eq!(
                run_git(&gd, &["check-ignore", "-q", "g_flow.parentonly"])
                    .status
                    .code(),
                Some(1),
                "{repo}: git itself ignores a parent rule inside a nested repository"
            );
        }
        // the parent's own rule still holds at the parent's level
        fs::write(m.join("top.parentonly"), "guest parent level\n").unwrap();
        fs::write(m.join("top_flow.txt"), "guest parent flow\n").unwrap();
        eventually("a guest file at the parent level on the host", SYNC, || {
            host_has(&proj.join("top_flow.txt"), "guest parent flow\n")
        });
        thread::sleep(Duration::from_millis(500));
        assert!(!proj.join("top.parentonly").exists());
        assert_eq!(
            read(&m.join("top.parentonly")).as_deref(),
            Some("guest parent level\n")
        );
    }

    fn guest_edits(m: &Path, proj: &Path) {
        for repo in REPOS {
            let (t, gd, hd) = (tag(repo), m.join(repo), proj.join(repo));
            fs::write(gd.join("tracked.txt"), format!("{t} guest edit\n")).unwrap();
            fs::write(gd.join("build/kept.txt"), format!("{t} kept guest\n")).unwrap();
            fs::write(gd.join("pinned.tmp"), format!("{t} pinned guest\n")).unwrap();
            fs::write(gd.join("new.txt"), format!("{t} guest new\n")).unwrap();
            fs::rename(gd.join("rename_me.txt"), gd.join("renamed.txt")).unwrap();
            fs::remove_file(gd.join("delete_me.txt")).unwrap();
            fs::write(gd.join(".atomic.swp"), format!("{t} atomic saved\n")).unwrap();
            fs::rename(gd.join(".atomic.swp"), gd.join("atomic.txt")).unwrap();
            fs::create_dir_all(gd.join("src/inner")).unwrap();
            fs::write(gd.join("src/inner/n.rs"), format!("// {t} nested dir\n")).unwrap();

            eventually("the guest edits on the host", SYNC, || {
                host_has(&hd.join("tracked.txt"), &format!("{t} guest edit\n"))
                    && host_has(&hd.join("build/kept.txt"), &format!("{t} kept guest\n"))
                    && host_has(&hd.join("pinned.tmp"), &format!("{t} pinned guest\n"))
                    && host_has(&hd.join("new.txt"), &format!("{t} guest new\n"))
                    && host_has(&hd.join("renamed.txt"), &format!("{t} rename_me base\n"))
                    && host_has(&hd.join("atomic.txt"), &format!("{t} atomic saved\n"))
                    && host_has(&hd.join("src/inner/n.rs"), &format!("// {t} nested dir\n"))
                    && !hd.join("rename_me.txt").exists()
                    && !hd.join("delete_me.txt").exists()
                    && !hd.join(".atomic.swp").exists()
            });
            let mut st: Vec<String> = git(&hd, &["status", "--porcelain", "-uall"])
                .lines()
                .map(str::to_owned)
                .collect();
            st.retain(|l| !l.contains("_flow") && !l.contains("ext/"));
            st.sort();
            let mut want = vec![
                " D delete_me.txt",
                " D rename_me.txt",
                " M atomic.txt",
                " M build/kept.txt",
                " M pinned.tmp",
                " M tracked.txt",
                "?? new.txt",
                "?? renamed.txt",
                "?? src/inner/n.rs",
            ];
            want.sort();
            assert_eq!(st, want, "host status of {repo} after the guest edits");
        }
    }

    fn host_edits(m: &Path, proj: &Path) {
        let mut watch = Watch::new();
        for repo in REPOS {
            watch.add(m, repo);
        }
        let mut wants = Vec::new();
        for repo in REPOS {
            let (t, hd) = (tag(repo), proj.join(repo));
            fs::write(hd.join("host_new.txt"), format!("{t} host new\n")).unwrap();
            fs::write(hd.join("build/kept.txt"), format!("{t} kept host\n")).unwrap();
            fs::write(hd.join("pinned.tmp"), format!("{t} pinned host\n")).unwrap();
            fs::write(hd.join(".host.swp"), format!("{t} host saved\n")).unwrap();
            fs::rename(hd.join(".host.swp"), hd.join("host_edit.txt")).unwrap();
            wants.push((
                format!("{repo}/host_new.txt"),
                ReadFlags::CREATE | ReadFlags::MOVED_TO | ReadFlags::CLOSE_WRITE,
            ));
            wants.push((
                format!("{repo}/host_edit.txt"),
                ReadFlags::CREATE
                    | ReadFlags::MOVED_TO
                    | ReadFlags::MODIFY
                    | ReadFlags::CLOSE_WRITE
                    | ReadFlags::ATTRIB,
            ));
        }
        watch.wait(wants, SYNC);
        for repo in REPOS {
            let t = tag(repo);
            eventually("the host edits on the guest", SYNC, || {
                host_has(
                    &m.join(repo).join("host_new.txt"),
                    &format!("{t} host new\n"),
                ) && host_has(
                    &m.join(repo).join("host_edit.txt"),
                    &format!("{t} host saved\n"),
                ) && host_has(
                    &m.join(repo).join("build/kept.txt"),
                    &format!("{t} kept host\n"),
                ) && host_has(
                    &m.join(repo).join("pinned.tmp"),
                    &format!("{t} pinned host\n"),
                )
            });
        }
    }

    fn git_dirs_read_only(m: &Path, proj: &Path) {
        let gitdirs = [
            (".git/modules/libs/sub", "HEAD"),
            (".git/modules/libs/sub", "config"),
            (PLAIN, ".git/HEAD"),
            (PLAIN, ".git/config"),
            (DEEP, ".git/HEAD"),
            (DEEP, ".git/config"),
        ];
        for (dir, file) in gitdirs {
            let g = m.join(dir).join(file);
            let before = read(&proj.join(dir).join(file)).unwrap();
            refused(
                &OpenOptions::new().write(true).open(&g),
                &format!("write open of {dir}/{file}"),
            );
            refused(&fs::write(&g, "x"), &format!("overwrite of {dir}/{file}"));
            refused(&fs::remove_file(&g), &format!("unlink of {dir}/{file}"));
            refused(
                &fs::rename(&g, g.with_extension("moved")),
                &format!("rename of {dir}/{file}"),
            );
            let base = m.join(dir);
            let base = if file.starts_with(".git/") {
                base.join(".git")
            } else {
                base
            };
            refused(
                &fs::write(base.join("csync_new"), "x"),
                &format!("create beside {dir}/{file}"),
            );
            assert_eq!(
                read(&proj.join(dir).join(file)),
                Some(before),
                "{dir}/{file} on the host"
            );
            assert!(!proj.join(dir).join("csync_new").exists());
        }
        let link = m.join(SUB).join(".git");
        refused(
            &OpenOptions::new().write(true).open(&link),
            "write open of the gitlink file",
        );
        refused(&fs::remove_file(&link), "unlink of the gitlink file");
        assert!(
            read(&proj.join(SUB).join(".git"))
                .unwrap()
                .starts_with("gitdir: "),
            "gitlink file on the host"
        );
        for repo in REPOS {
            let host_head = git(&proj.join(repo), &["rev-parse", "HEAD"]);
            let o = run_git(
                &m.join(repo),
                &["commit", "--allow-empty", "-qm", "from the guest"],
            );
            assert!(
                !o.status.success(),
                "a commit in {repo} succeeded on the guest"
            );
            assert_eq!(
                git(&proj.join(repo), &["rev-parse", "HEAD"]),
                host_head,
                "{repo}"
            );
        }
    }

    // deepest first, so each parent records the new head of the repository below it
    fn host_commits(m: &Path, proj: &Path) {
        for repo in [DEEP, PLAIN, SUB] {
            let (t, hd, gd) = (tag(repo), proj.join(repo), m.join(repo));
            fs::write(hd.join("host_commit.txt"), format!("{t} committed\n")).unwrap();
            git(&hd, &["add", "-A"]);
            git(&hd, &["commit", "-qm", &format!("{t} host commit")]);
            let head = git(&hd, &["rev-parse", "HEAD"]).trim().to_owned();
            eventually("the host commit on the guest", SYNC, || {
                run_git(&gd, &["rev-parse", "HEAD"]).stdout == format!("{head}\n").as_bytes()
                    && host_has(&gd.join("host_commit.txt"), &format!("{t} committed\n"))
            });
            let log = git(&gd, &["log", "--oneline", "-1"]);
            assert!(
                log.contains(&format!("{t} host commit")),
                "{repo} log: {log}"
            );
            assert_eq!(git(&gd, &["cat-file", "-t", &head]).trim(), "commit");
            eventually("a clean status on the guest", SYNC, || {
                run_git(&gd, &["status", "--porcelain"]).stdout.is_empty()
            });
            assert_eq!(
                git(&gd, &["log", "--oneline"]),
                git(&hd, &["log", "--oneline"]),
                "{repo} history"
            );
        }
    }

    // git ignores a directory whole, so a repository inside it is never seen
    fn ignored_parent_directory(m: &Path, proj: &Path) {
        assert!(proj.join("vendored/inner/.git").exists());
        fs::write(proj.join("vendored/late.txt"), "late\n").unwrap();
        fs::write(proj.join("after_vendored.txt"), "marker\n").unwrap();
        eventually("the marker file on the guest", SYNC, || {
            host_has(&m.join("after_vendored.txt"), "marker\n")
        });
        thread::sleep(Duration::from_millis(500));
        assert!(
            !m.join("vendored").exists(),
            "the ignored directory reached the guest"
        );
        assert!(proj.join("vendored/inner/tracked.txt").exists());
    }
}
