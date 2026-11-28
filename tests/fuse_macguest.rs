// the macos guest end to end on one mac: `csync host` on a temp project and `csync join` mounting it through macfuse
// (fskit backend). needs CSYNC_BIN (the macos build) and an installed, enabled macfuse; prints `skip:` and runs nothing otherwise

#[test]
fn fuse_macguest() {
    #[cfg(target_os = "macos")]
    mac::run();
    #[cfg(not(target_os = "macos"))]
    eprintln!("skip: the macos guest test runs on macos only");
}

#[cfg(target_os = "macos")]
mod mac {
    use csync::sys::{WatchEvent, start_watcher};
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        path::{Path, PathBuf},
        process::{Child, ChildStdin, Command, Output, Stdio},
        sync::{
            Arc, Mutex,
            mpsc::{self, Receiver},
        },
        thread,
        time::{Duration, Instant},
    };

    const START: Duration = Duration::from_secs(120);
    const SYNC: Duration = Duration::from_secs(20);
    // the fskit attribute lifetime is 1 s, so a host change must show well inside this
    const HOST_VISIBLE: Duration = Duration::from_secs(5);

    struct Proc {
        child: Child,
        stdin: Option<ChildStdin>,
        lines: Receiver<String>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Proc {
        fn spawn(name: &str, bin: &Path, home: &Path, args: &[&str]) -> Self {
            let mut child = Command::new(bin)
                .args(args)
                .env("CSYNC_HOME", home)
                .env("NO_COLOR", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
            let out = child.stdout.take().expect("stdout");
            let err = child.stderr.take().expect("stderr");
            let stdin = child.stdin.take();
            let log = Arc::new(Mutex::new(Vec::new()));
            let (tx, rx) = mpsc::channel();
            let (n, l) = (name.to_owned(), log.clone());
            thread::spawn(move || {
                for line in BufReader::new(out).lines().map_while(Result::ok) {
                    eprintln!("[{n}] {line}");
                    l.lock().unwrap().push(line.clone());
                    if tx.send(line).is_err() {
                        return;
                    }
                }
            });
            let (n, l) = (name.to_owned(), log.clone());
            thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    eprintln!("[{n}!] {line}");
                    l.lock().unwrap().push(format!("stderr: {line}"));
                }
            });
            Self {
                child,
                stdin,
                lines: rx,
                log,
            }
        }

        fn alive(&mut self) -> bool {
            matches!(self.child.try_wait(), Ok(None))
        }

        fn wait_line(&mut self, what: &str, limit: Duration, f: impl Fn(&str) -> bool) -> String {
            let end = Instant::now() + limit;
            loop {
                let left = end.saturating_duration_since(Instant::now());
                match self
                    .lines
                    .recv_timeout(left.min(Duration::from_millis(500)))
                {
                    Ok(l) if f(&l) => return l,
                    Ok(_) => {}
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        panic!("exited while waiting for {what}:\n{}", self.dump())
                    }
                }
                if Instant::now() >= end {
                    panic!("timed out waiting for {what}:\n{}", self.dump());
                }
            }
        }

        fn dump(&self) -> String {
            self.log.lock().unwrap().join("\n")
        }

        fn say(&mut self, cmd: &str) {
            if let Some(i) = self.stdin.as_mut() {
                let _ = writeln!(i, "{cmd}");
                let _ = i.flush();
            }
        }

        fn exit_within(&mut self, limit: Duration) -> bool {
            let end = Instant::now() + limit;
            while Instant::now() < end {
                if !self.alive() {
                    return true;
                }
                thread::sleep(Duration::from_millis(50));
            }
            false
        }
    }

    impl Drop for Proc {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    // unmounts a left-over mount if a failed run never reached the clean close
    struct Unmount(PathBuf);

    impl Drop for Unmount {
        fn drop(&mut self) {
            if mounted(&self.0) {
                let _ = Command::new("/sbin/umount").arg("-f").arg(&self.0).output();
            }
        }
    }

    struct Clean(PathBuf);

    impl Drop for Clean {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mounted(at: &Path) -> bool {
        let Ok(out) = Command::new("/sbin/mount").output() else {
            return false;
        };
        let at = fs::canonicalize(at).unwrap_or_else(|_| at.to_path_buf());
        let needle = format!(" on {} (", at.display());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|l| l.contains(&needle))
    }

    fn mount_table() -> String {
        Command::new("/sbin/mount")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    }

    fn csync(bin: &Path, home: &Path, args: &[&str]) -> String {
        let out = Command::new(bin)
            .args(args)
            .env("CSYNC_HOME", home)
            .output()
            .expect("run csync");
        assert!(
            out.status.success(),
            "csync {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn eventually(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if f() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out after {limit:?}: {what}");
    }

    // how long after `from` the check first held, polling up to 8s
    fn visible_after(from: Instant, mut f: impl FnMut() -> bool) -> Option<Duration> {
        while from.elapsed() < Duration::from_secs(8) {
            if f() {
                return Some(from.elapsed());
            }
            thread::sleep(Duration::from_millis(25));
        }
        None
    }

    fn files_reported(l: &str) -> bool {
        l.starts_with("stats ")
            && l.split(' ')
                .any(|t| t.strip_prefix("files=").is_some_and(|v| v != "0"))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + i / 251) as u8).collect()
    }

    fn entries(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    // watches `root` with the crate's own fsevents watcher; `seen` reports whether an event for `name` arrives
    struct Watch {
        _w: Box<dyn csync::sys::Watcher>,
        rx: crossbeam_channel::Receiver<Vec<WatchEvent>>,
    }

    impl Watch {
        fn start(root: &Path) -> Self {
            let (tx, rx) = crossbeam_channel::bounded(4096);
            let w = start_watcher(root, None, tx).expect("start the fsevents watcher");
            // the stream needs a moment before it delivers
            thread::sleep(Duration::from_millis(500));
            Self { _w: w, rx }
        }

        fn drain(&self) {
            while self.rx.try_recv().is_ok() {}
        }

        fn seen(&self, name: &str, limit: Duration) -> (bool, Vec<String>) {
            let end = Instant::now() + limit;
            let mut all = Vec::new();
            while let Some(left) = end.checked_duration_since(Instant::now()) {
                match self.rx.recv_timeout(left) {
                    Ok(batch) => {
                        for e in batch {
                            all.push(format!("{}:{:#x}", e.path.as_str(), e.flags));
                            if e.path.as_str().contains(name) {
                                return (true, all);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            (false, all)
        }
    }

    fn yn(b: bool) -> &'static str {
        if b { "yes" } else { "no" }
    }

    fn git_present() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn git_run(dir: &Path, args: &[&str]) -> Output {
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
                "commit.gpgsign=false",
            ])
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("LC_ALL", "C")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("git {args:?}: {e}"))
    }

    fn git_describe(args: &[&str], o: &Output) -> String {
        format!(
            "git {args:?}: exit {:?}\nstdout: {}\nstderr: {}",
            o.status.code(),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    }

    // turns the fixture's bare .git skeleton into a repository with two commits, before the host indexes it
    fn git_fixture(proj: &Path) {
        for (args, note) in [
            (vec!["init", "-q", "-b", "main"], None),
            (vec!["add", "-A"], None),
            (vec!["commit", "-qm", "first commit"], None),
            (vec!["add", "-A"], Some("notes.txt")),
            (vec!["commit", "-qm", "second commit"], None),
        ] {
            if let Some(name) = note {
                fs::write(proj.join(name), "second commit adds this\n").unwrap();
            }
            let o = git_run(proj, &args);
            assert!(o.status.success(), "fixture {}", git_describe(&args, &o));
        }
    }

    // every file and directory under `dir` with its size, sorted, for a before and after comparison
    fn dir_listing(dir: &Path) -> Vec<(String, u64)> {
        let mut found = Vec::new();
        let mut stack = vec![(dir.to_path_buf(), String::new())];
        while let Some((d, rel)) = stack.pop() {
            let Ok(rd) = fs::read_dir(&d) else {
                found.push((format!("{rel}/<unreadable>"), 0));
                continue;
            };
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let r = if rel.is_empty() {
                    name
                } else {
                    format!("{rel}/{name}")
                };
                let Ok(md) = fs::symlink_metadata(e.path()) else {
                    found.push((format!("{r}<unreadable>"), 0));
                    continue;
                };
                if md.is_dir() {
                    stack.push((e.path(), r.clone()));
                }
                found.push((r, md.len()));
            }
        }
        found.sort();
        found
    }

    // git on the mount against the host's two-commit repository; returns what went wrong, one entry per failure
    fn git_block(mnt: &Path, proj: &Path) -> Vec<String> {
        let mut bad = Vec::new();

        let args = ["status", "--porcelain"];
        let o = git_run(mnt, &args);
        let clean = o.status.success() && o.stdout.is_empty();
        if !clean {
            bad.push(git_describe(&args, &o));
        }
        eprintln!("git status --porcelain clean={}", yn(clean));

        let args = ["log", "--format=%s"];
        let o = git_run(mnt, &args);
        let subjects = String::from_utf8_lossy(&o.stdout).into_owned();
        let both = o.status.success()
            && subjects.lines().collect::<Vec<_>>() == ["second commit", "first commit"];
        if !both {
            bad.push(git_describe(&args, &o));
        }
        eprintln!("git log --oneline shows both commits={}", yn(both));

        let args = ["fsck", "--full"];
        let o = git_run(mnt, &args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        let healthy = o.status.success() && !text.contains("corrupt");
        if !healthy {
            bad.push(git_describe(&args, &o));
        }
        eprintln!("git fsck --full healthy={}", yn(healthy));

        let before = dir_listing(&proj.join(".git"));
        let args = ["commit", "--allow-empty", "-m", "x"];
        let o = git_run(mnt, &args);
        let refused = !o.status.success() && o.status.code().is_some();
        if !refused {
            bad.push(format!(
                "a commit on the read-only .git was not refused: {}",
                git_describe(&args, &o)
            ));
        }
        eprintln!("git commit --allow-empty refused={}", yn(refused));

        let after = dir_listing(&proj.join(".git"));
        let same = before == after;
        if !same {
            bad.push(format!(
                "the host .git changed under the refused commit: before {before:?}, after {after:?}"
            ));
        }
        eprintln!("git host .git unchanged={}", yn(same));
        bad
    }

    pub fn run() {
        let Some(bin) = std::env::var_os("CSYNC_BIN").map(PathBuf::from) else {
            eprintln!("skip: set CSYNC_BIN to the macos csync build");
            return;
        };
        if !Path::new("/Library/Filesystems/macfuse.fs").is_dir() {
            eprintln!("skip: macFUSE is not installed");
            return;
        }
        let bin = fs::canonicalize(&bin).unwrap_or_else(|e| panic!("CSYNC_BIN: {e}"));
        let tmp = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("csync-mg-{}", std::process::id()));
        let _clean = Clean(tmp.clone());
        let proj = tmp.join("proj");
        let mnt = tmp.join("mnt");
        let (hh, gh) = (tmp.join("hh"), tmp.join("gh"));
        fs::create_dir_all(proj.join("src")).unwrap();
        fs::create_dir_all(proj.join(".git/objects")).unwrap();
        fs::create_dir_all(proj.join(".git/refs/heads")).unwrap();
        fs::create_dir_all(&mnt).unwrap();
        fs::write(proj.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            proj.join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        )
        .unwrap();
        fs::write(proj.join(".gitignore"), "target/\n").unwrap();
        fs::write(proj.join("hello.txt"), "hello from host\n").unwrap();
        fs::write(proj.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let have_git = git_present();
        if have_git {
            git_fixture(&proj);
        }
        let _unmount = Unmount(mnt.clone());

        let hk = csync(&bin, &hh, &["key", "show"]);
        let gk = csync(&bin, &gh, &["key", "show"]);
        let host_fpr = csync(&bin, &hh, &["key", "show", "--fingerprint"]);
        csync(
            &bin,
            &hh,
            &["trust", "add", &gk, "--role", "guest", "--name", "g"],
        );
        csync(
            &bin,
            &gh,
            &["trust", "add", &hk, "--role", "host", "--name", "h"],
        );

        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap()
            .port();
        let addr = format!("127.0.0.1:{port}");
        let p = proj.to_str().unwrap();
        let mut host = Proc::spawn(
            "host",
            &bin,
            &hh,
            &[
                "--no-tui",
                "host",
                p,
                "--listen",
                &addr,
                "--no-pair",
                "--no-mdns",
            ],
        );
        host.wait_line("an indexed project", START, files_reported);

        // the control: the watcher must see a plain apfs directory, or a `no` on the mount means nothing
        let ctl = tmp.join("ctl");
        fs::create_dir_all(&ctl).unwrap();
        let cw = Watch::start(&ctl);
        fs::write(ctl.join("probe.txt"), "x").unwrap();
        let (control, _) = cw.seen("probe.txt", Duration::from_secs(5));
        drop(cw);

        let m = mnt.to_str().unwrap();
        let mut guest = Proc::spawn(
            "guest",
            &bin,
            &gh,
            &["--no-tui", "join", m, "--connect", &addr, "--host", "h"],
        );
        guest.wait_line("the guest mount", START, |l| l.starts_with("mounted "));
        assert!(guest.alive(), "the guest exited after mounting");
        let t_mount = Instant::now();
        while !mounted(&mnt) {
            assert!(
                t_mount.elapsed() < Duration::from_secs(30),
                "the guest reported mounted but the mount table has no mount at {m} after 30s:\n{}\nguest alive: {}\n{}",
                mount_table(),
                guest.alive(),
                guest.dump()
            );
            thread::sleep(Duration::from_millis(100));
        }
        eprintln!(
            "mount table entry appeared {:?} after the guest reported mounted",
            t_mount.elapsed()
        );
        let state = gh.join("state/hosts").join(&host_fpr);
        assert!(state.is_dir(), "no guest state at {}", state.display());

        // a synced file reads through the mount
        assert_eq!(
            fs::read_to_string(mnt.join("hello.txt")).unwrap(),
            "hello from host\n"
        );
        assert_eq!(
            fs::read_to_string(mnt.join("src/lib.rs")).unwrap(),
            "pub fn f() {}\n"
        );

        let git_failures = if have_git {
            git_block(&mnt, &proj)
        } else {
            eprintln!("skip: git is not installed, no git checks on the mount");
            Vec::new()
        };

        // host changes show on the mount inside the attribute lifetime plus slack; each shape is timed on its own
        // and all are asserted at the end of the test
        let mw = Watch::start(&mnt);
        mw.drain();
        let listed = |name: &str| entries(&mnt).iter().any(|n| n == name);
        let reads =
            |rel: &str, want: &str| fs::read_to_string(mnt.join(rel)).is_ok_and(|s| s == want);
        let t = Instant::now();
        fs::write(proj.join("listed.txt"), "one\n").unwrap();
        let by_listing = visible_after(t, || listed("listed.txt"));
        let t = Instant::now();
        fs::write(proj.join("fromhost.txt"), "written on the host\n").unwrap();
        let by_lookup = visible_after(t, || reads("fromhost.txt", "written on the host\n"));
        let t = Instant::now();
        fs::write(proj.join("src/lib.rs"), "pub fn g() {}\n").unwrap();
        let edited = visible_after(t, || reads("src/lib.rs", "pub fn g() {}\n"));
        let t = Instant::now();
        fs::write(proj.join("src/lib.rs"), "pub fn grown() { 1 }\n").unwrap();
        let grown = visible_after(t, || reads("src/lib.rs", "pub fn grown() { 1 }\n"));
        eprintln!("host edit that changes the size: {grown:?}");
        let t = Instant::now();
        fs::write(proj.join("third.txt"), "three\n").unwrap();
        let after_listing = visible_after(t, || reads("third.txt", "three\n"));
        eprintln!(
            "host changes on the mount: new file by listing {by_listing:?}, new file by lookup {by_lookup:?}, edit of a synced file {edited:?}, new file by lookup after a listing {after_listing:?}"
        );
        let (host_change, host_ev) = mw.seen("fromhost.txt", Duration::from_secs(1));
        let shapes = [
            ("new file by listing", by_listing),
            ("new file by lookup", by_lookup),
            ("edit of a synced file", edited),
            ("edit that changes the size", grown),
            ("new file by lookup after a listing", after_listing),
        ];

        // a guest create, write and close reaches the host byte for byte
        mw.drain();
        let body = pattern(300_000);
        {
            let mut f = fs::File::create(mnt.join("fromguest.bin")).unwrap();
            f.write_all(&body).unwrap();
            f.sync_all().unwrap();
        }
        let (guest_write, guest_ev) = mw.seen("fromguest.bin", Duration::from_secs(3));
        eventually("the guest file on the host", SYNC, || {
            fs::read(proj.join("fromguest.bin")).is_ok_and(|b| b == body)
        });
        assert_eq!(fs::read(mnt.join("fromguest.bin")).unwrap(), body);
        drop(mw);

        // an ignored path stays on the guest
        fs::create_dir(mnt.join("target")).unwrap();
        fs::write(mnt.join("target/x"), "obj").unwrap();
        assert_eq!(fs::read_to_string(mnt.join("target/x")).unwrap(), "obj");
        thread::sleep(Duration::from_secs(2));
        assert!(
            !proj.join("target").exists(),
            "an ignored directory reached the host"
        );

        eprintln!(
            "fsevents control={} guest_write={} host_change={}",
            yn(control),
            yn(guest_write),
            yn(host_change)
        );
        eprintln!("fsevents guest_write events: {guest_ev:?}");
        eprintln!("fsevents host_change events: {host_ev:?}");

        // whether the host-created files ever show, long after the probes gave up
        let late = entries(&mnt);
        eprintln!(
            "late listing of the mount root: {late:?} (host-created: listed.txt={} fromhost.txt={} third.txt={})",
            late.iter().any(|n| n == "listed.txt"),
            late.iter().any(|n| n == "fromhost.txt"),
            late.iter().any(|n| n == "third.txt")
        );

        // quit unmounts, ends the process and wipes the guest's local state for this host
        guest.say("quit");
        guest.stdin = None;
        assert!(
            guest.exit_within(Duration::from_secs(60)),
            "the guest did not exit after quit:\n{}",
            guest.dump()
        );
        assert!(!mounted(&mnt), "still mounted after quit");
        assert!(
            entries(&mnt).is_empty(),
            "the mount point is not empty after quit: {:?}",
            entries(&mnt)
        );
        assert!(!state.exists(), "guest state survived quit");
        assert!(
            !gh.join("cache").join(&host_fpr).exists(),
            "the guest's blob cache survived quit"
        );
        assert!(
            proj.join("fromguest.bin").exists() && !proj.join("target").exists(),
            "the host project changed on unmount"
        );
        host.say("quit");

        assert!(
            git_failures.is_empty(),
            "git on the mount failed:\n{}",
            git_failures.join("\n---\n")
        );

        // asserted last so a host change that never shows does not hide the other results
        for (what, t) in shapes {
            assert!(
                t.is_some_and(|d| d <= HOST_VISIBLE),
                "{what} did not show on the mount within {HOST_VISIBLE:?}: {t:?}"
            );
        }
    }
}
