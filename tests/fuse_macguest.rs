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
        process::{Child, ChildStdin, Command, Stdio},
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
        assert!(mounted(&mnt), "no mount in the mount table at {m}");
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

        // a host write shows on the mount inside the attribute lifetime plus slack
        let mw = Watch::start(&mnt);
        mw.drain();
        let t0 = Instant::now();
        fs::write(proj.join("fromhost.txt"), "written on the host\n").unwrap();
        eventually("the host write on the mount", HOST_VISIBLE, || {
            fs::read_to_string(mnt.join("fromhost.txt")).is_ok_and(|s| s == "written on the host\n")
        });
        eprintln!("host write visible on the mount after {:?}", t0.elapsed());
        let (host_change, host_ev) = mw.seen("fromhost.txt", Duration::from_secs(3));

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
    }
}
