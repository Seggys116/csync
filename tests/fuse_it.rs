// end-to-end: a real host and guest process on 127.0.0.1 with pre-shared keys, driven in headless mode

#[test]
fn fuse_end_to_end() {
    #[cfg(target_os = "linux")]
    linux::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE integration test runs on Linux only");
}

// interactive pairing from empty config dirs: sas, accept/confirm, resume, reject, revoke, garbage handshakes
#[test]
fn fuse_pairing() {
    #[cfg(target_os = "linux")]
    linux::run_pairing();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE pairing test runs on Linux only");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs,
        io::{self, BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        os::unix::fs::{FileExt, PermissionsExt},
        path::{Path, PathBuf},
        process::{Child, ChildStdin, Command, Stdio},
        sync::mpsc::{self, Receiver},
        thread,
        time::{Duration, Instant},
    };

    const START: Duration = Duration::from_secs(60);
    const SYNC: Duration = Duration::from_secs(15);
    const RECONNECT: Duration = Duration::from_secs(40);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let p = base.join(format!("csync-it-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&p).expect("create temp dir");
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            // never walk into a live mount: that would delete host files through the guest
            if mounts().iter().any(|m| m.starts_with(&self.0)) {
                eprintln!(
                    "leaving {} in place: a mount is still active under it",
                    self.0.display()
                );
                return;
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Unmount(PathBuf);

    impl Drop for Unmount {
        fn drop(&mut self) {
            if is_mounted(&self.0) {
                let _ = Command::new("fusermount3").arg("-uz").arg(&self.0).status();
                if is_mounted(&self.0) {
                    let _ = Command::new("umount").arg("-l").arg(&self.0).status();
                }
            }
        }
    }

    fn unescape_mountinfo(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\'
                && i + 3 < b.len()
                && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
            {
                out.push(((b[i + 1] - b'0') << 6) | ((b[i + 2] - b'0') << 3) | (b[i + 3] - b'0'));
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn mounts() -> Vec<PathBuf> {
        let text = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        text.lines()
            .filter_map(|l| l.split(' ').nth(4))
            .map(|m| PathBuf::from(unescape_mountinfo(m)))
            .collect()
    }

    fn is_mounted(p: &Path) -> bool {
        mounts().iter().any(|m| m == p)
    }

    struct Proc {
        name: &'static str,
        child: Child,
        stdin: Option<ChildStdin>,
        lines: Receiver<String>,
    }

    impl Proc {
        fn spawn(name: &'static str, bin: &Path, home: &Path, args: &[&str]) -> Self {
            let mut child = Command::new(bin)
                .args(args)
                .env("CSYNC_HOME", home)
                .env("NO_COLOR", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
            let stdout = child.stdout.take().expect("stdout");
            let stdin = child.stdin.take();
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    eprintln!("[{name}] {line}");
                    if tx.send(line).is_err() {
                        return;
                    }
                }
            });
            Self {
                name,
                child,
                stdin,
                lines: rx,
            }
        }

        fn alive(&mut self) -> bool {
            matches!(self.child.try_wait(), Ok(None))
        }

        fn wait_line(
            &mut self,
            what: &str,
            timeout: Duration,
            pred: impl Fn(&str) -> bool,
        ) -> String {
            let end = Instant::now() + timeout;
            loop {
                let left = end.saturating_duration_since(Instant::now());
                match self
                    .lines
                    .recv_timeout(left.min(Duration::from_millis(200)))
                {
                    Ok(l) if pred(&l) => return l,
                    Ok(_) => {}
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        assert!(
                            self.alive(),
                            "{} exited while waiting for {what}",
                            self.name
                        );
                        assert!(
                            Instant::now() < end,
                            "{} did not report {what} within {timeout:?}",
                            self.name
                        );
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        panic!("{} closed stdout while waiting for {what}", self.name)
                    }
                }
            }
        }

        fn quit(&mut self, timeout: Duration) {
            if let Some(mut i) = self.stdin.take() {
                let _ = i.write_all(b"quit\n");
            }
            let end = Instant::now() + timeout;
            while Instant::now() < end {
                if !self.alive() {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            panic!("{} did not stop within {timeout:?} after quit", self.name);
        }
    }

    impl Drop for Proc {
        fn drop(&mut self) {
            if self.alive() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }

    fn csync(bin: &Path, home: &Path, args: &[&str]) -> String {
        let out = Command::new(bin)
            .args(args)
            .env("CSYNC_HOME", home)
            .stdin(Stdio::null())
            .output()
            .expect("run csync");
        assert!(
            out.status.success(),
            "csync {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout)
            .expect("utf-8 output")
            .trim()
            .to_owned()
    }

    fn eventually(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
        let end = Instant::now() + timeout;
        while Instant::now() < end {
            if f() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out after {timeout:?}: {what}");
    }

    fn read(p: &Path) -> Option<String> {
        fs::read_to_string(p).ok()
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("free port")
            .port()
    }

    fn files_reported(l: &str) -> bool {
        l.starts_with("stats ")
            && l.split(' ')
                .any(|t| t.strip_prefix("files=").is_some_and(|v| v != "0"))
    }

    fn all_names(dir: &Path, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            if is_dir && name != ".git" {
                all_names(&e.path(), out);
            }
            out.push(name);
        }
    }

    fn assert_no_strays(dir: &Path) {
        let mut names = Vec::new();
        all_names(dir, &mut names);
        for n in &names {
            assert!(
                !n.starts_with(".csync~"),
                "stray staging file {n} in {}",
                dir.display()
            );
            assert!(
                !(n.contains("conflict") && n != "conflict.txt"),
                "stray conflict copy {n} in {}",
                dir.display()
            );
            assert!(
                !n.ends_with(".orig") && !n.ends_with(".rej"),
                "stray merge leftover {n} in {}",
                dir.display()
            );
        }
    }

    fn errno(r: io::Result<impl Sized>) -> Option<i32> {
        r.err().and_then(|e| e.raw_os_error())
    }

    fn write_project(proj: &Path) {
        fs::create_dir_all(proj.join("src")).unwrap();
        fs::create_dir_all(proj.join(".git/objects")).unwrap();
        fs::create_dir_all(proj.join(".git/refs/heads")).unwrap();
        fs::write(proj.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            proj.join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        )
        .unwrap();
        fs::write(proj.join(".gitignore"), "target/\n").unwrap();
        fs::write(proj.join("README.md"), "hello from host\n").unwrap();
        fs::write(proj.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        fs::write(proj.join("merge.txt"), "a\nb\nc\nd\ne\nf\ng\nh\n").unwrap();
        fs::write(proj.join("conflict.txt"), "one\n").unwrap();
        fs::write(proj.join("atomic.txt"), "v1\n").unwrap();
    }

    pub fn run() {
        let Some(bin) = std::env::var_os("CSYNC_BIN").map(PathBuf::from) else {
            eprintln!(
                "skip: set CSYNC_BIN to a built csync binary to run the FUSE integration test"
            );
            return;
        };
        let bin =
            fs::canonicalize(&bin).unwrap_or_else(|e| panic!("CSYNC_BIN {}: {e}", bin.display()));
        assert!(
            Path::new("/dev/fuse").exists(),
            "/dev/fuse is missing; load the fuse module"
        );

        let tmp = TempDir::new();
        let proj = tmp.0.join("proj");
        let host_home = tmp.0.join("host-home");
        let guest_home = tmp.0.join("guest-home");
        let mnt = tmp.0.join("mnt");
        let _unmount = Unmount(mnt.clone());
        write_project(&proj);

        let hk = csync(&bin, &host_home, &["key", "show"]);
        let gk = csync(&bin, &guest_home, &["key", "show"]);
        assert_eq!(hk.len(), 44, "host key {hk:?}");
        assert_ne!(hk, gk);
        csync(
            &bin,
            &host_home,
            &["trust", "add", &gk, "--role", "guest", "--name", "it-guest"],
        );
        csync(
            &bin,
            &guest_home,
            &["trust", "add", &hk, "--role", "host", "--name", "it-host"],
        );

        let addr = format!("127.0.0.1:{}", free_port());
        let proj_s = proj.to_str().unwrap().to_owned();
        let mnt_s = mnt.to_str().unwrap().to_owned();
        let host_args = [
            "--no-tui",
            "host",
            proj_s.as_str(),
            "--listen",
            addr.as_str(),
            "--no-pair",
            "--no-mdns",
        ];
        let mut host = Proc::spawn("host", &bin, &host_home, &host_args);
        host.wait_line("an indexed project", START, files_reported);
        thread::sleep(Duration::from_millis(500));

        let mut guest = Proc::spawn(
            "guest",
            &bin,
            &guest_home,
            &[
                "--no-tui",
                "join",
                mnt_s.as_str(),
                "--connect",
                addr.as_str(),
                "--host",
                "it-host",
            ],
        );
        let end = Instant::now() + START;
        while !is_mounted(&mnt) {
            assert!(guest.alive(), "guest exited before mounting");
            assert!(
                Instant::now() < end,
                "mount did not appear within {START:?}"
            );
            thread::sleep(Duration::from_millis(100));
        }
        eventually("README visible on the guest", SYNC, || {
            mnt.join("README.md").exists()
        });

        // reads
        assert_eq!(
            read(&mnt.join("README.md")).as_deref(),
            Some("hello from host\n")
        );
        assert_eq!(
            read(&mnt.join("src/lib.rs")).as_deref(),
            Some("pub fn f() {}\n")
        );

        // create and write on the guest reaches the host
        fs::write(mnt.join("new.txt"), "from guest\n").unwrap();
        eventually("guest file on the host", SYNC, || {
            read(&proj.join("new.txt")).as_deref() == Some("from guest\n")
        });

        // atomic save: write a temp file and rename it over the destination
        assert_eq!(read(&mnt.join("atomic.txt")).as_deref(), Some("v1\n"));
        fs::write(mnt.join(".atomic.txt.tmp"), "v2\n").unwrap();
        fs::rename(mnt.join(".atomic.txt.tmp"), mnt.join("atomic.txt")).unwrap();
        eventually("atomic save on the host", SYNC, || {
            read(&proj.join("atomic.txt")).as_deref() == Some("v2\n")
        });
        eventually("temp name gone on the host", SYNC, || {
            !proj.join(".atomic.txt.tmp").exists()
        });
        assert_eq!(read(&mnt.join("atomic.txt")).as_deref(), Some("v2\n"));

        // concurrent edits on different lines merge cleanly
        assert_eq!(
            read(&mnt.join("merge.txt")).as_deref(),
            Some("a\nb\nc\nd\ne\nf\ng\nh\n")
        );
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(mnt.join("merge.txt"))
            .unwrap();
        f.write_at(b"A", 0).unwrap();
        fs::write(proj.join("merge.txt"), "a\nb\nc\nd\ne\nf\ng\nH\n").unwrap();
        fs::write(proj.join("sync1.txt"), "1\n").unwrap();
        eventually("host change pushed before the merge", SYNC, || {
            mnt.join("sync1.txt").exists()
        });
        f.sync_all().expect("a clean merge commits");
        drop(f);
        eventually("merged result on the host", SYNC, || {
            read(&proj.join("merge.txt")).as_deref() == Some("A\nb\nc\nd\ne\nf\ng\nH\n")
        });

        // overlapping edits: the later guest edit is refused with ECANCELED and leaves nothing behind
        assert_eq!(read(&mnt.join("conflict.txt")).as_deref(), Some("one\n"));
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(mnt.join("conflict.txt"))
            .unwrap();
        f.set_len(0).unwrap();
        f.write_at(b"guest\n", 0).unwrap();
        fs::write(proj.join("conflict.txt"), "host\n").unwrap();
        fs::write(proj.join("sync2.txt"), "2\n").unwrap();
        eventually("host change pushed before the refusal", SYNC, || {
            mnt.join("sync2.txt").exists()
        });
        assert_eq!(
            errno(f.sync_all()),
            Some(libc::ECANCELED),
            "a conflicting commit must fail with ECANCELED"
        );
        drop(f);
        thread::sleep(Duration::from_millis(500));
        assert_eq!(
            read(&proj.join("conflict.txt")).as_deref(),
            Some("host\n"),
            "the host copy wins"
        );
        eventually("guest shows the host copy after refusal", SYNC, || {
            read(&mnt.join("conflict.txt")).as_deref() == Some("host\n")
        });
        assert_no_strays(&proj);
        assert_no_strays(&mnt);

        // ignored paths stay on the guest
        fs::create_dir(mnt.join("target")).unwrap();
        fs::write(mnt.join("target/out.o"), "obj").unwrap();
        assert_eq!(read(&mnt.join("target/out.o")).as_deref(), Some("obj"));
        thread::sleep(Duration::from_secs(1));
        assert!(
            !proj.join("target").exists(),
            "an ignored directory reached the host"
        );

        // .git is readable and read-only
        assert_eq!(
            read(&mnt.join(".git/HEAD")).as_deref(),
            Some("ref: refs/heads/main\n")
        );
        assert_eq!(
            errno(
                fs::OpenOptions::new()
                    .write(true)
                    .open(mnt.join(".git/HEAD"))
            ),
            Some(libc::EROFS)
        );
        assert_eq!(
            errno(fs::write(mnt.join(".git/new"), "x")),
            Some(libc::EROFS)
        );
        assert!(!proj.join(".git/new").exists());

        // host edits raise inotify events inside the mount
        let w = inotify::Watch::new(&mnt).expect("inotify watch on the mount");
        fs::write(proj.join("watched.txt"), "w\n").unwrap();
        assert!(
            w.wait_for(
                "watched.txt",
                libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_CLOSE_WRITE,
                SYNC
            ),
            "no create event on the guest for a host-created file"
        );
        fs::write(proj.join("README.md"), "hello again\n").unwrap();
        assert!(
            w.wait_for(
                "README.md",
                libc::IN_MODIFY | libc::IN_CLOSE_WRITE | libc::IN_ATTRIB,
                SYNC
            ),
            "no modify event on the guest for a host edit"
        );
        eventually("guest reads the host edit", SYNC, || {
            read(&mnt.join("README.md")).as_deref() == Some("hello again\n")
        });

        // host restart: cached reads keep working, then the guest reconnects and catches up
        host.quit(SYNC);
        drop(host);
        assert_eq!(
            read(&mnt.join("README.md")).as_deref(),
            Some("hello again\n"),
            "cached read while the host is down"
        );
        fs::write(proj.join("after_restart.txt"), "back\n").unwrap();
        let mut host = Proc::spawn("host", &bin, &host_home, &host_args);
        host.wait_line("an indexed project after restart", START, files_reported);
        eventually("guest catches up after the host restart", RECONNECT, || {
            read(&mnt.join("after_restart.txt")).as_deref() == Some("back\n")
        });
        fs::write(proj.join("live_again.txt"), "live\n").unwrap();
        eventually("live pushes after reconnect", SYNC, || {
            read(&mnt.join("live_again.txt")).as_deref() == Some("live\n")
        });

        guest.quit(SYNC);
        eventually("unmounted after guest quit", SYNC, || !is_mounted(&mnt));
        host.quit(SYNC);
        assert_no_strays(&proj);
    }

    const EXIT_AUTH: i32 = 4;
    const SAS_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    impl Proc {
        fn say(&mut self, cmd: &str) {
            let name = self.name;
            let i = self.stdin.as_mut().expect("stdin still open");
            i.write_all(format!("{cmd}\n").as_bytes())
                .and_then(|()| i.flush())
                .unwrap_or_else(|e| panic!("send '{cmd}' to {name}: {e}"));
        }

        fn exit_code(&mut self, timeout: Duration) -> Option<i32> {
            let end = Instant::now() + timeout;
            loop {
                if let Some(st) = self.child.try_wait().expect("try_wait") {
                    return st.code();
                }
                assert!(
                    Instant::now() < end,
                    "{} did not exit within {timeout:?}",
                    self.name
                );
                thread::sleep(Duration::from_millis(50));
            }
        }

        // like exit_code, but fails if the mount ever appears on the way
        fn exit_code_unmounted(&mut self, mnt: &Path, timeout: Duration) -> Option<i32> {
            let end = Instant::now() + timeout;
            loop {
                assert!(
                    !is_mounted(mnt),
                    "{} mounted {} although it was refused",
                    self.name,
                    mnt.display()
                );
                if let Some(st) = self.child.try_wait().expect("try_wait") {
                    return st.code();
                }
                assert!(
                    Instant::now() < end,
                    "{} did not exit within {timeout:?}",
                    self.name
                );
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn field(line: &str, key: &str) -> Option<String> {
        line.split(' ')
            .skip(1)
            .find_map(|t| t.strip_prefix(key)?.strip_prefix('='))
            .map(str::to_owned)
    }

    fn wait_mount(p: &mut Proc, mnt: &Path) {
        let end = Instant::now() + START;
        while !is_mounted(mnt) {
            assert!(p.alive(), "{} exited before mounting", p.name);
            assert!(
                Instant::now() < end,
                "{} did not mount within {START:?}",
                p.name
            );
            thread::sleep(Duration::from_millis(100));
        }
        eventually("README visible through the mount", SYNC, || {
            mnt.join("README.md").exists()
        });
        assert_eq!(
            read(&mnt.join("README.md")).as_deref(),
            Some("hello from host\n"),
            "host file read through the {} mount",
            p.name
        );
    }

    fn join(bin: &Path, home: &Path, mnt: &Path, addr: &str, label: &'static str) -> Proc {
        Proc::spawn(
            label,
            bin,
            home,
            &[
                "--no-tui",
                "join",
                mnt.to_str().unwrap(),
                "--connect",
                addr,
                "--name",
                label,
            ],
        )
    }

    // the sas on both sides, after checking they agree and look like a code
    fn pairing_codes(host: &mut Proc, guest: &mut Proc) -> String {
        let h = host.wait_line("a pairing prompt", START, |l| {
            l.starts_with("pairing ") && l.contains(" sas=")
        });
        let g = guest.wait_line("a verification code", START, |l| {
            l.starts_with("peer ") && l.contains(" state=pairing")
        });
        let hs = field(&h, "sas").expect("host sas");
        let gs = field(&g, "sas").expect("guest sas");
        assert_eq!(hs, gs, "host and guest show different verification codes");
        assert_eq!(hs.len(), 9, "sas {hs:?}");
        for (i, c) in hs.chars().enumerate() {
            if i == 4 {
                assert_eq!(c, '-', "sas {hs:?}");
            } else {
                assert!(SAS_ALPHABET.contains(c), "sas {hs:?}");
            }
        }
        hs
    }

    fn fingerprint(bin: &Path, home: &Path) -> String {
        csync(bin, home, &["key", "show", "--fingerprint"])
    }

    // (role, fpr, name) for each trusted peer; an empty store exits 6
    fn trusted(bin: &Path, home: &Path) -> Vec<(String, String, String)> {
        let out = Command::new(bin)
            .args(["trust", "list"])
            .env("CSYNC_HOME", home)
            .stdin(Stdio::null())
            .output()
            .expect("run csync trust list");
        match out.status.code() {
            Some(0) => String::from_utf8(out.stdout)
                .expect("utf-8 output")
                .lines()
                .filter_map(|l| {
                    let mut it = l.split_whitespace();
                    Some((
                        it.next()?.to_owned(),
                        it.next()?.to_owned(),
                        it.next()?.to_owned(),
                    ))
                })
                .collect(),
            Some(6) => Vec::new(),
            c => panic!(
                "csync trust list exited {c:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }

    fn trusts(bin: &Path, home: &Path, fpr: &str) -> bool {
        trusted(bin, home).iter().any(|(_, f, _)| f == fpr)
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p)
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
            .permissions()
            .mode()
            & 0o777
    }

    fn assert_private_store(home: &Path) {
        let cfg = home.join("config");
        assert_eq!(mode(&cfg), 0o700, "{}", cfg.display());
        for f in ["identity", "peers"] {
            assert_eq!(mode(&cfg.join(f)), 0o600, "{}", cfg.join(f).display());
        }
    }

    // a raw client speaking garbage; with expect_close the host must hang up well before its 10s handshake timeout
    fn probe(addr: &str, bytes: &[u8], expect_close: bool) {
        let mut s = TcpStream::connect(addr).expect("probe connect");
        let _ = s.write_all(bytes);
        if expect_close {
            let wait = Duration::from_secs(5);
            s.set_read_timeout(Some(wait)).unwrap();
            let end = Instant::now() + wait;
            let mut buf = [0u8; 512];
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        panic!("host kept a malformed handshake {bytes:02x?} open")
                    }
                    Err(_) => break,
                }
                assert!(
                    Instant::now() < end,
                    "host kept a malformed handshake open"
                );
            }
        }
    }

    pub fn run_pairing() {
        let Some(bin) = std::env::var_os("CSYNC_BIN").map(PathBuf::from) else {
            eprintln!("skip: set CSYNC_BIN to a built csync binary to run the FUSE pairing test");
            return;
        };
        let bin =
            fs::canonicalize(&bin).unwrap_or_else(|e| panic!("CSYNC_BIN {}: {e}", bin.display()));
        assert!(
            Path::new("/dev/fuse").exists(),
            "/dev/fuse is missing; load the fuse module"
        );

        let tmp = TempDir::new();
        let proj = tmp.0.join("proj");
        let host_home = tmp.0.join("host-home");
        let homes: Vec<PathBuf> = (1..=4).map(|i| tmp.0.join(format!("g{i}-home"))).collect();
        let mnts: Vec<PathBuf> = (1..=4).map(|i| tmp.0.join(format!("mnt{i}"))).collect();
        let _unmounts: Vec<Unmount> = mnts.iter().cloned().map(Unmount).collect();
        write_project(&proj);

        let addr = format!("127.0.0.1:{}", free_port());
        let proj_s = proj.to_str().unwrap().to_owned();
        let host_args = [
            "--no-tui",
            "host",
            proj_s.as_str(),
            "--listen",
            addr.as_str(),
            "--no-mdns",
        ];
        let mut host = Proc::spawn("host", &bin, &host_home, &host_args);
        host.wait_line("an indexed project", START, files_reported);
        thread::sleep(Duration::from_millis(500));

        // tampered handshakes: oversized length, bad mode, garbage noise, a forged reject, truncation
        let mut big = vec![1u8, 0xff, 0xff];
        big.extend(std::iter::repeat_n(0x41, 64));
        probe(&addr, &big, true);
        let mut bad_mode = vec![0x7fu8];
        bad_mode.extend(std::iter::repeat_n(0xa5, 4096));
        probe(&addr, &bad_mode, true);
        let mut resume = vec![2u8, 0x04, 0x00];
        resume.extend((0..1024u32).map(|i| (i * 31 + 7) as u8));
        probe(&addr, &resume, true);
        probe(&addr, &[2, 0, 0, 9], true);
        let mut eph = vec![1u8, 0x00, 0x20];
        eph.extend((0..32u8).map(|i| i.wrapping_mul(13)));
        probe(&addr, &eph, false);
        probe(&addr, &[2, 0x04], false);
        probe(&addr, &[], false);
        thread::sleep(Duration::from_millis(500));
        assert!(host.alive(), "the host died on a malformed handshake");

        // first contact: xx pairing with matching codes on both sides
        let (g1, m1) = (&homes[0], &mnts[0]);
        let mut guest = join(&bin, g1, m1, &addr, "it-guest1");
        pairing_codes(&mut host, &mut guest);
        assert!(!is_mounted(m1), "mounted before pairing was confirmed");
        host.say("accept");
        guest.say("confirm yes");
        wait_mount(&mut guest, m1);

        let hf = fingerprint(&bin, &host_home);
        let g1f = fingerprint(&bin, g1);
        assert!(
            trusted(&bin, &host_home)
                .iter()
                .any(|(r, f, n)| r == "guest" && *f == g1f && n == "it-guest1"),
            "host does not trust the paired guest"
        );
        assert!(
            trusted(&bin, g1)
                .iter()
                .any(|(r, f, _)| r == "host" && *f == hf),
            "guest does not trust the paired host"
        );
        assert_private_store(&host_home);
        assert_private_store(g1);

        // both restart; the guest resumes through trust without any pairing step
        guest.quit(SYNC);
        eventually("unmounted after guest quit", SYNC, || !is_mounted(m1));
        host.quit(SYNC);
        drop(guest);
        drop(host);
        let mut host = Proc::spawn("host", &bin, &host_home, &host_args);
        host.wait_line("an indexed project after restart", START, files_reported);
        thread::sleep(Duration::from_millis(500));
        let mut guest = join(&bin, g1, m1, &addr, "it-guest1");
        wait_mount(&mut guest, m1);
        let live = host.wait_line("the resumed guest live", START, |l| {
            l.starts_with("peer ") && l.contains(" name=it-guest1 ") && l.contains(" state=live")
        });
        let g1_id = field(&live, "id").expect("peer id");

        // a guest the host rejects never mounts and leaves no trust behind
        let (g2, m2) = (&homes[1], &mnts[1]);
        let mut rejected = join(&bin, g2, m2, &addr, "it-guest2");
        pairing_codes(&mut host, &mut rejected);
        host.say("reject");
        assert_eq!(
            rejected.exit_code_unmounted(m2, RECONNECT),
            Some(EXIT_AUTH),
            "a rejected guest must exit with the auth code"
        );
        host.wait_line("the pairing prompt closed", SYNC, |l| {
            l == "pairing state=closed"
        });
        let g2f = fingerprint(&bin, g2);
        assert!(!trusts(&bin, &host_home, &g2f), "host trusts a rejected guest");
        assert!(trusted(&bin, g2).is_empty(), "a rejected guest stored trust");

        // a guest that declines the code, even after the host accepted, leaves no trust either side
        let (g3, m3) = (&homes[2], &mnts[2]);
        let mut declined = join(&bin, g3, m3, &addr, "it-guest3");
        pairing_codes(&mut host, &mut declined);
        host.say("accept");
        declined.say("confirm no");
        assert_eq!(
            declined.exit_code_unmounted(m3, RECONNECT),
            Some(EXIT_AUTH),
            "a declined pairing must exit with the auth code"
        );
        host.wait_line("the pairing prompt closed", SYNC, |l| {
            l == "pairing state=closed"
        });
        let g3f = fingerprint(&bin, g3);
        assert!(!trusts(&bin, &host_home, &g3f), "host trusts a declined guest");
        assert!(trusted(&bin, g3).is_empty(), "a declined guest stored trust");
        assert!(host.alive());

        // revoke from the host session drops the live guest and refuses its reconnect
        host.say(&format!("revoke {g1_id}"));
        assert_eq!(
            guest.exit_code(RECONNECT),
            Some(EXIT_AUTH),
            "a revoked guest must exit with the auth code"
        );
        eventually("unmounted after revoke", SYNC, || !is_mounted(m1));
        assert!(!trusts(&bin, &host_home, &g1f), "revoke left the guest trusted");
        let mut again = join(&bin, g1, m1, &addr, "it-guest1");
        assert_eq!(
            again.exit_code_unmounted(m1, RECONNECT),
            Some(EXIT_AUTH),
            "a revoked guest must not reconnect"
        );

        // csync forget against the running host does the same
        let (g4, m4) = (&homes[3], &mnts[3]);
        let mut fourth = join(&bin, g4, m4, &addr, "it-guest4");
        pairing_codes(&mut host, &mut fourth);
        host.say("accept");
        fourth.say("confirm yes");
        wait_mount(&mut fourth, m4);
        let g4f = fingerprint(&bin, g4);
        assert!(trusts(&bin, &host_home, &g4f));
        csync(&bin, &host_home, &["forget", "it-guest4"]);
        assert_eq!(
            fourth.exit_code(RECONNECT),
            Some(EXIT_AUTH),
            "a forgotten guest must exit with the auth code"
        );
        eventually("unmounted after forget", SYNC, || !is_mounted(m4));
        assert!(!trusts(&bin, &host_home, &g4f), "forget left the guest trusted");
        let mut again = join(&bin, g4, m4, &addr, "it-guest4");
        assert_eq!(
            again.exit_code_unmounted(m4, RECONNECT),
            Some(EXIT_AUTH),
            "a forgotten guest must not reconnect"
        );

        assert!(host.alive(), "host stopped during the pairing scenarios");
        host.quit(SYNC);
    }

    #[allow(unsafe_code)]
    mod inotify {
        use std::{
            ffi::CString,
            fs::File,
            io::{self, Read},
            os::{
                fd::{FromRawFd, OwnedFd},
                unix::ffi::OsStrExt,
            },
            path::Path,
            thread,
            time::{Duration, Instant},
        };

        const HDR: usize = 16;

        pub struct Watch {
            file: File,
        }

        impl Watch {
            pub fn new(dir: &Path) -> io::Result<Self> {
                // SAFETY: inotify_init1 takes only flags and returns a new descriptor or -1.
                let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: fd was just returned by inotify_init1 and nothing else owns it.
                let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                let c = CString::new(dir.as_os_str().as_bytes())
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
                let mask = libc::IN_CREATE
                    | libc::IN_MODIFY
                    | libc::IN_CLOSE_WRITE
                    | libc::IN_MOVED_TO
                    | libc::IN_ATTRIB
                    | libc::IN_DELETE;
                // SAFETY: c is a valid nul-terminated path and fd is an open inotify descriptor owned above.
                let wd = unsafe { libc::inotify_add_watch(fd, c.as_ptr(), mask) };
                if wd < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self {
                    file: File::from(owned),
                })
            }

            pub fn wait_for(&self, name: &str, mask: u32, timeout: Duration) -> bool {
                let end = Instant::now() + timeout;
                let mut buf = vec![0u8; 64 << 10];
                while Instant::now() < end {
                    match (&self.file).read(&mut buf) {
                        Ok(n) => {
                            let mut off = 0;
                            while off + HDR <= n {
                                let word = |at: usize| {
                                    u32::from_ne_bytes([
                                        buf[at],
                                        buf[at + 1],
                                        buf[at + 2],
                                        buf[at + 3],
                                    ])
                                };
                                let ev_mask = word(off + 4);
                                let len = word(off + 12) as usize;
                                let raw = &buf[off + HDR..(off + HDR + len).min(n)];
                                let ev_name = raw.split(|&b| b == 0).next().unwrap_or_default();
                                if ev_mask & mask != 0 && ev_name == name.as_bytes() {
                                    return true;
                                }
                                off += HDR + len;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20))
                        }
                        Err(_) => return false,
                    }
                }
                false
            }
        }
    }
}
