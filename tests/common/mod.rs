// shared harness for the soak and chaos tests: real host and guest processes on loopback, pre-shared keys
#![cfg(target_os = "linux")]
#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::{
        fd::IntoRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

pub const START: Duration = Duration::from_secs(90);
pub const SYNC: Duration = Duration::from_secs(20);
pub const RECONNECT: Duration = Duration::from_secs(60);

pub fn bin() -> Option<PathBuf> {
    let Some(bin) = std::env::var_os("CSYNC_BIN").map(PathBuf::from) else {
        eprintln!("skip: set CSYNC_BIN to a built csync binary to run this test");
        return None;
    };
    assert!(
        Path::new("/dev/fuse").exists(),
        "/dev/fuse is missing; load the fuse module"
    );
    Some(fs::canonicalize(&bin).unwrap_or_else(|e| panic!("CSYNC_BIN {}: {e}", bin.display())))
}

pub fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let base = std::env::var_os("CSYNC_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let base = fs::canonicalize(base).expect("temp dir");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let p = base.join(format!("csync-{tag}-{}-{nanos}", std::process::id()));
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

pub struct Unmount(pub PathBuf);

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

pub fn mounts() -> Vec<PathBuf> {
    let text = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    text.lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(|m| PathBuf::from(unescape_mountinfo(m)))
        .collect()
}

pub fn is_mounted(p: &Path) -> bool {
    mounts().iter().any(|m| m == p)
}

pub struct Proc {
    pub name: String,
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    pub lines: Receiver<String>,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Proc {
    pub fn spawn(name: &str, bin: &Path, home: &Path, args: &[&str]) -> Self {
        let mut child = Command::new(bin)
            .args(args)
            .env("CSYNC_HOME", home)
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
        let stdout = child.stdout.take().expect("stdout");
        let stderr = child.stderr.take().expect("stderr");
        let stdin = child.stdin.take();
        let log = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = mpsc::channel();
        let quiet = std::env::var_os("CSYNC_QUIET").is_some();
        let (n1, l1) = (name.to_owned(), log.clone());
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if !quiet || !line.starts_with("stats ") {
                    eprintln!("[{n1}] {line}");
                }
                l1.lock().unwrap().push(line.clone());
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let (n2, l2) = (name.to_owned(), log.clone());
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("[{n2}!] {line}");
                l2.lock().unwrap().push(format!("stderr: {line}"));
            }
        });
        Self {
            name: name.to_owned(),
            child,
            stdin,
            lines: rx,
            log,
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn wait_line(
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

    // drains queued status lines so a later wait_line only sees fresh ones
    pub fn drain(&mut self) {
        while self.lines.try_recv().is_ok() {}
    }

    pub fn say(&mut self, cmd: &str) {
        if let Some(i) = self.stdin.as_mut() {
            let _ = i
                .write_all(format!("{cmd}\n").as_bytes())
                .and_then(|()| i.flush());
        }
    }

    pub fn quit(&mut self, timeout: Duration) {
        self.say("quit");
        self.stdin = None;
        let end = Instant::now() + timeout;
        while Instant::now() < end {
            if !self.alive() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("{} did not stop within {timeout:?} after quit", self.name);
    }

    pub fn signal(&self, sig: &str) {
        let _ = Command::new("kill")
            .arg(format!("-{sig}"))
            .arg(self.pid().to_string())
            .status();
    }

    pub fn kill9(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    pub fn exit_within(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let end = Instant::now() + timeout;
        loop {
            if let Ok(Some(st)) = self.child.try_wait() {
                return Some(st);
            }
            if Instant::now() >= end {
                return None;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn log_has(&self, needle: &str) -> bool {
        self.log.lock().unwrap().iter().any(|l| l.contains(needle))
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if self.alive() {
            // a stopped process ignores nothing but sigkill, yet resume it so its peers see a clean end
            self.signal("CONT");
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

pub fn csync(bin: &Path, home: &Path, args: &[&str]) -> String {
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

pub fn eventually(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if f() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out after {timeout:?}: {what}");
}

pub fn read(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok()
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port()
}

pub fn files_reported(l: &str) -> bool {
    l.starts_with("stats ")
        && l.split(' ')
            .any(|t| t.strip_prefix("files=").is_some_and(|v| v != "0"))
}

pub fn errno<T>(r: &io::Result<T>) -> Option<i32> {
    r.as_ref().err().and_then(io::Error::raw_os_error)
}

// close(2) reports the flush result, which is where a guest commit is refused; drop would hide it
#[allow(unsafe_code)]
pub fn close_checked(f: File) -> io::Result<()> {
    let fd = f.into_raw_fd();
    // SAFETY: fd was just released from an owned File and is closed exactly once here.
    if unsafe { libc::close(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn write_project(proj: &Path) {
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
}

// one host plus any number of trusted guests, all with their own config dirs under one temp root
pub struct World {
    pub bin: PathBuf,
    pub tmp: TempDir,
    pub proj: PathBuf,
    pub host_home: PathBuf,
    pub addr: String,
    host_key: String,
    unmounts: Vec<Unmount>,
}

pub struct Guest {
    pub home: PathBuf,
    pub mnt: PathBuf,
    pub label: String,
}

impl World {
    pub fn new(tag: &str, populate: impl FnOnce(&Path)) -> Self {
        let bin = bin().expect("checked by the caller");
        let tmp = TempDir::new(tag);
        let proj = tmp.0.join("proj");
        let host_home = tmp.0.join("host-home");
        fs::create_dir_all(&proj).unwrap();
        populate(&proj);
        let host_key = csync(&bin, &host_home, &["key", "show"]);
        let addr = format!("127.0.0.1:{}", free_port());
        Self {
            bin,
            tmp,
            proj,
            host_home,
            addr,
            host_key,
            unmounts: Vec::new(),
        }
    }

    pub fn guest(&mut self, label: &str) -> Guest {
        let home = self.tmp.0.join(format!("{label}-home"));
        let mnt = self.tmp.0.join(format!("{label}-mnt"));
        let gk = csync(&self.bin, &home, &["key", "show"]);
        csync(
            &self.bin,
            &self.host_home,
            &["trust", "add", &gk, "--role", "guest", "--name", label],
        );
        csync(
            &self.bin,
            &home,
            &[
                "trust",
                "add",
                &self.host_key,
                "--role",
                "host",
                "--name",
                "it-host",
            ],
        );
        self.unmounts.push(Unmount(mnt.clone()));
        Guest {
            home,
            mnt,
            label: label.to_owned(),
        }
    }

    pub fn host_args(&self) -> Vec<String> {
        let p = self.proj.to_str().unwrap().to_owned();
        [
            "--no-tui",
            "host",
            &p,
            "--listen",
            &self.addr,
            "--no-pair",
            "--no-mdns",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    }

    pub fn spawn_host(&self) -> Proc {
        let args = self.host_args();
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut h = Proc::spawn("host", &self.bin, &self.host_home, &a);
        h.wait_line("an indexed project", START, files_reported);
        h
    }

    pub fn spawn_guest(&self, g: &Guest, addr: &str, extra: &[&str]) -> Proc {
        let mnt = g.mnt.to_str().unwrap().to_owned();
        let mut args = vec![
            "--no-tui",
            "join",
            mnt.as_str(),
            "--connect",
            addr,
            "--host",
            "it-host",
        ];
        args.extend_from_slice(extra);
        let mut p = Proc::spawn(&g.label, &self.bin, &g.home, &args);
        let end = Instant::now() + START;
        while !is_mounted(&g.mnt) {
            assert!(p.alive(), "{} exited before mounting", g.label);
            assert!(
                Instant::now() < end,
                "{} did not mount within {START:?}",
                g.label
            );
            thread::sleep(Duration::from_millis(100));
        }
        p
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ent {
    Dir,
    File {
        len: u64,
        exec: bool,
        hash: Option<[u8; 32]>,
    },
    Link(PathBuf),
    Other(u32),
}

pub type Tree = BTreeMap<String, Ent>;

// relative path set with kinds; hashes only when asked, since every hash of a mount is a full read
pub fn snapshot(root: &Path, hash: bool, skip: &dyn Fn(&str) -> bool) -> io::Result<Tree> {
    let mut out = Tree::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        for e in fs::read_dir(&dir)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let r = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if skip(&r) {
                continue;
            }
            let p = e.path();
            let md = fs::symlink_metadata(&p)?;
            let ft = md.file_type();
            let ent = if ft.is_dir() {
                stack.push((p.clone(), r.clone()));
                Ent::Dir
            } else if ft.is_symlink() {
                Ent::Link(fs::read_link(&p)?)
            } else if ft.is_file() {
                let h = if hash {
                    let mut f = File::open(&p)?;
                    let mut hs = blake3::Hasher::new();
                    let mut buf = vec![0u8; 1 << 20];
                    loop {
                        let n = f.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        hs.update(&buf[..n]);
                    }
                    Some(*hs.finalize().as_bytes())
                } else {
                    None
                };
                Ent::File {
                    len: md.len(),
                    exec: md.permissions().mode() & 0o100 != 0,
                    hash: h,
                }
            } else {
                Ent::Other(md.mode())
            };
            out.insert(r, ent);
        }
    }
    Ok(out)
}

pub fn diff(a: &Tree, b: &Tree, max: usize) -> Vec<String> {
    let mut d = Vec::new();
    let short = |k: &str| {
        if k.len() <= 160 {
            return k.to_owned();
        }
        let tail: String = k
            .chars()
            .rev()
            .take(80)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("({} components) ...{tail}", k.split('/').count())
    };
    for (k, v) in a {
        match b.get(k) {
            None => d.push(format!("only on host: {} {v:?}", short(k))),
            Some(w) if w != v => d.push(format!("differs: {} host={v:?} guest={w:?}", short(k))),
            Some(_) => {}
        }
    }
    for (k, v) in b {
        if !a.contains_key(k) {
            d.push(format!("only on guest: {} {v:?}", short(k)));
        }
    }
    let total = d.len();
    d.truncate(max);
    if total > max {
        d.push(format!("... {} more", total - max));
    }
    d
}

// waits until both trees agree twice in a row (meta, then content); returns the last diff on timeout
pub fn converge(
    host: &Path,
    guest: &Path,
    timeout: Duration,
    skip: &dyn Fn(&str) -> bool,
) -> Result<Tree, Vec<String>> {
    let end = Instant::now() + timeout;
    let mut last = vec!["never compared".to_owned()];
    let mut agreed = 0;
    while Instant::now() < end {
        match (snapshot(host, false, skip), snapshot(guest, false, skip)) {
            (Ok(a), Ok(b)) if a == b => {
                match (snapshot(host, true, skip), snapshot(guest, true, skip)) {
                    (Ok(a), Ok(b)) if a == b => {
                        agreed += 1;
                        if agreed >= 2 {
                            return Ok(a);
                        }
                        thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                    (Ok(a), Ok(b)) => last = diff(&a, &b, 40),
                    (a, b) => {
                        last = vec![format!(
                            "hash walk failed: host {:?} guest {:?}",
                            a.err(),
                            b.err()
                        )]
                    }
                }
            }
            (Ok(a), Ok(b)) => last = diff(&a, &b, 40),
            (a, b) => {
                last = vec![format!(
                    "walk failed: host {:?} guest {:?}",
                    a.err(),
                    b.err()
                )]
            }
        }
        agreed = 0;
        thread::sleep(Duration::from_secs(1));
    }
    Err(last)
}

pub fn stray_names(root: &Path) -> Vec<String> {
    let mut bad = Vec::new();
    let Ok(t) = snapshot(root, false, &|r| r == ".git" || r.starts_with(".git/")) else {
        return vec![format!("walk of {} failed", root.display())];
    };
    for k in t.keys() {
        let n = k.rsplit('/').next().unwrap_or(k);
        if n.starts_with(".csync~")
            || n.ends_with(".orig")
            || n.ends_with(".rej")
            || n.ends_with(".bak")
            || n.ends_with(".A")
            || n.ends_with(".B")
            || n.contains("conflict")
        {
            bad.push(k.clone());
        }
    }
    bad
}

// thread stacks of a live process, for hang reports; empty when gdb is missing or ptrace is denied
pub fn stacks(pid: u32) -> String {
    Command::new("gdb")
        .args([
            "-p",
            &pid.to_string(),
            "-batch",
            "-ex",
            "thread apply all bt",
        ])
        .stdin(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

pub fn proc_stat(pid: u32) -> Option<(u64, u64, u64, u64)> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
    };
    let rss_kb = field("VmRSS:")?;
    let threads = field("Threads:")?;
    let fds = fs::read_dir(format!("/proc/{pid}/fd")).ok()?.count() as u64;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit(')').next()?;
    let f: Vec<&str> = after.split_whitespace().collect();
    let ticks = f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?;
    Some((rss_kb, threads, fds, ticks))
}

// a tcp relay between guest and host that the test can blackhole, cut or slow down
pub struct Relay {
    pub addr: String,
    pub hold: Arc<AtomicBool>,
    pub delay_ms: Arc<AtomicU64>,
    conns: Arc<Mutex<Vec<TcpStream>>>,
    stop: Arc<AtomicBool>,
}

impl Relay {
    pub fn new(target: &str) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").expect("relay bind");
        let addr = l.local_addr().unwrap().to_string();
        let hold = Arc::new(AtomicBool::new(false));
        let delay_ms = Arc::new(AtomicU64::new(0));
        let conns: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let target = target.to_owned();
        let (h, d, c, s) = (hold.clone(), delay_ms.clone(), conns.clone(), stop.clone());
        l.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                match l.accept() {
                    Ok((down, _)) => {
                        let _ = down.set_nonblocking(false);
                        if h.load(Ordering::Relaxed) {
                            // a partition: the connect itself must not complete into the host
                            c.lock().unwrap().push(down);
                            continue;
                        }
                        let Ok(up) = TcpStream::connect(&target) else {
                            continue;
                        };
                        let _ = up.set_nodelay(true);
                        let _ = down.set_nodelay(true);
                        c.lock().unwrap().push(down.try_clone().unwrap());
                        c.lock().unwrap().push(up.try_clone().unwrap());
                        for (from, to) in [
                            (down.try_clone().unwrap(), up.try_clone().unwrap()),
                            (up, down),
                        ] {
                            let (h, d) = (h.clone(), d.clone());
                            thread::spawn(move || pump(from, to, &h, &d));
                        }
                    }
                    Err(_) => thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Self {
            addr,
            hold,
            delay_ms,
            conns,
            stop,
        }
    }

    // resets every relayed connection, as a link flap would
    pub fn cut(&self) {
        for c in self.conns.lock().unwrap().drain(..) {
            let _ = c.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.cut();
    }
}

fn pump(mut from: TcpStream, mut to: TcpStream, hold: &AtomicBool, delay: &AtomicU64) {
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        // while held, bytes are swallowed after a pause: the peer sees silence, not a reset
        while hold.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(50));
        }
        let d = delay.load(Ordering::Relaxed);
        if d > 0 {
            thread::sleep(Duration::from_millis(d));
        }
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

// splitmix64: small, seedable and good enough to drive an op generator
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    pub fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

pub fn seed_from_env(name: &str) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(1, |d| d.as_nanos() as u64)
        })
}
