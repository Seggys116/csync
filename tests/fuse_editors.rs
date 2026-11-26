// what editors and file watchers on the guest see when the host changes the tree: the inotify events
// a native directory would raise, also for bursts larger than the injector queue

#[test]
fn fuse_editors() {
    #[cfg(target_os = "linux")]
    ed::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE editor test runs on Linux only");
}

#[test]
fn fuse_torn_reads() {
    #[cfg(target_os = "linux")]
    tr::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE torn read test runs on Linux only");
}

#[cfg(target_os = "linux")]
mod common;

// guest readers racing host saves of different lengths must each see one whole version
#[cfg(target_os = "linux")]
mod tr {
    use super::common::*;
    use std::{
        fs::{self, File},
        io::Read,
        os::unix::fs::FileExt,
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{
                AtomicBool, AtomicUsize,
                Ordering::{Relaxed, SeqCst},
            },
        },
        thread,
        time::{Duration, Instant},
    };

    const ROUNDS: usize = 6;
    const SAVES: usize = 250;

    // lengths cycle through several pages, one page and a partial page
    fn body(i: usize) -> String {
        let lines = [900, 40, 300][i % 3];
        let mut s = String::with_capacity(lines * 13 + 20);
        for k in 0..lines {
            s.push_str(&format!("{i:07} {k:04}\n"));
        }
        s.push_str(&format!("end {i:07} {lines}\n"));
        s
    }

    fn check(b: &[u8]) -> Result<(), String> {
        let v = std::str::from_utf8(b.get(..7).unwrap_or_default())
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        match v {
            Some(i) if body(i).as_bytes() == b => Ok(()),
            _ => {
                let tail = String::from_utf8_lossy(&b[b.len().saturating_sub(24)..]).into_owned();
                let want = v.map(|i| body(i).len());
                Err(format!(
                    "len {} (version {v:?} is {want:?}) ends {tail:?}",
                    b.len()
                ))
            }
        }
    }

    fn reader(p: PathBuf, stop: Arc<AtomicBool>, quiet: Arc<AtomicUsize>, mode: u8) -> Seen {
        let mut s = Seen::default();
        let mut held: Option<(File, usize)> = None;
        let mut buf = vec![0u8; 1 << 16];
        while !stop.load(Relaxed) {
            let settled = quiet.load(SeqCst);
            let mut opened = settled;
            let r: std::io::Result<Vec<u8>> = match mode {
                0 => fs::read(&p),
                1 => File::open(&p).and_then(|mut f| {
                    let mut out = Vec::new();
                    loop {
                        let n = f.read(&mut buf[..4096])?;
                        if n == 0 {
                            return Ok(out);
                        }
                        out.extend_from_slice(&buf[..n]);
                    }
                }),
                // a held handle preads the whole file again and again
                _ => {
                    if held.is_none() || s.reads % 64 == 0 {
                        held = File::open(&p).ok().map(|f| (f, settled));
                    }
                    match &held {
                        Some((f, at)) => {
                            opened = *at;
                            f.read_at(&mut buf, 0).map(|n| buf[..n].to_vec())
                        }
                        None => continue,
                    }
                }
            };
            // only a file opened after the last save and read before the next must be that save
            let strict = settled > 0 && opened == settled && quiet.load(SeqCst) == settled;
            let res = match r {
                Ok(b) if strict && b != body(settled - 1).as_bytes() => {
                    check(&b).and(Err(format!("an older version {:?}", b.get(..7))))
                }
                Ok(b) => check(&b),
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
                Err(e) => {
                    s.errors.push(format!("mode {mode}: {e}"));
                    Ok(())
                }
            };
            if let Err(e) = res {
                let e = format!("mode {mode}: {e}");
                if strict {
                    s.quiet.push(e);
                } else {
                    s.burst.push(e);
                }
            }
            s.reads += 1;
        }
        s
    }

    #[derive(Default)]
    struct Seen {
        reads: u32,
        burst: Vec<String>,
        errors: Vec<String>,
        quiet: Vec<String>,
    }

    pub fn run() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("torn", write_project);
        let g = w.guest("g");
        let _host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        let (m, proj) = (g.mnt.clone(), w.proj.clone());
        fs::create_dir_all(proj.join("tr")).unwrap();
        fs::write(proj.join("tr/f.txt"), body(0)).unwrap();
        let f = m.join("tr/f.txt");
        eventually("tr/f.txt on the guest", SYNC, || {
            read(&f).is_some_and(|s| s == body(0))
        });
        let stop = Arc::new(AtomicBool::new(false));
        let quiet = Arc::new(AtomicUsize::new(0));
        let readers: Vec<_> = [0u8, 0, 1, 2, 2]
            .into_iter()
            .map(|mode| {
                let (p, stop, quiet) = (f.clone(), stop.clone(), quiet.clone());
                thread::spawn(move || reader(p, stop, quiet, mode))
            })
            .collect();
        let start = Instant::now();
        let (mut last, mut arrived) = (0, true);
        for round in 0..ROUNDS {
            quiet.store(0, SeqCst);
            last = save_loop(&proj.join("tr"), round * SAVES);
            let (want, end) = (body(last), Instant::now() + SYNC);
            while read(&f).is_none_or(|s| s != want) && Instant::now() < end {
                thread::sleep(Duration::from_millis(20));
            }
            arrived = read(&f).is_some_and(|s| s == want);
            if !arrived {
                break;
            }
            // nothing changes now: every read until the next burst must be the last save, whole
            quiet.store(last + 1, SeqCst);
            thread::sleep(Duration::from_millis(300));
        }
        // the readers stop before any assert, so a failure cannot leave them blocking the unmount
        stop.store(true, Relaxed);
        let mut all = Seen::default();
        for r in readers {
            let s = r.join().unwrap();
            all.reads += s.reads;
            all.burst.extend(s.burst);
            all.quiet.extend(s.quiet);
            all.errors.extend(s.errors);
        }
        eprintln!(
            "{} reads in {:?}, {} torn during saves, {} errors, {} wrong after them",
            all.reads,
            start.elapsed(),
            all.burst.len(),
            all.errors.len(),
            all.quiet.len()
        );
        assert!(arrived, "save {last} never showed on the guest whole");
        assert!(all.reads > 1000, "only {} reads", all.reads);
        assert!(
            all.quiet.is_empty(),
            "{} reads after the last save of {last} were not it: {:?}",
            all.quiet.len(),
            &all.quiet[..all.quiet.len().min(8)]
        );
        assert!(
            all.burst.is_empty() && all.errors.is_empty(),
            "{} of {} reads were not one whole version and {} failed: {:?}",
            all.burst.len(),
            all.reads,
            all.errors.len(),
            all.burst
                .iter()
                .chain(&all.errors)
                .take(8)
                .collect::<Vec<_>>()
        );
        guest.quit(Duration::from_secs(30));
    }

    // atomic saves (temp file renamed over) and in-place saves that grow the file
    fn save_loop(dir: &Path, base: usize) -> usize {
        let (f, tmp) = (dir.join("f.txt"), dir.join(".f.txt.tmp"));
        for i in base + 1..=base + SAVES {
            if i % 4 == 3 && i % 3 != 1 {
                // one write over the whole, shorter file: an in-place save that only grows it
                let fd = fs::OpenOptions::new().write(true).open(&f).unwrap();
                fd.write_all_at(body(i).as_bytes(), 0).unwrap();
            } else {
                fs::write(&tmp, body(i)).unwrap();
                fs::rename(&tmp, &f).unwrap();
            }
            thread::sleep(Duration::from_millis(2));
        }
        base + SAVES
    }
}

#[cfg(target_os = "linux")]
mod ed {
    use super::common::*;
    use rustix::fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags};
    use rustix::io::Errno;
    use std::{
        collections::{HashMap, HashSet},
        fs,
        mem::MaybeUninit,
        os::fd::OwnedFd,
        path::Path,
        thread,
        time::{Duration, Instant},
    };

    const SYNC: Duration = Duration::from_secs(20);
    // more than the injector queue holds, fewer than the kernel's default inotify queue
    const BURST: usize = 6_000;

    #[derive(Debug, Clone)]
    struct Ev {
        path: String,
        mask: ReadFlags,
        cookie: u32,
    }

    struct Watch {
        fd: OwnedFd,
        wds: HashMap<i32, String>,
        buf: Vec<MaybeUninit<u8>>,
    }

    impl Watch {
        fn new() -> Self {
            let fd = inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC).unwrap();
            Self {
                fd,
                wds: HashMap::new(),
                buf: vec![MaybeUninit::uninit(); 1 << 20],
            }
        }

        fn add(&mut self, dir: &Path, rel: &str) {
            let mask = WatchFlags::CREATE
                | WatchFlags::MODIFY
                | WatchFlags::ATTRIB
                | WatchFlags::CLOSE_WRITE
                | WatchFlags::DELETE
                | WatchFlags::DELETE_SELF
                | WatchFlags::MOVED_FROM
                | WatchFlags::MOVED_TO
                | WatchFlags::MOVE_SELF;
            let wd = inotify::add_watch(&self.fd, dir.join(rel), mask)
                .unwrap_or_else(|e| panic!("watch {rel}: {e}"));
            self.wds.insert(wd, rel.to_owned());
        }

        // events until `quiet` passes without one, or `cap` in all
        fn collect(&mut self, quiet: Duration, cap: Duration) -> Vec<Ev> {
            let (start, mut last) = (Instant::now(), Instant::now());
            let mut out = Vec::new();
            while start.elapsed() < cap && last.elapsed() < quiet {
                let mut r = inotify::Reader::new(&self.fd, &mut self.buf);
                loop {
                    match r.next() {
                        Ok(e) => {
                            let base = self.wds.get(&e.wd()).cloned().unwrap_or_default();
                            let name = e.file_name().map(|n| n.to_string_lossy().into_owned());
                            let path = match name {
                                Some(n) if !n.is_empty() && base.is_empty() => n,
                                Some(n) if !n.is_empty() => format!("{base}/{n}"),
                                _ => base,
                            };
                            out.push(Ev {
                                path,
                                mask: e.events(),
                                cookie: e.cookie(),
                            });
                            last = Instant::now();
                        }
                        Err(Errno::AGAIN) => break,
                        Err(e) => panic!("inotify read: {e}"),
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
            out
        }
    }

    fn has(evs: &[Ev], path: &str, f: ReadFlags) -> bool {
        evs.iter().any(|e| e.path == path && e.mask.contains(f))
    }

    fn pos(evs: &[Ev], path: &str, f: ReadFlags) -> Option<usize> {
        evs.iter()
            .position(|e| e.path == path && e.mask.contains(f))
    }

    pub fn run() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("editors", write_project);
        let g = w.guest("g");
        let _host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        let m = g.mnt.clone();
        eventually("README on the guest", SYNC, || m.join("README.md").exists());

        created_file_is_modified(&m, &w.proj);
        rename_raises_no_attrib(&m, &w.proj);
        rename_over_unlinks_target(&m, &w.proj);
        atomic_save_keeps_the_name(&m, &w.proj);
        subtree_removal(&m, &w.proj);
        burst_is_never_silent(&m, &w.proj);

        guest.quit(Duration::from_secs(30));
    }

    // a host file born with content shows IN_CREATE, then IN_MODIFY, then IN_CLOSE_WRITE
    fn created_file_is_modified(m: &Path, proj: &Path) {
        fs::create_dir_all(proj.join("cm")).unwrap();
        eventually("cm on the guest", SYNC, || m.join("cm").is_dir());
        // written in the ignored target/ and moved in, so the host sees the file appear with its content
        fs::create_dir_all(proj.join("target")).unwrap();
        fs::write(proj.join("target/new.txt"), "content\n").unwrap();
        let mut w = Watch::new();
        w.add(m, "cm");
        fs::rename(proj.join("target/new.txt"), proj.join("cm/new.txt")).unwrap();
        let evs = w.collect(Duration::from_secs(2), SYNC);
        let c = pos(&evs, "cm/new.txt", ReadFlags::CREATE);
        let md = pos(&evs, "cm/new.txt", ReadFlags::MODIFY);
        let cw = evs
            .iter()
            .rposition(|e| e.path == "cm/new.txt" && e.mask.contains(ReadFlags::CLOSE_WRITE));
        assert!(
            c.is_some() && md.is_some() && cw.is_some(),
            "create events: {evs:?}"
        );
        assert!(c < md && md < cw, "create event order: {evs:?}");
        assert_eq!(read(&m.join("cm/new.txt")).as_deref(), Some("content\n"));
    }

    // a host rename only touches ctime, which raises no IN_ATTRIB on a native filesystem
    fn rename_raises_no_attrib(m: &Path, proj: &Path) {
        fs::create_dir_all(proj.join("rn")).unwrap();
        fs::write(proj.join("rn/a.txt"), "a\n").unwrap();
        eventually("rn/a.txt on the guest", SYNC, || {
            m.join("rn/a.txt").exists()
        });
        let mut w = Watch::new();
        w.add(m, "rn");
        fs::rename(proj.join("rn/a.txt"), proj.join("rn/b.txt")).unwrap();
        let evs = w.collect(Duration::from_secs(2), SYNC);
        let from = evs
            .iter()
            .find(|e| e.path == "rn/a.txt" && e.mask.contains(ReadFlags::MOVED_FROM));
        let to = evs
            .iter()
            .find(|e| e.path == "rn/b.txt" && e.mask.contains(ReadFlags::MOVED_TO));
        match (from, to) {
            (Some(f), Some(t)) => assert!(f.cookie != 0 && f.cookie == t.cookie, "{evs:?}"),
            _ => panic!("rename events: {evs:?}"),
        }
        assert!(
            !evs.iter().any(|e| e.mask.contains(ReadFlags::ATTRIB)),
            "rename raised IN_ATTRIB: {evs:?}"
        );
    }

    // an atomic save on the host (temp file renamed over the original) unlinks the original inode, so a
    // watch on that file ends with IN_DELETE_SELF as natively
    fn rename_over_unlinks_target(m: &Path, proj: &Path) {
        fs::create_dir_all(proj.join("ro")).unwrap();
        fs::write(proj.join("ro/t.txt"), "old\n").unwrap();
        fs::write(proj.join("ro/.t.txt.tmp"), "new\n").unwrap();
        eventually("ro files on the guest", SYNC, || {
            m.join("ro/t.txt").exists() && m.join("ro/.t.txt.tmp").exists()
        });
        let mut w = Watch::new();
        w.add(m, "ro");
        w.add(m, "ro/t.txt");
        fs::rename(proj.join("ro/.t.txt.tmp"), proj.join("ro/t.txt")).unwrap();
        let evs = w.collect(Duration::from_secs(2), SYNC);
        assert!(has(&evs, "ro/t.txt", ReadFlags::MOVED_TO), "{evs:?}");
        let to = pos(&evs, "ro/t.txt", ReadFlags::MOVED_TO);
        let gone = pos(&evs, "ro/t.txt", ReadFlags::DELETE_SELF);
        assert!(
            gone.is_some(),
            "replaced file raised no IN_DELETE_SELF: {evs:?}"
        );
        assert!(to < gone, "IN_DELETE_SELF before the move: {evs:?}");
        assert_eq!(read(&m.join("ro/t.txt")).as_deref(), Some("new\n"));
    }

    // a host editor saving by rename never makes the name vanish for a guest reader, and every
    // read sees one whole version
    fn atomic_save_keeps_the_name(m: &Path, proj: &Path) {
        fs::create_dir_all(proj.join("as")).unwrap();
        let body = |i: usize| format!("version {i}\n").repeat(40);
        fs::write(proj.join("as/f.txt"), body(0)).unwrap();
        eventually("as/f.txt on the guest", SYNC, || {
            m.join("as/f.txt").exists()
        });
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let (stop, p) = (stop.clone(), m.join("as/f.txt"));
            thread::spawn(move || {
                let (mut reads, mut bad) = (0u32, Vec::new());
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    match fs::read_to_string(&p) {
                        Ok(s) => {
                            let first = s.lines().next().unwrap_or_default().to_owned();
                            if s.is_empty() || s != format!("{first}\n").repeat(40) {
                                bad.push(format!("torn read {:?}", &s[..s.len().min(40)]));
                            }
                        }
                        Err(e) if e.raw_os_error() == Some(libc::EIO) => {}
                        Err(e) => bad.push(e.to_string()),
                    }
                    reads += 1;
                }
                (reads, bad)
            })
        };
        let tmp = proj.join("as/.f.txt.tmp");
        for i in 1..=1000 {
            fs::write(&tmp, body(i)).unwrap();
            fs::rename(&tmp, proj.join("as/f.txt")).unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        thread::sleep(Duration::from_millis(500));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let (reads, bad) = reader.join().unwrap();
        assert!(reads > 100, "only {reads} reads");
        assert!(
            bad.is_empty(),
            "{} of {reads} reads failed: {:?}",
            bad.len(),
            &bad[..bad.len().min(5)]
        );
        eventually("the last save on the guest", SYNC, || {
            read(&m.join("as/f.txt")) == Some(body(1000))
        });
    }

    // rm -r on the host reaches a recursive watcher bottom-up: every entry and every watched directory
    fn subtree_removal(m: &Path, proj: &Path) {
        fs::create_dir_all(proj.join("rt/a/b")).unwrap();
        fs::write(proj.join("rt/a/f1"), "1").unwrap();
        fs::write(proj.join("rt/a/b/f2"), "2").unwrap();
        fs::write(proj.join("rt/top"), "t").unwrap();
        eventually("rt/a/b/f2 on the guest", SYNC, || {
            m.join("rt/a/b/f2").exists()
        });
        let mut w = Watch::new();
        for d in ["rt", "rt/a", "rt/a/b"] {
            w.add(m, d);
        }
        fs::remove_dir_all(proj.join("rt")).unwrap();
        let evs = w.collect(Duration::from_secs(2), SYNC);
        for f in ["rt/a/f1", "rt/a/b/f2", "rt/top"] {
            assert!(
                has(&evs, f, ReadFlags::DELETE),
                "no delete for {f}: {evs:?}"
            );
        }
        for d in ["rt", "rt/a", "rt/a/b"] {
            let gone = pos(&evs, d, ReadFlags::DELETE_SELF);
            assert!(gone.is_some(), "no IN_DELETE_SELF for {d}: {evs:?}");
        }
        assert!(
            pos(&evs, "rt/a/b/f2", ReadFlags::DELETE) < pos(&evs, "rt/a/b", ReadFlags::DELETE_SELF)
                && pos(&evs, "rt/a/b", ReadFlags::DELETE_SELF)
                    < pos(&evs, "rt/a", ReadFlags::DELETE_SELF),
            "subtree deleted out of order: {evs:?}"
        );
        assert!(!m.join("rt").exists());
    }

    // a burst larger than the injector queue must reach a watcher as events or as an overflow, never as silence
    fn burst_is_never_silent(m: &Path, proj: &Path) {
        let d = proj.join("burst");
        fs::create_dir_all(&d).unwrap();
        for i in 0..BURST {
            fs::write(d.join(format!("f{i}")), "a\n").unwrap();
        }
        eventually("burst files on the guest", Duration::from_secs(60), || {
            fs::read_dir(m.join("burst")).is_ok_and(|r| r.count() == BURST)
        });
        let mut w = Watch::new();
        w.add(m, "burst");
        for i in 0..BURST {
            fs::write(d.join(format!("f{i}")), "b\n").unwrap();
        }
        let evs = w.collect(Duration::from_secs(3), Duration::from_secs(120));
        let overflow = evs
            .iter()
            .any(|e| e.mask.contains(ReadFlags::QUEUE_OVERFLOW));
        let seen: HashSet<&str> = evs
            .iter()
            .filter(|e| e.mask.intersects(ReadFlags::MODIFY | ReadFlags::ATTRIB))
            .map(|e| e.path.as_str())
            .collect();
        assert!(
            overflow || seen.len() == BURST,
            "{} of {BURST} host edits raised an event and no overflow was reported",
            seen.len()
        );
        eventually("the burst content on the guest", SYNC, || {
            read(&m.join(format!("burst/f{}", BURST - 1))).as_deref() == Some("b\n")
        });
    }
}
