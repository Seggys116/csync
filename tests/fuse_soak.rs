// randomised differential soak: a host and a guest edit the same tree at once, then both sides must agree exactly
// CSYNC_SOAK_SECS (default 20), CSYNC_SOAK_SEED to replay, CSYNC_SOAK_RATE ops per second per side (default 20)

#[test]
fn fuse_soak() {
    #[cfg(target_os = "linux")]
    soak::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE soak test runs on Linux only");
}

// minimal repro distilled from the soak: an atomic save whose rename is refused must leave no temp on either side
#[test]
fn refused_atomic_save_leaves_no_tmp() {
    #[cfg(target_os = "linux")]
    soak::refused_atomic_save();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE soak test runs on Linux only");
}

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod soak {
    use super::common::*;
    use std::{
        collections::BTreeMap,
        fs::{self, File, OpenOptions},
        io::{self, Write},
        os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    const HOT: [&str; 2] = ["shared.txt", "d0/hot.txt"];
    const LINE: usize = 32;
    const LINES: usize = 64;
    const DIRS: [&str; 7] = ["", "d0", "d1", "d1/sub", "d2", "deep/a/b/c", "üni"];
    const LONG_LEN: usize = 240;
    const HANG: Duration = Duration::from_secs(90);
    const QUIESCE: Duration = Duration::from_secs(120);
    const BASE_RULES: &str = "target/\n*.log\n";

    fn names() -> Vec<String> {
        let mut v: Vec<String> = (0..8).map(|i| format!("f{i}.txt")).collect();
        v.extend(
            [
                "Case.txt",
                "case.txt",
                "名前.txt",
                "émoji_ñ.rs",
                "empty",
                "big.bin",
                "x",
            ]
            .map(str::to_owned),
        );
        v.push(format!("{}.txt", "L".repeat(LONG_LEN)));
        v
    }

    // anything under target/, *.log, the git dir, and scratch/ while its rule may be on
    fn ignored(rel: &str, scratch_too: bool) -> bool {
        rel == ".git"
            || rel.starts_with(".git/")
            || rel.split('/').any(|c| c == "target" || c.ends_with(".log"))
            || (scratch_too && (rel == "scratch" || rel.starts_with("scratch/")))
    }

    fn hot_body(tag: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(LINE * LINES);
        for i in 0..LINES {
            out.extend_from_slice(fixed_line(&format!("{i:02} {tag}")).as_slice());
        }
        out
    }

    fn fixed_line(s: &str) -> [u8; LINE] {
        let mut l = [b' '; LINE];
        let b = s.as_bytes();
        let n = b.len().min(LINE - 1);
        l[..n].copy_from_slice(&b[..n]);
        l[LINE - 1] = b'\n';
        l
    }

    fn content(rng: &mut Rng, tok: &str) -> Vec<u8> {
        let size = match rng.below(100) {
            0..8 => 0,
            8..48 => rng.below(512),
            48..78 => 512 + rng.below(16 << 10),
            78..93 => (16 << 10) + rng.below(240 << 10),
            93..98 => (256 << 10) + rng.below(2 << 20),
            _ => (2 << 20) + rng.below(6 << 20),
        } as usize;
        if size == 0 {
            return Vec::new();
        }
        let mut v = format!("{tok}\n").into_bytes();
        let binary = rng.chance(20);
        while v.len() < size {
            if binary {
                v.extend_from_slice(&rng.next().to_le_bytes());
            } else {
                v.extend_from_slice(
                    format!("line {} of {tok} {}\n", v.len(), rng.next() % 1000).as_bytes(),
                );
            }
        }
        v.truncate(size.max(tok.len() + 1));
        v
    }

    #[derive(Default)]
    struct Stats {
        ops: AtomicU64,
        errs: Mutex<BTreeMap<String, u64>>,
        refused: Mutex<Vec<String>>,
        ignored_made: Mutex<Vec<String>>,
        last_op: Mutex<String>,
    }

    impl Stats {
        fn note(&self, op: &str, r: &io::Result<()>) -> Option<i32> {
            self.ops.fetch_add(1, Ordering::Relaxed);
            let e = errno(r);
            if let Err(err) = r {
                let k = format!("{op}:{}", e.map_or_else(|| err.kind().to_string(), errname));
                *self.errs.lock().unwrap().entry(k).or_default() += 1;
            }
            e
        }
    }

    fn errname(e: i32) -> String {
        match e {
            libc::ENOENT => "ENOENT".into(),
            libc::EEXIST => "EEXIST".into(),
            libc::ENOTDIR => "ENOTDIR".into(),
            libc::EISDIR => "EISDIR".into(),
            libc::ENOTEMPTY => "ENOTEMPTY".into(),
            libc::EINVAL => "EINVAL".into(),
            libc::ECANCELED => "ECANCELED".into(),
            libc::EIO => "EIO".into(),
            libc::ENOTCONN => "ENOTCONN".into(),
            libc::EROFS => "EROFS".into(),
            libc::EPERM => "EPERM".into(),
            libc::EACCES => "EACCES".into(),
            libc::EBUSY => "EBUSY".into(),
            libc::EXDEV => "EXDEV".into(),
            libc::ENAMETOOLONG => "ENAMETOOLONG".into(),
            libc::ETIMEDOUT => "ETIMEDOUT".into(),
            libc::ENOSPC => "ENOSPC".into(),
            libc::ELOOP => "ELOOP".into(),
            other => format!("errno{other}"),
        }
    }

    struct Side {
        root: PathBuf,
        tag: char,
        guest: bool,
        stats: Arc<Stats>,
        n: u64,
        names: Vec<String>,
    }

    impl Side {
        fn tok(&mut self) -> String {
            self.n += 1;
            format!("@@{}{}@@", self.tag, self.n)
        }

        // a random existing entry below a random walk from the root, never the git dir, ignored or hot paths
        fn pick(&self, rng: &mut Rng, want_dir: bool) -> Option<String> {
            let mut rel = String::new();
            let mut best: Option<String> = None;
            for _ in 0..6 {
                let dir = if rel.is_empty() {
                    self.root.clone()
                } else {
                    self.root.join(&rel)
                };
                let Ok(rd) = fs::read_dir(&dir) else { break };
                let mut kids: Vec<(String, bool)> = rd
                    .flatten()
                    .filter_map(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        let r = if rel.is_empty() {
                            n
                        } else {
                            format!("{rel}/{n}")
                        };
                        let is_dir = e.file_type().ok()?.is_dir();
                        let skip = ignored(&r, false)
                            || r == ".gitignore"
                            || HOT.contains(&r.as_str())
                            || r == "scratch";
                        (!skip).then_some((r, is_dir))
                    })
                    .collect();
                kids.sort();
                if kids.is_empty() {
                    break;
                }
                let (r, is_dir) = rng.pick(&kids).clone();
                if is_dir == want_dir {
                    best = Some(r.clone());
                    if rng.chance(50) {
                        break;
                    }
                }
                if !is_dir {
                    break;
                }
                rel = r;
            }
            best
        }

        fn rand_dir(&self, rng: &mut Rng) -> String {
            if rng.chance(30)
                && let Some(d) = self.pick(rng, true)
            {
                return d;
            }
            (*rng.pick(&DIRS)).to_owned()
        }

        fn rand_file(&self, rng: &mut Rng) -> String {
            let d = self.rand_dir(rng);
            let n = rng.pick(&self.names).clone();
            if d.is_empty() { n } else { format!("{d}/{n}") }
        }

        fn p(&self, rel: &str) -> PathBuf {
            self.root.join(rel)
        }

        // commit point on the guest: fsync or close, whichever reports first
        fn finish(&self, rng: &mut Rng, f: File) -> io::Result<()> {
            if rng.chance(50) {
                let r = f.sync_all();
                let c = close_checked(f);
                r.and(c)
            } else {
                close_checked(f)
            }
        }

        fn write_file(&mut self, rng: &mut Rng, rel: &str, body: &[u8]) -> io::Result<()> {
            let p = self.p(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&p)?;
            f.write_all(body)?;
            self.finish(rng, f)
        }

        fn record(&self, op: &str, tok: Option<&str>, r: io::Result<()>) {
            if self.stats.note(op, &r) == Some(libc::ECANCELED)
                && let Some(t) = tok
            {
                self.stats.refused.lock().unwrap().push(t.to_owned());
            }
        }

        fn step(&mut self, rng: &mut Rng) {
            let roll = rng.below(1000);
            let op;
            let r: io::Result<()>;
            let mut tok = None;
            match roll {
                0..180 => {
                    op = "write";
                    let rel = self.rand_file(rng);
                    let t = self.tok();
                    let body = content(rng, &t);
                    if !body.is_empty() {
                        tok = Some(t);
                    }
                    r = self.write_file(rng, &rel, &body);
                }
                180..260 => {
                    op = "append";
                    let rel = self.pick(rng, false).unwrap_or_else(|| self.rand_file(rng));
                    let t = self.tok();
                    r = (|| {
                        let mut f = OpenOptions::new()
                            .append(true)
                            .create(true)
                            .custom_flags(libc::O_NOFOLLOW)
                            .open(self.p(&rel))?;
                        f.write_all(format!("{t} appended\n").as_bytes())?;
                        self.finish(rng, f)
                    })();
                    tok = Some(t);
                }
                260..300 => {
                    op = "truncate";
                    r = match self.pick(rng, false) {
                        Some(rel) => (|| {
                            let f = OpenOptions::new()
                                .write(true)
                                .custom_flags(libc::O_NOFOLLOW)
                                .open(self.p(&rel))?;
                            let len = f.metadata()?.len();
                            f.set_len(rng.below(len + 1))?;
                            self.finish(rng, f)
                        })(),
                        None => Ok(()),
                    };
                }
                300..460 => {
                    op = "hotline";
                    let rel = *rng.pick(&HOT);
                    let t = self.tok();
                    let p = self.p(rel);
                    r = (|| {
                        let ok = fs::metadata(&p).is_ok_and(|m| m.len() == (LINE * LINES) as u64);
                        if !ok {
                            return self.write_file(rng, rel, &hot_body(&t));
                        }
                        let f = OpenOptions::new().read(true).write(true).open(&p)?;
                        let k = rng.below(LINES as u64) as usize;
                        f.write_at(&fixed_line(&format!("{k:02} {t}")), (k * LINE) as u64)?;
                        self.finish(rng, f)
                    })();
                    tok = Some(t);
                }
                460..520 => {
                    op = "delete";
                    r = self
                        .pick(rng, false)
                        .map_or(Ok(()), |rel| fs::remove_file(self.p(&rel)));
                }
                520..590 => {
                    op = "rename";
                    let to = self.rand_file(rng);
                    r = self.pick(rng, false).map_or(Ok(()), |rel| {
                        if let Some(parent) = self.p(&to).parent() {
                            let _ = fs::create_dir_all(parent);
                        }
                        fs::rename(self.p(&rel), self.p(&to))
                    });
                }
                590..680 => {
                    op = "atomic";
                    let rel = self.rand_file(rng);
                    let t = self.tok();
                    let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel.as_str()));
                    let short: String = name.chars().take(40).collect();
                    let tmp = if dir.is_empty() {
                        format!(".{short}.tmp{}", self.n)
                    } else {
                        format!("{dir}/.{short}.tmp{}", self.n)
                    };
                    let mut body = content(rng, &t);
                    if body.is_empty() {
                        body = format!("{t}\n").into_bytes();
                    }
                    r = self
                        .write_file(rng, &tmp, &body)
                        .and_then(|()| fs::rename(self.p(&tmp), self.p(&rel)));
                    tok = Some(t);
                }
                680..720 => {
                    op = "mkdirp";
                    let base = self.rand_dir(rng);
                    let mut rel = base;
                    for _ in 0..1 + rng.below(4) {
                        let c = format!("n{}", rng.below(5));
                        rel = if rel.is_empty() {
                            c
                        } else {
                            format!("{rel}/{c}")
                        };
                    }
                    r = fs::create_dir_all(self.p(&rel));
                }
                720..735 => {
                    op = "storm";
                    let base = format!("storm{}", rng.below(3));
                    r = (|| {
                        for i in 0..20 {
                            fs::create_dir_all(self.p(&format!("{base}/s{}/t{i}", i % 4)))?;
                        }
                        for i in 0..10 {
                            fs::write(
                                self.p(&format!("{base}/s{}/t{i}/leaf{}", i % 4, self.tag)),
                                format!("{i}\n"),
                            )?;
                        }
                        Ok(())
                    })();
                }
                735..765 => {
                    op = "rmrf";
                    r = self
                        .pick(rng, true)
                        .map_or(Ok(()), |rel| fs::remove_dir_all(self.p(&rel)));
                }
                765..790 => {
                    op = "renamedir";
                    let to = format!("{}/m{}", self.rand_dir(rng), rng.below(4));
                    let to = to.trim_start_matches('/').to_owned();
                    r = self
                        .pick(rng, true)
                        .map_or(Ok(()), |rel| fs::rename(self.p(&rel), self.p(&to)));
                }
                790..830 => {
                    op = "chmod";
                    r = self.pick(rng, false).map_or(Ok(()), |rel| {
                        let p = self.p(&rel);
                        let m = fs::symlink_metadata(&p)?;
                        if m.file_type().is_symlink() {
                            return Ok(());
                        }
                        let mode = m.permissions().mode() & 0o777;
                        fs::set_permissions(&p, fs::Permissions::from_mode(mode ^ 0o111))
                    });
                }
                830..860 => {
                    op = "symlink";
                    let dir = self.rand_dir(rng);
                    let depth = if dir.is_empty() {
                        0
                    } else {
                        dir.split('/').count()
                    };
                    let target = format!("{}{}", "../".repeat(depth), self.rand_file(rng));
                    let rel = if dir.is_empty() {
                        format!("lnk{}", rng.below(6))
                    } else {
                        format!("{dir}/lnk{}", rng.below(6))
                    };
                    let _ = fs::create_dir_all(self.p(&dir));
                    let p = self.p(&rel);
                    r = match fs::symlink_metadata(&p) {
                        Ok(m) if m.file_type().is_symlink() => {
                            fs::remove_file(&p).and_then(|()| symlink(&target, &p))
                        }
                        Ok(_) => Ok(()),
                        Err(_) => symlink(&target, &p),
                    };
                }
                860..880 => {
                    op = "caserename";
                    let d = self.rand_dir(rng);
                    let j = |n: &str| {
                        if d.is_empty() {
                            n.to_owned()
                        } else {
                            format!("{d}/{n}")
                        }
                    };
                    let (a, b) = (j("Case.txt"), j("case.txt"));
                    r = if self.p(&a).exists() {
                        fs::rename(self.p(&a), self.p(&b))
                    } else {
                        fs::rename(self.p(&b), self.p(&a))
                    };
                }
                880..910 => {
                    op = "ignored";
                    let rel = if rng.chance(50) {
                        format!("target/{}_{}.o", self.tag, self.n)
                    } else {
                        format!("{}_{}.log", self.tag, self.n)
                    };
                    self.n += 1;
                    self.stats.ignored_made.lock().unwrap().push(rel.clone());
                    r = self.write_file(rng, &rel, b"ignored\n");
                }
                910..940 => {
                    op = "scratch";
                    let rel = format!("scratch/{}_{}.txt", self.tag, rng.below(12));
                    let t = self.tok();
                    r = self.write_file(rng, &rel, format!("{t}\n").as_bytes());
                }
                940..960 if !self.guest => {
                    op = "rules";
                    let rules = if rng.chance(50) {
                        format!("{BASE_RULES}scratch/\n")
                    } else {
                        BASE_RULES.to_owned()
                    };
                    r = fs::write(self.p(".gitignore"), rules);
                }
                940..970 => {
                    op = "patch";
                    r = match self.pick(rng, false) {
                        Some(rel) => (|| {
                            let f = OpenOptions::new()
                                .read(true)
                                .write(true)
                                .custom_flags(libc::O_NOFOLLOW)
                                .open(self.p(&rel))?;
                            let len = f.metadata()?.len();
                            let t = format!("<{}>", self.n);
                            f.write_at(t.as_bytes(), rng.below(len + 1))?;
                            self.finish(rng, f)
                        })(),
                        None => Ok(()),
                    };
                }
                _ => {
                    op = "read";
                    r = self.pick(rng, false).map_or(Ok(()), |rel| {
                        OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_NOFOLLOW)
                            .open(self.p(&rel))
                            .and_then(|mut f| io::copy(&mut f, &mut io::sink()))
                            .map(drop)
                    });
                }
            }
            *self.stats.last_op.lock().unwrap() = op.to_owned();
            self.record(op, tok.as_deref(), r);
        }
    }

    fn run_side(mut side: Side, seed: u64, rate: u64, stop: Arc<AtomicBool>) {
        let mut rng = Rng::new(seed);
        let gap = Duration::from_micros(1_000_000 / rate.max(1));
        while !stop.load(Ordering::Relaxed) {
            let t0 = Instant::now();
            side.step(&mut rng);
            if let Some(left) = gap.checked_sub(t0.elapsed()) {
                thread::sleep(left);
            }
        }
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn files_with(root: &Path, toks: &[String]) -> Vec<String> {
        let mut hits = Vec::new();
        let Ok(t) = snapshot(root, false, &|r| ignored(r, false)) else {
            return hits;
        };
        for (rel, e) in t {
            if let Ent::File { .. } = e
                && let Ok(b) = fs::read(root.join(&rel))
            {
                for k in toks {
                    if contains(&b, k.as_bytes()) {
                        hits.push(format!("{rel} holds refused {k}"));
                    }
                }
            }
        }
        hits
    }

    pub fn refused_atomic_save() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("atomicrefuse", write_project);
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README on the guest", SYNC, || {
            g.mnt.join("README.md").exists()
        });
        let mut problems = Vec::new();
        for (k, (size, sync)) in [
            (100usize, false),
            (100, true),
            (5 << 20, false),
            (5 << 20, true),
        ]
        .into_iter()
        .enumerate()
        {
            let t = format!("t{k}.txt");
            fs::write(w.proj.join(&t), "v1\n").unwrap();
            eventually("v1 on the guest", SYNC, || {
                read(&g.mnt.join(&t)).as_deref() == Some("v1\n")
            });
            let held = File::open(g.mnt.join(&t)).unwrap();
            fs::write(w.proj.join(&t), "host v2 wins\n").unwrap();
            eventually("v2 on the guest", SYNC, || {
                read(&g.mnt.join(&t)).as_deref() == Some("host v2 wins\n")
            });
            let tmp = format!(".{t}.tmp");
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(g.mnt.join(&tmp))
                .unwrap();
            f.write_all(&vec![b'g'; size]).unwrap();
            if sync {
                f.sync_all().unwrap();
            }
            close_checked(f).unwrap();
            let r = fs::rename(g.mnt.join(&tmp), g.mnt.join(&t));
            drop(held);
            thread::sleep(Duration::from_secs(3));
            let case = format!(
                "size={size} fsync={sync} rename={:?}",
                r.as_ref().map_err(|e| e.raw_os_error())
            );
            if r.is_ok() {
                // a clean replace is also acceptable; then both sides hold the guest bytes
                if fs::metadata(w.proj.join(&t)).map(|m| m.len()).ok() != Some(size as u64) {
                    problems.push(format!(
                        "{case}: rename succeeded but the host lacks the new bytes"
                    ));
                }
            } else if read(&w.proj.join(&t)).as_deref() != Some("host v2 wins\n") {
                problems.push(format!("{case}: refused rename changed the host target"));
            }
            let (h, gs) = (w.proj.join(&tmp).exists(), g.mnt.join(&tmp).exists());
            if h != gs {
                problems.push(format!("{case}: temp left on host={h} guest={gs}"));
            }
            if let Err(d) = converge(&w.proj, &g.mnt, SYNC, &|r: &str| {
                r == ".git" || r.starts_with(".git/")
            }) {
                problems.push(format!("{case}: diverged: {d:?}"));
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    pub fn run() {
        if bin().is_none() {
            return;
        }
        let secs = env_u64("CSYNC_SOAK_SECS", 20);
        let rate = env_u64("CSYNC_SOAK_RATE", 20);
        let seed = seed_from_env("CSYNC_SOAK_SEED");
        eprintln!("soak: seed={seed} secs={secs} rate={rate} (replay with CSYNC_SOAK_SEED={seed})");

        let mut w = World::new("soak", |p| {
            write_project(p);
            fs::write(p.join(".gitignore"), BASE_RULES).unwrap();
            for d in DIRS {
                fs::create_dir_all(p.join(d)).unwrap();
            }
            for h in HOT {
                fs::write(p.join(h), hot_body("init")).unwrap();
            }
        });
        let g = w.guest("soak-guest");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README visible on the guest", SYNC, || {
            g.mnt.join("README.md").exists()
        });

        let stop = Arc::new(AtomicBool::new(false));
        let hs = Arc::new(Stats::default());
        let gs = Arc::new(Stats::default());
        let mk = |root: &Path, tag, guest, stats: &Arc<Stats>| Side {
            root: root.to_path_buf(),
            tag,
            guest,
            stats: stats.clone(),
            n: 0,
            names: names(),
        };
        let th = {
            let (s, st) = (mk(&w.proj, 'h', false, &hs), stop.clone());
            thread::spawn(move || run_side(s, seed, rate, st))
        };
        let tg = {
            let (s, st) = (mk(&g.mnt, 'g', true, &gs), stop.clone());
            thread::spawn(move || run_side(s, seed.rotate_left(17) ^ 0x5eed, rate, st))
        };

        // watchdog: a side that stops making progress is a hang; capture both daemons' stacks
        let end = Instant::now() + Duration::from_secs(secs);
        let mut last = (0, 0, Instant::now());
        while Instant::now() < end || !(th.is_finished() && tg.is_finished()) {
            if Instant::now() >= end {
                stop.store(true, Ordering::Relaxed);
            }
            thread::sleep(Duration::from_millis(500));
            let now = (
                hs.ops.load(Ordering::Relaxed),
                gs.ops.load(Ordering::Relaxed),
            );
            let done = (th.is_finished(), tg.is_finished());
            if (now.0 != last.0 || done.0) && (now.1 != last.1 || done.1) {
                last = (now.0, now.1, Instant::now());
            } else if last.2.elapsed() > HANG {
                let hst = stacks(host.pid());
                let gst = stacks(guest.pid());
                panic!(
                    "soak hang (seed {seed}): no progress for {HANG:?}; host op {:?} guest op {:?}\n--- host stacks\n{hst}\n--- guest stacks\n{gst}",
                    hs.last_op.lock().unwrap(),
                    gs.last_op.lock().unwrap()
                );
            }
            assert!(host.alive(), "host died during the soak (seed {seed})");
            assert!(guest.alive(), "guest died during the soak (seed {seed})");
        }
        th.join().expect("host generator panicked");
        tg.join().expect("guest generator panicked");
        eprintln!(
            "soak: ops host={} guest={} errors host={:?} guest={:?}",
            hs.ops.load(Ordering::Relaxed),
            gs.ops.load(Ordering::Relaxed),
            hs.errs.lock().unwrap(),
            gs.errs.lock().unwrap()
        );

        // final rules drop scratch/, so everything made under it on either side must now sync too
        fs::write(w.proj.join(".gitignore"), BASE_RULES).unwrap();
        let skip = |r: &str| ignored(r, false);
        let tree = converge(&w.proj, &g.mnt, QUIESCE, &skip).unwrap_or_else(|d| {
            panic!(
                "host and guest never converged (seed {seed}):\n{}",
                d.join("\n")
            )
        });
        eprintln!("soak: converged on {} entries", tree.len());

        let mut problems = Vec::new();
        for rel in gs.ignored_made.lock().unwrap().iter() {
            if fs::symlink_metadata(w.proj.join(rel)).is_ok() {
                problems.push(format!("guest-ignored {rel} reached the host"));
            }
        }
        for rel in hs.ignored_made.lock().unwrap().iter() {
            if fs::symlink_metadata(g.mnt.join(rel)).is_ok() {
                problems.push(format!("host-ignored {rel} reached the guest"));
            }
        }
        for s in stray_names(&w.proj) {
            problems.push(format!("stray on host: {s}"));
        }
        for s in stray_names(&g.mnt) {
            problems.push(format!("stray on guest: {s}"));
        }
        let refused = gs.refused.lock().unwrap().clone();
        eprintln!(
            "soak: {} guest ops were refused with ECANCELED",
            refused.len()
        );
        problems.extend(files_with(&w.proj, &refused));
        for (k, n) in gs.errs.lock().unwrap().iter() {
            if ["EIO", "ENOTCONN", "ETIMEDOUT", "EBUSY", "ENOSPC"]
                .iter()
                .any(|e| k.ends_with(e))
            {
                problems.push(format!("guest saw {n} x {k} on a healthy link"));
            }
        }
        assert!(
            problems.is_empty(),
            "soak invariants broken (seed {seed}):\n{}",
            problems.join("\n")
        );
        assert!(host.alive() && guest.alive());
        guest.quit(SYNC);
        eventually("unmounted after guest quit", SYNC, || !is_mounted(&g.mnt));
        host.quit(SYNC);
    }
}
