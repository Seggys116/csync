// fault injection against a live host and guest: crashes, stops, partitions, full disks, odd trees, signals, load
// each scenario is its own test; CSYNC_LOAD_SECS sets the load run (default 20)

macro_rules! linux_test {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            #[cfg(target_os = "linux")]
            chaos::$name();
            #[cfg(not(target_os = "linux"))]
            eprintln!("skip: the FUSE chaos tests run on Linux only");
        }
    )*};
}

linux_test!(
    host_kill9_mid_churn,
    guest_kill9_stale_remount,
    host_sigstop,
    partition_and_netem,
    disk_full,
    host_root_replaced,
    odd_trees,
    branch_switch_under_readers,
    two_guests,
    dir_moves_under_host_writes,
    shutdown_signals,
    link_flapping,
    load,
    refused_unlink_of_a_file_the_host_made_a_symlink,
);

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod chaos {
    use super::common::*;
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Read, Write},
        os::unix::fs::FileExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    // how long a syscall on the mount may take while the host is unreachable before it counts as a hang
    const BOUND: Duration = Duration::from_secs(30);
    const CONVERGE: Duration = Duration::from_secs(120);

    fn skip_git(r: &str) -> bool {
        r == ".git" || r.starts_with(".git/") || r.split('/').any(|c| c == "target")
    }

    // runs f on its own thread; None when it did not return within d (the thread is left blocked)
    fn timed<T: Send + 'static>(d: Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(d).ok()
    }

    fn put(p: &Path, body: &[u8]) -> io::Result<()> {
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?;
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(p)?;
        f.write_all(body)?;
        close_checked(f)
    }

    fn must_converge(what: &str, a: &Path, b: &Path, skip: &dyn Fn(&str) -> bool) -> Tree {
        converge(a, b, CONVERGE, skip)
            .unwrap_or_else(|d| panic!("{what}: never converged:\n{}", d.join("\n")))
    }

    fn assert_clean(roots: &[&Path]) {
        for r in roots {
            let s = stray_names(r);
            assert!(s.is_empty(), "strays under {}: {s:?}", r.display());
        }
    }

    fn rand_bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut r = Rng::new(seed);
        let mut v = Vec::with_capacity(n + 8);
        while v.len() < n {
            v.extend_from_slice(&r.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }

    fn not_crash(st: std::process::ExitStatus, who: &str) {
        use std::os::unix::process::ExitStatusExt;
        assert!(
            !matches!(
                st.signal(),
                Some(libc::SIGABRT | libc::SIGSEGV | libc::SIGBUS | libc::SIGILL)
            ) && st.code() != Some(101),
            "{who} crashed: {st:?}"
        );
    }

    // (a) kill -9 the host during a 5k-file churn; acknowledged guest writes survive and both sides converge
    pub fn host_kill9_mid_churn() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("kill9host", write_project);
        let g = w.guest("g");
        let host = w.spawn_host();
        let guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README on the guest", SYNC, || {
            g.mnt.join("README.md").exists()
        });

        let made = Arc::new(AtomicU64::new(0));
        let proj = w.proj.clone();
        let m2 = made.clone();
        let churn = thread::spawn(move || {
            for i in 0..5000u64 {
                let _ = fs::create_dir_all(proj.join(format!("churn/d{}", i / 100)));
                fs::write(
                    proj.join(format!("churn/d{}/f{i}.txt", i / 100)),
                    format!("v1 {i}\n"),
                )
                .unwrap();
                m2.store(i, Ordering::Relaxed);
                if i % 50 == 0 {
                    thread::sleep(Duration::from_millis(5));
                }
            }
            for i in (0..5000u64).step_by(5) {
                fs::write(
                    proj.join(format!("churn/d{}/f{i}.txt", i / 100)),
                    format!("v2 {i}\n"),
                )
                .unwrap();
            }
            for i in (1..5000u64).step_by(10) {
                let _ = fs::remove_file(proj.join(format!("churn/d{}/f{i}.txt", i / 100)));
            }
        });
        let mnt = g.mnt.clone();
        let acked = Arc::new(Mutex::new(Vec::new()));
        let failed = Arc::new(Mutex::new(Vec::new()));
        let (a2, f2) = (acked.clone(), failed.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let gw = thread::spawn(move || {
            let mut i = 0;
            while !s2.load(Ordering::Relaxed) {
                let rel = format!("gw/w{i}.txt");
                let body = format!("guest write {i}\n");
                match put(&mnt.join(&rel), body.as_bytes()) {
                    Ok(()) => a2.lock().unwrap().push((rel, body)),
                    Err(e) => f2.lock().unwrap().push(format!("{rel}: {e}")),
                }
                i += 1;
                thread::sleep(Duration::from_millis(40));
            }
        });
        eventually("churn under way", Duration::from_secs(60), || {
            made.load(Ordering::Relaxed) > 2000
        });
        let mut host = host;
        host.kill9();
        drop(host);
        thread::sleep(Duration::from_secs(2));
        let host = w.spawn_host();
        churn.join().unwrap();
        thread::sleep(Duration::from_secs(3));
        stop.store(true, Ordering::Relaxed);
        gw.join().unwrap();
        eprintln!(
            "kill9: guest writes acked={:?} failed={:?}",
            acked
                .lock()
                .unwrap()
                .iter()
                .map(|a| a.0.as_str())
                .collect::<Vec<_>>(),
            failed.lock().unwrap()
        );
        let t = must_converge("after a host kill -9", &w.proj, &g.mnt, &skip_git);
        for (rel, body) in acked.lock().unwrap().iter() {
            assert_eq!(
                read(&w.proj.join(rel)).as_deref(),
                Some(body.as_str()),
                "acknowledged guest write {rel} lost"
            );
        }
        assert_eq!(
            t.keys()
                .filter(|k| k.starts_with("churn/") && k.ends_with(".txt"))
                .count(),
            4500
        );
        assert_clean(&[&w.proj, &g.mnt]);
        let mut guest = guest;
        let mut host = host;
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    // (b) kill -9 the guest, remount over the stale mount with a cache whose blobs were tampered with
    pub fn guest_kill9_stale_remount() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("kill9guest", |p| {
            write_project(p);
            for i in 0..20u64 {
                fs::write(
                    p.join(format!("blob{i}.bin")),
                    rand_bytes(i, 100_000 + i as usize * 7919),
                )
                .unwrap();
            }
        });
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README on the guest", SYNC, || {
            g.mnt.join("README.md").exists()
        });
        for i in 0..20u64 {
            assert_eq!(
                fs::read(g.mnt.join(format!("blob{i}.bin"))).unwrap(),
                rand_bytes(i, 100_000 + i as usize * 7919)
            );
        }
        guest.kill9();
        drop(guest);
        assert!(
            is_mounted(&g.mnt),
            "a killed guest should leave its mount behind"
        );
        // stat can still be served from the kernel attribute cache; an open has to reach the dead daemon
        let stale = File::open(g.mnt.join("README.md"));
        assert!(stale.is_err(), "a dead mount still answered an open");

        let mut blobs = Vec::new();
        collect_files(&g.home.join("cache"), &mut blobs);
        let blobs: Vec<PathBuf> = blobs
            .into_iter()
            .filter(|p| p.components().any(|c| c.as_os_str() == "blobs"))
            .collect();
        assert!(
            !blobs.is_empty(),
            "no cached blobs survived under {}",
            g.home.join("cache").display()
        );
        let mut flipped = 0;
        for b in &blobs {
            if let Ok(f) = OpenOptions::new().read(true).write(true).open(b) {
                let len = f.metadata().map(|m| m.len()).unwrap_or(0);
                if len > 16 {
                    let mut x = [0u8; 1];
                    let _ = f.read_at(&mut x, len / 2);
                    x[0] ^= 0x5a;
                    let _ = f.write_at(&x, len / 2);
                    flipped += 1;
                }
            }
        }
        eprintln!(
            "kill9guest: {} cached blobs survived, {flipped} tampered",
            blobs.len()
        );

        fs::write(
            w.proj.join("while_down.txt"),
            "made while the guest was dead\n",
        )
        .unwrap();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README after remount", SYNC, || {
            read(&g.mnt.join("README.md")).as_deref() == Some("hello from host\n")
        });
        for i in 0..20u64 {
            let p = g.mnt.join(format!("blob{i}.bin"));
            let got =
                timed(BOUND, move || fs::read(p)).expect("read of a tampered cached blob hung");
            match got {
                Ok(b) => assert!(
                    b == rand_bytes(i, 100_000 + i as usize * 7919),
                    "blob{i}.bin served from a corrupted cache"
                ),
                Err(e) => panic!(
                    "blob{i}.bin unreadable after cache tampering: {e} (a bad blob must be refetched)"
                ),
            }
        }
        eventually("host edit made while the guest was dead", SYNC, || {
            g.mnt.join("while_down.txt").exists()
        });
        must_converge("after guest remount", &w.proj, &g.mnt, &skip_git);
        guest.quit(SYNC);
        eventually("unmounted", SYNC, || !is_mounted(&g.mnt));
        host.quit(SYNC);
    }

    fn collect_files(d: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = fs::read_dir(d) else { return };
        for e in rd.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => collect_files(&e.path(), out),
                Ok(t) if t.is_file() => out.push(e.path()),
                _ => {}
            }
        }
    }

    // what the guest does while the host cannot answer: cached reads work, everything else returns in bounded time
    fn unreachable_probe(mnt: &Path, tag: &str) -> Vec<String> {
        let mut bad = Vec::new();
        let t0 = Instant::now();
        let p = mnt.join("README.md");
        match timed(BOUND, move || fs::read_to_string(p)) {
            None => bad.push(format!("{tag}: cached read hung")),
            Some(Err(e)) => bad.push(format!("{tag}: cached read failed: {e}")),
            Some(Ok(s)) if s != "hello from host\n" => {
                bad.push(format!("{tag}: cached read returned {s:?}"))
            }
            Some(Ok(_)) => {}
        }
        let p = mnt.join("cold.bin");
        let t1 = Instant::now();
        match timed(BOUND + BOUND, move || fs::read(p)) {
            None => bad.push(format!(
                "{tag}: uncached read blocked for over {:?}",
                BOUND + BOUND
            )),
            Some(Ok(b)) => {
                if b != rand_bytes(99, 3 << 20) {
                    bad.push(format!("{tag}: uncached read returned wrong bytes"));
                }
                eprintln!("{tag}: uncached read succeeded after {:?}", t1.elapsed());
            }
            Some(Err(e)) => eprintln!("{tag}: uncached read failed after {:?}: {e}", t1.elapsed()),
        }
        let p = mnt.join(format!("{tag}_write.txt"));
        let t2 = Instant::now();
        match timed(BOUND + BOUND, move || {
            put(&p, b"written while unreachable\n")
        }) {
            None => bad.push(format!("{tag}: write blocked for over {:?}", BOUND + BOUND)),
            Some(r) => eprintln!(
                "{tag}: write while unreachable -> {r:?} after {:?}",
                t2.elapsed()
            ),
        }
        eprintln!("{tag}: probe took {:?}", t0.elapsed());
        bad
    }

    fn cold_project(p: &Path) {
        write_project(p);
        fs::write(p.join("cold.bin"), rand_bytes(99, 3 << 20)).unwrap();
    }

    // (c) sigstop the host for 20 s: the guest must not hang, and nothing is lost after sigcont
    pub fn host_sigstop() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("sigstop", cold_project);
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README on the guest", SYNC, || {
            read(&g.mnt.join("README.md")).is_some()
        });
        host.signal("STOP");
        let stopped = Instant::now();
        let bad = unreachable_probe(&g.mnt, "sigstop");
        if let Some(left) = Duration::from_secs(20).checked_sub(stopped.elapsed()) {
            thread::sleep(left);
        }
        host.signal("CONT");
        fs::write(w.proj.join("after_cont.txt"), "resumed\n").unwrap();
        eventually("host edit after sigcont", RECONNECT, || {
            read(&g.mnt.join("after_cont.txt")).is_some()
        });
        let probe_file = w.proj.join("sigstop_write.txt");
        must_converge("after sigstop", &w.proj, &g.mnt, &skip_git);
        eprintln!(
            "sigstop: guest write landed on host: {}",
            probe_file.exists()
        );
        assert!(bad.is_empty(), "{}", bad.join("\n"));
        assert!(guest.alive() && host.alive());
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    struct Netem;

    impl Netem {
        fn on(spec: &str) -> Option<Self> {
            let ok = Command::new("tc")
                .args(["qdisc", "add", "dev", "lo", "root", "netem"])
                .args(spec.split_whitespace())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            ok.then_some(Self)
        }
    }

    impl Drop for Netem {
        fn drop(&mut self) {
            let _ = Command::new("tc")
                .args(["qdisc", "del", "dev", "lo", "root"])
                .status();
        }
    }

    // (d) a 15 s blackhole between guest and host, then loss, delay and reordering on loopback
    pub fn partition_and_netem() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("partition", cold_project);
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let relay = Relay::new(&w.addr);
        let mut guest = w.spawn_guest(&g, &relay.addr.clone(), &[]);
        eventually("README on the guest", SYNC, || {
            read(&g.mnt.join("README.md")).is_some()
        });
        relay.hold.store(true, Ordering::Relaxed);
        let t0 = Instant::now();
        fs::write(
            w.proj.join("during_partition.txt"),
            "host edit while cut off\n",
        )
        .unwrap();
        let bad = unreachable_probe(&g.mnt, "partition");
        if let Some(left) = Duration::from_secs(15).checked_sub(t0.elapsed()) {
            thread::sleep(left);
        }
        relay.hold.store(false, Ordering::Relaxed);
        eventually("host edit after the partition heals", RECONNECT, || {
            g.mnt.join("during_partition.txt").exists()
        });
        must_converge("after partition", &w.proj, &g.mnt, &skip_git);
        assert!(bad.is_empty(), "{}", bad.join("\n"));

        match Netem::on("delay 50ms 10ms loss 5% reorder 25% 50%") {
            None => eprintln!("skip netem: tc qdisc unavailable (needs NET_ADMIN)"),
            Some(n) => {
                let end = Instant::now() + Duration::from_secs(20);
                let mut i = 0;
                let mut errs = Vec::new();
                while Instant::now() < end {
                    fs::write(
                        w.proj.join(format!("net/h{}.txt", i % 30)),
                        format!("host {i}\n"),
                    )
                    .unwrap_or_else(|_| {
                        fs::create_dir_all(w.proj.join("net")).unwrap();
                    });
                    if let Err(e) = put(
                        &g.mnt.join(format!("net/g{}.txt", i % 30)),
                        &rand_bytes(i, 1000 + (i as usize % 7) * 40_000),
                    ) {
                        errs.push(e.to_string());
                    }
                    i += 1;
                    thread::sleep(Duration::from_millis(100));
                }
                must_converge("under netem", &w.proj, &g.mnt, &skip_git);
                drop(n);
                eprintln!("netem: {i} rounds, guest write errors {errs:?}");
                assert!(
                    errs.is_empty(),
                    "guest writes failed on a lossy but connected link: {errs:?}"
                );
            }
        }
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    // a slow link lets the guest unlink a file the host has already replaced with a symlink; the refusal must
    // not turn the inode the kernel holds into another file type, which the kernel answers with EIO
    pub fn refused_unlink_of_a_file_the_host_made_a_symlink() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("kindswap", cold_project);
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let relay = Relay::new(&w.addr);
        let mut guest = w.spawn_guest(&g, &relay.addr.clone(), &[]);
        let mut problems = Vec::new();
        for round in 0..3 {
            let name = format!("swap{round}.txt");
            let (hp, gp) = (w.proj.join(&name), g.mnt.join(&name));
            fs::write(&hp, "file\n").unwrap();
            eventually("the file on the guest", SYNC, || {
                read(&gp).as_deref() == Some("file\n")
            });
            let held = File::open(&gp).unwrap();
            relay.delay_ms.store(1500, Ordering::Relaxed);
            fs::remove_file(&hp).unwrap();
            std::os::unix::fs::symlink("README.md", &hp).unwrap();
            let unlinked = fs::remove_file(&gp).map_err(|e| e.raw_os_error());
            relay.delay_ms.store(0, Ordering::Relaxed);
            match held.metadata() {
                Ok(m) if m.is_file() => {}
                r => problems.push(format!(
                    "round {round}: unlink {unlinked:?}, then fstat on the held file gave {:?}",
                    r.map(|m| m.file_type()).map_err(|e| e.raw_os_error())
                )),
            }
            drop(held);
            eventually("the host symlink on the guest", SYNC, || {
                fs::symlink_metadata(&gp).is_ok_and(|m| m.file_type().is_symlink())
            });
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
        must_converge("after the refused unlinks", &w.proj, &g.mnt, &skip_git);
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    fn mount_tmpfs(at: &Path, size: &str) -> bool {
        fs::create_dir_all(at).unwrap();
        Command::new("mount")
            .args(["-t", "tmpfs", "-o", &format!("size={size}"), "tmpfs"])
            .arg(at)
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
            && Command::new("chmod")
                .arg("700")
                .arg(at)
                .status()
                .is_ok_and(|s| s.success())
    }

    struct Umount(PathBuf);

    impl Drop for Umount {
        fn drop(&mut self) {
            let _ = Command::new("umount").arg("-l").arg(&self.0).status();
        }
    }

    // (e) the guest cache dir and the host project dir each on a tiny tmpfs
    pub fn disk_full() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("diskfull", |_| {});
        let _proj_mount = if mount_tmpfs(&w.proj, "48m") {
            Some(Umount(w.proj.clone()))
        } else {
            eprintln!("skip disk_full: cannot mount tmpfs (needs root)");
            return;
        };
        write_project(&w.proj);
        for i in 0..4u64 {
            fs::write(
                w.proj.join(format!("big{i}.bin")),
                rand_bytes(1000 + i, 8 << 20),
            )
            .unwrap();
        }
        let g = w.guest("g");
        let _cache_mount =
            mount_tmpfs(&g.home.join("cache"), "12m").then(|| Umount(g.home.join("cache")));
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        let end = Instant::now() + SYNC;
        let first = loop {
            match fs::read_to_string(g.mnt.join("README.md")) {
                Ok(s) => break s,
                Err(e) => assert!(
                    Instant::now() < end,
                    "a small file stays unreadable with the guest cache on its own tmpfs: {e}"
                ),
            }
            thread::sleep(Duration::from_millis(200));
        };
        // once cached, opens are served from the tmpfs blob
        for _ in 0..3 {
            let again = fs::read_to_string(g.mnt.join("README.md"));
            assert_eq!(
                again.as_ref().ok(),
                Some(&first),
                "a cached file read back wrong from a tmpfs cache: {again:?}"
            );
        }

        let mut bad = Vec::new();
        for i in 0..4u64 {
            let p = g.mnt.join(format!("big{i}.bin"));
            match timed(BOUND + BOUND, move || fs::read(p)) {
                None => bad.push(format!("read of big{i}.bin hung with a full cache")),
                Some(Ok(b)) if b != rand_bytes(1000 + i, 8 << 20) => {
                    bad.push(format!("big{i}.bin: wrong bytes with a full cache"))
                }
                Some(r) => eprintln!(
                    "diskfull: read big{i}.bin with a 12m cache -> {:?}",
                    r.map(|b| b.len())
                ),
            }
        }
        let p = g.mnt.join("guest_big.bin");
        let body = rand_bytes(7, 20 << 20);
        let b2 = body.clone();
        match timed(BOUND + BOUND, move || put(&p, &b2)) {
            None => bad.push("a 20 MiB guest write with a 12 MiB cache hung".into()),
            Some(r) => eprintln!("diskfull: 20 MiB guest write with a full cache -> {r:?}"),
        }
        if let Ok(h) = fs::read(w.proj.join("guest_big.bin"))
            && h != body
        {
            bad.push(format!(
                "host holds a partial guest_big.bin ({} bytes)",
                h.len()
            ));
        }
        fs::remove_file(g.mnt.join("guest_big.bin")).ok();

        // the host disk has about 15 MiB left
        let p = g.mnt.join("host_full.bin");
        let body = rand_bytes(8, 24 << 20);
        let b2 = body.clone();
        match timed(BOUND + BOUND, move || put(&p, &b2)) {
            None => bad.push("a guest write that overflows the host disk hung".into()),
            Some(Ok(())) => {
                thread::sleep(Duration::from_secs(2));
                if fs::read(w.proj.join("host_full.bin")).ok() != Some(body) {
                    bad.push("guest write overflowing the host disk was acknowledged but is not on the host".into());
                }
            }
            Some(Err(e)) => eprintln!("diskfull: host-full write refused: {e}"),
        }
        thread::sleep(Duration::from_secs(2));
        bad.extend(
            stray_names(&w.proj)
                .into_iter()
                .map(|s| format!("host stray after ENOSPC: {s}")),
        );
        assert!(
            host.alive() && guest.alive(),
            "a daemon died on a full disk"
        );
        let p = g.mnt.join("small_after.txt");
        let ok = timed(BOUND, move || put(&p, b"fits\n")).is_some_and(|r| r.is_ok());
        if !ok {
            bad.push("a small write after the disk-full episode failed".into());
        }
        must_converge("after disk full", &w.proj, &g.mnt, &skip_git);
        assert!(bad.is_empty(), "{}", bad.join("\n"));
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    // (f) the project root is moved away and a new tree put in its place while the host runs
    pub fn host_root_replaced() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("rootswap", write_project);
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README on the guest", SYNC, || {
            read(&g.mnt.join("README.md")).is_some()
        });
        let old = w.tmp.0.join("proj.old");
        fs::rename(&w.proj, &old).unwrap();
        fs::create_dir_all(&w.proj).unwrap();
        fs::write(w.proj.join("README.md"), "replacement tree\n").unwrap();
        fs::write(w.proj.join("new_only.txt"), "new\n").unwrap();
        thread::sleep(Duration::from_secs(3));
        let mnt = g.mnt.clone();
        let st = timed(BOUND, move || fs::read_dir(&mnt).map(|r| r.count()));
        assert!(
            st.is_some(),
            "guest readdir hung after the host root was replaced"
        );
        let p = g.mnt.join("after_swap.txt");
        let wr = timed(BOUND, move || put(&p, b"after swap\n"));
        assert!(
            wr.is_some(),
            "guest write hung after the host root was replaced"
        );
        thread::sleep(Duration::from_secs(3));
        let in_old = old.join("after_swap.txt").exists();
        let in_new = w.proj.join("after_swap.txt").exists();
        eprintln!(
            "rootswap: host alive={} guest write={:?} landed old={in_old} new={in_new} guest sees new_only={}",
            host.alive(),
            wr,
            g.mnt.join("new_only.txt").exists()
        );
        assert!(
            !in_old,
            "a guest write landed in the moved-away old root, which is no longer the project"
        );
        if host.alive() {
            must_converge("after root replacement", &w.proj, &g.mnt, &skip_git);
        } else {
            not_crash(host.child.wait().unwrap(), "host");
        }
        guest.quit(SYNC);
        let _ = host.exit_within(Duration::from_millis(1));
        if host.alive() {
            host.quit(SYNC);
        }
        let _ = fs::remove_dir_all(&old);
    }

    // (g) 100k files in one dir, 200 levels deep, a 4 GiB sparse file, 255-byte names, file/dir swaps under open handles
    pub fn odd_trees() {
        if bin().is_none() {
            return;
        }
        let deep: String = (0..200)
            .map(|i| format!("d{}", i % 10))
            .collect::<Vec<_>>()
            .join("/");
        let long_host = format!("{}.txt", "h".repeat(251));
        let (deep2, long2) = (deep.clone(), long_host.clone());
        let mut w = World::new("odd", move |p| {
            write_project(p);
            let many = p.join("many");
            fs::create_dir_all(&many).unwrap();
            for i in 0..100_000 {
                fs::write(many.join(format!("{i:06}")), b"x").unwrap();
            }
            fs::create_dir_all(p.join(&deep2)).unwrap();
            fs::write(p.join(&deep2).join("bottom.txt"), "deep\n").unwrap();
            let mid: String = deep2.split('/').take(100).collect::<Vec<_>>().join("/");
            fs::write(p.join(mid).join("mid.txt"), "mid\n").unwrap();
            let f = File::create(p.join("sparse.img")).unwrap();
            f.set_len(4 << 30).unwrap();
            f.write_at(b"HEAD", 0).unwrap();
            f.write_at(b"TAIL", (4 << 30) - 4).unwrap();
            fs::write(p.join(&long2), "long\n").unwrap();
            fs::write(p.join("swap.txt"), "a file first\n").unwrap();
            fs::create_dir_all(p.join("swapd")).unwrap();
            fs::write(p.join("swapd/c.txt"), "child\n").unwrap();
        });
        let g = w.guest("g");
        let t0 = Instant::now();
        let mut host = w.spawn_host();
        eprintln!("odd: host indexed in {:?}", t0.elapsed());
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        let mut bad = Vec::new();

        let many = g.mnt.join("many");
        let t1 = Instant::now();
        match timed(Duration::from_secs(120), move || {
            fs::read_dir(many).map(|r| r.count())
        }) {
            Some(Ok(100_000)) => {
                eprintln!("odd: listed 100k entries in {:?}", t1.elapsed())
            }
            other => bad.push(format!("listing 100k entries -> {other:?}")),
        }
        // the protocol caps paths at 128 components: below it everything syncs, past it nothing may be created
        let mid: String = deep.split('/').take(100).collect::<Vec<_>>().join("/");
        let p = g.mnt.join(&mid).join("mid.txt");
        match timed(BOUND, move || fs::read_to_string(p)) {
            Some(Ok(s)) if s == "mid\n" => {}
            other => bad.push(format!("100-deep read -> {other:?}")),
        }
        let p = g.mnt.join(&mid).join("guest_mid.txt");
        match timed(BOUND, move || put(&p, b"from guest mid\n")) {
            Some(Ok(())) => {}
            other => bad.push(format!("100-deep guest write -> {other:?}")),
        }
        let edge: String = deep.split('/').take(127).collect::<Vec<_>>().join("/");
        let p = g.mnt.join(&edge).join("past_limit");
        match timed(BOUND, move || {
            fs::create_dir(&p).and_then(|()| put(&p.join("x"), b"x"))
        }) {
            Some(Err(e)) => eprintln!("odd: create past the depth limit -> {e}"),
            other => bad.push(format!(
                "create past the 128-component limit -> {other:?}, want an error"
            )),
        }
        let p = g.mnt.join(&deep).join("bottom.txt");
        if timed(BOUND, move || fs::metadata(p)).is_none() {
            bad.push("lookup past the depth limit hung".into());
        }
        let p = g.mnt.join("sparse.img");
        let t2 = Instant::now();
        match timed(
            Duration::from_secs(300),
            move || -> io::Result<(u64, [u8; 4], [u8; 4])> {
                let f = File::open(&p)?;
                let (mut a, mut b) = ([0u8; 4], [0u8; 4]);
                f.read_exact_at(&mut a, 0)?;
                f.read_exact_at(&mut b, (4 << 30) - 4)?;
                Ok((f.metadata()?.len(), a, b))
            },
        ) {
            Some(Ok((len, a, b))) if len == 4 << 30 && &a == b"HEAD" && &b == b"TAIL" => {
                eprintln!("odd: 4 GiB sparse file read in {:?}", t2.elapsed())
            }
            other => bad.push(format!(
                "4 GiB sparse read -> {other:?} after {:?}",
                t2.elapsed()
            )),
        }
        if read(&g.mnt.join(&long_host)).as_deref() != Some("long\n") {
            bad.push("255-byte host name unreadable on the guest".into());
        }
        let long_guest = format!("{}x", "é".repeat(127));
        assert_eq!(long_guest.len(), 255);
        if let Err(e) = put(&g.mnt.join(&long_guest), b"long guest\n") {
            bad.push(format!("255-byte guest name -> {e}"));
        }
        let too_long = format!("{}xy", "é".repeat(127));
        match put(&g.mnt.join(&too_long), b"x") {
            Err(e) if e.raw_os_error() == Some(libc::ENAMETOOLONG) => {}
            other => bad.push(format!("256-byte name -> {other:?}, want ENAMETOOLONG")),
        }

        let mut fa = File::open(g.mnt.join("swap.txt")).unwrap();
        let held = File::open(g.mnt.join("swapd/c.txt")).unwrap();
        fs::remove_file(w.proj.join("swap.txt")).unwrap();
        fs::create_dir(w.proj.join("swap.txt")).unwrap();
        fs::write(w.proj.join("swap.txt/inner"), "now a dir\n").unwrap();
        fs::remove_dir_all(w.proj.join("swapd")).unwrap();
        fs::write(w.proj.join("swapd"), "now a file\n").unwrap();
        let r = timed(BOUND, move || {
            let mut s = String::new();
            fa.read_to_string(&mut s).map(|_| s)
        });
        eprintln!("odd: read on a handle whose file became a dir -> {r:?}");
        if r.is_none() {
            bad.push("read on a replaced file's handle hung".into());
        }
        eventually("file replaced by dir on the guest", SYNC, || {
            read(&g.mnt.join("swap.txt/inner")).as_deref() == Some("now a dir\n")
        });
        eventually("dir replaced by file on the guest", SYNC, || {
            read(&g.mnt.join("swapd")).as_deref() == Some("now a file\n")
        });
        drop(held);
        let skip = |r: &str| {
            skip_git(r)
                || r == "many"
                || r.starts_with("many/")
                || r == "sparse.img"
                || r.split('/').count() >= 128
        };
        must_converge("odd trees", &w.proj, &g.mnt, &skip);
        assert!(bad.is_empty(), "{}", bad.join("\n"));
        assert!(host.alive() && guest.alive());
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    fn git(dir: &Path, args: &[&str]) {
        let st = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .stdout(Stdio::null())
            .status()
            .expect("git");
        assert!(st.success(), "git {args:?} failed");
    }

    // (h) the host flips between two 10k-file branches while the guest searches and runs git status
    pub fn branch_switch_under_readers() {
        if bin().is_none() || Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let mut w = World::new("branches", |p| {
            git(p, &["init", "-q", "-b", "a"]);
            fs::write(p.join(".gitignore"), "target/\n").unwrap();
            for i in 0..10_000 {
                let d = p.join(format!("src/m{}", i / 250));
                fs::create_dir_all(&d).unwrap();
                fs::write(
                    d.join(format!("f{i}.rs")),
                    format!("fn a{i}() {{ needle_a(); }}\n"),
                )
                .unwrap();
            }
            git(p, &["add", "-A"]);
            git(p, &["commit", "-q", "-m", "a"]);
            git(p, &["switch", "-q", "-c", "b"]);
            for i in 0..10_000 {
                fs::write(
                    p.join(format!("src/m{}/f{i}.rs", i / 250)),
                    format!("fn b{i}() {{ needle_b(); }}\n"),
                )
                .unwrap();
            }
            git(p, &["add", "-A"]);
            git(p, &["commit", "-q", "-m", "b"]);
        });
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("tree on the guest", SYNC, || {
            g.mnt.join("src/m0/f0.rs").exists()
        });
        let stop = Arc::new(AtomicBool::new(false));
        let worst = Arc::new(Mutex::new((Duration::ZERO, String::new())));
        let fails = Arc::new(Mutex::new(Vec::new()));
        let mut readers = Vec::new();
        for cmd in [
            vec!["rg", "-c", "needle_"],
            vec!["git", "status", "--porcelain"],
        ] {
            let (mnt, stop, worst, fails) =
                (g.mnt.clone(), stop.clone(), worst.clone(), fails.clone());
            readers.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    let out = Command::new("timeout")
                        .arg("120")
                        .args(&cmd)
                        .current_dir(&mnt)
                        .stdout(Stdio::null())
                        .stderr(Stdio::piped())
                        .output();
                    let el = t.elapsed();
                    let mut wst = worst.lock().unwrap();
                    if el > wst.0 {
                        *wst = (el, cmd.join(" "));
                    }
                    if let Ok(o) = out {
                        // rg exits 1 for no match; 124 is our timeout
                        if o.status.code() == Some(124) || o.status.code().is_none() {
                            fails.lock().unwrap().push(format!(
                                "{} hung or crashed: {:?}",
                                cmd.join(" "),
                                o.status
                            ));
                        }
                    }
                }
            }));
        }
        for i in 0..6 {
            git(
                &w.proj,
                &["switch", "-q", if i % 2 == 0 { "a" } else { "b" }],
            );
            thread::sleep(Duration::from_secs(3));
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().unwrap();
        }
        eprintln!(
            "branches: slowest guest command {:?}",
            worst.lock().unwrap()
        );
        // the guest serves .git/index with its own stat data (guest/gitindex.rs), so the index is
        // compared by its entries rather than its bytes
        let skip = |r: &str| {
            r.split('/').any(|c| c == "target") || r == ".git/index.lock" || r == ".git/index"
        };
        must_converge("after branch switches", &w.proj, &g.mnt, &skip);
        let staged = |dir: &Path| {
            Command::new("git")
                .args(["ls-files", "-s"])
                .current_dir(dir)
                .output()
                .map(|o| o.stdout)
                .unwrap_or_default()
        };
        let want = staged(&w.proj);
        assert!(!want.is_empty(), "git ls-files on the host printed nothing");
        eventually("the same index entries on both sides", SYNC, || {
            staged(&g.mnt) == want
        });
        let st = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&g.mnt)
            .output()
            .unwrap();
        let dirty = String::from_utf8_lossy(&st.stdout).lines().count();
        assert!(
            fails.lock().unwrap().is_empty(),
            "{:?}",
            fails.lock().unwrap()
        );
        assert_eq!(
            dirty, 0,
            "git status on the guest sees {dirty} changes after the host settled on b"
        );
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    // (i) two guests with separate identities on one host; edits cross between them
    pub fn two_guests() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("twoguests", write_project);
        let g1 = w.guest("g1");
        let g2 = w.guest("g2");
        let mut host = w.spawn_host();
        let a = w.addr.clone();
        let mut p1 = w.spawn_guest(&g1, &a, &[]);
        let mut p2 = w.spawn_guest(&g2, &a, &[]);
        eventually("README on both", SYNC, || {
            g1.mnt.join("README.md").exists() && g2.mnt.join("README.md").exists()
        });
        put(&g1.mnt.join("from1.txt"), b"one\n").unwrap();
        eventually("g1 edit on g2", SYNC, || {
            read(&g2.mnt.join("from1.txt")).as_deref() == Some("one\n")
        });
        put(&g2.mnt.join("from2.txt"), b"two\n").unwrap();
        eventually("g2 edit on g1", SYNC, || {
            read(&g1.mnt.join("from2.txt")).as_deref() == Some("two\n")
        });
        let (m1, m2) = (g1.mnt.clone(), g2.mnt.clone());
        let t1 = thread::spawn(move || {
            (0..200)
                .filter(|i| {
                    put(
                        &m1.join(format!("x/{}.txt", i % 20)),
                        format!("g1 {i}\n").as_bytes(),
                    )
                    .is_err()
                })
                .count()
        });
        let t2 = thread::spawn(move || {
            (0..200)
                .filter(|i| {
                    put(
                        &m2.join(format!("x/{}.txt", i % 20)),
                        format!("g2 {i}\n").as_bytes(),
                    )
                    .is_err()
                })
                .count()
        });
        let (e1, e2) = (t1.join().unwrap(), t2.join().unwrap());
        eprintln!("twoguests: refused writes g1={e1} g2={e2}");
        let t = must_converge("host vs g1", &w.proj, &g1.mnt, &skip_git);
        let t2 = must_converge("host vs g2", &w.proj, &g2.mnt, &skip_git);
        assert_eq!(t, t2);
        assert_clean(&[&w.proj, &g1.mnt, &g2.mnt]);
        p1.quit(SYNC);
        p2.quit(SYNC);
        host.quit(SYNC);
    }

    // the guest renames directories while the host rewrites files in them: a host edit made under the old
    // name just before the move must still reach the guest under the new one
    pub fn dir_moves_under_host_writes() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("dirmoves", |p| {
            for d in ["a", "b", "c", "d"] {
                fs::create_dir_all(p.join(d)).unwrap();
                for i in 0..4 {
                    fs::write(p.join(format!("{d}/f{i}.txt")), format!("{d}{i}\n")).unwrap();
                }
            }
        });
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("the tree on the guest", SYNC, || {
            g.mnt.join("a/f0.txt").exists()
        });
        let stop = Arc::new(AtomicBool::new(false));
        let pick = |root: &Path, n: u64| -> Option<PathBuf> {
            let mut ds: Vec<PathBuf> = fs::read_dir(root)
                .ok()?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_dir() && !p.ends_with(".git"))
                .collect();
            ds.sort();
            (!ds.is_empty()).then(|| ds.remove(n as usize % ds.len()))
        };
        let (proj, mnt, s1, s2) = (w.proj.clone(), g.mnt.clone(), stop.clone(), stop.clone());
        let writer = thread::spawn(move || {
            let mut n = 0u64;
            while !s1.load(Ordering::Relaxed) {
                if let Some(d) = pick(&proj, n.wrapping_mul(7)) {
                    let _ = fs::write(
                        d.join(format!("f{}.txt", n % 6)),
                        format!("h {n}\n").repeat(1 + n as usize % 40),
                    );
                }
                n += 1;
                thread::sleep(Duration::from_millis(3));
            }
        });
        let mover = thread::spawn(move || {
            let mut n = 0u64;
            while !s2.load(Ordering::Relaxed) {
                if let Some(d) = pick(&mnt, n.wrapping_mul(13)) {
                    let _ = fs::rename(&d, mnt.join(format!("g{n}")));
                }
                n += 1;
                thread::sleep(Duration::from_millis(15));
            }
        });
        thread::sleep(Duration::from_secs(15));
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        mover.join().unwrap();
        must_converge("after directory moves", &w.proj, &g.mnt, &skip_git);
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    // (j) sigterm and sigint: the host exits cleanly and the guest keeps a healthy mount; a signalled guest unmounts
    pub fn shutdown_signals() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("signals", write_project);
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README on the guest", SYNC, || {
            read(&g.mnt.join("README.md")).is_some()
        });
        for sig in ["TERM", "INT"] {
            host.signal(sig);
            let st = host
                .exit_within(SYNC)
                .unwrap_or_else(|| panic!("host ignored SIG{sig}"));
            eprintln!("signals: host SIG{sig} -> {st:?}");
            not_crash(st, "host");
            assert!(
                st.success() || st.code() == Some(130),
                "host SIG{sig} exit {st:?}"
            );
            let p = g.mnt.join("README.md");
            let r = timed(BOUND, move || fs::read_to_string(p));
            assert_eq!(
                r.and_then(Result::ok).as_deref(),
                Some("hello from host\n"),
                "guest mount unhealthy after host SIG{sig}"
            );
            assert!(guest.alive(), "guest exited when the host got SIG{sig}");
            fs::write(w.proj.join(format!("after_{sig}.txt")), "x\n").unwrap();
            host = w.spawn_host();
            eventually("guest reconnects after host restart", RECONNECT, || {
                g.mnt.join(format!("after_{sig}.txt")).exists()
            });
        }
        for sig in ["TERM", "INT"] {
            guest.signal(sig);
            let st = guest
                .exit_within(SYNC)
                .unwrap_or_else(|| panic!("guest ignored SIG{sig}"));
            eprintln!("signals: guest SIG{sig} -> {st:?}");
            not_crash(st, "guest");
            assert!(
                st.success() || st.code() == Some(130),
                "guest SIG{sig} exit {st:?}"
            );
            assert!(!is_mounted(&g.mnt), "guest SIG{sig} left a stale mount");
            guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
            eventually("README after remount", SYNC, || {
                read(&g.mnt.join("README.md")).is_some()
            });
        }
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    // (k) the link is cut 50 times while the host edits; the guest must catch up and the host must not leak
    pub fn link_flapping() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("flap", write_project);
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let relay = Relay::new(&w.addr);
        let mut guest = w.spawn_guest(&g, &relay.addr.clone(), &[]);
        eventually("README on the guest", SYNC, || {
            read(&g.mnt.join("README.md")).is_some()
        });
        let before = proc_stat(host.pid()).unwrap();
        let gbefore = proc_stat(guest.pid()).unwrap();
        let mut rng = Rng::new(seed_from_env("CSYNC_SOAK_SEED"));
        let mut outcomes = Vec::new();
        for i in 0..50 {
            fs::write(
                w.proj.join(format!("flap{}.txt", i % 10)),
                format!("edit {i}\n"),
            )
            .unwrap();
            let t = Instant::now();
            let r = put(
                &g.mnt.join(format!("gflap{}.txt", i % 10)),
                format!("guest {i}\n").as_bytes(),
            );
            outcomes.push((
                i,
                r.as_ref().err().and_then(io::Error::raw_os_error),
                t.elapsed(),
            ));
            relay.cut();
            thread::sleep(Duration::from_millis(100 + rng.below(900)));
        }
        eprintln!("flap: guest write (i, errno, took) {outcomes:?}");
        // nobody else touches gflap*, so a refusal there is a lost write reported as a conflict
        let refused: Vec<_> = outcomes
            .iter()
            .filter(|o| o.1 == Some(libc::ECANCELED))
            .collect();
        fs::write(w.proj.join("flap_done.txt"), "done\n").unwrap();
        eventually("guest catches up after flapping", RECONNECT, || {
            g.mnt.join("flap_done.txt").exists()
        });
        must_converge("after flapping", &w.proj, &g.mnt, &skip_git);
        assert!(
            refused.is_empty(),
            "guest-only writes refused with ECANCELED across reconnects: {refused:?}"
        );
        thread::sleep(Duration::from_secs(5));
        let after = proc_stat(host.pid()).unwrap();
        let gafter = proc_stat(guest.pid()).unwrap();
        eprintln!(
            "flap: host (rss kb, threads, fds) {:?} -> {:?}; guest {:?} -> {:?}",
            before, after, gbefore, gafter
        );
        assert!(
            after.2 <= before.2 + 8,
            "host fds grew {} -> {} over 50 reconnects",
            before.2,
            after.2
        );
        assert!(
            after.1 <= before.1 + 8,
            "host threads grew {} -> {} over 50 reconnects",
            before.1,
            after.1
        );
        assert!(
            gafter.2 <= gbefore.2 + 8,
            "guest fds grew {} -> {} over 50 reconnects",
            gbefore.2,
            gafter.2
        );
        assert!(
            gafter.1 <= gbefore.1 + 8,
            "guest threads grew {} -> {} over 50 reconnects",
            gbefore.1,
            gafter.1
        );
        guest.quit(SYNC);
        host.quit(SYNC);
    }

    fn pct(v: &mut [Duration], p: usize) -> Duration {
        v.sort();
        v.get((v.len() * p / 100).min(v.len().saturating_sub(1)))
            .copied()
            .unwrap_or_default()
    }

    // 8 build-like writers into an ignored target/, 8 readers, host edits; samples rss, fds, threads and latency
    pub fn load() {
        if bin().is_none() {
            return;
        }
        let secs = env_u64("CSYNC_LOAD_SECS", 20);
        let mut w = World::new("load", |p| {
            write_project(p);
            for i in 0..2000 {
                let d = p.join(format!("src/m{}", i / 100));
                fs::create_dir_all(&d).unwrap();
                fs::write(
                    d.join(format!("f{i}.rs")),
                    format!("fn f{i}() {{}}\n").repeat(1 + i % 40),
                )
                .unwrap();
            }
        });
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("tree on the guest", SYNC, || {
            g.mnt.join("src/m0/f0.rs").exists()
        });
        let stop = Arc::new(AtomicBool::new(false));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let mut ts = Vec::new();
        for k in 0..8 {
            let (mnt, stop, errors) = (g.mnt.clone(), stop.clone(), errors.clone());
            ts.push(thread::spawn(move || {
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let p = mnt.join(format!("target/debug/w{k}/o{}.o", i % 200));
                    if let Err(e) = put(&p, &rand_bytes(i, 4096 + (i as usize % 50) * 4096)) {
                        errors.lock().unwrap().push(format!("writer {k}: {e}"));
                    }
                    if i % 200 == 199 {
                        let _ = fs::remove_dir_all(mnt.join(format!("target/debug/w{k}")));
                    }
                    i += 1;
                }
            }));
        }
        for k in 0..8 {
            let (mnt, stop, errors) = (g.mnt.clone(), stop.clone(), errors.clone());
            ts.push(thread::spawn(move || {
                let mut i = k * 250;
                while !stop.load(Ordering::Relaxed) {
                    let p = mnt.join(format!("src/m{}/f{}.rs", (i % 2000) / 100, i % 2000));
                    if let Err(e) = fs::read(&p)
                        && e.raw_os_error() != Some(libc::ENOENT)
                    {
                        errors.lock().unwrap().push(format!("reader {k}: {e}"));
                    }
                    if i % 500 == 0 {
                        let _ = Command::new("rg")
                            .args(["-c", "fn f1"])
                            .current_dir(&mnt)
                            .output();
                    }
                    i += 1;
                }
            }));
        }
        {
            let (proj, stop) = (w.proj.clone(), stop.clone());
            ts.push(thread::spawn(move || {
                let mut i = 0;
                while !stop.load(Ordering::Relaxed) {
                    let _ = fs::write(
                        proj.join(format!("src/m{}/f{}.rs", (i % 2000) / 100, i % 2000)),
                        format!("fn edited{i}() {{}}\n"),
                    );
                    i += 7;
                    thread::sleep(Duration::from_millis(20));
                }
            }));
        }
        let canary = g.mnt.join("canary.txt");
        put(&canary, b"0\n").unwrap();
        let mut lat = Vec::new();
        let mut samples = Vec::new();
        let start = Instant::now();
        let mut next_sample = Instant::now();
        let mut slow = 0;
        while start.elapsed() < Duration::from_secs(secs) {
            if Instant::now() >= next_sample {
                samples.push((
                    start.elapsed().as_secs(),
                    proc_stat(host.pid()),
                    proc_stat(guest.pid()),
                ));
                next_sample += Duration::from_secs(5);
            }
            let c = canary.clone();
            let t = Instant::now();
            let r = timed(BOUND, move || -> io::Result<()> {
                fs::metadata(&c)?;
                let mut f = OpenOptions::new().write(true).truncate(true).open(&c)?;
                f.write_all(b"tick\n")?;
                close_checked(f)
            });
            let el = t.elapsed();
            match r {
                Some(Ok(())) => lat.push(el),
                Some(Err(e)) => errors.lock().unwrap().push(format!("canary: {e}")),
                None => {
                    slow += 1;
                    lat.push(BOUND);
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
        stop.store(true, Ordering::Relaxed);
        for t in ts {
            t.join().unwrap();
        }
        samples.push((
            start.elapsed().as_secs(),
            proc_stat(host.pid()),
            proc_stat(guest.pid()),
        ));
        let (p50, p99) = (pct(&mut lat, 50), pct(&mut lat, 99));
        eprintln!(
            "load: canary n={} p50={p50:?} p99={p99:?} hung={slow}",
            lat.len()
        );
        eprintln!("load: samples (secs, host (rss kb, threads, fds, cpu ticks), guest ...):");
        for s in &samples {
            eprintln!("load:   {s:?}");
        }
        let errs = errors.lock().unwrap().clone();
        eprintln!(
            "load: {} errors, first {:?}",
            errs.len(),
            errs.iter().take(5).collect::<Vec<_>>()
        );
        let skip = |r: &str| skip_git(r);
        must_converge("after load", &w.proj, &g.mnt, &skip);
        assert!(
            !w.proj.join("target").exists(),
            "ignored build output reached the host"
        );
        assert!(
            errs.is_empty(),
            "errors under load: {:?}",
            &errs[..errs.len().min(10)]
        );
        assert_eq!(slow, 0, "canary syscalls hung under load");
        assert!(
            p99 < Duration::from_secs(2),
            "canary p99 {p99:?} under load"
        );
        // growth check: the last sample against the one a quarter of the way in, once warm
        let q = samples.len() / 4;
        for (who, pick) in [("host", 1usize), ("guest", 2)] {
            let at = |i: usize| match pick {
                1 => samples[i].1,
                _ => samples[i].2,
            };
            if let (Some(a), Some(b)) = (at(q), at(samples.len() - 1)) {
                assert!(
                    b.2 <= a.2 + 32,
                    "{who} fds grew {} -> {} under load",
                    a.2,
                    b.2
                );
                assert!(
                    b.1 <= a.1 + 16,
                    "{who} threads grew {} -> {} under load",
                    a.1,
                    b.1
                );
                assert!(
                    b.0 <= (a.0 * 2).max(a.0 + 256 * 1024),
                    "{who} rss grew {} -> {} kb under load",
                    a.0,
                    b.0
                );
            }
        }
        guest.quit(SYNC);
        host.quit(SYNC);
    }
}
