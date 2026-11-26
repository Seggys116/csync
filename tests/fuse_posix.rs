// posix conformance gaps found with pjdfstest, fsx and real tools (cargo, tar, rsync, sqlite) on both domains:
// src/ is synced to the host, target/ is gitignored and lives in the guest overlay

macro_rules! linux_test {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            #[cfg(target_os = "linux")]
            posix::$name();
            #[cfg(not(target_os = "linux"))]
            eprintln!("skip: the FUSE posix tests run on Linux only");
        }
    )*};
}

linux_test!(
    overlay_failed_cross_dir_link_keeps_source,
    synced_hardlink,
    tempdir_renamed_onto_ignored_name,
    dir_moves_across_domains,
    concurrent_appends_on_one_guest,
    path_truncate_right_after_write,
    unlink_open_file_overlay,
    unlink_open_file_synced,
    overlay_create_mode_ignores_csync_umask,
    overlay_file_over_2gib_keeps_size,
    symlink_times_nofollow_synced,
    overlay_user_xattrs,
    overlay_chown_as_root,
    overlay_rename_exchange,
    long_name_errno,
    utimensat_mtime_reaches_host,
    shared_mmap_write_reaches_host,
);

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod posix {
    use super::common::*;
    use rustix::{
        fs::{AtFlags, CWD, RenameFlags, Timespec, Timestamps, XattrFlags},
        io::Errno,
    };
    use std::{
        ffi::CString,
        fs::{self, File, OpenOptions},
        io::{self, Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt, PermissionsExt, symlink},
        },
        path::{Path, PathBuf},
        process::Command,
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };

    // field order is drop order: the guest leaves first so its mount is gone before the temp tree is removed
    struct Env {
        guest: Proc,
        host: Proc,
        g: Guest,
        w: World,
    }

    impl Env {
        fn up(tag: &str) -> Option<Self> {
            bin()?;
            let mut w = World::new(tag, write_project);
            let g = w.guest("g");
            let host = w.spawn_host();
            let addr = w.addr.clone();
            let guest = w.spawn_guest(&g, &addr, &[]);
            eventually("guest sees the project", START, || {
                g.mnt.join("README.md").exists()
            });
            fs::create_dir_all(g.mnt.join("target")).expect("mkdir target/ on the guest");
            Some(Self { guest, host, g, w })
        }

        fn m(&self, rel: &str) -> PathBuf {
            self.g.mnt.join(rel)
        }

        fn h(&self, rel: &str) -> PathBuf {
            self.w.proj.join(rel)
        }

        fn host_has(&self, rel: &str, want: &[u8]) {
            let p = self.h(rel);
            eventually(
                &format!("host has the guest's bytes in {rel}"),
                SYNC,
                || fs::read(&p).is_ok_and(|b| b == want),
            );
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            for p in [&mut self.guest, &mut self.host] {
                p.say("quit");
                p.stdin = None;
                if p.exit_within(Duration::from_secs(15)).is_none() {
                    p.kill9();
                }
            }
        }
    }

    fn eno(e: &io::Error) -> String {
        let names = [
            (libc::EPERM, "EPERM"),
            (libc::ENOENT, "ENOENT"),
            (libc::EIO, "EIO"),
            (libc::EBADF, "EBADF"),
            (libc::EACCES, "EACCES"),
            (libc::EEXIST, "EEXIST"),
            (libc::EXDEV, "EXDEV"),
            (libc::EINVAL, "EINVAL"),
            (libc::EROFS, "EROFS"),
            (libc::ENAMETOOLONG, "ENAMETOOLONG"),
            (libc::ENODATA, "ENODATA"),
            (libc::EOPNOTSUPP, "EOPNOTSUPP"),
            (libc::ECANCELED, "ECANCELED"),
        ];
        match e.raw_os_error() {
            Some(n) => names
                .iter()
                .find(|(c, _)| *c == n)
                .map_or_else(|| format!("errno {n}"), |(_, s)| (*s).to_owned()),
            None => e.to_string(),
        }
    }

    fn cpath(p: &Path) -> CString {
        CString::new(p.as_os_str().as_bytes()).expect("path without nul")
    }

    // truncate(2) by path with no open file, which is what python's os.truncate and make-style tools issue
    #[allow(unsafe_code)]
    fn truncate_path(p: &Path, len: i64) -> io::Result<()> {
        let c = cpath(p);
        // SAFETY: c is a valid nul-terminated path that outlives the call.
        if unsafe { libc::truncate(c.as_ptr(), len) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    // rustc's incremental cache and cargo's uplifting try a hard link into another directory first,
    // then copy on failure; after the refused link the source reads back empty, so ld finds no main
    pub fn overlay_failed_cross_dir_link_keeps_source() {
        let Some(e) = Env::up("posix-link-ov") else {
            return;
        };
        let body = vec![b'E'; 5448];
        fs::create_dir_all(e.m("target/inc/working")).unwrap();
        fs::write(e.m("target/m.o"), &body).unwrap();
        let link = fs::hard_link(e.m("target/m.o"), e.m("target/inc/working/m.o"));
        let back = fs::read(e.m("target/m.o")).unwrap();
        assert_eq!(
            back.len(),
            body.len(),
            "after link() returned {:?} the source reads {} bytes instead of {}",
            link.as_ref().map_err(eno),
            back.len(),
            body.len()
        );
        link.unwrap_or_else(|err| panic!("hard link inside the overlay failed: {}", eno(&err)));
        let md = fs::metadata(e.m("target/m.o")).unwrap();
        assert_eq!(md.nlink(), 2, "st_nlink after link");
        assert_eq!(fs::read(e.m("target/inc/working/m.o")).unwrap(), body);
        // both names are one inode: a write through one shows through the other at once
        let l = fs::metadata(e.m("target/inc/working/m.o")).unwrap();
        assert_eq!((l.ino(), l.nlink()), (md.ino(), 2));
        let mut f = OpenOptions::new()
            .append(true)
            .open(e.m("target/inc/working/m.o"))
            .unwrap();
        f.write_all(b"tail").unwrap();
        close_checked(f).unwrap();
        assert_eq!(fs::metadata(e.m("target/m.o")).unwrap().len(), 5452);
        assert!(fs::read(e.m("target/m.o")).unwrap().ends_with(b"tail"));
        let names: Vec<_> = fs::read_dir(e.m("target/inc/working"))
            .unwrap()
            .map(|d| d.unwrap().file_name())
            .collect();
        assert_eq!(names, ["m.o"], "readdir names the link by its own name");
        fs::rename(e.m("target/inc/working/m.o"), e.m("target/inc/m2.o")).unwrap();
        fs::remove_file(e.m("target/m.o")).unwrap();
        let l = fs::metadata(e.m("target/inc/m2.o")).unwrap();
        assert_eq!((l.nlink(), l.len()), (1, 5452));
        assert!(!e.m("target/m.o").exists());
        fs::remove_file(e.m("target/inc/m2.o")).unwrap();
    }

    // directories and files moved between the synced tree and the overlay in both directions, as mv and
    // build tools do; the host gains exactly the synced side
    pub fn dir_moves_across_domains() {
        let Some(e) = Env::up("posix-xmove") else {
            return;
        };
        let mv = |a: &str, b: &str| {
            let st = Command::new("mv")
                .arg(a)
                .arg(b)
                .current_dir(&e.g.mnt)
                .status()
                .unwrap();
            assert!(st.success(), "mv {a} {b}");
        };
        fs::create_dir_all(e.m("src/d/sub")).unwrap();
        fs::write(e.m("src/d/f"), b"f").unwrap();
        fs::write(e.m("src/d/sub/g"), vec![b'g'; 200_000]).unwrap();
        symlink("f", e.m("src/d/l")).unwrap();
        e.host_has("src/d/sub/g", &[b'g'; 200_000]);
        fs::rename(e.m("src/d"), e.m("target/d"))
            .unwrap_or_else(|err| panic!("synced dir into the overlay: {}", eno(&err)));
        assert_eq!(fs::read(e.m("target/d/f")).unwrap(), b"f");
        assert_eq!(fs::read(e.m("target/d/sub/g")).unwrap().len(), 200_000);
        assert_eq!(fs::read_link(e.m("target/d/l")).unwrap(), Path::new("f"));
        assert!(!e.m("src/d").exists());
        eventually("host drops the moved dir", SYNC, || !e.h("src/d").exists());
        assert!(
            !e.h("target/d").exists(),
            "overlay content reached the host"
        );

        fs::create_dir_all(e.m("target/d/target")).unwrap();
        fs::write(e.m("target/d/target/ignored"), b"i").unwrap();
        fs::rename(e.m("target/d"), e.m("src/back"))
            .unwrap_or_else(|err| panic!("overlay dir into the synced tree: {}", eno(&err)));
        e.host_has("src/back/f", b"f");
        e.host_has("src/back/sub/g", &[b'g'; 200_000]);
        assert_eq!(fs::read_link(e.h("src/back/l")).unwrap(), Path::new("f"));
        assert_eq!(fs::read(e.m("src/back/target/ignored")).unwrap(), b"i");
        assert!(
            !e.h("src/back/target").exists(),
            "ignored entry reached the host"
        );
        assert!(!e.m("target/d").exists());

        fs::write(e.m("src/one"), b"1").unwrap();
        e.host_has("src/one", b"1");
        mv("src/one", "target/one");
        assert_eq!(fs::read(e.m("target/one")).unwrap(), b"1");
        eventually("host drops the moved file", SYNC, || {
            !e.h("src/one").exists()
        });
        mv("target/one", "src/two");
        e.host_has("src/two", b"1");
        mv("src/back", "target/back");
        assert_eq!(fs::read(e.m("target/back/target/ignored")).unwrap(), b"i");
        eventually("host drops src/back", SYNC, || !e.h("src/back").exists());
    }

    // tar x and cp -a of trees with hard links fail with EPERM in synced directories; the host index has no
    // hard links, so a synced link is a documented independent copy with st_nlink 1, and crossing domains is EXDEV
    pub fn synced_hardlink() {
        let Some(e) = Env::up("posix-link-sync") else {
            return;
        };
        fs::write(e.m("src/a.txt"), b"one").unwrap();
        fs::hard_link(e.m("src/a.txt"), e.m("src/b.txt"))
            .unwrap_or_else(|err| panic!("hard link in a synced dir: {}", eno(&err)));
        assert_eq!(fs::read(e.m("src/b.txt")).unwrap(), b"one");
        assert_eq!(fs::metadata(e.m("src/a.txt")).unwrap().nlink(), 1);
        assert_eq!(fs::metadata(e.m("src/b.txt")).unwrap().nlink(), 1);
        fs::write(e.m("src/b.txt"), b"two").unwrap();
        assert_eq!(
            fs::read(e.m("src/a.txt")).unwrap(),
            b"one",
            "a synced link is a copy"
        );
        e.host_has("src/a.txt", b"one");
        e.host_has("src/b.txt", b"two");
        let x = fs::hard_link(e.m("src/a.txt"), e.m("target/a.txt"));
        assert_eq!(x.map_err(|err| eno(&err)), Err("EXDEV".to_owned()));
        fs::write(e.m("target/o"), b"o").unwrap();
        let x = fs::hard_link(e.m("target/o"), e.m("src/o"));
        assert_eq!(x.map_err(|err| eno(&err)), Err("EXDEV".to_owned()));
        assert_eq!(fs::read(e.m("target/o")).unwrap(), b"o");
    }

    // cargo creates target/ as a temp dir in the crate root and renames it into place: EXDEV today
    pub fn tempdir_renamed_onto_ignored_name() {
        let Some(e) = Env::up("posix-tmpdir") else {
            return;
        };
        fs::create_dir_all(e.m("src/cr")).unwrap();
        fs::create_dir(e.m("src/cr/.tmpAbC12")).unwrap();
        fs::write(
            e.m("src/cr/.tmpAbC12/CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55\n",
        )
        .unwrap();
        fs::rename(e.m("src/cr/.tmpAbC12"), e.m("src/cr/target")).unwrap_or_else(|err| {
            panic!("rename of a new dir onto an ignored name: {}", eno(&err))
        });
        assert!(e.m("src/cr/target/CACHEDIR.TAG").is_file());
        fs::write(e.m("src/cr/target/x"), b"x").unwrap();
        thread::sleep(Duration::from_secs(2));
        assert!(
            !e.h("src/cr/.tmpAbC12").exists(),
            "temp dir left on the host"
        );
        assert!(
            !e.h("src/cr/target").exists(),
            "an ignored dir reached the host"
        );
    }

    // parallel `>>` from several processes of one guest (make -j logs, test runners) must not conflict
    pub fn concurrent_appends_on_one_guest() {
        let Some(e) = Env::up("posix-append") else {
            return;
        };
        let p = e.m("src/log.txt");
        fs::write(&p, b"").unwrap();
        e.host_has("src/log.txt", b"");
        let errs = Arc::new(Mutex::new(Vec::new()));
        let ws: Vec<_> = (0..4u8)
            .map(|i| {
                let (p, errs) = (p.clone(), errs.clone());
                thread::spawn(move || {
                    for _ in 0..100 {
                        let r = OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(&p)
                            .and_then(|mut f| f.write_all(&[b'a' + i; 16]).map(|()| f))
                            .and_then(close_checked);
                        if let Err(err) = r {
                            errs.lock().unwrap().push(eno(&err));
                        }
                    }
                })
            })
            .collect();
        for w in ws {
            w.join().unwrap();
        }
        let errs = errs.lock().unwrap().clone();
        let len = fs::metadata(&p).unwrap().len();
        assert!(
            errs.is_empty() && len == 6400,
            "appends lost: len {len} of 6400, close errors {errs:?}"
        );
        eventually("host has every append", SYNC, || {
            fs::metadata(e.h("src/log.txt")).is_ok_and(|m| m.len() == 6400)
        });
    }

    // truncate(2) right after a write is sometimes dropped, or the next open+ftruncate fails with ECANCELED
    pub fn path_truncate_right_after_write() {
        let Some(e) = Env::up("posix-trunc") else {
            return;
        };
        let mut bad = Vec::new();
        for i in 0..200 {
            let p = e.m(&format!("src/t{i}"));
            fs::write(&p, b"abcdef").unwrap();
            let r = truncate_path(&p, 3)
                .and_then(|()| fs::read(&p))
                .and_then(|got| {
                    if got != b"abc" {
                        return Err(io::Error::other(format!(
                            "read {:?} after truncate",
                            String::from_utf8_lossy(&got)
                        )));
                    }
                    let f = OpenOptions::new().read(true).write(true).open(&p)?;
                    f.set_len(10)?;
                    close_checked(f)
                });
            if let Err(err) = r {
                bad.push(format!("t{i}: {}", eno(&err)));
            }
        }
        assert!(
            bad.is_empty(),
            "{} of 200 path truncates misbehaved: {bad:?}",
            bad.len()
        );
        e.host_has("src/t199", b"abc\0\0\0\0\0\0\0");
    }

    fn unlink_open(e: &Env, rel: &str) -> Vec<String> {
        let p = e.m(rel);
        fs::write(&p, b"still here").unwrap();
        let f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        fs::remove_file(&p).unwrap();
        let mut bad = Vec::new();
        match f.metadata() {
            Ok(m) if m.nlink() == 0 && m.len() == 10 => {}
            Ok(m) => bad.push(format!("fstat nlink {} len {}", m.nlink(), m.len())),
            Err(err) => bad.push(format!("fstat {}", eno(&err))),
        }
        let mut buf = [0u8; 10];
        if let Err(err) = f.read_exact_at(&mut buf, 0) {
            bad.push(format!("pread {}", eno(&err)));
        }
        if let Err(err) = f.write_all_at(b"STILL", 0) {
            bad.push(format!("pwrite {}", eno(&err)));
        }
        if let Err(err) = f.sync_all() {
            bad.push(format!("fsync {}", eno(&err)));
        }
        if let Err(err) = f.read_exact_at(&mut buf, 0).map(|()| buf) {
            bad.push(format!("pread after write {}", eno(&err)));
        } else if &buf != b"STILL here" {
            bad.push(format!("read back {:?}", String::from_utf8_lossy(&buf)));
        }
        if let Err(err) = close_checked(f) {
            bad.push(format!("close {}", eno(&err)));
        }
        assert!(!p.exists(), "unlinked name came back");
        bad
    }

    // build tools and test runners keep using files another process unlinked; fstat fails with ENOENT today
    pub fn unlink_open_file_overlay() {
        let Some(e) = Env::up("posix-unlink-ov") else {
            return;
        };
        let bad = unlink_open(&e, "target/uo");
        assert!(
            bad.is_empty(),
            "open fd of an unlinked overlay file: {bad:?}"
        );
    }

    // writing to an unlinked synced file is local scratch; fsync and close fail with ECANCELED today
    pub fn unlink_open_file_synced() {
        let Some(e) = Env::up("posix-unlink-sync") else {
            return;
        };
        let bad = unlink_open(&e, "src/uo");
        assert!(
            bad.is_empty(),
            "open fd of an unlinked synced file: {bad:?}"
        );
        eventually("host drops the unlinked file", SYNC, || {
            !e.h("src/uo").exists()
        });
    }

    // the overlay creates its backing file under csync's own umask, so umask 002 users lose group write
    pub fn overlay_create_mode_ignores_csync_umask() {
        let Some(e) = Env::up("posix-umask") else {
            return;
        };
        for dir in ["target", "src"] {
            let st = Command::new("sh")
                .arg("-c")
                .arg(format!("umask 0 && : > {dir}/m && mkdir {dir}/md"))
                .current_dir(&e.g.mnt)
                .status()
                .unwrap();
            assert!(st.success());
            let fm = fs::metadata(e.m(&format!("{dir}/m")))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            let dm = fs::metadata(e.m(&format!("{dir}/md")))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(
                (fm, dm),
                (0o666, 0o777),
                "{dir}: file {fm:o} dir {dm:o} under umask 0"
            );
        }
    }

    // one handle writing past 2 GiB in the overlay: the backing file is complete but the mount often reports
    // 0 bytes after close; intermittent, so a few rounds
    pub fn overlay_file_over_2gib_keeps_size() {
        let Some(e) = Env::up("posix-big") else {
            return;
        };
        let p = e.m("target/big.bin");
        let chunk: Vec<u8> = (0..1u32 << 20).map(|i| (i % 251) as u8).collect();
        let mib = 2049u64;
        for round in 0..4 {
            let mut f = File::create(&p).unwrap();
            for _ in 0..mib {
                f.write_all(&chunk).unwrap();
            }
            close_checked(f).unwrap();
            let len = fs::metadata(&p).unwrap().len();
            let mut tail = vec![0u8; 4096];
            let got = File::open(&p).and_then(|f| f.read_exact_at(&mut tail, (mib << 20) - 4096));
            fs::remove_file(&p).unwrap();
            assert_eq!(len, mib << 20, "round {round}: st_size after close");
            got.unwrap_or_else(|err| {
                panic!("round {round}: read of the last 4 KiB: {}", eno(&err))
            });
            assert_eq!(
                tail,
                chunk[chunk.len() - 4096..],
                "round {round}: last 4 KiB"
            );
        }
    }

    // tar x, rsync -a and cp -a set symlink times with AT_SYMLINK_NOFOLLOW; EINVAL makes all three exit non-zero
    pub fn symlink_times_nofollow_synced() {
        let Some(e) = Env::up("posix-lutimes") else {
            return;
        };
        symlink("lib.rs", e.m("src/l")).unwrap();
        let t = Timespec {
            tv_sec: 1_294_000_000,
            tv_nsec: 0,
        };
        let ts = Timestamps {
            last_access: t,
            last_modification: t,
        };
        rustix::fs::utimensat(CWD, e.m("src/l"), &ts, AtFlags::SYMLINK_NOFOLLOW).unwrap_or_else(
            |err| panic!("utimensat(AT_SYMLINK_NOFOLLOW) on a synced symlink: {err}"),
        );
        assert_eq!(
            fs::symlink_metadata(e.m("src/l")).unwrap().mtime(),
            1_294_000_000
        );
        assert_eq!(fs::read_link(e.m("src/l")).unwrap(), Path::new("lib.rs"));
        eventually("host symlink has the new mtime", SYNC, || {
            fs::symlink_metadata(e.h("src/l")).is_ok_and(|m| m.mtime() == 1_294_000_000)
        });
    }

    // xattrs stay unsupported: answering getxattr would cost a round trip per write (the kernel probes
    // security.capability before each one), so every call fails with ENOTSUP, which cp -a, tar and ls treat as
    // a filesystem without xattrs
    pub fn overlay_user_xattrs() {
        let Some(e) = Env::up("posix-xattr") else {
            return;
        };
        for p in [e.m("target/x"), e.m("src/x")] {
            fs::write(&p, b"x").unwrap();
            let mut buf = [0u8; 64];
            for name in ["user.none", "security.capability"] {
                let r = rustix::fs::getxattr(&p, name, &mut buf[..]);
                assert_eq!(r, Err(Errno::NOTSUP), "getxattr {name} on {p:?}");
            }
            // the kernel answers acl names itself: no acl
            let r = rustix::fs::getxattr(&p, "system.posix_acl_access", &mut buf[..]);
            assert_eq!(r, Err(Errno::NODATA), "acl on {p:?}");
            let r = rustix::fs::setxattr(&p, "user.k", b"v1", XattrFlags::empty());
            assert_eq!(r, Err(Errno::NOTSUP), "setxattr on {p:?}");
            let r = rustix::fs::listxattr(&p, &mut buf[..]);
            assert_eq!(r, Err(Errno::NOTSUP), "listxattr on {p:?}");
            let r = rustix::fs::removexattr(&p, "user.k");
            assert_eq!(r, Err(Errno::NOTSUP), "removexattr on {p:?}");
            assert_eq!(fs::read(&p).unwrap(), b"x");
        }
    }

    // as root (containers), tar and rsync -a chown extracted files; the overlay is local and can store owners
    pub fn overlay_chown_as_root() {
        if !rustix::process::geteuid().is_root() {
            eprintln!("skip: chown to another uid needs root");
            return;
        }
        let Some(e) = Env::up("posix-chown") else {
            return;
        };
        let p = e.m("target/owned");
        fs::write(&p, b"x").unwrap();
        std::os::unix::fs::chown(&p, Some(1000), Some(1000))
            .unwrap_or_else(|err| panic!("chown 1000:1000 as root in the overlay: {}", eno(&err)));
        let m = fs::metadata(&p).unwrap();
        assert_eq!((m.uid(), m.gid()), (1000, 1000));
        // the host decides synced ownership: chown there is an accepted no-op
        let s = e.m("src/owned");
        fs::write(&s, b"x").unwrap();
        std::os::unix::fs::chown(&s, Some(1000), Some(1000))
            .unwrap_or_else(|err| panic!("chown as root in the synced tree: {}", eno(&err)));
        assert_eq!(fs::read(&s).unwrap(), b"x");
    }

    // renameat2(RENAME_EXCHANGE) is a plain backing-fs call in the overlay; it fails with EINVAL today
    pub fn overlay_rename_exchange() {
        let Some(e) = Env::up("posix-xchg") else {
            return;
        };
        fs::write(e.m("target/a"), b"A").unwrap();
        fs::write(e.m("target/b"), b"B").unwrap();
        rustix::fs::renameat_with(
            CWD,
            e.m("target/a"),
            CWD,
            e.m("target/b"),
            RenameFlags::EXCHANGE,
        )
        .unwrap_or_else(|err| panic!("RENAME_EXCHANGE in the overlay: {err}"));
        assert_eq!(fs::read(e.m("target/a")).unwrap(), b"B");
        assert_eq!(fs::read(e.m("target/b")).unwrap(), b"A");
    }

    // a 256-byte name must fail with ENAMETOOLONG like create does, not EINVAL (pjdfstest mkdir/02, symlink/02)
    pub fn long_name_errno() {
        let Some(e) = Env::up("posix-namelen") else {
            return;
        };
        let long = "n".repeat(256);
        for dir in ["src", "target"] {
            let p = e.m(&format!("{dir}/{long}"));
            let mk = fs::create_dir(&p).map_err(|err| eno(&err));
            let sl = symlink("x", &p).map_err(|err| eno(&err));
            let cr = File::create(&p).map(drop).map_err(|err| eno(&err));
            let want: Result<(), String> = Err("ENAMETOOLONG".to_owned());
            assert_eq!(
                (&mk, &sl, &cr),
                (&want, &want, &want),
                "{dir}: mkdir, symlink, create"
            );
        }
    }

    // make and tar depend on exact mtimes: utimensat by path must land with nanoseconds on both sides
    pub fn utimensat_mtime_reaches_host() {
        let Some(e) = Env::up("posix-mtime") else {
            return;
        };
        for (i, (sec, nsec)) in [(1_600_000_000i64, 987_654_321i64), (4_000_000_000, 5)]
            .into_iter()
            .enumerate()
        {
            let rel = format!("src/mt{i}");
            fs::write(e.m(&rel), b"x").unwrap();
            let t = Timespec {
                tv_sec: sec,
                tv_nsec: nsec,
            };
            let ts = Timestamps {
                last_access: t,
                last_modification: t,
            };
            rustix::fs::utimensat(CWD, e.m(&rel), &ts, AtFlags::empty()).unwrap();
            let m = fs::metadata(e.m(&rel)).unwrap();
            assert_eq!(
                (m.mtime(), m.mtime_nsec()),
                (sec, nsec),
                "guest mtime of {rel}"
            );
            eventually(&format!("host mtime of {rel}"), SYNC, || {
                fs::metadata(e.h(&rel)).is_ok_and(|m| (m.mtime(), m.mtime_nsec()) == (sec, nsec))
            });
        }
    }

    // a MAP_SHARED write with msync and munmap but no write(2) must still be committed to the host
    #[allow(unsafe_code)]
    pub fn shared_mmap_write_reaches_host() {
        let Some(e) = Env::up("posix-mmap") else {
            return;
        };
        let p = e.m("src/mm.bin");
        fs::write(&p, vec![0u8; 8192]).unwrap();
        e.host_has("src/mm.bin", &[0u8; 8192]);
        let f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        // SAFETY: a fresh shared mapping of 8192 bytes of an open regular file of that size; unmapped below.
        let m = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                std::os::fd::AsRawFd::as_raw_fd(&f),
                0,
            )
        };
        assert_ne!(m, libc::MAP_FAILED, "mmap: {}", io::Error::last_os_error());
        // SAFETY: m points to 8192 writable mapped bytes until munmap.
        unsafe {
            std::ptr::copy_nonoverlapping(b"hello".as_ptr(), m.cast::<u8>(), 5);
            std::ptr::copy_nonoverlapping(b"world".as_ptr(), m.cast::<u8>().add(4096), 5);
            assert_eq!(libc::msync(m, 8192, libc::MS_SYNC), 0);
            assert_eq!(libc::munmap(m, 8192), 0);
        }
        close_checked(f).unwrap();
        let mut want = vec![0u8; 8192];
        want[..5].copy_from_slice(b"hello");
        want[4096..4101].copy_from_slice(b"world");
        let mut got = Vec::new();
        File::open(&p).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, want, "guest read after munmap");
        e.host_has("src/mm.bin", &want);
    }
}
