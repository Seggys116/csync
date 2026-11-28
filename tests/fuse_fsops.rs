// the optional fuse operations real tools reach for: fallocate, copy_file_range, fifos and sockets in the
// overlay, metadata on a file still being written, and the errno contract of what is refused

#[test]
fn fuse_fsops() {
    #[cfg(target_os = "linux")]
    ops::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE fsops test runs on Linux only");
}

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod ops {
    use super::common::*;
    use rustix::fs::{
        CWD, FallocateFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags, XattrFlags,
    };
    use std::{
        fs::{self, File, FileTimes, OpenOptions},
        io::{Read, Write},
        os::unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
        path::Path,
        time::{Duration, SystemTime},
    };

    const SYNC: Duration = Duration::from_secs(20);

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut r = Rng::new(seed);
        (0..len).map(|_| r.next() as u8).collect()
    }

    fn copy_all(src: &Path, dst: &Path) -> u64 {
        let a = File::open(src).unwrap();
        let b = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dst)
            .unwrap();
        let (mut off_in, mut off_out, mut total) = (0u64, 0u64, 0u64);
        loop {
            let n =
                rustix::fs::copy_file_range(&a, Some(&mut off_in), &b, Some(&mut off_out), 1 << 20)
                    .unwrap_or_else(|e| panic!("copy_file_range {}: {e}", dst.display()));
            if n == 0 {
                break;
            }
            total += n as u64;
        }
        close_checked(b).unwrap();
        total
    }

    fn host_has(p: &Path, want: &[u8]) -> bool {
        fs::read(p).is_ok_and(|b| b == want)
    }

    pub fn run() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("fsops", write_project);
        let g = w.guest("g");
        let _host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        let m = g.mnt.clone();
        eventually("README on the guest", SYNC, || m.join("README.md").exists());
        let local = m.join("target");
        fs::create_dir_all(&local).unwrap();

        refusals(&m, &local);
        fallocate(&m, &w.proj, &local);
        copy_range(&m, &w.proj, &local);
        specials(&m, &local);
        metadata_while_open(&m, &w.proj);
        locks(&m);

        // a closed session wipes the overlay, so its fifos and sockets are gone after a restart
        guest.quit(Duration::from_secs(30));
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README after restart", SYNC, || {
            m.join("README.md").exists()
        });
        for name in ["ff", "sk"] {
            assert!(
                fs::symlink_metadata(local.join(name)).is_err(),
                "{name} survived the restart"
            );
        }
        guest.quit(Duration::from_secs(30));
    }

    fn fallocate(m: &Path, proj: &Path, local: &Path) {
        for (dir, host) in [(m, Some(proj)), (local, None)] {
            let p = dir.join("fa.bin");
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&p)
                .unwrap();
            rustix::fs::fallocate(&f, FallocateFlags::empty(), 0, 1 << 20)
                .unwrap_or_else(|e| panic!("fallocate {}: {e}", p.display()));
            assert_eq!(f.metadata().unwrap().len(), 1 << 20);
            rustix::fs::fallocate(&f, FallocateFlags::KEEP_SIZE, 0, 4 << 20).unwrap();
            assert_eq!(f.metadata().unwrap().len(), 1 << 20, "keep size grew {p:?}");
            (&f).write_all(&[7u8; 8192]).unwrap();
            rustix::fs::fallocate(
                &f,
                FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE,
                0,
                4096,
            )
            .unwrap();
            close_checked(f).unwrap();
            let got = fs::read(&p).unwrap();
            assert_eq!(got.len(), 1 << 20);
            assert!(
                got[..4096].iter().all(|&b| b == 0),
                "punched range not zero"
            );
            assert!(
                got[4096..8192].iter().all(|&b| b == 7),
                "data beside the hole lost"
            );
            if let Some(h) = host {
                eventually("fallocated file on the host", SYNC, || {
                    host_has(&h.join("fa.bin"), &got)
                });
            }
            fs::remove_file(&p).unwrap();
        }
    }

    fn copy_range(m: &Path, proj: &Path, local: &Path) {
        let data = noise(3 << 20, 11);
        fs::write(m.join("cr.src"), &data).unwrap();
        eventually("copy source on the host", SYNC, || {
            host_has(&proj.join("cr.src"), &data)
        });
        let cases = [
            (m.join("cr.src"), m.join("cr.dst")),
            (m.join("cr.src"), local.join("cr.dst")),
            (local.join("cr.dst"), m.join("cr.back")),
        ];
        for (src, dst) in &cases {
            assert_eq!(copy_all(src, dst), data.len() as u64, "{dst:?}");
            assert!(fs::read(dst).unwrap() == data, "copy into {dst:?} differs");
        }
        for name in ["cr.dst", "cr.back"] {
            eventually("copied file on the host", SYNC, || {
                host_has(&proj.join(name), &data)
            });
        }
        // a range copy at an offset into an existing file
        let f = OpenOptions::new()
            .write(true)
            .open(m.join("cr.dst"))
            .unwrap();
        let src = File::open(m.join("cr.src")).unwrap();
        let (mut oi, mut oo) = (100u64, 5u64);
        let n = rustix::fs::copy_file_range(&src, Some(&mut oi), &f, Some(&mut oo), 10).unwrap();
        assert_eq!(n, 10);
        close_checked(f).unwrap();
        let got = fs::read(m.join("cr.dst")).unwrap();
        assert_eq!(&got[5..15], &data[100..110]);
        for p in [
            m.join("cr.src"),
            m.join("cr.dst"),
            m.join("cr.back"),
            local.join("cr.dst"),
        ] {
            fs::remove_file(p).unwrap();
        }
    }

    fn specials(m: &Path, local: &Path) {
        let ff = local.join("ff");
        rustix::fs::mknodat(CWD, &ff, FileType::Fifo, Mode::from_bits_truncate(0o644), 0)
            .unwrap_or_else(|e| panic!("mkfifo in the overlay: {e}"));
        assert!(fs::symlink_metadata(&ff).unwrap().file_type().is_fifo());
        let names: Vec<_> = fs::read_dir(local)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_name() == "ff")
            .map(|e| e.file_type().unwrap().is_fifo())
            .collect();
        assert_eq!(names, vec![true], "readdir type of the fifo");
        let w = ff.clone();
        let writer = std::thread::spawn(move || fs::write(w, b"through the pipe").unwrap());
        let mut got = String::new();
        File::open(&ff).unwrap().read_to_string(&mut got).unwrap();
        writer.join().unwrap();
        assert_eq!(got, "through the pipe");

        let sk = local.join("sk");
        let l = UnixListener::bind(&sk).unwrap_or_else(|e| panic!("bind in the overlay: {e}"));
        let mut c = UnixStream::connect(&sk).unwrap();
        let (mut s, _) = l.accept().unwrap();
        c.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        drop((c, s, l));
        assert!(fs::symlink_metadata(&sk).unwrap().file_type().is_socket());

        // the host cannot hold either, and they do not move into the synced tree
        let r = rustix::fs::mknodat(CWD, m.join("ff"), FileType::Fifo, Mode::empty(), 0);
        assert_eq!(r, Err(rustix::io::Errno::PERM), "mkfifo in the synced tree");
        let r = fs::rename(&ff, m.join("ff"));
        assert_eq!(
            errno(&r),
            Some(libc::EXDEV),
            "fifo renamed into the synced tree"
        );
        fs::rename(&ff, local.join("ff2")).unwrap();
        fs::rename(local.join("ff2"), &ff).unwrap();
        assert!(fs::symlink_metadata(&ff).unwrap().file_type().is_fifo());
    }

    // cp -a, tar and rsync set mode and times on the descriptor they are still writing
    fn metadata_while_open(m: &Path, proj: &Path) {
        let p = m.join("meta.txt");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        f.write_all(b"copied\n").unwrap();
        let when = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        f.set_times(FileTimes::new().set_accessed(when).set_modified(when))
            .unwrap_or_else(|e| panic!("futimens on a new file: {e}"));
        f.set_permissions(fs::Permissions::from_mode(0o640))
            .unwrap_or_else(|e| panic!("fchmod on a new file: {e}"));
        close_checked(f).unwrap();
        let md = fs::metadata(&p).unwrap();
        assert_eq!(md.mode() & 0o777, 0o640);
        assert_eq!(md.mtime(), 1_600_000_000);
        let hp = proj.join("meta.txt");
        eventually("mode and mtime on the host", SYNC, || {
            fs::metadata(&hp).is_ok_and(|h| h.mode() & 0o777 == 0o640 && h.mtime() == 1_600_000_000)
                && host_has(&hp, b"copied\n")
        });
        fs::remove_file(&p).unwrap();
    }

    fn refusals(m: &Path, local: &Path) {
        for dir in [m, local] {
            let a = dir.join("ra.txt");
            let b = dir.join("rb.txt");
            fs::write(&a, "a").unwrap();
            fs::write(&b, "b").unwrap();
            let same = |step: &str| {
                assert_eq!(fs::read_to_string(&a).unwrap(), "a", "{step} in {dir:?}");
                assert_eq!(
                    fs::read_to_string(&b).unwrap(),
                    "b",
                    "b after {step} in {dir:?}"
                );
            };
            // a real link in the overlay, an independent copy in the synced tree
            let r = rustix::fs::link(&a, dir.join("ra.hard"));
            assert_eq!(r, Ok(()), "link in {dir:?}");
            same("link");
            assert_eq!(fs::read_to_string(dir.join("ra.hard")).unwrap(), "a");
            fs::remove_file(dir.join("ra.hard")).unwrap();
            same("unlink of the link");
            let r = rustix::fs::setxattr(&a, "user.k", b"v", XattrFlags::empty());
            assert_eq!(r, Err(rustix::io::Errno::NOTSUP), "setxattr in {dir:?}");
            let mut buf = [0u8; 64];
            let r = rustix::fs::getxattr(&a, "user.k", &mut buf[..]);
            assert_eq!(r, Err(rustix::io::Errno::NOTSUP), "getxattr in {dir:?}");
            let r = rustix::fs::listxattr(&a, &mut buf[..]);
            assert_eq!(r, Err(rustix::io::Errno::NOTSUP), "listxattr in {dir:?}");
            same("xattr");
            let r = rustix::fs::open(dir, OFlags::TMPFILE | OFlags::RDWR, Mode::RUSR);
            assert_eq!(
                r.err(),
                Some(rustix::io::Errno::NOTSUP),
                "O_TMPFILE in {dir:?}"
            );
            same("tmpfile");
            let r = rustix::fs::renameat_with(CWD, &a, CWD, &b, RenameFlags::NOREPLACE);
            assert_eq!(r, Err(rustix::io::Errno::EXIST), "noreplace in {dir:?}");
            same("noreplace");
            // the host has no exchange, so only the overlay swaps
            let r = rustix::fs::renameat_with(CWD, &a, CWD, &b, RenameFlags::EXCHANGE);
            if dir == local {
                assert_eq!(r, Ok(()), "exchange in {dir:?}");
                assert_eq!(fs::read_to_string(&a).unwrap(), "b");
                rustix::fs::renameat_with(CWD, &a, CWD, &b, RenameFlags::EXCHANGE).unwrap();
            } else {
                assert_eq!(r, Err(rustix::io::Errno::INVAL), "exchange in {dir:?}");
            }
            assert_eq!(fs::read_to_string(&a).unwrap(), "a");
            assert_eq!(fs::read_to_string(&b).unwrap(), "b");
            fs::remove_file(&a).unwrap();
            fs::remove_file(&b).unwrap();
        }
    }

    // locks are the guest kernel's own: they exclude processes on this guest, never the host
    fn locks(m: &Path) {
        let p = m.join("lock");
        fs::write(&p, "").unwrap();
        let a = File::open(&p).unwrap();
        let b = File::open(&p).unwrap();
        rustix::fs::flock(&a, FlockOperation::NonBlockingLockExclusive).unwrap();
        let r = rustix::fs::flock(&b, FlockOperation::NonBlockingLockExclusive);
        assert_eq!(r, Err(rustix::io::Errno::WOULDBLOCK), "second flock");
        rustix::fs::flock(&a, FlockOperation::Unlock).unwrap();
        rustix::fs::flock(&b, FlockOperation::NonBlockingLockExclusive).unwrap();
        drop((a, b));
        fs::remove_file(&p).unwrap();
    }
}
