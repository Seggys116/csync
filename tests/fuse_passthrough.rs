// kernel passthrough only engages when the cache sits on a filesystem that can back it, so this mounts a tmpfs
// for the whole world; needs CSYNC_BIN, root and a kernel that offers passthrough, and skips otherwise

#[test]
fn edits_reach_a_file_another_process_holds_open() {
    #[cfg(target_os = "linux")]
    pass::held_open();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE passthrough test runs on Linux only");
}

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod pass {
    use super::common::*;
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    fn read_all(f: &mut File) -> std::io::Result<String> {
        let mut s = String::new();
        f.seek(SeekFrom::Start(0))?;
        f.read_to_string(&mut s)?;
        Ok(s)
    }

    pub fn held_open() {
        if bin().is_none() {
            return;
        }
        let base = TempDir::new("passthrough");
        let fsdir = base.0.join("fs");
        fs::create_dir_all(&fsdir).unwrap();
        let mounted = Command::new("mount")
            .args(["-t", "tmpfs", "-o", "size=256m", "tmpfs"])
            .arg(&fsdir)
            .status()
            .is_ok_and(|s| s.success());
        if !mounted {
            eprintln!(
                "skip: mounting a tmpfs for the passthrough cache needs root (CAP_SYS_ADMIN)"
            );
            return;
        }
        let _fs = Unmount(fsdir.clone());
        let mut w = World::with_tmp(TempDir::new_in(&fsdir, "pass"), |p| {
            write_project(p);
            fs::write(p.join(".gitignore"), "target/\n").unwrap();
            fs::write(p.join("a.txt"), "a1\n").unwrap();
            fs::write(p.join("b.txt"), "b1\n").unwrap();
        });
        let g = w.guest("g");
        let mut host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("a.txt on the guest", SYNC, || {
            read(&g.mnt.join("a.txt")).as_deref() == Some("a1\n")
        });
        // the status record is refreshed with the periodic stats, so give it a few ticks
        let end = Instant::now() + Duration::from_secs(5);
        let mut on = false;
        while !on && Instant::now() < end {
            on = csync(&w.bin, &g.home, &["status", "--json"]).contains("\"passthrough\":true");
            thread::sleep(Duration::from_millis(200));
        }
        if !on {
            eprintln!("skip: the kernel did not offer FUSE passthrough to this mount");
            guest.quit(SYNC);
            host.quit(SYNC);
            return;
        }

        // overlay files keep passthrough: a second open of a held file shares its backing
        let ov = g.mnt.join("target/out.bin");
        fs::create_dir_all(g.mnt.join("target")).unwrap();
        fs::write(&ov, "o1\n").unwrap();
        let mut held_ov = File::open(&ov).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&ov)
            .and_then(|mut f| f.write_all(b"o2\n"))
            .expect("append to an overlay file another handle holds open");
        assert_eq!(read_all(&mut held_ov).unwrap(), "o1\no2\n");
        assert_eq!(read(&ov).as_deref(), Some("o1\no2\n"));

        // a host edit while a guest process holds the file open
        let mut held_a = File::open(g.mnt.join("a.txt")).unwrap();
        assert_eq!(read_all(&mut held_a).unwrap(), "a1\n");
        fs::write(w.proj.join("a.txt"), "a1\na2 from the host\n").unwrap();
        eventually("the host edit through a new open", SYNC, || {
            read(&g.mnt.join("a.txt")).as_deref() == Some("a1\na2 from the host\n")
        });
        eventually("the host edit through the held handle", SYNC, || {
            read_all(&mut held_a).ok().as_deref() == Some("a1\na2 from the host\n")
        });
        drop(held_a);

        // a guest write while another guest process holds the file open
        let mut held_b = File::open(g.mnt.join("b.txt")).unwrap();
        assert_eq!(read_all(&mut held_b).unwrap(), "b1\n");
        let mut f = OpenOptions::new()
            .append(true)
            .open(g.mnt.join("b.txt"))
            .expect("open for write a file another process holds open");
        f.write_all(b"b2 from the guest\n").unwrap();
        close_checked(f).unwrap();
        assert_eq!(
            read(&g.mnt.join("b.txt")).as_deref(),
            Some("b1\nb2 from the guest\n")
        );
        eventually("the guest write on the host", SYNC, || {
            read(&w.proj.join("b.txt")).as_deref() == Some("b1\nb2 from the guest\n")
        });
        drop(held_b);
        drop(held_ov);

        guest.quit(SYNC);
        host.quit(SYNC);
    }
}
