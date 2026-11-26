// failures real build tools and package managers hit on the mount: each test is the smallest form of what the
// tool does, and failed before its fix

#[test]
fn fuse_tools() {
    #[cfg(target_os = "linux")]
    tools::run();
    #[cfg(not(target_os = "linux"))]
    eprintln!("skip: the FUSE tools test runs on Linux only");
}

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod tools {
    use super::common::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, symlink},
        path::Path,
        thread,
        time::Duration,
    };

    pub fn run() {
        if bin().is_none() {
            return;
        }
        let mut w = World::new("tools", write_project);
        let g = w.guest("g");
        let _host = w.spawn_host();
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        let m = g.mnt.clone();
        eventually("README on the guest", SYNC, || m.join("README.md").exists());

        self_ignoring_dir(&m, &w.proj);
        vendor_staging_renames(&m, &w.proj);

        // after a restart the overlay copy of the rule file still governs its synced directory
        guest.quit(Duration::from_secs(30));
        let mut guest = w.spawn_guest(&g, &w.addr.clone(), &[]);
        eventually("README after restart", SYNC, || {
            m.join("README.md").exists()
        });
        fs::write(m.join("venv/late.txt"), b"guest only\n").unwrap();
        thread::sleep(Duration::from_secs(2));
        assert!(
            !w.proj.join("venv/late.txt").exists(),
            "ignored file reached the host"
        );
        // rm -rf of the whole environment also clears the empty dirs, link and rule the host kept from before
        // the rule; a regular file the host kept would stop it, so that one goes on the host
        fs::remove_file(w.proj.join("venv/bin/activate")).unwrap();
        fs::remove_dir_all(m.join("venv")).unwrap_or_else(|e| panic!("rm -rf venv: {e}"));
        eventually("venv gone on the host", SYNC, || {
            !w.proj.join("venv").exists()
        });
        guest.quit(Duration::from_secs(30));
    }

    // python -m venv (and meson, pytest, ruff, mypy caches) fills a directory, then writes a `*` .gitignore
    // into it: the guest keeps what it wrote as ignored entries instead of losing them
    fn self_ignoring_dir(m: &Path, proj: &Path) {
        let v = m.join("venv");
        fs::create_dir_all(v.join("bin")).unwrap();
        fs::create_dir_all(v.join("lib/site-packages")).unwrap();
        symlink("lib", v.join("lib64")).unwrap();
        fs::write(v.join("bin/activate"), b"# activate\n").unwrap();
        let mtime = fs::metadata(v.join("bin/activate")).unwrap().mtime();
        eventually("host has bin/activate", SYNC, || {
            proj.join("venv/bin/activate").exists()
        });
        fs::write(v.join(".gitignore"), b"*\n").unwrap();
        eventually("host has the rule", SYNC, || {
            proj.join("venv/.gitignore").exists()
        });
        // the host's rescan of the newly ignored entries reaches the guest
        thread::sleep(Duration::from_secs(2));
        assert_eq!(
            fs::read(v.join("bin/activate")).ok().as_deref(),
            Some(&b"# activate\n"[..]),
            "a file the guest wrote vanished when its directory became ignored"
        );
        assert_eq!(fs::metadata(v.join("bin/activate")).unwrap().mtime(), mtime);
        assert_eq!(fs::read_link(v.join("lib64")).unwrap(), Path::new("lib"));
        assert_eq!(fs::read(v.join(".gitignore")).unwrap(), b"*\n");
        assert!(v.join("lib/site-packages").is_dir());
        // ignored now: absolute links are allowed and nothing new reaches the host
        symlink("/usr/bin/python3", v.join("bin/python3"))
            .unwrap_or_else(|e| panic!("venv interpreter link: {e}"));
        fs::write(v.join("pyvenv.cfg"), b"home = /usr/bin\n").unwrap();
        fs::write(v.join("lib/site-packages/m.py"), b"x = 1\n").unwrap();
        thread::sleep(Duration::from_secs(2));
        for p in [
            "venv/bin/python3",
            "venv/pyvenv.cfg",
            "venv/lib/site-packages/m.py",
        ] {
            assert!(!proj.join(p).exists(), "{p} reached the host");
        }
        let mut names: Vec<_> = fs::read_dir(v.join("bin"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["activate", "python3"]);
    }

    // cargo vendor fills a staging directory and renames each crate into place at once; a subdirectory made
    // just before the rename went missing on the guest while the host kept it
    fn vendor_staging_renames(m: &Path, proj: &Path) {
        let body = vec![b'v'; 3000];
        for c in 0..30 {
            let s = m.join(format!("vendor/.staging/c{c}"));
            fs::create_dir_all(s.join("src")).unwrap();
            for i in 0..150 {
                fs::write(s.join(format!("src/f{i}.rs")), &body).unwrap();
            }
            fs::create_dir(s.join("tests")).unwrap();
            fs::write(s.join("tests/t.rs"), &body).unwrap();
            fs::rename(&s, m.join(format!("vendor/c{c}"))).unwrap();
        }
        fs::remove_dir(m.join("vendor/.staging")).unwrap();
        if let Err(d) = converge(&proj.join("vendor"), &m.join("vendor"), SYNC, &|_| false) {
            panic!("vendor tree differs between host and guest: {d:#?}");
        }
        fs::remove_dir_all(m.join("vendor")).unwrap_or_else(|e| panic!("rm -rf vendor: {e}"));
        eventually("vendor gone on the host", SYNC, || {
            !proj.join("vendor").exists()
        });
    }
}
