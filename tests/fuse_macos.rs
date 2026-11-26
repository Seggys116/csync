// a real macos host on apfs with a linux guest in docker: case and unicode folding, macos metadata files,
// extended attributes. needs CSYNC_BIN (the macos build) and CSYNC_GUEST_IMAGE (an image with fuse3 and a
// linux csync at CSYNC_GUEST_BIN, default /usr/local/bin/csync; CSYNC_GUEST_VOLUME adds a `-v` mount for it)

#[test]
fn fuse_macos() {
    #[cfg(target_os = "macos")]
    mac::run();
    #[cfg(not(target_os = "macos"))]
    eprintln!("skip: the macos host test runs on macos only");
}

#[cfg(target_os = "macos")]
mod mac {
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        path::{Path, PathBuf},
        process::{Child, ChildStdin, Command, Output, Stdio},
        sync::mpsc::{self, Receiver},
        thread,
        time::{Duration, Instant},
    };

    struct Kill(Child, Option<String>);

    impl Drop for Kill {
        fn drop(&mut self) {
            if let Some(name) = &self.1 {
                let _ = Command::new("docker").args(["kill", name]).output();
            }
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct Clean(PathBuf);

    impl Drop for Clean {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn lines(child: &mut Child) -> Receiver<String> {
        let out = child.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    return;
                }
            }
        });
        rx
    }

    fn wait_for(rx: &Receiver<String>, what: &str, f: impl Fn(&str) -> bool) -> String {
        let end = Instant::now() + Duration::from_secs(90);
        while let Some(left) = end.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok(l) if f(&l) => return l,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!("timed out waiting for {what}");
    }

    fn eventually(what: &str, mut f: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(20);
        while Instant::now() < end {
            if f() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("timed out: {what}");
    }

    fn csync(bin: &Path, home: &Path, args: &[&str]) -> String {
        let out = Command::new(bin)
            .args(args)
            .env("CSYNC_HOME", home)
            .output()
            .expect("run csync");
        assert!(out.status.success(), "csync {args:?} failed");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn sh(name: &str, script: &str) -> Output {
        Command::new("docker")
            .args(["exec", name, "sh", "-c", script])
            .output()
            .expect("docker exec")
    }

    fn refused(o: &Output, why: &str) -> bool {
        !o.status.success() && String::from_utf8_lossy(&o.stderr).contains(why)
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    pub fn run() {
        let Some(bin) = std::env::var_os("CSYNC_BIN").map(PathBuf::from) else {
            eprintln!("skip: set CSYNC_BIN to the macos csync build");
            return;
        };
        let Ok(image) = std::env::var("CSYNC_GUEST_IMAGE") else {
            eprintln!("skip: set CSYNC_GUEST_IMAGE to a linux image with fuse3 and csync");
            return;
        };
        if !Command::new("docker")
            .arg("version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            eprintln!("skip: docker is not available");
            return;
        }
        let gbin =
            std::env::var("CSYNC_GUEST_BIN").unwrap_or_else(|_| "/usr/local/bin/csync".into());
        let tmp = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("csync-macos-{}", std::process::id()));
        let _clean = Clean(tmp.clone());
        let proj = tmp.join("proj \u{e9}");
        let hh = tmp.join("host-home");
        fs::create_dir_all(proj.join("Src")).unwrap();
        fs::write(proj.join("foo.txt"), "foo\n").unwrap();
        fs::write(proj.join("Src/main.c"), "m\n").unwrap();
        fs::write(proj.join("cafe\u{301}.txt"), "nfd\n").unwrap();
        fs::write(proj.join(".DS_Store"), "finder").unwrap();
        fs::write(proj.join("._foo.txt"), "appledouble").unwrap();
        fs::write(proj.join("Icon\r"), "").unwrap();
        fs::write(proj.join("tagged.txt"), "v1\n").unwrap();
        let tagged = fs::File::open(proj.join("tagged.txt")).unwrap();
        rustix::fs::fsetxattr(
            &tagged,
            "com.csync.test",
            b"red",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        drop(tagged);

        let hk = csync(&bin, &hh, &["key", "show"]);
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap()
            .port();
        let name = format!("csync-macos-it-{}", std::process::id());
        let script = format!(
            "{gbin} trust add {hk} --role host --name h >/dev/null && {gbin} key show && read _ && \
             mkdir -p /mnt/p && exec {gbin} --no-tui join /mnt/p --connect host.docker.internal:{port} --host h"
        );
        let mut args = vec![
            "run",
            "--rm",
            "-i",
            "--name",
            &name,
            "--device",
            "/dev/fuse",
            "--cap-add",
            "SYS_ADMIN",
            "--security-opt",
            "apparmor:unconfined",
            "-e",
            "CSYNC_HOME=/gh",
        ];
        let vol = std::env::var("CSYNC_GUEST_VOLUME").ok();
        if let Some(v) = &vol {
            args.extend(["-v", v.as_str()]);
        }
        args.extend([image.as_str(), "sh", "-c", script.as_str()]);
        let child = Command::new("docker")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("docker run");
        let mut guest = Kill(child, Some(name.clone()));
        let mut gin: ChildStdin = guest.0.stdin.take().unwrap();
        let grx = lines(&mut guest.0);
        let gk = wait_for(&grx, "the guest key", |l| l.len() == 44);
        csync(
            &bin,
            &hh,
            &["trust", "add", &gk, "--role", "guest", "--name", "g"],
        );

        let p = proj.to_str().unwrap().to_owned();
        let listen = format!("0.0.0.0:{port}");
        let mut host = Command::new(&bin)
            .args([
                "--no-tui",
                "host",
                &p,
                "--listen",
                &listen,
                "--no-mdns",
                "--no-pair",
            ])
            .env("CSYNC_HOME", &hh)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn host");
        let hrx = lines(&mut host);
        let _host = Kill(host, None);
        wait_for(&hrx, "the host index", |l| {
            l.starts_with("session role=host")
        });
        writeln!(gin, "go").unwrap();
        wait_for(&grx, "the guest mount", |l| l.starts_with("mounted "));

        // macos metadata files never reach the guest
        let ls = sh(&name, "ls -a /mnt/p");
        let listed = String::from_utf8_lossy(&ls.stdout).into_owned();
        assert!(
            listed.contains("foo.txt") && listed.contains("Src"),
            "{listed}"
        );
        for junk in [".DS_Store", "._foo.txt", "Icon\r"] {
            assert!(
                !listed.contains(junk),
                "{junk:?} reached the guest: {listed}"
            );
        }

        // case and normalisation variants of host names are refused, not merged or duplicated
        assert!(refused(
            &sh(&name, "echo g > /mnt/p/Foo.txt"),
            "File exists"
        ));
        assert!(refused(&sh(&name, "mkdir /mnt/p/src"), "File exists"));
        assert!(refused(
            &sh(&name, "printf x > \"/mnt/p/$(printf 'caf\\303\\251.txt')\""),
            "File exists"
        ));
        assert!(refused(
            &sh(&name, "touch \"/mnt/p/$(printf 'bad\\377')\""),
            "Invalid argument"
        ));
        assert_eq!(fs::read_to_string(proj.join("foo.txt")).unwrap(), "foo\n");

        // a case-only rename on either side renames in place
        assert!(
            sh(&name, "mv /mnt/p/foo.txt /mnt/p/FOO.txt")
                .status
                .success()
        );
        eventually("the host shows only FOO.txt", || {
            let n = names(&proj);
            n.contains(&"FOO.txt".into()) && !n.contains(&"foo.txt".into())
        });
        fs::rename(proj.join("Src"), proj.join("SRC")).unwrap();
        eventually("the guest shows only SRC", || {
            let o = String::from_utf8_lossy(&sh(&name, "ls /mnt/p").stdout).into_owned();
            o.lines().any(|l| l == "SRC") && !o.lines().any(|l| l == "Src")
        });
        assert_eq!(
            String::from_utf8_lossy(&sh(&name, "cat /mnt/p/SRC/main.c").stdout),
            "m\n"
        );

        // a guest edit keeps the host file's extended attributes
        assert!(sh(&name, "echo v2 > /mnt/p/tagged.txt").status.success());
        eventually("the guest edit reaches the host", || {
            fs::read_to_string(proj.join("tagged.txt")).is_ok_and(|s| s == "v2\n")
        });
        let f = fs::File::open(proj.join("tagged.txt")).unwrap();
        let mut v = [0u8; 8];
        let n = rustix::fs::fgetxattr(&f, "com.csync.test", &mut v[..]).unwrap();
        assert_eq!(&v[..n], b"red");

        // finder churn on metadata files is not synced
        for i in 0..20 {
            fs::write(proj.join(".DS_Store"), format!("{i}")).unwrap();
        }
        thread::sleep(Duration::from_millis(500));
        let ls = sh(&name, "ls -a /mnt/p");
        assert!(!String::from_utf8_lossy(&ls.stdout).contains(".DS_Store"));
        let _ = writeln!(gin, "quit");
    }
}
