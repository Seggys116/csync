use crate::config::{self, Dirs};
use crate::crypto::trust::{IDENTITY_FILE, PEERS_FILE};
use crate::ctl::{self, CtlReq};
use crate::tui::{json_str, unescape};
use std::{
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const KERNEL_MIN: (u32, u32) = (5, 15);
const PASSTHROUGH_MIN: (u32, u32) = (6, 9);
const WATCHES_MIN: u64 = 524_288;
const CACHE_FREE_WARN: u64 = 2 << 30;
const SKEW_WARN_MS: u64 = 1_000;
const CAP_SYS_ADMIN: u32 = 21;
const PROC_MAX: u64 = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Pass,
    Info,
    Warn,
    Fail,
}

impl Level {
    pub fn word(self) -> &'static str {
        match self {
            Level::Pass => "pass",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    pub fix: Option<String>,
}

fn check(
    name: &'static str,
    level: Level,
    detail: impl Into<String>,
    fix: Option<String>,
) -> Check {
    Check {
        name,
        level,
        detail: detail.into(),
        fix,
    }
}

#[derive(Clone, Debug, Default)]
pub struct Opts {
    pub mount: Option<PathBuf>,
    pub allow_other: bool,
}

pub fn run(dirs: &Dirs, o: &Opts) -> Vec<Check> {
    let mut out = Vec::with_capacity(14);
    if cfg!(target_os = "linux") {
        out.push(dev_fuse());
        out.push(fusermount());
        let kernel = kernel_version();
        out.push(kernel_check(kernel));
        out.push(cap_sys_admin(kernel));
        out.push(fuse_conf(o.allow_other));
    }
    if cfg!(target_os = "linux") {
        out.push(mount_point(o.mount.as_deref()));
        out.push(stale_mounts());
    }
    #[cfg(target_os = "macos")]
    if let Ok(cwd) = std::env::current_dir() {
        out.push(project_volume(&cwd));
    }
    out.push(cache_space(&dirs.cache));
    #[cfg(target_os = "linux")]
    out.push(reflink(&dirs.cache));
    if cfg!(target_os = "linux") {
        out.push(inotify_watches());
    }
    out.push(clock_skew(dirs));
    out.push(git());
    out.push(trust_files(&dirs.config));
    out
}

pub fn failed(checks: &[Check]) -> bool {
    checks.iter().any(|c| c.level == Level::Fail)
}

pub fn render(checks: &[Check]) -> String {
    let mut s = String::with_capacity(checks.len() * 96);
    let w = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for c in checks {
        let _ = writeln!(
            s,
            "{:<4}  {:<w$}  {}",
            c.level.word().to_ascii_uppercase(),
            c.name,
            c.detail
        );
        if let Some(f) = &c.fix {
            let _ = writeln!(s, "{:<4}  {:<w$}  fix: {f}", "", "");
        }
    }
    let n = |l: Level| checks.iter().filter(|c| c.level == l).count();
    let _ = writeln!(
        s,
        "\n{} passed, {} warnings, {} failed",
        n(Level::Pass),
        n(Level::Warn),
        n(Level::Fail)
    );
    s
}

pub fn render_json(checks: &[Check]) -> String {
    let mut s = String::from("[");
    for (i, c) in checks.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"check\":");
        json_str(&mut s, c.name);
        s.push_str(",\"level\":");
        json_str(&mut s, c.level.word());
        s.push_str(",\"detail\":");
        json_str(&mut s, &c.detail);
        s.push_str(",\"fix\":");
        match &c.fix {
            Some(f) => json_str(&mut s, f),
            None => s.push_str("null"),
        }
        s.push('}');
    }
    s.push(']');
    s
}

fn euid_root() -> bool {
    rustix::process::geteuid().is_root()
}

fn read_small(p: &Path) -> io::Result<String> {
    use std::io::Read;
    let mut s = String::new();
    fs::File::open(p)?.take(PROC_MAX).read_to_string(&mut s)?;
    Ok(s)
}

fn dev_fuse() -> Check {
    const N: &str = "/dev/fuse";
    match fs::OpenOptions::new().read(true).write(true).open(N) {
        Ok(_) => check(N, Level::Pass, "readable and writable", None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => check(
            N,
            Level::Fail,
            "missing",
            Some("sudo modprobe fuse, or enable FUSE for this VM or container".into()),
        ),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => check(
            N,
            Level::Fail,
            "not accessible to this user",
            Some("sudo chmod 0666 /dev/fuse, or add your user to the group that owns it".into()),
        ),
        Err(e) => check(
            N,
            Level::Fail,
            format!("cannot open: {e}"),
            Some("check that the fuse module is loaded: lsmod | grep fuse".into()),
        ),
    }
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(
            ["/usr/bin", "/bin", "/usr/local/bin"]
                .iter()
                .map(PathBuf::from),
        )
        .map(|d| d.join(bin))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file()))
}

fn fusermount() -> Check {
    use std::os::unix::fs::MetadataExt;
    const N: &str = "fusermount3";
    let Some(p) = find_in_path(N) else {
        return check(
            N,
            Level::Fail,
            "not found",
            Some("install fuse3 (apt install fuse3, dnf install fuse3, pacman -S fuse3)".into()),
        );
    };
    let Ok(m) = fs::metadata(&p) else {
        return check(N, Level::Fail, format!("cannot stat {}", p.display()), None);
    };
    if m.mode() & 0o4000 != 0 && m.uid() == 0 {
        check(
            N,
            Level::Pass,
            format!("{} is setuid root", p.display()),
            None,
        )
    } else if euid_root() {
        check(
            N,
            Level::Pass,
            format!("{} (running as root)", p.display()),
            None,
        )
    } else {
        check(
            N,
            Level::Fail,
            format!("{} is not setuid root", p.display()),
            Some(format!(
                "sudo chown root {0} && sudo chmod u+s {0}",
                p.display()
            )),
        )
    }
}

pub fn parse_kernel(release: &str) -> Option<(u32, u32)> {
    let mut it = release.trim().split(|c: char| !c.is_ascii_digit());
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

fn kernel_version() -> Option<(u32, u32)> {
    parse_kernel(&read_small(Path::new("/proc/sys/kernel/osrelease")).ok()?)
}

fn kernel_check(k: Option<(u32, u32)>) -> Check {
    const N: &str = "kernel";
    match k {
        None => check(
            N,
            Level::Warn,
            "could not read /proc/sys/kernel/osrelease",
            None,
        ),
        Some(v) if v < KERNEL_MIN => check(
            N,
            Level::Fail,
            format!(
                "{}.{} is older than {}.{}",
                v.0, v.1, KERNEL_MIN.0, KERNEL_MIN.1
            ),
            Some("upgrade the guest kernel".into()),
        ),
        Some(v) if v >= PASSTHROUGH_MIN => check(
            N,
            Level::Pass,
            format!("{}.{}: FUSE passthrough supported", v.0, v.1),
            None,
        ),
        Some(v) => check(
            N,
            Level::Pass,
            format!(
                "{}.{}: writeback cache only, passthrough needs {}.{}+",
                v.0, v.1, PASSTHROUGH_MIN.0, PASSTHROUGH_MIN.1
            ),
            None,
        ),
    }
}

pub fn parse_cap_eff(status: &str) -> Option<u64> {
    let line = status.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
    u64::from_str_radix(line.trim(), 16).ok()
}

fn cap_sys_admin(k: Option<(u32, u32)>) -> Check {
    const N: &str = "CAP_SYS_ADMIN";
    let caps = read_small(Path::new("/proc/self/status"))
        .ok()
        .as_deref()
        .and_then(parse_cap_eff);
    let has = caps.is_some_and(|c| c & (1 << CAP_SYS_ADMIN) != 0);
    let passthrough_kernel = k.is_some_and(|v| v >= PASSTHROUGH_MIN);
    match (has, passthrough_kernel) {
        (true, true) => check(N, Level::Pass, "present: file data can use kernel passthrough", None),
        (true, false) => check(N, Level::Info, "present, but the kernel is too old for passthrough", None),
        (false, _) => check(
            N,
            Level::Warn,
            "absent: file data is served by csync, not kernel passthrough",
            Some("run csync join as root for passthrough, or keep build output (CARGO_TARGET_DIR) outside the mount".into()),
        ),
    }
}

fn fuse_conf(allow_other: bool) -> Check {
    const N: &str = "fuse.conf";
    if !allow_other {
        return check(
            N,
            Level::Info,
            "user_allow_other not needed without --allow-other",
            None,
        );
    }
    if euid_root() {
        return check(N, Level::Pass, "running as root", None);
    }
    let ok = read_small(Path::new("/etc/fuse.conf"))
        .is_ok_and(|t| t.lines().any(|l| l.trim() == "user_allow_other"));
    if ok {
        check(N, Level::Pass, "user_allow_other is enabled", None)
    } else {
        check(
            N,
            Level::Fail,
            "user_allow_other is not enabled in /etc/fuse.conf",
            Some("echo user_allow_other | sudo tee -a /etc/fuse.conf".into()),
        )
    }
}

pub fn is_enotconn(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOTCONN)
}

// the same rules join applies before mounting
pub fn mount_point_problem(p: &Path) -> Option<(Level, String, Option<String>)> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) if is_enotconn(&e) => Some((
            Level::Fail,
            "stale csync mount (transport endpoint is not connected)".into(),
            Some(format!("fusermount3 -uz '{}'", p.display())),
        )),
        Err(e) => Some((Level::Fail, format!("cannot inspect: {e}"), None)),
        Ok(m) if !m.is_dir() => Some((
            Level::Fail,
            "exists and is not a directory".into(),
            Some("choose an empty directory".into()),
        )),
        Ok(m) if m.uid() != rustix::process::getuid().as_raw() => Some((
            Level::Fail,
            "is owned by another user".into(),
            Some("choose a directory you own".into()),
        )),
        Ok(_) => match fs::read_dir(p).map(|mut rd| rd.next().is_none()) {
            Ok(true) => None,
            Ok(false) => Some((
                Level::Fail,
                "is not empty".into(),
                Some("choose an empty directory; csync never mounts over files".into()),
            )),
            Err(e) => Some((Level::Fail, format!("cannot list: {e}"), None)),
        },
    }
}

// the volume csync host would serve from this directory
#[cfg(target_os = "macos")]
fn project_volume(dir: &Path) -> Check {
    const N: &str = "project volume";
    match crate::sys::volume_of(dir) {
        Err(e) => check(N, Level::Warn, format!("{}: {e}", dir.display()), None),
        Ok((ty, false, _)) => check(
            N,
            Level::Warn,
            format!(
                "{} is on a network volume ({ty}): its changes are not reported to csync",
                dir.display()
            ),
            Some("keep the project on a local disk and run csync host there".into()),
        ),
        Ok((ty, true, true)) => check(N, Level::Pass, format!("{ty}, case-sensitive"), None),
        Ok((ty, true, false)) => check(
            N,
            Level::Info,
            format!(
                "{ty}, case-insensitive: guests cannot create names that differ only by case or unicode form"
            ),
            None,
        ),
    }
}

fn mount_point(p: Option<&Path>) -> Check {
    const N: &str = "mount point";
    let Some(p) = p else {
        return check(
            N,
            Level::Info,
            "pass --mount PATH to check a specific mount point",
            None,
        );
    };
    match mount_point_problem(p) {
        None => check(N, Level::Pass, format!("{} is usable", p.display()), None),
        Some((level, why, fix)) => check(N, level, format!("{} {why}", p.display()), fix),
    }
}

pub fn unescape_mountinfo(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && let Some(oct) = b.get(i + 1..i + 4)
            && oct.iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push(((oct[0] - b'0') << 6) | ((oct[1] - b'0') << 3) | (oct[2] - b'0'));
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// mount points of csync fuse mounts listed in a mountinfo table
pub fn csync_mounts(mountinfo: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for line in mountinfo.lines() {
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let Some(mp) = pre.split(' ').nth(4) else {
            continue;
        };
        let mut post = post.split(' ');
        let (Some(fstype), Some(source)) = (post.next(), post.next()) else {
            continue;
        };
        if fstype.starts_with("fuse") && (fstype.contains("csync") || source == "csync") {
            out.push(PathBuf::from(unescape_mountinfo(mp)));
        }
    }
    out
}

fn stale_mounts() -> Check {
    const N: &str = "stale mounts";
    let Ok(info) = read_small(Path::new("/proc/self/mountinfo")) else {
        return check(N, Level::Warn, "cannot read /proc/self/mountinfo", None);
    };
    let mounts = csync_mounts(&info);
    let stale: Vec<&PathBuf> = mounts
        .iter()
        .filter(|p| fs::metadata(p).is_err_and(|e| is_enotconn(&e)))
        .collect();
    if let Some(first) = stale.first() {
        let list = stale
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return check(
            N,
            Level::Fail,
            format!("not connected: {list}"),
            Some(format!("fusermount3 -uz '{}'", first.display())),
        );
    }
    match mounts.len() {
        0 => check(N, Level::Pass, "none", None),
        n => check(N, Level::Pass, format!("{n} healthy csync mount(s)"), None),
    }
}

fn cache_space(cache: &Path) -> Check {
    const N: &str = "cache space";
    match config::free_bytes(cache) {
        Ok(free) => {
            let cap = config::cache_cap_for_free(free);
            let detail = format!(
                "{} free under {}, default cache cap {}",
                crate::tui::view::fmt_bytes(free),
                cache.display(),
                crate::tui::view::fmt_bytes(cap)
            );
            if free < CACHE_FREE_WARN {
                check(
                    N,
                    Level::Warn,
                    detail,
                    Some("free some space or pass --cache-size to csync join".into()),
                )
            } else {
                check(N, Level::Pass, detail, None)
            }
        }
        Err(e) => check(
            N,
            Level::Warn,
            format!("cannot measure free space: {e}"),
            None,
        ),
    }
}

#[cfg(target_os = "linux")]
fn reflink(cache: &Path) -> Check {
    use std::io::Write;
    const N: &str = "reflink";
    if let Err(e) = config::ensure_private_dir(cache) {
        return check(N, Level::Warn, format!("cache dir unusable: {e}"), None);
    }
    let pid = std::process::id();
    let a = cache.join(format!(".doctor-{pid}-a"));
    let b = cache.join(format!(".doctor-{pid}-b"));
    let res = (|| -> io::Result<()> {
        let mut fa = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&a)?;
        fa.write_all(&[0x5a; 4096])?;
        fa.sync_all()?;
        let fb = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&b)?;
        Ok(rustix::fs::ioctl_ficlone(&fb, &fa)?)
    })();
    let _ = fs::remove_file(&a);
    let _ = fs::remove_file(&b);
    match res {
        Ok(()) => check(
            N,
            Level::Pass,
            "the cache filesystem supports reflinks: staging copies are free",
            None,
        ),
        Err(e) => check(
            N,
            Level::Info,
            format!(
                "no reflinks ({e}): staging files are copied, which costs disk and time for large files"
            ),
            None,
        ),
    }
}

fn inotify_watches() -> Check {
    const N: &str = "max_user_watches";
    match read_small(Path::new("/proc/sys/fs/inotify/max_user_watches")).ok().and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(n) if n >= WATCHES_MIN => check(N, Level::Pass, n.to_string(), None),
        Some(n) => check(
            N,
            Level::Warn,
            format!("{n}: a Linux host may run out of directory watches"),
            Some("echo fs.inotify.max_user_watches=1048576 | sudo tee /etc/sysctl.d/90-csync.conf && sudo sysctl --system".into()),
        ),
        None => check(N, Level::Info, "cannot read /proc/sys/fs/inotify/max_user_watches", None),
    }
}

pub fn skew_from_report(report: &str) -> Option<i64> {
    let live = report
        .lines()
        .any(|l| l.starts_with("peer ") && l.split(' ').any(|t| t == "state=live"));
    if !live {
        return None;
    }
    let stats = report.lines().find(|l| l.starts_with("stats "))?;
    stats
        .split(' ')
        .find_map(|t| t.strip_prefix("skew_ms="))
        .and_then(|v| unescape(v).parse().ok())
}

fn clock_skew(dirs: &Dirs) -> Check {
    const N: &str = "clock skew";
    let worst = dirs
        .ctl_sockets()
        .iter()
        .filter_map(|p| ctl::request(p, &CtlReq::Status).ok())
        .filter_map(|r| skew_from_report(&r))
        .max_by_key(|s| s.unsigned_abs());
    match worst {
        None => check(N, Level::Info, "measured while connected; run csync doctor during a session to see it", None),
        Some(ms) if ms.unsigned_abs() >= SKEW_WARN_MS => check(
            N,
            Level::Warn,
            format!("{ms} ms between host and guest: tools that compare mtimes (cargo, make) may rebuild or skip work"),
            Some("enable NTP on both machines (timedatectl set-ntp true, or System Settings > Date & Time)".into()),
        ),
        Some(ms) => check(N, Level::Pass, format!("{ms} ms"), None),
    }
}

fn git() -> Check {
    const N: &str = "git";
    match Command::new("git")
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => check(
            N,
            Level::Pass,
            String::from_utf8_lossy(&o.stdout).trim().to_owned(),
            None,
        ),
        _ => check(
            N,
            Level::Warn,
            "not found: on a host, tracked files under ignored paths will not be synced",
            Some("install git on the host".into()),
        ),
    }
}

fn trust_files(dir: &Path) -> Check {
    const N: &str = "trust files";
    let fix = Some(format!(
        "chmod 700 '{0}' && chmod 600 '{0}/{IDENTITY_FILE}' '{0}/{PEERS_FILE}'",
        dir.display()
    ));
    match config::check_private_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return check(
                N,
                Level::Info,
                "no identity yet; one is created on first use",
                None,
            );
        }
        Err(e) => return check(N, Level::Fail, e.to_string(), fix),
        Ok(()) => {}
    }
    for f in [IDENTITY_FILE, PEERS_FILE] {
        match config::open_private(&dir.join(f)) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return check(N, Level::Fail, e.to_string(), fix),
        }
    }
    check(
        N,
        Level::Pass,
        format!("{} is private", dir.display()),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_and_caps() {
        assert_eq!(parse_kernel("6.8.0-45-generic\n"), Some((6, 8)));
        assert_eq!(
            parse_kernel("5.15.167.4-microsoft-standard-WSL2"),
            Some((5, 15))
        );
        assert_eq!(parse_kernel("garbage"), None);
        assert_eq!(
            parse_cap_eff("Name:\tx\nCapEff:\t000001ffffffffff\n"),
            Some(0x1ff_ffff_ffff)
        );
        assert_eq!(parse_cap_eff("CapEff:\tzz\n"), None);
    }

    #[test]
    fn finds_csync_mounts_and_unescapes_paths() {
        let info = "36 35 0:31 / /home/u/my\\040proj rw,nosuid - fuse.csync csync rw,user_id=1000\n\
                    37 35 0:32 / /mnt/other rw - fuse.sshfs host:/ rw\n\
                    38 35 0:33 / /mnt/c rw - fuse csync rw\n";
        assert_eq!(
            csync_mounts(info),
            vec![PathBuf::from("/home/u/my proj"), PathBuf::from("/mnt/c")]
        );
        assert_eq!(unescape_mountinfo("a\\134b\\9"), "a\\b\\9");
    }

    #[test]
    fn skew_needs_a_live_peer() {
        let r = "session role=guest\npeer id=1 state=live\nstats files=1 skew_ms=-1500\n";
        assert_eq!(skew_from_report(r), Some(-1500));
        assert_eq!(
            skew_from_report("peer id=1 state=disconnected\nstats skew_ms=9\n"),
            None
        );
    }

    #[test]
    fn json_output_escapes() {
        let c = vec![check("a", Level::Warn, "x\"y", None)];
        assert_eq!(
            render_json(&c),
            "[{\"check\":\"a\",\"level\":\"warn\",\"detail\":\"x\\\"y\",\"fix\":null}]"
        );
    }
}
