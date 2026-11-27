// self-update with the install script's trust model: https from github.com/Seggys116/csync releases only,
// the archive checked against the release's .sha256 file and its listing before anything is installed

use crate::cli::{Coded, EXIT_ENV, EXIT_FAIL, EXIT_OK, EXIT_UPDATE_AVAILABLE, EXIT_USAGE};
use crate::crypto::trust::hex;
use crate::sys;
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    env,
    ffi::OsStr,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsFd,
        unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const RELEASES: &str = "https://github.com/Seggys116/csync/releases";
const TAG_PREFIX: &str = "https://github.com/Seggys116/csync/releases/tag/";
const INSTALL_URL: &str = "https://raw.githubusercontent.com/Seggys116/csync/main/install.sh";
// the three entries every release archive has, in byte order
const ARCHIVE_ENTRIES: [&str; 3] = ["LICENSE", "README.md", "csync"];
const SMALL_TIMEOUT: Duration = Duration::from_secs(60);
const ARCHIVE_TIMEOUT: Duration = Duration::from_secs(300);
const TAR_TIMEOUT: Duration = Duration::from_secs(120);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const OUT_CAP: u64 = 1 << 20;
const ERR_CAP: u64 = 4096;
const CHECKSUM_CAP: u64 = 4096;

pub struct Opts {
    pub check: bool,
    pub version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<PreIdent>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum PreIdent {
    Num(u64),
    Alpha(String),
}

impl Ord for Version {
    fn cmp(&self, o: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(o.major, o.minor, o.patch))
            .then_with(|| match (self.pre.is_empty(), o.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&o.pre),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

#[derive(Clone, Debug)]
pub struct Release {
    pub tag: String,
    pub text: String,
    pub version: Version,
}

fn fail(code: u8, msg: impl Into<String>) -> Coded {
    Coded {
        code,
        msg: msg.into(),
    }
}

fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn pre_ident(s: &str) -> Option<PreIdent> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
        return None;
    }
    if s.bytes().all(|c| c.is_ascii_digit()) {
        return Some(PreIdent::Num(s.parse().ok()?));
    }
    Some(PreIdent::Alpha(s.to_owned()))
}

// MAJOR.MINOR.PATCH with an optional -prerelease and +build; the build part never affects ordering
pub fn parse_version(s: &str) -> Option<Version> {
    let (rest, build) = match s.split_once('+') {
        Some((r, b)) => (r, Some(b)),
        None => (s, None),
    };
    if let Some(b) = build {
        let ok = b
            .split('.')
            .all(|i| !i.is_empty() && i.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
        if !ok {
            return None;
        }
    }
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let mut parts = core.split('.');
    let major = number(parts.next()?)?;
    let minor = number(parts.next()?)?;
    let patch = number(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    let pre = match pre {
        None => Vec::new(),
        Some(p) => p.split('.').map(pre_ident).collect::<Option<Vec<_>>>()?,
    };
    Some(Version {
        major,
        minor,
        patch,
        pre,
    })
}

pub fn strip_v(s: &str) -> &str {
    s.strip_prefix('v').unwrap_or(s)
}

// the same charset install.sh accepts for CSYNC_VERSION, plus a version that parses
pub fn parse_release(input: &str) -> Result<Release, String> {
    let ok = !input.is_empty()
        && input
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'-'));
    if !ok {
        return Err(format!(
            "invalid version '{input}': only letters, digits, '.', '+' and '-' are allowed"
        ));
    }
    let text = strip_v(input);
    let version = parse_version(text)
        .ok_or_else(|| format!("invalid version '{input}': expected MAJOR.MINOR.PATCH"))?;
    Ok(Release {
        tag: format!("v{text}"),
        text: text.to_owned(),
        version,
    })
}

// the release a github redirect to .../releases/tag/<tag> names
pub fn release_from_url(url: &str) -> Option<Release> {
    let url = url.trim();
    let head = url.get(..TAG_PREFIX.len())?;
    if !head.eq_ignore_ascii_case(TAG_PREFIX) {
        return None;
    }
    parse_release(&url[TAG_PREFIX.len()..]).ok()
}

// the release target install.sh picks: static musl on Linux, native arch under rosetta
pub fn release_target(os: &str, arch: &str, translated: bool) -> Result<String, String> {
    let os = match os {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-musl",
        o => return Err(format!("unsupported OS {o}; csync runs on macOS and Linux")),
    };
    let arch = match arch {
        "aarch64" | "arm64" => "aarch64",
        "x86_64" | "amd64" => "x86_64",
        a => return Err(format!("unsupported architecture {a}")),
    };
    let arch = if os == "apple-darwin" && arch == "x86_64" && translated {
        "aarch64"
    } else {
        arch
    };
    Ok(format!("{arch}-{os}"))
}

pub fn archive_name(target: &str) -> String {
    format!("csync-{target}.tar.gz")
}

// the first line of a .sha256 file: a lowercase sha-256 hex digest, optionally followed by the archive name
pub fn parse_checksum(text: &str, archive: &str) -> Result<String, String> {
    let malformed = || "malformed checksum file".to_owned();
    let mut fields = text.lines().next().unwrap_or("").split_whitespace();
    let digest = fields.next().ok_or_else(malformed)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(malformed());
    }
    if let Some(name) = fields.next() {
        let name = name.strip_prefix('*').unwrap_or(name);
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(format!("checksum file names a path ('{name}')"));
        }
        if name != archive {
            return Err(format!("checksum file is for '{name}', not '{archive}'"));
        }
    }
    if fields.next().is_some() {
        return Err(malformed());
    }
    Ok(digest.to_owned())
}

// install.sh's check: exactly LICENSE, README.md and csync, an optional leading ./ ignored
pub fn check_listing(listing: &str) -> Result<(), String> {
    let mut names: Vec<&str> = listing
        .lines()
        .map(|l| l.strip_prefix("./").unwrap_or(l))
        .collect();
    names.sort_unstable();
    if names == ARCHIVE_ENTRIES {
        Ok(())
    } else {
        Err(format!("unexpected archive contents: {}", names.join(" ")))
    }
}

// what tar left in the extraction directory: the same three names, csync a regular file
pub fn check_extracted(dir: &Path) -> Result<(), String> {
    let mut names = Vec::new();
    for e in fs::read_dir(dir).map_err(|e| format!("cannot read the extracted files: {e}"))? {
        let e = e.map_err(|e| format!("cannot read the extracted files: {e}"))?;
        names.push(e.file_name().to_string_lossy().into_owned());
    }
    names.sort_unstable();
    if names != ARCHIVE_ENTRIES {
        return Err(format!("unexpected extracted files: {}", names.join(" ")));
    }
    match fs::symlink_metadata(dir.join("csync")) {
        Ok(m) if m.file_type().is_file() => Ok(()),
        _ => Err("archive csync is not a regular file".to_owned()),
    }
}

pub fn version_output_matches(out: &str, version: &str) -> bool {
    out.split_whitespace().any(|t| t == version)
}

// a package manager's prefix: its files are replaced by that tool, not by csync
pub fn managed_by(path: &Path) -> Option<&'static str> {
    const PREFIXES: [(&str, &str); 8] = [
        ("/opt/homebrew/", "Homebrew"),
        ("/usr/local/Cellar/", "Homebrew"),
        ("/home/linuxbrew/", "Homebrew"),
        ("/nix/store/", "Nix"),
        ("/usr/bin/", "the system package manager"),
        ("/usr/sbin/", "the system package manager"),
        ("/bin/", "the system package manager"),
        ("/sbin/", "the system package manager"),
    ];
    let s = path.to_str()?;
    PREFIXES
        .iter()
        .find(|(p, _)| s.starts_with(p))
        .map(|(_, n)| *n)
}

// versioned package directories are never rewritten in place, writable or not
pub fn in_package_store(path: &Path) -> bool {
    path.starts_with("/nix/store") || path.components().any(|c| c.as_os_str() == "Cellar")
}

struct Run {
    ok: bool,
    stdout: Vec<u8>,
    stderr: String,
}

fn drain<R: Read>(mut r: R, cap: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = (&mut r).take(cap).read_to_end(&mut buf);
    let _ = io::copy(&mut r, &mut io::sink());
    buf
}

// runs a tool without a shell or stdin and kills it at the limit; stdout and stderr are capped
fn run_bounded(cmd: &mut Command, limit: Duration, cap: u64) -> io::Result<Run> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = child
        .stdout
        .take()
        .map(|s| thread::spawn(move || drain(s, cap)));
    let err = child
        .stderr
        .take()
        .map(|s| thread::spawn(move || drain(s, ERR_CAP)));
    let end = Instant::now() + limit;
    let status = loop {
        match child.try_wait().unwrap_or(None) {
            Some(st) => break Some(st),
            None if Instant::now() < end => thread::sleep(Duration::from_millis(20)),
            None => break None,
        }
    };
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stdout = out.and_then(|h| h.join().ok()).unwrap_or_default();
    let stderr = err.and_then(|h| h.join().ok()).unwrap_or_default();
    match status {
        Some(st) => Ok(Run {
            ok: st.success(),
            stdout,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        }),
        None => Err(io::Error::from(io::ErrorKind::TimedOut)),
    }
}

fn tool_error(tool: &str, e: io::Error) -> Coded {
    match e.kind() {
        io::ErrorKind::NotFound => fail(EXIT_ENV, format!("{tool} is required for csync update")),
        io::ErrorKind::TimedOut => fail(EXIT_FAIL, format!("{tool} timed out")),
        _ => fail(EXIT_FAIL, format!("cannot run {tool}: {e}")),
    }
}

fn curl() -> Command {
    let mut c = Command::new("curl");
    c.args([
        "-fsSL",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--retry",
        "3",
    ]);
    c
}

fn fetch(url: &str, dest: &Path, limit: Duration) -> Result<(), Coded> {
    let run = run_bounded(curl().arg(url).arg("-o").arg(dest), limit, OUT_CAP)
        .map_err(|e| tool_error("curl", e))?;
    if run.ok {
        Ok(())
    } else {
        Err(fail(
            EXIT_FAIL,
            format!("download of {url} failed: {}", run.stderr.trim()),
        ))
    }
}

// the final url of github's releases/latest redirect names the newest release tag
fn latest_release() -> Result<Release, Coded> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-fsSLI",
        "-o",
        "/dev/null",
        "-w",
        "%{url_effective}",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--retry",
        "3",
    ])
    .arg(format!("{RELEASES}/latest"));
    let run = run_bounded(&mut cmd, SMALL_TIMEOUT, ERR_CAP).map_err(|e| tool_error("curl", e))?;
    if !run.ok {
        return Err(fail(
            EXIT_FAIL,
            format!("cannot look up the latest release: {}", run.stderr.trim()),
        ));
    }
    let url = String::from_utf8_lossy(&run.stdout).into_owned();
    release_from_url(&url).ok_or_else(|| {
        fail(
            EXIT_FAIL,
            format!(
                "the latest release lookup ended at an unexpected address ({})",
                url.trim()
            ),
        )
    })
}

fn random_hex() -> io::Result<String> {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|_| io::Error::other("system random source failed"))?;
    Ok(hex(&r))
}

// a private directory removed on every exit path
struct Scratch(PathBuf);

impl Scratch {
    fn create(parent: &Path) -> io::Result<Scratch> {
        let p = parent.join(format!("csync-update-{}", random_hex()?));
        DirBuilder::new().mode(0o700).create(&p)?;
        Ok(Scratch(p))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// the new binary beside its target, removed unless the rename succeeded
struct Staged {
    path: PathBuf,
    armed: bool,
}

impl Drop for Staged {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    sys::full_fsync(File::open(dir)?.as_fd())
}

fn stage(dir: &Path, src: &Path) -> io::Result<Staged> {
    if !fs::symlink_metadata(src)?.file_type().is_file() {
        return Err(io::Error::other("archive csync is not a regular file"));
    }
    let path = dir.join(format!(".csync-update-{}", random_hex()?));
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&path)?;
    let staged = Staged { path, armed: true };
    io::copy(&mut File::open(src)?, &mut out)?;
    out.set_permissions(fs::Permissions::from_mode(0o755))?;
    sys::full_fsync(out.as_fd())?;
    Ok(staged)
}

fn dest_error(dir: &Path, what: &str, e: io::Error) -> Coded {
    match e.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => fail(
            EXIT_ENV,
            format!("cannot write to {}: {e}; {}", dir.display(), write_hint()),
        ),
        _ => fail(EXIT_FAIL, format!("{what}: {e}")),
    }
}

fn write_hint() -> String {
    format!(
        "rerun the install script (curl -fsSL {INSTALL_URL} | sh) or run csync update as a user that can write there"
    )
}

// writes src beside target, lets verify check the staged file, then renames it over target
pub fn replace_binary(
    target: &Path,
    src: &Path,
    verify: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<(), Coded> {
    let dir = target
        .parent()
        .ok_or_else(|| fail(EXIT_FAIL, format!("{} has no directory", target.display())))?;
    let mut staged =
        stage(dir, src).map_err(|e| dest_error(dir, "cannot stage the new binary", e))?;
    fsync_dir(dir).map_err(|e| dest_error(dir, "cannot sync the install directory", e))?;
    verify(&staged.path).map_err(|m| fail(EXIT_FAIL, m))?;
    fs::rename(&staged.path, target)
        .map_err(|e| dest_error(dir, "cannot replace the running binary", e))?;
    staged.armed = false;
    let _ = fsync_dir(dir);
    Ok(())
}

fn verify_new_binary(path: &Path, version: &str) -> Result<(), String> {
    let run = run_bounded(Command::new(path).arg("--version"), VERIFY_TIMEOUT, ERR_CAP)
        .map_err(|e| format!("the new binary does not run: {e}"))?;
    if !run.ok {
        return Err("the new binary failed to print its version".to_owned());
    }
    let out = String::from_utf8_lossy(&run.stdout);
    if version_output_matches(&out, version) {
        Ok(())
    } else {
        Err(format!(
            "the new binary reports '{}', expected {version}",
            out.trim()
        ))
    }
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(hex(h.finalize().as_slice()))
}

fn dir_writable(dir: &Path) -> bool {
    rustix::fs::access(
        dir,
        rustix::fs::Access::WRITE_OK | rustix::fs::Access::EXEC_OK,
    )
    .is_ok()
}

fn check_destination(exe: &Path, dir: &Path) -> Result<(), Coded> {
    let writable = dir_writable(dir);
    let managed = managed_by(exe).filter(|_| !writable || in_package_store(exe));
    if let Some(tool) = managed {
        return Err(fail(
            EXIT_ENV,
            format!(
                "{} belongs to {tool}; update it with that tool instead",
                exe.display()
            ),
        ));
    }
    if !writable {
        return Err(fail(
            EXIT_ENV,
            format!("cannot write to {}; {}", dir.display(), write_hint()),
        ));
    }
    Ok(())
}

fn rosetta() -> bool {
    run_bounded(
        Command::new("/usr/sbin/sysctl").args(["-n", "sysctl.proc_translated"]),
        PROBE_TIMEOUT,
        ERR_CAP,
    )
    .ok()
    .filter(|r| r.ok)
    .is_some_and(|r| String::from_utf8_lossy(&r.stdout).trim() == "1")
}

fn tar(args: &[&OsStr]) -> Result<Run, Coded> {
    let run = run_bounded(Command::new("tar").args(args), TAR_TIMEOUT, OUT_CAP)
        .map_err(|e| tool_error("tar", e))?;
    if run.ok {
        Ok(run)
    } else {
        Err(fail(
            EXIT_FAIL,
            format!("cannot unpack the archive: {}", run.stderr.trim()),
        ))
    }
}

fn install(release: &Release, current: &str) -> Result<u8, Coded> {
    let translated = env::consts::OS == "macos" && env::consts::ARCH == "x86_64" && rosetta();
    let target = release_target(env::consts::OS, env::consts::ARCH, translated)
        .map_err(|e| fail(EXIT_ENV, e))?;
    let exe = env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| {
            fail(
                EXIT_FAIL,
                format!("cannot locate the running csync binary: {e}"),
            )
        })?;
    let dir = exe
        .parent()
        .ok_or_else(|| fail(EXIT_FAIL, format!("{} has no directory", exe.display())))?;
    check_destination(&exe, dir)?;

    let archive = archive_name(&target);
    let base = format!("{RELEASES}/download/{}", release.tag);
    let scratch = Scratch::create(&env::temp_dir()).map_err(|e| {
        fail(
            EXIT_ENV,
            format!("cannot create a temporary directory: {e}"),
        )
    })?;
    let archive_path = scratch.0.join(&archive);
    let sum_path = scratch.0.join(format!("{archive}.sha256"));

    eprintln!("csync: downloading {archive} ({})", release.tag);
    fetch(&format!("{base}/{archive}"), &archive_path, ARCHIVE_TIMEOUT)
        .map_err(|e| fail(e.code, format!("{}; no release asset for {target}?", e.msg)))?;
    fetch(
        &format!("{base}/{archive}.sha256"),
        &sum_path,
        SMALL_TIMEOUT,
    )?;

    let mut text = String::new();
    File::open(&sum_path)
        .and_then(|f| f.take(CHECKSUM_CAP).read_to_string(&mut text))
        .map_err(|_| fail(EXIT_FAIL, "malformed checksum file"))?;
    let expected = parse_checksum(&text, &archive).map_err(|m| fail(EXIT_FAIL, m))?;
    let actual = sha256_file(&archive_path)
        .map_err(|e| fail(EXIT_FAIL, format!("cannot hash the download: {e}")))?;
    if expected != actual {
        return Err(fail(
            EXIT_FAIL,
            format!("checksum mismatch (expected {expected}, got {actual})"),
        ));
    }

    let listing = tar(&[OsStr::new("-tzf"), archive_path.as_os_str()])?;
    check_listing(&String::from_utf8_lossy(&listing.stdout)).map_err(|m| fail(EXIT_FAIL, m))?;

    let unpacked = scratch.0.join("x");
    DirBuilder::new()
        .mode(0o700)
        .create(&unpacked)
        .map_err(|e| {
            fail(
                EXIT_FAIL,
                format!("cannot create a temporary directory: {e}"),
            )
        })?;
    tar(&[
        OsStr::new("-xzf"),
        archive_path.as_os_str(),
        OsStr::new("-C"),
        unpacked.as_os_str(),
    ])?;
    check_extracted(&unpacked).map_err(|m| fail(EXIT_FAIL, m))?;

    replace_binary(&exe, &unpacked.join("csync"), &|p| {
        verify_new_binary(p, &release.text)
    })?;
    println!(
        "csync updated: {current} -> {}; restart any running host or join sessions to use it",
        release.text
    );
    Ok(EXIT_OK)
}

pub fn run(opts: &Opts) -> Result<u8, Coded> {
    let current_text = env!("CARGO_PKG_VERSION");
    let current = parse_version(current_text).ok_or_else(|| {
        fail(
            EXIT_FAIL,
            format!("cannot parse the running version {current_text}"),
        )
    })?;
    let pinned = opts
        .version
        .as_deref()
        .map(parse_release)
        .transpose()
        .map_err(|e| fail(EXIT_USAGE, e))?;
    let release = match &pinned {
        Some(r) => r.clone(),
        None => latest_release()?,
    };
    let order = release.version.cmp(&current);

    if opts.check {
        println!("current: {current_text}");
        println!("latest: {}", release.text);
        if order == Ordering::Greater {
            println!("update available; run `csync update`");
            return Ok(EXIT_UPDATE_AVAILABLE);
        }
        println!("csync {current_text} is up to date");
        return Ok(EXIT_OK);
    }
    if pinned.is_none() && order != Ordering::Greater {
        println!("csync {current_text} is up to date");
        return Ok(EXIT_OK);
    }
    if pinned.is_some() {
        match order {
            Ordering::Less => eprintln!(
                "csync: {} is older than {current_text}; installing it as a deliberate downgrade",
                release.text
            ),
            Ordering::Equal => eprintln!("csync: reinstalling {current_text}"),
            Ordering::Greater => {}
        }
    }
    install(&release, current_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        parse_version(strip_v(s)).unwrap_or_else(|| panic!("{s} should parse"))
    }

    #[test]
    fn compares_versions() {
        let table = [
            ("1.2.3", "1.2.3", Ordering::Equal),
            ("1.2.4", "1.2.3", Ordering::Greater),
            ("1.10.0", "1.9.0", Ordering::Greater),
            ("2.0.0", "1.99.99", Ordering::Greater),
            ("0.1.0", "0.2.0", Ordering::Less),
            ("v1.2.3", "1.2.3", Ordering::Equal),
            ("1.0.0-rc.1", "1.0.0", Ordering::Less),
            ("1.0.0", "1.0.0-rc.1", Ordering::Greater),
            ("1.0.0-rc.1", "1.0.0-rc.2", Ordering::Less),
            ("1.0.0-rc.2", "1.0.0-rc.10", Ordering::Less),
            ("1.0.0-alpha", "1.0.0-alpha.1", Ordering::Less),
            ("1.0.0-1", "1.0.0-alpha", Ordering::Less),
            ("1.0.0-alpha", "1.0.0-beta", Ordering::Less),
            ("1.0.0+build5", "1.0.0+build9", Ordering::Equal),
            ("1.0.0+zzz", "1.0.1", Ordering::Less),
            ("1.0.0-rc.1+a", "1.0.0-rc.1+b", Ordering::Equal),
        ];
        for (a, b, want) in table {
            assert_eq!(v(a).cmp(&v(b)), want, "{a} vs {b}");
            assert_eq!(v(b).cmp(&v(a)), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn rejects_malformed_versions() {
        for s in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1..3",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.3+",
            "v1.2.3",
            "..",
            "1.2.3+a+b",
            "99999999999999999999.0.0",
        ] {
            assert!(parse_version(s).is_none(), "{s:?}");
        }
    }

    #[test]
    fn validates_requested_versions() {
        let r = parse_release("1.2.3").unwrap();
        assert_eq!((r.tag.as_str(), r.text.as_str()), ("v1.2.3", "1.2.3"));
        let r = parse_release("v1.2.3-rc.1+b5").unwrap();
        assert_eq!(
            (r.tag.as_str(), r.text.as_str()),
            ("v1.2.3-rc.1+b5", "1.2.3-rc.1+b5")
        );
        for s in [
            "",
            "v",
            "..",
            "../1.2.3",
            "1/2/3",
            "1.2.3 ",
            "1.2.3;rm -rf /",
            "$(id)",
            "`id`",
            "1.2.3&x",
            "1.2.3\n",
            "vv1.2.3",
            "latest",
            "1.2",
        ] {
            assert!(parse_release(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn reads_the_tag_from_the_redirect_url() {
        let r =
            release_from_url("https://github.com/Seggys116/csync/releases/tag/v0.2.0\n").unwrap();
        assert_eq!(r.tag, "v0.2.0");
        assert_eq!(r.version, v("0.2.0"));
        for u in [
            "",
            "http://github.com/Seggys116/csync/releases/tag/v0.2.0",
            "https://github.com.evil.example/Seggys116/csync/releases/tag/v0.2.0",
            "https://github.com/Other/csync/releases/tag/v0.2.0",
            "https://github.com/Seggys116/csync/releases/tag/",
            "https://github.com/Seggys116/csync/releases/tag/v0.2.0/extra",
            "https://github.com/Seggys116/csync/releases/tag/v0.2.0?x=1",
            "https://github.com/Seggys116/csync/releases",
            "https://github.com/Seggys116/csync/releases/tag/nightly",
        ] {
            assert!(release_from_url(u).is_none(), "{u:?}");
        }
    }

    #[test]
    fn picks_the_release_target() {
        let table = [
            ("macos", "aarch64", false, "aarch64-apple-darwin"),
            ("macos", "x86_64", false, "x86_64-apple-darwin"),
            ("macos", "x86_64", true, "aarch64-apple-darwin"),
            ("macos", "aarch64", true, "aarch64-apple-darwin"),
            ("linux", "aarch64", false, "aarch64-unknown-linux-musl"),
            ("linux", "x86_64", false, "x86_64-unknown-linux-musl"),
            ("linux", "x86_64", true, "x86_64-unknown-linux-musl"),
        ];
        for (os, arch, translated, want) in table {
            assert_eq!(release_target(os, arch, translated).as_deref(), Ok(want));
        }
        assert!(release_target("freebsd", "x86_64", false).is_err());
        assert!(release_target("linux", "riscv64", false).is_err());
        assert_eq!(
            archive_name("aarch64-apple-darwin"),
            "csync-aarch64-apple-darwin.tar.gz"
        );
    }

    const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ARCHIVE: &str = "csync-x86_64-unknown-linux-musl.tar.gz";

    #[test]
    fn parses_checksum_files() {
        let ok = [
            format!("{HASH}  {ARCHIVE}\n"),
            format!("{HASH} *{ARCHIVE}\n"),
            format!("{HASH}\n"),
            format!("{HASH}  {ARCHIVE}\nignored second line\n"),
        ];
        for text in ok {
            assert_eq!(
                parse_checksum(&text, ARCHIVE).as_deref(),
                Ok(HASH),
                "{text:?}"
            );
        }
        let bad = [
            String::new(),
            "\n".to_owned(),
            format!("{}  {ARCHIVE}\n", &HASH[..63]),
            format!("{HASH}0  {ARCHIVE}\n"),
            format!("{}  {ARCHIVE}\n", HASH.to_uppercase()),
            format!("{}g  {ARCHIVE}\n", &HASH[..63]),
            format!("{HASH}  {ARCHIVE} extra\n"),
            format!("{HASH}  csync-aarch64-apple-darwin.tar.gz\n"),
            format!("{HASH}  dist/{ARCHIVE}\n"),
            format!("{HASH}  /tmp/{ARCHIVE}\n"),
            format!("{HASH}  ../{ARCHIVE}\n"),
            format!("{HASH}  ..\n"),
            format!("{HASH}  {ARCHIVE}/..\n"),
            format!("{HASH}  dist\\{ARCHIVE}\n"),
            "not a checksum\n".to_owned(),
        ];
        for text in bad {
            assert!(parse_checksum(&text, ARCHIVE).is_err(), "{text:?}");
        }
        let err = parse_checksum(&format!("{HASH}  ../{ARCHIVE}\n"), ARCHIVE).unwrap_err();
        assert!(err.contains("path"), "{err}");
    }

    #[test]
    fn checks_the_archive_listing() {
        for ok in [
            "csync\nLICENSE\nREADME.md\n",
            "LICENSE\nREADME.md\ncsync\n",
            "./csync\n./LICENSE\n./README.md\n",
        ] {
            assert_eq!(check_listing(ok), Ok(()), "{ok:?}");
        }
        for bad in [
            "",
            "csync\nLICENSE\n",
            "csync\nLICENSE\nREADME.md\nextra\n",
            "csync\nLICENSE\nREADME.md\ncsync\n",
            "csync\nLICENSE\nREADME.md\n.hidden\n",
            "/csync\nLICENSE\nREADME.md\n",
            "../csync\nLICENSE\nREADME.md\n",
            "csync\nLICENSE\nREADME.md/..\n",
            "csync/\nLICENSE\nREADME.md\n",
            "csync/csync\nLICENSE\nREADME.md\n",
            "./\ncsync\nLICENSE\nREADME.md\n",
            "csync\nlicense\nREADME.md\n",
            "/etc/passwd\nLICENSE\nREADME.md\n",
        ] {
            let err = check_listing(bad).unwrap_err();
            assert!(
                err.starts_with("unexpected archive contents"),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn matches_the_version_output() {
        assert!(version_output_matches("csync 0.2.0\n", "0.2.0"));
        assert!(!version_output_matches("csync 0.2.0\n", "0.2"));
        assert!(!version_output_matches("csync 0.2.01\n", "0.2.0"));
        assert!(!version_output_matches("", "0.2.0"));
    }

    #[test]
    fn spots_package_managed_paths() {
        assert_eq!(
            managed_by(Path::new("/opt/homebrew/bin/csync")),
            Some("Homebrew")
        );
        assert_eq!(
            managed_by(Path::new("/usr/bin/csync")),
            Some("the system package manager")
        );
        assert_eq!(
            managed_by(Path::new("/nix/store/abc-csync/bin/csync")),
            Some("Nix")
        );
        assert_eq!(managed_by(Path::new("/home/me/.local/bin/csync")), None);
        assert_eq!(managed_by(Path::new("/usr/local/bin/csync")), None);
        assert!(in_package_store(Path::new(
            "/opt/homebrew/Cellar/csync/0.1.0/bin/csync"
        )));
        assert!(in_package_store(Path::new(
            "/nix/store/abc-csync/bin/csync"
        )));
        assert!(!in_package_store(Path::new("/opt/homebrew/bin/csync")));
    }

    #[test]
    fn hashes_a_file() {
        let dir = Scratch::create(&env::temp_dir()).unwrap();
        let f = dir.0.join("abc");
        fs::write(&f, b"abc").unwrap();
        assert_eq!(sha256_file(&f).unwrap(), HASH);
    }

    #[test]
    fn bounds_a_slow_tool_and_reports_a_missing_one() {
        let slow = run_bounded(
            Command::new("sleep").arg("5"),
            Duration::from_millis(100),
            ERR_CAP,
        );
        assert_eq!(slow.err().map(|e| e.kind()), Some(io::ErrorKind::TimedOut));
        let echo = run_bounded(Command::new("echo").arg("hi"), SMALL_TIMEOUT, ERR_CAP).unwrap();
        assert!(echo.ok);
        assert_eq!(echo.stdout, b"hi\n");
        let missing = run_bounded(
            &mut Command::new("csync-no-such-tool"),
            SMALL_TIMEOUT,
            ERR_CAP,
        );
        assert_eq!(
            missing.err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn scratch_directory_is_private_and_removed() {
        let parent = Scratch::create(&env::temp_dir()).unwrap();
        let path = {
            let inner = Scratch::create(&parent.0).unwrap();
            fs::write(inner.0.join("f"), b"x").unwrap();
            let mode = fs::metadata(&inner.0).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
            inner.0.clone()
        };
        assert!(!path.exists());
    }

    #[test]
    fn checks_extracted_files() {
        let dir = Scratch::create(&env::temp_dir()).unwrap();
        for n in ARCHIVE_ENTRIES {
            fs::write(dir.0.join(n), b"x").unwrap();
        }
        assert_eq!(check_extracted(&dir.0), Ok(()));
        fs::write(dir.0.join("extra"), b"x").unwrap();
        assert!(check_extracted(&dir.0).is_err());
        fs::remove_file(dir.0.join("extra")).unwrap();
        fs::remove_file(dir.0.join("csync")).unwrap();
        std::os::unix::fs::symlink("/bin/sh", dir.0.join("csync")).unwrap();
        let err = check_extracted(&dir.0).unwrap_err();
        assert!(err.contains("regular file"), "{err}");
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut n: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        n.sort();
        n
    }

    #[test]
    fn replaces_the_binary_atomically_with_mode_755() {
        let dir = Scratch::create(&env::temp_dir()).unwrap();
        let target = dir.0.join("csync");
        let src = dir.0.join("new");
        fs::write(&target, b"old").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&src, b"new binary").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o600)).unwrap();

        let seen = std::cell::RefCell::new(None);
        replace_binary(&target, &src, &|staged| {
            assert_eq!(staged.parent(), Some(dir.0.as_path()));
            assert_eq!(fs::read(staged).unwrap(), b"new binary");
            assert_eq!(fs::read(&target).unwrap(), b"old");
            *seen.borrow_mut() = Some(fs::metadata(staged).unwrap().permissions().mode() & 0o777);
            Ok(())
        })
        .unwrap();

        assert_eq!(*seen.borrow(), Some(0o755));
        assert_eq!(fs::read(&target).unwrap(), b"new binary");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(names(&dir.0), ["csync", "new"]);
    }

    #[test]
    fn a_failed_verification_keeps_the_old_binary_and_leaves_no_temp_file() {
        let dir = Scratch::create(&env::temp_dir()).unwrap();
        let target = dir.0.join("csync");
        let src = dir.0.join("new");
        fs::write(&target, b"old").unwrap();
        fs::write(&src, b"new binary").unwrap();

        let err = replace_binary(&target, &src, &|_| Err("wrong version".to_owned())).unwrap_err();
        assert_eq!((err.code, err.msg.as_str()), (EXIT_FAIL, "wrong version"));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(names(&dir.0), ["csync", "new"]);
    }

    #[test]
    fn a_missing_or_irregular_source_leaves_the_target_and_no_temp_file() {
        let dir = Scratch::create(&env::temp_dir()).unwrap();
        let target = dir.0.join("csync");
        fs::write(&target, b"old").unwrap();
        let never = |_: &Path| -> Result<(), String> { panic!("verify must not run") };

        let missing = dir.0.join("missing");
        assert!(replace_binary(&target, &missing, &never).is_err());

        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(replace_binary(&target, &link, &never).is_err());

        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(names(&dir.0), ["csync", "link"]);
    }

    #[test]
    fn an_unwritable_directory_is_an_environment_error() {
        let dir = Scratch::create(&env::temp_dir()).unwrap();
        let target = dir.0.join("csync");
        let src = dir.0.join("new");
        fs::write(&target, b"old").unwrap();
        fs::write(&src, b"new").unwrap();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o500)).unwrap();
        let writable = dir_writable(&dir.0);
        let result = replace_binary(&target, &src, &|_| Ok(()));
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).unwrap();
        if writable {
            // running as root: permissions do not apply
            return;
        }
        let err = result.unwrap_err();
        assert_eq!(err.code, EXIT_ENV);
        assert!(err.msg.contains("install script"), "{}", err.msg);
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(names(&dir.0), ["csync", "new"]);
    }
}
