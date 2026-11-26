use super::rules::Rules;
use crate::proto::{RelPath, TEXT_MAX};
use crate::sys;
use std::{
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Read},
    os::fd::AsFd,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub const GIT_OUT_MAX: usize = 64 << 20;
const DOTGIT_MAX: usize = 4096;
const CONFIG_MAX: usize = 1 << 20;
const INCLUDE_DEPTH: u32 = 10;
// global excludes plus an external info/exclude must fit one ExcludeSrc on the wire
const EXTRA_PART_MAX: usize = TEXT_MAX / 2 - 1;

const GIT_ENV_REMOVE: [&str; 9] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_CEILING_DIRECTORIES",
];

#[derive(Clone, Debug)]
pub struct RepoInfo {
    pub worktree: RelPath,
    pub gitdir: Option<PathBuf>,
    pub common: Option<PathBuf>,
    // these are Some only when the git dir lives inside the project root
    pub common_rel: Option<RelPath>,
    pub index_rel: Option<RelPath>,
}

pub fn read_bounded(path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if !f.metadata()?.is_file() {
        return Ok(None);
    }
    let mut out = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut out)?;
    if out.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds its size limit",
        ));
    }
    Ok(Some(out))
}

fn abs(root: &Path, p: &RelPath) -> PathBuf {
    if p.is_root() {
        root.to_path_buf()
    } else {
        root.join(p.as_str())
    }
}

fn rel_inside(root_c: &Path, p: &Path) -> Option<RelPath> {
    RelPath::new(p.strip_prefix(root_c).ok()?.to_str()?).ok()
}

// a gitlink file reads "gitdir: <path>", relative to the directory holding it
fn resolve_gitdir(wt_abs: &Path) -> Option<PathBuf> {
    let dotgit = wt_abs.join(".git");
    let md = fs::symlink_metadata(&dotgit).ok()?;
    if md.is_dir() {
        return fs::canonicalize(&dotgit).ok();
    }
    if !md.is_file() {
        return None;
    }
    let text = read_bounded(&dotgit, DOTGIT_MAX).ok()??;
    let first = text.split(|&b| b == b'\n').next()?;
    let target = first.strip_prefix(b"gitdir:")?.trim_ascii();
    if target.is_empty() {
        return None;
    }
    fs::canonicalize(wt_abs.join(OsStr::from_bytes(target))).ok()
}

fn common_dir(gitdir: &Path) -> PathBuf {
    let Ok(Some(text)) = read_bounded(&gitdir.join("commondir"), DOTGIT_MAX) else {
        return gitdir.to_path_buf();
    };
    let target = text
        .split(|&b| b == b'\n')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    if target.is_empty() {
        return gitdir.to_path_buf();
    }
    fs::canonicalize(gitdir.join(OsStr::from_bytes(target)))
        .unwrap_or_else(|_| gitdir.to_path_buf())
}

pub fn inspect(root: &Path, worktree: &RelPath) -> RepoInfo {
    let root_c = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let gitdir = resolve_gitdir(&abs(root, worktree));
    let common = gitdir.as_deref().map(common_dir);
    let common_rel = common.as_deref().and_then(|c| rel_inside(&root_c, c));
    let index_rel = gitdir
        .as_deref()
        .and_then(|g| rel_inside(&root_c, &g.join("index")));
    RepoInfo {
        worktree: worktree.clone(),
        gitdir,
        common,
        common_rel,
        index_rel,
    }
}

// registers a worktree that has a .git entry: info/exclude, excludes file and tracked-ignored exceptions
pub fn register(rules: &mut Rules, root: &Path, worktree: &RelPath) -> RepoInfo {
    if worktree.is_root() {
        probe_fold(rules, root);
    }
    let info = inspect(root, worktree);
    let wt_abs = abs(root, worktree);
    let nominal = RelPath::new(&join_rel(worktree, ".git")).unwrap_or_else(|_| worktree.clone());
    rules.add_repo(worktree, info.common_rel.as_ref().unwrap_or(&nominal));

    let mut extra = read_excludes(&wt_abs, info.common.as_deref());
    if let Some(common) = info.common.as_deref() {
        let text = read_bounded(&common.join("info").join("exclude"), EXTRA_PART_MAX)
            .ok()
            .flatten();
        match info
            .common_rel
            .as_ref()
            .and_then(|c| RelPath::new(&join_rel(c, "info/exclude")).ok())
        {
            Some(rel) => {
                rules.set_rule_file(&rel, text.as_deref());
            }
            None => {
                if let Some(t) = text {
                    extra.push(b'\n');
                    extra.extend_from_slice(&t);
                }
            }
        }
    }
    rules.set_extra(worktree, Some(&extra));
    rules.set_repo_exceptions(worktree, tracked_ignored(&wt_abs, worktree));
    info
}

// a project root that is not itself a repo still honours the user's global excludes
pub fn register_plain_root(rules: &mut Rules, root: &Path) {
    probe_fold(rules, root);
    let extra = read_excludes(root, None);
    rules.set_extra(&RelPath::root(), Some(&extra));
}

// once per Rules; a root that cannot be probed is treated as folding names, which only refuses more
fn probe_fold(rules: &mut Rules, root: &Path) {
    if rules.fold_known() {
        return;
    }
    let probed = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)
    .and_then(|fd| sys::probe_fold(fd.as_fd()));
    match probed {
        Ok((case, norm)) => rules.set_fs_fold(case, norm),
        Err(_) => rules.set_fs_fold(false, true),
    }
}

pub fn refresh_exceptions(rules: &mut Rules, root: &Path, worktree: &RelPath) {
    rules.set_repo_exceptions(worktree, tracked_ignored(&abs(root, worktree), worktree));
}

fn join_rel(a: &RelPath, b: &str) -> String {
    if a.is_root() {
        b.to_owned()
    } else {
        format!("{}/{b}", a.as_str())
    }
}

fn read_excludes(wt_abs: &Path, common: Option<&Path>) -> Vec<u8> {
    excludes_file(wt_abs, common)
        .and_then(|p| read_bounded(&p, EXTRA_PART_MAX).ok().flatten())
        .unwrap_or_default()
}

pub fn tracked_ignored(wt_abs: &Path, worktree: &RelPath) -> Vec<RelPath> {
    let Ok((0, out)) = run_git(
        wt_abs,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--ignored",
            "--exclude-standard",
        ],
        GIT_OUT_MAX,
    ) else {
        return Vec::new();
    };
    out.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok())
        .filter_map(|s| {
            if worktree.is_root() {
                RelPath::new(s).ok()
            } else {
                RelPath::new(&format!("{}/{s}", worktree.as_str())).ok()
            }
        })
        .collect()
}

// fixed argv, no shell, no inherited repository overrides, output capped at max bytes
pub fn run_git(dir: &Path, args: &[&str], max: usize) -> io::Result<(i32, Vec<u8>)> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).args(args);
    for k in GIT_ENV_REMOVE {
        cmd.env_remove(k);
    }
    cmd.env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let mut out = Vec::new();
    let read = match child.stdout.take() {
        Some(s) => s.take(max as u64 + 1).read_to_end(&mut out).map(|_| ()),
        None => Ok(()),
    };
    if read.is_err() || out.len() > max {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "git output exceeds its limit",
        ));
    }
    let status = child.wait()?;
    Ok((status.code().unwrap_or(-1), out))
}

pub fn excludes_file(wt_abs: &Path, common: Option<&Path>) -> Option<PathBuf> {
    match run_git(
        wt_abs,
        &["config", "--path", "--get", "core.excludesFile"],
        CONFIG_MAX,
    ) {
        Ok((0, out)) => {
            let v = out.strip_suffix(b"\n").unwrap_or(&out);
            if v.is_empty() {
                return None;
            }
            Some(wt_abs.join(OsStr::from_bytes(v)))
        }
        Ok((1, _)) => default_excludes(),
        _ => {
            let mut val = None;
            for f in config_files(common) {
                parse_config(&f, 0, &mut val);
            }
            match val {
                Some(v) if v.is_empty() => None,
                Some(v) => Some(wt_abs.join(expand_tilde(&v))),
                None => default_excludes(),
            }
        }
    }
}

fn home() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

fn xdg_config() -> Option<PathBuf> {
    match env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => Some(PathBuf::from(x)),
        _ => home().map(|h| h.join(".config")),
    }
}

fn default_excludes() -> Option<PathBuf> {
    xdg_config().map(|x| x.join("git").join("ignore"))
}

fn expand_tilde(v: &str) -> PathBuf {
    match (v.strip_prefix("~/"), home()) {
        (Some(rest), Some(h)) => h.join(rest),
        _ if v == "~" => home().unwrap_or_else(|| PathBuf::from(v)),
        _ => PathBuf::from(v),
    }
}

// same order git reads them in; the last assignment wins
fn config_files(common: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if env::var_os("GIT_CONFIG_NOSYSTEM").is_none() {
        v.push(
            env::var_os("GIT_CONFIG_SYSTEM")
                .map_or_else(|| PathBuf::from("/etc/gitconfig"), PathBuf::from),
        );
    }
    match env::var_os("GIT_CONFIG_GLOBAL") {
        Some(g) => v.push(PathBuf::from(g)),
        None => {
            if let Some(x) = xdg_config() {
                v.push(x.join("git").join("config"));
            }
            if let Some(h) = home() {
                v.push(h.join(".gitconfig"));
            }
        }
    }
    if let Some(c) = common {
        v.push(c.join("config"));
    }
    v
}

// fallback when git itself is unavailable: core.excludesFile and unconditional include.path only
fn parse_config(path: &Path, depth: u32, val: &mut Option<String>) {
    if depth > INCLUDE_DEPTH {
        return;
    }
    let Ok(Some(bytes)) = read_bounded(path, CONFIG_MAX) else {
        return;
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut section = String::new();
    let mut lines = text.lines();
    while let Some(raw) = lines.next() {
        let mut l = raw.trim_start();
        if let Some(rest) = l.strip_prefix('[') {
            let Some(end) = rest.find(']') else { continue };
            let hdr = &rest[..end];
            let name = hdr
                .split(|c: char| c.is_whitespace() || c == '.')
                .next()
                .unwrap_or_default();
            section = if hdr.len() == name.len() {
                name.to_ascii_lowercase()
            } else {
                String::new()
            };
            l = rest[end + 1..].trim_start();
        }
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let (key, rawv) = match l.find('=') {
            Some(i) => (l[..i].trim(), &l[i + 1..]),
            None => continue,
        };
        let value = parse_value(rawv, &mut lines);
        match (section.as_str(), key.to_ascii_lowercase().as_str()) {
            ("core", "excludesfile") => *val = Some(value),
            ("include", "path") if !value.is_empty() => {
                let inc = expand_tilde(&value);
                let inc = if inc.is_relative() {
                    path.parent().map_or(inc.clone(), |d| d.join(&inc))
                } else {
                    inc
                };
                parse_config(&inc, depth + 1, val);
            }
            _ => {}
        }
    }
}

fn parse_value<'a>(first: &'a str, rest: &mut impl Iterator<Item = &'a str>) -> String {
    let mut out = String::new();
    let mut quoted = false;
    let mut cur = first;
    loop {
        let mut chars = cur.chars();
        let mut cont = false;
        while let Some(c) = chars.next() {
            match c {
                '"' => quoted = !quoted,
                '\\' => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('b') => {
                        out.pop();
                    }
                    Some(o) => out.push(o),
                    None => cont = true,
                },
                '#' | ';' if !quoted => break,
                c => out.push(c),
            }
        }
        if !cont {
            break;
        }
        match rest.next() {
            Some(n) => cur = n,
            None => break,
        }
    }
    out.trim().to_owned()
}
