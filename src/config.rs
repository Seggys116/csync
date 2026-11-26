use crate::crypto::trust::{self, Identity, PeerKey, Trust};
use crate::proto::Name;
use std::{
    env, fs,
    io::{self, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const DEFAULT_PORT: u16 = crate::host::DEFAULT_PORT;
pub const CACHE_CAP_MAX: u64 = 10 << 30;
pub const CACHE_CAP_MIN: u64 = 256 << 20;
pub const CACHE_FREE_PCT: u64 = 20;
pub const MACHINE_NAME_MAX: usize = 64;
// sun_path is 104 bytes on macos and 108 on linux, both include the nul
const SOCK_PATH_MAX: usize = 100;
const ID_HEX: usize = 12;

pub const GUEST_TREE_FILE: &str = "tree.rkyv";
pub const LRU_FILE: &str = "lru.bin";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dirs {
    pub config: PathBuf,
    pub state: PathBuf,
    pub cache: PathBuf,
}

fn abs_env(key: &str) -> Option<PathBuf> {
    let v = env::var_os(key)?;
    let p = PathBuf::from(v);
    p.is_absolute().then_some(p)
}

fn home() -> io::Result<PathBuf> {
    abs_env("HOME").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "HOME is not set to an absolute path",
        )
    })
}

impl Dirs {
    // CSYNC_HOME roots all three directories, which keeps several identities apart on one machine
    pub fn discover() -> io::Result<Self> {
        if let Some(base) = abs_env("CSYNC_HOME") {
            return Ok(Self::under(&base));
        }
        Self::platform(&home()?)
    }

    pub fn under(base: &Path) -> Self {
        Self {
            config: base.join("config"),
            state: base.join("state"),
            cache: base.join("cache"),
        }
    }

    #[cfg(target_os = "macos")]
    fn platform(home: &Path) -> io::Result<Self> {
        let support = home.join("Library/Application Support/csync");
        Ok(Self {
            state: support.join("state"),
            config: support,
            cache: home.join("Library/Caches/csync"),
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn platform(home: &Path) -> io::Result<Self> {
        let xdg = |key: &str, fallback: &str| {
            abs_env(key)
                .unwrap_or_else(|| home.join(fallback))
                .join("csync")
        };
        Ok(Self {
            config: xdg("XDG_CONFIG_HOME", ".config"),
            state: xdg("XDG_STATE_HOME", ".local/state"),
            cache: xdg("XDG_CACHE_HOME", ".cache"),
        })
    }

    pub fn ensure(&self) -> io::Result<()> {
        ensure_private_dir(&self.config)?;
        ensure_private_dir(&self.state)?;
        ensure_private_dir(&self.cache)
    }

    pub fn trust_dir(&self) -> &Path {
        &self.config
    }

    // one state dir per hosted root, so two projects never share an index
    pub fn project_dir(&self, root: &Path) -> PathBuf {
        self.state.join("projects").join(path_id(root))
    }

    pub fn host_state_dir(&self, host: &PeerKey) -> PathBuf {
        self.state.join("hosts").join(host.fpr_hex())
    }

    pub fn blob_cache_dir(&self, host: &PeerKey) -> PathBuf {
        self.cache.join(host.fpr_hex())
    }

    fn preferred_run_dir(&self) -> PathBuf {
        self.state.join("run")
    }

    fn fallback_run_dir() -> PathBuf {
        env::temp_dir().join(format!("csync-{}", rustix::process::getuid().as_raw()))
    }

    pub fn run_dirs(&self) -> [PathBuf; 2] {
        [self.preferred_run_dir(), Self::fallback_run_dir()]
    }

    // a socket path that fits sun_path; the private tmp fallback covers very long home dirs
    pub fn ctl_socket(&self, role: &str, id: &str) -> io::Result<PathBuf> {
        let file = format!("{role}-{id}.sock");
        for dir in self.run_dirs() {
            let p = dir.join(&file);
            if p.as_os_str().len() <= SOCK_PATH_MAX {
                ensure_private_dir(&dir)?;
                return Ok(p);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control socket path is too long; set CSYNC_HOME to a shorter directory",
        ))
    }

    pub fn ctl_sockets(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for dir in self.run_dirs() {
            if trust::check_private_dir(&dir).is_err() {
                continue;
            }
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "sock") && !out.contains(&p) {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }
}

pub fn path_id(p: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let canon = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let h = blake3::hash(canon.as_os_str().as_bytes());
    let mut s = trust::hex(&h.as_bytes()[..ID_HEX / 2]);
    s.truncate(ID_HEX);
    s
}

pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    trust::ensure_private_dir(dir)
}

pub fn check_private_dir(dir: &Path) -> io::Result<()> {
    trust::check_private_dir(dir)
}

pub fn open_private(p: &Path) -> io::Result<fs::File> {
    trust::open_private(p)
}

pub fn read_private(p: &Path, max: u64) -> io::Result<Vec<u8>> {
    let f = open_private(p)?;
    let mut out = Vec::new();
    f.take(max + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is larger than {max} bytes", p.display()),
        ));
    }
    Ok(out)
}

// 0600 file in a 0700 dir, replaced atomically
pub fn write_private(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    ensure_private_dir(dir)?;
    trust::write_atomic(dir, name, data)
}

pub fn free_bytes(path: &Path) -> io::Result<u64> {
    let mut p = path;
    // the cache dir may not exist yet; measure the filesystem it will live on
    loop {
        match rustix::fs::statvfs(p) {
            Ok(st) => return Ok(st.f_bavail.saturating_mul(st.f_frsize)),
            Err(rustix::io::Errno::NOENT) => match p.parent() {
                Some(parent) => p = parent,
                None => return Err(io::ErrorKind::NotFound.into()),
            },
            Err(e) => return Err(e.into()),
        }
    }
}

pub fn cache_cap_for_free(free: u64) -> u64 {
    (free / 100)
        .saturating_mul(CACHE_FREE_PCT)
        .min(CACHE_CAP_MAX)
}

pub fn default_cache_cap(cache_dir: &Path) -> io::Result<u64> {
    Ok(cache_cap_for_free(free_bytes(cache_dir)?))
}

pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let split = t
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    if num.is_empty() {
        return Err(format!(
            "'{s}' is not a size (examples: 2G, 512M, 1073741824)"
        ));
    }
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        u => return Err(format!("unknown size unit '{u}' (use K, M, G or T)")),
    };
    let bytes = if num.contains('.') {
        let v: f64 = num
            .parse()
            .map_err(|_| format!("'{num}' is not a number"))?;
        let b = v * mult as f64;
        if !b.is_finite() || b < 0.0 || b >= u64::MAX as f64 {
            return Err(format!("'{s}' is out of range"));
        }
        b as u64
    } else {
        num.parse::<u64>()
            .ok()
            .and_then(|v| v.checked_mul(mult))
            .ok_or_else(|| format!("'{s}' is out of range"))?
    };
    if bytes < CACHE_CAP_MIN {
        return Err(format!(
            "cache size must be at least {} MiB",
            CACHE_CAP_MIN >> 20
        ));
    }
    Ok(bytes)
}

fn clean_label(raw: &str) -> String {
    let s: String = raw
        .trim()
        .chars()
        .map(|c| if c.is_control() || c == '/' { '-' } else { c })
        .take(MACHINE_NAME_MAX)
        .collect();
    s.trim().to_string()
}

fn static_name(s: &'static str) -> Name {
    Name::new(s).expect("static names are valid")
}

pub fn project_name(root: &Path) -> Name {
    let base = root
        .file_name()
        .map(|n| clean_label(&n.to_string_lossy()))
        .unwrap_or_default();
    Name::new(&base).unwrap_or_else(|_| static_name("project"))
}

pub fn machine_name(arg: Option<&str>) -> Result<Name, String> {
    if let Some(a) = arg {
        let t = a.trim();
        if t.is_empty()
            || t.chars().count() > MACHINE_NAME_MAX
            || t.chars().any(|c| c.is_control() || c == '/')
        {
            return Err(format!(
                "'{a}' is not a usable name: no control characters or '/', at most {MACHINE_NAME_MAX} characters"
            ));
        }
        return Name::new(t).map_err(|e| format!("'{a}' is not a usable name: {e:?}"));
    }
    let detected = std::process::Command::new("hostname")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| clean_label(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();
    let short = detected.split('.').next().unwrap_or("").to_string();
    Ok(Name::new(&short).unwrap_or_else(|_| static_name("csync")))
}

pub struct GuestCfg {
    pub mount: PathBuf,
    pub addr: SocketAddr,
    pub host_key: Option<PeerKey>,
    pub repair: bool,
    pub allow_other: bool,
    pub cache_cap: u64,
    pub name: Name,
    pub identity: Arc<Identity>,
    pub trust: Arc<Trust>,
    pub dirs: Dirs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_with_units_and_reject_garbage() {
        assert_eq!(parse_size("2G"), Ok(2 << 30));
        assert_eq!(parse_size("512mib"), Ok(512 << 20));
        assert_eq!(parse_size("1.5G"), Ok(3 << 29));
        assert_eq!(parse_size("1073741824"), Ok(1 << 30));
        assert!(parse_size("1M").is_err());
        assert!(parse_size("G").is_err());
        assert!(parse_size("5X").is_err());
        assert!(parse_size("99999999999T").is_err());
        assert!(parse_size("-1G").is_err());
    }

    #[test]
    fn cache_cap_is_bounded_by_free_space_and_ceiling() {
        assert_eq!(cache_cap_for_free(1 << 40), CACHE_CAP_MAX);
        assert_eq!(cache_cap_for_free(10 << 30), (10u64 << 30) / 100 * 20);
        assert_eq!(cache_cap_for_free(100 << 20), (100u64 << 20) / 100 * 20);
        assert_eq!(cache_cap_for_free(0), 0);
    }

    #[test]
    fn socket_paths_fit_and_names_are_clean() {
        let d = Dirs::under(Path::new("/tmp/x"));
        assert_eq!(d.config, Path::new("/tmp/x/config"));
        assert_eq!(project_name(Path::new("/a/my proj")).as_str(), "my proj");
        assert_eq!(project_name(Path::new("/")).as_str(), "project");
        assert!(machine_name(Some("bad\x1bname")).is_err());
        assert_eq!(machine_name(Some(" vm1 ")).unwrap().as_str(), "vm1");
        let long = Dirs::under(&PathBuf::from(format!("/{}", "d".repeat(200))));
        let p = long.ctl_socket("host", "0123456789ab").unwrap();
        assert!(p.as_os_str().len() <= SOCK_PATH_MAX);
        let _ = fs::remove_file(&p);
    }
}
