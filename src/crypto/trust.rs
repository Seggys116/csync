use crate::proto::{Name, hs::Role};
use snow::{
    params::DHChoice,
    resolvers::{CryptoResolver, DefaultResolver},
};
use std::{
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub const IDENTITY_FILE: &str = "identity";
pub const PEERS_FILE: &str = "peers";
const PEERS_MAX_BYTES: u64 = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PeerKey(pub [u8; 32]);

impl PeerKey {
    pub fn fpr(&self) -> [u8; 8] {
        let h = blake3::hash(&self.0);
        let mut out = [0u8; 8];
        out.copy_from_slice(&h.as_bytes()[..8]);
        out
    }

    pub fn fpr_hex(&self) -> String {
        hex(&self.fpr())
    }

    pub fn to_b64(&self) -> String {
        b64_encode(&self.0)
    }

    pub fn from_b64(s: &str) -> Option<Self> {
        b64_decode32(s.trim()).map(Self)
    }
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

pub struct Identity {
    secret: Zeroizing<[u8; 32]>,
    pub public: PeerKey,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("fpr", &self.public.fpr_hex())
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> io::Result<Self> {
        let public = public_of(&secret)?;
        Ok(Self { secret, public })
    }

    pub fn generate() -> io::Result<Self> {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut secret[..])
            .map_err(|_| io::Error::other("system random source failed"))?;
        Self::from_secret(secret)
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn load(dir: &Path) -> io::Result<Self> {
        check_private_dir(dir)?;
        let mut f = open_private(&dir.join(IDENTITY_FILE))?;
        if f.metadata()?.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "identity file must be exactly 32 bytes",
            ));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        f.read_exact(&mut secret[..])?;
        Self::from_secret(secret)
    }

    pub fn load_or_create(dir: &Path) -> io::Result<Self> {
        ensure_private_dir(dir)?;
        match Self::load(dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            r => return r,
        }
        let id = Self::generate()?;
        let tmp = dir.join(".identity.tmp");
        match fs::remove_file(&tmp) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut f = create_private(&tmp)?;
        f.write_all(&id.secret[..])?;
        f.sync_all()?;
        drop(f);
        // hard link refuses to clobber an identity another process created meanwhile
        let linked = fs::hard_link(&tmp, dir.join(IDENTITY_FILE));
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                sync_dir(dir)?;
                Ok(id)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Self::load(dir),
            Err(e) => Err(e),
        }
    }
}

fn public_of(secret: &[u8; 32]) -> io::Result<PeerKey> {
    let mut dh = DefaultResolver
        .resolve_dh(&DHChoice::Curve25519)
        .ok_or_else(|| io::Error::other("x25519 unavailable"))?;
    dh.set(&secret[..]);
    let mut k = [0u8; 32];
    let p = dh.pubkey();
    if p.len() != 32 {
        return Err(io::Error::other("x25519 public key length"));
    }
    k.copy_from_slice(p);
    Ok(PeerKey(k))
}

#[derive(Clone, Debug)]
pub struct TrustEntry {
    pub key: PeerKey,
    pub role: Role,
    pub name: Name,
    pub added_unix: u64,
}

pub struct Trust {
    dir: PathBuf,
    entries: Mutex<Vec<TrustEntry>>,
}

impl Trust {
    pub fn load(dir: &Path) -> io::Result<Self> {
        ensure_private_dir(dir)?;
        let entries = match open_private(&dir.join(PEERS_FILE)) {
            Ok(f) => {
                let mut text = String::new();
                f.take(PEERS_MAX_BYTES + 1).read_to_string(&mut text)?;
                if text.len() as u64 > PEERS_MAX_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "peers file too large",
                    ));
                }
                parse_peers(&text)?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            entries: Mutex::new(entries),
        })
    }

    pub fn get(&self, k: &PeerKey) -> Option<TrustEntry> {
        self.lock().iter().find(|e| e.key == *k).cloned()
    }

    pub fn entries(&self) -> Vec<TrustEntry> {
        self.lock().clone()
    }

    pub fn add(&self, e: TrustEntry) -> io::Result<()> {
        if !name_storable(e.name.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "peer name contains control characters",
            ));
        }
        let mut g = self.lock();
        let mut next = g.clone();
        match next.iter_mut().find(|x| x.key == e.key) {
            Some(x) => *x = e,
            None => next.push(e),
        }
        self.persist(&next)?;
        *g = next;
        Ok(())
    }

    pub fn forget(&self, selector: &str) -> io::Result<Vec<TrustEntry>> {
        let sel = selector.trim();
        if sel.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty selector",
            ));
        }
        let mut g = self.lock();
        let (gone, keep): (Vec<TrustEntry>, Vec<TrustEntry>) =
            g.iter().cloned().partition(|e| selects(e, sel));
        if !gone.is_empty() {
            self.persist(&keep)?;
            *g = keep;
        }
        Ok(gone)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<TrustEntry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn persist(&self, entries: &[TrustEntry]) -> io::Result<()> {
        let mut text = String::with_capacity(entries.len() * 96);
        for e in entries {
            let role = match e.role {
                Role::Host => "host",
                Role::Guest => "guest",
            };
            text.push_str(role);
            text.push(' ');
            text.push_str(&e.key.to_b64());
            text.push(' ');
            text.push_str(e.name.as_str());
            text.push(' ');
            text.push_str(&e.added_unix.to_string());
            text.push('\n');
        }
        write_atomic(&self.dir, PEERS_FILE, text.as_bytes())
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn selects(e: &TrustEntry, sel: &str) -> bool {
    if e.name.as_str() == sel || e.key.to_b64() == sel {
        return true;
    }
    sel.len() >= 4
        && sel.bytes().all(|b| b.is_ascii_hexdigit())
        && e.key.fpr_hex().starts_with(&sel.to_ascii_lowercase())
}

fn name_storable(s: &str) -> bool {
    !s.chars().any(char::is_control) && !s.starts_with(' ') && !s.ends_with(' ')
}

fn parse_peers(text: &str) -> io::Result<Vec<TrustEntry>> {
    let bad =
        |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("peers file: {what}"));
    let mut out: Vec<TrustEntry> = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(3, ' ');
        let (Some(role), Some(key), Some(rest)) = (it.next(), it.next(), it.next()) else {
            return Err(bad("malformed line"));
        };
        let role = match role {
            "host" => Role::Host,
            "guest" => Role::Guest,
            _ => return Err(bad("unknown role")),
        };
        let key = PeerKey::from_b64(key).ok_or_else(|| bad("bad key"))?;
        let (name, added) = rest.rsplit_once(' ').ok_or_else(|| bad("malformed line"))?;
        let name = Name::new(name).map_err(|_| bad("bad name"))?;
        let added_unix = added.parse::<u64>().map_err(|_| bad("bad timestamp"))?;
        if out.iter().any(|e| e.key == key) {
            return Err(bad("duplicate key"));
        }
        out.push(TrustEntry {
            key,
            role,
            name,
            added_unix,
        });
    }
    Ok(out)
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn loose(mode: u32) -> bool {
    mode & 0o077 != 0
}

pub fn check_private_dir(dir: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(dir)?;
    if !m.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if m.uid() != uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not owned by the current user", dir.display()),
        ));
    }
    if loose(m.mode()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is accessible by other users (mode {:o}); run chmod 700 on it",
                dir.display(),
                m.mode() & 0o777
            ),
        ));
    }
    Ok(())
}

pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?
        }
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    check_private_dir(dir)
}

fn check_private_file(f: &File, p: &Path) -> io::Result<()> {
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", p.display()),
        ));
    }
    if m.uid() != uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not owned by the current user", p.display()),
        ));
    }
    if loose(m.mode()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is accessible by other users (mode {:o}); run chmod 600 on it",
                p.display(),
                m.mode() & 0o777
            ),
        ));
    }
    Ok(())
}

pub fn open_private(p: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    check_private_file(&f, p)?;
    Ok(f)
}

fn create_private(p: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

pub fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut f = create_private(&tmp)?;
    let r = f.write_all(data).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = r.and_then(|()| fs::rename(&tmp, dir.join(name))) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(dir)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(src: &[u8]) -> String {
    let mut s = String::with_capacity(src.len().div_ceil(3) * 4);
    for c in src.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        s.push(B64[(n >> 18) as usize & 63] as char);
        s.push(B64[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

fn b64_val(c: u8) -> Option<u32> {
    B64.iter().position(|&x| x == c).map(|v| v as u32)
}

fn b64_decode32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 44 || b[43] != b'=' || b[42] == b'=' {
        return None;
    }
    let mut out = [0u8; 32];
    let mut o = 0;
    for (i, q) in b.chunks(4).enumerate() {
        let last = i == 10;
        let v0 = b64_val(q[0])?;
        let v1 = b64_val(q[1])?;
        let v2 = b64_val(q[2])?;
        let v3 = if last { 0 } else { b64_val(q[3])? };
        let n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        if last {
            // canonical encoding: the unused low bits must be zero
            if n & 0xff != 0 {
                return None;
            }
            out[o] = (n >> 16) as u8;
            out[o + 1] = (n >> 8) as u8;
        } else {
            out[o] = (n >> 16) as u8;
            out[o + 1] = (n >> 8) as u8;
            out[o + 2] = n as u8;
            o += 3;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir(tag: &str) -> PathBuf {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let d = std::env::temp_dir().join(format!("csync-test-{tag}-{}", hex(&r)));
        DirBuilder::new().mode(0o700).create(&d).unwrap();
        d
    }

    #[test]
    fn b64_round_trip_and_rejects_noncanonical() {
        let k = PeerKey([0xa5; 32]);
        let s = k.to_b64();
        assert_eq!(s.len(), 44);
        assert_eq!(PeerKey::from_b64(&s), Some(k));
        let zero = PeerKey([0; 32]).to_b64();
        assert_eq!(&zero[40..], "AAA=");
        let noncanonical = format!("{}AAB=", &zero[..40]);
        assert!(PeerKey::from_b64(&noncanonical).is_none());
        assert!(PeerKey::from_b64("AAAA").is_none());
        assert!(PeerKey::from_b64(&format!("{}AA==", &zero[..40])).is_none());
    }

    #[test]
    fn identity_persists_and_refuses_loose_permissions() {
        let d = tmpdir("id");
        let a = Identity::load_or_create(&d).unwrap();
        let b = Identity::load(&d).unwrap();
        assert_eq!(a.public, b.public);
        let p = d.join(IDENTITY_FILE);
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let e = Identity::load(&d).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            Identity::load(&d).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            Trust::load(&d).err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn trust_file_add_forget_and_loose_refusal() {
        let d = tmpdir("trust");
        let t = Trust::load(&d).unwrap();
        let k = PeerKey([7; 32]);
        t.add(TrustEntry {
            key: k,
            role: Role::Guest,
            name: Name::new("dev vm").unwrap(),
            added_unix: 5,
        })
        .unwrap();
        let bad = TrustEntry {
            key: PeerKey([8; 32]),
            role: Role::Guest,
            name: Name::new("a\nhost x").unwrap(),
            added_unix: 1,
        };
        assert!(t.add(bad).is_err());
        let t2 = Trust::load(&d).unwrap();
        let e = t2.get(&k).unwrap();
        assert_eq!(e.name.as_str(), "dev vm");
        assert_eq!(e.added_unix, 5);
        let p = d.join(PEERS_FILE);
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            Trust::load(&d).err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let gone = t2.forget(&k.fpr_hex()[..6]).unwrap();
        assert_eq!(gone.len(), 1);
        assert!(Trust::load(&d).unwrap().get(&k).is_none());
        fs::remove_dir_all(&d).unwrap();
    }
}
