// what a macfuse backend does with kernel cache notifications, measured once after the mount, and the cache policy that follows
use super::{
    cache::{pread_full, pwrite_all},
    fs::{Core, Inval, LOCAL_TTL, TTL},
    inject::SIZES_FROM_ATTRS,
    tree::{GDomain, ROOT},
};
use crate::{
    proto::{Name, RelPath},
    sys,
};
use rustix::{
    fs::{AtFlags, Mode, OFlags},
    io::Errno,
};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::atomic::{
        AtomicBool, AtomicU8, AtomicU32, AtomicU64,
        Ordering::{Acquire, Relaxed, Release},
    },
    time::{Duration, Instant},
};

const DIR: &str = ".TemporaryItems";
// os junk, so the guest keeps it in the overlay and it never syncs
pub const FILE: &str = "csync-probe";
const MOVED: &str = "csync-probe-moved";
const PATH: &str = ".TemporaryItems/csync-probe";
const MOVED_PATH: &str = ".TemporaryItems/csync-probe-moved";
const ATTR_SIZE: u64 = 100;
const TRUNC_SIZE: u64 = 321;
const MARK_A: [u8; 8] = *b"csyncAAA";
const MARK_B: [u8; 8] = *b"csyncBBB";
const SHORT_TTL_MS: u64 = 1_000;
const UNSET: u64 = u64::MAX;

pub const SHORT_TTL: Duration = Duration::from_millis(SHORT_TTL_MS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    FsKit,
    Kext,
}

impl BackendKind {
    pub fn name(self) -> &'static str {
        match self {
            BackendKind::FsKit => "fskit",
            BackendKind::Kext => "kext",
        }
    }

    fn code(self) -> u8 {
        match self {
            BackendKind::FsKit => 1,
            BackendKind::Kext => 2,
        }
    }
}

#[cfg(target_os = "macos")]
impl From<super::fuse::Backend> for BackendKind {
    fn from(b: super::fuse::Backend) -> Self {
        match b {
            super::fuse::Backend::FsKit => BackendKind::FsKit,
            super::fuse::Backend::Kext => BackendKind::Kext,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ident {
    // a request's process id is csync's own, and only the injector thread touches the mount
    Pid,
    // requests carry no usable process id (fskit sends 0), so the injector arms what it is about to do and a request is
    // its own only while an exact description of it is armed
    Window,
    // the requests could not be told from an injected one at all, so events are not replayed
    Claim,
}

// how stale kernel state is made current: the kernel is told, csync's own calls through the mount do it, or nothing replays
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    Native,
    Injected,
    Off,
}

impl Via {
    pub fn name(self) -> &'static str {
        match self {
            Via::Native => "native",
            Via::Injected => "injected",
            Via::Off => "off",
        }
    }

    fn code(self) -> u8 {
        match self {
            Via::Native => 1,
            Via::Injected => 2,
            Via::Off => 3,
        }
    }
}

// who a request says it came from
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    pub pid: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl Seen {
    // a reported uid or gid that differs means the request is not this process's, whatever its pid says
    fn is(self, own: Seen) -> bool {
        let agree = |a: Option<u32>, b: Option<u32>| a.zip(b).is_none_or(|(a, b)| a == b);
        self.pid == own.pid && agree(self.uid, own.uid) && agree(self.gid, own.gid)
    }

    // a reported uid or gid is known and differs from ours
    fn foreign(self, own: Seen) -> bool {
        let differs = |a: Option<u32>, b: Option<u32>| a.zip(b).is_some_and(|(a, b)| a != b);
        differs(self.uid, own.uid) || differs(self.gid, own.gid)
    }
}

// one invalidation test: the kernel kept its old view after a change behind its back, and showed the new one after being told
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Step {
    pub held: bool,
    pub fresh: bool,
}

impl Step {
    fn proven(self) -> bool {
        self.held && self.fresh
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeObs {
    // every control step ran before the probe's own entries and attributes could expire
    pub timely: bool,
    pub attrs: Step,
    pub entries: Step,
    pub data: Step,
    // a truncate through the mount left the kernel with the size the reply carried
    pub truncate_sets_size: bool,
    pub req: Option<Seen>,
    pub own: Seen,
}

impl ProbeObs {
    pub fn unverified(own: Seen) -> Self {
        ProbeObs {
            timely: false,
            attrs: Step::default(),
            entries: Step::default(),
            data: Step::default(),
            truncate_sets_size: false,
            req: None,
            own,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coherence {
    pub attrs: bool,
    pub entries: bool,
    pub data: bool,
    pub size_by_truncate: bool,
    pub synced_ttl: Duration,
    pub ident: Ident,
}

impl Coherence {
    pub fn native(&self) -> bool {
        self.attrs && self.entries && self.data
    }

    pub fn via(&self) -> Via {
        match (self.ident, self.native()) {
            (Ident::Claim, _) => Via::Off,
            (Ident::Pid | Ident::Window, true) => Via::Native,
            (Ident::Pid | Ident::Window, false) => Via::Injected,
        }
    }
}

// a control step that showed no stale view proves nothing, and a late one cannot be trusted, so both count as unproven
pub fn decide(obs: &ProbeObs, backend: BackendKind) -> Coherence {
    let proven = |s: Step| obs.timely && s.proven();
    let (attrs, entries, data) = (proven(obs.attrs), proven(obs.entries), proven(obs.data));
    let ident = match obs.req {
        Some(r) if r.is(obs.own) => Ident::Pid,
        Some(r) if r.pid != obs.own.pid && r.foreign(obs.own) => Ident::Window,
        _ => Ident::Claim,
    };
    // fskit ignores the entry lifetime a reply carries, so only the kext is trusted with the long one
    let synced_ttl = if attrs && entries && data && backend == BackendKind::Kext {
        TTL
    } else {
        SHORT_TTL
    };
    Coherence {
        attrs,
        entries,
        data,
        size_by_truncate: obs.timely && obs.truncate_sets_size,
        synced_ttl,
        ident,
    }
}

struct Live {
    ttl_ms: AtomicU64,
    keep: AtomicBool,
    backend: AtomicU8,
    via: AtomicU8,
}

static LIVE: Live = Live {
    ttl_ms: AtomicU64::new(SHORT_TTL_MS),
    keep: AtomicBool::new(false),
    backend: AtomicU8::new(0),
    via: AtomicU8::new(0),
};

// the policy in force until the self-test has spoken: short lifetimes, no kept page cache, truncate-driven sizes
pub fn begin(backend: BackendKind) {
    LIVE.ttl_ms.store(SHORT_TTL_MS, Relaxed);
    LIVE.keep.store(false, Relaxed);
    LIVE.via.store(0, Relaxed);
    LIVE.backend.store(backend.code(), Relaxed);
    SIZES_FROM_ATTRS.store(false, Relaxed);
}

pub fn apply(c: &Coherence, backend: BackendKind) {
    let kext = backend == BackendKind::Kext;
    let ms = u64::try_from(c.synced_ttl.as_millis()).unwrap_or(u64::MAX);
    LIVE.ttl_ms.store(ms, Relaxed);
    LIVE.keep.store(kext && c.data, Relaxed);
    SIZES_FROM_ATTRS.store(kext && c.attrs, Relaxed);
    LIVE.backend.store(backend.code(), Relaxed);
    LIVE.via.store(c.via().code(), Relaxed);
}

pub fn synced_ttl() -> Duration {
    Duration::from_millis(LIVE.ttl_ms.load(Relaxed))
}

pub fn keep_cache() -> bool {
    LIVE.keep.load(Relaxed)
}

// the backend and how invalidation is done, as the status words; None before a mount
pub fn status() -> Option<(&'static str, &'static str)> {
    let backend = match LIVE.backend.load(Relaxed) {
        1 => BackendKind::FsKit,
        2 => BackendKind::Kext,
        _ => return None,
    };
    let via = match LIVE.via.load(Relaxed) {
        c if c == Via::Native.code() => Via::Native.name(),
        c if c == Via::Injected.code() => Via::Injected.name(),
        c if c == Via::Off.code() => Via::Off.name(),
        _ => "probing",
    };
    Some((backend.name(), via))
}

pub fn summary() -> Option<String> {
    status().map(|(backend, via)| format!("{backend}, inval {via}"))
}

// what the filesystem's own handlers saw of the probe, shared with them
pub struct Probe {
    active: AtomicBool,
    seen: AtomicBool,
    ino: AtomicU64,
    parent: AtomicU64,
    gets: AtomicU32,
    lookups: AtomicU32,
    pid: AtomicU32,
    uid: AtomicU64,
    gid: AtomicU64,
}

pub static PROBE: Probe = Probe::new();

impl Default for Probe {
    fn default() -> Self {
        Self::new()
    }
}

impl Probe {
    pub const fn new() -> Self {
        Probe {
            active: AtomicBool::new(false),
            seen: AtomicBool::new(false),
            ino: AtomicU64::new(0),
            parent: AtomicU64::new(0),
            gets: AtomicU32::new(0),
            lookups: AtomicU32::new(0),
            pid: AtomicU32::new(0),
            uid: AtomicU64::new(UNSET),
            gid: AtomicU64::new(UNSET),
        }
    }

    // while set, every request is served as a user's, injector or not
    pub fn active(&self) -> bool {
        self.active.load(Acquire)
    }

    fn begin(&self) {
        self.seen.store(false, Relaxed);
        self.ino.store(0, Relaxed);
        self.parent.store(0, Relaxed);
        self.gets.store(0, Relaxed);
        self.lookups.store(0, Relaxed);
        self.pid.store(0, Relaxed);
        self.uid.store(UNSET, Relaxed);
        self.gid.store(UNSET, Relaxed);
        self.active.store(true, Release);
    }

    fn end(&self) {
        self.active.store(false, Release);
        self.ino.store(0, Release);
    }

    // the create handler names the probe file and who asked for it
    pub fn created(
        &self,
        name: &str,
        parent: u64,
        ino: u64,
        pid: u32,
        uid: Option<u32>,
        gid: Option<u32>,
    ) {
        if name != FILE || !self.active() {
            return;
        }
        self.parent.store(parent, Relaxed);
        self.pid.store(pid, Relaxed);
        self.uid.store(uid.map_or(UNSET, u64::from), Relaxed);
        self.gid.store(gid.map_or(UNSET, u64::from), Relaxed);
        self.seen.store(true, Relaxed);
        self.ino.store(ino, Release);
    }

    pub fn getattr(&self, ino: u64) {
        if ino != 0 && ino == self.ino.load(Relaxed) {
            self.gets.fetch_add(1, Relaxed);
        }
    }

    pub fn lookup(&self, ino: u64) {
        if ino != 0 && ino == self.ino.load(Relaxed) {
            self.lookups.fetch_add(1, Relaxed);
        }
    }

    // true for the probe file: its truncate is answered like an injected one
    pub fn setattr(&self, ino: u64) -> bool {
        ino != 0 && ino == self.ino.load(Relaxed)
    }

    fn target(&self) -> Option<(u64, u64)> {
        let ino = self.ino.load(Acquire);
        (ino != 0).then(|| (ino, self.parent.load(Relaxed)))
    }

    fn gets(&self) -> u32 {
        self.gets.load(Relaxed)
    }

    fn lookups(&self) -> u32 {
        self.lookups.load(Relaxed)
    }

    fn requester(&self) -> Option<Seen> {
        let opt = |v: u64| u32::try_from(v).ok();
        self.seen.load(Relaxed).then(|| Seen {
            pid: self.pid.load(Relaxed),
            uid: opt(self.uid.load(Relaxed)),
            gid: opt(self.gid.load(Relaxed)),
        })
    }
}

pub struct Env<'a> {
    pub root: BorrowedFd<'a>,
    pub core: &'a Core,
    pub inval: &'a Inval,
}

fn own_ident() -> Seen {
    Seen {
        pid: std::process::id(),
        uid: Some(rustix::process::getuid().as_raw()),
        gid: Some(rustix::process::getgid().as_raw()),
    }
}

// runs on the injector thread right after the mount and leaves the policy applied
pub fn run(env: &Env<'_>, backend: BackendKind) -> Coherence {
    let own = own_ident();
    let obs = observe(env, &PROBE, own).unwrap_or_else(|_| ProbeObs::unverified(own));
    let c = decide(&obs, backend);
    apply(&c, backend);
    c
}

// the mount root could not be opened, so nothing was observed
pub fn run_unverified(backend: BackendKind) -> Coherence {
    let c = decide(&ProbeObs::unverified(own_ident()), backend);
    apply(&c, backend);
    c
}

fn rel(p: &str) -> io::Result<RelPath> {
    RelPath::new(p).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn kernel_size(fd: &OwnedFd) -> io::Result<u64> {
    Ok(u64::try_from(rustix::fs::fstat(fd)?.st_size).unwrap_or(0))
}

// serves the probe's own requests as a user's for as long as it lives, and removes every trace of it
struct Guard<'a> {
    env: &'a Env<'a>,
    probe: &'a Probe,
    made_dir: bool,
}

impl<'a> Guard<'a> {
    fn new(env: &'a Env<'a>, probe: &'a Probe) -> io::Result<Self> {
        // a tracked directory of this name would carry the probe file to the host
        let tracked = {
            let t = env.core.t();
            t.child(ROOT, DIR)
                .and_then(|id| t.get(id))
                .is_some_and(|n| n.domain != GDomain::Local)
        };
        if tracked {
            return Err(io::Error::other(
                "the probe directory is tracked by the host",
            ));
        }
        probe.begin();
        let mut g = Guard {
            env,
            probe,
            made_dir: false,
        };
        let _ = rustix::fs::unlinkat(env.root, PATH, AtFlags::empty());
        g.made_dir = match rustix::fs::mkdirat(env.root, DIR, Mode::from_bits_truncate(0o700)) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(e) => return Err(e.into()),
        };
        Ok(g)
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let _ = rustix::fs::unlinkat(self.env.root, PATH, AtFlags::empty());
        if self.made_dir {
            let _ = rustix::fs::unlinkat(self.env.root, DIR, AtFlags::REMOVEDIR);
        }
        if let Ok(p) = rel(MOVED_PATH) {
            self.env.core.remove_overlay(&p);
        }
        self.probe.end();
    }
}

fn observe(env: &Env<'_>, probe: &Probe, own: Seen) -> io::Result<ProbeObs> {
    let _guard = Guard::new(env, probe)?;
    let mfd = rustix::fs::openat(
        env.root,
        PATH,
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )?;
    let (ino, parent) = probe
        .target()
        .ok_or_else(|| io::Error::other("the probe file was created without being seen"))?;
    {
        let t = env.core.t();
        let local = t.get(ino).is_some_and(|n| {
            n.domain == GDomain::Local && n.parent == parent && n.name.as_str() == FILE
        });
        let dir = t
            .get(parent)
            .is_some_and(|p| p.parent == ROOT && p.name.as_str() == DIR);
        if !local || !dir {
            return Err(io::Error::other(
                "the probe file did not land in the overlay",
            ));
        }
    }
    let started = Instant::now();
    let mut timely = true;
    let overlay = env.core.overlay.as_fd();
    let odir = sys::open_beneath(overlay, &rel(DIR)?, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let backing = sys::open_beneath(overlay, &rel(PATH)?, OFlags::RDWR | OFlags::CLOEXEC)?;
    let name = Name::new(FILE).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;

    let gets = probe.gets();
    rustix::fs::ftruncate(&backing, ATTR_SIZE)?;
    let held = kernel_size(&mfd)? == 0 && probe.gets() == gets;
    timely &= started.elapsed() < LOCAL_TTL;
    env.inval.attrs(ino);
    let attrs = Step {
        held,
        fresh: kernel_size(&mfd)? == ATTR_SIZE,
    };

    let lookups = probe.lookups();
    rustix::fs::renameat(&odir, FILE, &odir, MOVED)?;
    let _ = rustix::fs::statat(env.root, PATH, AtFlags::SYMLINK_NOFOLLOW);
    let held = probe.lookups() == lookups;
    timely &= started.elapsed() < LOCAL_TTL;
    env.inval.entry(parent, &name);
    let _ = rustix::fs::statat(env.root, PATH, AtFlags::SYMLINK_NOFOLLOW);
    let fresh = probe.lookups() > lookups;
    rustix::fs::renameat(&odir, MOVED, &odir, FILE)?;
    let entries = Step { held, fresh };

    let mut buf = [0u8; MARK_A.len()];
    pwrite_all(mfd.as_fd(), &MARK_A, 0)?;
    pread_full(mfd.as_fd(), &mut buf, 0)?;
    pwrite_all(backing.as_fd(), &MARK_B, 0)?;
    pread_full(mfd.as_fd(), &mut buf, 0)?;
    let held = buf == MARK_A;
    timely &= started.elapsed() < LOCAL_TTL;
    env.inval.inode(ino);
    pread_full(mfd.as_fd(), &mut buf, 0)?;
    let data = Step {
        held,
        fresh: buf == MARK_B,
    };

    rustix::fs::ftruncate(&backing, TRUNC_SIZE)?;
    rustix::fs::ftruncate(&mfd, TRUNC_SIZE)?;
    let truncate_sets_size = kernel_size(&mfd)? == TRUNC_SIZE;

    Ok(ProbeObs {
        timely,
        attrs,
        entries,
        data,
        truncate_sets_size,
        req: probe.requester(),
        own,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: Seen = Seen {
        pid: 4_242,
        uid: Some(501),
        gid: Some(20),
    };

    const PROVEN: Step = Step {
        held: true,
        fresh: true,
    };

    fn obs() -> ProbeObs {
        ProbeObs {
            timely: true,
            attrs: PROVEN,
            entries: PROVEN,
            data: PROVEN,
            truncate_sets_size: true,
            req: Some(OWN),
            own: OWN,
        }
    }

    #[test]
    fn a_kext_with_working_notifications_keeps_the_long_lifetime() {
        let c = decide(&obs(), BackendKind::Kext);
        assert!(c.attrs && c.entries && c.data && c.size_by_truncate);
        assert_eq!(c.synced_ttl, TTL);
        assert_eq!(c.ident, Ident::Pid);
        assert_eq!(c.via(), Via::Native);
    }

    #[test]
    fn fskit_without_notifications_gets_short_lifetimes_and_injection() {
        let none = Step {
            held: true,
            fresh: false,
        };
        let o = ProbeObs {
            attrs: none,
            entries: none,
            data: none,
            truncate_sets_size: true,
            ..obs()
        };
        let c = decide(&o, BackendKind::FsKit);
        assert!(!c.attrs && !c.entries && !c.data);
        assert!(c.size_by_truncate);
        assert_eq!(c.synced_ttl, SHORT_TTL);
        assert_eq!(c.via(), Via::Injected);
    }

    #[test]
    fn proven_notifications_on_fskit_still_get_the_short_lifetime() {
        let c = decide(&obs(), BackendKind::FsKit);
        assert!(c.native());
        assert_eq!(c.synced_ttl, SHORT_TTL);
        assert_eq!(c.via(), Via::Native);
    }

    #[test]
    fn a_control_step_that_showed_no_stale_view_proves_nothing() {
        let o = ProbeObs {
            attrs: Step {
                held: false,
                fresh: true,
            },
            ..obs()
        };
        let c = decide(&o, BackendKind::Kext);
        assert!(!c.attrs && c.entries && c.data);
        assert_eq!(c.synced_ttl, SHORT_TTL);
        assert_eq!(c.via(), Via::Injected);
    }

    #[test]
    fn a_late_probe_is_unproven_throughout() {
        let o = ProbeObs {
            timely: false,
            ..obs()
        };
        let c = decide(&o, BackendKind::Kext);
        assert!(!c.attrs && !c.entries && !c.data && !c.size_by_truncate);
        assert_eq!(c.synced_ttl, SHORT_TTL);
    }

    #[test]
    fn a_request_pid_other_than_ours_turns_replay_off() {
        let o = ProbeObs {
            req: Some(Seen { pid: 1, ..OWN }),
            ..obs()
        };
        let c = decide(&o, BackendKind::Kext);
        assert_eq!(c.ident, Ident::Claim);
        assert_eq!(c.via(), Via::Off);
    }

    #[test]
    fn requests_from_pid_zero_and_a_foreign_uid_are_told_apart_by_the_window() {
        let fskit = Seen {
            pid: 0,
            uid: Some(0),
            gid: Some(0),
        };
        let o = ProbeObs {
            req: Some(fskit),
            ..obs()
        };
        let c = decide(&o, BackendKind::FsKit);
        assert_eq!(c.ident, Ident::Window);
        assert_eq!(c.via(), Via::Native);
        let none = Step {
            held: true,
            fresh: false,
        };
        let o = ProbeObs {
            attrs: none,
            entries: none,
            data: none,
            req: Some(fskit),
            ..obs()
        };
        assert_eq!(decide(&o, BackendKind::FsKit).via(), Via::Injected);
    }

    #[test]
    fn another_pid_with_our_own_uid_and_gid_is_still_not_identified() {
        let o = ProbeObs {
            req: Some(Seen { pid: 0, ..OWN }),
            ..obs()
        };
        assert_eq!(decide(&o, BackendKind::FsKit).ident, Ident::Claim);
    }

    #[test]
    fn a_matching_pid_keeps_the_pid_identification() {
        let c = decide(&obs(), BackendKind::FsKit);
        assert_eq!(c.ident, Ident::Pid);
    }

    #[test]
    fn a_matching_pid_with_another_uid_is_not_ours() {
        let o = ProbeObs {
            req: Some(Seen {
                uid: Some(0),
                ..OWN
            }),
            ..obs()
        };
        assert_eq!(decide(&o, BackendKind::Kext).ident, Ident::Claim);
    }

    #[test]
    fn an_unreported_uid_or_gid_does_not_count_against_a_matching_pid() {
        let o = ProbeObs {
            req: Some(Seen {
                pid: OWN.pid,
                uid: None,
                gid: None,
            }),
            ..obs()
        };
        assert_eq!(decide(&o, BackendKind::Kext).ident, Ident::Pid);
    }

    #[test]
    fn a_probe_that_never_ran_is_unverified_everywhere() {
        let c = decide(&ProbeObs::unverified(OWN), BackendKind::Kext);
        assert!(!c.attrs && !c.entries && !c.data && !c.size_by_truncate);
        assert_eq!(c.synced_ttl, SHORT_TTL);
        assert_eq!(c.ident, Ident::Claim);
    }

    #[test]
    fn handlers_are_counted_only_for_the_probe_file_and_only_while_it_runs() {
        let p = Probe::new();
        p.created(FILE, 7, 9, 100, Some(501), None);
        assert!(p.target().is_none() && p.requester().is_none());
        p.begin();
        p.created("other", 7, 8, 1, None, None);
        assert!(p.target().is_none());
        p.created(FILE, 7, 9, 100, Some(501), None);
        assert_eq!(p.target(), Some((9, 7)));
        assert_eq!(
            p.requester(),
            Some(Seen {
                pid: 100,
                uid: Some(501),
                gid: None
            })
        );
        p.getattr(9);
        p.getattr(10);
        p.lookup(9);
        p.lookup(9);
        p.lookup(0);
        assert_eq!((p.gets(), p.lookups()), (1, 2));
        assert!(p.setattr(9) && !p.setattr(10) && !p.setattr(0));
        p.end();
        assert!(!p.active() && p.target().is_none());
        p.getattr(9);
        assert_eq!(p.gets(), 1);
    }

    #[test]
    fn the_applied_policy_and_its_summary_follow_the_decision() {
        assert_eq!(summary(), None);
        begin(BackendKind::FsKit);
        assert_eq!(summary().as_deref(), Some("fskit, inval probing"));
        assert_eq!(status(), Some(("fskit", "probing")));
        assert_eq!(synced_ttl(), SHORT_TTL);
        assert!(!keep_cache());
        apply(&decide(&obs(), BackendKind::Kext), BackendKind::Kext);
        assert_eq!(summary().as_deref(), Some("kext, inval native"));
        assert_eq!(synced_ttl(), TTL);
        assert!(keep_cache());
        assert!(SIZES_FROM_ATTRS.load(Relaxed));
        let unverified = decide(&ProbeObs::unverified(OWN), BackendKind::FsKit);
        apply(&unverified, BackendKind::FsKit);
        assert_eq!(summary().as_deref(), Some("fskit, inval off"));
        assert_eq!(synced_ttl(), SHORT_TTL);
        assert!(!keep_cache());
        assert!(!SIZES_FROM_ATTRS.load(Relaxed));
        LIVE.backend.store(0, Relaxed);
        LIVE.via.store(0, Relaxed);
    }
}
