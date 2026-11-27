pub mod tree;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod cache;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod coherence;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod fsops;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod fuse;
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub mod gitindex;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod inject;
#[cfg(target_os = "macos")]
mod mount_mac;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod pipe;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod prefetch;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod wipe;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod write;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use live::run;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod live {
    use super::cache::{BlobCache, CacheConfig, Remote, RemoteSlot, lock};
    #[cfg(target_os = "macos")]
    use super::coherence::{self, BackendKind, Env};
    use super::fs::{self, Core, Counters, Mounted};
    #[cfg(target_os = "macos")]
    use super::inject::Boot;
    use super::inject::{Injector, InjectorThread};
    use super::pipe::Pipe;
    use super::prefetch::{Hint, Prefetch, TreeView};
    use super::tree::{Effect, GDomain, GNode, GTree, NodeId, ROOT, Vis};
    use super::wipe::{self, HostPaths};
    use super::write::{NoticeFn, Writer};
    use crate::config::{GuestCfg, ensure_private_dir};
    use crate::crypto::noise::Reject;
    use crate::crypto::trust::{Identity, PeerKey, TrustEntry, now_unix};
    use crate::ignore::rules::{Class, Rules};
    use crate::net::conn::{self, CloseReason, Dial, In, Link, NetError, Session};
    use crate::net::rpc::Rpc;
    use crate::proto::{
        BATCH_MAX, Bye, Change, ExcludeSrc, Hash32, Hello, IndexId, Kind, Msg, Name, Notice,
        NoticeKind, Op, PROTO, Push, RelPath, Reply, TEXT_MAX, VerKey, Want, Welcome,
        hs::{HsHello, PAIR_TIMEOUT_S, PairStep, Role},
    };
    use crate::tui::{ConnState, PeerView, UiBus, UiCmd, now_ms};
    use crossbeam_channel::{
        Receiver, RecvTimeoutError, Sender, after, bounded, never, select, unbounded,
    };
    use rustc_hash::{FxHashMap, FxHashSet};
    use rustix::fs::{Mode, OFlags};
    #[cfg(target_os = "macos")]
    use std::os::fd::AsFd;
    use std::{
        collections::VecDeque,
        io,
        net::SocketAddr,
        sync::{
            Arc, Condvar, Mutex, OnceLock, RwLock,
            atomic::{AtomicBool, AtomicU32, Ordering::Relaxed},
        },
        thread::{self, JoinHandle},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    const HOST_PEER: u64 = 1;
    const HELLO_WAIT: Duration = Duration::from_secs(10);
    const BACKOFF_MIN: Duration = Duration::from_millis(100);
    const BACKOFF_MAX: Duration = Duration::from_secs(5);
    const UNVERIFIED_BACKOFF_MAX: Duration = Duration::from_secs(60);
    const UNVERIFIED_HINT: &str =
        "reconnect refused by an unverified response from host; still retrying";
    const STOP_POLL: Duration = Duration::from_millis(100);
    const UI_EVERY: Duration = Duration::from_millis(250);
    const PING_EVERY: Duration = Duration::from_secs(30);
    const RULE_JOBS: usize = 1_024;
    const RULE_WAIT: Duration = Duration::from_secs(30);
    const HASH_WAIT: Duration = Duration::from_secs(5);
    // how long shutdown lets closed new files finish their commits before the write pipe stops
    const SETTLE_WAIT: Duration = Duration::from_secs(10);
    // a FetchMany reply is one frame, so rule-file batches stay under FRAME_MAX
    const RULE_BATCH_BYTES: u64 = 3 << 20;
    #[cfg(target_os = "linux")]
    const OVERLAY_DIR: &str = "overlay";
    // spotlight skips directories named *.noindex
    #[cfg(target_os = "macos")]
    const OVERLAY_DIR: &str = "overlay.noindex";
    // how long shutdown waits for the last thread holding the session core to let go of it
    const CORE_WAIT: Duration = Duration::from_secs(3);
    const CRASH_HINT: &str =
        "an earlier session ended without cleaning up; its local state was wiped before this one";
    const WIPE_MOUNTED_HINT: &str = "the mount could not be released, so the local guest state was kept; the next join of this host wipes it";
    const WIPE_BUSY_HINT: &str = "the local guest state is still in use, so it was kept; the next join of this host wipes it";
    const WIPE_PARTIAL_HINT: &str = "some local guest state could not be wiped; the next join of this host retries and will not start until it is gone";

    enum Fail {
        Retry,
        // an unauthenticated refusal: retried slowly, never trusted to end the daemon
        Unverified,
        Fatal(io::Error),
        Quit,
    }

    fn denied(msg: &str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, msg.to_owned())
    }

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    fn me(cfg: &GuestCfg) -> HsHello {
        HsHello {
            proto: PROTO,
            role: Role::Guest,
            name: cfg.name.clone(),
        }
    }

    fn unverified(r: Reject) -> &'static str {
        match r {
            Reject::KeyMismatch => {
                "unverified response from host: it reports the trusted host key does not match"
            }
            Reject::UnknownPeer => {
                "unverified response from host: it reports it does not recognise this guest"
            }
            Reject::PairingDisabled => "unverified response from host: pairing is disabled",
            Reject::RateLimited | Reject::Refused => {
                "unverified response from host: the handshake was refused"
            }
        }
    }

    // only failures inside the authenticated handshake are fatal; a plaintext reject can be forged
    fn classify(e: NetError, first: bool) -> Fail {
        match e {
            NetError::Io(_) | NetError::RateLimited | NetError::Rejected(Reject::RateLimited) => {
                Fail::Retry
            }
            NetError::KeyMismatch => {
                Fail::Fatal(denied("the host's key does not match the trusted key"))
            }
            NetError::Rejected(r) if first => Fail::Fatal(denied(unverified(r))),
            NetError::Handshake(m) if first => Fail::Fatal(denied(m)),
            NetError::Rejected(_)
            | NetError::Handshake(_)
            | NetError::UnknownPeer
            | NetError::PairingLimited => Fail::Unverified,
        }
    }

    fn dial(
        addr: SocketAddr,
        id: &Identity,
        how: Dial,
        me: &HsHello,
        first: bool,
    ) -> Result<Session, Fail> {
        conn::dial(addr, id, how, me).map_err(|e| classify(e, first))
    }

    fn peer_view(name: &Name, key: &PeerKey, state: ConnState, rtt_us: u32) -> PeerView {
        PeerView {
            id: HOST_PEER,
            name: name.clone(),
            fpr: key.fpr(),
            state,
            rtt_us,
        }
    }

    fn put_peer(bus: &UiBus, v: PeerView) {
        bus.update(|s| match s.peers.iter_mut().find(|p| p.id == HOST_PEER) {
            Some(p) => *p = v,
            None => s.peers.push(v),
        });
    }

    // xx pairing: both the host's accept and this user's confirm of the sas are required
    fn pair(
        sess: &Session,
        cfg: &GuestCfg,
        bus: &UiBus,
        cmds: &Receiver<UiCmd>,
    ) -> Result<(), Fail> {
        let sas = sess
            .sas
            .ok_or_else(|| Fail::Fatal(denied("pairing produced no verification code")))?;
        let key = sess.link.peer();
        let name = sess.hello.name.clone();
        put_peer(bus, peer_view(&name, &key, ConnState::Pairing { sas }, 0));
        let refuse = |why: &str| {
            let _ = sess.link.send(Msg::Pair(PairStep::Rejected));
            Fail::Fatal(denied(why))
        };
        let deadline = Instant::now() + Duration::from_secs(PAIR_TIMEOUT_S);
        let (mut host_ok, mut me_ok) = (false, false);
        while !(host_ok && me_ok) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(refuse("pairing timed out"));
            }
            select! {
                recv(sess.inbox) -> m => match m {
                    Ok(In::Msg(Msg::Pair(PairStep::HostAccepted))) => host_ok = true,
                    Ok(In::Msg(Msg::Pair(_) | Msg::Bye(_)) | In::Closed(_)) | Err(_) => return Err(Fail::Fatal(denied("the host rejected pairing"))),
                    Ok(_) => {}
                },
                recv(cmds) -> c => match c {
                    Ok(UiCmd::Confirm(true)) if !me_ok => {
                        me_ok = true;
                        if sess.link.send(Msg::Pair(PairStep::GuestConfirmed)).is_err() {
                            return Err(Fail::Retry);
                        }
                    }
                    Ok(UiCmd::Confirm(false)) => return Err(refuse("pairing was declined")),
                    Ok(UiCmd::Quit) | Err(_) => {
                        let _ = refuse("quit");
                        return Err(Fail::Quit);
                    }
                    Ok(_) => {}
                },
                recv(after(left)) -> _ => {}
            }
        }
        cfg.trust
            .add(TrustEntry {
                key,
                role: Role::Host,
                name,
                added_unix: now_unix(),
            })
            .map_err(Fail::Fatal)?;
        Ok(())
    }

    fn hello(sess: &Session, tree: &RwLock<GTree>) -> Result<Welcome, Fail> {
        let have = {
            let t = tree.read().unwrap_or_else(|e| e.into_inner());
            (t.index_id() != 0).then(|| (t.index_id(), t.seq()))
        };
        let build = Name::new(env!("CARGO_PKG_VERSION"))
            .map_err(|_| Fail::Fatal(io::Error::other("invalid build name")))?;
        if sess
            .link
            .send(Msg::Hello(Hello {
                proto: PROTO,
                build,
                have,
            }))
            .is_err()
        {
            return Err(Fail::Retry);
        }
        let deadline = Instant::now() + HELLO_WAIT;
        loop {
            match sess
                .inbox
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(In::Msg(Msg::Welcome(w))) => {
                    if w.proto != PROTO {
                        return Err(Fail::Fatal(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "the host speaks a different protocol version",
                        )));
                    }
                    return Ok(w);
                }
                Ok(In::Msg(Msg::Bye(Bye::Revoked)) | In::Closed(CloseReason::Revoked)) => {
                    return Err(Fail::Fatal(denied("the host revoked this guest")));
                }
                Ok(In::Msg(Msg::Bye(Bye::ProtoMismatch))) => {
                    return Err(Fail::Fatal(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "the host speaks a different protocol version",
                    )));
                }
                Ok(In::Closed(_))
                | Err(RecvTimeoutError::Disconnected | RecvTimeoutError::Timeout) => {
                    return Err(Fail::Retry);
                }
                Ok(_) => {}
            }
        }
    }

    // false when the user asked to quit while waiting
    fn backoff_wait(cmds: &Receiver<UiCmd>, backoff: &mut Duration) -> bool {
        let wait = *backoff;
        *backoff = (*backoff * 2).min(BACKOFF_MAX);
        let until = Instant::now() + wait;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            select! {
                recv(cmds) -> c => if matches!(c, Ok(UiCmd::Quit) | Err(_)) { return false },
                recv(after(left)) -> _ => return true,
            }
        }
    }

    // whatever an earlier session left for this host is removed before anything is loaded, so a join always starts clean
    fn clear_previous(paths: &HostPaths, bus: &UiBus) -> io::Result<()> {
        let crashed = wipe::marker_present(paths.state());
        let sum = paths.wipe()?;
        if let Some(p) = sum.problem() {
            return Err(io::Error::other(format!(
                "cannot clear the guest state an earlier session left behind: {p}"
            )));
        }
        if crashed {
            bus.update(|s| s.hint(CRASH_HINT));
        }
        Ok(())
    }

    fn finish_wipe(paths: &HostPaths, bus: &UiBus, blocker: Option<&'static str>) {
        let hint = match blocker {
            Some(h) => h,
            None => match paths.wipe() {
                Ok(sum) if sum.is_clean() => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => WIPE_BUSY_HINT,
                Ok(_) | Err(_) => WIPE_PARTIAL_HINT,
            },
        };
        bus.update(|s| s.hint(hint));
    }

    // true once this was the last holder of the core, which frees the blob cache and its directory lock
    fn release(mut core: Arc<Core>) -> bool {
        let end = Instant::now() + CORE_WAIT;
        loop {
            match Arc::try_unwrap(core) {
                Ok(c) => {
                    drop(c);
                    return true;
                }
                Err(c) if Instant::now() < end => {
                    core = c;
                    thread::sleep(STOP_POLL / 5);
                }
                Err(_) => return false,
            }
        }
    }

    fn notice_fn(bus: Arc<UiBus>, link: Arc<Mutex<Option<Link>>>, ctr: Arc<Counters>) -> NoticeFn {
        Arc::new(move |n: Notice| {
            match n.kind {
                NoticeKind::Merged => {
                    ctr.merged.fetch_add(1, Relaxed);
                }
                NoticeKind::Refused => {
                    ctr.refused.fetch_add(1, Relaxed);
                }
                _ => {}
            }
            if let Some(l) = lock(&link).as_ref() {
                let _ = l.send(Msg::Push(Push::Notice(n.clone())));
            }
            bus.update(|s| s.push_notice(now_ms(), n));
        })
    }

    pub fn run(cfg: GuestCfg, bus: Arc<UiBus>, cmds: Receiver<UiCmd>) -> io::Result<()> {
        bus.update(|s| {
            s.mount = Some(cfg.mount.clone());
            s.host_addr = Some(cfg.addr);
            s.mounted = false;
        });
        let hs = me(&cfg);
        let pairing = cfg.repair || cfg.host_key.is_none();
        let mut backoff = BACKOFF_MIN;
        let sess = loop {
            let how = match (pairing, cfg.host_key) {
                (false, Some(k)) => Dial::Resume(k),
                _ => Dial::Pair,
            };
            let r = dial(cfg.addr, &cfg.identity, how, &hs, true).and_then(|s| {
                if pairing {
                    pair(&s, &cfg, &bus, &cmds)?;
                }
                Ok(s)
            });
            match r {
                Ok(s) => break s,
                Err(Fail::Retry | Fail::Unverified) => {
                    if !backoff_wait(&cmds, &mut backoff) {
                        return Ok(());
                    }
                }
                Err(Fail::Fatal(e)) => return Err(e),
                Err(Fail::Quit) => return Ok(()),
            }
        };
        let key = sess.link.peer();
        let paths = HostPaths::new(&cfg.dirs, &key);
        clear_previous(&paths, &bus)?;
        let (res, blocker) = session(cfg, bus.clone(), cmds, sess, key, &paths);
        finish_wipe(&paths, &bus, blocker);
        res
    }

    // the second value is why the local state must stay, or None when the session left nothing in use and it can be wiped
    fn session(
        cfg: GuestCfg,
        bus: Arc<UiBus>,
        cmds: Receiver<UiCmd>,
        sess: Session,
        key: PeerKey,
        paths: &HostPaths,
    ) -> (io::Result<()>, Option<&'static str>) {
        let mut g = match open(cfg, bus, cmds, key, sess.hello.name.clone(), paths) {
            Ok(g) => g,
            Err(e) => return (Err(e), None),
        };
        let res = match hello(&sess, &g.core.tree) {
            Ok(w) => {
                g.install(sess, w);
                g.event_loop()
            }
            Err(Fail::Fatal(e)) => Err(e),
            Err(Fail::Quit) => Ok(()),
            Err(Fail::Retry | Fail::Unverified) => {
                drop(sess);
                g.lost(CloseReason::Eof).and_then(|()| g.event_loop())
            }
        };
        (res, g.shutdown())
    }

    fn open(
        cfg: GuestCfg,
        bus: Arc<UiBus>,
        cmds: Receiver<UiCmd>,
        key: PeerKey,
        host_name: Name,
        paths: &HostPaths,
    ) -> io::Result<Guest> {
        let state = paths.state();
        ensure_private_dir(state)?;
        wipe::mark_live(state)?;
        let overlay_path = state.join(OVERLAY_DIR);
        ensure_private_dir(&overlay_path)?;
        let tree = Arc::new(RwLock::new(GTree::new()));
        let remote = RemoteSlot::new();
        let cache = Arc::new(BlobCache::open(
            &CacheConfig {
                dir: paths.cache().to_path_buf(),
                cap: Some(cfg.cache_cap),
            },
            remote.clone(),
        )?);
        let link_slot: Arc<Mutex<Option<Link>>> = Arc::new(Mutex::new(None));
        let ctr = Arc::new(Counters::default());
        let notice = notice_fn(bus.clone(), link_slot.clone(), ctr.clone());
        let (landed, _) = unbounded();
        let pipe = Pipe::new(remote.clone(), landed)?;
        let writer = Writer::new(cache.clone(), pipe.clone(), notice.clone());
        let view: Arc<dyn TreeView> = tree.clone();
        let prefetch = Prefetch::start(cache.clone(), view)?;
        let overlay = rustix::fs::open(
            overlay_path.as_path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let (kick_tx, kick_rx) = bounded(1);
        let core = Arc::new(Core {
            tree,
            cache,
            writer,
            prefetch,
            rules: RwLock::new(Rules::new(&[])),
            inj: OnceLock::new(),
            inval: OnceLock::new(),
            overlay,
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            ctr,
            kicked: Mutex::new(Vec::new()),
            kick: kick_tx,
            case_fold: AtomicBool::new(false),
            norm_fold: AtomicBool::new(false),
            passthrough: AtomicBool::new(false),
            notice,
            werrs: AtomicU32::new(0),
            staging_busy: Mutex::new(FxHashSet::default()),
            staging_done: Condvar::new(),
            promote_later: Mutex::new(FxHashSet::default()),
            own_scopes: Mutex::new(FxHashSet::default()),
            dir_moves: Mutex::new(Vec::new()),
            dir_moved: Condvar::new(),
        });
        let rules = Arc::new(RuleState::default());
        let (rules_tx, rules_rx) = bounded(RULE_JOBS);
        let rules_join = {
            let (c, st) = (core.clone(), rules.clone());
            thread::Builder::new()
                .name("csync-rules".into())
                .spawn(move || rules_worker(&c, &st, &rules_rx))?
        };
        // last: a failed spawn here drops rules_tx, which ends the rules worker
        let settle_join = {
            let (c, jobs) = (core.clone(), core.writer.jobs());
            thread::Builder::new()
                .name("csync-settle".into())
                .spawn(move || fs::settle_loop(&c, &jobs))?
        };
        let (dial_tx, dial_rx) = bounded(1);
        Ok(Guest {
            hash_run: Arc::new(AtomicBool::new(false)),
            hash_stop: Arc::new(AtomicBool::new(false)),
            hash_join: None,
            bus,
            cmds,
            core,
            remote,
            pipe,
            key,
            host_name,
            link_slot,
            link: None,
            rpc: None,
            inbox: never(),
            #[cfg(target_os = "macos")]
            project: None,
            mounted: None,
            mount_dev: None,
            inj: None,
            back: never(),
            kick_rx,
            rules,
            rules_tx: Some(rules_tx),
            rules_join: Some(rules_join),
            settle_join: Some(settle_join),
            dial_tx,
            dial_rx,
            dial_stop: Arc::new(AtomicBool::new(false)),
            dialing: false,
            synced: false,
            snap_next: None,
            synced_entries: 0,
            last_ui: Instant::now(),
            ui_due: None,
            last_ping: Instant::now(),
            rtt_us: 0,
            skew_ms: 0,
            notify: None,
            rule_paths: Vec::new(),
            bye: CloseReason::Local,
            cfg,
        })
    }

    struct Guest {
        cfg: GuestCfg,
        bus: Arc<UiBus>,
        cmds: Receiver<UiCmd>,
        core: Arc<Core>,
        remote: Arc<RemoteSlot>,
        pipe: Arc<Pipe>,
        key: PeerKey,
        host_name: Name,
        link_slot: Arc<Mutex<Option<Link>>>,
        link: Option<Link>,
        rpc: Option<Arc<Rpc>>,
        inbox: Receiver<In>,
        // names the volume the mount shows in finder
        #[cfg(target_os = "macos")]
        project: Option<Name>,
        mounted: Option<Mounted>,
        // the device under the mount point before this session mounted over it
        mount_dev: Option<u64>,
        inj: Option<InjectorThread>,
        back: Receiver<Vec<Effect>>,
        kick_rx: Receiver<()>,
        rules: Arc<RuleState>,
        rules_tx: Option<Sender<RuleJob>>,
        rules_join: Option<JoinHandle<()>>,
        // finishes the closes that did not wait for the host, as its answers arrive
        settle_join: Option<JoinHandle<()>>,
        // the short-lived thread pulling the hashes of pending files once the host has hashed them all
        hash_run: Arc<AtomicBool>,
        hash_stop: Arc<AtomicBool>,
        hash_join: Option<JoinHandle<()>>,
        dial_tx: Sender<Result<(Session, Welcome), Fail>>,
        dial_rx: Receiver<Result<(Session, Welcome), Fail>>,
        dial_stop: Arc<AtomicBool>,
        dialing: bool,
        synced: bool,
        snap_next: Option<u32>,
        synced_entries: u64,
        last_ui: Instant,
        ui_due: Option<Instant>,
        last_ping: Instant,
        rtt_us: u32,
        skew_ms: i64,
        notify: Option<Notify>,
        rule_paths: Vec<RelPath>,
        // what the host is told when the link closes at shutdown
        bye: CloseReason,
    }

    fn earliest(a: Option<Instant>, b: Instant) -> Option<Instant> {
        Some(a.map_or(b, |a| a.min(b)))
    }

    struct Notify {
        tx: Sender<Vec<Effect>>,
        join: JoinHandle<()>,
    }

    // the startup self-test, run by the injector thread once the root is verified to be on the mounted volume: the
    // identification it decides is how requests are told from injected ones, and Claim keeps events from being replayed
    #[cfg(target_os = "macos")]
    fn probe_boot(core: Arc<Core>, inval: fs::Inval, backend: BackendKind) -> Boot {
        Box::new(move |root| {
            let done = match root {
                Some(r) => {
                    let env = Env {
                        root: r.as_fd(),
                        core: &core,
                        inval: &inval,
                    };
                    coherence::run(&env, backend)
                }
                None => coherence::run_unverified(backend),
            };
            done.ident
        })
    }

    // a kernel notification can wait on a page or directory lock held by a request that is itself
    // waiting for a host change, so they are sent from here and never hold up the loop applying changes
    fn notify_loop(core: &Core, inval: &fs::Inval, rx: &Receiver<Vec<Effect>>) {
        loop {
            // the timeout runs only while a page cache waits for its readers to let go
            let next = match inval.next_due() {
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                Some(due) => rx.recv_timeout(due.saturating_duration_since(Instant::now())),
            };
            let mut fx = match next {
                Ok(fx) => fx,
                Err(RecvTimeoutError::Timeout) => Vec::new(),
                Err(RecvTimeoutError::Disconnected) => break,
            };
            while let Ok(more) = rx.try_recv() {
                fx.extend(more);
            }
            run_effects(core, Some(inval), fx);
            for id in inval.take_due(Instant::now()) {
                core.reload(inval, id, true);
            }
        }
    }

    // every effect here was queued before the first runs, so one entry invalidation covers its repeats
    fn run_effects(core: &Core, inval: Option<&fs::Inval>, fx: Vec<Effect>) {
        let mut entries = FxHashSet::default();
        let mut work: VecDeque<Effect> = fx
            .into_iter()
            .filter(|e| match e {
                Effect::InvalEntry(p, n) => entries.insert((*p, n.clone())),
                _ => true,
            })
            .collect();
        let mut seen = FxHashSet::default();
        while let Some(e) = work.pop_front() {
            match e {
                Effect::InvalInode(id) => {
                    if seen.insert(id)
                        && let Some(k) = inval
                    {
                        core.reload(k, id, false);
                    }
                }
                Effect::Reshow(id) => {
                    if !seen.contains(&id)
                        && let Some(k) = inval
                    {
                        core.reshow(k, id);
                    }
                }
                Effect::InvalEntry(p, n) => {
                    if let Some(k) = inval {
                        k.entry(p, &n);
                    }
                }
                Effect::Synth(s) => {
                    if !core.inj.get().is_some_and(|i| i.offer(s.clone())) {
                        let mut more = Vec::new();
                        core.tw().settle(&s, &mut more);
                        work.extend(more);
                    }
                }
                Effect::Warm(id, h) => core.prefetch.hint(Hint::Warm(id, h)),
                Effect::WarmPending(id) => core.prefetch.hint(Hint::WarmPending(id)),
                Effect::ConflictPending(id) => {
                    let h = core.t().get(id).and_then(|n| n.meta.hash);
                    if let Some(h) = h {
                        core.prefetch.hint(Hint::Warm(id, h));
                    }
                }
                // read_ver blobs are protected by the cache's open-time window, not by pins
                Effect::Unpin(_) => {}
                Effect::LocalDiscarded(p) => {
                    core.remove_overlay(&p);
                    (core.notice)(Notice {
                        kind: NoticeKind::Discarded,
                        path: p,
                    });
                }
                Effect::Promote(p) => core.promote(&p),
            }
        }
    }

    impl Guest {
        fn set_peer(&self, st: ConnState) {
            put_peer(
                &self.bus,
                peer_view(&self.host_name, &self.key, st, self.rtt_us),
            );
        }

        fn event_loop(&mut self) -> io::Result<()> {
            loop {
                let timer = self.timer();
                let (inbox, back, kick, dials, cmds) = (
                    self.inbox.clone(),
                    self.back.clone(),
                    self.kick_rx.clone(),
                    self.dial_rx.clone(),
                    self.cmds.clone(),
                );
                select! {
                    recv(inbox) -> m => match m {
                        Ok(i) => self.on_in(i)?,
                        Err(_) => self.lost(CloseReason::Eof)?,
                    },
                    recv(back) -> fx => match fx {
                        Ok(fx) => self.queue(fx),
                        Err(_) => self.back = never(),
                    },
                    recv(kick) -> k => if k.is_ok() {
                        let fx = self.core.take_kicked();
                        self.queue(fx);
                    },
                    recv(dials) -> r => match r {
                        Ok(Ok((s, w))) => self.install(s, w),
                        Ok(Err(Fail::Fatal(e))) => return Err(e),
                        Ok(Err(_)) => {
                            self.dialing = false;
                            self.spawn_dialer();
                        }
                        Err(_) => {}
                    },
                    recv(cmds) -> c => match c {
                        Ok(UiCmd::Quit) | Err(_) => return Ok(()),
                        Ok(UiCmd::Revoke(HOST_PEER)) => return Err(self.forget_host()),
                        Ok(_) => {}
                    },
                    recv(timer) -> _ => self.tick(),
                }
            }
        }

        // nothing wakes this thread unless there is pending ui or a live link to ping
        fn timer(&self) -> Receiver<Instant> {
            let mut due = self.ui_due;
            if self.link.is_some() {
                due = earliest(due, self.last_ping + PING_EVERY);
            }
            match due {
                Some(d) => after(d.saturating_duration_since(Instant::now())),
                None => never(),
            }
        }

        fn tick(&mut self) {
            let now = Instant::now();
            if self.ui_due.is_some_and(|d| d <= now) {
                self.ui();
            }
            if self.link.is_some() && now >= self.last_ping + PING_EVERY {
                self.ping();
            }
        }

        fn ping(&mut self) {
            self.last_ping = Instant::now();
            if let Some(l) = &self.link {
                let _ = l.send(Msg::Ping { t_ns: now_ns() });
            }
        }

        fn install(&mut self, sess: Session, w: Welcome) {
            let Session {
                link, inbox, hello, ..
            } = sess;
            self.host_name = hello.name;
            let rpc = Rpc::new(link.clone());
            self.core.tw().clear_acked();
            self.remote.set(Some(rpc.clone() as Arc<dyn Remote>));
            *lock(&self.link_slot) = Some(link.clone());
            self.link = Some(link);
            self.rpc = Some(rpc);
            self.inbox = inbox;
            self.dialing = false;
            self.snap_next = None;
            self.synced_entries = 0;
            self.core.case_fold.store(w.fs.case_fold, Relaxed);
            self.core.norm_fold.store(w.fs.norm_fold, Relaxed);
            let project = w.project.clone();
            #[cfg(target_os = "macos")]
            {
                self.project = Some(project.clone());
            }
            self.bus.update(|s| s.project = Some(project));
            rules_reset(&self.core, &self.rules, &w.excludes, &w.repos);
            self.set_peer(ConnState::Syncing { done: 0, total: 0 });
            self.ping();
        }

        // the user withdrew trust in this host: drop its entry, then end like a revoked session
        fn forget_host(&mut self) -> io::Error {
            let _ = self.cfg.trust.forget(&self.key.to_b64());
            self.bye = CloseReason::Revoked;
            denied("this guest forgot the host")
        }

        fn lost(&mut self, why: CloseReason) -> io::Result<()> {
            if matches!(why, CloseReason::Revoked) {
                return Err(denied("the host revoked this guest"));
            }
            self.remote.set(None);
            *lock(&self.link_slot) = None;
            self.link = None;
            self.rpc = None;
            self.inbox = never();
            self.abort_snapshot();
            self.set_peer(ConnState::Disconnected { since_ms: now_ms() });
            self.spawn_dialer();
            Ok(())
        }

        // a half-applied snapshot must not be resumed from, so the next hello asks for a fresh one
        fn abort_snapshot(&mut self) {
            if self.snap_next.take().is_some() {
                let mut t = self.core.tw();
                t.snapshot_reset();
                t.set_version(0, 0);
            }
        }

        fn protocol(&mut self, why: &'static str) {
            self.abort_snapshot();
            if let Some(l) = &self.link {
                l.close(CloseReason::Protocol(why));
            }
        }

        fn spawn_dialer(&mut self) {
            if self.dialing {
                return;
            }
            self.dialing = true;
            self.dial_stop.store(true, Relaxed);
            let stop = Arc::new(AtomicBool::new(false));
            self.dial_stop = stop.clone();
            let (addr, id, hs, key, tree, tx, bus) = (
                self.cfg.addr,
                self.cfg.identity.clone(),
                me(&self.cfg),
                self.key,
                self.core.tree.clone(),
                self.dial_tx.clone(),
                self.bus.clone(),
            );
            let spawned = thread::Builder::new()
                .name("csync-dial".into())
                .spawn(move || {
                    let mut backoff = BACKOFF_MIN;
                    while !stop.load(Relaxed) {
                        match dial(addr, &id, Dial::Resume(key), &hs, false)
                            .and_then(|s| hello(&s, &tree).map(|w| (s, w)))
                        {
                            Ok(x) => {
                                bus.update(|s| s.hints.retain(|h| *h != UNVERIFIED_HINT));
                                let _ = tx.send(Ok(x));
                                return;
                            }
                            Err(f @ (Fail::Retry | Fail::Unverified)) => {
                                let max = if matches!(f, Fail::Unverified) {
                                    bus.update(|s| s.hint(UNVERIFIED_HINT));
                                    UNVERIFIED_BACKOFF_MAX
                                } else {
                                    BACKOFF_MAX
                                };
                                let until = Instant::now() + backoff;
                                backoff = (backoff * 2).min(max);
                                while !stop.load(Relaxed) && Instant::now() < until {
                                    thread::sleep(
                                        STOP_POLL
                                            .min(until.saturating_duration_since(Instant::now())),
                                    );
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(e));
                                return;
                            }
                        }
                    }
                });
            if spawned.is_err() {
                self.dialing = false;
            }
        }

        fn on_in(&mut self, i: In) -> io::Result<()> {
            let i = match i {
                In::Closed(why) => {
                    if let Some(r) = &self.rpc {
                        r.dispatch(In::Closed(why.clone()));
                    }
                    return self.lost(why);
                }
                other => other,
            };
            let m = match (&self.rpc, i) {
                // only directory move replies come this way; later pushes name the new path, so the move lands first
                (Some(r), In::Msg(Msg::Resp { id, res })) => {
                    if let Some(m) = r.route_ordered(id, res) {
                        self.core.await_dir_move(&m);
                    }
                    None
                }
                (Some(r), i) => r.dispatch(i),
                (None, i) => match i {
                    In::Msg(m) => Some(m),
                    _ => None,
                },
            };
            match m {
                Some(Msg::Push(p)) => self.on_push(p)?,
                Some(Msg::Pong { t_ns, host_ns }) => {
                    let now = now_ns();
                    let rtt = now.saturating_sub(t_ns);
                    self.rtt_us = (rtt / 1_000).min(u64::from(u32::MAX)) as u32;
                    let mid = i128::from(t_ns) + i128::from(rtt / 2);
                    self.skew_ms = ((i128::from(host_ns) - mid) / 1_000_000) as i64;
                    self.ui_soon();
                }
                Some(Msg::Bye(Bye::Revoked)) => return Err(denied("the host revoked this guest")),
                Some(Msg::Req { .. } | Msg::Welcome(_) | Msg::Hello(_)) => {
                    self.protocol("unexpected message from host")
                }
                _ => {}
            }
            Ok(())
        }

        fn on_push(&mut self, p: Push) -> io::Result<()> {
            match p {
                Push::Snapshot {
                    index,
                    seq,
                    part,
                    last,
                    entries,
                } => {
                    if part != self.snap_next.unwrap_or(0) {
                        self.protocol("snapshot parts out of order");
                        return Ok(());
                    }
                    let mut fx = Vec::new();
                    let r = {
                        let mut t = self.core.tw();
                        if part == 0 {
                            t.snapshot_reset();
                        }
                        t.apply_snapshot_part(&entries, last, &mut fx)
                    };
                    self.queue(fx);
                    if let Err(e) = r {
                        self.snap_next = Some(part);
                        self.protocol(e);
                        return Ok(());
                    }
                    self.synced_entries += entries.len() as u64;
                    if last {
                        self.snap_next = None;
                        self.core.tw().set_version(index, seq);
                        self.synced(seq, true)?;
                    } else {
                        self.snap_next = Some(part.saturating_add(1));
                        self.set_peer(ConnState::Syncing {
                            done: self.synced_entries,
                            total: 0,
                        });
                    }
                }
                Push::Changes { seq, changes } => {
                    if self.snap_next.is_some() {
                        self.protocol("changes inside a snapshot");
                        return Ok(());
                    }
                    let mut fx = Vec::new();
                    // a remove of an entry this guest's own rule edit already ignores moves it to the overlay instead
                    let demote: Vec<RelPath> = {
                        let own = lock(&self.core.own_scopes);
                        let t = self.core.t();
                        let r = self.core.rules();
                        changes
                            .iter()
                            .filter_map(|c| match c {
                                Change::Remove { path }
                                    if own.iter().any(|s| path.starts_with(s)) =>
                                {
                                    let n = t.resolve(path).and_then(|id| t.get(id))?;
                                    (n.domain == GDomain::Synced
                                        && r.classify(path, n.is_dir()) == Class::Ignored)
                                        .then(|| path.clone())
                                }
                                _ => None,
                            })
                            .collect()
                    };
                    let kept = |p: &RelPath| demote.iter().any(|d| p.starts_with(d));
                    {
                        let mut t = self.core.tw();
                        for c in &changes {
                            if let Change::Remove { path } = c
                                && kept(path)
                            {
                                continue;
                            }
                            t.apply(c, &mut fx);
                        }
                        let index = t.index_id();
                        t.set_version(index, seq);
                    }
                    {
                        let r = self.core.rules();
                        for c in &changes {
                            match c {
                                Change::Remove { path } if kept(path) => {}
                                Change::Upsert { path, .. } | Change::Remove { path } => {
                                    if r.is_rule_file(path) {
                                        self.rule_paths.push(path.clone());
                                    }
                                }
                                Change::Rename { from, to } => {
                                    for p in [from, to] {
                                        if r.is_rule_file(p) {
                                            self.rule_paths.push(p.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if !demote.is_empty() {
                        self.rule_job(RuleJob::Demote(demote));
                    }
                    self.queue(fx);
                    self.synced(seq, false)?;
                }
                Push::Notice(n) => self.bus.update(|s| s.push_notice(now_ms(), n)),
                // a pushed hash only labels a node: bytes fetched by it are verified before they are stored
                Push::Hashes { index, items } => {
                    let applied: Vec<(RelPath, NodeId, Hash32)> = {
                        let mut t = self.core.tw();
                        if t.index_id() != index {
                            return Ok(());
                        }
                        items
                            .into_iter()
                            .filter_map(|(path, ver, h)| {
                                let id = t.resolve(&path)?;
                                t.learn_hash(id, ver, h).then_some((path, id, h))
                            })
                            .collect()
                    };
                    let rule_files: Vec<RelPath> = {
                        let r = self.core.rules();
                        applied
                            .iter()
                            .filter(|(p, _, _)| r.is_rule_file(p))
                            .map(|(p, _, _)| p.clone())
                            .collect()
                    };
                    if !rule_files.is_empty() {
                        self.rule_job(RuleJob::Paths(rule_files));
                    }
                    for (_, id, h) in applied {
                        self.core.prefetch.hint(Hint::Warm(id, h));
                    }
                }
                Push::HashesDone { index } => {
                    if index == self.core.t().index_id() {
                        self.pull_hashes();
                    }
                }
            }
            Ok(())
        }

        // the round trips run on their own thread, never on the one reading the network
        fn pull_hashes(&mut self) {
            if self.hash_stop.load(Relaxed) || self.hash_run.swap(true, Relaxed) {
                return;
            }
            if let Some(j) = self.hash_join.take() {
                let _ = j.join();
            }
            let (core, stop, run, rules_tx) = (
                self.core.clone(),
                self.hash_stop.clone(),
                self.hash_run.clone(),
                self.rules_tx.clone(),
            );
            let spawned = thread::Builder::new()
                .name("csync-hashes".into())
                .spawn(move || {
                    let _run = PullRun(run);
                    let rule_files = pull_pending(&core, &stop);
                    if !rule_files.is_empty()
                        && let Some(tx) = &rules_tx
                    {
                        send_rule_job(tx, RuleJob::Paths(rule_files));
                    }
                });
            match spawned {
                Ok(j) => self.hash_join = Some(j),
                Err(_) => self.hash_run.store(false, Relaxed),
            }
        }

        // a batch is fully applied: ack it, refresh ignore rules, and mount on the first one
        fn synced(&mut self, seq: u64, snapshot: bool) -> io::Result<()> {
            if let Some(l) = &self.link {
                let _ = l.send(Msg::Ack { seq });
            }
            if !self.synced {
                self.rule_paths.clear();
                rules_scan(&self.core, &self.rules);
                self.mount()?;
            } else {
                if snapshot {
                    self.rule_job(RuleJob::Scan);
                    self.core.prefetch.hint(Hint::Start);
                }
                if !self.rule_paths.is_empty() {
                    let paths = std::mem::take(&mut self.rule_paths);
                    self.rule_job(RuleJob::Paths(paths));
                }
            }
            self.set_peer(ConnState::Live);
            self.ui_soon();
            Ok(())
        }

        fn rule_job(&self, j: RuleJob) {
            if let Some(tx) = &self.rules_tx {
                send_rule_job(tx, j);
            }
        }

        fn mount(&mut self) -> io::Result<()> {
            self.mount_dev = wipe::device_of(&self.cfg.mount);
            #[cfg(target_os = "linux")]
            let m = fs::mount(self.core.clone(), &self.cfg.mount, self.cfg.allow_other)?;
            #[cfg(target_os = "linux")]
            let (inj, thread, back) = Injector::start(&self.cfg.mount, self.core.tree.clone())?;
            #[cfg(target_os = "macos")]
            let volname = self.project.as_ref().map_or("csync", Name::as_str);
            #[cfg(target_os = "macos")]
            let m = fs::mount(
                self.core.clone(),
                &self.cfg.mount,
                self.cfg.allow_other,
                volname,
            )?;
            #[cfg(target_os = "macos")]
            let backend = m
                .backend()
                .ok_or_else(|| io::Error::other("the mount ended before it began"))?;
            #[cfg(target_os = "macos")]
            let (inj, thread, back) = Injector::start_probed(
                &self.cfg.mount,
                self.core.tree.clone(),
                self.mount_dev,
                probe_boot(self.core.clone(), m.inval(), backend),
            )?;
            let _ = self.core.inj.set(inj);
            self.inj = Some(thread);
            self.back = back;
            self.core.tw().set_mounted(true);
            let (tx, rx) = unbounded();
            let (core, inval) = (self.core.clone(), m.inval());
            let join = thread::Builder::new()
                .name("csync-notify".into())
                .spawn(move || notify_loop(&core, &inval, &rx))?;
            self.notify = Some(Notify { tx, join });
            self.mounted = Some(m);
            self.synced = true;
            self.core.prefetch.hint(Hint::Start);
            self.bus.update(|s| s.mounted = true);
            Ok(())
        }

        fn queue(&mut self, fx: Vec<Effect>) {
            if fx.is_empty() {
                return;
            }
            // promotions take host round trips, so the rules worker runs them, not the notifier
            let (up, fx): (Vec<Effect>, Vec<Effect>) = fx
                .into_iter()
                .partition(|e| matches!(e, Effect::Promote(_)));
            let up: Vec<RelPath> = up
                .into_iter()
                .filter_map(|e| match e {
                    Effect::Promote(p) => Some(p),
                    _ => None,
                })
                .collect();
            if !up.is_empty() {
                self.rule_job(RuleJob::Promote(up));
            }
            match &self.notify {
                Some(n) => {
                    if let Err(e) = n.tx.send(fx) {
                        run_effects(&self.core, None, e.into_inner());
                    }
                }
                None => run_effects(&self.core, None, fx),
            }
            self.ui_soon();
        }

        fn ui_soon(&mut self) {
            if self.ui_due.is_none() {
                self.ui_due = Some(self.last_ui + UI_EVERY);
            }
        }

        fn ui(&mut self) {
            self.ui_due = None;
            self.last_ui = Instant::now();
            let files = self.core.t().files();
            let (cached, cap) = self.core.cache.usage();
            let c = &self.core.ctr;
            let (hits, misses, commits, merged, refused, inflight) = (
                c.hits.load(Relaxed),
                c.misses.load(Relaxed),
                c.commits.load(Relaxed),
                c.merged.load(Relaxed),
                c.refused.load(Relaxed),
                c.inflight.load(Relaxed),
            );
            let backlog = self.core.inj.get().map_or(0, |i| i.backlog());
            let passthrough = self.core.passthrough.load(Relaxed);
            let pg = &self.core.prefetch.progress;
            let (pf_total, pf_done) = (pg.total.load(Relaxed), pg.done.load(Relaxed));
            let (mounted, skew, rtt) = (self.mounted.is_some(), self.skew_ms, self.rtt_us);
            #[cfg(target_os = "macos")]
            let (backend, inval) = coherence::status().unwrap_or_default();
            #[cfg(target_os = "macos")]
            let fault = self.core.inj.get().and_then(|i| i.fault());
            self.bus.update(|s| {
                #[cfg(target_os = "macos")]
                {
                    s.guest.backend = backend;
                    s.guest.inval = inval;
                    if let Some(h) = fault {
                        s.hint(h);
                    }
                }
                s.stats.files = files;
                s.stats.cached_bytes = cached;
                s.stats.cache_cap = cap;
                s.stats.fetches = misses;
                s.stats.commits = commits;
                s.stats.merged = merged;
                s.stats.refused = refused;
                s.stats.inject_backlog = u32::try_from(backlog).unwrap_or(u32::MAX);
                s.stats.skew_ms = skew;
                s.guest.hits = hits;
                s.guest.misses = misses;
                s.guest.inflight = inflight;
                s.guest.passthrough = passthrough;
                s.guest.prefetch_total = pf_total;
                s.guest.prefetch_done = pf_done.min(pf_total);
                s.mounted = mounted;
                if let Some(p) = s.peers.iter_mut().find(|p| p.id == HOST_PEER) {
                    p.rtt_us = rtt;
                }
            });
        }

        // the injector stops before the unmount; closes still waiting on the host settle next, then the write pipe and
        // the link close so final commits can land, and the settler stops once the pipe has failed what it never sent.
        // nothing is saved: the caller wipes the local state unless the returned reason says it is still in use
        fn shutdown(mut self) -> Option<&'static str> {
            self.dial_stop.store(true, Relaxed);
            // handlers the unmount waits on must not wait for a link the stopped dialer never brings
            self.remote.close();
            self.hash_stop.store(true, Relaxed);
            if let Some(t) = self.inj.take() {
                t.stop();
            }
            self.core.tw().set_mounted(false);
            if let Some(n) = self.notify.take() {
                drop(n.tx);
                let _ = n.join.join();
            }
            let had_mount = self.mounted.is_some();
            let unmounted = self.mounted.take().is_none_or(|m| m.unmount().is_ok());
            self.bus.update(|s| s.mounted = false);
            self.core.writer.drain(Instant::now() + SETTLE_WAIT);
            self.pipe.close();
            self.core.writer.stop_settler();
            if let Some(j) = self.settle_join.take() {
                let _ = j.join();
            }
            if let Some(l) = self.link.take() {
                l.close(self.bye.clone());
            }
            *lock(&self.link_slot) = None;
            self.remote.set(None);
            // before the rules queue closes: the pull thread holds a sender and a hold on the core
            if let Some(j) = self.hash_join.take() {
                let _ = j.join();
            }
            self.core.prefetch.stop();
            self.rules_tx = None;
            if let Some(j) = self.rules_join.take() {
                let _ = j.join();
            }
            let still_mounted =
                had_mount && (!unmounted || wipe::is_mounted_over(&self.cfg.mount, self.mount_dev));
            let Guest { core, .. } = self;
            let freed = release(core);
            if still_mounted {
                Some(WIPE_MOUNTED_HINT)
            } else if !freed {
                Some(WIPE_BUSY_HINT)
            } else {
                None
            }
        }
    }

    type KnownRules = FxHashMap<RelPath, (Hash32, Arc<[u8]>)>;

    #[derive(Default)]
    struct RuleState {
        known: Mutex<KnownRules>,
    }

    enum RuleJob {
        Scan,
        Paths(Vec<RelPath>),
        Promote(Vec<RelPath>),
        Demote(Vec<RelPath>),
    }

    fn send_rule_job(tx: &Sender<RuleJob>, j: RuleJob) {
        if tx.try_send(j).is_err() {
            let _ = tx.try_send(RuleJob::Scan);
        }
    }

    // clears the running flag however the pull thread ends
    struct PullRun(Arc<AtomicBool>);

    impl Drop for PullRun {
        fn drop(&mut self) {
            self.0.store(false, Relaxed);
        }
    }

    // returns the rule files it labelled, so their rules can be applied
    fn pull_pending(core: &Core, stop: &AtomicBool) -> Vec<RelPath> {
        let mut rule_files = Vec::new();
        while !stop.load(Relaxed) && core.cache.remote().current().is_some() {
            let (index, list) = {
                let t = core.t();
                (t.index_id(), t.pending_list(BATCH_MAX))
            };
            if list.is_empty() {
                break;
            }
            let asked: Vec<(RelPath, _)> = list.iter().map(|(_, p, v)| (p.clone(), *v)).collect();
            let Ok(got) = core
                .cache
                .pull_hashes(index, &asked, Instant::now() + HASH_WAIT)
            else {
                break;
            };
            let mut applied = Vec::new();
            {
                let mut t = core.tw();
                for ((id, p, v), h) in list.into_iter().zip(got) {
                    if let Some(h) = h
                        && t.learn_hash(id, v, h)
                    {
                        applied.push(p);
                    }
                }
            }
            if applied.is_empty() {
                break;
            }
            let r = core.rules();
            rule_files.extend(applied.into_iter().filter(|p| r.is_rule_file(p)));
        }
        rule_files
    }

    fn rules_worker(core: &Core, st: &RuleState, rx: &Receiver<RuleJob>) {
        while let Ok(j) = rx.recv() {
            let mut scan = false;
            let mut paths = Vec::new();
            let mut up = Vec::new();
            let mut down = Vec::new();
            for j in std::iter::once(j).chain(rx.try_iter()) {
                match j {
                    RuleJob::Scan => scan = true,
                    RuleJob::Paths(p) => paths.extend(p),
                    RuleJob::Promote(p) => up.extend(p),
                    RuleJob::Demote(p) => down.extend(p),
                }
            }
            for p in down {
                core.demote(&p);
            }
            if scan {
                rules_scan(core, st);
            } else if !paths.is_empty() {
                rules_paths(core, st, paths);
            }
            promote_all(core, up);
        }
    }

    // rebuilds the mirrored rules from the host's welcome and re-applies every rule file text already known
    fn rules_reset(
        core: &Core,
        st: &RuleState,
        excludes: &[ExcludeSrc],
        repos: &[(RelPath, RelPath)],
    ) {
        let mut r = Rules::new(excludes);
        for (wt, gd) in repos {
            r.add_repo(wt, gd);
        }
        for (p, (_, text)) in lock(&st.known).iter() {
            r.update_rule_file(p, Some(&text[..]));
        }
        *core.rules_mut() = r;
    }

    // pending: the node and host version to fetch the file by while the host has not hashed it yet
    struct RuleFile {
        path: RelPath,
        hash: Option<Hash32>,
        size: u64,
        pending: Option<(NodeId, VerKey)>,
    }

    fn rule_file(id: NodeId, n: &GNode, path: RelPath, index: IndexId) -> RuleFile {
        RuleFile {
            path,
            hash: n.meta.hash,
            size: n.meta.size,
            pending: n.ver_key(index).map(|k| (id, k)),
        }
    }

    // every rule file in the host tree; inside .git only the gitdir and its info directory are walked
    type Found = Vec<RuleFile>;

    // second list: guest-only rule files directly inside a synced directory
    fn collect_rule_files(core: &Core) -> (Found, Vec<RelPath>) {
        let t = core.t();
        let index = t.index_id();
        let rules = core.rules();
        let mut out = Vec::new();
        let mut local = Vec::new();
        let mut stack: Vec<(NodeId, RelPath)> = vec![(ROOT, RelPath::root())];
        while let Some((d, path)) = stack.pop() {
            let Some(kids) = t.get(d).and_then(|n| n.children.as_ref()) else {
                continue;
            };
            for (name, &c) in kids {
                let Some(n) = t.get(c) else { continue };
                if n.domain == GDomain::Local || n.vis == Vis::PendingDelete {
                    if n.domain == GDomain::Local
                        && n.meta.kind == Kind::File
                        && let Ok(p) = path.join(name)
                        && rules.is_rule_file(&p)
                    {
                        local.push(p);
                    }
                    continue;
                }
                let Ok(p) = path.join(name) else { continue };
                if n.is_dir() {
                    if n.domain != GDomain::GitRo
                        || name.as_str() == ".git"
                        || name.as_str() == "info"
                    {
                        stack.push((c, p));
                    }
                } else if n.meta.kind == Kind::File && rules.is_rule_file(&p) {
                    out.push(rule_file(c, n, p, index));
                }
            }
        }
        (out, local)
    }

    fn rules_scan(core: &Core, st: &RuleState) {
        let (found, local) = collect_rule_files(core);
        let gone: Vec<RelPath> = {
            let k = lock(&st.known);
            k.keys()
                .filter(|p| !found.iter().any(|f| f.path == **p))
                .cloned()
                .collect()
        };
        let mut scopes = Vec::new();
        for p in gone {
            lock(&st.known).remove(&p);
            if let Some(s) = core.rules_mut().update_rule_file(&p, None) {
                scopes.push(s);
            }
        }
        rules_apply(core, st, found, &mut scopes);
        for p in &local {
            core.local_rule(p);
        }
        promote_all(core, scopes);
    }

    fn rules_paths(core: &Core, st: &RuleState, paths: Vec<RelPath>) {
        let mut found = Vec::new();
        let mut scopes = Vec::new();
        for p in paths {
            let cur = {
                let t = core.t();
                t.resolve(&p)
                    .and_then(|id| t.get(id).map(|n| (id, n)))
                    .filter(|(_, n)| n.meta.kind == Kind::File && n.domain != GDomain::Local)
                    .map(|(id, n)| rule_file(id, n, p.clone(), t.index_id()))
            };
            match cur {
                Some(f) => found.push(f),
                None => {
                    lock(&st.known).remove(&p);
                    if let Some(s) = core.rules_mut().update_rule_file(&p, None) {
                        scopes.push(s);
                    }
                }
            }
        }
        rules_apply(core, st, found, &mut scopes);
        promote_all(core, scopes);
    }

    fn promote_all(core: &Core, mut scopes: Vec<RelPath>) {
        scopes.sort();
        scopes.dedup();
        let mut done: Vec<RelPath> = Vec::new();
        for s in scopes {
            if !done.iter().any(|d| s.starts_with(d)) {
                core.promote(&s);
                done.push(s);
            }
        }
    }

    fn rules_apply(
        core: &Core,
        st: &RuleState,
        mut found: Vec<RuleFile>,
        scopes: &mut Vec<RelPath>,
    ) {
        resolve_pending(&core.cache, &core.tree, &mut found);
        let todo: Vec<(RelPath, Hash32, u64)> = {
            let k = lock(&st.known);
            found
                .into_iter()
                .filter_map(|f| {
                    let h = f.hash?;
                    (f.size <= TEXT_MAX as u64 && k.get(&f.path).is_none_or(|(kh, _)| *kh != h))
                        .then_some((f.path, h, f.size))
                })
                .collect()
        };
        prefetch_rules(core, &todo);
        for (p, h, size) in todo {
            let text = if size == 0 {
                Some(Vec::new())
            } else {
                core.cache
                    .fetch_whole(&h, &p, size, Instant::now() + RULE_WAIT)
                    .ok()
                    .and_then(|b| b.read_all(TEXT_MAX as u64).ok())
            };
            let Some(text) = text else { continue };
            let scope = core.rules_mut().update_rule_file(&p, Some(&text));
            lock(&st.known).insert(p, (h, text.into()));
            if let Some(s) = scope {
                scopes.push(s);
            }
        }
    }

    // a pending rule file is fetched by version, which also yields its hash; the second round retries replaced ones
    fn resolve_pending(cache: &BlobCache, tree: &RwLock<GTree>, found: &mut [RuleFile]) {
        for _ in 0..2 {
            let asked: Vec<(usize, NodeId, VerKey)> = found
                .iter()
                .enumerate()
                .filter(|(_, f)| f.size <= TEXT_MAX as u64)
                .filter_map(|(i, f)| f.pending.map(|(id, k)| (i, id, k)))
                .collect();
            if asked.is_empty() {
                return;
            }
            let items: Vec<(RelPath, VerKey)> = asked
                .iter()
                .map(|&(i, _, k)| (found[i].path.clone(), k))
                .collect();
            let got = cache.fetch_many_ver(&items, Instant::now() + RULE_WAIT);
            let mut t = tree.write().unwrap_or_else(|e| e.into_inner());
            for (&(i, id, k), (_, r)) in asked.iter().zip(got) {
                let f = &mut found[i];
                match r {
                    Ok(v) => {
                        t.learn_hash(id, k.ver, v.hash);
                        f.hash = Some(v.hash);
                        f.pending = None;
                    }
                    Err(_) => {
                        let index = t.index_id();
                        let fresh = t
                            .resolve(&f.path)
                            .and_then(|nid| t.get(nid).map(|n| (nid, n)))
                            .filter(|(_, n)| {
                                n.meta.kind == Kind::File && n.domain != GDomain::Local
                            })
                            .map(|(nid, n)| rule_file(nid, n, f.path.clone(), index));
                        match fresh {
                            Some(fresh) if fresh.pending.map(|p| p.1) != Some(k) => *f = fresh,
                            _ => f.pending = None,
                        }
                    }
                }
            }
        }
    }

    // uncached rule files come back in as few FetchMany round trips as possible
    fn prefetch_rules(core: &Core, todo: &[(RelPath, Hash32, u64)]) {
        let Some(remote) = core.cache.remote().current() else {
            return;
        };
        let mut batch: Vec<(RelPath, Want)> = Vec::new();
        let mut bytes = 0u64;
        let flush = |batch: &mut Vec<(RelPath, Want)>| {
            if batch.is_empty() {
                return;
            }
            let want: FxHashMap<RelPath, Hash32> = batch
                .iter()
                .filter_map(|(p, w)| match w {
                    Want::Hash(h) => Some((p.clone(), *h)),
                    Want::Ver(_) => None,
                })
                .collect();
            if let Ok(Reply::Blobs { items }) = remote.call(
                Op::FetchMany {
                    items: std::mem::take(batch),
                },
                Instant::now() + RULE_WAIT,
            ) {
                for (p, r) in items {
                    if let (Ok((got, b)), Some(h)) = (r, want.get(&p))
                        && got == *h
                    {
                        let _ = core.cache.insert_bytes(h, &b.0, Some(&p));
                    }
                }
            }
        };
        for (p, h, size) in todo {
            if *size == 0 || *size > RULE_BATCH_BYTES || core.cache.contains(h) {
                continue;
            }
            if bytes + size > RULE_BATCH_BYTES || batch.len() >= BATCH_MAX {
                flush(&mut batch);
                bytes = 0;
            }
            bytes += size;
            batch.push((p.clone(), Want::Hash(*h)));
        }
        flush(&mut batch);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const FORGEABLE: [Reject; 4] = [
            Reject::KeyMismatch,
            Reject::UnknownPeer,
            Reject::PairingDisabled,
            Reject::Refused,
        ];

        #[test]
        fn forged_rejects_never_end_the_reconnect_loop() {
            for r in FORGEABLE {
                assert!(matches!(
                    classify(NetError::Rejected(r), false),
                    Fail::Unverified
                ));
            }
            assert!(matches!(
                classify(
                    NetError::Handshake("handshake authentication failed"),
                    false
                ),
                Fail::Unverified
            ));
            assert!(matches!(
                classify(NetError::Rejected(Reject::RateLimited), false),
                Fail::Retry
            ));
        }

        #[test]
        fn forged_rejects_on_first_connect_are_reported_unverified_without_repair_advice() {
            for r in FORGEABLE {
                let Fail::Fatal(e) = classify(NetError::Rejected(r), true) else {
                    panic!("first-connect reject must be reported");
                };
                let msg = e.to_string();
                assert!(msg.starts_with("unverified response from host"), "{msg}");
                assert!(!msg.contains("repair") && !msg.contains("revoked"), "{msg}");
            }
            assert!(matches!(
                classify(NetError::Rejected(Reject::RateLimited), true),
                Fail::Retry
            ));
        }

        #[test]
        fn authenticated_key_mismatch_stays_fatal() {
            for first in [true, false] {
                assert!(matches!(
                    classify(NetError::KeyMismatch, first),
                    Fail::Fatal(_)
                ));
            }
        }

        use crate::proto::Meta;

        struct Dir(std::path::PathBuf);
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn pending_meta(size: u64) -> Meta {
            Meta {
                kind: Kind::File,
                perm: 0o644,
                size,
                mtime_ns: 0,
                ctime_ns: 0,
                hash: None,
                link: None,
                git_ro: false,
            }
        }

        fn upsert(name: &str, size: u64, ver: u64) -> Change {
            Change::Upsert {
                path: RelPath::new(name).unwrap(),
                meta: pending_meta(size),
                ver,
            }
        }

        fn hash_of(data: &[u8]) -> Hash32 {
            *blake3::hash(data).as_bytes()
        }

        // a host holding rule file contents by version; the first request also applies `bump` to the tree
        struct Host {
            files: Mutex<FxHashMap<u64, Vec<u8>>>,
            rounds: std::sync::atomic::AtomicUsize,
            tree: Arc<RwLock<GTree>>,
            bump: Mutex<Option<Change>>,
        }

        impl Remote for Host {
            fn call(&self, op: Op, _d: Instant) -> Result<Reply, crate::net::rpc::RpcError> {
                use crate::net::rpc::RpcError;
                self.rounds.fetch_add(1, Relaxed);
                if let Some(c) = lock(&self.bump).take() {
                    self.tree.write().unwrap().apply(&c, &mut Vec::new());
                }
                let Op::FetchMany { items } = op else {
                    return Err(RpcError::Closed);
                };
                let files = lock(&self.files);
                let items = items
                    .into_iter()
                    .map(|(p, w)| match w {
                        Want::Ver(k) => match files.get(&k.ver) {
                            Some(b) => (p, Ok((hash_of(b), crate::proto::Bytes(b.clone())))),
                            None => (p, Err(crate::proto::WireErr::Gone)),
                        },
                        Want::Hash(_) => (p, Err(crate::proto::WireErr::NotFound)),
                    })
                    .collect();
                Ok(Reply::Blobs { items })
            }
            fn call_stream(
                &self,
                _op: Op,
                _sink: Box<dyn crate::net::rpc::ChunkSink>,
                _d: Instant,
            ) -> Result<Reply, crate::net::rpc::RpcError> {
                Err(crate::net::rpc::RpcError::Closed)
            }
            fn submit(
                &self,
                _op: Op,
                _done: super::super::cache::Done,
            ) -> Result<crate::proto::ReqId, crate::net::rpc::RpcError> {
                Err(crate::net::rpc::RpcError::Closed)
            }
            fn submit_stream(
                &self,
                _op: Op,
                _sink: Box<dyn crate::net::rpc::ChunkSink>,
                _done: super::super::cache::Done,
            ) -> Result<crate::proto::ReqId, crate::net::rpc::RpcError> {
                Err(crate::net::rpc::RpcError::Closed)
            }
            fn send_chunk(
                &self,
                _id: crate::proto::ReqId,
                _off: u64,
                _last: bool,
                _data: Vec<u8>,
            ) -> Result<(), crate::net::rpc::RpcError> {
                Ok(())
            }
            fn cancel(&self, _id: crate::proto::ReqId) {}
        }

        struct Rig {
            cache: BlobCache,
            tree: Arc<RwLock<GTree>>,
            host: Arc<Host>,
            _dir: Dir,
        }

        fn rig(files: &[(u64, &[u8])], nodes: &[(&str, u64, u64)]) -> Rig {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let dir = Dir(std::env::temp_dir().join(format!(
                "csync-rules-{}-{}",
                std::process::id(),
                N.fetch_add(1, Relaxed)
            )));
            let _ = std::fs::remove_dir_all(&dir.0);
            let tree = Arc::new(RwLock::new(GTree::new()));
            {
                let mut t = tree.write().unwrap();
                for (name, size, ver) in nodes {
                    t.apply(&upsert(name, *size, *ver), &mut Vec::new());
                }
                t.set_version(9, 1);
            }
            let host = Arc::new(Host {
                files: Mutex::new(files.iter().map(|(v, b)| (*v, b.to_vec())).collect()),
                rounds: std::sync::atomic::AtomicUsize::new(0),
                tree: tree.clone(),
                bump: Mutex::new(None),
            });
            let slot = RemoteSlot::new();
            slot.set(Some(host.clone() as Arc<dyn Remote>));
            let cache = BlobCache::open(
                &CacheConfig {
                    dir: dir.0.clone(),
                    cap: Some(1 << 30),
                },
                slot,
            )
            .unwrap();
            Rig {
                cache,
                tree,
                host,
                _dir: dir,
            }
        }

        fn found_at(r: &Rig, name: &str) -> RuleFile {
            let t = r.tree.read().unwrap();
            let p = RelPath::new(name).unwrap();
            let id = t.resolve(&p).unwrap();
            rule_file(id, t.get(id).unwrap(), p, t.index_id())
        }

        #[test]
        fn a_pending_rule_file_carries_the_version_to_fetch_it_by() {
            let r = rig(&[], &[(".gitignore", 8, 5)]);
            let f = found_at(&r, ".gitignore");
            let k = f.pending.map(|(_, k)| k);
            assert_eq!(
                k,
                Some(VerKey {
                    index: 9,
                    ver: 5,
                    size: 8
                })
            );
            assert_eq!((f.hash, f.size), (None, 8));
            r.tree.write().unwrap().apply(
                &Change::Upsert {
                    path: RelPath::new(".gitignore").unwrap(),
                    meta: Meta {
                        hash: Some([3; 32]),
                        ..pending_meta(8)
                    },
                    ver: 6,
                },
                &mut Vec::new(),
            );
            let f = found_at(&r, ".gitignore");
            assert_eq!((f.pending, f.hash), (None, Some([3; 32])));
        }

        #[test]
        fn pending_rule_files_are_fetched_in_one_round_and_learned() {
            let (gi, ig) = (&b"target/\n"[..], &b"*.log\n"[..]);
            let r = rig(
                &[(5, gi), (6, ig)],
                &[
                    (".gitignore", gi.len() as u64, 5),
                    (".ignore", ig.len() as u64, 6),
                ],
            );
            let mut found = vec![found_at(&r, ".gitignore"), found_at(&r, ".ignore")];
            resolve_pending(&r.cache, &r.tree, &mut found);

            assert_eq!(r.host.rounds.load(Relaxed), 1);
            assert_eq!(found[0].hash, Some(hash_of(gi)));
            assert_eq!(found[1].hash, Some(hash_of(ig)));
            assert!(found.iter().all(|f| f.pending.is_none()));
            assert!(r.cache.contains(&hash_of(gi)) && r.cache.contains(&hash_of(ig)));
            let learned = found_at(&r, ".gitignore");
            assert_eq!(learned.hash, Some(hash_of(gi)));
        }

        #[test]
        fn a_rule_file_replaced_under_the_fetch_is_retried_at_its_new_version() {
            let new = &b"node_modules/\n"[..];
            let r = rig(&[(6, new)], &[(".gitignore", 8, 5)]);
            *lock(&r.host.bump) = Some(upsert(".gitignore", new.len() as u64, 6));
            let mut found = vec![found_at(&r, ".gitignore")];
            resolve_pending(&r.cache, &r.tree, &mut found);

            assert_eq!(r.host.rounds.load(Relaxed), 2);
            assert_eq!(found[0].hash, Some(hash_of(new)));
            assert_eq!(found_at(&r, ".gitignore").hash, Some(hash_of(new)));
        }

        #[test]
        fn an_unresolvable_rule_file_is_left_without_a_hash() {
            let r = rig(&[], &[(".gitignore", 8, 5)]);
            let mut found = vec![found_at(&r, ".gitignore")];
            resolve_pending(&r.cache, &r.tree, &mut found);

            assert_eq!(r.host.rounds.load(Relaxed), 1);
            assert_eq!((found[0].hash, found[0].pending), (None, None));
            assert!(found_at(&r, ".gitignore").pending.is_some());
        }

        #[test]
        fn a_pending_rule_file_over_the_text_limit_is_not_fetched() {
            let r = rig(&[], &[(".gitignore", TEXT_MAX as u64 + 1, 5)]);
            let mut found = vec![found_at(&r, ".gitignore")];
            resolve_pending(&r.cache, &r.tree, &mut found);
            assert_eq!(r.host.rounds.load(Relaxed), 0);
            assert!(found[0].hash.is_none());
        }
    }
}
