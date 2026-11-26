pub mod tree;

#[cfg(target_os = "linux")]
pub mod cache;
#[cfg(target_os = "linux")]
pub mod fs;
#[cfg(target_os = "linux")]
pub mod inject;
#[cfg(target_os = "linux")]
pub mod prefetch;
#[cfg(target_os = "linux")]
pub mod write;

#[cfg(target_os = "linux")]
pub use live::run;

#[cfg(target_os = "linux")]
mod live {
    use super::cache::{BlobCache, CacheConfig, Remote, RemoteSlot, lock};
    use super::fs::{self, Core, Counters, Mounted};
    use super::inject::{Injector, InjectorThread};
    use super::prefetch::{Hint, Prefetch, TreeView};
    use super::tree::{Effect, GDomain, GTree, NodeId, ROOT, Vis};
    use super::write::{NoticeFn, Writer};
    use crate::config::{GUEST_TREE_FILE, GuestCfg, ensure_private_dir};
    use crate::crypto::noise::Reject;
    use crate::crypto::trust::{Identity, PeerKey, TrustEntry, now_unix};
    use crate::ignore::rules::Rules;
    use crate::index::persist;
    use crate::net::conn::{self, CloseReason, Dial, In, Link, NetError, Session};
    use crate::net::rpc::Rpc;
    use crate::proto::{
        BATCH_MAX, Bye, Change, ExcludeSrc, Hash32, Hello, Kind, Msg, Name, Notice, NoticeKind, Op,
        PROTO, Push, RelPath, Reply, TEXT_MAX, Welcome,
        hs::{HsHello, PAIR_TIMEOUT_S, PairStep, Role},
    };
    use crate::tui::{ConnState, PeerView, UiBus, UiCmd, now_ms};
    use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, after, bounded, never, select};
    use rustc_hash::{FxHashMap, FxHashSet};
    use rustix::fs::{Mode, OFlags};
    use std::{
        collections::VecDeque,
        io,
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex, OnceLock, RwLock,
            atomic::{AtomicBool, Ordering::Relaxed},
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
    const SAVE_EVERY: Duration = Duration::from_secs(60);
    const UI_EVERY: Duration = Duration::from_millis(250);
    const PING_EVERY: Duration = Duration::from_secs(30);
    const RULE_JOBS: usize = 1_024;
    const RULE_WAIT: Duration = Duration::from_secs(30);
    // a FetchMany reply is one frame, so rule-file batches stay under FRAME_MAX
    const RULE_BATCH_BYTES: u64 = 3 << 20;
    const OVERLAY_DIR: &str = "overlay";
    const GIT_HINT: &str = "git on the guest: export GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=core.checkStat GIT_CONFIG_VALUE_0=minimal GIT_CONFIG_KEY_1=core.trustCtime GIT_CONFIG_VALUE_1=false";

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

    fn load_tree(path: &Path) -> GTree {
        let mut t = GTree::new();
        if let Some((index, seq, entries)) = persist::load_guest_tree(path) {
            let mut fx = Vec::new();
            if t.apply_snapshot_part(&entries, true, &mut fx).is_ok() {
                t.set_version(index, seq);
            } else {
                t = GTree::new();
            }
        }
        t
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
        let state = cfg.dirs.host_state_dir(&key);
        ensure_private_dir(&state)?;
        let overlay_path = state.join(OVERLAY_DIR);
        ensure_private_dir(&overlay_path)?;
        let tree_path = state.join(GUEST_TREE_FILE);
        let tree = Arc::new(RwLock::new(load_tree(&tree_path)));
        let remote = RemoteSlot::new();
        let cache = Arc::new(BlobCache::open(
            &CacheConfig {
                dir: cfg.dirs.blob_cache_dir(&key),
                cap: Some(cfg.cache_cap),
            },
            remote.clone(),
        )?);
        let link_slot: Arc<Mutex<Option<Link>>> = Arc::new(Mutex::new(None));
        let ctr = Arc::new(Counters::default());
        let notice = notice_fn(bus.clone(), link_slot.clone(), ctr.clone());
        let writer = Writer::new(cache.clone(), notice.clone());
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
            overlay,
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            ctr,
            kicked: Mutex::new(Vec::new()),
            kick: kick_tx,
            case_fold: AtomicBool::new(false),
            passthrough: AtomicBool::new(false),
            notice,
        });
        let rules = Arc::new(RuleState::default());
        let (rules_tx, rules_rx) = bounded(RULE_JOBS);
        let rules_join = {
            let (c, st) = (core.clone(), rules.clone());
            thread::Builder::new()
                .name("csync-rules".into())
                .spawn(move || rules_worker(&c, &st, &rules_rx))?
        };
        let (dial_tx, dial_rx) = bounded(1);
        let host_name = sess.hello.name.clone();
        let mut g = Guest {
            bus,
            cmds,
            core,
            remote,
            key,
            host_name,
            tree_path,
            link_slot,
            link: None,
            rpc: None,
            inbox: never(),
            mounted: None,
            inj: None,
            back: never(),
            kick_rx,
            rules,
            rules_tx: Some(rules_tx),
            rules_join: Some(rules_join),
            dial_tx,
            dial_rx,
            dial_stop: Arc::new(AtomicBool::new(false)),
            dialing: false,
            synced: false,
            snap_next: None,
            synced_entries: 0,
            dirty: false,
            last_save: Instant::now(),
            last_ui: Instant::now(),
            ui_due: None,
            last_ping: Instant::now(),
            rtt_us: 0,
            skew_ms: 0,
            work: VecDeque::new(),
            seen: FxHashSet::default(),
            rule_paths: Vec::new(),
            bye: CloseReason::Local,
            cfg,
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
        g.shutdown();
        res
    }

    struct Guest {
        cfg: GuestCfg,
        bus: Arc<UiBus>,
        cmds: Receiver<UiCmd>,
        core: Arc<Core>,
        remote: Arc<RemoteSlot>,
        key: PeerKey,
        host_name: Name,
        tree_path: PathBuf,
        link_slot: Arc<Mutex<Option<Link>>>,
        link: Option<Link>,
        rpc: Option<Arc<Rpc>>,
        inbox: Receiver<In>,
        mounted: Option<Mounted>,
        inj: Option<InjectorThread>,
        back: Receiver<Vec<Effect>>,
        kick_rx: Receiver<()>,
        rules: Arc<RuleState>,
        rules_tx: Option<Sender<RuleJob>>,
        rules_join: Option<JoinHandle<()>>,
        dial_tx: Sender<Result<(Session, Welcome), Fail>>,
        dial_rx: Receiver<Result<(Session, Welcome), Fail>>,
        dial_stop: Arc<AtomicBool>,
        dialing: bool,
        synced: bool,
        snap_next: Option<u32>,
        synced_entries: u64,
        dirty: bool,
        last_save: Instant,
        last_ui: Instant,
        ui_due: Option<Instant>,
        last_ping: Instant,
        rtt_us: u32,
        skew_ms: i64,
        work: VecDeque<Effect>,
        seen: FxHashSet<NodeId>,
        rule_paths: Vec<RelPath>,
        // what the host is told when the link closes at shutdown
        bye: CloseReason,
    }

    fn earliest(a: Option<Instant>, b: Instant) -> Option<Instant> {
        Some(a.map_or(b, |a| a.min(b)))
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

        // nothing wakes this thread unless there is pending ui, an unsaved tree or a live link to ping
        fn timer(&self) -> Receiver<Instant> {
            let mut due = self.ui_due;
            if self.dirty && self.snap_next.is_none() {
                due = earliest(due, self.last_save + SAVE_EVERY);
            }
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
            if self.dirty && self.snap_next.is_none() && now >= self.last_save + SAVE_EVERY {
                self.save_tree();
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
            let project = w.project.clone();
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
            let m = match &self.rpc {
                Some(r) => r.dispatch(i),
                None => match i {
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
                    {
                        let mut t = self.core.tw();
                        for c in &changes {
                            t.apply(c, &mut fx);
                        }
                        let index = t.index_id();
                        t.set_version(index, seq);
                    }
                    {
                        let r = self.core.rules();
                        for c in &changes {
                            match c {
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
                    self.queue(fx);
                    self.synced(seq, false)?;
                }
                Push::Notice(n) => self.bus.update(|s| s.push_notice(now_ms(), n)),
            }
            Ok(())
        }

        // a batch is fully applied: ack it, refresh ignore rules, and mount on the first one
        fn synced(&mut self, seq: u64, snapshot: bool) -> io::Result<()> {
            if let Some(l) = &self.link {
                let _ = l.send(Msg::Ack { seq });
            }
            self.dirty = true;
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
            if let Some(tx) = &self.rules_tx
                && tx.try_send(j).is_err()
            {
                let _ = tx.try_send(RuleJob::Scan);
            }
        }

        fn mount(&mut self) -> io::Result<()> {
            let m = fs::mount(self.core.clone(), &self.cfg.mount, self.cfg.allow_other)?;
            let (inj, thread, back) = Injector::start(&self.cfg.mount, self.core.tree.clone())?;
            let _ = self.core.inj.set(inj);
            self.inj = Some(thread);
            self.back = back;
            self.core.tw().set_mounted(true);
            self.mounted = Some(m);
            self.synced = true;
            self.core.prefetch.hint(Hint::Start);
            self.bus.update(|s| {
                s.mounted = true;
                s.hint(GIT_HINT);
            });
            Ok(())
        }

        fn queue(&mut self, fx: Vec<Effect>) {
            if fx.is_empty() {
                return;
            }
            self.work.extend(fx);
            self.drain();
        }

        // the only place kernel notifications are sent; the tree lock is never held here
        fn drain(&mut self) {
            self.seen.clear();
            while let Some(e) = self.work.pop_front() {
                match e {
                    Effect::InvalInode(id) => {
                        if self.seen.insert(id)
                            && let Some(m) = &self.mounted
                        {
                            m.inval_inode(id);
                        }
                    }
                    Effect::InvalEntry(p, n) => {
                        if let Some(m) = &self.mounted {
                            m.inval_entry(p, &n);
                        }
                    }
                    Effect::Synth(s) => {
                        if !self.core.inj.get().is_some_and(|i| i.offer(s.clone())) {
                            let mut more = Vec::new();
                            self.core.tw().settle(&s, &mut more);
                            self.work.extend(more);
                        }
                    }
                    Effect::Warm(id, h) => self.core.prefetch.hint(Hint::Warm(id, h)),
                    Effect::ConflictPending(id) => {
                        let h = self.core.t().get(id).and_then(|n| n.meta.hash);
                        if let Some(h) = h {
                            self.core.prefetch.hint(Hint::Warm(id, h));
                        }
                    }
                    // read_ver blobs are protected by the cache's open-time window, not by pins
                    Effect::Unpin(_) => {}
                    Effect::LocalDiscarded(p) => {
                        self.core.remove_overlay(&p);
                        (self.core.notice)(Notice {
                            kind: NoticeKind::Discarded,
                            path: p,
                        });
                    }
                }
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
            self.bus.update(|s| {
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

        fn save_tree(&mut self) {
            self.last_save = Instant::now();
            if self.snap_next.is_some() {
                return;
            }
            let (index, seq, entries) = {
                let t = self.core.t();
                let mut v = Vec::with_capacity(usize::try_from(t.files()).unwrap_or(0));
                t.export(&mut |e| v.push(e));
                (t.index_id(), t.seq(), v)
            };
            if index != 0 && persist::save_guest_tree(&self.tree_path, index, seq, &entries).is_ok()
            {
                self.dirty = false;
            }
        }

        // the injector stops before the unmount; the link closes after it so final commits can land
        fn shutdown(&mut self) {
            self.dial_stop.store(true, Relaxed);
            if let Some(t) = self.inj.take() {
                t.stop();
            }
            self.core.tw().set_mounted(false);
            if let Some(m) = self.mounted.take() {
                let _ = m.unmount();
            }
            self.bus.update(|s| s.mounted = false);
            if let Some(l) = self.link.take() {
                l.close(self.bye.clone());
            }
            *lock(&self.link_slot) = None;
            self.remote.set(None);
            self.core.prefetch.stop();
            self.rules_tx = None;
            if let Some(j) = self.rules_join.take() {
                let _ = j.join();
            }
            if self.dirty {
                self.save_tree();
            }
            let _ = self.core.cache.save();
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
    }

    fn rules_worker(core: &Core, st: &RuleState, rx: &Receiver<RuleJob>) {
        while let Ok(j) = rx.recv() {
            let mut scan = false;
            let mut paths = Vec::new();
            for j in std::iter::once(j).chain(rx.try_iter()) {
                match j {
                    RuleJob::Scan => scan = true,
                    RuleJob::Paths(p) => paths.extend(p),
                }
            }
            if scan {
                rules_scan(core, st);
            } else {
                rules_paths(core, st, paths);
            }
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

    // every rule file in the host tree; inside .git only the gitdir and its info directory are walked
    fn collect_rule_files(core: &Core) -> Vec<(RelPath, Option<Hash32>, u64)> {
        let t = core.t();
        let rules = core.rules();
        let mut out = Vec::new();
        let mut stack: Vec<(NodeId, RelPath)> = vec![(ROOT, RelPath::root())];
        while let Some((d, path)) = stack.pop() {
            let Some(kids) = t.get(d).and_then(|n| n.children.as_ref()) else {
                continue;
            };
            for (name, &c) in kids {
                let Some(n) = t.get(c) else { continue };
                if n.domain == GDomain::Local || n.vis == Vis::PendingDelete {
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
                    out.push((p, n.meta.hash, n.meta.size));
                }
            }
        }
        out
    }

    fn rules_scan(core: &Core, st: &RuleState) {
        let found = collect_rule_files(core);
        let gone: Vec<RelPath> = {
            let k = lock(&st.known);
            k.keys()
                .filter(|p| !found.iter().any(|(f, _, _)| f == *p))
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
        promote_all(core, scopes);
    }

    fn rules_paths(core: &Core, st: &RuleState, paths: Vec<RelPath>) {
        let mut found = Vec::new();
        let mut scopes = Vec::new();
        for p in paths {
            let cur = {
                let t = core.t();
                t.resolve(&p)
                    .and_then(|id| t.get(id))
                    .filter(|n| n.meta.kind == Kind::File && n.domain != GDomain::Local)
                    .map(|n| (n.meta.hash, n.meta.size))
            };
            match cur {
                Some((h, size)) => found.push((p, h, size)),
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
        found: Vec<(RelPath, Option<Hash32>, u64)>,
        scopes: &mut Vec<RelPath>,
    ) {
        let todo: Vec<(RelPath, Hash32, u64)> = {
            let k = lock(&st.known);
            found
                .into_iter()
                .filter_map(|(p, h, size)| {
                    let h = h?;
                    (size <= TEXT_MAX as u64 && k.get(&p).is_none_or(|(kh, _)| *kh != h))
                        .then_some((p, h, size))
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

    // uncached rule files come back in as few FetchMany round trips as possible
    fn prefetch_rules(core: &Core, todo: &[(RelPath, Hash32, u64)]) {
        let Some(remote) = core.cache.remote().current() else {
            return;
        };
        let mut batch: Vec<(RelPath, Hash32)> = Vec::new();
        let mut bytes = 0u64;
        let flush = |batch: &mut Vec<(RelPath, Hash32)>| {
            if batch.is_empty() {
                return;
            }
            let want: FxHashMap<RelPath, Hash32> = batch.iter().cloned().collect();
            if let Ok(Reply::Blobs { items }) = remote.call(
                Op::FetchMany {
                    items: std::mem::take(batch),
                },
                Instant::now() + RULE_WAIT,
            ) {
                for (p, r) in items {
                    if let (Ok(b), Some(h)) = (r, want.get(&p)) {
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
            batch.push((p.clone(), *h));
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
    }
}
