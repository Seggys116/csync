use crate::crypto::noise::{self, Established, Gate, HsError, Opener, Reject, Sealer};
use crate::crypto::trust::{Identity, PeerKey, Trust, TrustEntry};
use crate::net::rpc::Rpc;
use crate::proto::{
    BATCH_MAX, Body, Bye, CHUNK_MAX, Change, FILE_MAX, FRAME_MAX, INFLIGHT_MAX, Meta, Msg, Name,
    Op, PROTO, Push, RANGE_UNIT, Reply, ReqId, SIGS_MAX, Seq, TEXT_MAX, UNACKED_PUSH_MAX,
    frame::{Decoder, Encoder, Frame, FrameError, NOISE_MAX},
    hs::{HsHello, HsMode, Role},
};
use crossbeam_channel::{Receiver, Select, Sender, TryRecvError, bounded};
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, TryLockError, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CTL_CAP: usize = 1_024;
const BULK_CAP: usize = 512;
const INBOX_CAP: usize = 4_096;
const BATCH_BYTES: usize = 1 << 20;
const SOCK_BUF: usize = 4 << 20;
const RD_BUF: usize = 1 << 20;
const KEEPALIVE: Duration = Duration::from_secs(15);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const HS_TIMEOUT: Duration = Duration::from_secs(10);
const HS_FIRST_BYTE: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const DELIVER_TIMEOUT: Duration = Duration::from_secs(10);
const HS_CONCURRENT_MAX: usize = 16;
const HS_PER_IP_MAX: usize = 4;
const ACCEPT_QUEUE: usize = 16;
const HS_PER_MIN: f64 = 20.0;
const PAIR_PER_IP_HOUR: f64 = 5.0;
const PAIR_ALL_HOUR: f64 = 20.0;
const LIMIT_TABLE_MAX: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prio {
    Ctl,
    Bulk,
}
pub enum Out {
    Msg(Prio, Msg),
    Chunk {
        id: ReqId,
        off: u64,
        last: bool,
        data: Vec<u8>,
    },
}
pub enum In {
    Msg(Msg),
    Chunk {
        id: ReqId,
        off: u64,
        last: bool,
        data: Vec<u8>,
    },
    Closed(CloseReason),
}

#[derive(Clone, Debug)]
pub enum CloseReason {
    Eof,
    Io(io::ErrorKind),
    Protocol(&'static str),
    Revoked,
    Local,
}
#[derive(Debug)]
pub struct Closed;
#[derive(Debug)]
pub enum NetError {
    Io(io::Error),
    Handshake(&'static str),
    // a plaintext reject frame: anyone on the path can forge one, so it is never authoritative
    Rejected(Reject),
    UnknownPeer,
    // the authenticated handshake proved the peer's key differs from the pinned one
    KeyMismatch,
    RateLimited,
    PairingLimited,
}

#[derive(Debug)]
pub enum PushError {
    Full(Push),
    Closed,
}

// a message that could not be queued without waiting: the bulk queue is full or the link is closed
#[derive(Debug, PartialEq, Eq)]
pub struct Full;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn try_lock<T>(m: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match m.try_lock() {
        Ok(g) => Some(g),
        Err(TryLockError::Poisoned(e)) => Some(e.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

struct Shared {
    closed: AtomicBool,
    reason: Mutex<Option<CloseReason>>,
    peer_inflight: AtomicUsize,
    unacked: Mutex<VecDeque<Seq>>,
    router: OnceLock<Weak<Rpc>>,
}

impl Shared {
    fn set_reason(&self, r: CloseReason) -> CloseReason {
        lock(&self.reason).get_or_insert(r).clone()
    }

    fn router(&self) -> Option<Arc<Rpc>> {
        self.router.get().and_then(Weak::upgrade)
    }
}

#[derive(Clone)]
struct Signal {
    ctl: Sender<Out>,
    stop: Sender<()>,
    shared: Arc<Shared>,
}

impl Signal {
    fn close(&self, why: CloseReason, say_bye: bool) {
        let first = !self.shared.closed.swap(true, Ordering::AcqRel);
        let why = self.shared.set_reason(why);
        if first && say_bye {
            let bye = match why {
                CloseReason::Local => Some(Bye::Shutdown),
                CloseReason::Revoked => Some(Bye::Revoked),
                CloseReason::Protocol(_) => Some(Bye::Limit),
                CloseReason::Eof | CloseReason::Io(_) => None,
            };
            if let Some(b) = bye {
                let _ = self.ctl.try_send(Out::Msg(Prio::Ctl, Msg::Bye(b)));
            }
        }
        let _ = self.stop.try_send(());
    }
}

struct LinkInner {
    sig: Signal,
    bulk: Sender<Out>,
    peer: PeerKey,
    tx: Arc<Mutex<Tx>>,
    kick: Sender<()>,
}

impl LinkInner {
    // a control message with nothing queued ahead of it is written by the caller, saving the writer thread's wakeup
    fn direct(&self, mut g: MutexGuard<'_, Tx>, o: Out) -> Result<(), Closed> {
        let t = &mut *g;
        t.begin();
        if let Err(e) = t.put(o, &self.sig.shared).and_then(|()| t.seal(true)) {
            let _ = t.sock.shutdown(Shutdown::Both);
            drop(g);
            self.sig.close(CloseReason::Protocol(e), false);
            return Err(Closed);
        }
        let mut done = 0;
        while done < t.out.len() {
            match SockRef::from(&t.sock).send_with_flags(&t.out[done..], SEND_NOWAIT) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    let _ = t.sock.shutdown(Shutdown::Both);
                    drop(g);
                    self.sig.close(CloseReason::Io(e.kind()), false);
                    return Err(Closed);
                }
            }
        }
        if done < t.out.len() {
            t.spill.extend_from_slice(&t.out[done..]);
            let _ = self.kick.try_send(());
        }
        t.trim();
        Ok(())
    }
}

impl Drop for LinkInner {
    fn drop(&mut self) {
        self.sig.close(CloseReason::Local, true);
    }
}

#[derive(Clone)]
pub struct Link {
    inner: Arc<LinkInner>,
}

fn prio_of(m: &Msg) -> Prio {
    match m {
        Msg::Resp {
            res: Ok(Reply::Blob { .. } | Reply::Blobs { .. }),
            ..
        } => Prio::Bulk,
        _ => Prio::Ctl,
    }
}

impl Link {
    pub fn peer(&self) -> PeerKey {
        self.inner.peer
    }

    pub fn send(&self, m: Msg) -> Result<(), Closed> {
        let p = prio_of(&m);
        self.send_out(Out::Msg(p, m))
    }

    pub fn send_out(&self, o: Out) -> Result<(), Closed> {
        if self.is_closed() {
            return Err(Closed);
        }
        let inner = &*self.inner;
        // the writer only dequeues while holding tx, so an empty control queue under tx means nothing is ahead;
        // pushes stay queued since they are sent under the host's tree lock
        if matches!(&o, Out::Msg(Prio::Ctl, m) if !matches!(m, Msg::Push(_)))
            && inner.sig.ctl.is_empty()
            && let Some(g) = try_lock(&inner.tx)
            && g.spill.is_empty()
            && inner.sig.ctl.is_empty()
        {
            return inner.direct(g, o);
        }
        let q = match &o {
            Out::Msg(Prio::Ctl, _) => &self.inner.sig.ctl,
            _ => &self.inner.bulk,
        };
        q.send(o).map_err(|_| Closed)
    }

    pub fn close(&self, why: CloseReason) {
        self.inner.sig.close(why, true);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.sig.shared.closed.load(Ordering::Acquire)
    }

    pub fn try_push(&self, p: Push) -> Result<(), PushError> {
        if self.is_closed() {
            return Err(PushError::Closed);
        }
        if let Push::Changes { seq, .. } = &p {
            let mut u = lock(&self.inner.sig.shared.unacked);
            if u.len() >= UNACKED_PUSH_MAX {
                return Err(PushError::Full(p));
            }
            u.push_back(*seq);
        }
        self.send(Msg::Push(p)).map_err(|_| PushError::Closed)
    }

    // queues behind file data and never waits, so the caller may drop what is not essential
    pub fn try_send_bulk(&self, m: Msg) -> Result<(), Full> {
        if self.is_closed() {
            return Err(Full);
        }
        self.inner
            .bulk
            .try_send(Out::Msg(Prio::Bulk, m))
            .map_err(|_| Full)
    }

    pub fn unacked_pushes(&self) -> usize {
        lock(&self.inner.sig.shared.unacked).len()
    }

    pub fn bulk_backlog(&self) -> usize {
        self.inner.bulk.len()
    }

    pub(crate) fn attach_router(&self, rpc: &Arc<Rpc>) -> bool {
        self.inner
            .sig
            .shared
            .router
            .set(Arc::downgrade(rpc))
            .is_ok()
    }
}

pub struct Session {
    pub link: Link,
    pub inbox: Receiver<In>,
    pub hello: HsHello,
    pub sas: Option<[u8; 8]>,
}
pub enum Dial {
    Pair,
    Resume(PeerKey),
}
pub enum Incoming {
    Known(Session, TrustEntry),
    Pairing(Session),
}

fn tune(s: &TcpStream) -> io::Result<()> {
    s.set_nodelay(true)?;
    SockRef::from(s).set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(KEEPALIVE)
            .with_interval(KEEPALIVE_INTERVAL),
    )
}

fn new_socket(addr: &SocketAddr) -> io::Result<Socket> {
    let s = Socket::new(
        Domain::for_address(*addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    // buffers must be sized before connect/listen for the window scale to take effect
    let _ = s.set_send_buffer_size(SOCK_BUF);
    let _ = s.set_recv_buffer_size(SOCK_BUF);
    Ok(s)
}

fn start(stream: TcpStream, est: Established, hello: HsHello) -> io::Result<Session> {
    tune(&stream)?;
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let sas = (est.mode == HsMode::Pair).then(|| est.sas());
    let peer = est.remote;
    let (sealer, opener) = est.split();
    let (ctl_tx, ctl_rx) = bounded(CTL_CAP);
    let (bulk_tx, bulk_rx) = bounded(BULK_CAP);
    let (stop_tx, stop_rx) = bounded(1);
    let (in_tx, in_rx) = bounded(INBOX_CAP);
    let shared = Arc::new(Shared {
        closed: AtomicBool::new(false),
        reason: Mutex::new(None),
        peer_inflight: AtomicUsize::new(0),
        unacked: Mutex::new(VecDeque::new()),
        router: OnceLock::new(),
    });
    let sig = Signal {
        ctl: ctl_tx,
        stop: stop_tx,
        shared: shared.clone(),
    };
    let (kick_tx, kick_rx) = bounded(1);
    let tx = Arc::new(Mutex::new(Tx::new(stream.try_clone()?, sealer)));
    let w = Writer {
        tx: tx.clone(),
        ctl: ctl_rx,
        bulk: bulk_rx,
        stop: stop_rx,
        kick: kick_rx,
        shared,
    };
    thread::Builder::new()
        .name("csync-net-wr".into())
        .spawn(move || w.run())?;
    let r = Reader {
        sock: stream,
        opener,
        inbox: in_tx,
        sig: sig.clone(),
    };
    if let Err(e) = thread::Builder::new()
        .name("csync-net-rd".into())
        .spawn(move || r.run())
    {
        sig.close(CloseReason::Local, false);
        return Err(e);
    }
    let link = Link {
        inner: Arc::new(LinkInner {
            sig,
            bulk: bulk_tx,
            peer,
            tx,
            kick: kick_tx,
        }),
    };
    Ok(Session {
        link,
        inbox: in_rx,
        hello,
        sas,
    })
}

fn seal_with(
    sealer: &mut Sealer,
    out: &mut Vec<u8>,
    f: impl FnOnce(&mut dyn FnMut(&[u8])) -> Result<(), FrameError>,
) -> Result<(), &'static str> {
    let mut bad = false;
    let r = {
        let mut emit = |seg: &[u8]| {
            if !bad && sealer.seal(seg, out).is_err() {
                bad = true;
            }
        };
        f(&mut emit)
    };
    if r.is_err() {
        return Err("frame encode failed");
    }
    if bad {
        return Err("seal failed");
    }
    Ok(())
}

// the sending half; whoever holds it frames, seals and writes, so frames leave in the order they were taken
struct Tx {
    sock: TcpStream,
    sealer: Sealer,
    enc: Encoder,
    out: Vec<u8>,
    // a batch is framed into plain first and sealed in one go, so a large one is sealed on all cores
    plain: Vec<u8>,
    spans: Vec<(usize, usize)>,
    // what a caller could not hand to a full socket; the writer thread sends it before anything else
    spill: Vec<u8>,
}

impl Tx {
    fn new(sock: TcpStream, sealer: Sealer) -> Self {
        Self {
            sock,
            sealer,
            enc: Encoder::default(),
            out: Vec::with_capacity(BATCH_BYTES + NOISE_MAX + 2),
            plain: Vec::with_capacity(BATCH_BYTES + NOISE_MAX),
            spans: Vec::new(),
            spill: Vec::new(),
        }
    }

    fn begin(&mut self) {
        self.out.clear();
        self.plain.clear();
        self.spans.clear();
    }

    fn put(&mut self, o: Out, shared: &Shared) -> Result<(), &'static str> {
        let (plain, spans) = (&mut self.plain, &mut self.spans);
        let mut emit = |seg: &[u8]| {
            spans.push((plain.len(), seg.len()));
            plain.extend_from_slice(seg);
        };
        match o {
            // rekeys are only emitted by seal, in step with sealer.rekey()
            Out::Msg(_, Msg::Rekey) => Ok(()),
            Out::Msg(_, m) => {
                if matches!(m, Msg::Resp { .. }) {
                    // saturating decrement; try_update is past the msrv and fetch_update is deprecated
                    let inflight = &shared.peer_inflight;
                    let mut cur = inflight.load(Ordering::Acquire);
                    while let Some(next) = cur.checked_sub(1) {
                        match inflight.compare_exchange_weak(
                            cur,
                            next,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => break,
                            Err(seen) => cur = seen,
                        }
                    }
                }
                self.enc
                    .msg(&m, &mut emit)
                    .map_err(|_| "frame encode failed")
            }
            Out::Chunk {
                id,
                off,
                last,
                data,
            } => {
                if data.len() > CHUNK_MAX {
                    return Err("chunk too large");
                }
                self.enc
                    .chunk(id, off, last, &data, &mut emit)
                    .map_err(|_| "frame encode failed")
            }
        }
    }

    fn seal(&mut self, rekey: bool) -> Result<(), &'static str> {
        self.sealer
            .seal_many(&self.plain, &self.spans, &mut self.out)
            .map_err(|_| "seal failed")?;
        if rekey && self.sealer.rekey_due() {
            let enc = &mut self.enc;
            seal_with(&mut self.sealer, &mut self.out, |e| enc.msg(&Msg::Rekey, e))?;
            self.sealer.rekey();
        }
        Ok(())
    }

    fn trim(&mut self) {
        if self.out.capacity() > 2 * (BATCH_BYTES + NOISE_MAX) {
            self.out = Vec::with_capacity(BATCH_BYTES + NOISE_MAX + 2);
        }
        if self.plain.capacity() > 2 * (BATCH_BYTES + NOISE_MAX) {
            self.plain = Vec::with_capacity(BATCH_BYTES + NOISE_MAX);
        }
        if self.spill.capacity() > 2 * (BATCH_BYTES + NOISE_MAX) && self.spill.is_empty() {
            self.spill = Vec::new();
        }
    }
}

#[cfg(target_os = "linux")]
const SEND_NOWAIT: i32 = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_NOWAIT: i32 = libc::MSG_DONTWAIT;

struct Writer {
    tx: Arc<Mutex<Tx>>,
    ctl: Receiver<Out>,
    bulk: Receiver<Out>,
    stop: Receiver<()>,
    kick: Receiver<()>,
    shared: Arc<Shared>,
}

impl Writer {
    fn run(self) {
        let Writer {
            tx,
            ctl,
            bulk,
            stop,
            kick,
            shared,
        } = self;
        // nothing is taken off a queue until the sending half is held, so a caller writing directly never overtakes it
        let mut sel = Select::new();
        sel.recv(&stop);
        sel.recv(&ctl);
        sel.recv(&bulk);
        sel.recv(&kick);
        let why = loop {
            sel.ready();
            let mut stopping = stop.try_recv().is_ok();
            let _ = kick.try_recv();
            let mut g = lock(&tx);
            let t = &mut *g;
            if !t.spill.is_empty() {
                if let Err(e) = t.sock.write_all(&t.spill) {
                    break Some(CloseReason::Io(e.kind()));
                }
                t.spill.clear();
            }
            t.begin();
            let mut res = Ok(());
            while res.is_ok() && t.plain.len() < BATCH_BYTES {
                match ctl.try_recv() {
                    Ok(o) => {
                        res = t.put(o, &shared);
                        continue;
                    }
                    Err(TryRecvError::Disconnected) => stopping = true,
                    Err(TryRecvError::Empty) => {}
                }
                if stopping {
                    break;
                }
                match bulk.try_recv() {
                    Ok(o) => res = t.put(o, &shared),
                    Err(TryRecvError::Disconnected) => stopping = true,
                    Err(TryRecvError::Empty) => break,
                }
            }
            if let Err(e) = res.and_then(|()| t.seal(!stopping)) {
                break Some(CloseReason::Protocol(e));
            }
            if !t.out.is_empty()
                && let Err(e) = t.sock.write_all(&t.out)
            {
                break Some(CloseReason::Io(e.kind()));
            }
            t.trim();
            drop(g);
            if stopping {
                break None;
            }
        };
        if let Some(w) = why {
            shared.set_reason(w);
        }
        shared.closed.store(true, Ordering::Release);
        let _ = lock(&tx).sock.shutdown(Shutdown::Both);
    }
}

struct Reader {
    sock: TcpStream,
    opener: Opener,
    inbox: Sender<In>,
    sig: Signal,
}

fn io_reason(e: &io::Error) -> CloseReason {
    match e.kind() {
        io::ErrorKind::UnexpectedEof => CloseReason::Eof,
        k => CloseReason::Io(k),
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

impl Reader {
    fn run(self) {
        let Reader {
            sock,
            mut opener,
            inbox,
            sig,
        } = self;
        // every segment that has fully arrived is opened as one run, so a backlog is opened on all cores
        let mut rb = vec![0u8; RD_BUF];
        let (mut lo, mut hi) = (0usize, 0usize);
        let mut arena: Vec<u8> = Vec::new();
        let mut cts: Vec<(usize, usize)> = Vec::new();
        let mut res = Vec::new();
        let mut dec = Decoder::default();
        let why = 'run: loop {
            cts.clear();
            let mut p = lo;
            let mut empty = false;
            while hi - p >= 2 {
                let n = u16::from_be_bytes([rb[p], rb[p + 1]]) as usize;
                if n == 0 {
                    empty = true;
                    break;
                }
                if hi - p - 2 < n {
                    break;
                }
                cts.push((p + 2, n));
                p += 2 + n;
            }
            if cts.is_empty() {
                if empty {
                    break CloseReason::Protocol("empty segment");
                }
                if lo > 0 {
                    rb.copy_within(lo..hi, 0);
                    hi -= lo;
                    lo = 0;
                }
                match (&sock).read(&mut rb[hi..]) {
                    Ok(0) => break CloseReason::Eof,
                    Ok(k) => hi += k,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => break io_reason(&e),
                }
                continue;
            }
            let total: usize = cts.iter().map(|c| c.1).sum();
            if arena.len() < total {
                arena.resize(total, 0);
            }
            let base = {
                let refs: Vec<&[u8]> = cts.iter().map(|&(a, n)| &rb[a..a + n]).collect();
                let mut outs = Vec::with_capacity(cts.len());
                let mut rest = &mut arena[..total];
                for &(_, n) in &cts {
                    let (o, t) = rest.split_at_mut(n);
                    outs.push(o);
                    rest = t;
                }
                match opener.open_many(&refs, outs, &mut res) {
                    Ok(b) => b,
                    Err(_) => break CloseReason::Protocol("segment failed authentication"),
                }
            };
            let epoch = opener.epoch();
            let mut at = 0usize;
            for (i, &(a, n)) in cts.iter().enumerate() {
                let slot = at;
                at += n;
                let opened = if opener.epoch() == epoch {
                    res[i]
                } else {
                    opener.open_at(base + i as u64, &rb[a..a + n], &mut arena[slot..slot + n])
                };
                let Ok(m) = opened else {
                    break 'run CloseReason::Protocol("segment failed authentication");
                };
                if sig.shared.closed.load(Ordering::Acquire) {
                    break 'run CloseReason::Local;
                }
                let frame = match dec.push(&arena[slot..slot + m]) {
                    Ok(Some(f)) => f,
                    Ok(None) => continue,
                    Err(_) => break 'run CloseReason::Protocol("bad frame"),
                };
                match frame {
                    Frame::Msg(msg) => {
                        if let Some(why) = on_msg(msg, &mut opener, &inbox, &sig) {
                            break 'run why;
                        }
                    }
                    Frame::Chunk {
                        id,
                        off,
                        last,
                        data,
                    } => {
                        if data.len() > CHUNK_MAX {
                            break 'run CloseReason::Protocol("chunk too large");
                        }
                        let handled = sig
                            .shared
                            .router()
                            .is_some_and(|r| r.route_chunk(id, off, last, data));
                        if !handled {
                            let _ = inbox.send(In::Chunk {
                                id,
                                off,
                                last,
                                data: data.to_vec(),
                            });
                        }
                    }
                }
            }
            lo = p;
            if lo == hi {
                lo = 0;
                hi = 0;
            }
        };
        let protocol = matches!(why, CloseReason::Protocol(_));
        sig.close(why.clone(), protocol);
        let why = lock(&sig.shared.reason).clone().unwrap_or(why);
        if let Some(r) = sig.shared.router() {
            r.fail_all();
        }
        let _ = inbox.send(In::Closed(why));
    }
}

fn on_msg(msg: Msg, opener: &mut Opener, inbox: &Sender<In>, sig: &Signal) -> Option<CloseReason> {
    if let Err(e) = check_msg(&msg) {
        return Some(CloseReason::Protocol(e));
    }
    let sh = &sig.shared;
    match msg {
        Msg::Ping { t_ns } => {
            let _ = sig.ctl.try_send(Out::Msg(
                Prio::Ctl,
                Msg::Pong {
                    t_ns,
                    host_ns: now_ns(),
                },
            ));
        }
        Msg::Rekey => opener.rekey(),
        Msg::Resp { id, res } => {
            let res = match sh.router() {
                Some(r) => r.on_resp(id, res),
                None => Some(res),
            };
            if let Some(res) = res {
                let _ = inbox.send(In::Msg(Msg::Resp { id, res }));
            }
        }
        Msg::Req { id, op } => {
            if sh.peer_inflight.fetch_add(1, Ordering::AcqRel) >= INFLIGHT_MAX {
                return Some(CloseReason::Protocol("too many requests in flight"));
            }
            let _ = inbox.send(In::Msg(Msg::Req { id, op }));
        }
        Msg::Ack { seq } => {
            {
                let mut u = lock(&sh.unacked);
                while u.front().is_some_and(|&s| s <= seq) {
                    u.pop_front();
                }
            }
            let _ = inbox.send(In::Msg(Msg::Ack { seq }));
        }
        Msg::Bye(b) => {
            let _ = inbox.send(In::Msg(Msg::Bye(b)));
            return Some(if b == Bye::Revoked {
                CloseReason::Revoked
            } else {
                CloseReason::Eof
            });
        }
        m => {
            let _ = inbox.send(In::Msg(m));
        }
    }
    None
}

fn meta_ok(m: &Meta) -> bool {
    m.size <= FILE_MAX
}

fn body_ok(b: &Body) -> bool {
    match b {
        Body::Empty => true,
        Body::Inline(x) => x.0.len() <= FRAME_MAX,
        Body::Stream { len } => *len <= FILE_MAX,
        Body::Delta { ops, data_len } => ops.len() <= BATCH_MAX && *data_len <= FILE_MAX,
    }
}

fn op_ok(op: &Op) -> bool {
    match op {
        Op::Fetch { have, range, .. } => {
            have.as_ref().is_none_or(|h| h.len() <= SIGS_MAX)
                && range.is_none_or(|(_, l)| l <= RANGE_UNIT)
        }
        Op::FetchMany { items } => items.len() <= BATCH_MAX,
        Op::Hashes { items, .. } => items.len() <= BATCH_MAX,
        Op::Resolve { .. } => true,
        Op::Commit { new, body, .. } => new.size <= FILE_MAX && body_ok(body),
        Op::Rename { body, .. } => body
            .as_ref()
            .is_none_or(|(v, b)| v.size <= FILE_MAX && body_ok(b)),
        Op::Mk { .. } | Op::Remove { .. } | Op::SetAttr { .. } => true,
    }
}

fn reply_ok(r: &Reply) -> bool {
    match r {
        Reply::Blob { meta, body } => meta_ok(meta) && body_ok(body),
        Reply::Blobs { items } => items.len() <= BATCH_MAX,
        Reply::Hashes { items } => items.len() <= BATCH_MAX,
        Reply::Done { meta } => meta_ok(meta),
        Reply::Conflict { current, .. } => current.as_ref().is_none_or(meta_ok),
    }
}

fn check_msg(m: &Msg) -> Result<(), &'static str> {
    let ok = match m {
        Msg::Req { op, .. } => op_ok(op),
        Msg::Resp { res: Ok(r), .. } => reply_ok(r),
        Msg::Push(Push::Snapshot { entries, .. }) => {
            entries.len() <= BATCH_MAX && entries.iter().all(|e| meta_ok(&e.meta))
        }
        Msg::Push(Push::Changes { changes, .. }) => {
            changes.len() <= BATCH_MAX
                && changes.iter().all(|c| match c {
                    Change::Upsert { meta, .. } => meta_ok(meta),
                    Change::Remove { .. } | Change::Rename { .. } => true,
                })
        }
        Msg::Push(Push::Hashes { items, .. }) => items.len() <= BATCH_MAX,
        Msg::Welcome(w) => {
            w.repos.len() <= BATCH_MAX
                && w.excludes.len() <= BATCH_MAX
                && w.excludes.iter().all(|e| e.text.0.len() <= TEXT_MAX)
        }
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err("message exceeds protocol limits")
    }
}

fn hs_err(e: HsError) -> NetError {
    match e {
        HsError::Io(e) => NetError::Io(e),
        HsError::Crypto => NetError::Handshake("handshake authentication failed"),
        HsError::Malformed(s) => NetError::Handshake(s),
        HsError::PinMismatch => NetError::KeyMismatch,
        HsError::Rejected(r) => NetError::Rejected(r),
    }
}

// bounds the whole handshake, not each read, so a byte-at-a-time peer cannot hold a slot
struct Timed<'a> {
    s: &'a TcpStream,
    until: Instant,
    first: Option<Instant>,
}

impl<'a> Timed<'a> {
    fn new(s: &'a TcpStream, whole: Duration, first: Option<Duration>) -> Self {
        let now = Instant::now();
        Self {
            s,
            until: now + whole,
            first: first.map(|f| now + f),
        }
    }

    fn left(until: Instant) -> io::Result<Duration> {
        let d = until.saturating_duration_since(Instant::now());
        if d.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "handshake deadline exceeded",
            ))
        } else {
            Ok(d)
        }
    }
}

impl Read for Timed<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let until = self.first.map_or(self.until, |f| f.min(self.until));
        self.s.set_read_timeout(Some(Self::left(until)?))?;
        let n = (&*self.s).read(b)?;
        if n > 0 {
            self.first = None;
        }
        Ok(n)
    }
}

impl Write for Timed<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.s.set_write_timeout(Some(Self::left(self.until)?))?;
        (&*self.s).write(b)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.s).flush()
    }
}

pub fn dial(addr: SocketAddr, id: &Identity, how: Dial, me: &HsHello) -> Result<Session, NetError> {
    let sock = new_socket(&addr).map_err(NetError::Io)?;
    sock.connect_timeout(&addr.into(), CONNECT_TIMEOUT)
        .map_err(NetError::Io)?;
    let s: TcpStream = sock.into();
    s.set_nodelay(true).map_err(NetError::Io)?;
    let pin = match how {
        Dial::Pair => None,
        Dial::Resume(k) => Some(k),
    };
    let mut io = Timed::new(&s, HS_TIMEOUT, None);
    let (est, hello) = noise::initiate(&mut io, id, pin.as_ref(), me).map_err(hs_err)?;
    if hello.role != Role::Host {
        return Err(NetError::Handshake("peer is not a csync host"));
    }
    start(s, est, hello).map_err(NetError::Io)
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

fn take(
    map: &mut HashMap<IpAddr, Bucket>,
    key: IpAddr,
    cap: f64,
    per_sec: f64,
    now: Instant,
) -> bool {
    let refill = |b: &Bucket| {
        (b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * per_sec).min(cap)
    };
    if !map.contains_key(&key) && map.len() >= LIMIT_TABLE_MAX {
        map.retain(|_, b| refill(&*b) < cap);
        if map.len() >= LIMIT_TABLE_MAX {
            return false;
        }
    }
    let b = map.entry(key).or_insert(Bucket {
        tokens: cap,
        at: now,
    });
    b.tokens = refill(&*b);
    b.at = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        true
    } else {
        false
    }
}

struct Limits {
    hs: HashMap<IpAddr, Bucket>,
    pair: HashMap<IpAddr, Bucket>,
    pair_all: Bucket,
}

// one ipv6 /64 is one subscriber, so a whole prefix shares a bucket
fn ip_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

impl Limits {
    fn handshake(&mut self, ip: IpAddr) -> bool {
        take(
            &mut self.hs,
            ip_key(ip),
            HS_PER_MIN,
            HS_PER_MIN / 60.0,
            Instant::now(),
        )
    }

    fn pair_all_now(&self, now: Instant) -> f64 {
        let b = &self.pair_all;
        (b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * PAIR_ALL_HOUR / 3600.0)
            .min(PAIR_ALL_HOUR)
    }

    // checks the pairing budget without spending it, so an aborted handshake costs nothing
    fn pairing_open(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.pair_all_now(now) < 1.0 {
            return false;
        }
        self.pair.get(&ip_key(ip)).is_none_or(|b| {
            let per_sec = PAIR_PER_IP_HOUR / 3600.0;
            let t = b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * per_sec;
            t.min(PAIR_PER_IP_HOUR) >= 1.0
        })
    }

    fn pairing(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let all = self.pair_all_now(now);
        if all < 1.0 {
            return false;
        }
        if !take(
            &mut self.pair,
            ip_key(ip),
            PAIR_PER_IP_HOUR,
            PAIR_PER_IP_HOUR / 3600.0,
            now,
        ) {
            return false;
        }
        self.pair_all = Bucket {
            tokens: all - 1.0,
            at: now,
        };
        true
    }
}

#[derive(Clone, Copy)]
struct HsTiming {
    first: Duration,
    whole: Duration,
}

const HS_TIMING: HsTiming = HsTiming {
    first: HS_FIRST_BYTE,
    whole: HS_TIMEOUT,
};

#[derive(Default)]
struct Inflight {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

struct Ctx {
    id: Arc<Identity>,
    trust: Arc<Trust>,
    allow_pairing: bool,
    hello: Mutex<HsHello>,
    limits: Mutex<Limits>,
    inflight: Mutex<Inflight>,
    timing: HsTiming,
    tx: Sender<Result<Incoming, NetError>>,
}

// holds one global and one per-ip handshake slot; dropping it on any exit path frees both
struct Busy {
    ctx: Arc<Ctx>,
    key: IpAddr,
}

impl Busy {
    fn admit(ctx: &Arc<Ctx>, ip: IpAddr) -> Option<Self> {
        let key = ip_key(ip);
        let mut f = lock(&ctx.inflight);
        let n = f.per_ip.get(&key).copied().unwrap_or(0);
        if f.total >= HS_CONCURRENT_MAX || n >= HS_PER_IP_MAX {
            return None;
        }
        f.total += 1;
        f.per_ip.insert(key, n + 1);
        Some(Self {
            ctx: ctx.clone(),
            key,
        })
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        let mut f = lock(&self.ctx.inflight);
        f.total = f.total.saturating_sub(1);
        if let Some(n) = f.per_ip.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                f.per_ip.remove(&self.key);
            }
        }
    }
}

struct ListenGate<'a> {
    ctx: &'a Ctx,
    ip: IpAddr,
    entry: Option<TrustEntry>,
    pair_limited: bool,
}

impl ListenGate<'_> {
    fn pair_limited(&mut self) -> Result<(), Reject> {
        self.pair_limited = true;
        Err(Reject::RateLimited)
    }
}

impl Gate for ListenGate<'_> {
    fn mode(&mut self, m: HsMode) -> Result<(), Reject> {
        match m {
            HsMode::Resume => Ok(()),
            HsMode::Pair if !self.ctx.allow_pairing => Err(Reject::PairingDisabled),
            HsMode::Pair if !lock(&self.ctx.limits).pairing_open(self.ip) => self.pair_limited(),
            HsMode::Pair => Ok(()),
        }
    }

    fn peer(&mut self, m: HsMode, key: &PeerKey, hello: &HsHello) -> Result<(), Reject> {
        if hello.role != Role::Guest {
            return Err(Reject::Refused);
        }
        if m == HsMode::Pair {
            // spent only once the guest has completed the key exchange
            if !lock(&self.ctx.limits).pairing(self.ip) {
                return self.pair_limited();
            }
            return Ok(());
        }
        match self.ctx.trust.get(key) {
            Some(e) if e.role == Role::Guest => {
                self.entry = Some(e);
                Ok(())
            }
            _ => Err(Reject::UnknownPeer),
        }
    }
}

fn reject(s: &TcpStream, r: Reject) {
    let mut w = s;
    let _ = w.write_all(&r.frame());
    let _ = s.shutdown(Shutdown::Write);
}

fn handshake_in(s: TcpStream, ip: IpAddr, ctx: &Ctx) -> Result<Incoming, NetError> {
    s.set_nodelay(true).map_err(NetError::Io)?;
    let me = lock(&ctx.hello).clone();
    let mut gate = ListenGate {
        ctx,
        ip,
        entry: None,
        pair_limited: false,
    };
    let mut io = Timed::new(&s, ctx.timing.whole, Some(ctx.timing.first));
    let (est, hello) = match noise::respond(&mut io, &ctx.id, &me, &mut gate) {
        Ok(x) => x,
        Err(_) if gate.pair_limited => return Err(NetError::PairingLimited),
        Err(e) => return Err(hs_err(e)),
    };
    let mode = est.mode;
    let entry = gate.entry.take();
    let sess = start(s, est, hello).map_err(NetError::Io)?;
    match (mode, entry) {
        (HsMode::Pair, _) => Ok(Incoming::Pairing(sess)),
        (HsMode::Resume, Some(e)) => Ok(Incoming::Known(sess, e)),
        (HsMode::Resume, None) => Err(NetError::UnknownPeer),
    }
}

fn accept_loop(l: TcpListener, ctx: Arc<Ctx>, stop: Arc<AtomicBool>) {
    loop {
        let accepted = l.accept();
        if stop.load(Ordering::Acquire) {
            return;
        }
        let (s, peer) = match accepted {
            Ok(x) => x,
            Err(e) => {
                if !matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::WouldBlock
                ) {
                    // fd exhaustion and similar: back off instead of spinning
                    thread::sleep(Duration::from_millis(100));
                }
                continue;
            }
        };
        let ip = peer.ip();
        if !lock(&ctx.limits).handshake(ip) {
            reject(&s, Reject::RateLimited);
            let _ = ctx.tx.try_send(Err(NetError::RateLimited));
            continue;
        }
        let Some(guard) = Busy::admit(&ctx, ip) else {
            reject(&s, Reject::RateLimited);
            continue;
        };
        let _ = thread::Builder::new()
            .name("csync-hs".into())
            .spawn(move || {
                let c = &guard.ctx;
                match handshake_in(s, ip, c) {
                    Ok(inc) => {
                        let _ = c.tx.send_timeout(Ok(inc), DELIVER_TIMEOUT);
                    }
                    Err(e) => {
                        let _ = c.tx.try_send(Err(e));
                    }
                }
            });
    }
}

pub struct Listener {
    addr: SocketAddr,
    rx: Receiver<Result<Incoming, NetError>>,
    stop: Arc<AtomicBool>,
    ctx: Arc<Ctx>,
}

impl Listener {
    pub fn bind(
        addr: SocketAddr,
        id: Arc<Identity>,
        trust: Arc<Trust>,
        allow_pairing: bool,
    ) -> io::Result<Self> {
        Self::bind_timed(addr, id, trust, allow_pairing, HS_TIMING)
    }

    fn bind_timed(
        addr: SocketAddr,
        id: Arc<Identity>,
        trust: Arc<Trust>,
        allow_pairing: bool,
        timing: HsTiming,
    ) -> io::Result<Self> {
        let sock = new_socket(&addr)?;
        sock.set_reuse_address(true)?;
        sock.bind(&addr.into())?;
        sock.listen(128)?;
        let l: TcpListener = sock.into();
        let local = l.local_addr()?;
        let name = Name::new(&format!("csync-{}", &id.public.fpr_hex()[..8]))
            .map_err(|_| io::Error::other("host name"))?;
        let (tx, rx) = bounded(ACCEPT_QUEUE);
        let now = Instant::now();
        let ctx = Arc::new(Ctx {
            id,
            trust,
            allow_pairing,
            hello: Mutex::new(HsHello {
                proto: PROTO,
                role: Role::Host,
                name,
            }),
            limits: Mutex::new(Limits {
                hs: HashMap::new(),
                pair: HashMap::new(),
                pair_all: Bucket {
                    tokens: PAIR_ALL_HOUR,
                    at: now,
                },
            }),
            inflight: Mutex::new(Inflight::default()),
            timing,
            tx,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (c, s) = (ctx.clone(), stop.clone());
        thread::Builder::new()
            .name("csync-accept".into())
            .spawn(move || accept_loop(l, c, s))?;
        Ok(Self {
            addr: local,
            rx,
            stop,
            ctx,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn set_hello(&self, me: HsHello) {
        *lock(&self.ctx.hello) = me;
    }

    pub fn accept(&self) -> Result<Incoming, NetError> {
        self.rx
            .recv()
            .unwrap_or_else(|_| Err(NetError::Io(io::Error::other("listener stopped"))))
    }

    pub fn incoming(&self) -> &Receiver<Result<Incoming, NetError>> {
        &self.rx
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let mut wake = self.addr;
        if wake.ip().is_unspecified() {
            wake.set_ip(match wake.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            });
        }
        let _ = TcpStream::connect_timeout(&wake, Duration::from_millis(200));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::proto::{Bytes, ExcludeSrc, Expect, FsTraits, RelPath, Welcome, frame::F_MORE};

    struct AllowAll;
    impl Gate for AllowAll {
        fn mode(&mut self, _: HsMode) -> Result<(), Reject> {
            Ok(())
        }
        fn peer(&mut self, _: HsMode, _: &PeerKey, _: &HsHello) -> Result<(), Reject> {
            Ok(())
        }
    }

    fn hello(role: Role) -> HsHello {
        HsHello {
            proto: PROTO,
            role,
            name: Name::new("t").unwrap(),
        }
    }

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        (a, b)
    }

    fn handshake(a: &TcpStream, b: TcpStream) -> (Established, (Established, HsHello)) {
        let host = Identity::generate().unwrap();
        let guest = Identity::generate().unwrap();
        let hk = host.public;
        let t = thread::spawn(move || {
            let mut io = &b;
            noise::respond(&mut io, &host, &hello(Role::Host), &mut AllowAll).unwrap()
        });
        let mut io = a;
        let (g, _) = noise::initiate(&mut io, &guest, Some(&hk), &hello(Role::Guest)).unwrap();
        (g, t.join().unwrap())
    }

    pub(crate) fn test_pair() -> (Session, Session) {
        let (a, b) = tcp_pair();
        let b2 = b.try_clone().unwrap();
        let (g, (h, hh)) = handshake(&a, b);
        let gs = start(a, g, hello(Role::Host)).unwrap();
        let hs = start(b2, h, hh).unwrap();
        (gs, hs)
    }

    struct Raw {
        s: TcpStream,
        sealer: Sealer,
        opener: Opener,
        enc: Encoder,
        dec: Decoder,
    }

    impl Raw {
        fn send_msg(&mut self, m: &Msg) {
            let mut out = Vec::new();
            let enc = &mut self.enc;
            seal_with(&mut self.sealer, &mut out, |e| enc.msg(m, e)).unwrap();
            self.s.write_all(&out).unwrap();
        }

        fn send_plain(&mut self, pt: &[u8]) {
            let mut out = Vec::new();
            self.sealer.seal(pt, &mut out).unwrap();
            let _ = self.s.write_all(&out);
        }

        fn recv_msg(&mut self) -> Option<Msg> {
            let mut ct = vec![0u8; NOISE_MAX];
            let mut pt = vec![0u8; NOISE_MAX];
            loop {
                let mut l = [0u8; 2];
                self.s.read_exact(&mut l).ok()?;
                let n = u16::from_be_bytes(l) as usize;
                self.s.read_exact(&mut ct[..n]).ok()?;
                let m = self.opener.open(&ct[..n], &mut pt).ok()?;
                if let Some(Frame::Msg(msg)) = self.dec.push(&pt[..m]).ok()? {
                    return Some(msg);
                }
            }
        }
    }

    fn raw_pair() -> (Session, Raw) {
        let (a, b) = tcp_pair();
        let b2 = b.try_clone().unwrap();
        let (g, (h, _)) = handshake(&a, b);
        let gs = start(a, g, hello(Role::Host)).unwrap();
        b2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (sealer, opener) = h.split();
        (
            gs,
            Raw {
                s: b2,
                sealer,
                opener,
                enc: Encoder::default(),
                dec: Decoder::default(),
            },
        )
    }

    fn recv(s: &Session) -> In {
        s.inbox
            .recv_timeout(Duration::from_secs(5))
            .expect("inbox timed out")
    }

    fn noise_bytes(n: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn large_runs_cross_a_rekey_in_both_directions() {
        let (g, mut raw) = raw_pair();
        let parts: Vec<Vec<u8>> = (0..16).map(|i| noise_bytes(CHUNK_MAX + i)).collect();
        // one write holds a parallel run, a rekey, then a run under the new key
        let mut plain = Vec::new();
        let mut spans = Vec::new();
        let mut out = Vec::new();
        for (i, p) in parts.iter().enumerate() {
            let d = &p[..CHUNK_MAX];
            let mut emit = |s: &[u8]| {
                spans.push((plain.len(), s.len()));
                plain.extend_from_slice(s);
            };
            raw.enc
                .chunk(3, (i * CHUNK_MAX) as u64, i == 15, d, &mut emit)
                .unwrap();
            if i == 7 {
                raw.sealer.seal_many(&plain, &spans, &mut out).unwrap();
                plain.clear();
                spans.clear();
                let enc = &mut raw.enc;
                seal_with(&mut raw.sealer, &mut out, |e| enc.msg(&Msg::Rekey, e)).unwrap();
                raw.sealer.rekey();
            }
        }
        raw.sealer.seal_many(&plain, &spans, &mut out).unwrap();
        raw.s.write_all(&out).unwrap();
        for (i, p) in parts.iter().enumerate() {
            match recv(&g) {
                In::Chunk {
                    id: 3, off, data, ..
                } => {
                    assert_eq!(off, (i * CHUNK_MAX) as u64);
                    assert_eq!(data, p[..CHUNK_MAX]);
                }
                _ => panic!("expected chunk {i}"),
            }
        }

        for (i, p) in parts.iter().enumerate() {
            g.link
                .send_out(Out::Chunk {
                    id: 4,
                    off: i as u64,
                    last: i == 15,
                    data: p[..CHUNK_MAX].to_vec(),
                })
                .unwrap();
        }
        let mut ct = vec![0u8; NOISE_MAX];
        let mut pt = vec![0u8; NOISE_MAX];
        let mut seen = 0;
        while seen < 16 {
            let mut l = [0u8; 2];
            raw.s.read_exact(&mut l).unwrap();
            let n = u16::from_be_bytes(l) as usize;
            raw.s.read_exact(&mut ct[..n]).unwrap();
            let m = raw.opener.open(&ct[..n], &mut pt).unwrap();
            if let Some(Frame::Chunk {
                id: 4, off, data, ..
            }) = raw.dec.push(&pt[..m]).unwrap()
            {
                assert_eq!(off, seen as u64);
                assert_eq!(data, &parts[seen][..CHUNK_MAX]);
                seen += 1;
            }
        }
    }

    #[test]
    fn link_round_trips_messages_chunks_and_graceful_bye() {
        let (g, h) = test_pair();
        g.link.send(Msg::Ping { t_ns: 7 }).unwrap();
        assert!(matches!(recv(&g), In::Msg(Msg::Pong { t_ns: 7, .. })));

        let big = noise_bytes(300_000);
        let w = Welcome {
            proto: PROTO,
            project: Name::new("p").unwrap(),
            index: 1,
            seq: 2,
            fs: FsTraits {
                case_fold: true,
                norm_fold: false,
            },
            repos: vec![],
            excludes: vec![ExcludeSrc {
                repo: RelPath::root(),
                text: Bytes(big.clone()),
            }],
            host_ns: 3,
        };
        h.link.send(Msg::Welcome(w.clone())).unwrap();
        match recv(&g) {
            In::Msg(Msg::Welcome(got)) => assert_eq!(got, w),
            _ => panic!("expected welcome"),
        }

        let data = noise_bytes(CHUNK_MAX);
        g.link
            .send_out(Out::Chunk {
                id: 9,
                off: 128,
                last: true,
                data: data.clone(),
            })
            .unwrap();
        match recv(&h) {
            In::Chunk {
                id: 9,
                off: 128,
                last: true,
                data: got,
            } => assert_eq!(got, data),
            _ => panic!("expected chunk"),
        }

        for s in 0..UNACKED_PUSH_MAX as u64 {
            h.link
                .try_push(Push::Changes {
                    seq: s,
                    changes: vec![],
                })
                .unwrap();
        }
        assert!(matches!(
            h.link.try_push(Push::Changes {
                seq: 99,
                changes: vec![]
            }),
            Err(PushError::Full(_))
        ));
        g.link.send(Msg::Ack { seq: 9 }).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while h.link.unacked_pushes() != UNACKED_PUSH_MAX - 10 {
            assert!(Instant::now() < deadline, "ack not applied");
            thread::sleep(Duration::from_millis(5));
        }

        h.link.close(CloseReason::Local);
        let mut saw_bye = false;
        loop {
            match recv(&g) {
                In::Msg(Msg::Bye(Bye::Shutdown)) => saw_bye = true,
                In::Closed(CloseReason::Eof) => break,
                In::Closed(r) => panic!("unexpected close {r:?}"),
                _ => {}
            }
        }
        assert!(saw_bye);
        assert!(g.link.send(Msg::Rekey).is_err());
        loop {
            if let In::Closed(r) = recv(&h) {
                assert!(matches!(r, CloseReason::Local));
                break;
            }
        }
    }

    #[test]
    fn bulk_messages_are_delivered_without_waiting_and_refused_once_closed() {
        let (g, h) = test_pair();
        let items = vec![(RelPath::new("a/b").unwrap(), 4, [7u8; 32])];
        h.link
            .try_send_bulk(Msg::Push(Push::Hashes {
                index: 9,
                items: items.clone(),
            }))
            .unwrap();
        match recv(&g) {
            In::Msg(Msg::Push(Push::Hashes {
                index: 9,
                items: got,
            })) => assert_eq!(got, items),
            _ => panic!("expected pushed hashes"),
        }
        h.link.close(CloseReason::Local);
        assert_eq!(
            h.link
                .try_send_bulk(Msg::Push(Push::HashesDone { index: 9 })),
            Err(Full)
        );
    }

    fn expect_protocol_close(g: &Session) {
        loop {
            match recv(g) {
                In::Closed(CloseReason::Protocol(_)) => return,
                In::Closed(r) => panic!("expected protocol close, got {r:?}"),
                _ => {}
            }
        }
    }

    #[test]
    fn oversize_reassembly_is_rejected() {
        let (g, mut raw) = raw_pair();
        let mut seg = vec![0u8; NOISE_MAX - 16];
        seg[0] = F_MORE;
        for _ in 0..(FRAME_MAX / (seg.len() - 1) + 2) {
            raw.send_plain(&seg);
        }
        expect_protocol_close(&g);
    }

    #[test]
    fn empty_and_forged_segments_are_rejected() {
        let (g, mut raw) = raw_pair();
        raw.s.write_all(&[0, 0]).unwrap();
        expect_protocol_close(&g);

        let (g, mut raw) = raw_pair();
        let mut junk = vec![0u8; 2 + 40];
        junk[..2].copy_from_slice(&40u16.to_be_bytes());
        raw.s.write_all(&junk).unwrap();
        expect_protocol_close(&g);
    }

    #[test]
    fn batch_limits_are_enforced_after_decode() {
        let (g, mut raw) = raw_pair();
        let p = RelPath::new("a").unwrap();
        let changes = vec![Change::Remove { path: p }; BATCH_MAX + 1];
        raw.send_msg(&Msg::Push(Push::Changes { seq: 1, changes }));
        expect_protocol_close(&g);
    }

    #[test]
    fn peer_inflight_cap_closes_with_bye_limit() {
        let (g, mut raw) = raw_pair();
        for id in 0..=INFLIGHT_MAX as u32 {
            raw.send_msg(&Msg::Req {
                id,
                op: Op::Remove {
                    path: RelPath::new("x").unwrap(),
                    expect: Expect::Any,
                },
            });
        }
        let mut reqs = 0;
        loop {
            match recv(&g) {
                In::Msg(Msg::Req { .. }) => reqs += 1,
                In::Closed(CloseReason::Protocol(_)) => break,
                _ => panic!("unexpected inbound"),
            }
        }
        assert_eq!(reqs, INFLIGHT_MAX);
        let mut bye = None;
        while let Some(m) = raw.recv_msg() {
            if let Msg::Bye(b) = m {
                bye = Some(b);
                break;
            }
        }
        assert_eq!(bye, Some(Bye::Limit));
    }

    fn test_listener(pairing: bool, timing: HsTiming) -> (Listener, std::path::PathBuf) {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let d =
            std::env::temp_dir().join(format!("csync-test-conn-{}", crate::crypto::trust::hex(&r)));
        let trust = Arc::new(Trust::load(&d).unwrap());
        let id = Arc::new(Identity::generate().unwrap());
        let addr = "127.0.0.1:0".parse().unwrap();
        let l = Listener::bind_timed(addr, id, trust, pairing, timing).unwrap();
        (l, d)
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    // true once the host has dropped the connection
    fn host_closed(c: &TcpStream) -> bool {
        let mut b = [0u8; 16];
        match (&*c).read(&mut b) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ),
        }
    }

    #[test]
    fn handshake_deadline_bounds_a_trickling_peer() {
        let timing = HsTiming {
            first: ms(500),
            whole: ms(800),
        };
        let (l, d) = test_listener(false, timing);
        let c = TcpStream::connect(l.local_addr()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let t0 = Instant::now();
        // resume mode and a 256-byte frame header, then one byte every 100 ms
        (&c).write_all(&[HsMode::Resume as u8, 1, 0]).unwrap();
        let w = c.try_clone().unwrap();
        let trickle = thread::spawn(move || {
            for _ in 0..40 {
                thread::sleep(ms(100));
                if (&w).write_all(&[1]).is_err() {
                    break;
                }
            }
        });
        assert!(host_closed(&c), "host kept a trickling handshake open");
        assert!(t0.elapsed() < Duration::from_secs(3));
        let _ = c.shutdown(Shutdown::Both);
        trickle.join().unwrap();
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn silent_peer_is_dropped_after_first_byte_timeout() {
        let timing = HsTiming {
            first: ms(300),
            whole: Duration::from_secs(10),
        };
        let (l, d) = test_listener(false, timing);
        let c = TcpStream::connect(l.local_addr()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let t0 = Instant::now();
        assert!(host_closed(&c), "host kept a silent connection open");
        assert!(t0.elapsed() < Duration::from_secs(3));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn one_ip_cannot_hold_every_handshake_slot_and_slots_are_released() {
        let timing = HsTiming {
            first: Duration::from_secs(10),
            whole: Duration::from_secs(10),
        };
        let (l, d) = test_listener(false, timing);
        let idle: Vec<TcpStream> = (0..HS_PER_IP_MAX)
            .map(|_| {
                let c = TcpStream::connect(l.local_addr()).unwrap();
                (&c).write_all(&[HsMode::Resume as u8]).unwrap();
                c
            })
            .collect();
        let probe = |wait: Duration| -> Option<[u8; 3]> {
            let c = TcpStream::connect(l.local_addr()).unwrap();
            c.set_read_timeout(Some(wait)).unwrap();
            let mut b = [0u8; 3];
            (&c).read_exact(&mut b).ok().map(|()| b)
        };
        assert_eq!(
            probe(Duration::from_secs(5)),
            Some(Reject::RateLimited.frame())
        );
        drop(idle);
        let mut admitted = false;
        for _ in 0..10 {
            if probe(ms(300)).is_none() {
                admitted = true;
                break;
            }
            thread::sleep(ms(100));
        }
        assert!(admitted, "closed handshakes did not release their slots");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn pairing_budget_is_spent_only_by_completed_key_exchanges() {
        let (l, d) = test_listener(true, HS_TIMING);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let mut gate = ListenGate {
            ctx: &l.ctx,
            ip,
            entry: None,
            pair_limited: false,
        };
        for _ in 0..50 {
            assert_eq!(gate.mode(HsMode::Pair), Ok(()));
        }
        let (k, h) = (PeerKey([1; 32]), hello(Role::Guest));
        for _ in 0..PAIR_PER_IP_HOUR as usize {
            assert_eq!(gate.peer(HsMode::Pair, &k, &h), Ok(()));
        }
        assert!(!gate.pair_limited);
        assert_eq!(gate.peer(HsMode::Pair, &k, &h), Err(Reject::RateLimited));
        assert!(gate.pair_limited);
        assert_eq!(gate.mode(HsMode::Pair), Err(Reject::RateLimited));

        let guest = Identity::generate().unwrap();
        // the reject frame can race the reset from unread bytes, so only the host side is exact
        assert!(dial(l.local_addr(), &guest, Dial::Pair, &hello(Role::Guest)).is_err());
        let seen = l.incoming().recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(seen, Err(NetError::PairingLimited)));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn plaintext_reject_is_never_reported_as_an_authenticated_key_mismatch() {
        let fake = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = fake.local_addr().unwrap();
        let host = thread::spawn(move || {
            let (s, _) = fake.accept().unwrap();
            let mut b = [0u8; 4096];
            let _ = (&s).read(&mut b);
            (&s).write_all(&Reject::KeyMismatch.frame()).unwrap();
            while matches!((&s).read(&mut b), Ok(n) if n > 0) {}
        });
        let guest = Identity::generate().unwrap();
        let pin = Identity::generate().unwrap().public;
        let r = dial(addr, &guest, Dial::Resume(pin), &hello(Role::Guest));
        host.join().unwrap();
        assert!(matches!(r, Err(NetError::Rejected(Reject::KeyMismatch))));
        assert!(matches!(
            hs_err(HsError::PinMismatch),
            NetError::KeyMismatch
        ));
    }
}
