// every guest mutation goes through one queue and one sender thread, so the host sees them in ticket order.
// a busy answer is retried before anything newer is sent; in-flight uploads stay below the host's upload cap.
use super::cache::{Done, Remote, RemoteSlot, lock, pread_full};
use super::tree::NodeId;
use crate::delta;
use crate::net::rpc::RpcError;
use crate::proto::{
    Body, CHUNK_MAX, DeltaOp, Expect, Kind, Meta, Op, RelPath, Reply, ReqId, Version, WireErr,
};
use crossbeam_channel::Sender;
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub type Ticket = u64;

// the host refuses an upload past its own cap without queueing the request, so the pipe stays below it
pub const STREAMS: usize = 32;
// ops queued or in flight; the rest of the per-guest request budget is left to fetches
pub const WINDOW: usize = 96;
const BUSY_MIN: Duration = Duration::from_millis(1);
const BUSY_MAX: Duration = Duration::from_millis(50);
const SUBMIT_RETRY: Duration = Duration::from_millis(5);
// how often a sender waiting for the link looks at close
const POLL: Duration = Duration::from_millis(50);
// an op is sent again once after the link drops under it, as a direct call was
const REPLAYS: u32 = 1;
// staging reads for a streamed body, split into wire chunks
const READ_BLOCK: usize = CHUNK_MAX * 16;
// a new file's commit that is last in the queue waits this long, so the chmod or utimes that follows a close folds into it
pub const LINGER: Duration = Duration::from_millis(1);

// who is told when the op completes; Sync means a caller blocks in wait()
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    Sync,
    Staged(u32),
    Node(NodeId),
}

#[derive(Debug)]
pub struct Landed {
    pub ticket: Ticket,
    pub tag: Tag,
    pub res: Result<Reply, RpcError>,
}

// the chunks that follow a request whose body is Stream or Delta; owned, so a replay can send them again
pub enum Payload {
    None,
    File {
        fd: OwnedFd,
        len: u64,
    },
    Literals {
        new: Vec<u8>,
        ops: Vec<DeltaOp>,
        data_len: u64,
    },
}

enum Sink {
    Wait,
    Land(Tag),
    Call(Done),
}

enum Fire {
    Land(Landed),
    Call(Done, Result<Reply, RpcError>),
}

struct Item {
    ticket: Ticket,
    op: Op,
    payload: Arc<Payload>,
    sink: Sink,
    queued: Instant,
    deadline: Instant,
    streamed: bool,
    replays: u32,
    backoff: Duration,
    not_before: Option<Instant>,
}

struct Flight {
    item: Item,
    // names one send of the ticket: an answer to an earlier send is not this one's
    epoch: u64,
    slot_gen: u64,
    remote: Arc<dyn Remote>,
    id: Option<ReqId>,
}

struct Back {
    ticket: Ticket,
    epoch: u64,
    res: Result<Reply, RpcError>,
}

struct State {
    next: Ticket,
    epoch: u64,
    queue: VecDeque<Item>,
    flight: BTreeMap<Ticket, Flight>,
    replies: VecDeque<Back>,
    results: FxHashMap<Ticket, Result<Reply, RpcError>>,
    streams: usize,
    closed: bool,
}

impl State {
    fn pending(&self, t: Ticket) -> bool {
        self.flight.contains_key(&t) || self.queue.iter().any(|i| i.ticket == t)
    }

    fn next_event(&self, now: Instant) -> Option<Instant> {
        let flights = self.flight.values().map(|f| f.item.deadline);
        let queued = self.queue.iter().map(|i| i.deadline);
        let retry = self
            .queue
            .front()
            .and_then(|i| i.not_before)
            .filter(|t| *t > now);
        let linger = self.linger_end().filter(|t| *t > now);
        flights.chain(queued).chain(retry).chain(linger).min()
    }

    // when the op at the front stops waiting for company: only a first send of a new file's async commit that
    // nothing is queued behind waits at all
    fn linger_end(&self) -> Option<Instant> {
        let front = self.queue.front()?;
        (self.queue.len() == 1
            && front.replays == 0
            && front.not_before.is_none()
            && lingers(&front.op))
        .then(|| front.queued + LINGER)
    }
}

fn lingers(op: &Op) -> bool {
    matches!(
        op,
        Op::Commit {
            base: Expect::Absent,
            sync: false,
            ..
        }
    )
}

// true when the op names a path strictly below dir
fn below(op: &Op, dir: &RelPath) -> bool {
    let under = |p: &RelPath| p != dir && p.starts_with(dir);
    match op {
        Op::Commit { path, .. }
        | Op::Mk { path, .. }
        | Op::Remove { path, .. }
        | Op::SetAttr { path, .. } => under(path),
        Op::Rename { from, to, .. } => under(from) || under(to),
        Op::Fetch { .. } | Op::FetchMany { .. } | Op::Resolve { .. } | Op::Hashes { .. } => false,
    }
}

struct Shared {
    remote: Arc<RemoteSlot>,
    landed: Sender<Landed>,
    st: Mutex<State>,
    // the sender: new work, an answer, a close
    wake: Condvar,
    // callers: a result, room in the window
    done: Condvar,
}

pub struct Pipe {
    sh: Arc<Shared>,
    join: Mutex<Option<JoinHandle<()>>>,
}

fn park<'a, T>(cv: &Condvar, g: MutexGuard<'a, T>, d: Duration) -> MutexGuard<'a, T> {
    match cv.wait_timeout(g, d) {
        Ok((g, _)) => g,
        Err(e) => e.into_inner().0,
    }
}

fn idle<'a, T>(cv: &Condvar, g: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    match cv.wait(g) {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    }
}

fn uploads(op: &Op) -> bool {
    let up = |b: &Body| match b {
        Body::Stream { len } => *len > 0,
        Body::Delta { data_len, .. } => *data_len > 0,
        Body::Empty | Body::Inline(_) => false,
    };
    match op {
        Op::Commit { body, .. } => up(body),
        Op::Rename {
            body: Some((_, b)), ..
        } => up(b),
        _ => false,
    }
}

// what a remove that already landed would have answered, as far as the request knows
fn removed(expect: Expect) -> Meta {
    let v = match expect {
        Expect::Is(v) => Some(v),
        _ => None,
    };
    Meta {
        kind: if expect == Expect::Dir {
            Kind::Dir
        } else {
            Kind::File
        },
        perm: 0,
        size: v.map_or(0, |v| v.size),
        mtime_ns: 0,
        ctime_ns: 0,
        hash: v.map(|v| v.hash),
        link: None,
        git_ro: false,
    }
}

fn requeue(q: &mut VecDeque<Item>, item: Item) {
    let at = q.partition_point(|i| i.ticket < item.ticket);
    q.insert(at, item);
}

fn leave(g: &mut State, t: Ticket) -> Option<Flight> {
    let f = g.flight.remove(&t)?;
    if f.item.streamed {
        g.streams = g.streams.saturating_sub(1);
    }
    Some(f)
}

fn complete(
    g: &mut State,
    fires: &mut Vec<Fire>,
    ticket: Ticket,
    sink: Sink,
    res: Result<Reply, RpcError>,
) {
    match sink {
        Sink::Wait => {
            g.results.insert(ticket, res);
        }
        Sink::Land(tag) => fires.push(Fire::Land(Landed { ticket, tag, res })),
        Sink::Call(d) => fires.push(Fire::Call(d, res)),
    }
}

// the generation of a link that dropped under the ticket, when this answer says so
fn on_reply(g: &mut State, b: Back, now: Instant, fires: &mut Vec<Fire>) -> Option<u64> {
    let f = g.flight.get(&b.ticket)?;
    if f.epoch != b.epoch {
        return None;
    }
    if matches!(b.res, Err(RpcError::Closed)) {
        return Some(f.slot_gen);
    }
    let mut f = leave(g, b.ticket)?;
    match b.res {
        // busy means the host changed nothing: the op goes again from its own place in the order
        Err(RpcError::Wire(WireErr::Busy)) if now + f.item.backoff < f.item.deadline => {
            f.item.not_before = Some(now + f.item.backoff);
            f.item.backoff = (f.item.backoff * 2).min(BUSY_MAX);
            requeue(&mut g.queue, f.item);
        }
        res => {
            let replayed_gone = f.item.replays > 0
                && matches!(res, Err(RpcError::Wire(WireErr::NotFound)))
                && matches!(f.item.op, Op::Remove { .. });
            let res = match (&f.item.op, replayed_gone) {
                (Op::Remove { expect, .. }, true) => Ok(Reply::Done {
                    meta: removed(*expect),
                }),
                _ => res,
            };
            complete(g, fires, b.ticket, f.item.sink, res);
        }
    }
    None
}

// an op the host already answered busy surfaces busy when its deadline passes, not a timeout
fn expiry_error(it: &Item) -> RpcError {
    if it.not_before.is_some() {
        RpcError::Wire(WireErr::Busy)
    } else {
        RpcError::Timeout
    }
}

fn expire(
    g: &mut State,
    now: Instant,
    fires: &mut Vec<Fire>,
    cancels: &mut Vec<(Arc<dyn Remote>, ReqId)>,
) -> bool {
    let mut any = false;
    let late: Vec<Ticket> = g
        .flight
        .iter()
        .filter(|(_, f)| f.item.deadline <= now)
        .map(|(t, _)| *t)
        .collect();
    for t in late {
        if let Some(f) = leave(g, t) {
            if let Some(id) = f.id {
                cancels.push((f.remote, id));
            }
            let err = expiry_error(&f.item);
            complete(g, fires, t, f.item.sink, Err(err));
            any = true;
        }
    }
    let mut i = 0;
    while i < g.queue.len() {
        if g.queue[i].deadline <= now
            && let Some(it) = g.queue.remove(i)
        {
            let err = expiry_error(&it);
            complete(g, fires, it.ticket, it.sink, Err(err));
            any = true;
        } else {
            i += 1;
        }
    }
    any
}

// chunk offsets count from the start of the body stream; the last chunk carries last=true
fn send_chunks(remote: &dyn Remote, id: ReqId, payload: &Payload) -> Result<(), RpcError> {
    match payload {
        Payload::None => Ok(()),
        Payload::File { fd, len } => {
            let mut block = vec![0u8; (*len).min(READ_BLOCK as u64) as usize];
            let mut off = 0u64;
            while off < *len {
                let n = (*len - off).min(block.len() as u64) as usize;
                match pread_full(fd.as_fd(), &mut block[..n], off) {
                    Ok(k) if k == n => {}
                    _ => return Err(RpcError::Wire(WireErr::Io)),
                }
                for (i, c) in block[..n].chunks(CHUNK_MAX).enumerate() {
                    let at = off + (i * CHUNK_MAX) as u64;
                    let end = at + c.len() as u64;
                    remote.send_chunk(id, at, end == *len, c.to_vec())?;
                }
                off += n as u64;
            }
            Ok(())
        }
        Payload::Literals { new, ops, data_len } => {
            let mut buf = Vec::with_capacity(CHUNK_MAX);
            let mut off = 0u64;
            for mut s in delta::literals(new, ops) {
                while !s.is_empty() {
                    let take = (CHUNK_MAX - buf.len()).min(s.len());
                    let (a, rest) = s.split_at(take);
                    buf.extend_from_slice(a);
                    s = rest;
                    if buf.len() == CHUNK_MAX {
                        let n = buf.len() as u64;
                        let full = std::mem::replace(&mut buf, Vec::with_capacity(CHUNK_MAX));
                        remote.send_chunk(id, off, off + n == *data_len, full)?;
                        off += n;
                    }
                }
            }
            if !buf.is_empty() {
                remote.send_chunk(id, off, true, buf)?;
            }
            Ok(())
        }
    }
}

impl Shared {
    fn is_closed(&self) -> bool {
        lock(&self.st).closed
    }

    // a link newer than `after` (any live one when None); none once the slot says no other can come
    fn link(&self, after: Option<u64>, deadline: Instant) -> Option<(u64, Arc<dyn Remote>)> {
        loop {
            let now = Instant::now();
            if self.is_closed() || now >= deadline {
                return None;
            }
            let slice = (now + POLL).min(deadline);
            let got = match after {
                Some(g) => self.remote.newer(g, slice),
                None => self.remote.get(slice),
            };
            match got {
                Ok(c) => return Some(c),
                Err(_) if self.remote.is_closed() => return None,
                Err(_) => {}
            }
        }
    }

    fn fire(&self, fires: Vec<Fire>) {
        for f in fires {
            match f {
                Fire::Land(l) => {
                    let _ = self.landed.send(l);
                }
                Fire::Call(d, r) => d(r),
            }
        }
        self.done.notify_all();
    }

    fn push(&self, op: Op, payload: Payload, sink: Sink, deadline: Instant) -> Result<Ticket, i32> {
        let streamed = uploads(&op);
        let mut g = lock(&self.st);
        loop {
            if g.closed {
                return Err(libc::EIO);
            }
            if g.queue.len() + g.flight.len() < WINDOW {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(libc::EIO);
            }
            g = park(&self.done, g, deadline - now);
        }
        let ticket = g.next;
        g.next += 1;
        g.queue.push_back(Item {
            ticket,
            op,
            payload: Arc::new(payload),
            sink,
            queued: Instant::now(),
            deadline,
            streamed,
            replays: 0,
            backoff: BUSY_MIN,
            not_before: None,
        });
        drop(g);
        self.wake.notify_all();
        Ok(ticket)
    }

    // completes the ticket now with a timeout; a request already on the wire is cancelled
    fn cancel(&self, t: Ticket) {
        let mut fires = Vec::new();
        let mut wire = None;
        {
            let mut g = lock(&self.st);
            if let Some(pos) = g.queue.iter().position(|i| i.ticket == t)
                && let Some(it) = g.queue.remove(pos)
            {
                complete(&mut g, &mut fires, t, it.sink, Err(RpcError::Timeout));
            } else if let Some(f) = leave(&mut g, t) {
                wire = f.id.map(|id| (f.remote, id));
                complete(&mut g, &mut fires, t, f.item.sink, Err(RpcError::Timeout));
            }
        }
        if let Some((r, id)) = wire {
            r.cancel(id);
        }
        self.fire(fires);
        self.wake.notify_all();
    }
}

struct Worker {
    sh: Arc<Shared>,
    conn: Option<(u64, Arc<dyn Remote>)>,
}

enum Act {
    Again,
    Send,
    Lost(u64),
    Stop,
}

impl Worker {
    fn run(mut self) {
        loop {
            match self.plan() {
                Act::Stop => return,
                Act::Again => {}
                Act::Send => {
                    if let Some(slot_gen) = self.send() {
                        self.reconnect(slot_gen);
                    }
                }
                Act::Lost(slot_gen) => self.reconnect(slot_gen),
            }
        }
    }

    // takes in the answers, times out what is late, and sleeps until there is something to send
    fn plan(&self) -> Act {
        let mut fires = Vec::new();
        let mut cancels = Vec::new();
        let mut g = lock(&self.sh.st);
        let act = loop {
            if g.closed {
                break Act::Stop;
            }
            let now = Instant::now();
            let mut lost = None;
            let mut touched = false;
            while let Some(b) = g.replies.pop_front() {
                touched = true;
                lost = on_reply(&mut g, b, now, &mut fires).or(lost);
            }
            touched |= expire(&mut g, now, &mut fires, &mut cancels);
            if touched {
                self.sh.done.notify_all();
            }
            if let Some(slot_gen) = lost {
                break Act::Lost(slot_gen);
            }
            if !fires.is_empty() || !cancels.is_empty() {
                break Act::Again;
            }
            if let Some(front) = g.queue.front()
                && front.not_before.is_none_or(|t| t <= now)
                && (!front.streamed || g.streams < STREAMS)
                && g.linger_end().is_none_or(|t| t <= now)
            {
                break Act::Send;
            }
            g = match g.next_event(now) {
                Some(t) => park(&self.sh.wake, g, t.saturating_duration_since(now)),
                None => idle(&self.sh.wake, g),
            };
        };
        drop(g);
        for (r, id) in cancels {
            r.cancel(id);
        }
        self.sh.fire(fires);
        act
    }

    fn callback(&self, ticket: Ticket, epoch: u64) -> Done {
        let sh = Arc::downgrade(&self.sh);
        Box::new(move |res| {
            if let Some(sh) = Weak::upgrade(&sh) {
                lock(&sh.st).replies.push_back(Back { ticket, epoch, res });
                sh.wake.notify_all();
            }
        })
    }

    fn fail_queued(&self, ticket: Ticket, e: RpcError) {
        let mut fires = Vec::new();
        {
            let mut g = lock(&self.sh.st);
            if let Some(pos) = g.queue.iter().position(|i| i.ticket == ticket)
                && let Some(it) = g.queue.remove(pos)
            {
                complete(&mut g, &mut fires, ticket, it.sink, Err(e));
            }
        }
        self.sh.fire(fires);
    }

    fn fail_sent(&self, ticket: Ticket, epoch: u64, e: RpcError) {
        let mut fires = Vec::new();
        {
            let mut g = lock(&self.sh.st);
            if g.flight.get(&ticket).is_some_and(|f| f.epoch == epoch)
                && let Some(f) = leave(&mut g, ticket)
            {
                complete(&mut g, &mut fires, ticket, f.item.sink, Err(e));
            }
        }
        self.sh.fire(fires);
    }

    // sends the front op and its chunks; the generation of the link when it turned out to be dead
    fn send(&mut self) -> Option<u64> {
        let (ticket, deadline) = {
            let g = lock(&self.sh.st);
            let i = g.queue.front()?;
            (i.ticket, i.deadline)
        };
        let known = self.conn.clone();
        let (slot_gen, remote) = match known {
            Some(c) => c,
            None => match self.sh.link(None, deadline) {
                Some(c) => {
                    self.conn = Some(c.clone());
                    c
                }
                None => {
                    self.fail_queued(ticket, RpcError::Closed);
                    return None;
                }
            },
        };
        let (epoch, op, payload) = {
            let mut g = lock(&self.sh.st);
            if g.closed || g.queue.front().is_none_or(|i| i.ticket != ticket) {
                return None;
            }
            let item = g.queue.pop_front()?;
            g.epoch += 1;
            let epoch = g.epoch;
            if item.streamed {
                g.streams += 1;
            }
            let sent = (epoch, item.op.clone(), item.payload.clone());
            g.flight.insert(
                ticket,
                Flight {
                    item,
                    epoch,
                    slot_gen,
                    remote: remote.clone(),
                    id: None,
                },
            );
            sent
        };
        let id = loop {
            match remote.submit(op.clone(), self.callback(ticket, epoch)) {
                Ok(id) => break id,
                Err(RpcError::Closed) => return Some(slot_gen),
                Err(RpcError::Busy) if Instant::now() < deadline && !self.sh.is_closed() => {
                    std::thread::sleep(SUBMIT_RETRY)
                }
                Err(e) => {
                    self.fail_sent(ticket, epoch, e);
                    return None;
                }
            }
        };
        let live = {
            let mut g = lock(&self.sh.st);
            match g.flight.get_mut(&ticket) {
                Some(f) if f.epoch == epoch => {
                    f.id = Some(id);
                    true
                }
                _ => false,
            }
        };
        if !live {
            remote.cancel(id);
            return None;
        }
        match send_chunks(&*remote, id, &payload) {
            Ok(()) => None,
            Err(RpcError::Closed) => Some(slot_gen),
            Err(e) => {
                self.fail_sent(ticket, epoch, e);
                remote.cancel(id);
                None
            }
        }
    }

    // every op the host has not answered goes again, in order, on the next link and before anything newer
    fn reconnect(&mut self, slot_gen: u64) {
        self.conn = None;
        let mut fires = Vec::new();
        {
            let mut g = lock(&self.sh.st);
            let now = Instant::now();
            while let Some(b) = g.replies.pop_front() {
                on_reply(&mut g, b, now, &mut fires);
            }
            let sent: Vec<Ticket> = g.flight.keys().copied().collect();
            for t in sent {
                let Some(mut f) = leave(&mut g, t) else {
                    continue;
                };
                f.item.replays += 1;
                if f.item.replays > REPLAYS {
                    complete(&mut g, &mut fires, t, f.item.sink, Err(RpcError::Closed));
                } else {
                    f.item.not_before = None;
                    requeue(&mut g.queue, f.item);
                }
            }
        }
        self.sh.fire(fires);
        loop {
            let soonest = {
                let g = lock(&self.sh.st);
                if g.closed {
                    return;
                }
                g.queue.iter().map(|i| i.deadline).min()
            };
            let Some(soonest) = soonest else { return };
            if let Some(c) = self.sh.link(Some(slot_gen), soonest) {
                self.conn = Some(c);
                return;
            }
            let mut fires = Vec::new();
            let last = self.sh.remote.is_closed();
            {
                let mut g = lock(&self.sh.st);
                expire(&mut g, Instant::now(), &mut fires, &mut Vec::new());
                if last {
                    while let Some(it) = g.queue.pop_front() {
                        complete(
                            &mut g,
                            &mut fires,
                            it.ticket,
                            it.sink,
                            Err(RpcError::Closed),
                        );
                    }
                }
            }
            self.sh.fire(fires);
            if last {
                return;
            }
        }
    }
}

impl Pipe {
    pub fn new(remote: Arc<RemoteSlot>, landed: Sender<Landed>) -> io::Result<Arc<Self>> {
        let sh = Arc::new(Shared {
            remote,
            landed,
            st: Mutex::new(State {
                next: 1,
                epoch: 0,
                queue: VecDeque::new(),
                flight: BTreeMap::new(),
                replies: VecDeque::new(),
                results: FxHashMap::default(),
                streams: 0,
                closed: false,
            }),
            wake: Condvar::new(),
            done: Condvar::new(),
        });
        let worker = Worker {
            sh: sh.clone(),
            conn: None,
        };
        let join = std::thread::Builder::new()
            .name("csync-pipe".into())
            .spawn(move || worker.run())?;
        Ok(Arc::new(Self {
            sh,
            join: Mutex::new(Some(join)),
        }))
    }

    // enqueues in ticket order; blocks only while the window is full, until the deadline
    pub fn push(
        &self,
        op: Op,
        payload: Payload,
        tag: Tag,
        deadline: Instant,
    ) -> Result<Ticket, i32> {
        let sink = match tag {
            Tag::Sync => Sink::Wait,
            other => Sink::Land(other),
        };
        self.sh.push(op, payload, sink, deadline)
    }

    // like push, but the answer is handed to `done` on the sender thread instead of a waiter or the channel
    pub fn push_with(
        &self,
        op: Op,
        payload: Payload,
        deadline: Instant,
        done: Done,
    ) -> Result<Ticket, i32> {
        self.sh.push(op, payload, Sink::Call(done), deadline)
    }

    // for a Tag::Sync ticket; past the deadline the op is cancelled and its timeout is the answer
    pub fn wait(&self, t: Ticket, deadline: Instant) -> Result<Reply, RpcError> {
        let mut g = lock(&self.sh.st);
        loop {
            if let Some(r) = g.results.remove(&t) {
                return r;
            }
            if !g.pending(t) {
                return Err(RpcError::Closed);
            }
            let now = Instant::now();
            if now >= deadline {
                drop(g);
                self.sh.cancel(t);
                return lock(&self.sh.st)
                    .results
                    .remove(&t)
                    .unwrap_or(Err(RpcError::Timeout));
            }
            g = park(&self.sh.done, g, deadline - now);
        }
    }

    pub fn cancel(&self, t: Ticket) {
        self.sh.cancel(t);
    }

    // folds a mode or mtime change into the newest op for `path` at `ver` that has not been sent: a commit of that
    // version, or a setattr that expects it. false when none is left to fold into. an op that went out once and came
    // back (a replay, a busy retry) may already have landed without the change, so it is never amended
    pub fn amend(
        &self,
        path: &RelPath,
        ver: Version,
        perm: Option<u16>,
        mtime_ns: Option<i64>,
    ) -> bool {
        let mut g = lock(&self.sh.st);
        for it in g.queue.iter_mut().rev() {
            if it.replays > 0 || it.not_before.is_some() {
                continue;
            }
            match &mut it.op {
                Op::Commit {
                    path: p,
                    new,
                    perm: cp,
                    mtime_ns: cm,
                    ..
                } if p == path && *new == ver => {
                    *cp = perm.or(*cp);
                    *cm = mtime_ns.or(*cm);
                    return true;
                }
                Op::SetAttr {
                    path: p,
                    expect: Expect::Is(v),
                    perm: sp,
                    mtime_ns: sm,
                } if p == path && *v == ver => {
                    *sp = perm.or(*sp);
                    *sm = mtime_ns.or(*sm);
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    // removes the ops not yet sent that name a path below `dir` (the entry that held them was refused) and answers
    // each with NotFound; ops already on the wire fail on their own. returns the tickets removed
    pub fn drop_under(&self, dir: &RelPath) -> Vec<Ticket> {
        let mut fires = Vec::new();
        let mut gone = Vec::new();
        {
            let mut g = lock(&self.sh.st);
            let mut i = 0;
            while i < g.queue.len() {
                if below(&g.queue[i].op, dir)
                    && let Some(it) = g.queue.remove(i)
                {
                    gone.push(it.ticket);
                    let err = Err(RpcError::Wire(WireErr::NotFound));
                    complete(&mut g, &mut fires, it.ticket, it.sink, err);
                } else {
                    i += 1;
                }
            }
        }
        self.sh.fire(fires);
        gone
    }

    pub fn is_closed(&self) -> bool {
        self.sh.is_closed()
    }

    // fails everything not yet answered with Closed and joins the sender; requests already sent are left to land
    pub fn close(&self) {
        let mut fires = Vec::new();
        {
            let mut g = lock(&self.sh.st);
            g.closed = true;
            g.replies.clear();
            let sent: Vec<Ticket> = g.flight.keys().copied().collect();
            for t in sent {
                if let Some(f) = leave(&mut g, t) {
                    complete(&mut g, &mut fires, t, f.item.sink, Err(RpcError::Closed));
                }
            }
            while let Some(it) = g.queue.pop_front() {
                complete(
                    &mut g,
                    &mut fires,
                    it.ticket,
                    it.sink,
                    Err(RpcError::Closed),
                );
            }
        }
        self.sh.wake.notify_all();
        self.sh.fire(fires);
        if let Some(j) = lock(&self.join).take() {
            let _ = j.join();
        }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::rpc::ChunkSink;
    use crate::proto::Mk;
    use crossbeam_channel::{Receiver, unbounded};
    use std::fs::File;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    #[derive(Default)]
    struct Fake {
        script: Mutex<VecDeque<Result<Reply, RpcError>>>,
        log: Mutex<Vec<Op>>,
        held: Mutex<VecDeque<Done>>,
        dead: AtomicBool,
    }

    impl Fake {
        fn scripted(rs: Vec<Result<Reply, RpcError>>) -> Arc<Self> {
            let f = Arc::new(Self::default());
            lock(&f.script).extend(rs);
            f
        }

        fn names(&self) -> Vec<String> {
            lock(&self.log)
                .iter()
                .map(|o| match o {
                    Op::Remove { path, .. }
                    | Op::Commit { path, .. }
                    | Op::Mk { path, .. }
                    | Op::SetAttr { path, .. } => path.as_str().to_string(),
                    o => panic!("unexpected {o:?}"),
                })
                .collect()
        }

        fn sent(&self) -> usize {
            lock(&self.log).len()
        }

        fn held(&self) -> usize {
            lock(&self.held).len()
        }

        fn answer(&self, r: Result<Reply, RpcError>) {
            let d = lock(&self.held).pop_front().expect("nothing held");
            d(r);
        }

        // like a closed Rpc: what was sent fails with Closed and nothing more is accepted
        fn drop_link(&self) {
            self.dead.store(true, Ordering::SeqCst);
            let all: Vec<Done> = lock(&self.held).drain(..).collect();
            for d in all {
                d(Err(RpcError::Closed));
            }
        }
    }

    impl Remote for Fake {
        fn call(&self, _op: Op, _d: Instant) -> Result<Reply, RpcError> {
            Err(RpcError::Closed)
        }
        fn call_stream(
            &self,
            _op: Op,
            _s: Box<dyn ChunkSink>,
            _d: Instant,
        ) -> Result<Reply, RpcError> {
            Err(RpcError::Closed)
        }
        fn submit(&self, op: Op, done: Done) -> Result<ReqId, RpcError> {
            if self.dead.load(Ordering::SeqCst) {
                return Err(RpcError::Closed);
            }
            let next = lock(&self.script).pop_front();
            match next {
                Some(r) => done(r),
                None => lock(&self.held).push_back(done),
            }
            // logged last, so a counted send is already held
            let mut l = lock(&self.log);
            l.push(op);
            Ok(l.len() as ReqId)
        }
        fn submit_stream(
            &self,
            _op: Op,
            _s: Box<dyn ChunkSink>,
            _done: Done,
        ) -> Result<ReqId, RpcError> {
            Err(RpcError::Closed)
        }
        fn send_chunk(
            &self,
            _id: ReqId,
            _off: u64,
            _last: bool,
            _data: Vec<u8>,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        fn cancel(&self, _id: ReqId) {}
    }

    fn meta() -> Meta {
        Meta {
            kind: Kind::File,
            perm: 0o644,
            size: 0,
            mtime_ns: 1,
            ctime_ns: 1,
            hash: None,
            link: None,
            git_ro: false,
        }
    }

    fn done() -> Result<Reply, RpcError> {
        Ok(Reply::Done { meta: meta() })
    }

    fn busy() -> Result<Reply, RpcError> {
        Err(RpcError::Wire(WireErr::Busy))
    }

    fn rm(name: &str) -> Op {
        Op::Remove {
            path: crate::proto::RelPath::new(name).unwrap(),
            expect: Expect::Any,
        }
    }

    fn upload(name: &str) -> (Op, Payload) {
        let op = Op::Commit {
            path: crate::proto::RelPath::new(name).unwrap(),
            base: Expect::Absent,
            new: Version {
                hash: [0; 32],
                size: 1,
            },
            perm: None,
            body: Body::Stream { len: 1 },
            sync: false,
            mtime_ns: None,
        };
        let fd = OwnedFd::from(File::open("/dev/zero").unwrap());
        (op, Payload::File { fd, len: 1 })
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(20)
    }

    fn until(what: &str, f: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !f() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn rig(first: &Arc<Fake>) -> (Arc<RemoteSlot>, Arc<Pipe>, Receiver<Landed>) {
        let slot = RemoteSlot::new();
        slot.set(Some(first.clone() as Arc<dyn Remote>));
        let (tx, rx) = unbounded();
        let pipe = Pipe::new(slot.clone(), tx).unwrap();
        (slot, pipe, rx)
    }

    fn push(p: &Pipe, name: &str) -> Ticket {
        p.push(rm(name), Payload::None, Tag::Sync, later()).unwrap()
    }

    fn is_done(r: Result<Reply, RpcError>) -> bool {
        matches!(r, Ok(Reply::Done { .. }))
    }

    #[test]
    fn ops_are_sent_in_ticket_order() {
        let fake = Fake::scripted((0..20).map(|_| done()).collect());
        let (_slot, pipe, _rx) = rig(&fake);
        let names: Vec<String> = (0..20).map(|i| format!("f{i}")).collect();
        let tickets: Vec<Ticket> = names.iter().map(|n| push(&pipe, n)).collect();
        assert!(tickets.windows(2).all(|w| w[0] < w[1]));
        for t in tickets {
            assert!(is_done(pipe.wait(t, later())));
        }
        assert_eq!(fake.names(), names);
    }

    #[test]
    fn busy_is_retried_in_place_without_reordering() {
        let fake = Fake::scripted(vec![busy(), done(), done(), done()]);
        let (_slot, pipe, _rx) = rig(&fake);
        let tickets: Vec<Ticket> = ["a", "b", "c"].iter().map(|n| push(&pipe, n)).collect();
        for t in tickets {
            assert!(is_done(pipe.wait(t, later())));
        }
        assert_eq!(fake.names(), ["a", "a", "b", "c"]);
    }

    #[test]
    fn busy_past_the_deadline_is_surfaced() {
        let fake = Fake::scripted((0..64).map(|_| busy()).collect());
        let (_slot, pipe, _rx) = rig(&fake);
        let dl = Instant::now() + Duration::from_millis(100);
        let t = pipe.push(rm("a"), Payload::None, Tag::Sync, dl).unwrap();
        assert!(matches!(
            pipe.wait(t, dl + Duration::from_secs(5)),
            Err(RpcError::Wire(WireErr::Busy))
        ));
    }

    #[test]
    fn unanswered_ops_replay_in_order_after_a_reconnect() {
        let first = Fake::scripted(Vec::new());
        let (slot, pipe, _rx) = rig(&first);
        let (a, b, c) = (push(&pipe, "a"), push(&pipe, "b"), push(&pipe, "c"));
        until("three sends", || first.held() == 3);
        first.answer(done());
        assert!(is_done(pipe.wait(a, later())));

        first.drop_link();
        let d = push(&pipe, "d");
        let second = Fake::scripted(vec![done(), done(), done()]);
        slot.set(Some(second.clone() as Arc<dyn Remote>));
        for t in [b, c, d] {
            assert!(is_done(pipe.wait(t, later())));
        }
        assert_eq!(first.names(), ["a", "b", "c"]);
        assert_eq!(second.names(), ["b", "c", "d"]);
    }

    #[test]
    fn an_op_is_replayed_once() {
        let first = Fake::scripted(Vec::new());
        let (slot, pipe, _rx) = rig(&first);
        let t = push(&pipe, "a");
        until("the send", || first.held() == 1);
        first.drop_link();
        let second = Fake::scripted(Vec::new());
        slot.set(Some(second.clone() as Arc<dyn Remote>));
        until("the replay", || second.held() == 1);
        second.drop_link();
        let third = Fake::scripted(vec![done()]);
        slot.set(Some(third.clone() as Arc<dyn Remote>));
        assert!(matches!(pipe.wait(t, later()), Err(RpcError::Closed)));
        assert_eq!(third.sent(), 0);
    }

    #[test]
    fn a_replayed_remove_answered_not_found_counts_as_done() {
        let first = Fake::scripted(Vec::new());
        let (slot, pipe, _rx) = rig(&first);
        let t = push(&pipe, "gone");
        until("the send", || first.held() == 1);
        first.drop_link();
        let second = Fake::scripted(vec![Err(RpcError::Wire(WireErr::NotFound))]);
        slot.set(Some(second.clone() as Arc<dyn Remote>));
        assert!(is_done(pipe.wait(t, later())));
        assert_eq!(second.names(), ["gone"]);
    }

    #[test]
    fn a_remove_answered_not_found_the_first_time_is_an_error() {
        let fake = Fake::scripted(vec![Err(RpcError::Wire(WireErr::NotFound))]);
        let (_slot, pipe, _rx) = rig(&fake);
        let t = push(&pipe, "gone");
        assert!(matches!(
            pipe.wait(t, later()),
            Err(RpcError::Wire(WireErr::NotFound))
        ));
    }

    #[test]
    fn streamed_uploads_in_flight_stay_at_the_cap() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        let tickets: Vec<Ticket> = (0..=STREAMS)
            .map(|i| {
                let (op, payload) = upload(&format!("u{i}"));
                pipe.push(op, payload, Tag::Sync, later()).unwrap()
            })
            .collect();
        until("the cap", || fake.sent() == STREAMS);
        thread::sleep(Duration::from_millis(150));
        assert_eq!(
            fake.sent(),
            STREAMS,
            "the next upload waits for one to finish"
        );
        fake.answer(done());
        until("the last upload", || fake.sent() == STREAMS + 1);
        for _ in 0..STREAMS {
            fake.answer(done());
        }
        for t in tickets {
            assert!(is_done(pipe.wait(t, later())));
        }
    }

    #[test]
    fn an_op_behind_a_capped_upload_keeps_its_place() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        for i in 0..=STREAMS {
            let (op, payload) = upload(&format!("u{i}"));
            pipe.push(op, payload, Tag::Sync, later()).unwrap();
        }
        push(&pipe, "after");
        until("the cap", || fake.sent() == STREAMS);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(fake.sent(), STREAMS);
        fake.answer(done());
        until("the rest", || fake.sent() == STREAMS + 2);
        let names = fake.names();
        assert_eq!(names[STREAMS], format!("u{STREAMS}"));
        assert_eq!(names[STREAMS + 1], "after");
    }

    #[test]
    fn push_blocks_at_the_window_and_resumes() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        for i in 0..WINDOW {
            push(&pipe, &format!("w{i}"));
        }
        let (tx, rx) = crossbeam_channel::bounded(1);
        let blocked = Arc::new(AtomicBool::new(true));
        let h = {
            let (pipe, blocked) = (pipe.clone(), blocked.clone());
            thread::spawn(move || {
                let r = pipe.push(rm("over"), Payload::None, Tag::Sync, later());
                blocked.store(false, Ordering::SeqCst);
                let _ = tx.send(r);
            })
        };
        thread::sleep(Duration::from_millis(150));
        assert!(
            blocked.load(Ordering::SeqCst),
            "push returned with a full window"
        );
        until("a send", || fake.held() >= 1);
        fake.answer(done());
        let r = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(r.is_ok());
        h.join().unwrap();
    }

    #[test]
    fn a_full_window_gives_up_at_the_deadline() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        for i in 0..WINDOW {
            push(&pipe, &format!("w{i}"));
        }
        let dl = Instant::now() + Duration::from_millis(50);
        assert_eq!(
            pipe.push(rm("over"), Payload::None, Tag::Sync, dl),
            Err(libc::EIO)
        );
    }

    #[test]
    fn close_fails_pending_waiters_and_later_pushes() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        let sent = push(&pipe, "sent");
        until("the send", || fake.held() == 1);
        let queued = pipe
            .push(rm("q"), Payload::None, Tag::Sync, later())
            .unwrap();
        let waiters: Vec<_> = [sent, queued]
            .into_iter()
            .map(|t| {
                let p = pipe.clone();
                thread::spawn(move || p.wait(t, later()))
            })
            .collect();
        thread::sleep(Duration::from_millis(50));
        pipe.close();
        for w in waiters {
            assert!(matches!(w.join().unwrap(), Err(RpcError::Closed)));
        }
        assert_eq!(
            pipe.push(rm("late"), Payload::None, Tag::Sync, later()),
            Err(libc::EIO)
        );
    }

    #[test]
    fn other_tags_complete_on_the_landed_channel() {
        let fake = Fake::scripted(vec![done(), Err(RpcError::Wire(WireErr::Denied))]);
        let (_slot, pipe, rx) = rig(&fake);
        let a = pipe
            .push(rm("a"), Payload::None, Tag::Staged(7), later())
            .unwrap();
        let b = pipe
            .push(rm("b"), Payload::None, Tag::Node(9), later())
            .unwrap();
        let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((first.ticket, first.tag), (a, Tag::Staged(7)));
        assert!(is_done(first.res));
        assert_eq!((second.ticket, second.tag), (b, Tag::Node(9)));
        assert!(matches!(second.res, Err(RpcError::Wire(WireErr::Denied))));
    }

    #[test]
    fn push_with_hands_the_answer_to_its_callback() {
        let fake = Fake::scripted(vec![done()]);
        let (_slot, pipe, _rx) = rig(&fake);
        let (tx, rx) = crossbeam_channel::bounded(1);
        pipe.push_with(
            rm("a"),
            Payload::None,
            later(),
            Box::new(move |r| {
                let _ = tx.send(r);
            }),
        )
        .unwrap();
        assert!(is_done(rx.recv_timeout(Duration::from_secs(5)).unwrap()));
    }

    #[test]
    fn cancel_completes_a_sent_op_with_a_timeout() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        let t = push(&pipe, "a");
        until("the send", || fake.held() == 1);
        pipe.cancel(t);
        assert!(matches!(pipe.wait(t, later()), Err(RpcError::Timeout)));
    }

    #[test]
    fn a_late_answer_to_a_timed_out_op_is_dropped() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        let t = pipe
            .push(
                rm("a"),
                Payload::None,
                Tag::Sync,
                Instant::now() + Duration::from_millis(60),
            )
            .unwrap();
        assert!(matches!(pipe.wait(t, later()), Err(RpcError::Timeout)));
        fake.answer(done());
        let next = push(&pipe, "b");
        until("the next send", || fake.held() == 1);
        fake.answer(done());
        assert!(is_done(pipe.wait(next, later())));
    }

    // the shutdown hang: an unmount waits on a release whose op waits for a link the stopped dialer never brings
    #[test]
    fn ops_stop_waiting_for_a_link_once_none_can_come() {
        let fake = Fake::scripted(Vec::new());
        let (slot, pipe, _rx) = rig(&fake);
        slot.set(None);
        let queued = push(&pipe, "q");
        let p = pipe.clone();
        let waiter = thread::spawn(move || {
            let t0 = Instant::now();
            (p.wait(queued, later()), t0.elapsed())
        });
        thread::sleep(Duration::from_millis(100));
        slot.close();
        let (r, took) = waiter.join().unwrap();
        assert!(matches!(r, Err(RpcError::Closed)), "{r:?}");
        assert!(took < Duration::from_secs(2), "waited {took:?}");
        let t0 = Instant::now();
        let late = push(&pipe, "late");
        assert!(matches!(pipe.wait(late, later()), Err(RpcError::Closed)));
        assert!(t0.elapsed() < Duration::from_secs(2));
        assert_eq!(fake.sent(), 0);
    }

    #[test]
    fn a_link_lost_after_the_last_one_fails_its_ops_at_once() {
        let fake = Fake::scripted(Vec::new());
        let (slot, pipe, _rx) = rig(&fake);
        slot.close();
        let (a, b) = (push(&pipe, "a"), push(&pipe, "b"));
        until("two sends", || fake.held() == 2);
        let t0 = Instant::now();
        slot.set(None);
        fake.drop_link();
        assert!(matches!(pipe.wait(a, later()), Err(RpcError::Closed)));
        assert!(matches!(pipe.wait(b, later()), Err(RpcError::Closed)));
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_last_link_still_carries_ops() {
        let fake = Fake::scripted(vec![done()]);
        let (slot, pipe, _rx) = rig(&fake);
        slot.close();
        let t = push(&pipe, "a");
        assert!(is_done(pipe.wait(t, later())));
        assert_eq!(fake.names(), ["a"]);
    }

    fn the_version() -> Version {
        Version {
            hash: [0; 32],
            size: 1,
        }
    }

    // the first STREAMS uploads fill the cap, so whatever is pushed after them stays queued
    fn fill(pipe: &Pipe, first: &str) -> Vec<Ticket> {
        (0..STREAMS)
            .map(|i| {
                let name = if i == 0 {
                    first.to_string()
                } else {
                    format!("u{i}")
                };
                let (op, payload) = upload(&name);
                pipe.push(op, payload, Tag::Sync, later()).unwrap()
            })
            .collect()
    }

    fn answer_all(fake: &Fake, pipe: &Pipe, tickets: Vec<Ticket>) {
        while fake.held() > 0 {
            fake.answer(done());
        }
        for t in tickets {
            assert!(is_done(pipe.wait(t, later())));
        }
    }

    #[test]
    fn amend_folds_a_mode_and_mtime_into_an_unsent_commit() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        let mut tickets = fill(&pipe, "first");
        until("the cap", || fake.sent() == STREAMS);
        let (op, payload) = upload("late");
        tickets.push(pipe.push(op, payload, Tag::Sync, later()).unwrap());
        let late = RelPath::new("late").unwrap();
        let ver = the_version();

        assert!(pipe.amend(&late, ver, Some(0o600), None));
        assert!(pipe.amend(&late, ver, None, Some(77)));
        assert!(!pipe.amend(&RelPath::new("other").unwrap(), ver, Some(1), None));
        let other = Version {
            hash: [1; 32],
            size: 1,
        };
        assert!(!pipe.amend(&late, other, Some(1), None));

        fake.answer(done());
        until("the last upload", || fake.sent() == STREAMS + 1);
        match lock(&fake.log).last() {
            Some(Op::Commit { perm, mtime_ns, .. }) => {
                assert_eq!((*perm, *mtime_ns), (Some(0o600), Some(77)))
            }
            o => panic!("unexpected {o:?}"),
        }
        assert!(
            !pipe.amend(&late, ver, Some(0o644), None),
            "a sent commit is not amended"
        );
        answer_all(&fake, &pipe, tickets);
    }

    #[test]
    fn amend_folds_into_an_unsent_setattr_that_expects_the_version() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        let mut tickets = fill(&pipe, "first");
        until("the cap", || fake.sent() == STREAMS);
        let (op, payload) = upload("late");
        tickets.push(pipe.push(op, payload, Tag::Sync, later()).unwrap());
        let p = RelPath::new("p").unwrap();
        let ver = the_version();
        let attr = Op::SetAttr {
            path: p.clone(),
            expect: Expect::Is(ver),
            perm: Some(0o600),
            mtime_ns: None,
        };
        tickets.push(pipe.push(attr, Payload::None, Tag::Sync, later()).unwrap());

        assert!(pipe.amend(&p, ver, None, Some(9)));
        let other = Version {
            hash: [2; 32],
            size: 1,
        };
        assert!(!pipe.amend(&p, other, None, Some(1)));
        fake.answer(done());
        until("the setattr", || fake.sent() == STREAMS + 2);
        match lock(&fake.log).last() {
            Some(Op::SetAttr { perm, mtime_ns, .. }) => {
                assert_eq!((*perm, *mtime_ns), (Some(0o600), Some(9)))
            }
            o => panic!("unexpected {o:?}"),
        }
        assert!(!pipe.amend(&p, ver, Some(1), None));
        answer_all(&fake, &pipe, tickets);
    }

    #[test]
    fn drop_under_removes_unsent_descendants_and_leaves_sent_ones() {
        let fake = Fake::scripted(Vec::new());
        let (_slot, pipe, _rx) = rig(&fake);
        let mut tickets = fill(&pipe, "d/sent");
        until("the cap", || fake.sent() == STREAMS);
        let (op, payload) = upload("d/a");
        let a = pipe.push(op, payload, Tag::Sync, later()).unwrap();
        let b = push(&pipe, "d/b");
        let (tx, rx) = crossbeam_channel::bounded(1);
        let mk = Op::Mk {
            path: RelPath::new("d/m").unwrap(),
            what: Mk::Dir { perm: 0o755 },
        };
        let cb = Box::new(move |r| {
            let _ = tx.send(r);
        });
        pipe.push_with(mk, Payload::None, later(), cb).unwrap();
        tickets.push(push(&pipe, "d"));
        tickets.push(push(&pipe, "e/x"));

        let mut gone = pipe.drop_under(&RelPath::new("d").unwrap());
        gone.sort();
        assert_eq!(gone.len(), 3);
        assert!(gone.contains(&a) && gone.contains(&b));
        for t in [a, b] {
            assert!(matches!(
                pipe.wait(t, later()),
                Err(RpcError::Wire(WireErr::NotFound))
            ));
        }
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(RpcError::Wire(WireErr::NotFound))
        ));
        until("the rest", || fake.sent() == STREAMS + 2);
        let names = fake.names();
        assert_eq!(names[0], "d/sent");
        assert_eq!(names[STREAMS..], ["d", "e/x"]);
        answer_all(&fake, &pipe, tickets);
    }

    fn lone(op: Op, at: Instant) -> State {
        let item = Item {
            ticket: 1,
            op,
            payload: Arc::new(Payload::None),
            sink: Sink::Wait,
            queued: at,
            deadline: at,
            streamed: false,
            replays: 0,
            backoff: BUSY_MIN,
            not_before: None,
        };
        State {
            next: 2,
            epoch: 0,
            queue: VecDeque::from([item]),
            flight: BTreeMap::new(),
            replies: VecDeque::new(),
            results: FxHashMap::default(),
            streams: 0,
            closed: false,
        }
    }

    fn commit_op(base: Expect, sync: bool) -> Op {
        Op::Commit {
            path: RelPath::new("f").unwrap(),
            base,
            new: the_version(),
            perm: Some(0o644),
            body: Body::Empty,
            sync,
            mtime_ns: None,
        }
    }

    #[test]
    fn only_a_lone_unsynced_new_file_commit_lingers() {
        let t0 = Instant::now();
        let new = commit_op(Expect::Absent, false);
        assert_eq!(lone(new.clone(), t0).linger_end(), Some(t0 + LINGER));

        let mut behind = lone(new.clone(), t0);
        let second = lone(rm("g"), t0).queue.pop_front().unwrap();
        behind.queue.push_back(second);
        assert_eq!(behind.linger_end(), None, "an op behind ends the wait");

        assert_eq!(lone(commit_op(Expect::Absent, true), t0).linger_end(), None);
        let edit = commit_op(Expect::Is(the_version()), false);
        assert_eq!(lone(edit, t0).linger_end(), None);
        assert_eq!(lone(rm("g"), t0).linger_end(), None);

        let mut again = lone(new, t0);
        again.queue[0].replays = 1;
        assert_eq!(again.linger_end(), None, "a replay goes out at once");
    }

    #[test]
    fn a_lone_new_file_commit_is_sent_after_the_linger_not_before() {
        let fake = Fake::scripted(vec![done()]);
        let (_slot, pipe, _rx) = rig(&fake);
        let t0 = Instant::now();
        let t = pipe
            .push(
                commit_op(Expect::Absent, false),
                Payload::None,
                Tag::Sync,
                later(),
            )
            .unwrap();
        assert!(is_done(pipe.wait(t, later())));
        assert!(t0.elapsed() >= LINGER);
        assert_eq!(fake.names(), ["f"]);
    }
}
