use crate::net::conn::{In, Link};
use crate::proto::{Body, Expect, FILE_MAX, INFLIGHT_MAX, Msg, Op, RelPath, Reply, ReqId, WireErr};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded};
use rustc_hash::FxHashMap;
use std::{
    io,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::Instant,
};

pub trait ChunkSink: Send {
    fn chunk(&mut self, off: u64, data: &[u8], last: bool) -> io::Result<()>;
}
#[derive(Debug)]
pub enum RpcError {
    Wire(WireErr),
    Closed,
    Timeout,
    Busy,
}

type Done = Box<dyn FnOnce(Result<Reply, RpcError>) + Send>;

enum Waiter {
    Sync(Sender<Result<Reply, RpcError>>),
    Async(Done),
}

impl Waiter {
    fn fire(self, r: Result<Reply, RpcError>) {
        match self {
            Self::Sync(tx) => {
                let _ = tx.try_send(r);
            }
            Self::Async(f) => f(r),
        }
    }
}

struct Pending {
    waiter: Option<Waiter>,
    sink: Option<Box<dyn ChunkSink>>,
    streamed: bool,
    sink_busy: bool,
    reply: Option<Result<Reply, WireErr>>,
    resp: bool,
    wants: bool,
    last: bool,
    next_off: Option<u64>,
    cancelled: bool,
    // a directory move, answered in order with the pushes around it
    moves: Option<Box<(RelPath, RelPath)>>,
    queued: bool,
}

// the guest moves a directory in its own tree only on the reply, so the reply keeps its place in the push
// stream: pushes before it name the old path, pushes after it the new one
fn ordered(op: &Op) -> Option<Box<(RelPath, RelPath)>> {
    match op {
        Op::Rename {
            from,
            to,
            from_expect: Expect::Dir,
            body: None,
            ..
        } => Some(Box::new((from.clone(), to.clone()))),
        _ => None,
    }
}

impl Pending {
    // the slot stays taken until the peer has answered, so both ends agree on the in-flight count
    fn removable(&self) -> bool {
        self.resp && (self.cancelled || self.last || !self.wants)
    }

    fn fail(&mut self, e: RpcError) -> After {
        self.cancelled = true;
        if !self.sink_busy {
            self.sink = None;
        }
        self.reply = None;
        After {
            fire: self.waiter.take().map(|w| (w, Err(e))),
            cancel: !(self.resp && self.last),
        }
    }
}

#[derive(Default)]
struct After {
    fire: Option<(Waiter, Result<Reply, RpcError>)>,
    cancel: bool,
}

struct Table {
    map: FxHashMap<ReqId, Pending>,
    next: ReqId,
    closed: bool,
}

pub struct Rpc {
    link: Link,
    t: Mutex<Table>,
    slot: Condvar,
}

fn wants_chunks(r: &Reply) -> bool {
    match r {
        Reply::Blob {
            body: Body::Stream { len },
            ..
        } => *len > 0,
        Reply::Blob {
            body: Body::Delta { data_len, .. },
            ..
        } => *data_len > 0,
        _ => false,
    }
}

impl Rpc {
    pub fn new(link: Link) -> Arc<Self> {
        let rpc = Arc::new(Self {
            link,
            t: Mutex::new(Table {
                map: FxHashMap::default(),
                next: 1,
                closed: false,
            }),
            slot: Condvar::new(),
        });
        rpc.link.attach_router(&rpc);
        rpc
    }

    pub fn link(&self) -> &Link {
        &self.link
    }

    pub fn inflight(&self) -> usize {
        self.lock().map.len()
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.t.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn register(
        &self,
        waiter: Waiter,
        sink: Option<Box<dyn ChunkSink>>,
        deadline: Option<Instant>,
        moves: Option<Box<(RelPath, RelPath)>>,
    ) -> Result<ReqId, RpcError> {
        let mut t = self.lock();
        loop {
            if t.closed || self.link.is_closed() {
                return Err(RpcError::Closed);
            }
            if t.map.len() < INFLIGHT_MAX {
                break;
            }
            let Some(d) = deadline else {
                return Err(RpcError::Busy);
            };
            let now = Instant::now();
            if now >= d {
                return Err(RpcError::Timeout);
            }
            t = match self.slot.wait_timeout(t, d - now) {
                Ok((g, _)) => g,
                Err(e) => e.into_inner().0,
            };
        }
        let id = loop {
            let id = t.next;
            t.next = t.next.wrapping_add(1);
            if !t.map.contains_key(&id) {
                break id;
            }
        };
        let streamed = sink.is_some();
        t.map.insert(
            id,
            Pending {
                waiter: Some(waiter),
                sink,
                streamed,
                sink_busy: false,
                reply: None,
                resp: false,
                wants: false,
                last: false,
                next_off: None,
                cancelled: false,
                moves,
                queued: false,
            },
        );
        Ok(id)
    }

    fn start(
        &self,
        op: Op,
        waiter: Waiter,
        sink: Option<Box<dyn ChunkSink>>,
        deadline: Option<Instant>,
    ) -> Result<ReqId, RpcError> {
        let id = self.register(waiter, sink, deadline, ordered(&op))?;
        if self.link.send(Msg::Req { id, op }).is_err() {
            let mut t = self.lock();
            // absent means fail_all already fired the waiter with Closed
            if t.map.remove(&id).is_some() {
                drop(t);
                self.slot.notify_one();
                return Err(RpcError::Closed);
            }
        }
        Ok(id)
    }

    fn wait(
        &self,
        id: ReqId,
        rx: Receiver<Result<Reply, RpcError>>,
        deadline: Instant,
    ) -> Result<Reply, RpcError> {
        match rx.recv_deadline(deadline) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => {
                self.cancel(id);
                rx.try_recv().unwrap_or(Err(RpcError::Timeout))
            }
            Err(RecvTimeoutError::Disconnected) => Err(RpcError::Closed),
        }
    }

    pub fn call(&self, op: Op, deadline: Instant) -> Result<Reply, RpcError> {
        let (tx, rx) = bounded(1);
        let id = self.start(op, Waiter::Sync(tx), None, Some(deadline))?;
        self.wait(id, rx, deadline)
    }

    pub fn call_stream(
        &self,
        op: Op,
        sink: Box<dyn ChunkSink>,
        deadline: Instant,
    ) -> Result<Reply, RpcError> {
        let (tx, rx) = bounded(1);
        let id = self.start(op, Waiter::Sync(tx), Some(sink), Some(deadline))?;
        self.wait(id, rx, deadline)
    }

    pub fn submit(
        &self,
        op: Op,
        done: Box<dyn FnOnce(Result<Reply, RpcError>) + Send>,
    ) -> Result<ReqId, RpcError> {
        self.start(op, Waiter::Async(done), None, None)
    }

    pub fn submit_stream(
        &self,
        op: Op,
        sink: Box<dyn ChunkSink>,
        done: Box<dyn FnOnce(Result<Reply, RpcError>) + Send>,
    ) -> Result<ReqId, RpcError> {
        self.start(op, Waiter::Async(done), Some(sink), None)
    }

    pub fn cancel(&self, id: ReqId) {
        let after = {
            let mut t = self.lock();
            let Some(p) = t.map.get_mut(&id) else { return };
            if p.cancelled {
                return;
            }
            let a = p.fail(RpcError::Timeout);
            if p.removable() {
                t.map.remove(&id);
                self.slot.notify_one();
            }
            a
        };
        self.run(id, after);
    }

    fn run(&self, id: ReqId, a: After) {
        if a.cancel {
            let _ = self.link.send(Msg::Cancel { id });
        }
        if let Some((w, r)) = a.fire {
            w.fire(r);
        }
    }

    // the reader's entry point: an ordered reply is handed back for the inbox, the rest are routed here
    pub(crate) fn on_resp(
        &self,
        id: ReqId,
        res: Result<Reply, WireErr>,
    ) -> Option<Result<Reply, WireErr>> {
        {
            let mut t = self.lock();
            if let Some(p) = t.map.get_mut(&id)
                && p.moves.is_some()
                && !p.resp
                && !p.queued
            {
                p.queued = true;
                return Some(res);
            }
        }
        self.route_resp(id, res);
        None
    }

    // routes a reply taken from the inbox; returns the move it confirmed to a caller still waiting
    pub fn route_ordered(
        &self,
        id: ReqId,
        res: Result<Reply, WireErr>,
    ) -> Option<(RelPath, RelPath)> {
        let moved = if matches!(res, Ok(Reply::Done { .. })) {
            let t = self.lock();
            t.map
                .get(&id)
                .filter(|p| p.waiter.is_some() && !p.cancelled)
                .and_then(|p| p.moves.as_deref().cloned())
        } else {
            None
        };
        self.route_resp(id, res);
        moved
    }

    pub(crate) fn route_resp(&self, id: ReqId, res: Result<Reply, WireErr>) {
        let after = {
            let mut t = self.lock();
            let Some(p) = t.map.get_mut(&id) else { return };
            if p.resp {
                return;
            }
            p.resp = true;
            let wants = matches!(&res, Ok(r) if wants_chunks(r));
            p.wants = wants;
            let mut a = After::default();
            if !p.cancelled {
                if wants && !p.streamed {
                    a = p.fail(RpcError::Wire(WireErr::Invalid));
                } else if !wants || p.last {
                    a.fire = p.waiter.take().map(|w| (w, res.map_err(RpcError::Wire)));
                } else {
                    p.reply = Some(res);
                }
            }
            if p.removable() {
                t.map.remove(&id);
                self.slot.notify_one();
            }
            a
        };
        self.run(id, after);
    }

    pub(crate) fn route_chunk(&self, id: ReqId, off: u64, last: bool, data: &[u8]) -> bool {
        let mut sink = {
            let mut t = self.lock();
            let Some(p) = t.map.get_mut(&id) else {
                return false;
            };
            if p.last {
                return true;
            }
            if p.cancelled {
                p.last = last;
                if p.removable() {
                    t.map.remove(&id);
                    self.slot.notify_one();
                }
                return true;
            }
            let end = off
                .checked_add(data.len() as u64)
                .filter(|&e| e <= FILE_MAX);
            let contiguous = p.next_off.is_none_or(|n| n == off);
            match (p.streamed, end, contiguous, p.sink.take()) {
                (true, Some(e), true, Some(s)) => {
                    p.next_off = Some(e);
                    p.sink_busy = true;
                    s
                }
                _ => {
                    let a = p.fail(RpcError::Wire(WireErr::Invalid));
                    p.last = last;
                    if p.removable() {
                        t.map.remove(&id);
                        self.slot.notify_one();
                    }
                    drop(t);
                    self.run(id, a);
                    return true;
                }
            }
        };
        let wrote = sink.chunk(off, data, last);
        let after = {
            let mut t = self.lock();
            let Some(p) = t.map.get_mut(&id) else {
                return true;
            };
            p.sink_busy = false;
            let mut a = After::default();
            if p.cancelled {
                drop(sink);
            } else if wrote.is_err() {
                drop(sink);
                a = p.fail(RpcError::Wire(WireErr::Io));
            } else {
                p.sink = Some(sink);
            }
            p.last = last;
            if last
                && !p.cancelled
                && p.resp
                && let Some(res) = p.reply.take()
            {
                a.fire = p.waiter.take().map(|w| (w, res.map_err(RpcError::Wire)));
            }
            if p.removable() {
                t.map.remove(&id);
                self.slot.notify_one();
            }
            a
        };
        self.run(id, after);
        true
    }

    pub(crate) fn fail_all(&self) {
        let waiters: Vec<Waiter> = {
            let mut t = self.lock();
            t.closed = true;
            // a reply already in the inbox is still delivered from there, in order
            let mut out = Vec::new();
            t.map.retain(|_, p| {
                if p.queued {
                    return true;
                }
                out.extend(p.waiter.take());
                false
            });
            out
        };
        self.slot.notify_all();
        for w in waiters {
            w.fire(Err(RpcError::Closed));
        }
    }

    pub fn dispatch(&self, inbound: In) -> Option<Msg> {
        match inbound {
            In::Msg(Msg::Resp { id, res }) => {
                self.route_resp(id, res);
                None
            }
            In::Msg(m) => Some(m),
            In::Chunk {
                id,
                off,
                last,
                data,
            } => {
                self.route_chunk(id, off, last, &data);
                None
            }
            In::Closed(_) => {
                self.fail_all();
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::conn::tests::test_pair;
    use crate::proto::{Expect, Kind, Meta, RelPath};
    use std::time::Duration;

    fn op() -> Op {
        Op::Remove {
            path: RelPath::new("f").unwrap(),
            expect: Expect::Any,
        }
    }

    fn done_meta() -> Reply {
        Reply::Done {
            meta: Meta {
                kind: Kind::File,
                perm: 0o644,
                size: 1,
                mtime_ns: 0,
                ctime_ns: 0,
                hash: None,
                link: None,
                git_ro: false,
            },
        }
    }

    fn next_req(s: &crate::net::conn::Session) -> ReqId {
        loop {
            match s
                .inbox
                .recv_timeout(Duration::from_secs(5))
                .expect("no request")
            {
                In::Msg(Msg::Req { id, .. }) => return id,
                In::Closed(r) => panic!("closed {r:?}"),
                _ => {}
            }
        }
    }

    fn wait_until(f: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !f() {
            assert!(Instant::now() < deadline, "condition not reached");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn timeout_cancels_and_holds_slot_until_peer_answers() {
        let (g, h) = test_pair();
        let rpc = Rpc::new(g.link.clone());
        let r = rpc.call(op(), Instant::now() + Duration::from_millis(50));
        assert!(matches!(r, Err(RpcError::Timeout)));
        let id = next_req(&h);
        match h
            .inbox
            .recv_timeout(Duration::from_secs(5))
            .expect("no cancel")
        {
            In::Msg(Msg::Cancel { id: c }) => assert_eq!(c, id),
            _ => panic!("expected cancel"),
        }
        assert_eq!(rpc.inflight(), 1);
        h.link
            .send(Msg::Resp {
                id,
                res: Ok(done_meta()),
            })
            .unwrap();
        wait_until(|| rpc.inflight() == 0);

        let (tx, rx) = bounded(4);
        let id = rpc
            .submit(
                op(),
                Box::new(move |r: Result<Reply, RpcError>| tx.send(r).unwrap()),
            )
            .unwrap();
        assert_eq!(next_req(&h), id);
        rpc.cancel(id);
        rpc.cancel(id);
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(Err(RpcError::Timeout))
        ));
        h.link
            .send(Msg::Resp {
                id,
                res: Ok(done_meta()),
            })
            .unwrap();
        wait_until(|| rpc.inflight() == 0);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn inflight_cap_returns_busy_then_frees_on_reply() {
        let (g, h) = test_pair();
        let rpc = Rpc::new(g.link.clone());
        let (tx, rx) = bounded(INFLIGHT_MAX + 1);
        for _ in 0..INFLIGHT_MAX {
            let tx = tx.clone();
            rpc.submit(
                op(),
                Box::new(move |r: Result<Reply, RpcError>| tx.send(r.is_ok()).unwrap()),
            )
            .unwrap();
        }
        assert!(matches!(
            rpc.submit(op(), Box::new(|_: Result<Reply, RpcError>| {})),
            Err(RpcError::Busy)
        ));
        assert!(matches!(
            rpc.call(op(), Instant::now() + Duration::from_millis(20)),
            Err(RpcError::Timeout)
        ));
        let first = next_req(&h);
        h.link
            .send(Msg::Resp {
                id: first,
                res: Ok(done_meta()),
            })
            .unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(true));
        wait_until(|| rpc.inflight() == INFLIGHT_MAX - 1);
        let tx2 = tx.clone();
        rpc.submit(
            op(),
            Box::new(move |r: Result<Reply, RpcError>| tx2.send(r.is_ok()).unwrap()),
        )
        .unwrap();
        h.link.close(crate::net::conn::CloseReason::Local);
        let mut closed = 0;
        while let Ok(ok) = rx.recv_timeout(Duration::from_secs(5)) {
            assert!(!ok);
            closed += 1;
            if closed == INFLIGHT_MAX {
                break;
            }
        }
        assert_eq!(closed, INFLIGHT_MAX);
        assert!(matches!(
            rpc.submit(op(), Box::new(|_: Result<Reply, RpcError>| {})),
            Err(RpcError::Closed)
        ));
    }

    #[test]
    fn a_dir_move_reply_keeps_its_place_among_the_pushes() {
        let (g, h) = test_pair();
        let rpc = Rpc::new(g.link.clone());
        let mv = Op::Rename {
            from: RelPath::new("d1").unwrap(),
            to: RelPath::new("m2").unwrap(),
            from_expect: Expect::Dir,
            to_expect: Expect::Absent,
            body: None,
        };
        let (tx, rx) = bounded(4);
        let (t1, t2) = (tx.clone(), tx);
        let a = rpc
            .submit(
                mv,
                Box::new(move |r: Result<Reply, RpcError>| t1.send(("mv", r.is_ok())).unwrap()),
            )
            .unwrap();
        let b = rpc
            .submit(
                op(),
                Box::new(move |r: Result<Reply, RpcError>| t2.send(("rm", r.is_ok())).unwrap()),
            )
            .unwrap();
        assert_eq!(next_req(&h), a);
        assert_eq!(next_req(&h), b);
        let push = Msg::Push(crate::proto::Push::Changes {
            seq: 5,
            changes: Vec::new(),
        });
        for m in [
            Msg::Resp {
                id: a,
                res: Ok(done_meta()),
            },
            push,
            Msg::Resp {
                id: b,
                res: Ok(done_meta()),
            },
        ] {
            h.link.send(m).unwrap();
        }
        // an ordinary reply is routed at once, the move's waits in the inbox ahead of the push
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(("rm", true)));
        let (id, res) = match g.inbox.recv_timeout(Duration::from_secs(5)).unwrap() {
            In::Msg(Msg::Resp { id, res }) => (id, res),
            _ => panic!("expected the move's reply first"),
        };
        assert!(matches!(
            g.inbox.recv_timeout(Duration::from_secs(5)),
            Ok(In::Msg(Msg::Push(_)))
        ));
        assert!(rx.try_recv().is_err());
        // a link lost before the inbox is drained still delivers the reply that arrived
        h.link.close(crate::net::conn::CloseReason::Local);
        while !matches!(
            g.inbox.recv_timeout(Duration::from_secs(5)).unwrap(),
            In::Closed(_)
        ) {}
        assert!(rx.try_recv().is_err());
        assert_eq!(
            rpc.route_ordered(id, res),
            Some((RelPath::new("d1").unwrap(), RelPath::new("m2").unwrap()))
        );
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(("mv", true)));
    }
}
