use crate::crypto::trust::{Identity, PeerKey};
use crate::proto::{
    PROTO,
    frame::SEG_MAX,
    hs::{self, HS_MSG_MAX, HsHello, HsMode, PATTERN_PAIR, PATTERN_RESUME},
};
use rayon::prelude::*;
use snow::{Builder, HandshakeState, StatelessTransportState, params::NoiseParams};
use std::{
    io::{self, Read, Write},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

pub const REKEY_BYTES: u64 = 1 << 30;
pub const REKEY_AGE: Duration = Duration::from_secs(3600);
const TAG: usize = 16;
// below this a run is sealed or opened on the calling thread; waking the pool costs more than it saves
const PAR_SEGS: usize = 2;
const PAR_BYTES: usize = 128 << 10;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reject {
    KeyMismatch = 1,
    UnknownPeer = 2,
    RateLimited = 3,
    PairingDisabled = 4,
    Refused = 5,
}

impl Reject {
    fn from_u8(b: u8) -> Self {
        match b {
            1 => Self::KeyMismatch,
            2 => Self::UnknownPeer,
            3 => Self::RateLimited,
            4 => Self::PairingDisabled,
            _ => Self::Refused,
        }
    }

    pub fn frame(self) -> [u8; 3] {
        [0, 0, self as u8]
    }
}

#[derive(Debug)]
pub enum HsError {
    Io(io::Error),
    Crypto,
    Malformed(&'static str),
    Rejected(Reject),
    PinMismatch,
}

impl From<io::Error> for HsError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<snow::Error> for HsError {
    fn from(_: snow::Error) -> Self {
        Self::Crypto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    TooLarge,
    Exhausted,
    Auth,
}

fn params(mode: HsMode) -> Result<NoiseParams, HsError> {
    let p = match mode {
        HsMode::Pair => PATTERN_PAIR,
        HsMode::Resume => PATTERN_RESUME,
    };
    p.parse::<NoiseParams>()
        .map_err(|_| HsError::Malformed("noise pattern"))
}

pub struct Handshake {
    st: HandshakeState,
    mode: HsMode,
    pin: Option<PeerKey>,
}

impl Handshake {
    pub fn initiator(id: &Identity, mode: HsMode, pin: Option<&PeerKey>) -> Result<Self, HsError> {
        let prologue = hs::prologue(mode);
        let b = Builder::new(params(mode)?)
            .local_private_key(id.secret())?
            .prologue(&prologue)?;
        let st = match (mode, pin) {
            (HsMode::Resume, Some(k)) => b.remote_public_key(&k.0)?.build_initiator()?,
            (HsMode::Resume, None) => return Err(HsError::Malformed("resume needs a pinned key")),
            (HsMode::Pair, _) => b.build_initiator()?,
        };
        Ok(Self {
            st,
            mode,
            pin: pin.copied(),
        })
    }

    pub fn responder(id: &Identity, mode: HsMode) -> Result<Self, HsError> {
        let prologue = hs::prologue(mode);
        let st = Builder::new(params(mode)?)
            .local_private_key(id.secret())?
            .prologue(&prologue)?
            .build_responder()?;
        Ok(Self {
            st,
            mode,
            pin: None,
        })
    }

    pub fn mode(&self) -> HsMode {
        self.mode
    }

    pub fn write_frame(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), HsError> {
        let mut buf = [0u8; HS_MSG_MAX];
        let n = self.st.write_message(payload, &mut buf)?;
        out.extend_from_slice(&(n as u16).to_be_bytes());
        out.extend_from_slice(&buf[..n]);
        Ok(())
    }

    pub fn read_msg(
        &mut self,
        msg: &[u8],
        payload: &mut [u8; HS_MSG_MAX],
    ) -> Result<usize, HsError> {
        if msg.len() > HS_MSG_MAX {
            return Err(HsError::Malformed("handshake message too large"));
        }
        Ok(self.st.read_message(msg, payload)?)
    }

    pub fn remote(&self) -> Option<PeerKey> {
        let r = self.st.get_remote_static()?;
        let mut k = [0u8; 32];
        if r.len() != 32 {
            return None;
        }
        k.copy_from_slice(r);
        Some(PeerKey(k))
    }

    pub fn finish(self) -> Result<Established, HsError> {
        if !self.st.is_handshake_finished() {
            return Err(HsError::Malformed("handshake incomplete"));
        }
        let remote = self
            .remote()
            .ok_or(HsError::Malformed("no remote static key"))?;
        if let Some(pin) = self.pin
            && pin != remote
        {
            return Err(HsError::PinMismatch);
        }
        let h = self.st.get_handshake_hash();
        let mut hash = [0u8; 32];
        if h.len() != 32 {
            return Err(HsError::Malformed("handshake hash length"));
        }
        hash.copy_from_slice(h);
        let mode = self.mode;
        let t = self.st.into_stateless_transport_mode()?;
        Ok(Established {
            transport: Arc::new(Transport(RwLock::new(t))),
            remote,
            hash,
            mode,
        })
    }
}

pub struct Established {
    transport: Arc<Transport>,
    pub remote: PeerKey,
    pub hash: [u8; 32],
    pub mode: HsMode,
}

impl Established {
    pub fn sas(&self) -> [u8; 8] {
        hs::sas(&self.hash)
    }

    pub fn split(self) -> (Sealer, Opener) {
        let s = Sealer {
            t: self.transport.clone(),
            nonce: 0,
            bytes: 0,
            since: Instant::now(),
        };
        let o = Opener {
            t: self.transport,
            nonce: 0,
            epoch: 0,
        };
        (s, o)
    }
}

struct Transport(RwLock<StatelessTransportState>);

impl Transport {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, StatelessTransportState> {
        self.0.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, StatelessTransportState> {
        self.0.write().unwrap_or_else(|e| e.into_inner())
    }
}

pub struct Sealer {
    t: Arc<Transport>,
    nonce: u64,
    bytes: u64,
    since: Instant,
}

impl Sealer {
    pub fn seal(&mut self, pt: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        if pt.len() > SEG_MAX {
            return Err(CryptoError::TooLarge);
        }
        if self.nonce == u64::MAX {
            return Err(CryptoError::Exhausted);
        }
        let start = out.len();
        out.resize(start + 2 + pt.len() + TAG, 0);
        let n = self
            .t
            .read()
            .write_message(self.nonce, pt, &mut out[start + 2..])
            .map_err(|_| CryptoError::Auth);
        let n = match n {
            Ok(n) => n,
            Err(e) => {
                out.truncate(start);
                return Err(e);
            }
        };
        out[start..start + 2].copy_from_slice(&(n as u16).to_be_bytes());
        out.truncate(start + 2 + n);
        self.nonce += 1;
        self.bytes += n as u64;
        Ok(())
    }

    // seals plain[a..a + n] for each span under consecutive nonces, on all cores when the run is large
    pub fn seal_many(
        &mut self,
        plain: &[u8],
        spans: &[(usize, usize)],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let total: usize = spans.iter().map(|s| s.1).sum();
        if spans.len() < PAR_SEGS || total < PAR_BYTES {
            for &(a, n) in spans {
                let pt = a
                    .checked_add(n)
                    .and_then(|e| plain.get(a..e))
                    .ok_or(CryptoError::TooLarge)?;
                self.seal(pt, out)?;
            }
            return Ok(());
        }
        let mut pts = Vec::with_capacity(spans.len());
        for &(a, n) in spans {
            let pt = a
                .checked_add(n)
                .and_then(|e| plain.get(a..e))
                .filter(|p| p.len() <= SEG_MAX)
                .ok_or(CryptoError::TooLarge)?;
            pts.push(pt);
        }
        let count = spans.len() as u64;
        if self.nonce.checked_add(count).is_none() {
            return Err(CryptoError::Exhausted);
        }
        let start = out.len();
        out.resize(start + total + spans.len() * (2 + TAG), 0);
        let mut jobs = Vec::with_capacity(pts.len());
        let mut rest = &mut out[start..];
        for (i, pt) in pts.into_iter().enumerate() {
            let (dst, tail) = rest.split_at_mut(2 + pt.len() + TAG);
            rest = tail;
            jobs.push((self.nonce + i as u64, pt, dst));
        }
        let g = self.t.read();
        let st: &StatelessTransportState = &g;
        let ok = jobs.into_par_iter().all(|(nonce, pt, dst)| {
            let (len, body) = dst.split_at_mut(2);
            match st.write_message(nonce, pt, body) {
                Ok(m) if m == body.len() => {
                    len.copy_from_slice(&(m as u16).to_be_bytes());
                    true
                }
                _ => false,
            }
        });
        drop(g);
        if !ok {
            out.truncate(start);
            return Err(CryptoError::Auth);
        }
        self.nonce += count;
        self.bytes += (total + spans.len() * TAG) as u64;
        Ok(())
    }

    pub fn rekey_due(&self) -> bool {
        self.bytes >= REKEY_BYTES || self.since.elapsed() >= REKEY_AGE
    }

    pub fn rekey(&mut self) {
        self.t.write().rekey_outgoing();
        self.bytes = 0;
        self.since = Instant::now();
    }
}

pub struct Opener {
    t: Arc<Transport>,
    nonce: u64,
    epoch: u64,
}

impl Opener {
    // opens a run of segments under consecutive nonces, on all cores when the run is large; returns the first nonce
    pub fn open_many(
        &mut self,
        cts: &[&[u8]],
        outs: Vec<&mut [u8]>,
        res: &mut Vec<Result<usize, CryptoError>>,
    ) -> Result<u64, CryptoError> {
        let count = cts.len() as u64;
        let base = self.nonce;
        if base.checked_add(count).is_none() || cts.len() != outs.len() {
            return Err(CryptoError::Exhausted);
        }
        let total: usize = cts.iter().map(|c| c.len()).sum();
        let g = self.t.read();
        let st: &StatelessTransportState = &g;
        res.clear();
        if cts.len() < PAR_SEGS || total < PAR_BYTES {
            res.extend(
                cts.iter()
                    .zip(outs)
                    .enumerate()
                    .map(|(i, (ct, out))| open_one(st, base + i as u64, ct, out)),
            );
        } else {
            cts.par_iter()
                .zip(outs)
                .enumerate()
                .map(|(i, (ct, out))| open_one(st, base + i as u64, ct, out))
                .collect_into_vec(res);
        }
        drop(g);
        self.nonce += count;
        Ok(base)
    }

    // a segment of a run whose earlier part rekeyed, opened again under the new key
    pub fn open_at(&self, nonce: u64, ct: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        open_one(&self.t.read(), nonce, ct, out)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn open(&mut self, ct: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if ct.len() < TAG || ct.len() - TAG > out.len() {
            return Err(CryptoError::TooLarge);
        }
        if self.nonce == u64::MAX {
            return Err(CryptoError::Exhausted);
        }
        let n = open_one(&self.t.read(), self.nonce, ct, out)?;
        self.nonce += 1;
        Ok(n)
    }

    pub fn rekey(&mut self) {
        self.t.write().rekey_incoming();
        self.epoch += 1;
    }
}

fn open_one(
    st: &StatelessTransportState,
    nonce: u64,
    ct: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    if ct.len() < TAG || ct.len() - TAG > out.len() {
        return Err(CryptoError::TooLarge);
    }
    if nonce == u64::MAX {
        return Err(CryptoError::Exhausted);
    }
    st.read_message(nonce, ct, out)
        .map_err(|_| CryptoError::Auth)
}

pub trait Gate {
    fn mode(&mut self, m: HsMode) -> Result<(), Reject>;
    fn peer(&mut self, m: HsMode, key: &PeerKey, hello: &HsHello) -> Result<(), Reject>;
}

fn read_frame<S: Read>(io: &mut S, buf: &mut [u8; HS_MSG_MAX]) -> Result<usize, HsError> {
    let mut l = [0u8; 2];
    io.read_exact(&mut l)?;
    let n = u16::from_be_bytes(l) as usize;
    if n == 0 {
        let mut c = [0u8; 1];
        io.read_exact(&mut c)?;
        return Err(HsError::Rejected(Reject::from_u8(c[0])));
    }
    if n > HS_MSG_MAX {
        return Err(HsError::Malformed("handshake message too large"));
    }
    io.read_exact(&mut buf[..n])?;
    Ok(n)
}

fn encode_hello(h: &HsHello) -> Result<Vec<u8>, HsError> {
    postcard::to_allocvec(h).map_err(|_| HsError::Malformed("hello encode"))
}

fn decode_hello(b: &[u8]) -> Result<HsHello, HsError> {
    match postcard::take_from_bytes::<HsHello>(b) {
        Ok((h, rest)) if rest.is_empty() && h.proto == PROTO => Ok(h),
        _ => Err(HsError::Malformed("bad hello")),
    }
}

pub fn initiate<S: Read + Write>(
    io: &mut S,
    id: &Identity,
    pin: Option<&PeerKey>,
    me: &HsHello,
) -> Result<(Established, HsHello), HsError> {
    let mode = if pin.is_some() {
        HsMode::Resume
    } else {
        HsMode::Pair
    };
    let mut hs = Handshake::initiator(id, mode, pin)?;
    let mine = encode_hello(me)?;
    let mut out = Vec::with_capacity(HS_MSG_MAX);
    let mut msg = [0u8; HS_MSG_MAX];
    let mut payload = [0u8; HS_MSG_MAX];
    out.push(mode as u8);
    let peer = match mode {
        HsMode::Pair => {
            hs.write_frame(&[], &mut out)?;
            io.write_all(&out)?;
            io.flush()?;
            let n = read_frame(io, &mut msg)?;
            let p = hs.read_msg(&msg[..n], &mut payload)?;
            let peer = decode_hello(&payload[..p])?;
            out.clear();
            hs.write_frame(&mine, &mut out)?;
            io.write_all(&out)?;
            io.flush()?;
            peer
        }
        HsMode::Resume => {
            hs.write_frame(&mine, &mut out)?;
            io.write_all(&out)?;
            io.flush()?;
            let n = read_frame(io, &mut msg)?;
            let p = hs.read_msg(&msg[..n], &mut payload)?;
            decode_hello(&payload[..p])?
        }
    };
    Ok((hs.finish()?, peer))
}

pub fn respond<S: Read + Write>(
    io: &mut S,
    id: &Identity,
    me: &HsHello,
    gate: &mut dyn Gate,
) -> Result<(Established, HsHello), HsError> {
    let mut b = [0u8; 1];
    io.read_exact(&mut b)?;
    let mode = HsMode::from_u8(b[0]).ok_or(HsError::Malformed("bad handshake mode"))?;
    if let Err(r) = gate.mode(mode) {
        let _ = io.write_all(&r.frame());
        return Err(HsError::Rejected(r));
    }
    let mut hs = Handshake::responder(id, mode)?;
    let mine = encode_hello(me)?;
    let mut out = Vec::with_capacity(HS_MSG_MAX);
    let mut msg = [0u8; HS_MSG_MAX];
    let mut payload = [0u8; HS_MSG_MAX];
    let n = read_frame(io, &mut msg)?;
    let p = match hs.read_msg(&msg[..n], &mut payload) {
        Ok(p) => p,
        Err(HsError::Crypto) if mode == HsMode::Resume => {
            let _ = io.write_all(&Reject::KeyMismatch.frame());
            return Err(HsError::Crypto);
        }
        Err(e) => return Err(e),
    };
    let peer = match mode {
        HsMode::Pair => {
            if p != 0 {
                return Err(HsError::Malformed("unexpected payload"));
            }
            hs.write_frame(&mine, &mut out)?;
            io.write_all(&out)?;
            io.flush()?;
            let n = read_frame(io, &mut msg)?;
            let p = hs.read_msg(&msg[..n], &mut payload)?;
            let peer = decode_hello(&payload[..p])?;
            let key = hs
                .remote()
                .ok_or(HsError::Malformed("no remote static key"))?;
            if let Err(r) = gate.peer(mode, &key, &peer) {
                let _ = io.write_all(&r.frame());
                return Err(HsError::Rejected(r));
            }
            peer
        }
        HsMode::Resume => {
            let peer = decode_hello(&payload[..p])?;
            let key = hs
                .remote()
                .ok_or(HsError::Malformed("no remote static key"))?;
            if let Err(r) = gate.peer(mode, &key, &peer) {
                let _ = io.write_all(&r.frame());
                return Err(HsError::Rejected(r));
            }
            hs.write_frame(&mine, &mut out)?;
            io.write_all(&out)?;
            io.flush()?;
            peer
        }
    };
    Ok((hs.finish()?, peer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Name, hs::Role};
    use std::os::unix::net::UnixStream;
    use std::thread;

    struct Open;
    impl Gate for Open {
        fn mode(&mut self, _: HsMode) -> Result<(), Reject> {
            Ok(())
        }
        fn peer(&mut self, _: HsMode, _: &PeerKey, _: &HsHello) -> Result<(), Reject> {
            Ok(())
        }
    }

    struct Known(PeerKey);
    impl Gate for Known {
        fn mode(&mut self, _: HsMode) -> Result<(), Reject> {
            Ok(())
        }
        fn peer(&mut self, _: HsMode, k: &PeerKey, _: &HsHello) -> Result<(), Reject> {
            if *k == self.0 {
                Ok(())
            } else {
                Err(Reject::UnknownPeer)
            }
        }
    }

    fn hello(role: Role, n: &str) -> HsHello {
        HsHello {
            proto: PROTO,
            role,
            name: Name::new(n).unwrap(),
        }
    }

    type Side = Result<(Established, HsHello), HsError>;

    fn run(
        pin: Option<PeerKey>,
        host: Identity,
        guest: Identity,
        mut gate: Box<dyn Gate + Send>,
    ) -> (Side, Side) {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || {
            let r = respond(&mut b, &host, &hello(Role::Host, "host"), &mut *gate);
            drop(b);
            r
        });
        let g = initiate(&mut a, &guest, pin.as_ref(), &hello(Role::Guest, "guest"));
        drop(a);
        (g, h.join().unwrap())
    }

    fn roundtrip(g: Established, h: Established) {
        let (mut gs, mut go) = g.split();
        let (mut hs, mut ho) = h.split();
        let mut wire = Vec::new();
        let mut pt = vec![0u8; 65_535];
        for i in 0..3u8 {
            wire.clear();
            gs.seal(&[i; 100], &mut wire).unwrap();
            let n = ho.open(&wire[2..], &mut pt).unwrap();
            assert_eq!(&pt[..n], &[i; 100]);
            wire.clear();
            hs.seal(b"back", &mut wire).unwrap();
            let n = go.open(&wire[2..], &mut pt).unwrap();
            assert_eq!(&pt[..n], b"back");
        }
        gs.rekey();
        ho.rekey();
        wire.clear();
        gs.seal(b"after rekey", &mut wire).unwrap();
        let n = ho.open(&wire[2..], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"after rekey");
        wire.clear();
        gs.seal(b"x", &mut wire).unwrap();
        wire[4] ^= 1;
        assert_eq!(ho.open(&wire[2..], &mut pt), Err(CryptoError::Auth));
        assert_eq!(
            gs.seal(&vec![0u8; SEG_MAX + 1], &mut wire),
            Err(CryptoError::TooLarge)
        );
    }

    #[test]
    fn xx_round_trip_agrees_on_keys_and_sas() {
        let host = Identity::generate().unwrap();
        let guest = Identity::generate().unwrap();
        let (hk, gk) = (host.public, guest.public);
        let (g, h) = run(None, host, guest, Box::new(Open));
        let (g, gh) = g.unwrap();
        let (h, hh) = h.unwrap();
        assert_eq!(g.remote, hk);
        assert_eq!(h.remote, gk);
        assert_eq!(gh.role, Role::Host);
        assert_eq!(hh.role, Role::Guest);
        assert_eq!(g.sas(), h.sas());
        assert_eq!(g.mode, HsMode::Pair);
        roundtrip(g, h);
    }

    #[test]
    fn ik_round_trip_with_pinned_key() {
        let host = Identity::generate().unwrap();
        let guest = Identity::generate().unwrap();
        let (hk, gk) = (host.public, guest.public);
        let (g, h) = run(Some(hk), host, guest, Box::new(Known(gk)));
        let (g, _) = g.unwrap();
        let (h, _) = h.unwrap();
        assert_eq!(g.remote, hk);
        assert_eq!(h.remote, gk);
        assert_eq!(g.mode, HsMode::Resume);
        roundtrip(g, h);
    }

    #[test]
    fn ik_pin_mismatch_is_rejected_without_fallback() {
        let host = Identity::generate().unwrap();
        let guest = Identity::generate().unwrap();
        let wrong = Identity::generate().unwrap().public;
        let gk = guest.public;
        let (g, h) = run(Some(wrong), host, guest, Box::new(Known(gk)));
        assert!(matches!(g, Err(HsError::Rejected(Reject::KeyMismatch))));
        assert!(matches!(h, Err(HsError::Crypto)));
    }

    #[test]
    fn ik_unknown_guest_is_rejected() {
        let host = Identity::generate().unwrap();
        let guest = Identity::generate().unwrap();
        let hk = host.public;
        let (g, h) = run(Some(hk), host, guest, Box::new(Known(PeerKey([9; 32]))));
        assert!(matches!(g, Err(HsError::Rejected(Reject::UnknownPeer))));
        assert!(matches!(h, Err(HsError::Rejected(Reject::UnknownPeer))));
    }

    #[test]
    fn tampered_and_truncated_handshakes_fail() {
        let host = Identity::generate().unwrap();
        let guest = Identity::generate().unwrap();
        let mut payload = [0u8; HS_MSG_MAX];

        let mut i = Handshake::initiator(&guest, HsMode::Pair, None).unwrap();
        let mut r = Handshake::responder(&host, HsMode::Pair).unwrap();
        let mut m1 = Vec::new();
        i.write_frame(&[], &mut m1).unwrap();
        r.read_msg(&m1[2..], &mut payload).unwrap();
        let mut m2 = Vec::new();
        r.write_frame(&encode_hello(&hello(Role::Host, "h")).unwrap(), &mut m2)
            .unwrap();
        let last = m2.len() - 1;
        m2[last] ^= 0x40;
        assert!(matches!(
            i.read_msg(&m2[2..], &mut payload),
            Err(HsError::Crypto)
        ));

        let mut i = Handshake::initiator(&guest, HsMode::Resume, Some(&host.public)).unwrap();
        let mut r = Handshake::responder(&host, HsMode::Resume).unwrap();
        let mut m1 = Vec::new();
        i.write_frame(&encode_hello(&hello(Role::Guest, "g")).unwrap(), &mut m1)
            .unwrap();
        m1.truncate(m1.len() - 5);
        assert!(r.read_msg(&m1[2..], &mut payload).is_err());

        let mut wire = vec![HsMode::Resume as u8];
        wire.extend_from_slice(&200u16.to_be_bytes());
        wire.extend_from_slice(&[1u8; 50]);
        let mut cur = Duplex {
            r: io::Cursor::new(wire),
            w: Vec::new(),
        };
        let e = respond(&mut cur, &host, &hello(Role::Host, "h"), &mut Open)
            .err()
            .unwrap();
        assert!(matches!(e, HsError::Io(ref x) if x.kind() == io::ErrorKind::UnexpectedEof));

        let mut wire = vec![HsMode::Pair as u8];
        wire.extend_from_slice(&((HS_MSG_MAX + 1) as u16).to_be_bytes());
        let mut cur = Duplex {
            r: io::Cursor::new(wire),
            w: Vec::new(),
        };
        assert!(matches!(
            respond(&mut cur, &host, &hello(Role::Host, "h"), &mut Open),
            Err(HsError::Malformed(_))
        ));

        let mut cur = Duplex {
            r: io::Cursor::new(vec![9u8]),
            w: Vec::new(),
        };
        assert!(matches!(
            respond(&mut cur, &host, &hello(Role::Host, "h"), &mut Open),
            Err(HsError::Malformed(_))
        ));
    }

    struct Duplex {
        r: io::Cursor<Vec<u8>>,
        w: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.r.read(b)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.w.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
