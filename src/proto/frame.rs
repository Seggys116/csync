use super::{CHUNK_MAX, FRAME_MAX, INFLIGHT_MAX, Msg, ReqId};
use lz4_flex::block::{compress_into, decompress_into, get_maximum_output_size};
use postcard::ser_flavors::Flavor;
use rustc_hash::FxHashSet;
use std::fmt;

pub const NOISE_MAX: usize = 65_535;
pub const SEG_MAX: usize = NOISE_MAX - 16;
pub const F_MORE: u8 = 1;
pub const F_LZ4: u8 = 2;
pub const F_CHUNK: u8 = 4;
pub const F_LAST: u8 = 8;
pub const CHUNK_HDR: usize = 1 + 4 + 8;
pub const LZ4_MIN: usize = 512;

const F_ALL: u8 = F_MORE | F_LZ4 | F_CHUNK | F_LAST;
const LZ4_HDR: usize = 4;
// an lz4 block cannot expand by more than 255x, so larger declared sizes are lies
const LZ4_RATIO_MAX: usize = 256;
const NOLZ_MAX: usize = 4 * INFLIGHT_MAX;

#[derive(Debug)]
pub enum FrameError {
    TooLarge,
    BadFlags,
    Truncated,
    Decompress,
    Decode(postcard::Error),
    Encode(postcard::Error),
    Invalid(&'static str),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("frame too large"),
            Self::BadFlags => f.write_str("bad frame flags"),
            Self::Truncated => f.write_str("truncated frame"),
            Self::Decompress => f.write_str("lz4 decompress failed"),
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::Encode(e) => write!(f, "encode: {e}"),
            Self::Invalid(why) => write!(f, "invalid message: {why}"),
        }
    }
}

impl std::error::Error for FrameError {}

#[derive(Debug)]
pub enum Frame<'a> {
    Msg(Msg),
    Chunk {
        id: ReqId,
        off: u64,
        last: bool,
        data: &'a [u8],
    },
}

struct VecSink<'a> {
    v: &'a mut Vec<u8>,
    max: usize,
}

impl Flavor for VecSink<'_> {
    type Output = ();
    fn try_push(&mut self, b: u8) -> postcard::Result<()> {
        if self.v.len() >= self.max {
            return Err(postcard::Error::SerializeBufferFull);
        }
        self.v.push(b);
        Ok(())
    }
    fn try_extend(&mut self, d: &[u8]) -> postcard::Result<()> {
        if self.v.len() + d.len() > self.max {
            return Err(postcard::Error::SerializeBufferFull);
        }
        self.v.extend_from_slice(d);
        Ok(())
    }
    fn finalize(self) -> postcard::Result<()> {
        Ok(())
    }
}

// writes [raw len u32 le | lz4 block] at z[at..]; returns its length, z keeps its size to avoid refilling
fn try_lz4(src: &[u8], z: &mut Vec<u8>, at: usize) -> Option<usize> {
    let need = at + LZ4_HDR + get_maximum_output_size(src.len());
    if z.len() < need {
        z.resize(need, 0);
    }
    let n = compress_into(src, z.get_mut(at + LZ4_HDR..need)?).ok()?;
    z.get_mut(at..at + LZ4_HDR)?
        .copy_from_slice(&u32::try_from(src.len()).ok()?.to_le_bytes());
    Some(LZ4_HDR + n)
}

fn worth(packed: usize, raw: usize) -> bool {
    packed * 8 <= raw * 7
}

fn unlz4<'z>(src: &[u8], max: usize, z: &'z mut Vec<u8>) -> Result<&'z [u8], FrameError> {
    let Some((len, comp)) = src.split_first_chunk::<LZ4_HDR>() else {
        return Err(FrameError::Truncated);
    };
    let raw = u32::from_le_bytes(*len) as usize;
    if raw > max {
        return Err(FrameError::TooLarge);
    }
    if raw > comp.len().saturating_mul(LZ4_RATIO_MAX) {
        return Err(FrameError::Decompress);
    }
    if z.len() < raw {
        z.resize(raw, 0);
    }
    let out = z.get_mut(..raw).ok_or(FrameError::Decompress)?;
    let n = decompress_into(comp, out).map_err(|_| FrameError::Decompress)?;
    if n != raw {
        return Err(FrameError::Decompress);
    }
    z.get(..raw).ok_or(FrameError::Decompress)
}

pub fn decode_msg(raw: &[u8]) -> Result<Msg, FrameError> {
    if raw.len() > FRAME_MAX {
        return Err(FrameError::TooLarge);
    }
    let (m, rest) = postcard::take_from_bytes::<Msg>(raw).map_err(FrameError::Decode)?;
    if !rest.is_empty() {
        return Err(FrameError::Decode(postcard::Error::DeserializeBadEncoding));
    }
    m.validate().map_err(FrameError::Invalid)?;
    Ok(m)
}

fn decode_payload(body: &[u8], lz4: bool, z: &mut Vec<u8>) -> Result<Msg, FrameError> {
    let raw = if lz4 {
        unlz4(body, FRAME_MAX, z)?
    } else {
        body
    };
    decode_msg(raw)
}

#[derive(Default)]
pub struct Encoder {
    ser: Vec<u8>,
    z: Vec<u8>,
    seg: Vec<u8>,
    nolz: FxHashSet<ReqId>,
}

impl Encoder {
    pub fn msg(&mut self, m: &Msg, emit: &mut dyn FnMut(&[u8])) -> Result<(), FrameError> {
        self.ser.clear();
        self.ser.push(0);
        postcard::serialize_with_flavor(
            m,
            VecSink {
                v: &mut self.ser,
                max: FRAME_MAX + 1,
            },
        )
        .map_err(|e| match e {
            postcard::Error::SerializeBufferFull => FrameError::TooLarge,
            e => FrameError::Encode(e),
        })?;
        let raw = self.ser.len() - 1;
        let packed = if raw >= LZ4_MIN {
            self.ser
                .get(1..)
                .and_then(|src| try_lz4(src, &mut self.z, 1))
        } else {
            None
        };
        // byte 0 of ser and z is reserved for flags so the single-segment case is emitted without a copy
        let (buf, len, flags) = match packed {
            Some(n) if worth(n, raw) => (&mut self.z, 1 + n, F_LZ4),
            _ => (&mut self.ser, 1 + raw, 0),
        };
        if len <= SEG_MAX {
            buf[0] = flags;
            emit(&buf[..len]);
            return Ok(());
        }
        if self.seg.len() < SEG_MAX {
            self.seg.resize(SEG_MAX, 0);
        }
        let mut rest = &buf[1..len];
        while !rest.is_empty() {
            let (part, tail) = rest.split_at(rest.len().min(SEG_MAX - 1));
            rest = tail;
            self.seg[0] = if rest.is_empty() {
                flags
            } else {
                flags | F_MORE
            };
            self.seg[1..1 + part.len()].copy_from_slice(part);
            emit(&self.seg[..1 + part.len()]);
        }
        Ok(())
    }

    pub fn chunk(
        &mut self,
        id: ReqId,
        off: u64,
        last: bool,
        data: &[u8],
        emit: &mut dyn FnMut(&[u8]),
    ) -> Result<(), FrameError> {
        if data.len() > CHUNK_MAX {
            return Err(FrameError::TooLarge);
        }
        let mut flags = F_CHUNK | if last { F_LAST } else { 0 };
        let mut end = 0;
        if data.len() >= LZ4_MIN && !self.nolz.contains(&id) {
            match try_lz4(data, &mut self.seg, CHUNK_HDR) {
                Some(n) if worth(n, data.len()) => {
                    flags |= F_LZ4;
                    end = CHUNK_HDR + n;
                }
                Some(n) if n * 10 > data.len() * 9 => {
                    if self.nolz.len() >= NOLZ_MAX {
                        self.nolz.clear();
                    }
                    self.nolz.insert(id);
                }
                _ => {}
            }
        }
        if end == 0 {
            end = CHUNK_HDR + data.len();
            if self.seg.len() < end {
                self.seg.resize(end, 0);
            }
            self.seg[CHUNK_HDR..end].copy_from_slice(data);
        }
        self.seg[0] = flags;
        self.seg[1..5].copy_from_slice(&id.to_le_bytes());
        self.seg[5..CHUNK_HDR].copy_from_slice(&off.to_le_bytes());
        emit(&self.seg[..end]);
        if last {
            self.nolz.remove(&id);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
    z: Vec<u8>,
    more: bool,
    lz4: bool,
}

impl Decoder {
    fn fail(&mut self, e: FrameError) -> FrameError {
        self.buf.clear();
        self.more = false;
        e
    }

    // chunks may interleave with the segments of a message; message segments may not interleave with each other
    pub fn push<'a>(&'a mut self, seg: &'a [u8]) -> Result<Option<Frame<'a>>, FrameError> {
        let Some((&flags, body)) = seg.split_first() else {
            return Err(self.fail(FrameError::Truncated));
        };
        if seg.len() > SEG_MAX {
            return Err(self.fail(FrameError::TooLarge));
        }
        if flags & !F_ALL != 0 {
            return Err(self.fail(FrameError::BadFlags));
        }
        let lz4 = flags & F_LZ4 != 0;
        if flags & F_CHUNK != 0 {
            if flags & F_MORE != 0 {
                return Err(self.fail(FrameError::BadFlags));
            }
            let Some((id, rest)) = body.split_first_chunk::<4>() else {
                return Err(self.fail(FrameError::Truncated));
            };
            let Some((off, data)) = rest.split_first_chunk::<8>() else {
                return Err(self.fail(FrameError::Truncated));
            };
            let (id, off, last) = (
                u32::from_le_bytes(*id),
                u64::from_le_bytes(*off),
                flags & F_LAST != 0,
            );
            if !lz4 {
                if data.len() > CHUNK_MAX {
                    return Err(self.fail(FrameError::TooLarge));
                }
                return Ok(Some(Frame::Chunk {
                    id,
                    off,
                    last,
                    data,
                }));
            }
            let data = unlz4(data, CHUNK_MAX, &mut self.z)?;
            return Ok(Some(Frame::Chunk {
                id,
                off,
                last,
                data,
            }));
        }
        if flags & F_LAST != 0 {
            return Err(self.fail(FrameError::BadFlags));
        }
        let more = flags & F_MORE != 0;
        if !self.more && !more {
            return decode_payload(body, lz4, &mut self.z).map(|m| Some(Frame::Msg(m)));
        }
        if self.more && lz4 != self.lz4 {
            return Err(self.fail(FrameError::BadFlags));
        }
        if self.buf.len() + body.len() > FRAME_MAX {
            return Err(self.fail(FrameError::TooLarge));
        }
        self.buf.extend_from_slice(body);
        if more {
            self.more = true;
            self.lz4 = lz4;
            return Ok(None);
        }
        self.more = false;
        let res = decode_payload(&self.buf, lz4, &mut self.z);
        self.buf.clear();
        res.map(|m| Some(Frame::Msg(m)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{BATCH_MAX, Body, Bytes, Change, Expect, Op, Push, RelPath, Version};

    fn noise(n: usize, seed: u8) -> Vec<u8> {
        let mut v = vec![0u8; n];
        blake3::Hasher::new()
            .update(&[seed])
            .finalize_xof()
            .fill(&mut v);
        v
    }

    fn segs_of(enc: &mut Encoder, m: &Msg) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        enc.msg(m, &mut |s| out.push(s.to_vec())).unwrap();
        out
    }

    fn decode_all(d: &mut Decoder, segs: &[Vec<u8>]) -> Msg {
        let mut got = None;
        for (i, s) in segs.iter().enumerate() {
            match d.push(s).unwrap() {
                Some(Frame::Msg(m)) => {
                    assert_eq!(i, segs.len() - 1);
                    got = Some(m);
                }
                Some(Frame::Chunk { .. }) => panic!("unexpected chunk"),
                None => assert!(i < segs.len() - 1),
            }
        }
        got.unwrap()
    }

    fn changes(n: usize) -> Msg {
        let path = RelPath::new("src/some/fairly/long/path/name.rs").unwrap();
        Msg::Push(Push::Changes {
            seq: 7,
            changes: vec![Change::Remove { path }; n],
        })
    }

    fn inline(data: Vec<u8>) -> Msg {
        let op = Op::Commit {
            path: RelPath::new("f").unwrap(),
            base: Expect::Any,
            new: Version {
                hash: [1; 32],
                size: data.len() as u64,
            },
            perm: None,
            body: Body::Inline(Bytes(data)),
            sync: false,
        };
        Msg::Req { id: 3, op }
    }

    #[test]
    fn small_msg_single_segment() {
        let mut enc = Encoder::default();
        let m = Msg::Ping { t_ns: 42 };
        let segs = segs_of(&mut enc, &m);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0][0], 0);
        assert_eq!(decode_all(&mut Decoder::default(), &segs), m);
    }

    #[test]
    fn large_compressible_msg_segments_and_lz4() {
        let mut enc = Encoder::default();
        let mut dec = Decoder::default();
        let m = changes(BATCH_MAX);
        let segs = segs_of(&mut enc, &m);
        assert!(segs.iter().all(|s| s[0] & F_LZ4 != 0 && s.len() <= SEG_MAX));
        assert_eq!(decode_all(&mut dec, &segs), m);
        let m2 = Msg::Ack { seq: 9 };
        assert_eq!(decode_all(&mut dec, &segs_of(&mut enc, &m2)), m2);
    }

    #[test]
    fn incompressible_msg_bypasses_lz4() {
        let mut enc = Encoder::default();
        let m = inline(noise(300_000, 1));
        let segs = segs_of(&mut enc, &m);
        assert!(segs.len() >= 5);
        assert!(segs.iter().all(|s| s[0] & F_LZ4 == 0));
        let (last, init) = segs.split_last().unwrap();
        assert!(
            init.iter()
                .all(|s| s[0] & F_MORE != 0 && s.len() == SEG_MAX)
        );
        assert_eq!(last[0] & F_MORE, 0);
        assert_eq!(decode_all(&mut Decoder::default(), &segs), m);
    }

    #[test]
    fn oversize_msg_refused_on_encode() {
        let mut enc = Encoder::default();
        let r = enc.msg(&inline(vec![0; FRAME_MAX]), &mut |_| panic!("emitted"));
        assert!(matches!(r, Err(FrameError::TooLarge)));
    }

    #[test]
    fn chunk_roundtrip_raw_and_lz4() {
        let mut enc = Encoder::default();
        let mut dec = Decoder::default();
        for (data, lz) in [
            (vec![7u8; CHUNK_MAX], true),
            (noise(1000, 2), false),
            (b"tiny".to_vec(), false),
            (Vec::new(), false),
        ] {
            let mut segs = Vec::new();
            enc.chunk(5, 1 << 40, true, &data, &mut |s| segs.push(s.to_vec()))
                .unwrap();
            assert_eq!(segs.len(), 1);
            assert_eq!(segs[0][0] & F_LZ4 != 0, lz);
            match dec.push(&segs[0]).unwrap() {
                Some(Frame::Chunk {
                    id,
                    off,
                    last,
                    data: got,
                }) => {
                    assert_eq!((id, off, last), (5, 1 << 40, true));
                    assert_eq!(got, &data[..]);
                }
                _ => panic!("expected chunk"),
            }
        }
        assert!(matches!(
            enc.chunk(1, 0, false, &vec![0; CHUNK_MAX + 1], &mut |_| {}),
            Err(FrameError::TooLarge)
        ));
    }

    #[test]
    fn chunk_stream_stops_trying_lz4() {
        let mut enc = Encoder::default();
        let mut flags = Vec::new();
        enc.chunk(9, 0, false, &noise(4096, 3), &mut |s| flags.push(s[0]))
            .unwrap();
        enc.chunk(9, 4096, false, &[0u8; 4096], &mut |s| flags.push(s[0]))
            .unwrap();
        enc.chunk(10, 0, false, &[0u8; 4096], &mut |s| flags.push(s[0]))
            .unwrap();
        enc.chunk(9, 8192, true, &[0u8; 4096], &mut |s| flags.push(s[0]))
            .unwrap();
        enc.chunk(9, 0, false, &[0u8; 4096], &mut |s| flags.push(s[0]))
            .unwrap();
        assert_eq!(
            flags.iter().map(|f| f & F_LZ4 != 0).collect::<Vec<_>>(),
            [false, false, true, false, true]
        );
    }

    #[test]
    fn chunk_interleaves_with_reassembly() {
        let mut enc = Encoder::default();
        let mut dec = Decoder::default();
        let m = inline(noise(100_000, 4));
        let segs = segs_of(&mut enc, &m);
        assert!(dec.push(&segs[0]).unwrap().is_none());
        let mut c = Vec::new();
        enc.chunk(1, 0, false, b"abc", &mut |s| c = s.to_vec())
            .unwrap();
        assert!(matches!(
            dec.push(&c).unwrap(),
            Some(Frame::Chunk { id: 1, .. })
        ));
        assert_eq!(decode_all(&mut dec, &segs[1..]), m);
    }

    #[test]
    fn decoder_rejects_malformed() {
        let mut d = Decoder::default();
        assert!(matches!(d.push(&[]), Err(FrameError::Truncated)));
        assert!(matches!(d.push(&[0x10, 1]), Err(FrameError::BadFlags)));
        assert!(matches!(
            d.push(&[F_CHUNK | F_MORE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(FrameError::BadFlags)
        ));
        assert!(matches!(d.push(&[F_LAST, 0]), Err(FrameError::BadFlags)));
        assert!(matches!(
            d.push(&[F_CHUNK, 1, 2, 3, 4, 5, 6, 7]),
            Err(FrameError::Truncated)
        ));
        let mut big = vec![0u8; CHUNK_HDR + CHUNK_MAX + 1];
        big[0] = F_CHUNK;
        assert!(matches!(d.push(&big), Err(FrameError::TooLarge)));
        assert!(matches!(
            d.push(&vec![0u8; SEG_MAX + 1]),
            Err(FrameError::TooLarge)
        ));
        assert!(matches!(d.push(&[0]), Err(FrameError::Decode(_))));
        assert!(matches!(
            d.push(&[0, 0xff, 0xff, 0xff]),
            Err(FrameError::Decode(_))
        ));
    }

    #[test]
    fn decoder_rejects_trailing_and_invalid() {
        let mut enc = Encoder::default();
        let mut seg = segs_of(&mut enc, &Msg::Ping { t_ns: 1 }).remove(0);
        seg.push(0);
        assert!(matches!(
            Decoder::default().push(&seg),
            Err(FrameError::Decode(_))
        ));
        let segs = segs_of(&mut enc, &changes(BATCH_MAX + 1));
        let mut d = Decoder::default();
        let mut res = None;
        for s in &segs {
            res = Some(d.push(s).map(|f| f.is_some()));
        }
        assert!(matches!(res, Some(Err(FrameError::Invalid(_)))));
    }

    #[test]
    fn decoder_lz4_bounds() {
        let mut d = Decoder::default();
        let mut seg = vec![F_LZ4];
        seg.extend_from_slice(&((FRAME_MAX + 1) as u32).to_le_bytes());
        seg.extend_from_slice(&[0; 64]);
        assert!(matches!(d.push(&seg), Err(FrameError::TooLarge)));
        let mut seg = vec![F_LZ4];
        seg.extend_from_slice(&(FRAME_MAX as u32).to_le_bytes());
        seg.extend_from_slice(&[0; 8]);
        assert!(matches!(d.push(&seg), Err(FrameError::Decompress)));
        assert!(d.z.len() < 4096);
        let mut seg = vec![F_CHUNK | F_LZ4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        seg.extend_from_slice(&((CHUNK_MAX + 1) as u32).to_le_bytes());
        seg.extend_from_slice(&[0; 600]);
        assert!(matches!(d.push(&seg), Err(FrameError::TooLarge)));
        let mut seg = vec![F_LZ4];
        seg.extend_from_slice(&100u32.to_le_bytes());
        seg.extend_from_slice(&[0xf0, 0xff, 0xff, 0xff, 0x01]);
        assert!(matches!(d.push(&seg), Err(FrameError::Decompress)));
        assert!(matches!(d.push(&[F_LZ4, 1, 0]), Err(FrameError::Truncated)));
    }

    #[test]
    fn reassembly_is_capped_and_recovers() {
        let mut d = Decoder::default();
        let mut seg = vec![0u8; SEG_MAX];
        seg[0] = F_MORE;
        let mut err = None;
        for _ in 0..FRAME_MAX / (SEG_MAX - 1) + 2 {
            if let Err(e) = d.push(&seg) {
                err = Some(e);
                break;
            }
        }
        assert!(matches!(err, Some(FrameError::TooLarge)));
        assert!(d.buf.len() <= FRAME_MAX);
        let mut enc = Encoder::default();
        assert_eq!(
            decode_all(&mut d, &segs_of(&mut enc, &Msg::Rekey)),
            Msg::Rekey
        );
        assert!(d.push(&[F_MORE | F_LZ4, 1]).unwrap().is_none());
        assert!(matches!(d.push(&[0, 1]), Err(FrameError::BadFlags)));
    }
}
