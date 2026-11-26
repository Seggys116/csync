use crate::proto::{BATCH_MAX, ChunkSig, DeltaOp, FILE_MAX, SIGS_MAX};
use fastcdc::v2020::FastCDC;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::{fmt, io};

const AVG_MIN: u64 = 8 << 10;
const AVG_MAX: u64 = 4 << 20;
const PAR_MIN: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaError {
    TooManyOps,
    TooLarge,
    BadRange,
    DataLen,
    Io(io::ErrorKind),
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyOps => f.write_str("too many delta ops"),
            Self::TooLarge => f.write_str("delta output too large"),
            Self::BadRange => f.write_str("delta copy outside base"),
            Self::DataLen => f.write_str("delta literal length mismatch"),
            Self::Io(k) => write!(f, "delta write: {k}"),
        }
    }
}

impl std::error::Error for DeltaError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    pub ops: Vec<DeltaOp>,
    pub data_len: u64,
}

// chunk sizes depend only on the base length so both sides cut identically; min = avg/4 keeps the count near SIGS_MAX at worst
fn params(base_len: u64) -> (usize, usize, usize) {
    let need = base_len.saturating_mul(4) / (SIGS_MAX as u64 - 1) + 1;
    let avg = need.max(AVG_MIN).next_power_of_two().min(AVG_MAX) as usize;
    (avg / 4, avg, avg * 4)
}

fn bounds(data: &[u8], (min, avg, max): (usize, usize, usize)) -> Vec<(usize, usize)> {
    FastCDC::new(data, min, avg, max)
        .map(|c| (c.offset, c.length))
        .collect()
}

fn hash16(b: &[u8]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o.copy_from_slice(&blake3::hash(b).as_bytes()[..16]);
    o
}

fn hash_chunks(data: &[u8], cuts: &[(usize, usize)]) -> Vec<[u8; 16]> {
    let one = |&(o, l): &(usize, usize)| hash16(data.get(o..o + l).unwrap_or_default());
    if data.len() >= PAR_MIN {
        cuts.par_iter().map(one).collect()
    } else {
        cuts.iter().map(one).collect()
    }
}

pub fn sigs(base: &[u8]) -> Vec<ChunkSig> {
    if base.len() as u64 > FILE_MAX {
        return Vec::new();
    }
    let cuts = bounds(base, params(base.len() as u64));
    if cuts.len() > SIGS_MAX {
        return Vec::new();
    }
    let hashes = hash_chunks(base, &cuts);
    cuts.iter()
        .zip(hashes)
        .map(|(&(_, l), hash)| ChunkSig {
            len: l as u32,
            hash,
        })
        .collect()
}

fn push_copy(ops: &mut Vec<DeltaOp>, off: u64, len: u32) {
    if let Some(DeltaOp::Copy { off: po, len: pl }) = ops.last_mut()
        && *po + u64::from(*pl) == off
        && let Some(sum) = pl.checked_add(len)
    {
        *pl = sum;
        return;
    }
    ops.push(DeltaOp::Copy { off, len });
}

fn push_data(ops: &mut Vec<DeltaOp>, len: u32) {
    if let Some(DeltaOp::Data { len: pl }) = ops.last_mut()
        && let Some(sum) = pl.checked_add(len)
    {
        *pl = sum;
        return;
    }
    ops.push(DeltaOp::Data { len });
}

// None when the signatures are unusable or the delta would not save anything over sending `new`
pub fn encode(new: &[u8], have: &[ChunkSig]) -> Option<Encoded> {
    if have.is_empty() || have.len() > SIGS_MAX || new.len() as u64 > FILE_MAX {
        return None;
    }
    let mut index: FxHashMap<[u8; 16], (u64, u32)> =
        FxHashMap::with_capacity_and_hasher(have.len(), Default::default());
    let mut base_len = 0u64;
    for s in have {
        index.entry(s.hash).or_insert((base_len, s.len));
        base_len = base_len.checked_add(u64::from(s.len))?;
    }
    if base_len > FILE_MAX {
        return None;
    }
    let cuts = bounds(new, params(base_len));
    let hashes = hash_chunks(new, &cuts);
    let mut ops = Vec::new();
    let mut data_len = 0u64;
    for (&(_, l), h) in cuts.iter().zip(&hashes) {
        let l = l as u32;
        match index.get(h) {
            Some(&(off, len)) if len == l => push_copy(&mut ops, off, l),
            _ => {
                push_data(&mut ops, l);
                data_len += u64::from(l);
            }
        }
        if ops.len() > BATCH_MAX {
            return None;
        }
    }
    if !new.is_empty() && data_len == new.len() as u64 {
        return None;
    }
    Some(Encoded { ops, data_len })
}

// the literal byte runs of `new` that Data ops refer to, in order, without copying
pub fn literals<'a>(new: &'a [u8], ops: &'a [DeltaOp]) -> impl Iterator<Item = &'a [u8]> + 'a {
    let mut pos = 0usize;
    ops.iter().filter_map(move |op| match *op {
        DeltaOp::Copy { len, .. } => {
            pos = pos.saturating_add(len as usize);
            None
        }
        DeltaOp::Data { len } => {
            let s = new.get(pos..pos.saturating_add(len as usize));
            pos = pos.saturating_add(len as usize);
            s
        }
    })
}

// validates peer ops before any data is accepted; returns the exact output length
pub fn check(ops: &[DeltaOp], base_len: u64, data_len: u64, cap: u64) -> Result<u64, DeltaError> {
    if ops.len() > BATCH_MAX {
        return Err(DeltaError::TooManyOps);
    }
    let cap = cap.min(FILE_MAX);
    let (mut out, mut data) = (0u64, 0u64);
    for op in ops {
        let len = match *op {
            DeltaOp::Copy { off, len } => {
                let end = off
                    .checked_add(u64::from(len))
                    .ok_or(DeltaError::BadRange)?;
                if end > base_len {
                    return Err(DeltaError::BadRange);
                }
                len
            }
            DeltaOp::Data { len } => {
                data = data
                    .checked_add(u64::from(len))
                    .ok_or(DeltaError::DataLen)?;
                len
            }
        };
        out = out
            .checked_add(u64::from(len))
            .ok_or(DeltaError::TooLarge)?;
        if out > cap {
            return Err(DeltaError::TooLarge);
        }
    }
    if data != data_len {
        return Err(DeltaError::DataLen);
    }
    Ok(out)
}

pub fn apply_with(
    base: &[u8],
    ops: &[DeltaOp],
    data: &[u8],
    cap: u64,
    sink: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> Result<u64, DeltaError> {
    let total = check(ops, base.len() as u64, data.len() as u64, cap)?;
    let mut lit = 0usize;
    for op in ops {
        let part = match *op {
            DeltaOp::Copy { off, len } => {
                let off = usize::try_from(off).map_err(|_| DeltaError::BadRange)?;
                base.get(off..off + len as usize)
                    .ok_or(DeltaError::BadRange)?
            }
            DeltaOp::Data { len } => {
                let s = data
                    .get(lit..lit + len as usize)
                    .ok_or(DeltaError::DataLen)?;
                lit += len as usize;
                s
            }
        };
        sink(part).map_err(|e| DeltaError::Io(e.kind()))?;
    }
    Ok(total)
}

pub fn apply(
    base: &[u8],
    ops: &[DeltaOp],
    data: &[u8],
    cap: u64,
    out: &mut Vec<u8>,
) -> Result<(), DeltaError> {
    let total = check(ops, base.len() as u64, data.len() as u64, cap)?;
    out.clear();
    out.try_reserve_exact(usize::try_from(total).map_err(|_| DeltaError::TooLarge)?)
        .map_err(|_| DeltaError::TooLarge)?;
    apply_with(base, ops, data, cap, &mut |p| {
        out.extend_from_slice(p);
        Ok(())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(n: usize, seed: u8) -> Vec<u8> {
        let mut v = vec![0u8; n];
        blake3::Hasher::new()
            .update(&[seed])
            .finalize_xof()
            .fill(&mut v);
        v
    }

    fn roundtrip(base: &[u8], new: &[u8]) -> Encoded {
        let e = encode(new, &sigs(base)).expect("delta");
        let data: Vec<u8> = literals(new, &e.ops).flatten().copied().collect();
        assert_eq!(data.len() as u64, e.data_len);
        let mut out = Vec::new();
        apply(base, &e.ops, &data, FILE_MAX, &mut out).unwrap();
        assert_eq!(out, new);
        e
    }

    #[test]
    fn edit_in_middle_reuses_most_of_base() {
        let base = noise(2 << 20, 1);
        let mut new = base.clone();
        let _ = new.splice(1_000_000..1_000_010, b"inserted bytes here".iter().copied());
        let e = roundtrip(&base, &new);
        assert!(e.data_len < 200_000, "{}", e.data_len);
        assert!(e.ops.len() <= 5);
    }

    #[test]
    fn appended_and_truncated() {
        let base = noise(1 << 20, 2);
        let mut grown = base.clone();
        grown.extend_from_slice(&noise(50_000, 3));
        roundtrip(&base, &grown);
        roundtrip(&base, &base[..600_000]);
        roundtrip(&base, &[]);
    }

    #[test]
    fn unrelated_data_gives_no_delta() {
        assert_eq!(encode(&noise(1 << 20, 4), &sigs(&noise(1 << 20, 5))), None);
        assert_eq!(encode(b"x", &[]), None);
    }

    #[test]
    fn sig_count_bounded() {
        let s = sigs(&vec![0u8; 8 << 20]);
        assert!(!s.is_empty() && s.len() <= SIGS_MAX);
        assert_eq!(s.iter().map(|c| u64::from(c.len)).sum::<u64>(), 8 << 20);
        let (min, avg, max) = params(FILE_MAX);
        assert!(min >= 64 && avg <= AVG_MAX as usize && max <= 16 << 20);
    }

    #[test]
    fn malicious_ops_rejected() {
        let base = vec![1u8; 100];
        let data = vec![2u8; 10];
        let mut out = Vec::new();
        let bad = |ops: &[DeltaOp], out: &mut Vec<u8>| apply(&base, ops, &data, 1 << 20, out);
        assert_eq!(
            bad(
                &[
                    DeltaOp::Copy { off: 90, len: 11 },
                    DeltaOp::Data { len: 10 }
                ],
                &mut out
            ),
            Err(DeltaError::BadRange)
        );
        assert_eq!(
            bad(
                &[
                    DeltaOp::Copy {
                        off: u64::MAX,
                        len: 2
                    },
                    DeltaOp::Data { len: 10 }
                ],
                &mut out
            ),
            Err(DeltaError::BadRange)
        );
        assert_eq!(
            bad(
                &[
                    DeltaOp::Copy { off: 100, len: 1 },
                    DeltaOp::Data { len: 10 }
                ],
                &mut out
            ),
            Err(DeltaError::BadRange)
        );
        assert_eq!(
            bad(&[DeltaOp::Data { len: 11 }], &mut out),
            Err(DeltaError::DataLen)
        );
        assert_eq!(
            bad(&[DeltaOp::Data { len: 9 }], &mut out),
            Err(DeltaError::DataLen)
        );
        assert_eq!(
            bad(
                &[
                    DeltaOp::Data { len: u32::MAX },
                    DeltaOp::Data { len: u32::MAX }
                ],
                &mut out
            ),
            Err(DeltaError::TooLarge)
        );
        let amplify = vec![DeltaOp::Copy { off: 0, len: 100 }; BATCH_MAX];
        assert_eq!(
            apply(&base, &amplify, &[], 1 << 16, &mut out),
            Err(DeltaError::TooLarge)
        );
        let many = vec![DeltaOp::Copy { off: 0, len: 1 }; BATCH_MAX + 1];
        assert_eq!(bad(&many, &mut out), Err(DeltaError::TooManyOps));
        assert!(out.is_empty());
        bad(
            &[
                DeltaOp::Copy { off: 0, len: 100 },
                DeltaOp::Data { len: 10 },
                DeltaOp::Copy { off: 99, len: 1 },
            ],
            &mut out,
        )
        .unwrap();
        assert_eq!(out.len(), 111);
        assert_eq!(&out[100..110], &data[..]);
    }

    #[test]
    fn check_reports_exact_length_before_data() {
        let ops = [DeltaOp::Copy { off: 0, len: 5 }, DeltaOp::Data { len: 3 }];
        assert_eq!(check(&ops, 5, 3, FILE_MAX), Ok(8));
        assert_eq!(check(&ops, 4, 3, FILE_MAX), Err(DeltaError::BadRange));
        assert_eq!(check(&ops, 5, 3, 7), Err(DeltaError::TooLarge));
    }
}
