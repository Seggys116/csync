#![no_main]
use csync::{
    delta::{apply, check, encode, literals, sigs},
    proto::DeltaOp,
};
use libfuzzer_sys::fuzz_target;

const CAP: u64 = 1 << 20;

fn split(rest: &[u8], n: usize) -> (&[u8], &[u8]) { rest.split_at(n.min(rest.len())) }

// mode bit 0 picks hostile ops against apply, otherwise an encode/apply roundtrip
fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let Some((hdr, rest)) = rest.split_first_chunk::<4>() else { return };
    let (a, rest) = split(rest, usize::from(u16::from_le_bytes([hdr[0], hdr[1]])));
    let (b, rest) = split(rest, usize::from(u16::from_le_bytes([hdr[2], hdr[3]])));
    if mode & 1 == 0 {
        let ops: Vec<DeltaOp> = rest
            .chunks_exact(13)
            .map(|r| {
                let off = u64::from_le_bytes(r[1..9].try_into().unwrap());
                let len = u32::from_le_bytes(r[9..13].try_into().unwrap());
                let len = if r[0] & 4 != 0 { len % 512 } else { len };
                if r[0] & 1 == 0 {
                    let off = if r[0] & 2 != 0 { off % (a.len() as u64 + 1) } else { off };
                    DeltaOp::Copy { off, len }
                } else {
                    DeltaOp::Data { len }
                }
            })
            .collect();
        let mut out = Vec::new();
        let checked = check(&ops, a.len() as u64, b.len() as u64, CAP);
        match apply(a, &ops, b, CAP, &mut out) {
            Ok(()) => assert_eq!(checked, Ok(out.len() as u64)),
            Err(e) => assert_eq!(checked.err(), Some(e)),
        }
        assert!(out.len() as u64 <= CAP);
    } else if let Some(e) = encode(b, &sigs(a)) {
        let lits: Vec<u8> = literals(b, &e.ops).flatten().copied().collect();
        assert_eq!(lits.len() as u64, e.data_len);
        let mut out = Vec::new();
        apply(a, &e.ops, &lits, u64::MAX, &mut out).expect("own delta applies");
        assert_eq!(out, b);
    }
});
