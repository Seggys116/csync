#![no_main]
use csync::{
    merge::{MergeError, merge3},
    proto::MERGE_MAX,
};
use libfuzzer_sys::fuzz_target;

fn split(rest: &[u8], n: usize) -> (&[u8], &[u8]) { rest.split_at(n.min(rest.len())) }

fuzz_target!(|data: &[u8]| {
    let Some((hdr, rest)) = data.split_first_chunk::<4>() else { return };
    let (base, rest) = split(rest, usize::from(u16::from_le_bytes([hdr[0], hdr[1]])));
    let (ours, theirs) = split(rest, usize::from(u16::from_le_bytes([hdr[2], hdr[3]])));
    match merge3(base, ours, theirs) {
        Ok(out) => {
            assert!(std::str::from_utf8(&out).is_ok() && !out.contains(&0));
            if base == ours { assert_eq!(out, theirs); }
            if base == theirs || ours == theirs { assert_eq!(out, ours); }
        }
        Err(MergeError::Conflict(c)) => assert!(!c.is_empty() && base != ours && base != theirs && ours != theirs),
        Err(MergeError::Binary) => {
            assert!([base, ours, theirs].iter().any(|s| s.contains(&0) || std::str::from_utf8(s).is_err()));
        }
        Err(MergeError::TooLarge) => assert!(theirs.len() as u64 > MERGE_MAX),
    }
});
