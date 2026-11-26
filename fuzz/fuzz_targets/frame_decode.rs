#![no_main]
use csync::proto::{
    CHUNK_MAX, Msg,
    frame::{Decoder, Encoder, Frame, SEG_MAX},
};
use libfuzzer_sys::fuzz_target;

fn roundtrip(enc: &mut Encoder, m: &Msg) {
    let mut segs = Vec::new();
    enc.msg(m, &mut |s| segs.push(s.to_vec())).expect("re-encode");
    let mut dec = Decoder::default();
    let mut got = None;
    for s in &segs {
        assert!(s.len() <= SEG_MAX);
        if let Some(Frame::Msg(x)) = dec.push(s).expect("re-decode") { got = Some(x); }
    }
    assert_eq!(got.as_ref(), Some(m));
}

// input is a sequence of [len u16 le | segment] records fed to one decoder
fuzz_target!(|data: &[u8]| {
    let mut dec = Decoder::default();
    let mut enc = Encoder::default();
    let mut rest = data;
    while let Some((len, tail)) = rest.split_first_chunk::<2>() {
        let n = usize::from(u16::from_le_bytes(*len)).min(tail.len());
        let (seg, tail) = tail.split_at(n);
        rest = tail;
        match dec.push(seg) {
            Ok(Some(Frame::Msg(m))) => roundtrip(&mut enc, &m),
            Ok(Some(Frame::Chunk { data, .. })) => assert!(data.len() <= CHUNK_MAX),
            _ => {}
        }
    }
});
