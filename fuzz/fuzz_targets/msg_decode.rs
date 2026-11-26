#![no_main]
use csync::proto::frame::{Decoder, Encoder, Frame, decode_msg};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(m) = decode_msg(data) else { return };
    assert!(m.validate().is_ok());
    let mut segs = Vec::new();
    Encoder::default().msg(&m, &mut |s| segs.push(s.to_vec())).expect("re-encode");
    let mut dec = Decoder::default();
    let mut got = None;
    for s in &segs {
        if let Some(Frame::Msg(x)) = dec.push(s).expect("re-decode") { got = Some(x); }
    }
    assert_eq!(got, Some(m));
});
