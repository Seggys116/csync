#![no_main]
use csync::proto::{DEPTH_MAX, LinkTarget, NAME_MAX, Name, PATH_MAX, RelPath, path::TMP_PREFIX};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(p) = RelPath::new(s) {
        assert!(p.as_str().len() <= PATH_MAX);
        assert!(p.depth() <= DEPTH_MAX);
        assert_eq!(p.components().count(), p.depth());
        assert!(!s.starts_with('/') && !s.ends_with('/') && !s.contains('\0') && !s.contains("//"));
        for c in p.components() {
            assert!(c != "." && c != ".." && c.len() <= NAME_MAX && !c.starts_with(TMP_PREFIX));
            assert!(Name::new(c).is_ok());
        }
        if let Some(parent) = p.parent() {
            assert!(p.starts_with(&parent));
            assert_eq!(RelPath::new(parent.as_str()).as_ref(), Ok(&parent));
        }
    }
    if let Ok(n) = Name::new(s) {
        assert!(!s.contains('/') && s.len() <= NAME_MAX);
        let _ = n.fold_key(true);
        assert_eq!(RelPath::root().join(&n).map(|p| p.depth()), Ok(1));
    }
    if let Ok(t) = LinkTarget::new(s) {
        let at = RelPath::new("a/b/link").unwrap();
        if t.stays_within(&at) {
            let mut depth: isize = 2;
            for c in s.split('/') {
                match c { "" | "." => {} ".." => depth -= 1, _ => depth += 1 }
                assert!(depth >= 0);
            }
            assert!(!s.starts_with('/'));
        }
    }
});
