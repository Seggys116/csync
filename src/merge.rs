use crate::proto::MERGE_MAX;
use similar::{MergeResolution, TextMerge};
use std::ops::Range;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictRegion {
    pub base: Range<usize>,
    pub ours: Range<usize>,
    pub theirs: Range<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeError {
    TooLarge,
    Binary,
    Conflict(Vec<ConflictRegion>),
}

fn text(b: &[u8]) -> Result<&str, MergeError> {
    if b.contains(&0) {
        return Err(MergeError::Binary);
    }
    std::str::from_utf8(b).map_err(|_| MergeError::Binary)
}

// merge3(base, ours, theirs) -> merged bytes; conflicts come back as line ranges, markers are never written
pub fn merge3(base: &[u8], ours: &[u8], theirs: &[u8]) -> Result<Vec<u8>, MergeError> {
    if [base, ours, theirs]
        .iter()
        .any(|s| s.len() as u64 > MERGE_MAX)
    {
        return Err(MergeError::TooLarge);
    }
    let (b, o, t) = (text(base)?, text(ours)?, text(theirs)?);
    if o == t || b == t {
        return Ok(ours.to_vec());
    }
    if b == o {
        return Ok(theirs.to_vec());
    }
    let m = TextMerge::from_lines(b, o, t);
    if m.is_conflicted() {
        return Err(MergeError::Conflict(
            m.conflicts()
                .map(|r| ConflictRegion {
                    base: r.base_range(),
                    ours: r.ours_range(),
                    theirs: r.theirs_range(),
                })
                .collect(),
        ));
    }
    // each line keeps its own terminator, so lf, crlf and a missing final newline survive byte for byte
    let mut out = Vec::with_capacity(o.len().max(t.len()));
    for r in m.regions() {
        match r.resolution() {
            MergeResolution::Unchanged | MergeResolution::Ours | MergeResolution::Both => {
                for i in r.ours_range() {
                    out.extend_from_slice(m.ours_line(i).unwrap_or_default().as_bytes());
                }
            }
            MergeResolution::Theirs => {
                for i in r.theirs_range() {
                    out.extend_from_slice(m.theirs_line(i).unwrap_or_default().as_bytes());
                }
            }
            _ => {
                return Err(MergeError::Conflict(vec![ConflictRegion {
                    base: r.base_range(),
                    ours: r.ours_range(),
                    theirs: r.theirs_range(),
                }]));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_disjoint_edits() {
        let base = b"one\ntwo\nthree\nfour\n";
        let ours = b"ONE\ntwo\nthree\nfour\n";
        let theirs = b"one\ntwo\nthree\nFOUR\n";
        assert_eq!(
            merge3(base, ours, theirs).unwrap(),
            b"ONE\ntwo\nthree\nFOUR\n"
        );
    }

    #[test]
    fn trivial_sides() {
        let base = b"a\nb\n";
        let changed = b"a\nB\n";
        assert_eq!(merge3(base, base, changed).unwrap(), changed);
        assert_eq!(merge3(base, changed, base).unwrap(), changed);
        assert_eq!(merge3(base, changed, changed).unwrap(), changed);
    }

    #[test]
    fn conflict_is_structured_without_markers() {
        let r = merge3(
            b"one\ntwo\nthree\n",
            b"one\nours\nthree\n",
            b"one\ntheirs\nthree\n",
        );
        match r {
            Err(MergeError::Conflict(c)) => {
                assert_eq!(
                    c,
                    vec![ConflictRegion {
                        base: 1..2,
                        ours: 1..2,
                        theirs: 1..2
                    }]
                );
            }
            other => panic!("expected conflict, got {other:?}"),
        }
    }

    #[test]
    fn line_endings_preserved() {
        let base = b"a\r\nb\r\nc\r\nd";
        let ours = b"A\r\nb\r\nc\r\nd";
        let theirs = b"a\r\nb\r\nc\r\nD";
        assert_eq!(merge3(base, ours, theirs).unwrap(), b"A\r\nb\r\nc\r\nD");
        let mixed_base = b"x\ny\r\nz\n";
        let mixed_ours = b"x\ny\r\nz\nend\n";
        let mixed_theirs = b"X\ny\r\nz\n";
        assert_eq!(
            merge3(mixed_base, mixed_ours, mixed_theirs).unwrap(),
            b"X\ny\r\nz\nend\n"
        );
    }

    #[test]
    fn binary_and_oversize_refused() {
        assert_eq!(merge3(b"a\0b", b"a\0c", b"a\0d"), Err(MergeError::Binary));
        assert_eq!(
            merge3(b"a\n", b"\xff\xfe\n", b"b\n"),
            Err(MergeError::Binary)
        );
        assert_eq!(merge3(b"a\n", b"b\n", b"c\0\n"), Err(MergeError::Binary));
        let big = vec![b'a'; MERGE_MAX as usize + 1];
        assert_eq!(merge3(b"", &big, b"x"), Err(MergeError::TooLarge));
        assert_eq!(merge3(&big, b"", b"x"), Err(MergeError::TooLarge));
    }
}
