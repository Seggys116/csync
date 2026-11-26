// the guest's view of a git index: an entry whose recorded stat still matches the host file gets the
// inode, owner and times the mount reports for it, so git on the guest finds it clean without rehashing

use sha1::{Digest, Sha1};
use sha2::Sha256;

const HDR: usize = 12;
const STAT: usize = 40;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;
const EXTENDED: u16 = 0x4000;
const NAME_MASK: u16 = 0x0fff;

// what the mount reports for a worktree file
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shown {
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sum {
    Sha1,
    Sha256,
    // index.skipHash: an all-zero trailer that git never checks
    Skip(usize),
}

impl Sum {
    fn len(self) -> usize {
        match self {
            Sum::Sha1 => 20,
            Sum::Sha256 => 32,
            Sum::Skip(n) => n,
        }
    }
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    if let Some(d) = b.get_mut(at..at + 4) {
        d.copy_from_slice(&v.to_be_bytes());
    }
}

// git's offset varint from varint.c
fn varint(b: &[u8], at: &mut usize) -> Option<usize> {
    let mut c = *b.get(*at)?;
    *at += 1;
    let mut v = usize::from(c & 0x7f);
    while c & 0x80 != 0 {
        c = *b.get(*at)?;
        *at += 1;
        v = v.checked_add(1)?.checked_mul(128)? | usize::from(c & 0x7f);
    }
    Some(v)
}

fn split_ns(ns: i64) -> (u32, u32) {
    (
        ns.div_euclid(1_000_000_000) as u32,
        ns.rem_euclid(1_000_000_000) as u32,
    )
}

// an index from a git built without USE_NSEC records zero nanoseconds
fn same_time(b: &[u8], at: usize, ns: i64) -> bool {
    let (s, n) = split_ns(ns);
    be32(b, at) == Some(s) && matches!(be32(b, at + 4), Some(x) if x == 0 || x == n)
}

struct Entry {
    at: usize,
    path: Vec<u8>,
}

// every entry's offset and path, or None unless entries and extensions end exactly at the trailer
fn entries(raw: &[u8], oid: usize, end: usize) -> Option<Vec<Entry>> {
    let ver = be32(raw, 4)?;
    let count = be32(raw, 8)? as usize;
    // the smallest v4 entry is 40 stat bytes, the oid, flags, a varint and a nul
    if count > end / (STAT + oid + 4) {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    let mut at = HDR;
    let mut prev: Vec<u8> = Vec::new();
    for _ in 0..count {
        let flags = be16(raw, at + STAT + oid)?;
        let mut p = at + STAT + oid + 2;
        if flags & EXTENDED != 0 {
            if ver < 3 {
                return None;
            }
            p += 2;
        }
        let path = if ver == 4 {
            let strip = varint(raw, &mut p)?;
            let tail = raw.get(p..end)?;
            let nul = tail.iter().position(|&c| c == 0)?;
            let keep = prev.len().checked_sub(strip)?;
            let mut path = Vec::with_capacity(keep + nul);
            path.extend_from_slice(prev.get(..keep)?);
            path.extend_from_slice(tail.get(..nul)?);
            p += nul + 1;
            path
        } else {
            let n = usize::from(flags & NAME_MASK);
            let n = if n < usize::from(NAME_MASK) {
                if raw.get(p + n) != Some(&0) {
                    return None;
                }
                n
            } else {
                raw.get(p..end)?.iter().position(|&c| c == 0)?
            };
            let path = raw.get(p..p + n)?.to_vec();
            p = at + ((p - at + n + 8) & !7);
            path
        };
        if p > end {
            return None;
        }
        if ver == 4 {
            prev.clone_from(&path);
        }
        out.push(Entry { at, path });
        at = p;
    }
    while at < end {
        let len = be32(raw, at + 4)? as usize;
        at = at.checked_add(8)?.checked_add(len)?;
    }
    (at == end).then_some(out)
}

fn sum(raw: &[u8]) -> Option<(Sum, Vec<Entry>)> {
    if raw.len() < HDR + 20 || raw.get(..4)? != b"DIRC" || !(2..=4).contains(&be32(raw, 4)?) {
        return None;
    }
    let tail = |n: usize| raw.get(raw.len().checked_sub(n)?..);
    let kinds: &[Sum] = if tail(20)?.iter().all(|&b| b == 0) {
        &[Sum::Skip(20), Sum::Skip(32)]
    } else {
        &[Sum::Sha1, Sum::Sha256]
    };
    for &k in kinds {
        let Some(end) = raw.len().checked_sub(k.len()).filter(|&e| e >= HDR) else {
            continue;
        };
        let ok = match k {
            Sum::Sha1 => Sha1::digest(&raw[..end]).as_slice() == &raw[end..],
            Sum::Sha256 => Sha256::digest(&raw[..end]).as_slice() == &raw[end..],
            Sum::Skip(_) => raw[end..].iter().all(|&b| b == 0),
        };
        if !ok {
            continue;
        }
        if let Some(e) = entries(raw, k.len(), end) {
            return Some((k, e));
        }
    }
    None
}

// None when the index is not one this understands or no entry changes
pub fn rewrite(raw: &[u8], mut look: impl FnMut(&[u8]) -> Option<Shown>) -> Option<Vec<u8>> {
    let (kind, list) = sum(raw)?;
    let mut out: Option<Vec<u8>> = None;
    for e in &list {
        let at = e.at;
        let mode = be32(raw, at + 24)?;
        let flags = be16(raw, at + STAT + kind.len())?;
        let regular = matches!(mode & S_IFMT, S_IFREG | S_IFLNK);
        if !regular || flags & 0x3000 != 0 {
            continue;
        }
        let Some(s) = look(&e.path) else {
            continue;
        };
        if be32(raw, at + 36)? != s.size as u32
            || !same_time(raw, at, s.ctime_ns)
            || !same_time(raw, at + 8, s.mtime_ns)
        {
            continue;
        }
        let (_, cn) = split_ns(s.ctime_ns);
        let (_, mn) = split_ns(s.mtime_ns);
        let want = [
            (at + 4, cn),
            (at + 12, mn),
            (at + 20, s.ino as u32),
            (at + 28, s.uid),
            (at + 32, s.gid),
        ];
        if want.iter().all(|&(o, v)| be32(raw, o) == Some(v)) {
            continue;
        }
        let buf = out.get_or_insert_with(|| raw.to_vec());
        for (o, v) in want {
            put32(buf, o, v);
        }
    }
    let mut buf = out?;
    let end = buf.len() - kind.len();
    match kind {
        Sum::Sha1 => {
            let h = Sha1::digest(&buf[..end]);
            buf[end..].copy_from_slice(&h);
        }
        Sum::Sha256 => {
            let h = Sha256::digest(&buf[..end]);
            buf[end..].copy_from_slice(&h);
        }
        Sum::Skip(_) => {}
    }
    Some(buf)
}

// the worktree a non-.git git directory names through core.worktree, relative to that directory
pub fn core_worktree(config: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(config).ok()?;
    let mut core = false;
    let mut found = None;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            core = l
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .eq_ignore_ascii_case("core");
            continue;
        }
        if !core {
            continue;
        }
        if let Some((k, v)) = l.split_once('=')
            && k.trim().eq_ignore_ascii_case("worktree")
        {
            found = Some(v.trim().trim_matches('"').to_owned());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E<'a> {
        path: &'a str,
        mode: u32,
        stage: u16,
        stat: [u32; 10],
    }

    fn stat(ctime: (u32, u32), mtime: (u32, u32), ino: u32, size: u32) -> [u32; 10] {
        [
            ctime.0, ctime.1, mtime.0, mtime.1, 7, ino, 0o100_644, 501, 20, size,
        ]
    }

    fn build(ver: u32, oid: usize, ents: &[E<'_>], ext: &[u8], kind: Sum) -> Vec<u8> {
        let mut b = b"DIRC".to_vec();
        b.extend_from_slice(&ver.to_be_bytes());
        b.extend_from_slice(&(ents.len() as u32).to_be_bytes());
        let mut prev = "";
        for e in ents {
            let start = b.len();
            let mut st = e.stat;
            st[6] = e.mode;
            for v in st {
                b.extend_from_slice(&v.to_be_bytes());
            }
            b.extend(std::iter::repeat_n(0xab, oid));
            let ext_flag = if ver >= 3 { EXTENDED } else { 0 };
            let flags = (e.stage << 12) | ext_flag | (e.path.len().min(0xfff) as u16);
            b.extend_from_slice(&flags.to_be_bytes());
            if ext_flag != 0 {
                b.extend_from_slice(&[0, 0]);
            }
            if ver == 4 {
                let common = prev
                    .bytes()
                    .zip(e.path.bytes())
                    .take_while(|(a, b)| a == b)
                    .count();
                let strip = prev.len() - common;
                assert!(strip < 128);
                b.push(strip as u8);
                b.extend_from_slice(&e.path.as_bytes()[common..]);
                b.push(0);
                prev = e.path;
            } else {
                b.extend_from_slice(e.path.as_bytes());
                let len = (b.len() - start + 8) & !7;
                b.resize(start + len, 0);
            }
        }
        b.extend_from_slice(ext);
        match kind {
            Sum::Sha1 => {
                let h = Sha1::digest(&b);
                b.extend_from_slice(&h);
            }
            Sum::Sha256 => {
                let h = Sha256::digest(&b);
                b.extend_from_slice(&h);
            }
            Sum::Skip(n) => b.resize(b.len() + n, 0),
        }
        b
    }

    fn shown(ctime: i64, mtime: i64, ino: u64, size: u64) -> Shown {
        Shown {
            ino,
            uid: 1000,
            gid: 1000,
            mtime_ns: mtime,
            ctime_ns: ctime,
            size,
        }
    }

    const NS: i64 = 1_000_000_000;

    fn field(b: &[u8], entry: usize, word: usize) -> u32 {
        let (_, list) = sum(b).unwrap();
        be32(b, list[entry].at + word * 4).unwrap()
    }

    fn sample<'a>() -> Vec<E<'a>> {
        vec![
            E {
                path: "a.txt",
                mode: 0o100_644,
                stage: 0,
                stat: stat((100, 5), (90, 6), 11, 3),
            },
            E {
                path: "dir/changed.rs",
                mode: 0o100_755,
                stage: 0,
                stat: stat((100, 0), (90, 0), 12, 4),
            },
            E {
                path: "dir/sub/link",
                mode: 0o120_000,
                stage: 0,
                stat: stat((100, 0), (90, 0), 13, 9),
            },
            E {
                path: "dir/sub/modul",
                mode: 0o160_000,
                stage: 0,
                stat: stat((0, 0), (0, 0), 0, 0),
            },
            E {
                path: "z/conflict",
                mode: 0o100_644,
                stage: 2,
                stat: stat((100, 0), (90, 0), 15, 1),
            },
        ]
    }

    fn look(p: &[u8]) -> Option<Shown> {
        match p {
            b"a.txt" => Some(shown(100 * NS + 5, 90 * NS + 6, 501, 3)),
            // the host changed it after the index was written
            b"dir/changed.rs" => Some(shown(200 * NS, 90 * NS, 502, 4)),
            // an index without nanoseconds still matches on whole seconds
            b"dir/sub/link" => Some(shown(100 * NS + 77, 90 * NS + 88, 503, 9)),
            b"dir/sub/modul" | b"z/conflict" => Some(shown(100 * NS, 90 * NS, 504, 1)),
            _ => None,
        }
    }

    #[test]
    fn matching_entries_take_the_guest_stat_in_every_format() {
        let ext = {
            let mut x = b"TREE".to_vec();
            x.extend_from_slice(&3u32.to_be_bytes());
            x.extend_from_slice(b"abc");
            x
        };
        for (ver, kind) in [
            (2, Sum::Sha1),
            (3, Sum::Sha1),
            (4, Sum::Sha1),
            (2, Sum::Sha256),
            (4, Sum::Skip(20)),
            (3, Sum::Skip(32)),
        ] {
            let oid = if matches!(kind, Sum::Sha256 | Sum::Skip(32)) {
                32
            } else {
                20
            };
            let raw = build(ver, oid, &sample(), &ext, kind);
            let out = rewrite(&raw, look).unwrap_or_else(|| panic!("v{ver} {kind:?}"));
            assert_eq!(out.len(), raw.len());
            let (k2, _) = sum(&out).expect("rewritten index keeps a valid trailer");
            assert_eq!(k2, kind);
            // ino, uid, gid of the clean entry
            assert_eq!(field(&out, 0, 5), 501);
            assert_eq!(field(&out, 0, 7), 1000);
            assert_eq!(field(&out, 0, 8), 1000);
            // the changed file keeps the host's stat so git rehashes it
            assert_eq!(field(&out, 1, 5), 12);
            assert_eq!(field(&out, 1, 7), 501);
            // whole-second match fills in the nanoseconds the mount reports
            assert_eq!(field(&out, 2, 5), 503);
            assert_eq!(field(&out, 2, 1), 77);
            assert_eq!(field(&out, 2, 3), 88);
            // gitlinks and unmerged stages are left alone
            assert_eq!(field(&out, 3, 5), 0);
            assert_eq!(field(&out, 4, 5), 15);
            let changed: Vec<usize> = (0..raw.len()).filter(|&i| raw[i] != out[i]).collect();
            let entries_end = raw.len() - kind.len() - ext.len();
            assert!(
                changed
                    .iter()
                    .all(|&i| i < entries_end || i >= raw.len() - kind.len())
            );
        }
    }

    #[test]
    fn nothing_to_change_or_unreadable_input_is_left_alone() {
        let raw = build(2, 20, &sample(), &[], Sum::Sha1);
        assert!(rewrite(&raw, |_| None).is_none());
        let once = rewrite(&raw, look).unwrap();
        assert!(
            rewrite(&once, look).is_none(),
            "a second pass changes nothing"
        );
        let mut bad = raw.clone();
        bad[40] ^= 1;
        assert!(rewrite(&bad, look).is_none(), "checksum mismatch");
        assert!(rewrite(&raw[..raw.len() - 3], look).is_none());
        assert!(rewrite(b"DIRC", look).is_none());
        let mut huge = raw.clone();
        huge[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        let end = huge.len() - 20;
        let h = Sha1::digest(&huge[..end]);
        huge[end..].copy_from_slice(&h);
        assert!(rewrite(&huge, look).is_none());
        let mut v2ext = build(2, 20, &sample()[..1], &[], Sum::Sha1);
        v2ext[HDR + STAT + 20] |= 0x40;
        let end = v2ext.len() - 20;
        let h = Sha1::digest(&v2ext[..end]);
        v2ext[end..].copy_from_slice(&h);
        assert!(
            rewrite(&v2ext, look).is_none(),
            "extended flag in a v2 index"
        );
    }

    #[test]
    fn long_names_and_truncated_extensions() {
        let long = "d/".repeat(2100) + "f";
        let ents = [E {
            path: &long,
            mode: 0o100_644,
            stage: 0,
            stat: stat((100, 5), (90, 6), 11, 3),
        }];
        let raw = build(2, 20, &ents, &[], Sum::Sha1);
        let out = rewrite(&raw, |p| {
            (p == long.as_bytes()).then(|| shown(100 * NS + 5, 90 * NS + 6, 9, 3))
        })
        .expect("a name over 4095 bytes is nul terminated");
        assert_eq!(field(&out, 0, 5), 9);
        let mut ext = b"TREE".to_vec();
        ext.extend_from_slice(&100u32.to_be_bytes());
        let raw = build(2, 20, &sample(), &ext, Sum::Sha1);
        assert!(
            rewrite(&raw, look).is_none(),
            "extension longer than the file"
        );
    }

    #[test]
    fn worktree_from_config() {
        let c = b"[core]\n\trepositoryformatversion = 0\n\tworktree = ../../../sub/x\n[remote \"o\"]\n\tworktree = no\n";
        assert_eq!(core_worktree(c).as_deref(), Some("../../../sub/x"));
        assert_eq!(core_worktree(b"[core]\n\tbare = false\n"), None);
    }
}
