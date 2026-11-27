use serde::{Deserialize, Serialize};
pub mod frame;
pub mod hs;
pub mod path;
pub use path::{LinkTarget, Name, PathError, RelPath};

pub const PROTO: u16 = 2;
pub const FRAME_MAX: usize = 4 << 20;
pub const CHUNK_MAX: usize = 64_000;
pub const INLINE_MAX: usize = 48 << 10;
pub const BATCH_MAX: usize = 8_192;
pub const NAME_MAX: usize = 255;
pub const PATH_MAX: usize = 4_096;
pub const DEPTH_MAX: usize = 128;
pub const LINK_MAX: usize = 4_096;
pub const TEXT_MAX: usize = 1 << 20;
pub const FILE_MAX: u64 = 1 << 36;
pub const RANGE_FILE_MIN: u64 = 64 << 20;
pub const RANGE_UNIT: u32 = 4 << 20;
pub const DELTA_MIN: u64 = 1 << 20;
pub const SIGS_MAX: usize = 1 << 16;
pub const MERGE_MAX: u64 = 8 << 20;
pub const INFLIGHT_MAX: usize = 256;
pub const UNACKED_PUSH_MAX: usize = 64;

pub type Hash32 = [u8; 32];
pub type ReqId = u32;
pub type Seq = u64;
pub type IndexId = u128;
pub type BlobItem = (RelPath, Result<(Hash32, Bytes), WireErr>);

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Version {
    pub hash: Hash32,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Meta {
    pub kind: Kind,
    pub perm: u16,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub hash: Option<Hash32>,
    pub link: Option<LinkTarget>,
    pub git_ro: bool,
}
impl Meta {
    pub fn version(&self) -> Option<Version> {
        self.hash.map(|hash| Version {
            hash,
            size: self.size,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct Bytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

// names one content version of a file by the host index entry that held it, without its hash
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VerKey {
    pub index: IndexId,
    pub ver: Seq,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Want {
    Hash(Hash32),
    Ver(VerKey),
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Expect {
    Absent,
    Is(Version),
    Ver(VerKey),
    Dir,
    Any,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChunkSig {
    pub len: u32,
    pub hash: [u8; 16],
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeltaOp {
    Copy { off: u64, len: u32 },
    Data { len: u32 },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Body {
    Empty,
    Inline(Bytes),
    Stream { len: u64 },
    Delta { ops: Vec<DeltaOp>, data_len: u64 },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Mk {
    Dir { perm: u16 },
    Symlink { target: LinkTarget },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Op {
    Fetch {
        path: RelPath,
        want: Option<Want>,
        have: Option<Vec<ChunkSig>>,
        range: Option<(u64, u32)>,
    },
    FetchMany {
        items: Vec<(RelPath, Want)>,
    },
    Resolve {
        path: RelPath,
        at: VerKey,
        inline: bool,
    },
    Hashes {
        index: IndexId,
        items: Vec<(RelPath, Seq)>,
    },
    Commit {
        path: RelPath,
        base: Expect,
        new: Version,
        perm: Option<u16>,
        body: Body,
        sync: bool,
        mtime_ns: Option<i64>,
    },
    Mk {
        path: RelPath,
        what: Mk,
    },
    Remove {
        path: RelPath,
        expect: Expect,
    },
    Rename {
        from: RelPath,
        to: RelPath,
        from_expect: Expect,
        to_expect: Expect,
        body: Option<(Version, Body)>,
    },
    SetAttr {
        path: RelPath,
        expect: Expect,
        perm: Option<u16>,
        mtime_ns: Option<i64>,
    },
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireErr {
    NotFound,
    Exists,
    NotEmpty,
    NotDir,
    IsDir,
    ReadOnly,
    Ignored,
    Invalid,
    TooLarge,
    Busy,
    Io,
    Denied,
    Gone,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Reply {
    Blob {
        meta: Meta,
        body: Body,
    },
    Blobs {
        items: Vec<BlobItem>,
    },
    Hashes {
        items: Vec<Option<Hash32>>,
    },
    Done {
        meta: Meta,
    },
    Conflict {
        current: Option<Meta>,
        inline: Option<Bytes>,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SnapEntry {
    pub parent: u32,
    pub name: Name,
    pub meta: Meta,
    pub ver: Seq,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Change {
    Upsert { path: RelPath, meta: Meta, ver: Seq },
    Remove { path: RelPath },
    Rename { from: RelPath, to: RelPath },
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoticeKind {
    Refused,
    Merged,
    Promoted,
    Discarded,
    Resynced,
    IgnoreChanged,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Notice {
    pub kind: NoticeKind,
    pub path: RelPath,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Push {
    Snapshot {
        index: IndexId,
        seq: Seq,
        part: u32,
        last: bool,
        entries: Vec<SnapEntry>,
    },
    Changes {
        seq: Seq,
        changes: Vec<Change>,
    },
    Notice(Notice),
    Hashes {
        index: IndexId,
        items: Vec<(RelPath, Seq, Hash32)>,
    },
    HashesDone {
        index: IndexId,
    },
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct FsTraits {
    pub case_fold: bool,
    pub norm_fold: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ExcludeSrc {
    pub repo: RelPath,
    pub text: Bytes,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Hello {
    pub proto: u16,
    pub build: Name,
    pub have: Option<(IndexId, Seq)>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Welcome {
    pub proto: u16,
    pub project: Name,
    pub index: IndexId,
    pub seq: Seq,
    pub fs: FsTraits,
    pub repos: Vec<(RelPath, RelPath)>,
    pub excludes: Vec<ExcludeSrc>,
    pub host_ns: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bye {
    Shutdown,
    Revoked,
    ProtoMismatch,
    Limit,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Msg {
    Hello(Hello),
    Welcome(Welcome),
    Pair(hs::PairStep),
    Req {
        id: ReqId,
        op: Op,
    },
    Resp {
        id: ReqId,
        res: Result<Reply, WireErr>,
    },
    Push(Push),
    Ack {
        seq: Seq,
    },
    Cancel {
        id: ReqId,
    },
    Ping {
        t_ns: u64,
    },
    Pong {
        t_ns: u64,
        host_ns: u64,
    },
    Rekey,
    Bye(Bye),
}

fn ensure(ok: bool, why: &'static str) -> Result<(), &'static str> {
    if ok { Ok(()) } else { Err(why) }
}

impl Version {
    pub fn validate(&self) -> Result<(), &'static str> {
        ensure(self.size <= FILE_MAX, "version size")
    }
}

impl VerKey {
    pub fn validate(&self) -> Result<(), &'static str> {
        ensure(self.size <= FILE_MAX, "ver size")
    }
}

impl Want {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Hash(_) => Ok(()),
            Self::Ver(k) => k.validate(),
        }
    }
}

impl Expect {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Is(v) => v.validate(),
            Self::Ver(k) => k.validate(),
            _ => Ok(()),
        }
    }
}

impl Meta {
    pub fn validate(&self) -> Result<(), &'static str> {
        ensure(self.size <= FILE_MAX, "meta size")
    }
}

impl Body {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Empty | Self::Inline(_) => Ok(()),
            Self::Stream { len } => ensure(*len <= FILE_MAX, "stream len"),
            Self::Delta { ops, data_len } => {
                ensure(ops.len() <= BATCH_MAX, "delta ops")?;
                ensure(*data_len <= FILE_MAX, "delta data len")
            }
        }
    }
}

impl Op {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Fetch {
                want, have, range, ..
            } => {
                if let Some(w) = want {
                    w.validate()?;
                }
                if let Some(h) = have {
                    ensure(h.len() <= SIGS_MAX, "sigs")?;
                }
                if let Some((off, len)) = range {
                    ensure(*off <= FILE_MAX && *len <= RANGE_UNIT, "range")?;
                }
                Ok(())
            }
            Self::FetchMany { items } => {
                ensure(items.len() <= BATCH_MAX, "fetch items")?;
                items.iter().try_for_each(|(_, w)| w.validate())
            }
            Self::Resolve { at, .. } => at.validate(),
            Self::Hashes { items, .. } => ensure(items.len() <= BATCH_MAX, "hash items"),
            Self::Commit {
                base, new, body, ..
            } => {
                base.validate()?;
                new.validate()?;
                body.validate()
            }
            Self::Mk { .. } => Ok(()),
            Self::Remove { expect, .. } | Self::SetAttr { expect, .. } => expect.validate(),
            Self::Rename {
                from_expect,
                to_expect,
                body,
                ..
            } => {
                from_expect.validate()?;
                to_expect.validate()?;
                if let Some((v, b)) = body {
                    v.validate()?;
                    b.validate()?;
                }
                Ok(())
            }
        }
    }
}

impl Reply {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Blob { meta, body } => {
                meta.validate()?;
                body.validate()
            }
            Self::Blobs { items } => ensure(items.len() <= BATCH_MAX, "blob items"),
            Self::Hashes { items } => ensure(items.len() <= BATCH_MAX, "hash items"),
            Self::Done { meta } => meta.validate(),
            Self::Conflict { current, .. } => current.as_ref().map_or(Ok(()), Meta::validate),
        }
    }
}

impl Push {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Snapshot { entries, .. } => {
                ensure(entries.len() <= BATCH_MAX, "snapshot entries")?;
                entries.iter().try_for_each(|e| e.meta.validate())
            }
            Self::Changes { changes, .. } => {
                ensure(changes.len() <= BATCH_MAX, "changes")?;
                changes.iter().try_for_each(|c| match c {
                    Change::Upsert { meta, .. } => meta.validate(),
                    _ => Ok(()),
                })
            }
            Self::Notice(_) | Self::HashesDone { .. } => Ok(()),
            Self::Hashes { items, .. } => ensure(items.len() <= BATCH_MAX, "pushed hashes"),
        }
    }
}

impl Msg {
    // bounds that postcard cannot express; the frame decoder runs this on every message
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Welcome(w) => {
                ensure(
                    w.repos.len() <= BATCH_MAX && w.excludes.len() <= BATCH_MAX,
                    "welcome lists",
                )?;
                w.excludes
                    .iter()
                    .try_for_each(|x| ensure(x.text.0.len() <= TEXT_MAX, "exclude text"))
            }
            Self::Req { op, .. } => op.validate(),
            Self::Resp { res: Ok(r), .. } => r.validate(),
            Self::Push(p) => p.validate(),
            _ => Ok(()),
        }
    }
}

// entry i of a snapshot part has global index first + i; parents must point strictly backwards
pub fn check_snapshot_part(entries: &[SnapEntry], first: u32) -> Result<(), &'static str> {
    for (i, e) in entries.iter().enumerate() {
        let own = u64::from(first) + i as u64;
        ensure(u64::from(e.parent) < own, "snapshot parent")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(size: u64) -> Meta {
        Meta {
            kind: Kind::File,
            perm: 0o644,
            size,
            mtime_ns: 0,
            ctime_ns: 0,
            hash: None,
            link: None,
            git_ro: false,
        }
    }

    #[test]
    fn validate_bounds() {
        let p = RelPath::new("a").unwrap();
        let big = Msg::Push(Push::Changes {
            seq: 1,
            changes: vec![Change::Remove { path: p.clone() }; BATCH_MAX + 1],
        });
        assert!(big.validate().is_err());
        let ok = Msg::Push(Push::Changes {
            seq: 1,
            changes: vec![Change::Remove { path: p.clone() }; BATCH_MAX],
        });
        assert!(ok.validate().is_ok());
        let huge = Msg::Push(Push::Changes {
            seq: 1,
            changes: vec![Change::Upsert {
                path: p.clone(),
                meta: meta(FILE_MAX + 1),
                ver: 1,
            }],
        });
        assert!(huge.validate().is_err());
        let range = Msg::Req {
            id: 1,
            op: Op::Fetch {
                path: p.clone(),
                want: None,
                have: None,
                range: Some((0, RANGE_UNIT + 1)),
            },
        };
        assert!(range.validate().is_err());
        let sigs = Msg::Req {
            id: 1,
            op: Op::Fetch {
                path: p.clone(),
                want: None,
                have: Some(vec![
                    ChunkSig {
                        len: 1,
                        hash: [0; 16]
                    };
                    SIGS_MAX + 1
                ]),
                range: None,
            },
        };
        assert!(sigs.validate().is_err());
        let stream = Msg::Req {
            id: 1,
            op: Op::Commit {
                path: p.clone(),
                base: Expect::Absent,
                new: Version {
                    hash: [0; 32],
                    size: 1,
                },
                perm: None,
                body: Body::Stream { len: FILE_MAX + 1 },
                sync: false,
                mtime_ns: None,
            },
        };
        assert!(stream.validate().is_err());
        let text = Msg::Welcome(Welcome {
            proto: PROTO,
            project: Name::new("p").unwrap(),
            index: 0,
            seq: 0,
            fs: FsTraits {
                case_fold: false,
                norm_fold: false,
            },
            repos: vec![],
            excludes: vec![ExcludeSrc {
                repo: p,
                text: Bytes(vec![b'x'; TEXT_MAX + 1]),
            }],
            host_ns: 0,
        });
        assert!(text.validate().is_err());
    }

    #[test]
    fn snapshot_parents() {
        let e = |parent| SnapEntry {
            parent,
            name: Name::new("n").unwrap(),
            meta: meta(0),
            ver: 0,
        };
        assert!(check_snapshot_part(&[e(0), e(1), e(0)], 1).is_ok());
        assert!(check_snapshot_part(&[e(0), e(2)], 1).is_err());
        assert!(check_snapshot_part(&[e(5)], 5).is_err());
        assert!(check_snapshot_part(&[e(4)], 5).is_ok());
    }

    fn key(size: u64) -> VerKey {
        VerKey {
            index: u128::MAX - 3,
            ver: 77,
            size,
        }
    }

    fn roundtrip(m: &Msg) {
        let raw = postcard::to_stdvec(m).unwrap();
        let back: Msg = postcard::from_bytes(&raw).unwrap();
        assert_eq!(&back, m);
        assert!(back.validate().is_ok());
    }

    #[test]
    fn commit_mtime_roundtrip() {
        for mtime_ns in [
            None,
            Some(0),
            Some(1_700_000_000_123_456_789),
            Some(i64::MIN),
        ] {
            roundtrip(&Msg::Req {
                id: 8,
                op: Op::Commit {
                    path: RelPath::new("a/b").unwrap(),
                    base: Expect::Absent,
                    new: Version {
                        hash: [3; 32],
                        size: 2,
                    },
                    perm: Some(0o640),
                    body: Body::Inline(Bytes(vec![1, 2])),
                    sync: true,
                    mtime_ns,
                },
            });
        }
    }

    #[test]
    fn new_variants_roundtrip() {
        let p = RelPath::new("a/b").unwrap();
        let k = key(10);
        assert_eq!(
            postcard::from_bytes::<VerKey>(&postcard::to_stdvec(&k).unwrap()).unwrap(),
            k
        );
        for want in [Want::Hash([9; 32]), Want::Ver(k)] {
            assert_eq!(
                postcard::from_bytes::<Want>(&postcard::to_stdvec(&want).unwrap()).unwrap(),
                want
            );
            roundtrip(&Msg::Req {
                id: 1,
                op: Op::Fetch {
                    path: p.clone(),
                    want: Some(want),
                    have: None,
                    range: Some((4, 8)),
                },
            });
            roundtrip(&Msg::Req {
                id: 2,
                op: Op::FetchMany {
                    items: vec![(p.clone(), want)],
                },
            });
        }
        roundtrip(&Msg::Req {
            id: 3,
            op: Op::Resolve {
                path: p.clone(),
                at: k,
                inline: true,
            },
        });
        roundtrip(&Msg::Req {
            id: 4,
            op: Op::Hashes {
                index: 5,
                items: vec![(p.clone(), 6), (p.clone(), 7)],
            },
        });
        roundtrip(&Msg::Req {
            id: 5,
            op: Op::Remove {
                path: p.clone(),
                expect: Expect::Ver(k),
            },
        });
        roundtrip(&Msg::Resp {
            id: 6,
            res: Ok(Reply::Hashes {
                items: vec![Some([1; 32]), None],
            }),
        });
        roundtrip(&Msg::Resp {
            id: 7,
            res: Ok(Reply::Blobs {
                items: vec![
                    (p.clone(), Ok(([2; 32], Bytes(vec![1, 2, 3])))),
                    (p.clone(), Err(WireErr::Gone)),
                ],
            }),
        });
        roundtrip(&Msg::Push(Push::Hashes {
            index: 9,
            items: vec![(p.clone(), 3, [4; 32])],
        }));
        roundtrip(&Msg::Push(Push::HashesDone { index: 9 }));
        roundtrip(&Msg::Push(Push::Changes {
            seq: 8,
            changes: vec![Change::Upsert {
                path: p.clone(),
                meta: meta(3),
                ver: 8,
            }],
        }));
        roundtrip(&Msg::Push(Push::Snapshot {
            index: 1,
            seq: 8,
            part: 0,
            last: true,
            entries: vec![SnapEntry {
                parent: 0,
                name: Name::new("n").unwrap(),
                meta: meta(3),
                ver: 8,
            }],
        }));
    }

    #[test]
    fn validate_rejects_oversized_hash_lists_and_ver_sizes() {
        let p = RelPath::new("a").unwrap();
        let many = |n: usize| Msg::Req {
            id: 1,
            op: Op::FetchMany {
                items: vec![(p.clone(), Want::Hash([0; 32])); n],
            },
        };
        assert!(many(BATCH_MAX + 1).validate().is_err());
        assert!(many(BATCH_MAX).validate().is_ok());
        let hashes = |n: usize| Msg::Req {
            id: 1,
            op: Op::Hashes {
                index: 1,
                items: vec![(p.clone(), 1); n],
            },
        };
        assert!(hashes(BATCH_MAX + 1).validate().is_err());
        assert!(hashes(BATCH_MAX).validate().is_ok());
        let pushed = |n: usize| {
            Msg::Push(Push::Hashes {
                index: 1,
                items: vec![(p.clone(), 1, [0; 32]); n],
            })
        };
        assert!(pushed(BATCH_MAX + 1).validate().is_err());
        assert!(pushed(BATCH_MAX).validate().is_ok());
        let replied = |n: usize| Msg::Resp {
            id: 1,
            res: Ok(Reply::Hashes {
                items: vec![None; n],
            }),
        };
        assert!(replied(BATCH_MAX + 1).validate().is_err());
        assert!(replied(BATCH_MAX).validate().is_ok());
        let by_ver = Msg::Req {
            id: 1,
            op: Op::FetchMany {
                items: vec![(p.clone(), Want::Ver(key(FILE_MAX + 1)))],
            },
        };
        assert!(by_ver.validate().is_err());
        let resolve = Msg::Req {
            id: 1,
            op: Op::Resolve {
                path: p.clone(),
                at: key(FILE_MAX + 1),
                inline: false,
            },
        };
        assert!(resolve.validate().is_err());
        let expect = Msg::Req {
            id: 1,
            op: Op::Remove {
                path: p,
                expect: Expect::Ver(key(FILE_MAX + 1)),
            },
        };
        assert!(expect.validate().is_err());
    }
}
