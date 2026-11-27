// conversions between the facade's value types and libfuse's c structs

use super::{
    ffi::{DarwinAttr, DarwinEntryParam, FileInfo, Timespec, fi_bit, set_attr},
    types::{BsdFileFlags, FileAttr, FileHandle, FileType, FopenFlags, Generation, TimeOrNow},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) fn kind_bits(kind: FileType) -> u16 {
    match kind {
        FileType::NamedPipe => libc::S_IFIFO,
        FileType::CharDevice => libc::S_IFCHR,
        FileType::BlockDevice => libc::S_IFBLK,
        FileType::Directory => libc::S_IFDIR,
        FileType::RegularFile => libc::S_IFREG,
        FileType::Symlink => libc::S_IFLNK,
        FileType::Socket => libc::S_IFSOCK,
    }
}

// times saturate here instead of at i64's ends, which the kernel may negate or add to
const TIME_BOUND: i64 = 1 << 60;

fn bounded_secs(secs: u64) -> i64 {
    i64::try_from(secs).unwrap_or(TIME_BOUND).min(TIME_BOUND)
}

pub(super) fn timespec(t: SystemTime) -> Timespec {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => Timespec {
            sec: bounded_secs(d.as_secs()),
            nsec: i64::from(d.subsec_nanos()),
        },
        Err(e) => {
            let d = e.duration();
            let secs = bounded_secs(d.as_secs());
            match d.subsec_nanos() {
                0 => Timespec {
                    sec: -secs,
                    nsec: 0,
                },
                n => Timespec {
                    sec: -secs - 1,
                    nsec: 1_000_000_000 - i64::from(n),
                },
            }
        }
    }
}

pub(super) fn system_time(sec: i64, nsec: i64) -> SystemTime {
    let nanos = u32::try_from(nsec.clamp(0, 999_999_999)).unwrap_or(0);
    let sec = sec.clamp(-TIME_BOUND, TIME_BOUND);
    if sec >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(sec.unsigned_abs(), nanos))
            .unwrap_or(UNIX_EPOCH)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(sec.unsigned_abs()))
            .and_then(|t| t.checked_add(Duration::from_nanos(u64::from(nanos))))
            .unwrap_or(UNIX_EPOCH)
    }
}

pub(super) fn darwin_attr(a: &FileAttr) -> DarwinAttr {
    DarwinAttr {
        ino: a.ino.0,
        mode: kind_bits(a.kind) | (a.perm & 0o7777),
        nlink: u16::try_from(a.nlink).unwrap_or(u16::MAX),
        uid: a.uid,
        gid: a.gid,
        rdev: a.rdev as i32,
        atimespec: timespec(a.atime),
        mtimespec: timespec(a.mtime),
        ctimespec: timespec(a.ctime),
        btimespec: timespec(a.crtime),
        bkuptimespec: Timespec::default(),
        size: i64::try_from(a.size).unwrap_or(i64::MAX),
        blocks: i64::try_from(a.blocks).unwrap_or(i64::MAX),
        blksize: i32::try_from(a.blksize).unwrap_or(i32::MAX),
        flags: a.flags,
        reserved: [0; 8],
    }
}

pub(super) fn entry_param(
    ttl: &Duration,
    a: &FileAttr,
    generation: Generation,
) -> DarwinEntryParam {
    DarwinEntryParam {
        ino: a.ino.0,
        generation: generation.0,
        attr: darwin_attr(a),
        attr_timeout: ttl.as_secs_f64(),
        entry_timeout: ttl.as_secs_f64(),
    }
}

pub(super) fn open_info(fh: FileHandle, flags: FopenFlags) -> FileInfo {
    let map = [
        (FopenFlags::FOPEN_DIRECT_IO, fi_bit::DIRECT_IO),
        (FopenFlags::FOPEN_KEEP_CACHE, fi_bit::KEEP_CACHE),
        (FopenFlags::FOPEN_NONSEEKABLE, fi_bit::NONSEEKABLE),
        (FopenFlags::FOPEN_CACHE_DIR, fi_bit::CACHE_READDIR),
        (FopenFlags::FOPEN_NOFLUSH, fi_bit::NOFLUSH),
        (
            FopenFlags::FOPEN_PARALLEL_DIRECT_WRITES,
            fi_bit::PARALLEL_DIRECT_WRITES,
        ),
    ];
    let bits = map
        .iter()
        .filter(|(f, _)| flags.contains(*f))
        .fold(0, |acc, (_, bit)| acc | bit);
    FileInfo {
        fh: fh.0,
        bits,
        ..FileInfo::default()
    }
}

pub(super) fn zeroed_statfs() -> libc::statfs {
    // SAFETY: statfs is plain integers and byte arrays, for which all zero bytes is a valid value.
    unsafe { std::mem::zeroed() }
}

// darwin counts blocks in f_bsize units, so the fundamental size goes there and the io size in f_iosize
pub(super) fn statfs_of(
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
    frsize: u32,
) -> libc::statfs {
    let mut st = zeroed_statfs();
    st.f_bsize = if frsize != 0 { frsize } else { bsize };
    st.f_iosize = i32::try_from(bsize).unwrap_or(i32::MAX);
    st.f_blocks = blocks;
    st.f_bfree = bfree;
    st.f_bavail = bavail;
    st.f_files = files;
    st.f_ffree = ffree;
    st
}

// the fields of a setattr request, each present only when its bit was set
#[derive(Debug, PartialEq)]
pub(super) struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<TimeOrNow>,
    pub mtime: Option<TimeOrNow>,
    pub ctime: Option<SystemTime>,
    pub crtime: Option<SystemTime>,
    pub bkuptime: Option<SystemTime>,
    pub flags: Option<BsdFileFlags>,
    pub kill_suid_gid: bool,
}

impl SetAttr {
    pub(super) fn decode(to_set: u32, a: &DarwinAttr) -> SetAttr {
        let has = |bit: u32| to_set & bit != 0;
        let at = |t: &Timespec| system_time(t.sec, t.nsec);
        let time_or_now = |set: u32, now: u32, t: &Timespec| {
            if has(now) {
                Some(TimeOrNow::Now)
            } else {
                has(set).then(|| TimeOrNow::SpecificTime(at(t)))
            }
        };
        SetAttr {
            mode: has(set_attr::MODE).then_some(u32::from(a.mode)),
            uid: has(set_attr::UID).then_some(a.uid),
            gid: has(set_attr::GID).then_some(a.gid),
            size: has(set_attr::SIZE).then(|| u64::try_from(a.size).unwrap_or(u64::MAX)),
            atime: time_or_now(set_attr::ATIME, set_attr::ATIME_NOW, &a.atimespec),
            mtime: time_or_now(set_attr::MTIME, set_attr::MTIME_NOW, &a.mtimespec),
            ctime: has(set_attr::CTIME).then(|| at(&a.ctimespec)),
            crtime: has(set_attr::BTIME).then(|| at(&a.btimespec)),
            bkuptime: has(set_attr::BKUPTIME).then(|| at(&a.bkuptimespec)),
            flags: has(set_attr::FLAGS).then(|| BsdFileFlags::from_bits_retain(a.flags)),
            kill_suid_gid: has(set_attr::KILL_SUID | set_attr::KILL_SGID),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::macos::fuse3::types::INodeNo;

    fn attr() -> FileAttr {
        FileAttr {
            ino: INodeNo(42),
            size: 1234,
            blocks: 3,
            atime: UNIX_EPOCH + Duration::new(10, 1),
            mtime: UNIX_EPOCH + Duration::new(20, 2),
            ctime: UNIX_EPOCH + Duration::new(30, 3),
            crtime: UNIX_EPOCH + Duration::new(40, 4),
            kind: FileType::RegularFile,
            perm: 0o640,
            nlink: 2,
            uid: 501,
            gid: 20,
            rdev: 0,
            blksize: 4096,
            flags: 0x8000,
        }
    }

    #[test]
    fn file_attr_converts_to_a_darwin_attr() {
        let d = darwin_attr(&attr());
        assert_eq!(d.ino, 42);
        assert_eq!(d.mode, libc::S_IFREG | 0o640);
        assert_eq!(d.nlink, 2);
        assert_eq!((d.uid, d.gid), (501, 20));
        assert_eq!((d.size, d.blocks, d.blksize), (1234, 3, 4096));
        assert_eq!((d.atimespec.sec, d.atimespec.nsec), (10, 1));
        assert_eq!((d.mtimespec.sec, d.mtimespec.nsec), (20, 2));
        assert_eq!((d.ctimespec.sec, d.ctimespec.nsec), (30, 3));
        assert_eq!((d.btimespec.sec, d.btimespec.nsec), (40, 4));
        assert_eq!((d.bkuptimespec.sec, d.bkuptimespec.nsec), (0, 0));
        assert_eq!(d.flags, 0x8000);
    }

    #[test]
    fn kinds_map_to_their_mode_bits_and_perm_never_leaks_into_them() {
        let mut a = attr();
        a.perm = 0o7777;
        for (kind, bits) in [
            (FileType::Directory, libc::S_IFDIR),
            (FileType::Symlink, libc::S_IFLNK),
            (FileType::NamedPipe, libc::S_IFIFO),
            (FileType::Socket, libc::S_IFSOCK),
            (FileType::CharDevice, libc::S_IFCHR),
            (FileType::BlockDevice, libc::S_IFBLK),
        ] {
            a.kind = kind;
            assert_eq!(darwin_attr(&a).mode, bits | 0o7777);
        }
        a.perm = 0xffff;
        assert_eq!(darwin_attr(&a).mode & libc::S_IFMT, libc::S_IFBLK);
    }

    #[test]
    fn oversized_fields_saturate_instead_of_wrapping() {
        let mut a = attr();
        a.nlink = 70_000;
        a.size = u64::MAX;
        a.blksize = u32::MAX;
        let d = darwin_attr(&a);
        assert_eq!(d.nlink, u16::MAX);
        assert_eq!(d.size, i64::MAX);
        assert_eq!(d.blksize, i32::MAX);
    }

    #[test]
    fn times_before_the_epoch_use_a_negative_second_and_positive_nanoseconds() {
        let t = UNIX_EPOCH - Duration::new(1, 500_000_000);
        let ts = timespec(t);
        assert_eq!((ts.sec, ts.nsec), (-2, 500_000_000));
        assert_eq!(system_time(ts.sec, ts.nsec), t);
        let whole = UNIX_EPOCH - Duration::from_secs(5);
        let ts = timespec(whole);
        assert_eq!((ts.sec, ts.nsec), (-5, 0));
        assert_eq!(system_time(-5, 0), whole);
    }

    #[test]
    fn system_time_survives_out_of_range_input() {
        let bound = Duration::from_secs(TIME_BOUND.unsigned_abs());
        assert_eq!(system_time(i64::MIN, 0), UNIX_EPOCH - bound);
        assert_eq!(system_time(i64::MAX, 0), UNIX_EPOCH + bound);
        let far = timespec(UNIX_EPOCH - bound - Duration::from_secs(1000));
        assert_eq!((far.sec, far.nsec), (-TIME_BOUND, 0));
        assert_ne!(far.sec, i64::MIN);
        assert_eq!(system_time(7, -3), UNIX_EPOCH + Duration::from_secs(7));
        assert_eq!(
            system_time(7, 2_000_000_000),
            UNIX_EPOCH + Duration::new(7, 999_999_999)
        );
    }

    #[test]
    fn entry_param_carries_the_ttl_and_generation() {
        let e = entry_param(&Duration::from_millis(1500), &attr(), Generation(9));
        assert_eq!(e.ino, 42);
        assert_eq!(e.generation, 9);
        assert_eq!(e.attr_timeout, 1.5);
        assert_eq!(e.entry_timeout, 1.5);
        assert_eq!(e.attr.ino, 42);
    }

    #[test]
    fn fopen_flags_fill_the_file_info_bitfield() {
        let fi = open_info(FileHandle(7), FopenFlags::empty());
        assert_eq!((fi.fh, fi.bits), (7, 0));
        let all = FopenFlags::FOPEN_DIRECT_IO
            | FopenFlags::FOPEN_KEEP_CACHE
            | FopenFlags::FOPEN_NONSEEKABLE
            | FopenFlags::FOPEN_CACHE_DIR
            | FopenFlags::FOPEN_NOFLUSH
            | FopenFlags::FOPEN_PARALLEL_DIRECT_WRITES;
        let fi = open_info(FileHandle(1), all);
        assert_eq!(
            fi.bits,
            fi_bit::DIRECT_IO
                | fi_bit::KEEP_CACHE
                | fi_bit::NONSEEKABLE
                | fi_bit::CACHE_READDIR
                | fi_bit::NOFLUSH
                | fi_bit::PARALLEL_DIRECT_WRITES
        );
        let one = open_info(FileHandle(1), FopenFlags::FOPEN_KEEP_CACHE);
        assert_eq!(one.bits, fi_bit::KEEP_CACHE);
        assert_eq!(one.backing_id, 0);
    }

    #[test]
    fn passthrough_and_stream_never_reach_the_file_info() {
        let fi = open_info(
            FileHandle(1),
            FopenFlags::FOPEN_PASSTHROUGH | FopenFlags::FOPEN_STREAM,
        );
        assert_eq!(fi.bits, 0);
        assert_eq!(fi.backing_id, 0);
    }

    #[test]
    fn statfs_counts_in_the_fundamental_block_size() {
        let st = statfs_of(100, 40, 30, 1000, 500, 1 << 20, 4096);
        assert_eq!(st.f_bsize, 4096);
        assert_eq!(st.f_iosize, 1 << 20);
        assert_eq!((st.f_blocks, st.f_bfree, st.f_bavail), (100, 40, 30));
        assert_eq!((st.f_files, st.f_ffree), (1000, 500));
        let no_frsize = statfs_of(1, 1, 1, 1, 1, 8192, 0);
        assert_eq!(no_frsize.f_bsize, 8192);
    }

    #[test]
    fn setattr_decodes_only_the_bits_that_are_set() {
        let a = DarwinAttr {
            mode: 0o100644,
            uid: 7,
            gid: 8,
            size: 99,
            atimespec: Timespec { sec: 5, nsec: 6 },
            mtimespec: Timespec { sec: 9, nsec: 10 },
            flags: 0x2,
            ..DarwinAttr::default()
        };
        let none = SetAttr::decode(0, &a);
        assert_eq!(
            none,
            SetAttr {
                mode: None,
                uid: None,
                gid: None,
                size: None,
                atime: None,
                mtime: None,
                ctime: None,
                crtime: None,
                bkuptime: None,
                flags: None,
                kill_suid_gid: false,
            }
        );
        let some = SetAttr::decode(
            set_attr::MODE | set_attr::SIZE | set_attr::ATIME | set_attr::MTIME | set_attr::FLAGS,
            &a,
        );
        assert_eq!(some.mode, Some(0o100644));
        assert_eq!(some.size, Some(99));
        assert_eq!(some.uid, None);
        assert_eq!(
            some.atime,
            Some(TimeOrNow::SpecificTime(UNIX_EPOCH + Duration::new(5, 6)))
        );
        assert_eq!(
            some.mtime,
            Some(TimeOrNow::SpecificTime(UNIX_EPOCH + Duration::new(9, 10)))
        );
        assert_eq!(some.flags, Some(BsdFileFlags::UF_IMMUTABLE));
    }

    #[test]
    fn setattr_now_bits_win_over_the_stored_time_and_kill_bits_combine() {
        let a = DarwinAttr::default();
        let s = SetAttr::decode(
            set_attr::ATIME | set_attr::ATIME_NOW | set_attr::MTIME_NOW | set_attr::KILL_SGID,
            &a,
        );
        assert_eq!(s.atime, Some(TimeOrNow::Now));
        assert_eq!(s.mtime, Some(TimeOrNow::Now));
        assert!(s.kill_suid_gid);
        assert!(SetAttr::decode(set_attr::KILL_SUID, &a).kill_suid_gid);
        assert!(!SetAttr::decode(set_attr::MODE, &a).kill_suid_gid);
    }

    #[test]
    fn a_negative_size_is_passed_on_as_an_unrepresentable_one() {
        let a = DarwinAttr {
            size: -1,
            ..DarwinAttr::default()
        };
        assert_eq!(SetAttr::decode(set_attr::SIZE, &a).size, Some(u64::MAX));
    }
}
