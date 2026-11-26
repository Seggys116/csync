use crate::{
    index::tree::StatKey,
    proto::Name,
    sys::{DirEntryPlus, S_IFDIR, S_IFLNK, S_IFREG, key_size, kind_of_mode, ts_ns},
};
use std::{
    cell::RefCell,
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

const ATTR_CMN_ERROR: u32 = 0x2000_0000;
const VREG: u32 = 1;
const VDIR: u32 = 2;
const VLNK: u32 = 5;
const BUF_WORDS: usize = 16 << 10;
const FIXED: usize = 96;

thread_local! {
    static BUF: RefCell<Box<[u64]>> = RefCell::new(vec![0u64; BUF_WORDS].into_boxed_slice());
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[off..off + 4]);
    u32::from_ne_bytes(a)
}

fn rd_i64(b: &[u8], off: usize) -> i64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    i64::from_ne_bytes(a)
}

pub fn read_dir_plus(dir: BorrowedFd<'_>, out: &mut Vec<DirEntryPlus>) -> io::Result<()> {
    rustix::fs::seek(dir, rustix::fs::SeekFrom::Start(0))?;
    let mut al = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_RETURNED_ATTRS
            | libc::ATTR_CMN_NAME
            | libc::ATTR_CMN_DEVID
            | libc::ATTR_CMN_OBJTYPE
            | libc::ATTR_CMN_MODTIME
            | libc::ATTR_CMN_CHGTIME
            | libc::ATTR_CMN_ACCESSMASK
            | libc::ATTR_CMN_FILEID
            | ATTR_CMN_ERROR,
        volattr: 0,
        dirattr: 0,
        fileattr: libc::ATTR_FILE_DATALENGTH,
        forkattr: 0,
    };
    BUF.with_borrow_mut(|words| {
        let cap = words.len() * 8;
        loop {
            // SAFETY: al is a valid attrlist, the buffer is cap writable bytes owned by this thread, dir is open.
            let n = unsafe {
                libc::getattrlistbulk(
                    dir.as_raw_fd(),
                    (&raw mut al).cast(),
                    words.as_mut_ptr().cast(),
                    cap,
                    u64::from(libc::FSOPT_PACK_INVAL_ATTRS),
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Ok(());
            }
            // SAFETY: the u64 buffer is initialised and viewing it as bytes is always valid.
            let bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), cap) };
            let mut off = 0usize;
            for _ in 0..n {
                if off + 4 > cap {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "getattrlistbulk overran its buffer",
                    ));
                }
                let len = rd_u32(bytes, off) as usize;
                if len < FIXED || off + len > cap {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "getattrlistbulk entry has a bad length",
                    ));
                }
                if let Some(e) = parse(&bytes[off..off + len]) {
                    out.push(e);
                }
                off += len;
            }
        }
    })
}

// fixed layout under fsopt_pack_inval_attrs: every requested attribute is present, in bit order,
// except that the kernel packs attr_cmn_error directly after the returned-attributes set
fn parse(e: &[u8]) -> Option<DirEntryPlus> {
    let returned_cmn = rd_u32(e, 4);
    if returned_cmn & libc::ATTR_CMN_NAME == 0 || rd_u32(e, 24) != 0 {
        return None;
    }
    let name_off = (28i64 + i64::from(rd_u32(e, 28) as i32)) as usize;
    let name_len = rd_u32(e, 32) as usize;
    let raw = e.get(name_off..name_off.checked_add(name_len)?)?;
    let raw = raw.split(|&b| b == 0).next()?;
    let name = Name::new(std::str::from_utf8(raw).ok()?).ok()?;

    let dev = rd_u32(e, 36) as i32;
    let objtype = rd_u32(e, 40);
    let mtime_ns = ts_ns(rd_i64(e, 44), rd_i64(e, 52));
    let ctime_ns = ts_ns(rd_i64(e, 60), rd_i64(e, 68));
    let perm = rd_u32(e, 76) & 0o7777;
    let ino = rd_i64(e, 80) as u64;
    let datalen = rd_i64(e, 88).max(0) as u64;
    let ftype = match objtype {
        VREG => S_IFREG,
        VDIR => S_IFDIR,
        VLNK => S_IFLNK,
        _ => 0,
    };
    let mode = ftype | perm;
    Some(DirEntryPlus {
        name,
        kind: kind_of_mode(mode),
        stat: StatKey {
            dev: dev as u64,
            ino,
            size: key_size(mode, datalen),
            mtime_ns,
            ctime_ns,
            mode,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Kind;
    use std::{
        collections::HashMap,
        fs,
        os::unix::fs::{MetadataExt, symlink},
    };

    #[test]
    fn read_dir_plus_agrees_with_std() {
        let root = std::env::temp_dir().join(format!("csync-sys-macdir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub")).unwrap();
        for i in 0..700 {
            fs::write(
                root.join(format!("f{i:04}-{}", "x".repeat(i % 90))),
                vec![b'a'; i * 3],
            )
            .unwrap();
        }
        symlink("sub", root.join("link")).unwrap();
        fs::write(root.join(".csync~tmp"), b"internal").unwrap();

        let fd = rustix::fs::open(
            &root,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let mut got = Vec::new();
        read_dir_plus(std::os::fd::AsFd::as_fd(&fd), &mut got).unwrap();
        let mut again = Vec::new();
        read_dir_plus(std::os::fd::AsFd::as_fd(&fd), &mut again).unwrap();
        assert_eq!(got.len(), again.len());

        let by: HashMap<String, DirEntryPlus> = got
            .into_iter()
            .map(|e| (e.name.as_str().to_owned(), e))
            .collect();
        let mut n = 0;
        for de in fs::read_dir(&root).unwrap() {
            let de = de.unwrap();
            let name = de.file_name().into_string().unwrap();
            if name.starts_with(".csync~") {
                assert!(!by.contains_key(&name));
                continue;
            }
            n += 1;
            let md = fs::symlink_metadata(de.path()).unwrap();
            let e = by.get(&name).unwrap_or_else(|| panic!("missing {name}"));
            let want = if md.is_dir() {
                Kind::Dir
            } else if md.file_type().is_symlink() {
                Kind::Symlink
            } else {
                Kind::File
            };
            assert_eq!(e.kind, Some(want), "{name}");
            assert_eq!(e.stat.ino, md.ino(), "{name}");
            assert_eq!(e.stat.dev, md.dev(), "{name}");
            assert_eq!(e.stat.mode, md.mode(), "{name}");
            assert_eq!(
                e.stat.mtime_ns,
                md.mtime() * 1_000_000_000 + md.mtime_nsec(),
                "{name}"
            );
            assert_eq!(
                e.stat.ctime_ns,
                md.ctime() * 1_000_000_000 + md.ctime_nsec(),
                "{name}"
            );
            if !md.is_dir() {
                assert_eq!(e.stat.size, md.size(), "{name}");
            }
            let fd2 = rustix::fs::openat(
                &fd,
                name.as_str(),
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::SYMLINK,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let k = crate::sys::stat_key(std::os::fd::AsFd::as_fd(&fd2)).unwrap();
            assert_eq!(k, e.stat, "{name}");
        }
        assert_eq!(n, by.len());
        let _ = fs::remove_dir_all(&root);
    }
}
