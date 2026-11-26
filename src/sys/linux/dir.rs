use crate::{
    proto::Name,
    sys::{
        DirEntryPlus, S_IFDIR, S_IFMT,
        fs_unix::{key_from_statx, statx_at},
        kind_of_mode,
    },
};
use rustix::fs::{AtFlags, FileType, RawDir, SeekFrom};
use rustix::io::Errno;
use std::{io, mem::MaybeUninit, os::fd::BorrowedFd};

const DENTS_BUF: usize = 32 << 10;

fn plain_name(raw: &[u8]) -> Option<Name> {
    if raw == b"." || raw == b".." {
        return None;
    }
    Name::new(std::str::from_utf8(raw).ok()?).ok()
}

pub fn read_dir_plus(dir: BorrowedFd<'_>, out: &mut Vec<DirEntryPlus>) -> io::Result<()> {
    rustix::fs::seek(dir, SeekFrom::Start(0))?;
    let mut buf = [MaybeUninit::<u8>::uninit(); DENTS_BUF];
    let mut it = RawDir::new(dir, &mut buf);
    while let Some(ent) = it.next() {
        let ent = match ent {
            Ok(e) => e,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        };
        let cname = ent.file_name();
        let Some(name) = plain_name(cname.to_bytes()) else {
            continue;
        };
        let st = match statx_at(dir, cname, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(e) => return Err(e),
        };
        let stat = key_from_statx(&st);
        out.push(DirEntryPlus {
            name,
            kind: kind_of_mode(stat.mode),
            stat,
        });
    }
    Ok(())
}

// subdirectory names only; d_type answers without a stat on every common filesystem
pub fn subdirs(dir: BorrowedFd<'_>, out: &mut Vec<Name>) -> io::Result<()> {
    rustix::fs::seek(dir, SeekFrom::Start(0))?;
    let mut buf = [MaybeUninit::<u8>::uninit(); DENTS_BUF];
    let mut it = RawDir::new(dir, &mut buf);
    while let Some(ent) = it.next() {
        let ent = match ent {
            Ok(e) => e,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        };
        let is_dir = match ent.file_type() {
            FileType::Directory => true,
            FileType::Unknown => match statx_at(dir, ent.file_name(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => u32::from(st.stx_mode) & S_IFMT == S_IFDIR,
                Err(_) => false,
            },
            _ => false,
        };
        if is_dir && let Some(name) = plain_name(ent.file_name().to_bytes()) {
            out.push(name);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Kind;
    use std::{
        collections::HashMap,
        fs,
        os::fd::AsFd,
        os::unix::fs::{MetadataExt, symlink},
    };

    #[test]
    fn read_dir_plus_agrees_with_std() {
        let root = std::env::temp_dir().join(format!("csync-sys-linuxdir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::create_dir_all(root.join("sub2")).unwrap();
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
        read_dir_plus(fd.as_fd(), &mut got).unwrap();
        let mut again = Vec::new();
        read_dir_plus(fd.as_fd(), &mut again).unwrap();
        assert_eq!(got.len(), again.len());
        let mut dirs = Vec::new();
        subdirs(fd.as_fd(), &mut dirs).unwrap();
        let mut dirs: Vec<&str> = dirs.iter().map(|n| n.as_str()).collect();
        dirs.sort_unstable();
        assert_eq!(dirs, ["sub", "sub2"]);

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
        }
        assert_eq!(n, by.len());
        let _ = fs::remove_dir_all(&root);
    }
}
