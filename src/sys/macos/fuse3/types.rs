// value types shared with the facade; names and shapes follow the fuser 0.19 crate

use super::ffi::{ConnInfo, cap};
use std::{
    fmt, io,
    num::NonZeroI32,
    ops::{BitAnd, BitOr, BitOrAssign, Not},
    time::SystemTime,
};

macro_rules! flag_type {
    ($name:ident($ty:ty) { $($c:ident = $v:expr;)* }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name($ty);

        impl $name {
            $(pub const $c: $name = $name($v);)*

            pub const fn empty() -> Self {
                Self(0)
            }

            pub const fn bits(self) -> $ty {
                self.0
            }

            pub const fn from_bits_retain(bits: $ty) -> Self {
                Self(bits)
            }

            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }

            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            pub const fn union(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }

            pub const fn intersection(self, other: Self) -> Self {
                Self(self.0 & other.0)
            }
        }

        impl BitOr for $name {
            type Output = Self;

            fn bitor(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }
        }

        impl BitOrAssign for $name {
            fn bitor_assign(&mut self, other: Self) {
                self.0 |= other.0;
            }
        }

        impl BitAnd for $name {
            type Output = Self;

            fn bitand(self, other: Self) -> Self {
                Self(self.0 & other.0)
            }
        }

        impl Not for $name {
            type Output = Self;

            fn not(self) -> Self {
                Self(!self.0)
            }
        }
    };
}

flag_type!(InitFlags(u64) {
    FUSE_ASYNC_READ = cap::ASYNC_READ;
    FUSE_POSIX_LOCKS = cap::POSIX_LOCKS;
    FUSE_ATOMIC_O_TRUNC = cap::ATOMIC_O_TRUNC;
    FUSE_EXPORT_SUPPORT = cap::EXPORT_SUPPORT;
    FUSE_DONT_MASK = cap::DONT_MASK;
    FUSE_SPLICE_WRITE = cap::SPLICE_WRITE;
    FUSE_SPLICE_MOVE = cap::SPLICE_MOVE;
    FUSE_SPLICE_READ = cap::SPLICE_READ;
    FUSE_FLOCK_LOCKS = cap::FLOCK_LOCKS;
    FUSE_HAS_IOCTL_DIR = cap::IOCTL_DIR;
    FUSE_AUTO_INVAL_DATA = cap::AUTO_INVAL_DATA;
    FUSE_DO_READDIRPLUS = cap::READDIRPLUS;
    FUSE_READDIRPLUS_AUTO = cap::READDIRPLUS_AUTO;
    FUSE_ASYNC_DIO = cap::ASYNC_DIO;
    FUSE_WRITEBACK_CACHE = cap::WRITEBACK_CACHE;
    FUSE_NO_OPEN_SUPPORT = cap::NO_OPEN_SUPPORT;
    FUSE_PARALLEL_DIROPS = cap::PARALLEL_DIROPS;
    FUSE_POSIX_ACL = cap::POSIX_ACL;
    FUSE_HANDLE_KILLPRIV = cap::HANDLE_KILLPRIV;
    FUSE_HANDLE_KILLPRIV_V2 = cap::HANDLE_KILLPRIV_V2;
    FUSE_CACHE_SYMLINKS = cap::CACHE_SYMLINKS;
    FUSE_NO_OPENDIR_SUPPORT = cap::NO_OPENDIR_SUPPORT;
    FUSE_EXPLICIT_INVAL_DATA = cap::EXPLICIT_INVAL_DATA;
    FUSE_EXPIRE_ONLY = cap::EXPIRE_ONLY;
    FUSE_SETXATTR_EXT = cap::SETXATTR_EXT;
    FUSE_DIRECT_IO_ALLOW_MMAP = cap::DIRECT_IO_ALLOW_MMAP;
    FUSE_PASSTHROUGH = cap::PASSTHROUGH;
    FUSE_NO_EXPORT_SUPPORT = cap::NO_EXPORT_SUPPORT;
    FUSE_OVER_IO_URING = cap::OVER_IO_URING;
    FUSE_MAX_PAGES = cap::MAX_PAGES;
});

flag_type!(FopenFlags(u32) {
    FOPEN_DIRECT_IO = 1 << 0;
    FOPEN_KEEP_CACHE = 1 << 1;
    FOPEN_NONSEEKABLE = 1 << 2;
    FOPEN_CACHE_DIR = 1 << 3;
    FOPEN_STREAM = 1 << 4;
    FOPEN_NOFLUSH = 1 << 5;
    FOPEN_PARALLEL_DIRECT_WRITES = 1 << 6;
    FOPEN_PASSTHROUGH = 1 << 7;
});

flag_type!(WriteFlags(u32) {
    FUSE_WRITE_CACHE = 1 << 0;
    FUSE_WRITE_LOCKOWNER = 1 << 1;
    FUSE_WRITE_KILL_SUIDGID = 1 << 2;
});

flag_type!(CopyFileRangeFlags(u64) {});

flag_type!(BsdFileFlags(u32) {
    UF_NODUMP = libc::UF_NODUMP;
    UF_IMMUTABLE = libc::UF_IMMUTABLE;
    UF_APPEND = libc::UF_APPEND;
    UF_OPAQUE = libc::UF_OPAQUE;
    UF_HIDDEN = libc::UF_HIDDEN;
    SF_ARCHIVED = libc::SF_ARCHIVED;
    SF_IMMUTABLE = libc::SF_IMMUTABLE;
    SF_APPEND = libc::SF_APPEND;
});

// macos has no whiteout rename; the bit is masked out of every incoming flag word so it never matches
flag_type!(RenameFlags(u32) {
    RENAME_SWAP = 1 << 1;
    RENAME_EXCL = 1 << 2;
    RENAME_EXCHANGE = 1 << 1;
    RENAME_NOREPLACE = 1 << 2;
    RENAME_WHITEOUT = 1 << 31;
});

impl fmt::Display for RenameFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.bits(), f)
    }
}

macro_rules! errnos {
    ($($n:ident),* $(,)?) => {
        $(pub const $n: Errno = Errno(match NonZeroI32::new(libc::$n) {
            Some(v) => v,
            None => panic!(),
        });)*
    };
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Errno(NonZeroI32);

impl Errno {
    errnos!(
        EPERM,
        ENOENT,
        ESRCH,
        EINTR,
        EIO,
        ENXIO,
        E2BIG,
        ENOEXEC,
        EBADF,
        ECHILD,
        EAGAIN,
        ENOMEM,
        EACCES,
        EFAULT,
        ENOTBLK,
        EBUSY,
        EEXIST,
        EXDEV,
        ENODEV,
        ENOTDIR,
        EISDIR,
        EINVAL,
        ENFILE,
        EMFILE,
        ENOTTY,
        ETXTBSY,
        EFBIG,
        ENOSPC,
        ESPIPE,
        EROFS,
        EMLINK,
        EPIPE,
        EDOM,
        ERANGE,
        EDEADLK,
        ENAMETOOLONG,
        ENOLCK,
        ENOSYS,
        ENOTEMPTY,
        ELOOP,
        ENOTSUP,
        EOPNOTSUPP,
        ESTALE,
        EDQUOT,
        ETIMEDOUT,
        ENOTCONN,
        ESHUTDOWN,
        ECANCELED,
        EOVERFLOW,
        EILSEQ,
        EPROTO,
        EFTYPE,
        ENOATTR,
    );

    pub const NO_XATTR: Errno = Self::ENOATTR;

    // a value that is not a positive errno becomes eio
    pub fn from_i32(err: i32) -> Errno {
        NonZeroI32::new(err)
            .filter(|e| e.get() > 0)
            .map(Errno)
            .unwrap_or(Errno::EIO)
    }

    pub fn code(self) -> i32 {
        self.0.get()
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&io::Error::from_raw_os_error(self.code()), f)
    }
}

impl From<io::Error> for Errno {
    fn from(err: io::Error) -> Self {
        Errno::from_i32(err.raw_os_error().unwrap_or(0))
    }
}

impl From<Errno> for i32 {
    fn from(e: Errno) -> Self {
        e.code()
    }
}

macro_rules! id_type {
    ($($(#[$m:meta])* $name:ident: $($derive:ident),+;)*) => {
        $(
            #[derive(Debug, Clone, Copy, PartialEq, Eq, $($derive),+)]
            $(#[$m])*
            pub struct $name(pub u64);

            impl From<$name> for u64 {
                fn from(v: $name) -> u64 {
                    v.0
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    fmt::Display::fmt(&self.0, f)
                }
            }
        )*
    };
}

id_type! {
    INodeNo: PartialOrd, Ord, Hash;
    FileHandle: PartialOrd, Ord, Hash;
    Generation: PartialOrd, Ord, Hash;
    LockOwner: PartialOrd, Ord, Hash;
}

impl INodeNo {
    pub const ROOT: INodeNo = INodeNo(1);
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FileType {
    NamedPipe,
    CharDevice,
    BlockDevice,
    Directory,
    RegularFile,
    Symlink,
    Socket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileAttr {
    pub ino: INodeNo,
    pub size: u64,
    pub blocks: u64,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub crtime: SystemTime,
    pub kind: FileType,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimeOrNow {
    SpecificTime(SystemTime),
    Now,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum OpenAccMode {
    O_RDONLY = libc::O_RDONLY,
    O_WRONLY = libc::O_WRONLY,
    O_RDWR = libc::O_RDWR,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct OpenFlags(pub i32);

impl fmt::LowerHex for OpenFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for OpenFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl OpenFlags {
    pub fn acc_mode(self) -> OpenAccMode {
        match self.0 & libc::O_ACCMODE {
            libc::O_WRONLY => OpenAccMode::O_WRONLY,
            libc::O_RDWR => OpenAccMode::O_RDWR,
            _ => OpenAccMode::O_RDONLY,
        }
    }
}

// what libfuse reports about the caller of one request
#[derive(Clone, Copy, Debug)]
pub struct Request {
    uid: u32,
    gid: u32,
    pid: u32,
    umask: u32,
}

impl Request {
    pub(super) fn new(uid: u32, gid: u32, pid: u32, umask: u32) -> Request {
        Request {
            uid,
            gid,
            pid,
            umask,
        }
    }

    pub fn uid(&self) -> Option<u32> {
        (self.uid != u32::MAX).then_some(self.uid)
    }

    pub fn gid(&self) -> Option<u32> {
        (self.gid != u32::MAX).then_some(self.gid)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn umask(&self) -> u32 {
        self.umask
    }

    pub(super) fn owner(&self) -> Owner {
        Owner {
            uid: self.uid,
            gid: self.gid,
        }
    }
}

// capabilities the facade never grants: libfuse offers them but csync has no implementation behind them
const UNSUPPORTED: InitFlags = InitFlags::FUSE_PASSTHROUGH
    .union(InitFlags::FUSE_WRITEBACK_CACHE)
    .union(InitFlags::FUSE_MAX_PAGES)
    .union(InitFlags::FUSE_OVER_IO_URING);

const MIN_WRITE: u32 = 4096;

#[derive(Debug)]
pub struct KernelConfig {
    capable: InitFlags,
    pub(super) requested: InitFlags,
    pub(super) max_write: u32,
    max_write_limit: u32,
    pub(super) max_readahead: u32,
    max_readahead_limit: u32,
    pub(super) max_background: u32,
}

impl KernelConfig {
    pub(super) fn from_conn(conn: &ConnInfo) -> KernelConfig {
        let capable = InitFlags::from_bits_retain(conn.capable_ext).intersection(!UNSUPPORTED);
        KernelConfig {
            capable,
            requested: InitFlags::FUSE_ASYNC_READ.intersection(capable),
            max_write: conn.max_write,
            max_write_limit: conn.max_write,
            max_readahead: conn.max_readahead,
            max_readahead_limit: conn.max_readahead,
            max_background: conn.max_background,
        }
    }

    pub fn capabilities(&self) -> InitFlags {
        self.capable
    }

    // all or nothing: a request containing a capability the kernel lacks adds none of them
    pub fn add_capabilities(&mut self, capabilities_to_add: InitFlags) -> Result<(), InitFlags> {
        let refused = capabilities_to_add & !self.capable;
        if !refused.is_empty() {
            return Err(refused);
        }
        self.requested |= capabilities_to_add;
        Ok(())
    }

    // passthrough is never available, so only a depth of zero can be set
    pub fn set_max_stack_depth(&mut self, value: u32) -> Result<u32, u32> {
        if value > 0 { Err(0) } else { Ok(0) }
    }

    pub fn set_max_write(&mut self, value: u32) -> Result<u32, u32> {
        if value < MIN_WRITE {
            return Err(MIN_WRITE.min(self.max_write_limit));
        }
        if value > self.max_write_limit {
            return Err(self.max_write_limit);
        }
        Ok(std::mem::replace(&mut self.max_write, value))
    }

    pub fn set_max_readahead(&mut self, value: u32) -> Result<u32, u32> {
        if value == 0 {
            return Err(1);
        }
        if value > self.max_readahead_limit {
            return Err(self.max_readahead_limit);
        }
        Ok(std::mem::replace(&mut self.max_readahead, value))
    }

    pub fn set_max_background(&mut self, value: u16) -> Result<u16, u16> {
        if value == 0 {
            return Err(1);
        }
        let previous = std::mem::replace(&mut self.max_background, u32::from(value));
        Ok(u16::try_from(previous).unwrap_or(u16::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(capable: u64) -> ConnInfo {
        ConnInfo {
            capable_ext: capable,
            max_write: 1 << 20,
            max_readahead: 1 << 17,
            max_background: 12,
            ..ConnInfo::default()
        }
    }

    #[test]
    fn unsupported_capabilities_are_hidden_and_refused() {
        let all = cap::ASYNC_READ
            | cap::READDIRPLUS
            | cap::PASSTHROUGH
            | cap::WRITEBACK_CACHE
            | cap::EXPLICIT_INVAL_DATA
            | cap::MAX_PAGES;
        let mut cfg = KernelConfig::from_conn(&conn(all));
        let caps = cfg.capabilities();
        assert!(caps.contains(InitFlags::FUSE_ASYNC_READ));
        assert!(caps.contains(InitFlags::FUSE_DO_READDIRPLUS));
        assert!(!caps.contains(InitFlags::FUSE_PASSTHROUGH));
        assert!(!caps.contains(InitFlags::FUSE_WRITEBACK_CACHE));
        assert!(!caps.contains(InitFlags::FUSE_MAX_PAGES));
        assert_eq!(
            cfg.add_capabilities(InitFlags::FUSE_PASSTHROUGH),
            Err(InitFlags::FUSE_PASSTHROUGH)
        );
        assert_eq!(
            cfg.add_capabilities(InitFlags::FUSE_WRITEBACK_CACHE),
            Err(InitFlags::FUSE_WRITEBACK_CACHE)
        );
        assert_eq!(
            cfg.add_capabilities(InitFlags::FUSE_MAX_PAGES),
            Err(InitFlags::FUSE_MAX_PAGES)
        );
    }

    #[test]
    fn add_capabilities_is_all_or_nothing() {
        let mut cfg = KernelConfig::from_conn(&conn(cap::ASYNC_READ | cap::READDIRPLUS));
        let before = cfg.requested;
        let both = InitFlags::FUSE_DO_READDIRPLUS | InitFlags::FUSE_PARALLEL_DIROPS;
        assert_eq!(
            cfg.add_capabilities(both),
            Err(InitFlags::FUSE_PARALLEL_DIROPS)
        );
        assert_eq!(cfg.requested, before);
        assert_eq!(cfg.add_capabilities(InitFlags::FUSE_DO_READDIRPLUS), Ok(()));
        assert!(cfg.requested.contains(InitFlags::FUSE_DO_READDIRPLUS));
    }

    #[test]
    fn requested_starts_with_async_read_only_when_offered() {
        let with = KernelConfig::from_conn(&conn(cap::ASYNC_READ));
        assert_eq!(with.requested, InitFlags::FUSE_ASYNC_READ);
        let without = KernelConfig::from_conn(&conn(cap::READDIRPLUS));
        assert!(without.requested.is_empty());
    }

    #[test]
    fn sizes_are_clamped_to_what_the_kernel_offered() {
        let mut cfg = KernelConfig::from_conn(&conn(0));
        assert_eq!(cfg.set_max_write(2 << 20), Err(1 << 20));
        assert_eq!(cfg.set_max_write(100), Err(4096));
        assert_eq!(cfg.set_max_write(1 << 19), Ok(1 << 20));
        assert_eq!(cfg.max_write, 1 << 19);
        assert_eq!(cfg.set_max_readahead(0), Err(1));
        assert_eq!(cfg.set_max_readahead(1 << 20), Err(1 << 17));
        assert_eq!(cfg.set_max_readahead(1 << 16), Ok(1 << 17));
        assert_eq!(cfg.set_max_background(0), Err(1));
        assert_eq!(cfg.set_max_background(64), Ok(12));
        assert_eq!(cfg.max_background, 64);
        assert_eq!(cfg.set_max_stack_depth(1), Err(0));
        assert_eq!(cfg.set_max_stack_depth(0), Ok(0));
    }

    #[test]
    fn errno_maps_non_positive_codes_to_eio() {
        assert_eq!(Errno::from_i32(libc::ENOENT), Errno::ENOENT);
        assert_eq!(Errno::from_i32(0), Errno::EIO);
        assert_eq!(Errno::from_i32(-2), Errno::EIO);
        assert_eq!(Errno::ENOENT.code(), libc::ENOENT);
        assert_eq!(Errno::NO_XATTR, Errno::ENOATTR);
    }

    #[test]
    fn open_flags_report_the_access_mode() {
        assert_eq!(OpenFlags(libc::O_RDONLY).acc_mode(), OpenAccMode::O_RDONLY);
        assert_eq!(
            OpenFlags(libc::O_WRONLY | libc::O_TRUNC).acc_mode(),
            OpenAccMode::O_WRONLY
        );
        assert_eq!(
            OpenFlags(libc::O_RDWR | libc::O_APPEND).acc_mode(),
            OpenAccMode::O_RDWR
        );
    }

    #[test]
    fn rename_flags_follow_the_darwin_values() {
        let swap = RenameFlags::from_bits_retain(2);
        assert!(swap.contains(RenameFlags::RENAME_EXCHANGE));
        assert!(!swap.contains(RenameFlags::RENAME_NOREPLACE));
        let excl = RenameFlags::from_bits_retain(4);
        assert!(excl.contains(RenameFlags::RENAME_NOREPLACE));
        assert!(!RenameFlags::empty().contains(RenameFlags::RENAME_WHITEOUT));
    }
}
