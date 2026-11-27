// raw libfuse3 3.18 (macfuse 5.5) interface, resolved with dlopen so the binary starts without macfuse

use std::{
    ffi::{CStr, CString, c_char, c_int, c_uint, c_void},
    fmt, fs, io,
    os::unix::fs::MetadataExt,
    sync::OnceLock,
};

pub(super) const LIB_PATH: &str = "/usr/local/lib/libfuse3.4.dylib";
pub(super) const VERSION: (u32, u32, u32) = (3, 18, 3);
pub(super) const VERSION_DARWIN_EXTENSIONS: u32 = 1;
pub(super) const DARWIN_CAP_THREAD_SAFE: u64 = 1 << 0;
pub(super) const DARWIN_CAP_RENAME_EXT: u64 = 1 << 3;

pub(super) type RawReq = *mut c_void;
pub(super) type RawSession = *mut c_void;
pub(super) type RawLoopConfig = *mut c_void;

pub(super) mod cap {
    pub const ASYNC_READ: u64 = 1 << 0;
    pub const POSIX_LOCKS: u64 = 1 << 1;
    pub const ATOMIC_O_TRUNC: u64 = 1 << 3;
    pub const EXPORT_SUPPORT: u64 = 1 << 4;
    pub const DONT_MASK: u64 = 1 << 6;
    pub const SPLICE_WRITE: u64 = 1 << 7;
    pub const SPLICE_MOVE: u64 = 1 << 8;
    pub const SPLICE_READ: u64 = 1 << 9;
    pub const FLOCK_LOCKS: u64 = 1 << 10;
    pub const IOCTL_DIR: u64 = 1 << 11;
    pub const AUTO_INVAL_DATA: u64 = 1 << 12;
    pub const READDIRPLUS: u64 = 1 << 13;
    pub const READDIRPLUS_AUTO: u64 = 1 << 14;
    pub const ASYNC_DIO: u64 = 1 << 15;
    pub const WRITEBACK_CACHE: u64 = 1 << 16;
    pub const NO_OPEN_SUPPORT: u64 = 1 << 17;
    pub const PARALLEL_DIROPS: u64 = 1 << 18;
    pub const POSIX_ACL: u64 = 1 << 19;
    pub const HANDLE_KILLPRIV: u64 = 1 << 20;
    pub const HANDLE_KILLPRIV_V2: u64 = 1 << 21;
    pub const CACHE_SYMLINKS: u64 = 1 << 23;
    pub const NO_OPENDIR_SUPPORT: u64 = 1 << 24;
    pub const EXPLICIT_INVAL_DATA: u64 = 1 << 25;
    pub const EXPIRE_ONLY: u64 = 1 << 26;
    pub const SETXATTR_EXT: u64 = 1 << 27;
    pub const DIRECT_IO_ALLOW_MMAP: u64 = 1 << 28;
    pub const PASSTHROUGH: u64 = 1 << 29;
    pub const NO_EXPORT_SUPPORT: u64 = 1 << 30;
    pub const OVER_IO_URING: u64 = 1 << 31;
    // no libfuse counterpart: a bit above the 32 libfuse defines, never offered by the kernel
    pub const MAX_PAGES: u64 = 1 << 40;
}

pub(super) mod set_attr {
    pub const MODE: u32 = 1 << 0;
    pub const UID: u32 = 1 << 1;
    pub const GID: u32 = 1 << 2;
    pub const SIZE: u32 = 1 << 3;
    pub const ATIME: u32 = 1 << 4;
    pub const MTIME: u32 = 1 << 5;
    pub const ATIME_NOW: u32 = 1 << 7;
    pub const MTIME_NOW: u32 = 1 << 8;
    pub const CTIME: u32 = 1 << 10;
    pub const KILL_SUID: u32 = 1 << 11;
    pub const KILL_SGID: u32 = 1 << 12;
    pub const BTIME: u32 = 1 << 28;
    pub const BKUPTIME: u32 = 1 << 30;
    pub const FLAGS: u32 = 1 << 31;
}

// bits of the word at offset 4 of fuse_file_info, lowest bit first
pub(super) mod fi_bit {
    pub const WRITEPAGE: u32 = 1 << 0;
    pub const DIRECT_IO: u32 = 1 << 1;
    pub const KEEP_CACHE: u32 = 1 << 2;
    pub const FLUSH: u32 = 1 << 3;
    pub const NONSEEKABLE: u32 = 1 << 4;
    pub const FLOCK_RELEASE: u32 = 1 << 5;
    pub const CACHE_READDIR: u32 = 1 << 6;
    pub const NOFLUSH: u32 = 1 << 7;
    pub const PARALLEL_DIRECT_WRITES: u32 = 1 << 8;
    pub const KILL_SUIDGID: u32 = 1 << 9;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct DarwinAttr {
    pub ino: u64,
    pub mode: u16,
    pub nlink: u16,
    pub uid: u32,
    pub gid: u32,
    pub rdev: i32,
    pub atimespec: Timespec,
    pub mtimespec: Timespec,
    pub ctimespec: Timespec,
    pub btimespec: Timespec,
    pub bkuptimespec: Timespec,
    pub size: i64,
    pub blocks: i64,
    pub blksize: i32,
    pub flags: u32,
    pub reserved: [u64; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct DarwinEntryParam {
    pub ino: u64,
    pub generation: u64,
    pub attr: DarwinAttr,
    pub attr_timeout: f64,
    pub entry_timeout: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct FileInfo {
    pub flags: i32,
    pub bits: u32,
    pub padding2: u32,
    pub padding3: u32,
    pub fh: u64,
    pub lock_owner: u64,
    pub poll_events: u32,
    pub backing_id: i32,
    pub compat_flags: u64,
    pub reserved: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct ConnInfo {
    pub proto_major: u32,
    pub proto_minor: u32,
    pub max_write: u32,
    pub max_read: u32,
    pub max_readahead: u32,
    pub capable: u32,
    pub want: u32,
    pub max_background: u32,
    pub congestion_threshold: u32,
    pub time_gran: u32,
    pub max_backing_stack_depth: u32,
    pub bits: u32,
    pub capable_ext: u64,
    pub want_ext: u64,
    pub capable_darwin: u64,
    pub want_darwin: u64,
    pub request_timeout: u16,
    pub reserved: [u16; 31],
}

#[repr(C)]
pub(super) struct FuseCtx {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    pub umask: u16,
}

#[repr(C)]
pub(super) struct FuseArgs {
    pub argc: c_int,
    pub argv: *mut *mut c_char,
    pub allocated: c_int,
}

#[repr(C)]
pub(super) struct LibfuseVersion {
    pub major: u32,
    pub minor: u32,
    pub hotfix: u32,
    pub flags: u32,
}

type Unused = Option<unsafe extern "C" fn()>;

// every slot of struct fuse_lowlevel_ops in header order; slots csync does not serve stay null
#[repr(C)]
#[derive(Default)]
pub(super) struct LowlevelOps {
    pub init: Option<unsafe extern "C" fn(*mut c_void, *mut ConnInfo)>,
    pub destroy: Option<unsafe extern "C" fn(*mut c_void)>,
    pub lookup: Option<unsafe extern "C" fn(RawReq, u64, *const c_char)>,
    pub forget: Option<unsafe extern "C" fn(RawReq, u64, u64)>,
    pub getattr: Option<unsafe extern "C" fn(RawReq, u64, *mut FileInfo)>,
    pub setattr: Option<unsafe extern "C" fn(RawReq, u64, *mut DarwinAttr, c_int, *mut FileInfo)>,
    pub readlink: Option<unsafe extern "C" fn(RawReq, u64)>,
    pub mknod: Option<unsafe extern "C" fn(RawReq, u64, *const c_char, libc::mode_t, libc::dev_t)>,
    pub mkdir: Option<unsafe extern "C" fn(RawReq, u64, *const c_char, libc::mode_t)>,
    pub unlink: Option<unsafe extern "C" fn(RawReq, u64, *const c_char)>,
    pub rmdir: Option<unsafe extern "C" fn(RawReq, u64, *const c_char)>,
    pub symlink: Option<unsafe extern "C" fn(RawReq, *const c_char, u64, *const c_char)>,
    pub rename:
        Option<unsafe extern "C" fn(RawReq, u64, *const c_char, u64, *const c_char, c_uint)>,
    pub link: Option<unsafe extern "C" fn(RawReq, u64, u64, *const c_char)>,
    pub open: Option<unsafe extern "C" fn(RawReq, u64, *mut FileInfo)>,
    pub read: Option<unsafe extern "C" fn(RawReq, u64, usize, i64, *mut FileInfo)>,
    pub write: Option<unsafe extern "C" fn(RawReq, u64, *const c_char, usize, i64, *mut FileInfo)>,
    pub flush: Option<unsafe extern "C" fn(RawReq, u64, *mut FileInfo)>,
    pub release: Option<unsafe extern "C" fn(RawReq, u64, *mut FileInfo)>,
    pub fsync: Option<unsafe extern "C" fn(RawReq, u64, c_int, *mut FileInfo)>,
    pub opendir: Option<unsafe extern "C" fn(RawReq, u64, *mut FileInfo)>,
    pub readdir: Option<unsafe extern "C" fn(RawReq, u64, usize, i64, *mut FileInfo)>,
    pub releasedir: Option<unsafe extern "C" fn(RawReq, u64, *mut FileInfo)>,
    pub fsyncdir: Option<unsafe extern "C" fn(RawReq, u64, c_int, *mut FileInfo)>,
    pub statfs: Option<unsafe extern "C" fn(RawReq, u64)>,
    pub setxattr: Unused,
    pub getxattr: Unused,
    pub listxattr: Unused,
    pub removexattr: Unused,
    pub access: Unused,
    pub create:
        Option<unsafe extern "C" fn(RawReq, u64, *const c_char, libc::mode_t, *mut FileInfo)>,
    pub getlk: Unused,
    pub setlk: Unused,
    pub bmap: Unused,
    pub ioctl: Unused,
    pub poll: Unused,
    pub write_buf: Unused,
    pub retrieve_reply: Unused,
    pub forget_multi: Unused,
    pub flock: Unused,
    pub fallocate: Option<unsafe extern "C" fn(RawReq, u64, c_int, i64, i64, *mut FileInfo)>,
    pub readdirplus: Option<unsafe extern "C" fn(RawReq, u64, usize, i64, *mut FileInfo)>,
    pub copy_file_range: Option<
        unsafe extern "C" fn(
            RawReq,
            u64,
            i64,
            *mut FileInfo,
            u64,
            i64,
            *mut FileInfo,
            usize,
            c_int,
        ),
    >,
    pub lseek: Unused,
    pub tmpfile: Unused,
    pub setvolname: Unused,
    pub monitor: Unused,
    pub statx: Unused,
}

const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<Timespec>() == 16);
    assert!(size_of::<DarwinAttr>() == 192);
    assert!(offset_of!(DarwinAttr, mode) == 8);
    assert!(offset_of!(DarwinAttr, uid) == 12);
    assert!(offset_of!(DarwinAttr, rdev) == 20);
    assert!(offset_of!(DarwinAttr, atimespec) == 24);
    assert!(offset_of!(DarwinAttr, bkuptimespec) == 88);
    assert!(offset_of!(DarwinAttr, size) == 104);
    assert!(offset_of!(DarwinAttr, blksize) == 120);
    assert!(offset_of!(DarwinAttr, flags) == 124);
    assert!(offset_of!(DarwinAttr, reserved) == 128);
    assert!(size_of::<DarwinEntryParam>() == 224);
    assert!(offset_of!(DarwinEntryParam, attr) == 16);
    assert!(offset_of!(DarwinEntryParam, attr_timeout) == 208);
    assert!(offset_of!(DarwinEntryParam, entry_timeout) == 216);
    assert!(size_of::<FileInfo>() == 64);
    assert!(offset_of!(FileInfo, bits) == 4);
    assert!(offset_of!(FileInfo, fh) == 16);
    assert!(offset_of!(FileInfo, lock_owner) == 24);
    assert!(offset_of!(FileInfo, poll_events) == 32);
    assert!(offset_of!(FileInfo, backing_id) == 36);
    assert!(offset_of!(FileInfo, compat_flags) == 40);
    assert!(offset_of!(FileInfo, reserved) == 48);
    assert!(size_of::<ConnInfo>() == 144);
    assert!(offset_of!(ConnInfo, max_backing_stack_depth) == 40);
    assert!(offset_of!(ConnInfo, capable_ext) == 48);
    assert!(offset_of!(ConnInfo, want_ext) == 56);
    assert!(offset_of!(ConnInfo, capable_darwin) == 64);
    assert!(offset_of!(ConnInfo, want_darwin) == 72);
    assert!(offset_of!(ConnInfo, request_timeout) == 80);
    assert!(size_of::<FuseCtx>() == 16);
    assert!(offset_of!(FuseCtx, pid) == 8);
    assert!(offset_of!(FuseCtx, umask) == 12);
    assert!(size_of::<FuseArgs>() == 24);
    assert!(offset_of!(FuseArgs, allocated) == 16);
    assert!(size_of::<LibfuseVersion>() == 16);
    assert!(size_of::<LowlevelOps>() == 48 * 8);
    assert!(offset_of!(LowlevelOps, setattr) == 5 * 8);
    assert!(offset_of!(LowlevelOps, statfs) == 24 * 8);
    assert!(offset_of!(LowlevelOps, create) == 30 * 8);
    assert!(offset_of!(LowlevelOps, fallocate) == 40 * 8);
    assert!(offset_of!(LowlevelOps, readdirplus) == 41 * 8);
    assert!(offset_of!(LowlevelOps, copy_file_range) == 42 * 8);
    assert!(offset_of!(LowlevelOps, statx) == 47 * 8);
};

#[derive(Debug)]
pub(super) enum LoadError {
    Missing,
    Untrusted,
    Open(String),
    Symbol(&'static str),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Missing => write!(
                f,
                "macFUSE 5.5 or later is not installed ({LIB_PATH} missing); install it from https://macfuse.github.io"
            ),
            LoadError::Untrusted => write!(
                f,
                "refusing to load {LIB_PATH}: it must be owned by root and not writable by group or others"
            ),
            LoadError::Open(why) => write!(f, "cannot load {LIB_PATH}: {why}"),
            LoadError::Symbol(name) => {
                write!(
                    f,
                    "macFUSE at {LIB_PATH} is older than 5.5 (missing {name})"
                )
            }
        }
    }
}

impl std::error::Error for LoadError {}

impl From<&LoadError> for io::Error {
    fn from(e: &LoadError) -> io::Error {
        let kind = match e {
            LoadError::Missing => io::ErrorKind::NotFound,
            LoadError::Untrusted => io::ErrorKind::PermissionDenied,
            LoadError::Symbol(_) => io::ErrorKind::Unsupported,
            LoadError::Open(_) => io::ErrorKind::Other,
        };
        io::Error::new(kind, e.to_string())
    }
}

fn symbol<T: Copy>(
    handle: *mut c_void,
    nul_terminated: &'static str,
    name: &'static str,
) -> Result<T, LoadError> {
    const { assert!(size_of::<T>() == size_of::<*mut c_void>()) };
    // SAFETY: nul_terminated ends in a NUL byte and handle is a live dlopen handle that is never closed.
    let p = unsafe { libc::dlsym(handle, nul_terminated.as_ptr().cast::<c_char>()) };
    if p.is_null() {
        return Err(LoadError::Symbol(name));
    }
    // SAFETY: T is a function pointer type of pointer size and p is the address of the C function with that signature.
    Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&p) })
}

macro_rules! symbols {
    ($($field:ident = $name:literal: $ty:ty;)*) => {
        #[allow(clippy::type_complexity)]
        pub(super) struct Lib {
            $(pub(super) $field: $ty,)*
        }

        impl Lib {
            fn resolve(handle: *mut c_void) -> Result<Lib, LoadError> {
                Ok(Lib {
                    $($field: symbol::<$ty>(handle, concat!($name, "\0"), $name)?,)*
                })
            }
        }
    };
}

symbols! {
    session_new_versioned = "fuse_session_new_versioned": unsafe extern "C" fn(*mut FuseArgs, *const LowlevelOps, usize, *mut LibfuseVersion, *mut c_void) -> RawSession;
    session_mount = "fuse_session_mount": unsafe extern "C" fn(RawSession, *const c_char) -> c_int;
    session_unmount = "fuse_session_unmount": unsafe extern "C" fn(RawSession);
    session_exit = "fuse_session_exit": unsafe extern "C" fn(RawSession);
    session_destroy = "fuse_session_destroy": unsafe extern "C" fn(RawSession);
    session_loop_mt = "fuse_session_loop_mt_312": unsafe extern "C" fn(RawSession, RawLoopConfig) -> c_int;
    loop_cfg_create = "fuse_loop_cfg_create": unsafe extern "C" fn() -> RawLoopConfig;
    loop_cfg_destroy = "fuse_loop_cfg_destroy": unsafe extern "C" fn(RawLoopConfig);
    loop_cfg_set_max_threads = "fuse_loop_cfg_set_max_threads": unsafe extern "C" fn(RawLoopConfig, c_uint);
    loop_cfg_set_idle_threads = "fuse_loop_cfg_set_idle_threads": unsafe extern "C" fn(RawLoopConfig, c_uint);
    loop_cfg_set_clone_fd = "fuse_loop_cfg_set_clone_fd": unsafe extern "C" fn(RawLoopConfig, c_uint);
    opt_add_arg = "fuse_opt_add_arg": unsafe extern "C" fn(*mut FuseArgs, *const c_char) -> c_int;
    opt_free_args = "fuse_opt_free_args": unsafe extern "C" fn(*mut FuseArgs);
    req_userdata = "fuse_req_userdata": unsafe extern "C" fn(RawReq) -> *mut c_void;
    req_ctx = "fuse_req_ctx": unsafe extern "C" fn(RawReq) -> *const FuseCtx;
    reply_err = "fuse_reply_err": unsafe extern "C" fn(RawReq, c_int) -> c_int;
    reply_none = "fuse_reply_none": unsafe extern "C" fn(RawReq);
    reply_entry = "fuse_reply_entry$DARWIN": unsafe extern "C" fn(RawReq, *const DarwinEntryParam) -> c_int;
    reply_create = "fuse_reply_create$DARWIN": unsafe extern "C" fn(RawReq, *const DarwinEntryParam, *const FileInfo) -> c_int;
    reply_attr = "fuse_reply_attr$DARWIN": unsafe extern "C" fn(RawReq, *const DarwinAttr, f64) -> c_int;
    reply_statfs = "fuse_reply_statfs$DARWIN": unsafe extern "C" fn(RawReq, *const libc::statfs) -> c_int;
    reply_readlink = "fuse_reply_readlink": unsafe extern "C" fn(RawReq, *const c_char) -> c_int;
    reply_open = "fuse_reply_open": unsafe extern "C" fn(RawReq, *const FileInfo) -> c_int;
    reply_write = "fuse_reply_write": unsafe extern "C" fn(RawReq, usize) -> c_int;
    reply_buf = "fuse_reply_buf": unsafe extern "C" fn(RawReq, *const c_char, usize) -> c_int;
    add_direntry = "fuse_add_direntry$DARWIN": unsafe extern "C" fn(RawReq, *mut c_char, usize, *const c_char, *const DarwinAttr, i64) -> usize;
    add_direntry_plus = "fuse_add_direntry_plus$DARWIN": unsafe extern "C" fn(RawReq, *mut c_char, usize, *const c_char, *const DarwinEntryParam, i64) -> usize;
    notify_inval_inode = "fuse_lowlevel_notify_inval_inode": unsafe extern "C" fn(RawSession, u64, i64, i64) -> c_int;
    notify_inval_entry = "fuse_lowlevel_notify_inval_entry": unsafe extern "C" fn(RawSession, u64, *const c_char, usize) -> c_int;
    notify_delete = "fuse_lowlevel_notify_delete": unsafe extern "C" fn(RawSession, u64, u64, *const c_char, usize) -> c_int;
    set_feature_flag = "fuse_set_feature_flag": unsafe extern "C" fn(*mut ConnInfo, u64) -> bool;
    unset_feature_flag = "fuse_unset_feature_flag": unsafe extern "C" fn(*mut ConnInfo, u64);
    darwin_set_feature_flag = "fuse_darwin_set_feature_flag": unsafe extern "C" fn(*mut ConnInfo, u64) -> bool;
}

static LIB: OnceLock<Result<Lib, LoadError>> = OnceLock::new();

impl Lib {
    fn open() -> Result<Lib, LoadError> {
        let file = match fs::File::open(LIB_PATH) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(LoadError::Missing),
            Err(e) => return Err(LoadError::Open(e.to_string())),
        };
        let md = file
            .metadata()
            .map_err(|e| LoadError::Open(e.to_string()))?;
        if md.uid() != 0 || md.mode() & 0o022 != 0 {
            return Err(LoadError::Untrusted);
        }
        let path = CString::new(LIB_PATH).map_err(|e| LoadError::Open(e.to_string()))?;
        // SAFETY: path is a valid nul-terminated string and the flags are plain dlopen modes.
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(LoadError::Open(dl_error()));
        }
        drop(file);
        Lib::resolve(handle)
    }
}

fn dl_error() -> String {
    // SAFETY: dlerror returns null or a nul-terminated message owned by the loader.
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        return "unknown dlopen failure".to_owned();
    }
    // SAFETY: p is non-null and nul-terminated, and is read before any other dl call.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

pub(super) fn load() -> io::Result<&'static Lib> {
    LIB.get_or_init(Lib::open).as_ref().map_err(io::Error::from)
}

// the library every callback and reply runs against; callbacks exist only after a successful load
pub(super) fn active() -> &'static Lib {
    match LIB.get() {
        Some(Ok(lib)) => lib,
        _ => std::process::abort(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, mem::offset_of, path::PathBuf, process::Command};

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    macro_rules! layout {
        ($c:expr, $r:expr, $label:literal, $cty:literal, $rty:ty, [$($f:ident),* $(,)?]) => {
            $c.push_str(&format!("S(\"{}.sizeof\", {});\n", $label, $cty));
            $r.push((format!("{}.sizeof", $label), size_of::<$rty>() as u64));
            $(
                $c.push_str(&format!("O(\"{}.{}\", {}, {});\n", $label, stringify!($f), $cty, stringify!($f)));
                $r.push((format!("{}.{}", $label, stringify!($f)), offset_of!($rty, $f) as u64));
            )*
        };
    }

    #[test]
    fn layouts_and_constants_match_the_c_headers() {
        let header = "/usr/local/include/fuse3/fuse_lowlevel.h";
        if !std::path::Path::new(header).exists() {
            eprintln!("skipping: {header} is missing");
            return;
        }
        let mut c = String::new();
        let mut r: Vec<(String, u64)> = Vec::new();
        layout!(c, r, "timespec", "struct timespec", Timespec, []);
        layout!(
            c,
            r,
            "file_info",
            "struct fuse_file_info",
            FileInfo,
            [
                flags,
                fh,
                lock_owner,
                poll_events,
                backing_id,
                compat_flags,
                reserved
            ]
        );
        layout!(
            c,
            r,
            "conn_info",
            "struct fuse_conn_info",
            ConnInfo,
            [
                proto_major,
                proto_minor,
                max_write,
                max_read,
                max_readahead,
                capable,
                want,
                max_background,
                congestion_threshold,
                time_gran,
                max_backing_stack_depth,
                capable_ext,
                want_ext,
                capable_darwin,
                want_darwin,
                request_timeout,
                reserved
            ]
        );
        layout!(
            c,
            r,
            "darwin_attr",
            "struct fuse_darwin_attr",
            DarwinAttr,
            [
                ino,
                mode,
                nlink,
                uid,
                gid,
                rdev,
                atimespec,
                mtimespec,
                ctimespec,
                btimespec,
                bkuptimespec,
                size,
                blocks,
                blksize,
                flags,
                reserved
            ]
        );
        layout!(
            c,
            r,
            "entry_param",
            "struct fuse_darwin_entry_param",
            DarwinEntryParam,
            [ino, generation, attr, attr_timeout, entry_timeout]
        );
        layout!(
            c,
            r,
            "ctx",
            "struct fuse_ctx",
            FuseCtx,
            [uid, gid, pid, umask]
        );
        layout!(
            c,
            r,
            "args",
            "struct fuse_args",
            FuseArgs,
            [argc, argv, allocated]
        );
        layout!(
            c,
            r,
            "version",
            "struct libfuse_version",
            LibfuseVersion,
            [major, minor, hotfix]
        );
        layout!(
            c,
            r,
            "ops",
            "struct fuse_lowlevel_ops",
            LowlevelOps,
            [
                init,
                destroy,
                lookup,
                forget,
                getattr,
                setattr,
                readlink,
                mknod,
                mkdir,
                unlink,
                rmdir,
                symlink,
                rename,
                link,
                open,
                read,
                write,
                flush,
                release,
                fsync,
                opendir,
                readdir,
                releasedir,
                fsyncdir,
                statfs,
                setxattr,
                getxattr,
                listxattr,
                removexattr,
                access,
                create,
                getlk,
                setlk,
                bmap,
                ioctl,
                poll,
                write_buf,
                retrieve_reply,
                forget_multi,
                flock,
                fallocate,
                readdirplus,
                copy_file_range,
                lseek,
                tmpfile,
                setvolname,
                monitor,
                statx
            ]
        );

        let fi_bits: [(&str, u32); 10] = [
            ("writepage", fi_bit::WRITEPAGE),
            ("direct_io", fi_bit::DIRECT_IO),
            ("keep_cache", fi_bit::KEEP_CACHE),
            ("flush", fi_bit::FLUSH),
            ("nonseekable", fi_bit::NONSEEKABLE),
            ("flock_release", fi_bit::FLOCK_RELEASE),
            ("cache_readdir", fi_bit::CACHE_READDIR),
            ("noflush", fi_bit::NOFLUSH),
            ("parallel_direct_writes", fi_bit::PARALLEL_DIRECT_WRITES),
            ("kill_suidgid", fi_bit::KILL_SUIDGID),
        ];
        for (name, want) in fi_bits {
            c.push_str(&format!(
                "{{ struct fuse_file_info fi; uint32_t w; memset(&fi, 0, sizeof fi); fi.{name} = 1; memcpy(&w, (char *)&fi + 4, 4); P(\"fibit.{name}\", w); }}\n"
            ));
            r.push((format!("fibit.{name}"), u64::from(want)));
        }
        c.push_str(
            "{ struct libfuse_version v; uint32_t w; memset(&v, 0, sizeof v); v.darwin_extensions_enabled = 1; memcpy(&w, (char *)&v + 12, 4); P(\"version.flags\", w); }\n",
        );
        r.push((
            "version.flags".to_owned(),
            u64::from(VERSION_DARWIN_EXTENSIONS),
        ));

        let caps: [(&str, u64); 29] = [
            ("ASYNC_READ", cap::ASYNC_READ),
            ("POSIX_LOCKS", cap::POSIX_LOCKS),
            ("ATOMIC_O_TRUNC", cap::ATOMIC_O_TRUNC),
            ("EXPORT_SUPPORT", cap::EXPORT_SUPPORT),
            ("DONT_MASK", cap::DONT_MASK),
            ("SPLICE_WRITE", cap::SPLICE_WRITE),
            ("SPLICE_MOVE", cap::SPLICE_MOVE),
            ("SPLICE_READ", cap::SPLICE_READ),
            ("FLOCK_LOCKS", cap::FLOCK_LOCKS),
            ("IOCTL_DIR", cap::IOCTL_DIR),
            ("AUTO_INVAL_DATA", cap::AUTO_INVAL_DATA),
            ("READDIRPLUS", cap::READDIRPLUS),
            ("READDIRPLUS_AUTO", cap::READDIRPLUS_AUTO),
            ("ASYNC_DIO", cap::ASYNC_DIO),
            ("WRITEBACK_CACHE", cap::WRITEBACK_CACHE),
            ("NO_OPEN_SUPPORT", cap::NO_OPEN_SUPPORT),
            ("PARALLEL_DIROPS", cap::PARALLEL_DIROPS),
            ("POSIX_ACL", cap::POSIX_ACL),
            ("HANDLE_KILLPRIV", cap::HANDLE_KILLPRIV),
            ("HANDLE_KILLPRIV_V2", cap::HANDLE_KILLPRIV_V2),
            ("CACHE_SYMLINKS", cap::CACHE_SYMLINKS),
            ("NO_OPENDIR_SUPPORT", cap::NO_OPENDIR_SUPPORT),
            ("EXPLICIT_INVAL_DATA", cap::EXPLICIT_INVAL_DATA),
            ("EXPIRE_ONLY", cap::EXPIRE_ONLY),
            ("SETXATTR_EXT", cap::SETXATTR_EXT),
            ("DIRECT_IO_ALLOW_MMAP", cap::DIRECT_IO_ALLOW_MMAP),
            ("PASSTHROUGH", cap::PASSTHROUGH),
            ("NO_EXPORT_SUPPORT", cap::NO_EXPORT_SUPPORT),
            ("OVER_IO_URING", cap::OVER_IO_URING),
        ];
        for (name, want) in caps {
            c.push_str(&format!("P(\"cap.{name}\", FUSE_CAP_{name});\n"));
            r.push((format!("cap.{name}"), want));
        }
        let darwin_caps: [(&str, u64); 2] = [
            ("THREAD_SAFE", DARWIN_CAP_THREAD_SAFE),
            ("RENAME_EXT", DARWIN_CAP_RENAME_EXT),
        ];
        for (name, want) in darwin_caps {
            c.push_str(&format!(
                "P(\"darwin_cap.{name}\", (unsigned int)FUSE_DARWIN_CAP_{name});\n"
            ));
            r.push((format!("darwin_cap.{name}"), want));
        }
        let attrs: [(&str, u32); 14] = [
            ("MODE", set_attr::MODE),
            ("UID", set_attr::UID),
            ("GID", set_attr::GID),
            ("SIZE", set_attr::SIZE),
            ("ATIME", set_attr::ATIME),
            ("MTIME", set_attr::MTIME),
            ("ATIME_NOW", set_attr::ATIME_NOW),
            ("MTIME_NOW", set_attr::MTIME_NOW),
            ("CTIME", set_attr::CTIME),
            ("KILL_SUID", set_attr::KILL_SUID),
            ("KILL_SGID", set_attr::KILL_SGID),
            ("BTIME", set_attr::BTIME),
            ("BKUPTIME", set_attr::BKUPTIME),
            ("FLAGS", set_attr::FLAGS),
        ];
        for (name, want) in attrs {
            c.push_str(&format!(
                "P(\"set_attr.{name}\", (unsigned int)FUSE_SET_ATTR_{name});\n"
            ));
            r.push((format!("set_attr.{name}"), u64::from(want)));
        }

        let source = format!(
            "#include <stdio.h>\n#include <stddef.h>\n#include <string.h>\n#include <fuse_lowlevel.h>\n\
             #define S(l, t) printf(\"%s %zu\\n\", l, sizeof(t))\n\
             #define O(l, t, f) printf(\"%s %zu\\n\", l, offsetof(t, f))\n\
             #define P(l, v) printf(\"%s %llu\\n\", l, (unsigned long long)(v))\n\
             int main(void) {{\n{c}return 0;\n}}\n"
        );

        let dir =
            TempDir(std::env::temp_dir().join(format!("csync-fuse3-abi-{}", std::process::id())));
        fs::create_dir_all(&dir.0).unwrap();
        let src = dir.0.join("layout.c");
        let bin = dir.0.join("layout");
        fs::write(&src, source).unwrap();
        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86_64"
        };
        let built = Command::new("cc")
            .arg("-DFUSE_USE_VERSION=312")
            .arg("-I/usr/local/include/fuse3")
            .args(["-arch", arch])
            .arg("-o")
            .arg(&bin)
            .arg(&src)
            .output();
        let built = match built {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                eprintln!("skipping: cc is missing");
                return;
            }
            Err(e) => panic!("cannot run cc: {e}"),
        };
        assert!(
            built.status.success(),
            "cc failed: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        let ran = Command::new(&bin).output().unwrap();
        assert!(ran.status.success(), "layout probe failed");
        let got: HashMap<String, u64> = String::from_utf8_lossy(&ran.stdout)
            .lines()
            .filter_map(|l| {
                let (k, v) = l.rsplit_once(' ')?;
                Some((k.to_owned(), v.parse().ok()?))
            })
            .collect();
        for (key, want) in r {
            assert_eq!(
                got.get(&key),
                Some(&want),
                "{key} differs from the C header"
            );
        }
    }

    #[test]
    fn load_errors_carry_the_documented_messages() {
        assert_eq!(
            LoadError::Missing.to_string(),
            "macFUSE 5.5 or later is not installed (/usr/local/lib/libfuse3.4.dylib missing); install it from https://macfuse.github.io"
        );
        assert_eq!(
            LoadError::Symbol("fuse_session_new_versioned").to_string(),
            "macFUSE at /usr/local/lib/libfuse3.4.dylib is older than 5.5 (missing fuse_session_new_versioned)"
        );
        let e = io::Error::from(&LoadError::Missing);
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }
}
