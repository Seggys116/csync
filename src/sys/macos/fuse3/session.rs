// the filesystem trait, the callbacks libfuse invokes, and the mount, notify and teardown paths

use super::{
    args::{Backend, MountOpts, mount_args},
    ffi::{
        self, ConnInfo, DARWIN_CAP_RENAME_EXT, DARWIN_CAP_THREAD_SAFE, DarwinAttr, FileInfo,
        FuseArgs, Lib, LibfuseVersion, LowlevelOps, RawReq, RawSession, VERSION,
        VERSION_DARWIN_EXTENSIONS, fi_bit,
    },
    marshal::{SetAttr, zeroed_statfs},
    reply::{
        ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty,
        ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite,
    },
    types::{
        BsdFileFlags, CopyFileRangeFlags, Errno, FileHandle, FopenFlags, INodeNo, KernelConfig,
        LockOwner, OpenFlags, Owner, RenameFlags, Request, TimeOrNow, WriteFlags,
    },
};
use crate::sys::lock;
use std::{
    ffi::{CStr, CString, OsStr, c_char, c_int, c_uint, c_void},
    fmt, io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr::NonNull,
    sync::{Arc, Condvar, Mutex, RwLock},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

const LOOP_THREADS: c_uint = 8;
const JOIN_DEADLINE: Duration = Duration::from_secs(5);
const DISKUTIL_DEADLINE: Duration = Duration::from_secs(10);

#[allow(clippy::too_many_arguments)]
pub trait Filesystem: Send + Sync + 'static {
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
        Ok(())
    }

    fn destroy(&mut self) {}

    fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
        reply.error(Errno::ENOSYS);
    }

    fn forget(&self, _req: &Request, _ino: INodeNo, _nlookup: u64) {}

    fn getattr(&self, _req: &Request, _ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        reply.error(Errno::ENOSYS);
    }

    fn setattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        _kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn readlink(&self, _req: &Request, _ino: INodeNo, reply: ReplyData) {
        reply.error(Errno::ENOSYS);
    }

    fn mknod(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn mkdir(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn unlink(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::ENOSYS);
    }

    fn rmdir(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::ENOSYS);
    }

    fn symlink(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _link_name: &OsStr,
        _target: &Path,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EPERM);
    }

    fn rename(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _newparent: INodeNo,
        _newname: &OsStr,
        _flags: RenameFlags,
        _owner: Option<Owner>,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EPERM);
    }

    fn open(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        reply: ReplyDirectory,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn readdirplus(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        reply: ReplyDirectoryPlus,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    fn create(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        _kill_suid_gid: bool,
        _owner: Owner,
        reply: ReplyCreate,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn fallocate(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _length: u64,
        _mode: i32,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::ENOSYS);
    }

    fn copy_file_range(
        &self,
        _req: &Request,
        _ino_in: INodeNo,
        _fh_in: FileHandle,
        _offset_in: u64,
        _ino_out: INodeNo,
        _fh_out: FileHandle,
        _offset_out: u64,
        _len: u64,
        _flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        reply.error(Errno::ENOSYS);
    }
}

// the session's userdata: the filesystem plus the state callbacks share with the session owner
struct Ud<F> {
    fs: F,
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    se: RwLock<Option<SePtr>>,
    init_err: Mutex<Option<io::Error>>,
    done: Mutex<Option<c_int>>,
    done_cv: Condvar,
}

impl Shared {
    fn set_session(&self, se: Option<SePtr>) {
        *self.se.write().unwrap_or_else(|e| e.into_inner()) = se;
    }

    fn wait_done(&self, timeout: Duration) -> bool {
        let guard = lock(&self.done);
        let (guard, _) = self
            .done_cv
            .wait_timeout_while(guard, timeout, |d| d.is_none())
            .unwrap_or_else(|e| e.into_inner());
        guard.is_some()
    }
}

#[derive(Clone, Copy)]
struct SePtr(NonNull<c_void>);

// SAFETY: libfuse serialises its own session state and the pointer is only used until teardown destroys the session.
unsafe impl Send for SePtr {}
// SAFETY: see Send; notifications and exit may be issued from any thread.
unsafe impl Sync for SePtr {}

impl SePtr {
    fn as_ptr(self) -> RawSession {
        self.0.as_ptr()
    }
}

struct UdPtr(NonNull<c_void>);

// SAFETY: the userdata is a Ud<F> whose contents are Send + Sync, freed once by the session owner.
unsafe impl Send for UdPtr {}
// SAFETY: see Send; the pointer itself is only dereferenced at teardown.
unsafe impl Sync for UdPtr {}

// SAFETY contract for the callbacks below: libfuse hands them a live request or connection, valid pointers for the
// duration of the call, and userdata that is the Ud<F> leaked by mount and freed only after the session is destroyed.
fn enter<'a, F: Filesystem>(req: RawReq) -> (&'a Ud<F>, Request) {
    let lib = ffi::active();
    // SAFETY: req is the live request being dispatched; its userdata is the leaked Ud<F> and its context lives as long as the request.
    unsafe {
        let ud = &*(lib.req_userdata)(req).cast::<Ud<F>>();
        let c = &*(lib.req_ctx)(req);
        (
            ud,
            Request::new(c.uid, c.gid, c.pid as u32, u32::from(c.umask)),
        )
    }
}

fn os_name<'a>(p: *const c_char) -> &'a OsStr {
    if p.is_null() {
        return OsStr::new("");
    }
    // SAFETY: libfuse passes nul-terminated names that stay valid for the callback.
    OsStr::from_bytes(unsafe { CStr::from_ptr(p) }.to_bytes())
}

fn payload<'a>(buf: *const c_char, len: usize) -> &'a [u8] {
    if len == 0 || buf.is_null() {
        return &[];
    }
    // SAFETY: libfuse passes a buffer of len readable bytes that stays valid for the callback.
    unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) }
}

fn fi_opt(fi: *mut FileInfo) -> Option<FileInfo> {
    // SAFETY: libfuse passes null or a valid fuse_file_info that stays valid for the callback.
    unsafe { fi.as_ref().copied() }
}

fn fi_of(fi: *mut FileInfo) -> FileInfo {
    fi_opt(fi).unwrap_or_default()
}

fn attr_in(attr: *mut DarwinAttr) -> DarwinAttr {
    // SAFETY: libfuse passes null or a valid fuse_darwin_attr that stays valid for the callback.
    unsafe { attr.as_ref().copied() }.unwrap_or_default()
}

fn size32(size: usize) -> u32 {
    u32::try_from(size).unwrap_or(u32::MAX)
}

extern "C" fn tr_init<F: Filesystem>(ud: *mut c_void, conn: *mut ConnInfo) {
    // SAFETY: libfuse passes the userdata given at session creation and a live connection only this callback touches.
    let (ud, conn) = unsafe { (&mut *ud.cast::<Ud<F>>(), &mut *conn) };
    let lib = ffi::active();
    let mut cfg = KernelConfig::from_conn(conn);
    let req = Request::new(u32::MAX, u32::MAX, std::process::id(), 0);
    match ud.fs.init(&req, &mut cfg) {
        Ok(()) => apply_config(lib, conn, &cfg),
        Err(e) => {
            *lock(&ud.shared.init_err) = Some(e);
            let guard = ud.shared.se.read().unwrap_or_else(|e| e.into_inner());
            if let Some(se) = *guard {
                // SAFETY: the session pointer is live while the read guard is held.
                unsafe { (lib.session_exit)(se.as_ptr()) };
            }
        }
    }
}

// the capabilities libfuse enables by default are cleared first so the connection carries exactly what init asked for
fn apply_config(lib: &Lib, conn: &mut ConnInfo, cfg: &KernelConfig) {
    let wanted = cfg.requested.bits();
    for bit in 0..32 {
        let flag = 1u64 << bit;
        if wanted & flag != 0 {
            // SAFETY: conn is the live connection of this init callback and flag is one capability bit.
            unsafe { (lib.set_feature_flag)(conn, flag) };
        } else if conn.want_ext & flag != 0 {
            // SAFETY: as above.
            unsafe { (lib.unset_feature_flag)(conn, flag) };
        }
    }
    for flag in [DARWIN_CAP_THREAD_SAFE, DARWIN_CAP_RENAME_EXT] {
        if conn.capable_darwin & flag != 0 {
            // SAFETY: conn is the live connection and the kernel offered this darwin capability.
            unsafe { (lib.darwin_set_feature_flag)(conn, flag) };
        }
    }
    conn.max_write = cfg.max_write;
    conn.max_readahead = cfg.max_readahead;
    conn.max_background = cfg.max_background;
}

extern "C" fn tr_destroy<F: Filesystem>(ud: *mut c_void) {
    // SAFETY: libfuse passes the userdata given at session creation, and no request runs once destroy is called.
    let ud = unsafe { &mut *ud.cast::<Ud<F>>() };
    ud.fs.destroy();
}

extern "C" fn tr_lookup<F: Filesystem>(req: RawReq, parent: u64, name: *const c_char) {
    let (ud, rq) = enter::<F>(req);
    ud.fs
        .lookup(&rq, INodeNo(parent), os_name(name), ReplyEntry::new(req));
}

extern "C" fn tr_forget<F: Filesystem>(req: RawReq, ino: u64, nlookup: u64) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.forget(&rq, INodeNo(ino), nlookup);
    // SAFETY: req is the live request and forget is answered by fuse_reply_none, which also frees it.
    unsafe { (ffi::active().reply_none)(req) };
}

extern "C" fn tr_getattr<F: Filesystem>(req: RawReq, ino: u64, fi: *mut FileInfo) {
    let (ud, rq) = enter::<F>(req);
    let fh = fi_opt(fi).map(|f| FileHandle(f.fh));
    ud.fs.getattr(&rq, INodeNo(ino), fh, ReplyAttr::new(req));
}

extern "C" fn tr_setattr<F: Filesystem>(
    req: RawReq,
    ino: u64,
    attr: *mut DarwinAttr,
    to_set: c_int,
    fi: *mut FileInfo,
) {
    let (ud, rq) = enter::<F>(req);
    let s = SetAttr::decode(to_set as u32, &attr_in(attr));
    let fh = fi_opt(fi).map(|f| FileHandle(f.fh));
    ud.fs.setattr(
        &rq,
        INodeNo(ino),
        s.mode,
        s.uid,
        s.gid,
        s.size,
        s.atime,
        s.mtime,
        s.ctime,
        fh,
        s.crtime,
        None,
        s.bkuptime,
        s.flags,
        s.kill_suid_gid,
        ReplyAttr::new(req),
    );
}

extern "C" fn tr_readlink<F: Filesystem>(req: RawReq, ino: u64) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.readlink(&rq, INodeNo(ino), ReplyData::link(req));
}

extern "C" fn tr_mknod<F: Filesystem>(
    req: RawReq,
    parent: u64,
    name: *const c_char,
    mode: libc::mode_t,
    rdev: libc::dev_t,
) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.mknod(
        &rq,
        INodeNo(parent),
        os_name(name),
        u32::from(mode),
        rq.umask(),
        rdev as u32,
        rq.owner(),
        ReplyEntry::new(req),
    );
}

extern "C" fn tr_mkdir<F: Filesystem>(
    req: RawReq,
    parent: u64,
    name: *const c_char,
    mode: libc::mode_t,
) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.mkdir(
        &rq,
        INodeNo(parent),
        os_name(name),
        u32::from(mode),
        rq.umask(),
        rq.owner(),
        ReplyEntry::new(req),
    );
}

extern "C" fn tr_unlink<F: Filesystem>(req: RawReq, parent: u64, name: *const c_char) {
    let (ud, rq) = enter::<F>(req);
    ud.fs
        .unlink(&rq, INodeNo(parent), os_name(name), ReplyEmpty::new(req));
}

extern "C" fn tr_rmdir<F: Filesystem>(req: RawReq, parent: u64, name: *const c_char) {
    let (ud, rq) = enter::<F>(req);
    ud.fs
        .rmdir(&rq, INodeNo(parent), os_name(name), ReplyEmpty::new(req));
}

extern "C" fn tr_symlink<F: Filesystem>(
    req: RawReq,
    link: *const c_char,
    parent: u64,
    name: *const c_char,
) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.symlink(
        &rq,
        INodeNo(parent),
        os_name(name),
        Path::new(os_name(link)),
        rq.owner(),
        ReplyEntry::new(req),
    );
}

extern "C" fn tr_rename<F: Filesystem>(
    req: RawReq,
    parent: u64,
    name: *const c_char,
    newparent: u64,
    newname: *const c_char,
    flags: c_uint,
) {
    let (ud, rq) = enter::<F>(req);
    let flags = RenameFlags::from_bits_retain(flags) & !RenameFlags::RENAME_WHITEOUT;
    ud.fs.rename(
        &rq,
        INodeNo(parent),
        os_name(name),
        INodeNo(newparent),
        os_name(newname),
        flags,
        None,
        ReplyEmpty::new(req),
    );
}

extern "C" fn tr_link<F: Filesystem>(
    req: RawReq,
    ino: u64,
    newparent: u64,
    newname: *const c_char,
) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.link(
        &rq,
        INodeNo(ino),
        INodeNo(newparent),
        os_name(newname),
        ReplyEntry::new(req),
    );
}

extern "C" fn tr_open<F: Filesystem>(req: RawReq, ino: u64, fi: *mut FileInfo) {
    let (ud, rq) = enter::<F>(req);
    let f = fi_of(fi);
    ud.fs.open(
        &rq,
        INodeNo(ino),
        OpenFlags(f.flags),
        f.bits & fi_bit::KILL_SUIDGID != 0,
        ReplyOpen::new(req),
    );
}

extern "C" fn tr_read<F: Filesystem>(
    req: RawReq,
    ino: u64,
    size: usize,
    off: i64,
    fi: *mut FileInfo,
) {
    let (ud, rq) = enter::<F>(req);
    let f = fi_of(fi);
    ud.fs.read(
        &rq,
        INodeNo(ino),
        FileHandle(f.fh),
        off as u64,
        size32(size),
        OpenFlags(f.flags),
        None,
        ReplyData::new(req),
    );
}

extern "C" fn tr_write<F: Filesystem>(
    req: RawReq,
    ino: u64,
    buf: *const c_char,
    size: usize,
    off: i64,
    fi: *mut FileInfo,
) {
    let (ud, rq) = enter::<F>(req);
    let f = fi_of(fi);
    let mut write_flags = WriteFlags::empty();
    if f.bits & fi_bit::WRITEPAGE != 0 {
        write_flags |= WriteFlags::FUSE_WRITE_CACHE;
    }
    if f.bits & fi_bit::KILL_SUIDGID != 0 {
        write_flags |= WriteFlags::FUSE_WRITE_KILL_SUIDGID;
    }
    ud.fs.write(
        &rq,
        INodeNo(ino),
        FileHandle(f.fh),
        off as u64,
        payload(buf, size),
        write_flags,
        OpenFlags(f.flags),
        None,
        ReplyWrite::new(req),
    );
}

extern "C" fn tr_flush<F: Filesystem>(req: RawReq, ino: u64, fi: *mut FileInfo) {
    let (ud, rq) = enter::<F>(req);
    let f = fi_of(fi);
    ud.fs.flush(
        &rq,
        INodeNo(ino),
        FileHandle(f.fh),
        LockOwner(f.lock_owner),
        ReplyEmpty::new(req),
    );
}

extern "C" fn tr_release<F: Filesystem>(req: RawReq, ino: u64, fi: *mut FileInfo) {
    let (ud, rq) = enter::<F>(req);
    let f = fi_of(fi);
    ud.fs.release(
        &rq,
        INodeNo(ino),
        FileHandle(f.fh),
        OpenFlags(f.flags),
        (f.bits & fi_bit::FLOCK_RELEASE != 0).then_some(LockOwner(f.lock_owner)),
        f.bits & fi_bit::FLUSH != 0,
        ReplyEmpty::new(req),
    );
}

extern "C" fn tr_fsync<F: Filesystem>(req: RawReq, ino: u64, datasync: c_int, fi: *mut FileInfo) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.fsync(
        &rq,
        INodeNo(ino),
        FileHandle(fi_of(fi).fh),
        datasync != 0,
        ReplyEmpty::new(req),
    );
}

extern "C" fn tr_opendir<F: Filesystem>(req: RawReq, ino: u64, fi: *mut FileInfo) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.opendir(
        &rq,
        INodeNo(ino),
        OpenFlags(fi_of(fi).flags),
        ReplyOpen::new(req),
    );
}

extern "C" fn tr_readdir<F: Filesystem>(
    req: RawReq,
    ino: u64,
    size: usize,
    off: i64,
    fi: *mut FileInfo,
) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.readdir(
        &rq,
        INodeNo(ino),
        FileHandle(fi_of(fi).fh),
        off as u64,
        ReplyDirectory::new(req, size),
    );
}

extern "C" fn tr_readdirplus<F: Filesystem>(
    req: RawReq,
    ino: u64,
    size: usize,
    off: i64,
    fi: *mut FileInfo,
) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.readdirplus(
        &rq,
        INodeNo(ino),
        FileHandle(fi_of(fi).fh),
        off as u64,
        ReplyDirectoryPlus::new(req, size),
    );
}

extern "C" fn tr_releasedir<F: Filesystem>(req: RawReq, ino: u64, fi: *mut FileInfo) {
    let (ud, rq) = enter::<F>(req);
    let f = fi_of(fi);
    ud.fs.releasedir(
        &rq,
        INodeNo(ino),
        FileHandle(f.fh),
        OpenFlags(f.flags),
        ReplyEmpty::new(req),
    );
}

extern "C" fn tr_fsyncdir<F: Filesystem>(
    req: RawReq,
    ino: u64,
    datasync: c_int,
    fi: *mut FileInfo,
) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.fsyncdir(
        &rq,
        INodeNo(ino),
        FileHandle(fi_of(fi).fh),
        datasync != 0,
        ReplyEmpty::new(req),
    );
}

extern "C" fn tr_statfs<F: Filesystem>(req: RawReq, ino: u64) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.statfs(&rq, INodeNo(ino), ReplyStatfs::new(req));
}

extern "C" fn tr_create<F: Filesystem>(
    req: RawReq,
    parent: u64,
    name: *const c_char,
    mode: libc::mode_t,
    fi: *mut FileInfo,
) {
    let (ud, rq) = enter::<F>(req);
    let f = fi_of(fi);
    ud.fs.create(
        &rq,
        INodeNo(parent),
        os_name(name),
        u32::from(mode),
        rq.umask(),
        f.flags,
        f.bits & fi_bit::KILL_SUIDGID != 0,
        rq.owner(),
        ReplyCreate::new(req),
    );
}

extern "C" fn tr_fallocate<F: Filesystem>(
    req: RawReq,
    ino: u64,
    mode: c_int,
    offset: i64,
    length: i64,
    fi: *mut FileInfo,
) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.fallocate(
        &rq,
        INodeNo(ino),
        FileHandle(fi_of(fi).fh),
        offset as u64,
        length as u64,
        mode,
        ReplyEmpty::new(req),
    );
}

#[allow(clippy::too_many_arguments)]
extern "C" fn tr_copy_file_range<F: Filesystem>(
    req: RawReq,
    ino_in: u64,
    off_in: i64,
    fi_in: *mut FileInfo,
    ino_out: u64,
    off_out: i64,
    fi_out: *mut FileInfo,
    len: usize,
    flags: c_int,
) {
    let (ud, rq) = enter::<F>(req);
    ud.fs.copy_file_range(
        &rq,
        INodeNo(ino_in),
        FileHandle(fi_of(fi_in).fh),
        off_in as u64,
        INodeNo(ino_out),
        FileHandle(fi_of(fi_out).fh),
        off_out as u64,
        len as u64,
        CopyFileRangeFlags::from_bits_retain(u64::from(flags as u32)),
        ReplyWrite::new(req),
    );
}

fn ops<F: Filesystem>() -> LowlevelOps {
    LowlevelOps {
        init: Some(tr_init::<F>),
        destroy: Some(tr_destroy::<F>),
        lookup: Some(tr_lookup::<F>),
        forget: Some(tr_forget::<F>),
        getattr: Some(tr_getattr::<F>),
        setattr: Some(tr_setattr::<F>),
        readlink: Some(tr_readlink::<F>),
        mknod: Some(tr_mknod::<F>),
        mkdir: Some(tr_mkdir::<F>),
        unlink: Some(tr_unlink::<F>),
        rmdir: Some(tr_rmdir::<F>),
        symlink: Some(tr_symlink::<F>),
        rename: Some(tr_rename::<F>),
        link: Some(tr_link::<F>),
        open: Some(tr_open::<F>),
        read: Some(tr_read::<F>),
        write: Some(tr_write::<F>),
        flush: Some(tr_flush::<F>),
        release: Some(tr_release::<F>),
        fsync: Some(tr_fsync::<F>),
        opendir: Some(tr_opendir::<F>),
        readdir: Some(tr_readdir::<F>),
        releasedir: Some(tr_releasedir::<F>),
        fsyncdir: Some(tr_fsyncdir::<F>),
        statfs: Some(tr_statfs::<F>),
        create: Some(tr_create::<F>),
        fallocate: Some(tr_fallocate::<F>),
        readdirplus: Some(tr_readdirplus::<F>),
        copy_file_range: Some(tr_copy_file_range::<F>),
        ..LowlevelOps::default()
    }
}

// kernel cache notifications, sent from any thread; they fail with enotconn once the session is gone
#[derive(Clone)]
pub struct Notifier {
    lib: &'static Lib,
    shared: Arc<Shared>,
}

impl fmt::Debug for Notifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Notifier")
    }
}

impl Notifier {
    fn call(&self, f: impl FnOnce(&Lib, RawSession) -> c_int) -> io::Result<()> {
        let guard = self.shared.se.read().unwrap_or_else(|e| e.into_inner());
        let Some(se) = *guard else {
            return Err(io::Error::from_raw_os_error(libc::ENOTCONN));
        };
        match f(self.lib, se.as_ptr()) {
            0 => Ok(()),
            r => Err(io::Error::from_raw_os_error(r.saturating_abs())),
        }
    }

    pub fn inval_inode(&self, ino: INodeNo, offset: i64, len: i64) -> io::Result<()> {
        // SAFETY: the session is live while call holds its read guard and the arguments are plain integers.
        self.call(|l, se| unsafe { (l.notify_inval_inode)(se, ino.0, offset, len) })
    }

    pub fn inval_entry(&self, parent: INodeNo, name: &OsStr) -> io::Result<()> {
        let n = name.as_bytes();
        // SAFETY: the session is live while call holds its read guard and n is a readable slice libfuse copies.
        self.call(|l, se| unsafe {
            (l.notify_inval_entry)(se, parent.0, n.as_ptr().cast(), n.len())
        })
    }

    pub fn delete(&self, parent: INodeNo, child: INodeNo, name: &OsStr) -> io::Result<()> {
        let n = name.as_bytes();
        // SAFETY: the session is live while call holds its read guard and n is a readable slice libfuse copies.
        self.call(|l, se| unsafe {
            (l.notify_delete)(se, parent.0, child.0, n.as_ptr().cast(), n.len())
        })
    }
}

struct Live {
    se: SePtr,
    ud: UdPtr,
    drop_fs: unsafe fn(*mut c_void),
    thread: JoinHandle<()>,
    mountpoint: PathBuf,
}

pub struct BackgroundSession {
    lib: &'static Lib,
    shared: Arc<Shared>,
    backend: Backend,
    live: Option<Live>,
}

impl fmt::Debug for BackgroundSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackgroundSession")
            .field("backend", &self.backend)
            .field("mounted", &self.live.is_some())
            .finish()
    }
}

impl BackgroundSession {
    pub fn notifier(&self) -> Notifier {
        Notifier {
            lib: self.lib,
            shared: Arc::clone(&self.shared),
        }
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn umount_and_join(mut self) -> io::Result<()> {
        self.teardown()
    }

    fn teardown(&mut self) -> io::Result<()> {
        let Some(live) = self.live.take() else {
            return Ok(());
        };
        let lib = self.lib;
        let se = live.se.as_ptr();
        // SAFETY: se is the live session this value owns; exit and unmount may run while the loop is blocked in a read.
        unsafe {
            (lib.session_exit)(se);
            (lib.session_unmount)(se);
        }
        let mut exited = self.shared.wait_done(JOIN_DEADLINE);
        if !exited || still_mounted(&live.mountpoint) {
            force_unmount(&live.mountpoint);
            exited = exited || self.shared.wait_done(JOIN_DEADLINE);
        }
        if !exited {
            // the loop thread still uses the session and the filesystem, so both are leaked rather than freed under it
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the macFUSE session loop did not stop after a forced unmount",
            ));
        }
        let _ = live.thread.join();
        self.shared.set_session(None);
        // SAFETY: the loop thread has exited, so nothing uses the session; destroy runs the filesystem's destroy callback
        // if the kernel never sent one, then the userdata is freed exactly once.
        unsafe {
            (lib.session_destroy)(se);
            (live.drop_fs)(live.ud.0.as_ptr());
        }
        match lock(&self.shared.init_err).take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Drop for BackgroundSession {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

unsafe fn drop_ud<F>(p: *mut c_void) {
    // SAFETY: p is the Ud<F> leaked by mount, and the caller frees it once after the session is gone.
    drop(unsafe { Box::from_raw(p.cast::<Ud<F>>()) });
}

fn mount_failure(backend: Backend) -> io::Error {
    io::Error::other(match backend {
        Backend::FsKit => {
            "enable macFUSE in System Settings > General > Login Items & Extensions > File System Extensions"
        }
        Backend::Kext => {
            "allow the macFUSE system extension in Privacy & Security (Apple silicon needs Reduced Security)"
        }
    })
}

fn create_session<F: Filesystem>(
    lib: &Lib,
    args: &[CString],
    userdata: *mut c_void,
) -> io::Result<SePtr> {
    let mut fargs = FuseArgs {
        argc: 0,
        argv: std::ptr::null_mut(),
        allocated: 0,
    };
    for a in args {
        // SAFETY: fargs is a valid fuse_args under construction and a is a nul-terminated string that libfuse copies.
        if unsafe { (lib.opt_add_arg)(&mut fargs, a.as_ptr()) } != 0 {
            // SAFETY: fargs was built by fuse_opt_add_arg above.
            unsafe { (lib.opt_free_args)(&mut fargs) };
            return Err(io::Error::from_raw_os_error(libc::ENOMEM));
        }
    }
    let ops = ops::<F>();
    let mut version = LibfuseVersion {
        major: VERSION.0,
        minor: VERSION.1,
        hotfix: VERSION.2,
        flags: VERSION_DARWIN_EXTENSIONS,
    };
    // SAFETY: every pointer is valid for the call, libfuse copies the ops table, and op_size is its size.
    let se = unsafe {
        (lib.session_new_versioned)(
            &mut fargs,
            &ops,
            size_of::<LowlevelOps>(),
            &mut version,
            userdata,
        )
    };
    // SAFETY: fargs was built by fuse_opt_add_arg above and libfuse no longer reads it.
    unsafe { (lib.opt_free_args)(&mut fargs) };
    NonNull::new(se)
        .map(SePtr)
        .ok_or_else(|| io::Error::other("macFUSE rejected the mount options"))
}

fn run_loop(lib: &Lib, se: SePtr) -> c_int {
    // SAFETY: creating a config has no preconditions and returns an owned config or null.
    let cfg = unsafe { (lib.loop_cfg_create)() };
    if cfg.is_null() {
        return -libc::ENOMEM;
    }
    // SAFETY: cfg is the live config created above and the setters only store integers in it.
    unsafe {
        (lib.loop_cfg_set_max_threads)(cfg, LOOP_THREADS);
        (lib.loop_cfg_set_idle_threads)(cfg, LOOP_THREADS);
        (lib.loop_cfg_set_clone_fd)(cfg, 0);
    }
    // SAFETY: se is a mounted session destroyed only after this loop reports done, and cfg is live.
    let rc = unsafe { (lib.session_loop_mt)(se.as_ptr(), cfg) };
    // SAFETY: cfg was created above and the loop no longer reads it.
    unsafe { (lib.loop_cfg_destroy)(cfg) };
    rc
}

pub fn mount<F: Filesystem>(
    fs: F,
    at: &Path,
    opts: &MountOpts,
    backend: Backend,
) -> io::Result<BackgroundSession> {
    let lib = ffi::load()?;
    let mountpoint = std::fs::canonicalize(at)?;
    let c_mount = CString::new(mountpoint.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let shared = Arc::new(Shared::default());
    let ud = NonNull::from(Box::leak(Box::new(Ud {
        fs,
        shared: Arc::clone(&shared),
    })))
    .cast::<c_void>();
    let se = match create_session::<F>(lib, &mount_args(opts, backend), ud.as_ptr()) {
        Ok(se) => se,
        Err(e) => {
            // SAFETY: ud is the Ud<F> leaked above and no session holds it.
            unsafe { drop_ud::<F>(ud.as_ptr()) };
            return Err(e);
        }
    };
    // SAFETY: se is the live session just created and c_mount is a nul-terminated path.
    if unsafe { (lib.session_mount)(se.as_ptr(), c_mount.as_ptr()) } != 0 {
        // SAFETY: the session never ran, so destroying it and freeing its userdata cannot race a callback.
        unsafe {
            (lib.session_destroy)(se.as_ptr());
            drop_ud::<F>(ud.as_ptr());
        }
        return Err(mount_failure(backend));
    }
    shared.set_session(Some(se));
    let loop_shared = Arc::clone(&shared);
    let spawned = thread::Builder::new()
        .name("csync-fuse".to_owned())
        .spawn(move || {
            let rc = run_loop(lib, se);
            *lock(&loop_shared.done) = Some(rc);
            loop_shared.done_cv.notify_all();
        });
    let thread = match spawned {
        Ok(t) => t,
        Err(e) => {
            shared.set_session(None);
            // SAFETY: the loop never started, so unmounting, destroying and freeing cannot race a callback.
            unsafe {
                (lib.session_unmount)(se.as_ptr());
                (lib.session_destroy)(se.as_ptr());
                drop_ud::<F>(ud.as_ptr());
            }
            return Err(e);
        }
    };
    Ok(BackgroundSession {
        lib,
        shared,
        backend,
        live: Some(Live {
            se,
            ud: UdPtr(ud),
            drop_fs: drop_ud::<F>,
            thread,
            mountpoint,
        }),
    })
}

// getfsstat with mnt_nowait answers from the kernel's mount table without touching any filesystem, which
// matters because the daemon that would answer a statfs on this mount has already stopped
fn still_mounted(path: &Path) -> bool {
    // SAFETY: a null buffer of size zero only asks for the number of mounts.
    let n = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    let Ok(n) = usize::try_from(n) else {
        return false;
    };
    let mut buf: Vec<libc::statfs> = Vec::new();
    buf.resize_with(n + 8, zeroed_statfs);
    let bytes = c_int::try_from(buf.len() * size_of::<libc::statfs>()).unwrap_or(c_int::MAX);
    // SAFETY: buf holds bytes writable bytes of statfs records.
    let got = unsafe { libc::getfsstat(buf.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
    let got = usize::try_from(got).unwrap_or(0).min(buf.len());
    let want = path.as_os_str().as_bytes();
    buf[..got].iter().any(|s| {
        s.f_mntonname
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .eq(want.iter().copied())
    })
}

fn force_unmount(path: &Path) {
    if let Ok(c) = CString::new(path.as_os_str().as_bytes()) {
        // SAFETY: c is a valid nul-terminated path that unmount only reads.
        unsafe { libc::unmount(c.as_ptr(), libc::MNT_FORCE) };
    }
    if still_mounted(path) {
        run_diskutil(path);
    }
}

fn run_diskutil(path: &Path) {
    let spawned = Command::new("diskutil")
        .args(["unmount", "force"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        return;
    };
    let end = Instant::now() + DISKUTIL_DEADLINE;
    while Instant::now() < end {
        match child.try_wait() {
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Ok(Some(_)) | Err(_) => return,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Null;

    impl Filesystem for Null {}

    #[test]
    fn every_implemented_callback_is_registered_and_the_rest_are_not() {
        let o = ops::<Null>();
        assert!(o.init.is_some() && o.destroy.is_some());
        assert!(o.lookup.is_some() && o.forget.is_some() && o.getattr.is_some());
        assert!(o.setattr.is_some() && o.readlink.is_some() && o.mknod.is_some());
        assert!(o.mkdir.is_some() && o.unlink.is_some() && o.rmdir.is_some());
        assert!(o.symlink.is_some() && o.rename.is_some() && o.link.is_some());
        assert!(o.open.is_some() && o.read.is_some() && o.write.is_some());
        assert!(o.flush.is_some() && o.release.is_some() && o.fsync.is_some());
        assert!(o.opendir.is_some() && o.readdir.is_some() && o.releasedir.is_some());
        assert!(o.fsyncdir.is_some() && o.statfs.is_some() && o.create.is_some());
        assert!(o.fallocate.is_some() && o.readdirplus.is_some() && o.copy_file_range.is_some());
        assert!(o.setxattr.is_none() && o.getxattr.is_none() && o.listxattr.is_none());
        assert!(o.removexattr.is_none() && o.access.is_none() && o.getlk.is_none());
        assert!(o.setlk.is_none() && o.bmap.is_none() && o.ioctl.is_none() && o.poll.is_none());
        assert!(o.write_buf.is_none() && o.retrieve_reply.is_none() && o.forget_multi.is_none());
        assert!(o.flock.is_none() && o.lseek.is_none() && o.tmpfile.is_none());
        assert!(o.setvolname.is_none() && o.monitor.is_none() && o.statx.is_none());
    }

    #[test]
    fn name_and_payload_helpers_accept_null_and_empty_input() {
        assert_eq!(os_name(std::ptr::null()), OsStr::new(""));
        assert_eq!(payload(std::ptr::null(), 4), &[] as &[u8]);
        let c = CString::new("abc").unwrap();
        assert_eq!(os_name(c.as_ptr()), OsStr::new("abc"));
        assert_eq!(payload(c.as_ptr(), 2), b"ab");
        assert_eq!(payload(c.as_ptr(), 0), &[] as &[u8]);
    }

    #[test]
    fn missing_file_info_reads_as_zeroes() {
        let f = fi_of(std::ptr::null_mut());
        assert_eq!((f.fh, f.flags, f.bits), (0, 0, 0));
        assert!(fi_opt(std::ptr::null_mut()).is_none());
        let mut real = FileInfo {
            fh: 9,
            ..FileInfo::default()
        };
        assert_eq!(fi_of(&mut real).fh, 9);
    }

    #[test]
    fn sizes_beyond_u32_saturate() {
        assert_eq!(size32(4096), 4096);
        assert_eq!(size32(usize::MAX), u32::MAX);
    }

    #[test]
    fn wait_done_reports_completion_and_times_out() {
        let shared = Shared::default();
        assert!(!shared.wait_done(Duration::from_millis(10)));
        *lock(&shared.done) = Some(0);
        assert!(shared.wait_done(Duration::from_millis(10)));
    }

    #[test]
    fn the_mount_table_lists_the_root_volume_but_not_a_made_up_path() {
        assert!(still_mounted(Path::new("/")));
        assert!(!still_mounted(Path::new("/csync-no-such-mount-point")));
    }

    #[test]
    fn mount_failures_name_the_backend_specific_fix() {
        assert!(
            mount_failure(Backend::FsKit)
                .to_string()
                .contains("File System Extensions")
        );
        assert!(
            mount_failure(Backend::Kext)
                .to_string()
                .contains("Reduced Security")
        );
    }
}
