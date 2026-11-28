// one-shot reply handles; an unanswered handle answers eio when dropped, like fuser's

use super::{
    ffi::{self, DarwinAttr, Lib, RawReq},
    marshal::{darwin_attr, entry_param, kind_bits, open_info, statfs_of},
    types::{Errno, FileAttr, FileHandle, FileType, FopenFlags, Generation, INodeNo},
};
use std::{
    ffi::{CString, OsStr, c_int},
    io,
    os::{fd::AsFd, unix::ffi::OsStrExt},
    ptr::NonNull,
    time::Duration,
};

// the largest directory buffer one readdir reply may build
const DIR_BUF_MAX: usize = 16 << 20;

#[derive(Debug)]
struct Req(Option<NonNull<std::ffi::c_void>>);

// SAFETY: a libfuse3 request stays valid until it is replied to and may be replied to from any thread.
unsafe impl Send for Req {}

impl Req {
    fn new(raw: RawReq) -> Req {
        Req(NonNull::new(raw))
    }

    fn raw(&self) -> RawReq {
        self.0.map_or(std::ptr::null_mut(), NonNull::as_ptr)
    }

    // runs the reply call once; later calls and the drop find the request already taken
    fn finish(&mut self, f: impl FnOnce(&Lib, RawReq) -> c_int) {
        if let Some(r) = self.0.take() {
            f(ffi::active(), r.as_ptr());
        }
    }

    fn error(&mut self, err: Errno) {
        // SAFETY: r is the live request taken by finish and this is its only reply.
        self.finish(|l, r| unsafe { (l.reply_err)(r, err.code()) });
    }
}

impl Drop for Req {
    fn drop(&mut self) {
        self.error(Errno::EIO);
    }
}

// uninhabited: kernel passthrough is not offered through macfuse, so no backing id can exist
#[derive(Debug)]
pub enum BackingId {}

fn no_passthrough() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "kernel passthrough is not available through macFUSE",
    )
}

#[derive(Debug)]
pub struct ReplyEmpty {
    req: Req,
}

impl ReplyEmpty {
    pub(super) fn new(raw: RawReq) -> Self {
        Self { req: Req::new(raw) }
    }

    pub fn ok(mut self) {
        // SAFETY: r is the live request taken by finish; an error code of zero is success.
        self.req.finish(|l, r| unsafe { (l.reply_err)(r, 0) });
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

#[derive(Debug)]
pub struct ReplyData {
    req: Req,
    link: bool,
}

impl ReplyData {
    pub(super) fn new(raw: RawReq) -> Self {
        Self {
            req: Req::new(raw),
            link: false,
        }
    }

    // a readlink reply carries the target as a string
    pub(super) fn link(raw: RawReq) -> Self {
        Self {
            req: Req::new(raw),
            link: true,
        }
    }

    pub fn data(mut self, data: &[u8]) {
        let link = self.link;
        self.req.finish(|l, r| {
            if link {
                match CString::new(data) {
                    // SAFETY: r is the live request taken by finish and target is nul-terminated.
                    Ok(target) => unsafe { (l.reply_readlink)(r, target.as_ptr()) },
                    // SAFETY: r is the live request taken by finish.
                    Err(_) => unsafe { (l.reply_err)(r, libc::EIO) },
                }
            } else {
                // SAFETY: r is the live request taken by finish and data is a readable slice that libfuse copies.
                unsafe { (l.reply_buf)(r, data.as_ptr().cast(), data.len()) }
            }
        });
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

#[derive(Debug)]
pub struct ReplyEntry {
    req: Req,
}

impl ReplyEntry {
    pub(super) fn new(raw: RawReq) -> Self {
        Self { req: Req::new(raw) }
    }

    pub fn entry(mut self, ttl: &Duration, attr: &FileAttr, generation: Generation) {
        let e = entry_param(ttl, attr, generation);
        // SAFETY: r is the live request taken by finish and e outlives the call, which copies it.
        self.req.finish(|l, r| unsafe { (l.reply_entry)(r, &e) });
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

#[derive(Debug)]
pub struct ReplyAttr {
    req: Req,
}

impl ReplyAttr {
    pub(super) fn new(raw: RawReq) -> Self {
        Self { req: Req::new(raw) }
    }

    pub fn attr(mut self, ttl: &Duration, attr: &FileAttr) {
        let a: DarwinAttr = darwin_attr(attr);
        // SAFETY: r is the live request taken by finish and a outlives the call, which copies it.
        self.req
            .finish(|l, r| unsafe { (l.reply_attr)(r, &a, ttl.as_secs_f64()) });
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

#[derive(Debug)]
pub struct ReplyOpen {
    req: Req,
}

impl ReplyOpen {
    pub(super) fn new(raw: RawReq) -> Self {
        Self { req: Req::new(raw) }
    }

    pub fn opened(mut self, fh: FileHandle, flags: FopenFlags) {
        let fi = open_info(fh, flags);
        // SAFETY: r is the live request taken by finish and fi outlives the call, which copies it.
        self.req.finish(|l, r| unsafe { (l.reply_open)(r, &fi) });
    }

    pub fn open_backing(&self, _fd: impl AsFd) -> io::Result<BackingId> {
        Err(no_passthrough())
    }

    pub fn opened_passthrough(self, _fh: FileHandle, _flags: FopenFlags, backing_id: &BackingId) {
        match *backing_id {}
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

#[derive(Debug)]
pub struct ReplyWrite {
    req: Req,
}

impl ReplyWrite {
    pub(super) fn new(raw: RawReq) -> Self {
        Self { req: Req::new(raw) }
    }

    pub fn written(mut self, size: u32) {
        // SAFETY: r is the live request taken by finish; the count is plain data.
        self.req
            .finish(|l, r| unsafe { (l.reply_write)(r, size as usize) });
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

#[derive(Debug)]
pub struct ReplyStatfs {
    req: Req,
}

impl ReplyStatfs {
    pub(super) fn new(raw: RawReq) -> Self {
        Self { req: Req::new(raw) }
    }

    // darwin's statfs has no name length field
    #[allow(clippy::too_many_arguments)]
    pub fn statfs(
        mut self,
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        bsize: u32,
        _namelen: u32,
        frsize: u32,
    ) {
        let st = statfs_of(blocks, bfree, bavail, files, ffree, bsize, frsize);
        // SAFETY: r is the live request taken by finish and st outlives the call, which copies it.
        self.req.finish(|l, r| unsafe { (l.reply_statfs)(r, &st) });
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

#[derive(Debug)]
pub struct ReplyCreate {
    req: Req,
}

impl ReplyCreate {
    pub(super) fn new(raw: RawReq) -> Self {
        Self { req: Req::new(raw) }
    }

    pub fn created(
        mut self,
        ttl: &Duration,
        attr: &FileAttr,
        generation: Generation,
        fh: FileHandle,
        flags: FopenFlags,
    ) {
        let e = entry_param(ttl, attr, generation);
        let fi = open_info(fh, flags);
        // SAFETY: r is the live request taken by finish; e and fi outlive the call, which copies them.
        self.req
            .finish(|l, r| unsafe { (l.reply_create)(r, &e, &fi) });
    }

    pub fn open_backing(&self, _fd: impl AsFd) -> io::Result<BackingId> {
        Err(no_passthrough())
    }

    pub fn created_passthrough(
        self,
        _ttl: &Duration,
        _attr: &FileAttr,
        _generation: Generation,
        _fh: FileHandle,
        _flags: FopenFlags,
        backing_id: &BackingId,
    ) {
        match *backing_id {}
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

// entries are packed into a buffer sized by the kernel's request; add reports true once one no longer fits
fn dir_buffer(size: usize) -> Vec<u8> {
    vec![0; size.min(DIR_BUF_MAX)]
}

#[derive(Debug)]
pub struct ReplyDirectory {
    req: Req,
    buf: Vec<u8>,
    used: usize,
}

impl ReplyDirectory {
    pub(super) fn new(raw: RawReq, size: usize) -> Self {
        Self {
            req: Req::new(raw),
            buf: dir_buffer(size),
            used: 0,
        }
    }

    pub fn remaining_capacity(&self) -> usize {
        self.buf.len() - self.used
    }

    #[must_use]
    pub fn add<T: AsRef<OsStr>>(
        &mut self,
        ino: INodeNo,
        offset: u64,
        kind: FileType,
        name: T,
    ) -> bool {
        let Ok(name) = CString::new(name.as_ref().as_bytes()) else {
            return false;
        };
        let attr = DarwinAttr {
            ino: ino.0,
            mode: kind_bits(kind),
            ..DarwinAttr::default()
        };
        let room = self.buf.len() - self.used;
        let raw = self.req.raw();
        let tail = &mut self.buf[self.used..];
        // SAFETY: raw is the live request, tail is room writable bytes, and an entry that does not fit is not written.
        let need = unsafe {
            (ffi::active().add_direntry)(
                raw,
                tail.as_mut_ptr().cast(),
                room,
                name.as_ptr(),
                &attr,
                offset as i64,
            )
        };
        if need > room {
            return true;
        }
        self.used += need;
        false
    }

    pub fn ok(mut self) {
        let Self { req, buf, used } = &mut self;
        // SAFETY: r is the live request taken by finish and the first used bytes of buf are initialised.
        req.finish(|l, r| unsafe { (l.reply_buf)(r, buf.as_ptr().cast(), *used) });
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

#[derive(Debug)]
pub struct ReplyDirectoryPlus {
    req: Req,
    buf: Vec<u8>,
    used: usize,
}

impl ReplyDirectoryPlus {
    pub(super) fn new(raw: RawReq, size: usize) -> Self {
        Self {
            req: Req::new(raw),
            buf: dir_buffer(size),
            used: 0,
        }
    }

    pub fn remaining_capacity(&self) -> usize {
        self.buf.len() - self.used
    }

    pub fn add<T: AsRef<OsStr>>(
        &mut self,
        ino: INodeNo,
        offset: u64,
        name: T,
        ttl: &Duration,
        attr: &FileAttr,
        generation: Generation,
    ) -> bool {
        let Ok(name) = CString::new(name.as_ref().as_bytes()) else {
            return false;
        };
        let mut e = entry_param(ttl, attr, generation);
        e.ino = ino.0;
        let room = self.buf.len() - self.used;
        let raw = self.req.raw();
        let tail = &mut self.buf[self.used..];
        // SAFETY: raw is the live request, tail is room writable bytes, and an entry that does not fit is not written.
        let need = unsafe {
            (ffi::active().add_direntry_plus)(
                raw,
                tail.as_mut_ptr().cast(),
                room,
                name.as_ptr(),
                &e,
                offset as i64,
            )
        };
        if need > room {
            return true;
        }
        self.used += need;
        false
    }

    pub fn ok(mut self) {
        let Self { req, buf, used } = &mut self;
        // SAFETY: r is the live request taken by finish and the first used bytes of buf are initialised.
        req.finish(|l, r| unsafe { (l.reply_buf)(r, buf.as_ptr().cast(), *used) });
    }

    pub fn error(mut self, err: Errno) {
        self.req.error(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_buffers_are_bounded() {
        assert_eq!(dir_buffer(4096).len(), 4096);
        assert_eq!(dir_buffer(usize::MAX).len(), DIR_BUF_MAX);
    }

    #[test]
    fn a_reply_without_a_request_is_inert() {
        let mut dir = ReplyDirectory::new(std::ptr::null_mut(), 128);
        assert_eq!(dir.remaining_capacity(), 128);
        dir.used = 100;
        assert_eq!(dir.remaining_capacity(), 28);
        drop(dir);
        ReplyEmpty::new(std::ptr::null_mut()).ok();
    }
}
