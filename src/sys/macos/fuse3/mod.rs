// csync's own binding to macfuse's libfuse3 low-level api, shaped like the part of fuser 0.19 that the guest uses

mod args;
mod ffi;
mod marshal;
mod reply;
mod session;
mod types;

use std::io;

pub use args::{Backend, MountOpts};
pub use reply::{
    BackingId, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite,
};
pub use session::{BackgroundSession, Filesystem, Notifier, mount};
pub use types::{
    BsdFileFlags, CopyFileRangeFlags, Errno, FileAttr, FileHandle, FileType, FopenFlags,
    Generation, INodeNo, InitFlags, KernelConfig, LockOwner, OpenAccMode, OpenFlags, Owner,
    RenameFlags, Request, TimeOrNow, WriteFlags,
};

// loads the library without mounting, so a missing or old macfuse is reported before any mount work
pub fn probe() -> io::Result<()> {
    ffi::load().map(|_| ())
}
