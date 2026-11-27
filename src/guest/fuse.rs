#[cfg(target_os = "linux")]
pub use fuser::{
    BackgroundSession, BackingId, BsdFileFlags, Config, CopyFileRangeFlags, Errno, FileAttr,
    FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, InitFlags, KernelConfig,
    LockOwner, MountOption, Notifier, OpenAccMode, OpenFlags, Owner, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyStatfs, ReplyWrite, Request, Session, SessionACL, TimeOrNow, WriteFlags,
};

#[cfg(target_os = "macos")]
pub use crate::sys::macos::fuse3::{
    Backend, BackgroundSession, BackingId, BsdFileFlags, CopyFileRangeFlags, Errno, FileAttr,
    FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, InitFlags, KernelConfig,
    LockOwner, MountOpts, Notifier, OpenAccMode, OpenFlags, Owner, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyStatfs, ReplyWrite, Request, TimeOrNow, WriteFlags, mount,
};
