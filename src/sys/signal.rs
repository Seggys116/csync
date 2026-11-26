use crate::sys::lock;
use crossbeam_channel::{Receiver, unbounded};
use std::{
    io,
    os::fd::{FromRawFd, OwnedFd},
    sync::{
        Mutex,
        atomic::{AtomicI32, Ordering},
    },
};

const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

static WAKE_FD: AtomicI32 = AtomicI32::new(-1);
static RX: Mutex<Option<Receiver<i32>>> = Mutex::new(None);

#[cfg(target_os = "linux")]
fn errno_ptr() -> *mut libc::c_int {
    // SAFETY: returns the calling thread's errno slot, always valid.
    unsafe { libc::__errno_location() }
}

#[cfg(not(target_os = "linux"))]
fn errno_ptr() -> *mut libc::c_int {
    // SAFETY: returns the calling thread's errno slot, always valid.
    unsafe { libc::__error() }
}

// async-signal-safe: one write(2) to a nonblocking pipe, errno preserved
extern "C" fn on_signal(sig: libc::c_int) {
    let fd = WAKE_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    let e = errno_ptr();
    // SAFETY: e is this thread's errno slot; saved here and restored below.
    let saved = unsafe { *e };
    let b = sig as u8;
    // SAFETY: fd is the pipe write end, never closed once published, and b is a valid one-byte buffer.
    unsafe { libc::write(fd, (&raw const b).cast(), 1) };
    // SAFETY: as above.
    unsafe { *e = saved };
}

// installs sigint, sigterm and sighup once; later calls return another handle to the same stream
pub fn signals() -> io::Result<Receiver<i32>> {
    let mut slot = lock(&RX);
    if let Some(rx) = slot.as_ref() {
        return Ok(rx.clone());
    }
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds is a valid two-element array for pipe to fill.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe succeeded, so both fds are fresh and owned by nobody else.
    let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&rd, &wr] {
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)?;
    }
    rustix::fs::fcntl_setfl(&wr, rustix::fs::OFlags::NONBLOCK)?;

    let (tx, rx) = unbounded();
    std::thread::Builder::new()
        .name("csync-signals".into())
        .spawn(move || {
            let mut buf = [0u8; 64];
            loop {
                match rustix::io::read(&rd, &mut buf[..]) {
                    Ok(0) => return,
                    Ok(n) => {
                        for &s in &buf[..n] {
                            if tx.send(i32::from(s)).is_err() {
                                return;
                            }
                        }
                    }
                    Err(rustix::io::Errno::INTR) => {}
                    Err(_) => return,
                }
            }
        })?;

    // the write end lives for the rest of the process so the handler can never hit a closed fd
    let wr = std::os::fd::IntoRawFd::into_raw_fd(wr);
    WAKE_FD.store(wr, Ordering::Release);
    for sig in SIGNALS {
        // SAFETY: an all-zero sigaction is a valid initial value on every unix libc.
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        // SAFETY: sa is initialised, the handler only performs async-signal-safe work, and the old action is not needed.
        let r = unsafe {
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut())
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    *slot = Some(rx.clone());
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn raised_sighup_is_forwarded() {
        let rx = signals().unwrap();
        let again = signals().unwrap();
        drop(again);
        // SAFETY: raise only delivers a signal to this process, whose handler is installed above.
        assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            libc::SIGHUP
        );
    }
}
