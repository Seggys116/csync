use crate::crypto::trust::check_private_dir;
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::Shutdown,
    os::{
        fd::AsFd,
        unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub const REQ_MAX: usize = 1_024;
pub const RESP_MAX: u64 = 1 << 20;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CtlReq {
    Status,
    Forget(String),
}

fn selector_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= REQ_MAX - 16 && !s.chars().any(char::is_control)
}

impl CtlReq {
    fn encode(&self) -> io::Result<String> {
        match self {
            Self::Status => Ok("status\n".into()),
            Self::Forget(s) if selector_ok(s) => Ok(format!("forget {s}\n")),
            Self::Forget(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid forget selector",
            )),
        }
    }

    fn parse(line: &str) -> Option<Self> {
        let line = line.strip_suffix('\n')?;
        if line == "status" {
            return Some(Self::Status);
        }
        let sel = line.strip_prefix("forget ")?;
        selector_ok(sel).then(|| Self::Forget(sel.to_string()))
    }
}

pub type Handler = Box<dyn Fn(CtlReq) -> String + Send>;

pub struct CtlServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

fn my_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn same_user(c: &UnixStream) -> io::Result<()> {
    if crate::sys::peer_uid(c.as_fd())? != my_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control socket peer is a different user",
        ));
    }
    Ok(())
}

pub fn serve(path: &Path, handler: Handler) -> io::Result<CtlServer> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "control socket path has no parent",
        )
    })?;
    check_private_dir(dir)?;
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another csync host is already running",
                ));
            }
            fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "control socket path exists and is not a socket",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let thread = thread::Builder::new()
        .name("csync-ctl".into())
        .spawn(move || serve_loop(l, handler, s))?;
    Ok(CtlServer {
        path: path.to_path_buf(),
        stop,
        thread: Some(thread),
    })
}

fn serve_loop(l: UnixListener, handler: Handler, stop: Arc<AtomicBool>) {
    for conn in l.incoming() {
        if stop.load(Ordering::Acquire) {
            return;
        }
        match conn {
            Ok(c) => {
                let _ = handle(c, &handler);
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn handle(c: UnixStream, handler: &Handler) -> io::Result<()> {
    same_user(&c)?;
    c.set_read_timeout(Some(IO_TIMEOUT))?;
    c.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut line = String::new();
    BufReader::new((&c).take(REQ_MAX as u64)).read_line(&mut line)?;
    let resp = match CtlReq::parse(&line) {
        Some(r) => handler(r),
        None => "error: unknown request\n".into(),
    };
    (&c).write_all(resp.as_bytes())?;
    c.shutdown(Shutdown::Write)
}

impl Drop for CtlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.path);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

pub fn request(path: &Path, req: &CtlReq) -> io::Result<String> {
    let line = req.encode()?;
    let c = UnixStream::connect(path)?;
    same_user(&c)?;
    c.set_read_timeout(Some(IO_TIMEOUT))?;
    c.set_write_timeout(Some(IO_TIMEOUT))?;
    (&c).write_all(line.as_bytes())?;
    c.shutdown(Shutdown::Write)?;
    let mut out = String::new();
    (&c).take(RESP_MAX).read_to_string(&mut out)?;
    Ok(out)
}
