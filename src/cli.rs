use crate::config::{self, DEFAULT_PORT, Dirs, GuestCfg};
use crate::crypto::trust::{self, Identity, PeerKey, Trust, TrustEntry};
use crate::ctl::{self, CtlReq};
use crate::host::{HostCfg, HostCtl};
use crate::net::discover::{self, Found, HostAd};
use crate::proto::{Name, PROTO, hs::Role};
use crate::tui::{self, FoundHost, UiBus, UiCmd, view};
use crate::{bench, doctor, update};
use clap::{Parser, Subcommand, ValueEnum};
use crossbeam_channel::{Receiver, Sender, bounded, select};
use std::{
    env, fmt, fs,
    io::{self, IsTerminal},
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    sync::Arc,
    thread,
    time::Duration,
};

pub const EXIT_OK: u8 = 0;
pub const EXIT_FAIL: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_ENV: u8 = 3;
pub const EXIT_AUTH: u8 = 4;
pub const EXIT_NOT_RUNNING: u8 = 5;
pub const EXIT_NO_MATCH: u8 = 6;
pub const EXIT_UPDATE_AVAILABLE: u8 = 10;
pub const EXIT_INTERRUPTED: u8 = 130;

const CMD_QUEUE: usize = 64;
const CMD_TIMEOUT: Duration = Duration::from_secs(1);
const CTL_REPLY_TIMEOUT: Duration = Duration::from_secs(4);

const AFTER_HELP: &str = "\
Typical use:
  on the Mac, in the project:   csync host
  on a Linux or macOS guest:    csync join            (pick the host, compare the pairing code)

Without a terminal (or with --no-tui) csync prints one status record per line
(`kind key=value ...`, values percent-escaped) and reads commands from stdin:
  accept [ID] | reject [ID] | confirm yes|no | join N | revoke ID | status | quit

Exit codes: 0 ok, 1 failure, 2 usage, 3 environment (FUSE, mount point, platform),
4 trust or pairing refused, 5 no running session, 6 nothing matched, 10 update available
(`update --check`), 130 interrupted.";

#[derive(Parser, Debug)]
#[command(name = "csync", version, about = "Two-way code sync for a macOS host and a Linux or macOS FUSE guest", after_help = AFTER_HELP)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        help = "Print line-oriented status and read commands from stdin (automatic without a terminal)"
    )]
    pub no_tui: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    #[command(about = "Serve a project to guests (the project directory is the source of truth)")]
    Host {
        #[arg(
            value_name = "PATH",
            help = "Project root [default: current directory]"
        )]
        path: Option<PathBuf>,
        #[arg(
            long,
            help = "Refuse new pairings (XX handshakes); only already trusted guests can connect"
        )]
        no_pair: bool,
        #[arg(
            long,
            value_name = "ADDR",
            help = format!("Address to listen on [default: 0.0.0.0:{DEFAULT_PORT}]")
        )]
        listen: Option<SocketAddr>,
        #[arg(long, help = "Do not advertise over mDNS; guests must use --connect")]
        no_mdns: bool,
        #[arg(long, help = "Advertise on VPN and point-to-point interfaces too")]
        all_interfaces: bool,
    },
    #[command(
        about = "Join a host and mount its project with FUSE (Linux, or macOS with macFUSE 5.5 or later)"
    )]
    Join {
        #[arg(
            value_name = "MOUNTPOINT",
            help = "Empty directory to mount on [default: ./<project>]"
        )]
        mountpoint: Option<PathBuf>,
        #[arg(
            long,
            value_name = "HOST:PORT",
            help = "Connect to this address instead of discovering hosts over mDNS"
        )]
        connect: Option<String>,
        #[arg(
            long,
            value_name = "NAME",
            help = "Pick the host by name, project or fingerprint prefix"
        )]
        host: Option<String>,
        #[arg(
            long,
            help = "Pair again even if the host is trusted (after a host key change or failed resume)"
        )]
        repair: bool,
        #[arg(
            long,
            help = "Let other users access the mount (Linux: needs user_allow_other in /etc/fuse.conf)"
        )]
        allow_other: bool,
        #[arg(long, value_name = "SIZE", value_parser = config::parse_size, help = "Blob cache limit, e.g. 4G [default: min(10G, 20% of free space)]")]
        cache_size: Option<u64>,
        #[arg(
            long,
            value_name = "NAME",
            help = "Name shown to the host [default: this machine's hostname]"
        )]
        name: Option<String>,
        #[arg(long, help = "Discover hosts on VPN and point-to-point interfaces too")]
        all_interfaces: bool,
    },
    #[command(about = "Forget a paired peer by name or fingerprint and drop its live session")]
    Forget {
        #[arg(
            value_name = "SELECTOR",
            help = "Peer name, fingerprint prefix (4+ hex digits) or full key"
        )]
        selector: String,
    },
    #[command(about = "Manage trusted peer keys")]
    Trust {
        #[command(subcommand)]
        cmd: TrustCmd,
    },
    #[command(about = "Show this machine's identity key")]
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    #[command(about = "Check the environment and print a fix for each problem")]
    Doctor {
        #[arg(long, value_name = "PATH", help = "Also check this mount point")]
        mount: Option<PathBuf>,
        #[arg(long, help = "Check the requirements of join --allow-other")]
        allow_other: bool,
        #[arg(long, help = "Print the results as JSON")]
        json: bool,
    },
    #[command(about = "Show the state of running csync sessions")]
    Status {
        #[arg(long, help = "Print JSON")]
        json: bool,
    },
    #[command(
        about = "Install the latest csync release over this binary (checked against the release's SHA-256)"
    )]
    Update {
        #[arg(
            long,
            conflicts_with = "version",
            help = "Print the current and latest versions and install nothing; exit code 10 when an update is available"
        )]
        check: bool,
        #[arg(
            long,
            value_name = "VERSION",
            help = "Install this release instead of the latest; an older one is a deliberate downgrade"
        )]
        version: Option<String>,
    },
    #[command(hide = true, about = "Run local micro-benchmarks")]
    Bench {
        #[arg(
            long,
            value_name = "PATH",
            help = "Tree to scan [default: current directory]"
        )]
        path: Option<PathBuf>,
        #[arg(long, help = "Shorter runs")]
        quick: bool,
        #[arg(long, help = "Print JSON")]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    Host,
    Guest,
}

#[derive(Subcommand, Debug)]
pub enum TrustCmd {
    #[command(about = "Trust a pre-shared peer key (from `csync key show` on the other machine)")]
    Add {
        #[arg(value_name = "KEY")]
        key: String,
        #[arg(
            long,
            value_enum,
            help = "What the other machine is: host (when run on a guest) or guest (when run on a host)"
        )]
        role: RoleArg,
        #[arg(
            long,
            value_name = "NAME",
            help = "Name to remember the peer by [default: <role>-<fingerprint>]"
        )]
        name: Option<String>,
    },
    #[command(about = "List trusted peers")]
    List,
}

#[derive(Subcommand, Debug)]
pub enum KeyCmd {
    #[command(about = "Print the public key")]
    Show {
        #[arg(long, help = "Print the short fingerprint instead of the key")]
        fingerprint: bool,
    },
}

#[derive(Debug)]
pub struct Coded {
    pub code: u8,
    pub msg: String,
}

impl fmt::Display for Coded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Coded {}

fn coded(code: u8, msg: impl Into<String>) -> Coded {
    Coded {
        code,
        msg: msg.into(),
    }
}

// carries an exit code through an io::Error returned from a worker thread
fn coded_io(code: u8, msg: impl Into<String>) -> io::Error {
    io::Error::other(coded(code, msg))
}

impl From<io::Error> for Coded {
    fn from(e: io::Error) -> Self {
        if let Some(c) = e.get_ref().and_then(|x| x.downcast_ref::<Coded>()) {
            return coded(c.code, c.msg.clone());
        }
        let code = match e.kind() {
            io::ErrorKind::PermissionDenied => EXIT_AUTH,
            io::ErrorKind::Unsupported => EXIT_ENV,
            io::ErrorKind::Interrupted => EXIT_INTERRUPTED,
            _ => EXIT_FAIL,
        };
        coded(code, e.to_string())
    }
}

fn ctx(what: &str) -> impl FnOnce(io::Error) -> Coded + '_ {
    move |e| {
        let mut c = Coded::from(e);
        c.msg = format!("{what}: {}", c.msg);
        c
    }
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let headless = cli.no_tui || !io::stdout().is_terminal() || !io::stdin().is_terminal();
    let r = match cli.cmd {
        Cmd::Host {
            path,
            no_pair,
            listen,
            no_mdns,
            all_interfaces,
        } => cmd_host(
            HostArgs {
                path,
                no_pair,
                listen,
                no_mdns,
                all_interfaces,
            },
            headless,
        ),
        Cmd::Join {
            mountpoint,
            connect,
            host,
            repair,
            allow_other,
            cache_size,
            name,
            all_interfaces,
        } => cmd_join(
            JoinArgs {
                mountpoint,
                connect,
                host,
                repair,
                allow_other,
                cache_size,
                name,
                all_interfaces,
            },
            headless,
        ),
        Cmd::Forget { selector } => cmd_forget(&selector),
        Cmd::Trust {
            cmd: TrustCmd::Add { key, role, name },
        } => cmd_trust_add(&key, role, name.as_deref()),
        Cmd::Trust {
            cmd: TrustCmd::List,
        } => cmd_trust_list(),
        Cmd::Key {
            cmd: KeyCmd::Show { fingerprint },
        } => cmd_key_show(fingerprint),
        Cmd::Doctor {
            mount,
            allow_other,
            json,
        } => cmd_doctor(mount, allow_other, json),
        Cmd::Status { json } => cmd_status(json),
        Cmd::Update { check, version } => cmd_update(check, version),
        Cmd::Bench { path, quick, json } => cmd_bench(path, quick, json),
    };
    match r {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("csync: {}", e.msg);
            ExitCode::from(e.code)
        }
    }
}

fn setup_dirs() -> Result<Dirs, Coded> {
    let dirs = Dirs::discover().map_err(ctx("cannot locate the csync directories"))?;
    dirs.ensure()
        .map_err(ctx("cannot prepare the csync directories"))?;
    Ok(dirs)
}

fn load_keys(dirs: &Dirs) -> Result<(Arc<Identity>, Arc<Trust>), Coded> {
    let id = Identity::load_or_create(dirs.trust_dir())
        .map_err(|e| coded(EXIT_ENV, format!("identity key: {e}")))?;
    let trust =
        Trust::load(dirs.trust_dir()).map_err(|e| coded(EXIT_ENV, format!("trust store: {e}")))?;
    Ok((Arc::new(id), Arc::new(trust)))
}

type ForgetFn = Box<dyn Fn(&str) -> io::Result<Vec<TrustEntry>> + Send>;

fn ctl_handler(bus: Arc<UiBus>, forget: ForgetFn) -> ctl::Handler {
    Box::new(move |req| match req {
        CtlReq::Status => tui::report(&bus.read()),
        CtlReq::Forget(sel) => match forget(&sel) {
            Ok(gone) => format!("forgot {}\n", gone.len()),
            Err(e) => format!("error {e}\n"),
        },
    })
}

fn start_ctl(
    dirs: &Dirs,
    role: &str,
    id: &str,
    bus: &Arc<UiBus>,
    forget: ForgetFn,
) -> io::Result<ctl::CtlServer> {
    let paths = dirs.ctl_socket_candidates(role, id)?;
    ctl::serve_first(&paths, ctl_handler(bus.clone(), forget))
}

// the host owns its trust store, so forgetting goes through its loop, which also drops the session
fn host_forget(tx: Sender<HostCtl>) -> ForgetFn {
    Box::new(move |sel| {
        let (reply, rx) = bounded(1);
        tx.send_timeout(
            HostCtl::Forget {
                selector: sel.to_owned(),
                reply,
            },
            CMD_TIMEOUT,
        )
        .map_err(|_| io::Error::other("the host is not running"))?;
        rx.recv_timeout(CTL_REPLY_TIMEOUT)
            .map_err(|_| io::Error::other("the host did not answer"))?
    })
}

fn guest_forget(bus: Arc<UiBus>, trust: Arc<Trust>, cmds: Sender<UiCmd>) -> ForgetFn {
    Box::new(move |sel| {
        let gone = trust.forget(sel)?;
        let snap = bus.read();
        for e in &gone {
            let fpr = e.key.fpr();
            for p in snap.peers.iter().filter(|p| p.fpr == fpr) {
                let _ = cmds.send_timeout(UiCmd::Revoke(p.id), CMD_TIMEOUT);
            }
        }
        Ok(gone)
    })
}

struct DoneGuard(Option<Sender<io::Result<()>>>);

impl DoneGuard {
    fn finish(mut self, r: io::Result<()>) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(r);
        }
    }
}

impl Drop for DoneGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(Err(io::Error::other("the session stopped unexpectedly")));
        }
    }
}

// runs the session on a worker thread while this thread owns the terminal or the line protocol
fn drive(
    bus: &Arc<UiBus>,
    wake: &Receiver<()>,
    cmds: &Sender<UiCmd>,
    headless: bool,
    work: impl FnOnce() -> io::Result<()> + Send + 'static,
) -> Result<(), Coded> {
    // installed once per process; from here on sigint/sigterm/sighup arrive as messages, not kills
    let signals = crate::sys::signals().map_err(ctx("cannot install signal handlers"))?;
    let (done_tx, done_rx) = bounded(1);
    let worker = thread::Builder::new()
        .name("csync-session".into())
        .spawn(move || {
            let g = DoneGuard(Some(done_tx));
            g.finish(work());
        })
        .map_err(ctx("cannot start the session thread"))?;
    let mut ends = tui::Ends {
        done: &done_rx,
        signals: &signals,
        got_signal: None,
    };
    let r = if headless {
        tui::run_headless(bus, wake, cmds, &mut ends)
    } else {
        match tui::run_interactive(bus, wake, cmds, &mut ends) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("csync: terminal unavailable ({e}); using line output");
                tui::run_headless(bus, wake, cmds, &mut ends)
            }
        }
    };
    match r {
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(Coded::from(e)),
        r => {
            let _ = worker.join();
            r.map_err(Coded::from)?;
            if ends.got_signal == Some(libc::SIGINT) {
                return Err(coded(EXIT_INTERRUPTED, "interrupted"));
            }
            Ok(())
        }
    }
}

struct HostArgs {
    path: Option<PathBuf>,
    no_pair: bool,
    listen: Option<SocketAddr>,
    no_mdns: bool,
    all_interfaces: bool,
}

fn cmd_host(a: HostArgs, headless: bool) -> Result<u8, Coded> {
    let raw = a.path.unwrap_or_else(|| PathBuf::from("."));
    let root = fs::canonicalize(&raw)
        .map_err(|e| coded(EXIT_USAGE, format!("project root {}: {e}", raw.display())))?;
    if !root.is_dir() {
        return Err(coded(
            EXIT_USAGE,
            format!("project root {} is not a directory", root.display()),
        ));
    }
    let dirs = setup_dirs()?;
    load_keys(&dirs)?;
    let project = config::project_name(&root);
    let state_dir = dirs.project_dir(&root);
    config::ensure_private_dir(&state_dir).map_err(ctx("project state directory"))?;
    let listen = a.listen.unwrap_or(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        DEFAULT_PORT,
    ));
    // a probe bind reports a busy port before the host spends time on its index scan
    if listen.port() != 0 {
        std::net::TcpListener::bind(listen).map_err(ctx(&format!("cannot listen on {listen}")))?;
    }

    let (bus, wake) = UiBus::new(Role::Host);
    bus.update(|s| {
        s.project = Some(project.clone());
        s.root = Some(root.clone());
        s.listen = Some(listen);
        if a.no_pair {
            s.hint("pairing is disabled (--no-pair): only trusted guests can connect");
        }
    });
    let (cmd_tx, cmd_rx) = bounded(CMD_QUEUE);
    let (hctl_tx, hctl_rx) = bounded(4);
    let _ctl = start_ctl(
        &dirs,
        "host",
        &config::path_id(&root),
        &bus,
        host_forget(hctl_tx),
    )
    .map_err(ctx("control socket"))?;
    let mut cfg = HostCfg::new(root, dirs.config.clone(), state_dir);
    cfg.project = Some(project);
    cfg.listen = listen;
    cfg.allow_pairing = !a.no_pair;
    cfg.advertise = !a.no_mdns;
    cfg.all_ifaces = a.all_interfaces;
    cfg.ctl = Some(hctl_rx);
    let b = bus.clone();
    drive(&bus, &wake, &cmd_tx, headless, move || {
        crate::host::run(cfg, b, cmd_rx)
    })?;
    Ok(EXIT_OK)
}

struct JoinArgs {
    mountpoint: Option<PathBuf>,
    connect: Option<String>,
    host: Option<String>,
    repair: bool,
    allow_other: bool,
    cache_size: Option<u64>,
    name: Option<String>,
    all_interfaces: bool,
}

pub fn resolve_addr(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let bare = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_PORT));
    }
    let found: Vec<SocketAddr> = match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() => s.to_socket_addrs(),
        _ => (s, DEFAULT_PORT).to_socket_addrs(),
    }
    .map_err(|e| format!("cannot resolve {s}: {e}"))?
    .collect();
    found
        .iter()
        .find(|a| a.is_ipv4())
        .or(found.first())
        .copied()
        .ok_or_else(|| format!("{s} has no addresses"))
}

fn trusted_hosts(trust: &Trust) -> Vec<TrustEntry> {
    trust
        .entries()
        .into_iter()
        .filter(|e| e.role == Role::Host)
        .collect()
}

fn hex_prefix(sel: &str) -> Option<String> {
    (sel.len() >= 4 && sel.bytes().all(|b| b.is_ascii_hexdigit())).then(|| sel.to_ascii_lowercase())
}

fn entry_matches(e: &TrustEntry, sel: &str) -> bool {
    e.name.as_str() == sel
        || e.key.to_b64() == sel
        || hex_prefix(sel).is_some_and(|h| e.key.fpr_hex().starts_with(&h))
}

fn ad_matches(ad: &HostAd, sel: &str, trusted: &[TrustEntry]) -> bool {
    ad.label.as_str() == sel
        || ad.project.as_str() == sel
        || hex_prefix(sel).is_some_and(|h| view::fpr_text(&ad.fpr).starts_with(&h))
        || trusted
            .iter()
            .any(|e| e.key.fpr() == ad.fpr && entry_matches(e, sel))
}

// the key to resume with for a --connect target, or None to pair
fn connect_key(trust: &Trust, sel: Option<&str>, repair: bool) -> Result<Option<PeerKey>, Coded> {
    if repair {
        return Ok(None);
    }
    let hosts = trusted_hosts(trust);
    match sel {
        Some(sel) => Ok(hosts.iter().find(|e| entry_matches(e, sel)).map(|e| e.key)),
        None => match hosts.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(one.key)),
            _ => Err(coded(
                EXIT_USAGE,
                "several hosts are trusted: pass --host NAME to pick one (csync trust list shows them)",
            )),
        },
    }
}

fn mount_dir_name(project: &Name) -> String {
    let s: String = project
        .as_str()
        .chars()
        .map(|c| if view::is_hidden_char(c) { '_' } else { c })
        .collect();
    if s.starts_with('-') {
        format!("_{s}")
    } else {
        s
    }
}

fn prepare_mount(p: &Path) -> io::Result<PathBuf> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        env::current_dir()?.join(p)
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    crate::guest::fs::clear_stale(&abs);
    if let Err(e) = fs::symlink_metadata(&abs)
        && doctor::is_dead_mount(&e)
    {
        force_unmount(&abs);
    }
    if let Some((_, why, fix)) = doctor::mount_point_problem(&abs) {
        let fix = fix.map(|f| format!(" (fix: {f})")).unwrap_or_default();
        return Err(coded_io(
            EXIT_ENV,
            format!("mount point {} {why}{fix}", abs.display()),
        ));
    }
    doctor::remove_finder_litter(&abs);
    if !abs.exists() {
        fs::create_dir_all(&abs)?;
    }
    fs::canonicalize(&abs)
}

fn force_unmount(at: &Path) {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("diskutil");
        c.args(["unmount", "force"]);
        c
    } else {
        let mut c = Command::new("fusermount3");
        c.arg("-uz");
        c
    };
    let _ = cmd
        .arg(at)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

struct Picked {
    addr: SocketAddr,
    key: Option<PeerKey>,
    project: Option<Name>,
}

fn publish_hosts(bus: &UiBus, ads: &[HostAd], trusted: &[TrustEntry]) {
    let hosts: Vec<FoundHost> = ads
        .iter()
        .filter_map(|a| {
            Some(FoundHost {
                label: a.label.clone(),
                addr: *a.addrs.first()?,
                fpr: a.fpr,
                paired: trusted.iter().any(|e| e.key.fpr() == a.fpr),
            })
        })
        .collect();
    bus.update(|s| s.hosts = hosts);
}

fn pick(ad: &HostAd, trusted: &[TrustEntry], repair: bool) -> Option<Picked> {
    let key = if repair {
        None
    } else {
        trusted
            .iter()
            .find(|e| e.key.fpr() == ad.fpr)
            .map(|e| e.key)
    };
    Some(Picked {
        addr: *ad.addrs.first()?,
        key,
        project: Some(ad.project.clone()),
    })
}

// browses until the user picks a host, a --host selector matches, or the only trusted host appears
fn discover_host(
    bus: &UiBus,
    cmds: &Receiver<UiCmd>,
    trust: &Trust,
    sel: Option<&str>,
    repair: bool,
    all: bool,
) -> io::Result<Option<Picked>> {
    let browser = discover::browse(all).map_err(|e| {
        coded_io(
            EXIT_ENV,
            format!("mDNS discovery failed ({e}); use --connect HOST:PORT"),
        )
    })?;
    let trusted = trusted_hosts(trust);
    bus.update(|s| s.discovering = true);
    let mut ads: Vec<HostAd> = Vec::new();
    loop {
        select! {
            recv(browser.events()) -> ev => match ev {
                Ok(Found::Added(ad)) => {
                    if ad.proto == PROTO && !ad.addrs.is_empty() {
                        let auto = match sel {
                            Some(sel) => ad_matches(&ad, sel, &trusted),
                            None => !repair && trusted.len() == 1 && trusted[0].key.fpr() == ad.fpr,
                        };
                        if auto {
                            return Ok(pick(&ad, &trusted, repair));
                        }
                        match ads.iter_mut().find(|x| x.fullname == ad.fullname) {
                            Some(x) => *x = ad,
                            None => ads.push(ad),
                        }
                        publish_hosts(bus, &ads, &trusted);
                    }
                }
                Ok(Found::Removed { fullname }) => {
                    ads.retain(|x| x.fullname != fullname);
                    publish_hosts(bus, &ads, &trusted);
                }
                Err(_) => return Err(io::Error::other("mDNS discovery stopped")),
            },
            recv(cmds) -> c => match c {
                Ok(UiCmd::Join(i)) => {
                    if let Some(p) = ads.get(i).and_then(|ad| pick(ad, &trusted, repair)) {
                        return Ok(Some(p));
                    }
                }
                Ok(UiCmd::Quit) | Err(_) => return Ok(None),
                Ok(_) => {}
            },
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_guest(cfg: GuestCfg, bus: Arc<UiBus>, cmds: Receiver<UiCmd>) -> io::Result<()> {
    crate::guest::run(cfg, bus, cmds)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run_guest(cfg: GuestCfg, bus: Arc<UiBus>, cmds: Receiver<UiCmd>) -> io::Result<()> {
    let _ = (cfg, bus, cmds);
    Err(coded_io(
        EXIT_ENV,
        "csync join mounts with FUSE and runs on Linux or macOS only",
    ))
}

fn cmd_join(a: JoinArgs, headless: bool) -> Result<u8, Coded> {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err(coded(
            EXIT_ENV,
            "csync join mounts with FUSE and runs on Linux or macOS only",
        ));
    }
    #[cfg(target_os = "macos")]
    crate::sys::macos::fuse3::probe().map_err(|e| coded(EXIT_ENV, e.to_string()))?;
    let name = config::machine_name(a.name.as_deref()).map_err(|m| coded(EXIT_USAGE, m))?;
    let addr = match &a.connect {
        Some(c) => Some(resolve_addr(c).map_err(|m| coded(EXIT_USAGE, m))?),
        None => None,
    };
    if addr.is_some() && a.mountpoint.is_none() {
        return Err(coded(EXIT_USAGE, "pass a MOUNTPOINT when using --connect"));
    }
    let mount = match &a.mountpoint {
        Some(m) => Some(prepare_mount(m).map_err(Coded::from)?),
        None => None,
    };
    let dirs = setup_dirs()?;
    let (identity, trust) = load_keys(&dirs)?;
    let key = match addr {
        Some(_) => connect_key(&trust, a.host.as_deref(), a.repair)?,
        None => None,
    };
    let cache_cap = match a.cache_size {
        Some(c) => c,
        None => config::default_cache_cap(&dirs.cache)
            .map_err(ctx("cannot measure free space for the cache"))?,
    };
    let (bus, wake) = UiBus::new(Role::Guest);
    bus.update(|s| {
        s.mount = mount.clone();
        s.host_addr = addr;
        s.stats.cache_cap = cache_cap;
    });
    let (cmd_tx, cmd_rx) = bounded(CMD_QUEUE);
    let (b, ctl_tx) = (bus.clone(), cmd_tx.clone());
    let work = move || -> io::Result<()> {
        let picked = match addr {
            Some(addr) => Picked {
                addr,
                key,
                project: None,
            },
            None => match discover_host(
                &b,
                &cmd_rx,
                &trust,
                a.host.as_deref(),
                a.repair,
                a.all_interfaces,
            )? {
                Some(p) => p,
                None => return Ok(()),
            },
        };
        let mount = match mount {
            Some(m) => m,
            None => {
                let project = picked
                    .project
                    .as_ref()
                    .ok_or_else(|| coded_io(EXIT_USAGE, "pass a MOUNTPOINT"))?;
                prepare_mount(Path::new(&mount_dir_name(project)))?
            }
        };
        b.update(|s| {
            s.discovering = false;
            s.host_addr = Some(picked.addr);
            s.mount = Some(mount.clone());
            if s.project.is_none() {
                s.project = picked.project.clone();
            }
        });
        let _ctl = start_ctl(
            &dirs,
            "guest",
            &config::path_id(&mount),
            &b,
            guest_forget(b.clone(), trust.clone(), ctl_tx),
        )?;
        let cfg = GuestCfg {
            mount,
            addr: picked.addr,
            host_key: picked.key,
            repair: a.repair,
            allow_other: a.allow_other,
            cache_cap,
            name,
            identity,
            trust,
            dirs,
        };
        run_guest(cfg, b, cmd_rx)
    };
    drive(&bus, &wake, &cmd_tx, headless, work)?;
    Ok(EXIT_OK)
}

fn cmd_forget(sel: &str) -> Result<u8, Coded> {
    let dirs = setup_dirs()?;
    let mut live = 0usize;
    for p in dirs.ctl_sockets() {
        if let Ok(r) = ctl::request(&p, &CtlReq::Forget(sel.to_owned())) {
            live += r
                .trim()
                .strip_prefix("forgot ")
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0);
        }
    }
    let trust =
        Trust::load(dirs.trust_dir()).map_err(|e| coded(EXIT_ENV, format!("trust store: {e}")))?;
    let gone = trust
        .forget(sel)
        .map_err(ctx("cannot update the trust store"))?;
    for e in &gone {
        println!(
            "forgot {} {} {}",
            role_word(e.role),
            view::clean(e.name.as_str(), 64),
            e.key.fpr_hex()
        );
    }
    if gone.is_empty() {
        if live == 0 {
            eprintln!("csync: no trusted peer matches '{}'", view::clean(sel, 64));
            return Ok(EXIT_NO_MATCH);
        }
        println!("forgot {live} peer(s) in running sessions");
    }
    Ok(EXIT_OK)
}

fn role_word(r: Role) -> &'static str {
    match r {
        Role::Host => "host",
        Role::Guest => "guest",
    }
}

fn cmd_trust_add(key: &str, role: RoleArg, name: Option<&str>) -> Result<u8, Coded> {
    let key = PeerKey::from_b64(key).ok_or_else(|| {
        coded(
            EXIT_USAGE,
            "not a csync public key: expected the 44-character output of csync key show",
        )
    })?;
    let role = match role {
        RoleArg::Host => Role::Host,
        RoleArg::Guest => Role::Guest,
    };
    let dirs = setup_dirs()?;
    let (identity, trust) = load_keys(&dirs)?;
    if key == identity.public {
        return Err(coded(
            EXIT_USAGE,
            "that is this machine's own key; run csync key show on the other machine",
        ));
    }
    let name = match name {
        Some(n) => config::machine_name(Some(n)).map_err(|m| coded(EXIT_USAGE, m))?,
        None => Name::new(&format!("{}-{}", role_word(role), &key.fpr_hex()[..8]))
            .map_err(|e| coded(EXIT_FAIL, format!("{e:?}")))?,
    };
    trust
        .add(TrustEntry {
            key,
            role,
            name: name.clone(),
            added_unix: trust::now_unix(),
        })
        .map_err(ctx("cannot update the trust store"))?;
    println!(
        "trusted {} {} {}",
        role_word(role),
        name.as_str(),
        key.fpr_hex()
    );
    Ok(EXIT_OK)
}

fn cmd_trust_list() -> Result<u8, Coded> {
    let dirs = setup_dirs()?;
    let trust =
        Trust::load(dirs.trust_dir()).map_err(|e| coded(EXIT_ENV, format!("trust store: {e}")))?;
    let entries = trust.entries();
    if entries.is_empty() {
        eprintln!("csync: no trusted peers");
        return Ok(EXIT_NO_MATCH);
    }
    for e in entries {
        println!(
            "{:<5}  {}  {}",
            role_word(e.role),
            e.key.fpr_hex(),
            view::clean(e.name.as_str(), 64)
        );
    }
    Ok(EXIT_OK)
}

fn cmd_key_show(fingerprint: bool) -> Result<u8, Coded> {
    let dirs = setup_dirs()?;
    let id = Identity::load_or_create(dirs.trust_dir())
        .map_err(|e| coded(EXIT_ENV, format!("identity key: {e}")))?;
    if fingerprint {
        println!("{}", id.public.fpr_hex());
    } else {
        println!("{}", id.public.to_b64());
    }
    Ok(EXIT_OK)
}

fn cmd_doctor(mount: Option<PathBuf>, allow_other: bool, json: bool) -> Result<u8, Coded> {
    let dirs = Dirs::discover().map_err(ctx("cannot locate the csync directories"))?;
    let checks = doctor::run(&dirs, &doctor::Opts { mount, allow_other });
    if json {
        println!("{}", doctor::render_json(&checks));
    } else {
        print!("{}", doctor::render(&checks));
    }
    Ok(if doctor::failed(&checks) {
        EXIT_ENV
    } else {
        EXIT_OK
    })
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(' ')
        .skip(1)
        .find_map(|t| t.strip_prefix(key)?.strip_prefix('='))
}

fn val(line: &str, key: &str) -> String {
    field(line, key)
        .map(|v| view::clean(&tui::unescape(v), 120))
        .unwrap_or_default()
}

fn num(line: &str, key: &str) -> u64 {
    field(line, key).and_then(|v| v.parse().ok()).unwrap_or(0)
}

// a compact human summary of one session report
pub fn human_status(report: &str) -> String {
    let mut out = String::new();
    let mut notices = Vec::new();
    for line in report.lines() {
        let kind = line.split(' ').next().unwrap_or("");
        match kind {
            "session" => {
                let role = val(line, "role");
                let place = if role == "host" {
                    val(line, "root")
                } else {
                    val(line, "mount")
                };
                let addr = if role == "host" {
                    format!("listening on {}", val(line, "listen"))
                } else {
                    format!("host {}", val(line, "host"))
                };
                out.push_str(&format!(
                    "{role} {}  {place}  {addr}  pid {}\n",
                    val(line, "project"),
                    val(line, "pid")
                ));
            }
            "peer" => {
                let rtt = u32::try_from(num(line, "rtt_us")).unwrap_or(u32::MAX);
                out.push_str(&format!(
                    "  peer {} [{}] {}  rtt {}\n",
                    val(line, "name"),
                    val(line, "fpr"),
                    val(line, "state"),
                    view::fmt_rtt(rtt)
                ));
            }
            "pairing" => out.push_str(&format!(
                "  pairing request from {}, code {}\n",
                val(line, "name"),
                val(line, "sas")
            )),
            "stats" => out.push_str(&format!(
                "  files {}  commits {}  merged {}  refused {}  cache {} / {}  skew {} ms\n",
                view::fmt_count(num(line, "files")),
                view::fmt_count(num(line, "commits")),
                view::fmt_count(num(line, "merged")),
                view::fmt_count(num(line, "refused")),
                view::fmt_bytes(num(line, "cached_bytes")),
                view::fmt_bytes(num(line, "cache_cap")),
                val(line, "skew_ms"),
            )),
            "guest" => out.push_str(&format!(
                "  cache hits {}  misses {}  fetching {}\n",
                view::fmt_count(num(line, "hits")),
                view::fmt_count(num(line, "misses")),
                num(line, "inflight")
            )),
            "notice" => notices.push(format!(
                "  {} UTC  {:<9} {}\n",
                view::fmt_utc(num(line, "ts")),
                val(line, "kind"),
                val(line, "path")
            )),
            "hint" => out.push_str(&format!("  hint: {}\n", val(line, "text"))),
            _ => {}
        }
    }
    let skip = notices.len().saturating_sub(5);
    for n in notices.into_iter().skip(skip) {
        out.push_str(&n);
    }
    out
}

fn cmd_status(json: bool) -> Result<u8, Coded> {
    let dirs = Dirs::discover().map_err(ctx("cannot locate the csync directories"))?;
    let reports: Vec<String> = dirs
        .ctl_sockets()
        .iter()
        .filter_map(|p| ctl::request(p, &CtlReq::Status).ok())
        .filter(|r| r.starts_with("session "))
        .collect();
    if json {
        let objs: Vec<String> = reports.iter().map(|r| tui::report_json(r)).collect();
        println!("[{}]", objs.join(","));
    } else if reports.is_empty() {
        eprintln!("csync: no running csync session");
    } else {
        let text: Vec<String> = reports.iter().map(|r| human_status(r)).collect();
        print!("{}", text.join("\n"));
    }
    Ok(if reports.is_empty() {
        EXIT_NOT_RUNNING
    } else {
        EXIT_OK
    })
}

fn cmd_update(check: bool, version: Option<String>) -> Result<u8, Coded> {
    update::run(&update::Opts { check, version })
}

fn cmd_bench(path: Option<PathBuf>, quick: bool, json: bool) -> Result<u8, Coded> {
    let path = match path {
        Some(p) => Some(p),
        None => env::current_dir().ok(),
    };
    let rows = bench::run(&bench::Opts { path, quick }).map_err(ctx("benchmark failed"))?;
    if json {
        println!("{}", bench::render_json(&rows));
    } else {
        print!("{}", bench::render(&rows));
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn listen_help_names_the_real_default_port() {
        let mut c = Cli::command();
        let host = c.find_subcommand_mut("host").expect("host subcommand");
        let listen = host
            .get_arguments()
            .find(|a| a.get_id() == "listen")
            .and_then(|a| a.get_help())
            .map(ToString::to_string)
            .expect("listen help");
        assert!(
            listen.contains(&format!("0.0.0.0:{DEFAULT_PORT}]")),
            "{listen}"
        );
    }

    #[test]
    fn join_help_names_both_guest_platforms() {
        let c = Cli::command();
        let join = c.find_subcommand("join").expect("join subcommand");
        let about = join
            .get_about()
            .map(ToString::to_string)
            .expect("join about");
        assert!(about.contains("Linux") && about.contains("macOS") && about.contains("macFUSE"));
        assert!(AFTER_HELP.contains("Linux or macOS guest"));
    }

    #[test]
    fn parses_the_documented_commands() {
        let c = Cli::try_parse_from([
            "csync",
            "--no-tui",
            "join",
            "/mnt/p",
            "--connect",
            "10.0.0.2:9000",
            "--cache-size",
            "2G",
        ])
        .unwrap();
        assert!(c.no_tui);
        match c.cmd {
            Cmd::Join {
                mountpoint,
                connect,
                cache_size,
                ..
            } => {
                assert_eq!(mountpoint, Some(PathBuf::from("/mnt/p")));
                assert_eq!(connect.as_deref(), Some("10.0.0.2:9000"));
                assert_eq!(cache_size, Some(2 << 30));
            }
            other => panic!("{other:?}"),
        }
        assert!(Cli::try_parse_from(["csync", "join", "--cache-size", "1K"]).is_err());
        assert!(Cli::try_parse_from(["csync", "trust", "add", "k"]).is_err());
        assert!(Cli::try_parse_from(["csync", "trust", "add", "k", "--role", "guest"]).is_ok());
        assert!(
            Cli::try_parse_from(["csync", "host", ".", "--no-pair", "--listen", "127.0.0.1:0"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["csync", "status", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["csync", "bench", "--quick"]).is_ok());
    }

    #[test]
    fn parses_the_update_flags() {
        match Cli::try_parse_from(["csync", "update"]).unwrap().cmd {
            Cmd::Update { check, version } => assert_eq!((check, version), (false, None)),
            other => panic!("{other:?}"),
        }
        match Cli::try_parse_from(["csync", "update", "--check"])
            .unwrap()
            .cmd
        {
            Cmd::Update { check, version } => assert_eq!((check, version), (true, None)),
            other => panic!("{other:?}"),
        }
        match Cli::try_parse_from(["csync", "update", "--version", "v0.1.0"])
            .unwrap()
            .cmd
        {
            Cmd::Update { check, version } => {
                assert_eq!((check, version.as_deref()), (false, Some("v0.1.0")));
            }
            other => panic!("{other:?}"),
        }
        assert!(Cli::try_parse_from(["csync", "update", "--check", "--version", "1.0.0"]).is_err());
        assert!(Cli::try_parse_from(["csync", "update", "--version"]).is_err());
    }

    #[test]
    fn resolves_connect_targets() {
        assert_eq!(
            resolve_addr("10.1.2.3:99"),
            Ok("10.1.2.3:99".parse().unwrap())
        );
        assert_eq!(
            resolve_addr("10.1.2.3"),
            Ok(SocketAddr::new("10.1.2.3".parse().unwrap(), DEFAULT_PORT))
        );
        assert_eq!(
            resolve_addr("[::1]"),
            Ok(SocketAddr::new("::1".parse().unwrap(), DEFAULT_PORT))
        );
        assert_eq!(
            resolve_addr("::1"),
            Ok(SocketAddr::new("::1".parse().unwrap(), DEFAULT_PORT))
        );
        assert_eq!(resolve_addr("localhost:5").map(|a| a.port()), Ok(5));
    }

    #[test]
    fn exit_codes_survive_worker_errors() {
        let c = Coded::from(coded_io(EXIT_ENV, "mount point busy"));
        assert_eq!((c.code, c.msg.as_str()), (EXIT_ENV, "mount point busy"));
        assert_eq!(
            Coded::from(io::Error::from(io::ErrorKind::PermissionDenied)).code,
            EXIT_AUTH
        );
        assert_eq!(Coded::from(io::Error::other("x")).code, EXIT_FAIL);
    }

    #[test]
    fn human_status_cleans_peer_strings() {
        let r = "session role=host pid=1 project=p root=/r listen=0.0.0.0:1\npeer id=1 name=a%1B%5B2Jb fpr=00 state=live rtt_us=2000\n";
        let h = human_status(r);
        assert!(h.contains("peer a[2Jb"), "{h}");
        assert!(!h.contains('\x1b'));
    }
}
