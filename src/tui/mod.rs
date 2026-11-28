use crate::proto::{Name, Notice, hs::Role};
use crossbeam_channel::Sender;
use std::{collections::VecDeque, net::SocketAddr, path::PathBuf, sync::Mutex};

pub mod anim;
pub mod diff;
pub mod dither;
pub mod feed;
pub mod theme;
pub mod view;
pub mod widgets;

pub const NOTICES_MAX: usize = 200;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnState {
    Waiting,
    Discovering,
    Handshaking,
    Pairing {
        sas: [u8; 8],
    },
    Syncing {
        done: u64,
        total: u64,
    },
    Live,
    Disconnected {
        since_ms: u64,
        reason: Option<String>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerView {
    pub id: u64,
    pub name: Name,
    pub fpr: [u8; 8],
    pub state: ConnState,
    pub rtt_us: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundHost {
    pub label: Name,
    pub addr: SocketAddr,
    pub fpr: [u8; 8],
    pub paired: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairPrompt {
    pub peer: u64,
    pub name: Name,
    pub sas: [u8; 8],
    pub expires_ms: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub files: u64,
    pub cached_bytes: u64,
    pub cache_cap: u64,
    pub fetches: u64,
    pub commits: u64,
    pub merged: u64,
    pub refused: u64,
    pub tx: u64,
    pub rx: u64,
    pub inject_backlog: u32,
    // host: indexed files whose content hash is not known yet
    pub hash_pending: u32,
    pub skew_ms: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiSnapshot {
    pub role: Role,
    pub project: Option<Name>,
    pub mount: Option<PathBuf>,
    pub peers: Vec<PeerView>,
    pub pairing: Option<PairPrompt>,
    pub hosts: Vec<FoundHost>,
    pub stats: Stats,
    pub notices: VecDeque<(u64, Notice)>,
    pub hints: Vec<&'static str>,
    pub root: Option<PathBuf>,
    pub listen: Option<SocketAddr>,
    pub host_addr: Option<SocketAddr>,
    pub mounted: bool,
    pub discovering: bool,
    pub io: Vec<PeerIo>,
    pub guest: GuestStats,
}
#[derive(Clone, Copy, Debug)]
pub enum UiCmd {
    Accept(u64),
    Reject(u64),
    Join(usize),
    Confirm(bool),
    Revoke(u64),
    Quit,
}
pub struct UiBus {
    snap: Mutex<UiSnapshot>,
    wake: Sender<()>,
    role: Role,
    feed: feed::FeedSlot,
    // bumped by every update, so the interactive loop can tell a wake that changed nothing
    ver: AtomicU64,
}
impl UiBus {
    pub fn update(&self, f: impl FnOnce(&mut UiSnapshot)) {
        if let Ok(mut s) = self.snap.lock() {
            f(&mut s);
        }
        self.ver.fetch_add(1, Ordering::Release);
        let _ = self.wake.try_send(());
    }
    pub fn feed(&self) -> &feed::FeedSlot {
        &self.feed
    }
    // a notice goes to the snapshot as always and is mirrored into the activity feed
    pub fn notice(&self, ts_ms: u64, n: Notice) {
        let by = match self.role {
            Role::Host => feed::By::Host,
            Role::Guest => feed::By::Local,
        };
        self.feed.push_batch([feed::Entry {
            id: 0,
            ts_ms,
            what: feed::What::Notice(n.kind),
            by,
            path: n.path.clone(),
            from: None,
            size: 0,
            old: None,
            new: None,
            ver: 0,
            merged: false,
        }]);
        self.update(|s| s.push_notice(ts_ms, n));
    }
    pub fn read(&self) -> UiSnapshot {
        self.snap
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }
}

use crossbeam_channel::{Receiver, at, bounded, never, select};
use diff::{DiffSource, DiffView};
use feed::{Entry, FeedSlot};
use ratatui::{
    DefaultTerminal, Terminal,
    backend::Backend,
    buffer::Buffer,
    crossterm::{
        Command,
        event::{
            self, DisableBracketedPaste, DisableFocusChange, EnableBracketedPaste,
            EnableFocusChange, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton,
            MouseEvent, MouseEventKind,
        },
        execute, queue,
        terminal::{BeginSynchronizedUpdate, EndSynchronizedUpdate},
    },
    layout::Rect,
};
use std::{
    fmt::{self, Write as _},
    io::{self, BufRead, Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::{
        Arc, Once,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use theme::Depth;
use view::{FeedUi, Focus, Hits, ViewState};

const FRAME_MIN: Duration = anim::FRAME;
const UNFOCUSED_FRAME: Duration = Duration::from_secs(1);
const CMD_TIMEOUT: Duration = Duration::from_secs(1);
const INPUT_QUEUE: usize = 64;
const LINE_MAX: u64 = 4096;
const REPORT_NOTICES: usize = 20;
// producers push into the feed without waking the screen, so a focused one looks now and then
const FEED_POLL: Duration = Duration::from_millis(250);

// per-peer transfer counters, kept beside PeerView so producers update them in place
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerIo {
    pub id: u64,
    pub tx: u64,
    pub rx: u64,
    pub pending: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestStats {
    pub hits: u64,
    pub misses: u64,
    pub inflight: u32,
    pub prefetch_done: u64,
    pub prefetch_total: u64,
    pub passthrough: bool,
    // the macfuse backend and how a host change reaches the kernel (native, injected, off, probing); empty elsewhere
    pub backend: &'static str,
    pub inval: &'static str,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl UiSnapshot {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            project: None,
            mount: None,
            peers: Vec::new(),
            pairing: None,
            hosts: Vec::new(),
            stats: Stats::default(),
            notices: VecDeque::with_capacity(NOTICES_MAX),
            hints: Vec::new(),
            root: None,
            listen: None,
            host_addr: None,
            mounted: false,
            discovering: false,
            io: Vec::new(),
            guest: GuestStats::default(),
        }
    }

    pub fn push_notice(&mut self, ts_ms: u64, n: Notice) {
        while self.notices.len() >= NOTICES_MAX {
            self.notices.pop_front();
        }
        self.notices.push_back((ts_ms, n));
    }

    pub fn hint(&mut self, h: &'static str) {
        if !self.hints.contains(&h) {
            self.hints.push(h);
        }
    }

    pub fn peer_io(&mut self, id: u64) -> &mut PeerIo {
        let i = match self.io.iter().position(|p| p.id == id) {
            Some(i) => i,
            None => {
                self.io.push(PeerIo {
                    id,
                    ..PeerIo::default()
                });
                self.io.len() - 1
            }
        };
        &mut self.io[i]
    }

    pub fn drop_peer(&mut self, id: u64) {
        self.peers.retain(|p| p.id != id);
        self.io.retain(|p| p.id != id);
        if self.pairing.as_ref().is_some_and(|p| p.peer == id) {
            self.pairing = None;
        }
    }
}

impl UiBus {
    // wake is bounded(1) so bursts of updates coalesce into one redraw
    pub fn new(role: Role) -> (Arc<Self>, Receiver<()>) {
        let (wake, rx) = bounded(1);
        (
            Arc::new(Self {
                snap: Mutex::new(UiSnapshot::new(role)),
                wake,
                role,
                feed: feed::FeedSlot::default(),
                ver: AtomicU64::new(0),
            }),
            rx,
        )
    }
}

enum Action {
    None,
    Redraw,
    Cmd(UiCmd),
    // the view state already holds the open diff; this is the entry to compute it for
    Open(Box<Entry>),
    Quit,
}

// rows or lines one wheel notch moves
const WHEEL_ROWS: usize = 3;

fn open_selected(f: &mut FeedUi) -> Action {
    match f.open() {
        Some(e) => Action::Open(Box::new(e)),
        None => Action::None,
    }
}

fn diff_key(code: KeyCode, vs: &mut ViewState, repeat: bool) -> Option<Action> {
    let page = vs.feed.diff_page();
    let f = &mut vs.feed;
    match code {
        KeyCode::Esc if !repeat => {
            f.close_diff();
        }
        KeyCode::Up | KeyCode::Char('k') => f.scroll_diff(false, 1),
        KeyCode::Down | KeyCode::Char('j') => f.scroll_diff(true, 1),
        KeyCode::PageUp => f.scroll_diff(false, page),
        KeyCode::PageDown | KeyCode::Char(' ') => f.scroll_diff(true, page),
        KeyCode::Home => f.scroll_diff(false, usize::MAX),
        KeyCode::End => f.scroll_diff(true, usize::MAX),
        _ => return None,
    }
    Some(Action::Redraw)
}

// keys for the activity panel; None leaves the key to the rest of the screen
fn feed_key(k: KeyEvent, s: &UiSnapshot, vs: &mut ViewState, repeat: bool) -> Option<Action> {
    if vs.feed.diff.is_some() {
        return diff_key(k.code, vs, repeat);
    }
    let host = s.role == Role::Host;
    let page = vs.feed.page();
    let f = &mut vs.feed;
    let active = !host || f.focus == Focus::Activity;
    match k.code {
        KeyCode::Tab if host && !repeat => {
            f.focus = if active {
                Focus::Guests
            } else {
                Focus::Activity
            };
        }
        KeyCode::Up | KeyCode::Char('k') if active => f.step(false, 1),
        KeyCode::Down | KeyCode::Char('j') if active => f.step(true, 1),
        KeyCode::PageUp if active => f.step(false, page),
        KeyCode::PageDown if active => f.step(true, page),
        // the list runs newest first, so Home goes to the oldest row and End back to the newest
        KeyCode::Home if active => f.select(1),
        KeyCode::End if active => f.resume(),
        KeyCode::Enter if active && !repeat => return Some(open_selected(f)),
        KeyCode::Esc
            if !repeat && (f.anchor.is_some() || !f.follow || f.focus == Focus::Activity) =>
        {
            f.resume();
            f.focus = Focus::Guests;
        }
        _ => return None,
    }
    Some(Action::Redraw)
}

fn on_mouse(ev: MouseEvent, hits: &Hits, vs: &mut ViewState) -> Action {
    if !view::wants_mouse(vs) {
        return Action::None;
    }
    let down = match ev.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if vs.feed.diff.is_some() {
                return Action::None;
            }
            let Some(id) = hits.row_at(ev.column, ev.row) else {
                return Action::None;
            };
            vs.feed.focus = Focus::Activity;
            if vs.feed.anchor == Some(id) {
                return open_selected(&mut vs.feed);
            }
            vs.feed.select(id);
            return Action::Redraw;
        }
        MouseEventKind::ScrollDown => true,
        MouseEventKind::ScrollUp => false,
        _ => return Action::None,
    };
    if vs.feed.diff.is_some() {
        vs.feed.scroll_diff(down, WHEEL_ROWS);
    } else {
        vs.feed.scroll(down, WHEEL_ROWS);
    }
    Action::Redraw
}

fn on_key(k: KeyEvent, s: &UiSnapshot, vs: &mut ViewState) -> Action {
    if k.kind == KeyEventKind::Release {
        return Action::None;
    }
    let repeat = k.kind == KeyEventKind::Repeat;
    if k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('c' | 'C')) {
        return if repeat { Action::None } else { Action::Quit };
    }
    if repeat && vs.confirm_revoke.is_some() {
        return Action::None;
    }
    if let Some(id) = vs.confirm_revoke.take() {
        return if matches!(k.code, KeyCode::Char('y' | 'Y')) {
            Action::Cmd(UiCmd::Revoke(id))
        } else {
            Action::Redraw
        };
    }
    let len = match s.role {
        Role::Host => s.peers.len(),
        Role::Guest => s.hosts.len(),
    };
    let prompt = view::guest_prompt(s).is_some();
    if view::feed_live(s, vs)
        && let Some(a) = feed_key(k, s, vs, repeat)
    {
        return a;
    }
    match (s.role, k.code) {
        (_, KeyCode::Up | KeyCode::Char('k')) => {
            vs.sel = vs.sel.saturating_sub(1);
            Action::Redraw
        }
        (_, KeyCode::Down | KeyCode::Char('j')) => {
            if vs.sel + 1 < len {
                vs.sel += 1;
            }
            Action::Redraw
        }
        _ if repeat => Action::None,
        (_, KeyCode::Char('q' | 'Q')) => Action::Quit,
        (Role::Host, KeyCode::Char('a' | 'A')) => s
            .pairing
            .as_ref()
            .map_or(Action::None, |p| Action::Cmd(UiCmd::Accept(p.peer))),
        (Role::Host, KeyCode::Char('r' | 'R')) => s
            .pairing
            .as_ref()
            .map_or(Action::None, |p| Action::Cmd(UiCmd::Reject(p.peer))),
        (Role::Host, KeyCode::Char('x' | 'X')) => match s.peers.get(vs.sel) {
            Some(p) => {
                vs.confirm_revoke = Some(p.id);
                Action::Redraw
            }
            None => Action::None,
        },
        (Role::Guest, KeyCode::Char('y' | 'Y')) if prompt => Action::Cmd(UiCmd::Confirm(true)),
        (Role::Guest, KeyCode::Char('n' | 'N')) if prompt => Action::Cmd(UiCmd::Confirm(false)),
        (Role::Guest, KeyCode::Enter) if s.peers.is_empty() && vs.sel < s.hosts.len() => {
            Action::Cmd(UiCmd::Join(vs.sel))
        }
        _ => Action::None,
    }
}

static FOCUS_REPORTING: AtomicBool = AtomicBool::new(false);
static PASTE_REPORTING: AtomicBool = AtomicBool::new(false);
static MOUSE_REPORTING: AtomicBool = AtomicBool::new(false);

// button presses and the wheel only, never motion; the SGR form keeps wide terminals addressable
struct MouseMode(bool);

impl Command for MouseMode {
    fn write_ansi(&self, f: &mut impl fmt::Write) -> fmt::Result {
        f.write_str(if self.0 {
            "\x1b[?1000h\x1b[?1006h"
        } else {
            "\x1b[?1000l\x1b[?1006l"
        })
    }

    #[cfg(windows)]
    fn execute_winapi(&self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

fn mouse_off() {
    if MOUSE_REPORTING.swap(false, Ordering::SeqCst) {
        let _ = execute!(io::stdout(), MouseMode(false));
    }
}

fn mouse_on() -> io::Result<()> {
    execute!(io::stdout(), MouseMode(true))?;
    MOUSE_REPORTING.store(true, Ordering::SeqCst);
    Ok(())
}

// capture is held only while the activity panel can be clicked, so codes and addresses elsewhere stay selectable
fn mouse_follow(on: &mut bool, want: bool) {
    if want == *on {
        return;
    }
    if want {
        *on = mouse_on().is_ok();
    } else {
        mouse_off();
        *on = false;
    }
}

fn focus_off() {
    if FOCUS_REPORTING.swap(false, Ordering::SeqCst) {
        let _ = execute!(io::stdout(), DisableFocusChange);
    }
}

fn paste_off() {
    if PASTE_REPORTING.swap(false, Ordering::SeqCst) {
        let _ = execute!(io::stdout(), DisableBracketedPaste);
    }
}

// pasted text then arrives as one Paste event instead of keys that could answer a prompt
fn paste_on() -> io::Result<()> {
    execute!(io::stdout(), EnableBracketedPaste)?;
    PASTE_REPORTING.store(true, Ordering::SeqCst);
    Ok(())
}

fn bell() {
    let mut out = io::stdout();
    let _ = out.write_all(b"\x07");
    let _ = out.flush();
}

fn frame_gap(focused: bool, urgent: bool) -> Duration {
    if focused || urgent {
        FRAME_MIN
    } else {
        UNFOCUSED_FRAME
    }
}

fn prompt_appeared(old: &UiSnapshot, new: &UiSnapshot) -> bool {
    view::guest_prompt(old).is_none() && view::guest_prompt(new).is_some()
}

// asks the terminal to report focus; the panic hook and Restore both turn it off again
fn focus_on() -> io::Result<()> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            focus_off();
            paste_off();
            mouse_off();
            prev(info);
        }));
    });
    execute!(io::stdout(), EnableFocusChange)?;
    FOCUS_REPORTING.store(true, Ordering::SeqCst);
    Ok(())
}

struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        focus_off();
        paste_off();
        mouse_off();
        ratatui::restore();
    }
}

// owns what is on screen: the snapshot, view state and the last composited frame for transitions
struct Screen {
    snap: UiSnapshot,
    vs: ViewState,
    shown: Buffer,
    from: Buffer,
    last: Option<Instant>,
    redraws: u64,
}

impl Screen {
    fn new(snap: UiSnapshot, depth: Depth, now: Instant) -> Self {
        Self {
            snap,
            vs: ViewState::new(depth, now),
            shown: Buffer::default(),
            from: Buffer::default(),
            last: None,
            redraws: 0,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        self.vs.deadline(&self.snap)
    }

    // copies the rows the panel will show, and only when the feed or the view moved
    fn sync_feed(&mut self, slot: &FeedSlot, area: Rect) {
        let Self { snap, vs, .. } = self;
        if !vs.feed.on {
            return;
        }
        let rows = view::feed_rows(snap, vs, area);
        let ver = slot.version();
        if vs.feed.needs(rows, ver) {
            let win = slot.window(vs.feed.view, rows);
            vs.feed.set_rows(win, slot.len(), rows, ver);
        }
    }

    fn render<B: Backend>(
        &mut self,
        term: &mut Terminal<B>,
        now: Instant,
        wall_ms: u64,
    ) -> io::Result<()> {
        let Self {
            snap,
            vs,
            shown,
            from,
            ..
        } = self;
        vs.observe(snap, now, wall_ms);
        let len = match snap.role {
            Role::Host => snap.peers.len(),
            Role::Guest => snap.hosts.len(),
        };
        vs.sel = vs.sel.min(len.saturating_sub(1));
        let mut hits = Hits::default();
        let frame = term
            .draw(|f| {
                let area = f.area();
                let scene = view::scene(snap, vs, area);
                if scene != vs.scene {
                    if shown.area == area {
                        std::mem::swap(from, shown);
                    } else {
                        *from = Buffer::empty(area);
                    }
                    vs.scene = scene;
                    vs.trans = Some(now);
                }
                hits = view::draw(f, snap, vs);
                if let Some(t0) = vs.trans {
                    let p = anim::progress(t0, now, anim::TRANSITION);
                    if p < 1.0 && from.area == area {
                        dither::blend_into(from, f.buffer_mut(), anim::smooth(p));
                    } else {
                        vs.trans = None;
                    }
                }
            })
            .map_err(|e| io::Error::other(e.to_string()))?;
        vs.feed.hits = hits;
        if shown.area == frame.buffer.area {
            for (d, s) in shown.content.iter_mut().zip(&frame.buffer.content) {
                d.clone_from(s);
            }
        } else {
            *shown = frame.buffer.clone();
        }
        self.last = Some(now);
        self.redraws += 1;
        Ok(())
    }
}

// one frame wrapped in a synchronized update so terminals that support it never show a torn dissolve
fn frame(
    term: &mut DefaultTerminal,
    screen: &mut Screen,
    slot: &FeedSlot,
    now: Instant,
) -> io::Result<()> {
    let size = term.size()?;
    screen.sync_feed(slot, Rect::new(0, 0, size.width, size.height));
    queue!(term.backend_mut(), BeginSynchronizedUpdate)?;
    let r = screen.render(term, now, now_ms());
    queue!(term.backend_mut(), EndSynchronizedUpdate)?;
    Write::flush(term.backend_mut())?;
    r
}

pub struct Ends<'a> {
    pub done: &'a Receiver<io::Result<()>>,
    pub signals: &'a Receiver<i32>,
    pub got_signal: Option<i32>,
}

fn forced() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "stopped before a clean shutdown finished",
    )
}

// first signal asks the session to quit cleanly, a second one stops waiting
fn on_signal(sig: i32, ends: &mut Ends<'_>, cmds: &Sender<UiCmd>) -> bool {
    let again = ends.got_signal.is_some();
    ends.got_signal = Some(sig);
    if again {
        return true;
    }
    let _ = cmds.send_timeout(UiCmd::Quit, CMD_TIMEOUT);
    false
}

fn failed_view(why: &str) -> DiffView {
    DiffView {
        label: "",
        added: 0,
        removed: 0,
        lines: Vec::new(),
        cut: None,
        unavailable: Some(why.to_owned()),
        detail: None,
    }
}

fn compute_diff(source: Option<&dyn DiffSource>, entry: &Entry) -> DiffView {
    let Some(source) = source else {
        return failed_view("no earlier version is kept for this session");
    };
    catch_unwind(AssertUnwindSafe(|| diff::render(&source.sides(entry))))
        .unwrap_or_else(|_| failed_view("the diff could not be computed"))
}

// one short-lived thread per open diff, and only one at a time; a newer open waits its turn and replaces an older waiting one
struct DiffWorker {
    tx: Sender<(u64, DiffView)>,
    rx: Receiver<(u64, DiffView)>,
    busy: bool,
    queued: Option<(u64, Entry)>,
}

impl DiffWorker {
    fn new() -> Self {
        let (tx, rx) = bounded(2);
        Self {
            tx,
            rx,
            busy: false,
            queued: None,
        }
    }

    fn start(&mut self, req: u64, entry: Entry, slot: &FeedSlot) {
        if self.busy {
            self.queued = Some((req, entry));
            return;
        }
        self.busy = true;
        let source = slot.source();
        let tx = self.tx.clone();
        let spawned = thread::Builder::new().name("csync-diff".into()).spawn({
            let tx = tx.clone();
            move || {
                let view = compute_diff(source.as_deref(), &entry);
                let _ = tx.send((req, view));
            }
        });
        if spawned.is_err() {
            let _ = tx.try_send((req, failed_view("could not start the diff")));
        }
    }

    // whether the screen changed
    fn finish(&mut self, vs: &mut ViewState, slot: &FeedSlot, req: u64, view: DiffView) -> bool {
        self.busy = false;
        let shown = vs.feed.finish(req, view);
        if let Some((next, entry)) = self.queued.take()
            && vs.feed.diff.as_ref().is_some_and(|d| d.req == next)
        {
            self.start(next, entry, slot);
        }
        shown
    }
}

enum Step {
    Idle,
    Dirty,
    ForceQuit,
}

fn apply(
    act: Action,
    vs: &mut ViewState,
    cmds: &Sender<UiCmd>,
    worker: &mut DiffWorker,
    slot: &FeedSlot,
) -> Step {
    match act {
        Action::None => Step::Idle,
        Action::Redraw => Step::Dirty,
        Action::Cmd(c) => {
            let _ = cmds.send_timeout(c, CMD_TIMEOUT);
            Step::Dirty
        }
        Action::Open(entry) => {
            worker.start(vs.feed.req, *entry, slot);
            Step::Dirty
        }
        Action::Quit => {
            if vs.quitting {
                return Step::ForceQuit;
            }
            vs.quitting = true;
            let _ = cmds.send_timeout(UiCmd::Quit, CMD_TIMEOUT);
            Step::Dirty
        }
    }
}

// outer error: the terminal failed; inner: the worker's own result
pub fn run_interactive(
    bus: &UiBus,
    wake: &Receiver<()>,
    cmds: &Sender<UiCmd>,
    ends: &mut Ends<'_>,
) -> io::Result<io::Result<()>> {
    if std::env::var_os("TERM").is_some_and(|t| t == "dumb") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TERM=dumb has no cursor control",
        ));
    }
    let done = ends.done;
    let signals = ends.signals;
    let _restore = Restore;
    let mut term = ratatui::try_init()?;
    focus_on()?;
    paste_on()?;
    let (itx, irx) = bounded::<Event>(INPUT_QUEUE);
    thread::Builder::new()
        .name("csync-input".into())
        .spawn(move || {
            while let Ok(ev) = event::read() {
                if itx.send(ev).is_err() {
                    return;
                }
            }
        })?;
    let mut input_open = true;
    let mut sig_open = true;
    let slot = bus.feed();
    slot.enable();
    let mut seen_ver = bus.ver.load(Ordering::Acquire);
    let mut seen_feed = slot.version();
    let mut screen = Screen::new(bus.read(), Depth::detect(), Instant::now());
    screen.vs.feed.on = true;
    let mut worker = DiffWorker::new();
    let mut mouse = false;
    let mut poll_at = Instant::now() + FEED_POLL;
    let mut dirty = true;
    let mut urgent = false;
    loop {
        let now = Instant::now();
        let focused = screen.vs.focused;
        let gap = frame_gap(focused, urgent);
        let ready = screen
            .last
            .is_none_or(|t| now.saturating_duration_since(t) >= gap);
        let due = screen.deadline().is_some_and(|d| d <= now);
        if (dirty || due) && ready {
            frame(&mut term, &mut screen, slot, now)?;
            mouse_follow(&mut mouse, view::wants_mouse(&screen.vs));
            dirty = false;
            urgent = false;
        }
        // with nothing dirty and nothing animating the only timer is the slow feed check
        let target = if dirty { Some(now) } else { screen.deadline() };
        let gap = frame_gap(screen.vs.focused, urgent);
        let timer = match target {
            Some(d) => at(screen.last.map_or(d, |t| d.max(t + gap))),
            None => never(),
        };
        let poll = if screen.vs.focused {
            at(poll_at)
        } else {
            never()
        };
        let input = if input_open { irx.clone() } else { never() };
        let sigs = if sig_open { signals.clone() } else { never() };
        let results = worker.rx.clone();
        let vs = &mut screen.vs;
        select! {
            recv(wake) -> _ => {
                let v = bus.ver.load(Ordering::Acquire);
                if v != seen_ver {
                    seen_ver = v;
                    let fresh = bus.read();
                    if fresh != screen.snap {
                        if !vs.focused && prompt_appeared(&screen.snap, &fresh) {
                            urgent = true;
                            bell();
                        }
                        screen.snap = fresh;
                        vs.touch(Instant::now());
                        dirty = true;
                    }
                }
                let fv = slot.version();
                if fv != seen_feed {
                    seen_feed = fv;
                    dirty = true;
                }
            },
            recv(poll) -> _ => {
                poll_at = Instant::now() + FEED_POLL;
                let fv = slot.version();
                if fv != seen_feed {
                    seen_feed = fv;
                    dirty = true;
                }
            },
            recv(results) -> r => {
                if let Ok((req, done_view)) = r
                    && worker.finish(vs, slot, req, done_view)
                {
                    dirty = true;
                }
            },
            recv(input) -> ev => match ev {
                Ok(Event::FocusLost) => vs.focused = false,
                Ok(Event::FocusGained) => {
                    vs.focused = true;
                    vs.touch(Instant::now());
                    dirty = true;
                }
                Ok(Event::Key(k)) => {
                    vs.touch(Instant::now());
                    let act = on_key(k, &screen.snap, vs);
                    match apply(act, vs, cmds, &mut worker, slot) {
                        Step::Idle => {}
                        Step::Dirty => dirty = true,
                        Step::ForceQuit => return Ok(Err(forced())),
                    }
                }
                Ok(Event::Mouse(m)) => {
                    vs.touch(Instant::now());
                    let hits = vs.feed.hits.clone();
                    let act = on_mouse(m, &hits, vs);
                    match apply(act, vs, cmds, &mut worker, slot) {
                        Step::Idle => {}
                        Step::Dirty => dirty = true,
                        Step::ForceQuit => return Ok(Err(forced())),
                    }
                }
                Ok(Event::Resize(..)) => dirty = true,
                Ok(_) => {}
                Err(_) => input_open = false,
            },
            recv(done) -> r => return Ok(r.unwrap_or(Ok(()))),
            recv(sigs) -> s => match s {
                Ok(sig) => {
                    if on_signal(sig, ends, cmds) {
                        return Ok(Err(forced()));
                    }
                    vs.quitting = true;
                    dirty = true;
                }
                Err(_) => sig_open = false,
            },
            recv(timer) -> _ => {}
        }
    }
}

fn escape_into(out: &mut String, v: &str) {
    for &b in v.as_bytes() {
        if b.is_ascii_graphic() && b != b'%' && b != b'=' {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

pub fn unescape(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (
                b.get(i + 1).copied().and_then(hex),
                b.get(i + 2).copied().and_then(hex),
            )
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn rec(out: &mut String, kind: &str, fields: &[(&str, String)]) {
    out.push_str(kind);
    for (k, v) in fields {
        out.push(' ');
        out.push_str(k);
        out.push('=');
        escape_into(out, v);
    }
    out.push('\n');
}

fn role_word(r: Role) -> &'static str {
    match r {
        Role::Host => "host",
        Role::Guest => "guest",
    }
}

fn state_fields(st: &ConnState, f: &mut Vec<(&'static str, String)>) {
    let word = match st {
        ConnState::Waiting => "waiting",
        ConnState::Discovering => "discovering",
        ConnState::Handshaking => "handshaking",
        ConnState::Pairing { .. } => "pairing",
        ConnState::Syncing { .. } => "syncing",
        ConnState::Live => "live",
        ConnState::Disconnected { .. } => "disconnected",
    };
    f.push(("state", word.into()));
    match st {
        ConnState::Pairing { sas } => f.push(("sas", view::sas_text(sas))),
        ConnState::Syncing { done, total } => {
            f.push(("done", done.to_string()));
            f.push(("total", total.to_string()));
        }
        ConnState::Disconnected { since_ms, reason } => {
            f.push(("since_ms", since_ms.to_string()));
            if let Some(r) = reason {
                f.push(("reason", r.clone()));
            }
        }
        _ => {}
    }
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn session_fields(s: &UiSnapshot) -> Vec<(&'static str, String)> {
    let mut f = vec![
        ("role", role_word(s.role).to_owned()),
        ("pid", std::process::id().to_string()),
    ];
    if let Some(p) = &s.project {
        f.push(("project", p.as_str().to_owned()));
    }
    if let Some(r) = &s.root {
        f.push(("root", path_str(r)));
    }
    if let Some(a) = s.listen {
        f.push(("listen", a.to_string()));
    }
    if let Some(a) = s.host_addr {
        f.push(("host", a.to_string()));
    }
    if let Some(m) = &s.mount {
        f.push(("mount", path_str(m)));
        f.push(("mounted", s.mounted.to_string()));
    }
    if !s.guest.backend.is_empty() {
        f.push(("backend", s.guest.backend.to_owned()));
        f.push(("inval", s.guest.inval.to_owned()));
    }
    f
}

fn peer_fields(p: &PeerView, s: &UiSnapshot) -> Vec<(&'static str, String)> {
    let mut f = vec![
        ("id", p.id.to_string()),
        ("name", p.name.as_str().to_owned()),
        ("fpr", view::fpr_text(&p.fpr)),
    ];
    state_fields(&p.state, &mut f);
    f.push(("rtt_us", p.rtt_us.to_string()));
    if let Some(io) = s.io.iter().find(|x| x.id == p.id) {
        f.push(("tx", io.tx.to_string()));
        f.push(("rx", io.rx.to_string()));
        f.push(("pending", io.pending.to_string()));
    }
    f
}

fn pairing_fields(p: &PairPrompt) -> Vec<(&'static str, String)> {
    vec![
        ("peer", p.peer.to_string()),
        ("name", p.name.as_str().to_owned()),
        ("sas", view::sas_text(&p.sas)),
        ("expires_ms", p.expires_ms.to_string()),
    ]
}

fn host_fields(i: usize, h: &FoundHost) -> Vec<(&'static str, String)> {
    vec![
        ("index", i.to_string()),
        ("label", h.label.as_str().to_owned()),
        ("addr", h.addr.to_string()),
        ("fpr", view::fpr_text(&h.fpr)),
        ("paired", h.paired.to_string()),
    ]
}

fn stats_fields(st: &Stats) -> Vec<(&'static str, String)> {
    vec![
        ("files", st.files.to_string()),
        ("cached_bytes", st.cached_bytes.to_string()),
        ("cache_cap", st.cache_cap.to_string()),
        ("fetches", st.fetches.to_string()),
        ("commits", st.commits.to_string()),
        ("merged", st.merged.to_string()),
        ("refused", st.refused.to_string()),
        ("tx", st.tx.to_string()),
        ("rx", st.rx.to_string()),
        ("inject_backlog", st.inject_backlog.to_string()),
        ("skew_ms", st.skew_ms.to_string()),
    ]
}

fn notice_fields(ts: u64, n: &Notice) -> Vec<(&'static str, String)> {
    vec![
        ("ts", ts.to_string()),
        ("kind", view::notice_word(n.kind).to_owned()),
        ("path", n.path.as_str().to_owned()),
    ]
}

// line format: `kind key=value ...`, values percent-escaped so every record is one whitespace-split line
pub fn report(s: &UiSnapshot) -> String {
    let mut out = String::with_capacity(1024);
    rec(&mut out, "session", &session_fields(s));
    for p in &s.peers {
        rec(&mut out, "peer", &peer_fields(p, s));
    }
    if let Some(p) = &s.pairing {
        rec(&mut out, "pairing", &pairing_fields(p));
    }
    for (i, h) in s.hosts.iter().enumerate() {
        rec(&mut out, "host", &host_fields(i, h));
    }
    rec(&mut out, "stats", &stats_fields(&s.stats));
    if s.role == Role::Guest {
        let g = &s.guest;
        rec(
            &mut out,
            "guest",
            &[
                ("hits", g.hits.to_string()),
                ("misses", g.misses.to_string()),
                ("inflight", g.inflight.to_string()),
                ("prefetch_done", g.prefetch_done.to_string()),
                ("prefetch_total", g.prefetch_total.to_string()),
                ("passthrough", g.passthrough.to_string()),
            ],
        );
    }
    let skip = s.notices.len().saturating_sub(REPORT_NOTICES);
    for (ts, n) in s.notices.iter().skip(skip) {
        rec(&mut out, "notice", &notice_fields(*ts, n));
    }
    for h in &s.hints {
        rec(&mut out, "hint", &[("text", (*h).to_owned())]);
    }
    out
}

const LIST_KINDS: [&str; 5] = ["peer", "host", "notice", "hint", "found"];
const NUM_KEYS: [&str; 27] = [
    "id",
    "pid",
    "rtt_us",
    "tx",
    "rx",
    "pending",
    "files",
    "cached_bytes",
    "cache_cap",
    "fetches",
    "commits",
    "merged",
    "refused",
    "inject_backlog",
    "skew_ms",
    "ts",
    "done",
    "total",
    "since_ms",
    "expires_ms",
    "hits",
    "misses",
    "inflight",
    "prefetch_done",
    "prefetch_total",
    "index",
    "peer",
];
const BOOL_KEYS: [&str; 3] = ["paired", "passthrough", "mounted"];

pub fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\u{7f}' || view::is_hidden_char(c) => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_val(out: &mut String, k: &str, v: &str) {
    let numeric = NUM_KEYS.contains(&k) && (v.parse::<u64>().is_ok() || v.parse::<i64>().is_ok());
    if numeric || (BOOL_KEYS.contains(&k) && (v == "true" || v == "false")) {
        out.push_str(v);
    } else {
        json_str(out, v);
    }
}

fn json_obj(out: &mut String, fields: &[(String, String)]) {
    out.push('{');
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_str(out, k);
        out.push(':');
        json_val(out, k, v);
    }
    out.push('}');
}

// converts a report into one json object: list kinds become arrays named with a trailing s
type Fields = Vec<(String, String)>;

pub fn report_json(text: &str) -> String {
    let mut singles: Vec<(String, Fields)> = Vec::new();
    let mut lists: Vec<(String, Vec<Fields>)> = Vec::new();
    for line in text.lines() {
        let mut it = line.split(' ');
        let Some(kind) = it.next().filter(|k| !k.is_empty()) else {
            continue;
        };
        let fields: Fields = it
            .filter_map(|t| t.split_once('='))
            .map(|(k, v)| (unescape(k), unescape(v)))
            .collect();
        if LIST_KINDS.contains(&kind) {
            let key = format!("{kind}s");
            match lists.iter_mut().find(|(k, _)| *k == key) {
                Some((_, v)) => v.push(fields),
                None => lists.push((key, vec![fields])),
            }
        } else {
            match singles.iter_mut().find(|(k, _)| k == kind) {
                Some((_, v)) => *v = fields,
                None => singles.push((kind.to_owned(), fields)),
            }
        }
    }
    let mut out = String::with_capacity(text.len() + 64);
    out.push('{');
    let mut first = true;
    for (k, f) in &singles {
        if !first {
            out.push(',');
        }
        first = false;
        json_str(&mut out, k);
        out.push(':');
        json_obj(&mut out, f);
    }
    for (k, items) in &lists {
        if !first {
            out.push(',');
        }
        first = false;
        json_str(&mut out, k);
        out.push_str(":[");
        for (i, f) in items.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_obj(&mut out, f);
        }
        out.push(']');
    }
    out.push('}');
    out
}

#[derive(Default)]
struct Emitter {
    session: Vec<(&'static str, String)>,
    peers: Vec<(u64, String)>,
    pairing: Option<u64>,
    hosts: Vec<String>,
    last_notice: Option<(u64, Notice)>,
    stats: Option<(u64, u64, u64, u64)>,
    hints: Vec<&'static str>,
    mounted: bool,
}

impl Emitter {
    fn emit(&mut self, s: &UiSnapshot, out: &mut String) {
        let session = session_fields(s);
        if session != self.session {
            rec(out, "session", &session);
            self.session = session;
        }
        if s.mounted != self.mounted {
            let path = s.mount.as_deref().map(path_str).unwrap_or_default();
            rec(
                out,
                if s.mounted { "mounted" } else { "unmounted" },
                &[("path", path)],
            );
            self.mounted = s.mounted;
        }
        let mut seen = Vec::with_capacity(s.peers.len());
        for p in &s.peers {
            let mut f = vec![
                ("id", p.id.to_string()),
                ("name", p.name.as_str().to_owned()),
                ("fpr", view::fpr_text(&p.fpr)),
            ];
            state_fields(&p.state, &mut f);
            let mut key = String::new();
            rec(&mut key, "peer", &f);
            if !self.peers.iter().any(|(id, k)| *id == p.id && *k == key) {
                out.push_str(&key);
            }
            seen.push((p.id, key));
        }
        for (id, _) in self
            .peers
            .iter()
            .filter(|(id, _)| !seen.iter().any(|(x, _)| x == id))
        {
            rec(
                out,
                "peer",
                &[("id", id.to_string()), ("state", "gone".into())],
            );
        }
        self.peers = seen;
        let pairing = s.pairing.as_ref().map(|p| p.peer);
        if pairing != self.pairing {
            match &s.pairing {
                Some(p) => {
                    let mut f = pairing_fields(p);
                    f.push((
                        "reply",
                        if s.role == Role::Host {
                            "accept|reject".into()
                        } else {
                            "confirm yes|no".into()
                        },
                    ));
                    rec(out, "pairing", &f);
                }
                None => rec(out, "pairing", &[("state", "closed".into())]),
            }
            self.pairing = pairing;
        }
        let mut hosts = Vec::with_capacity(s.hosts.len());
        for (i, h) in s.hosts.iter().enumerate() {
            let mut line = String::new();
            rec(&mut line, "found", &host_fields(i, h));
            if !self.hosts.contains(&line) {
                out.push_str(&line);
            }
            hosts.push(line);
        }
        self.hosts = hosts;
        let start = match &self.last_notice {
            Some(last) => s
                .notices
                .iter()
                .rposition(|x| x == last)
                .map_or(0, |i| i + 1),
            None => 0,
        };
        for (ts, n) in s.notices.iter().skip(start) {
            rec(out, "notice", &notice_fields(*ts, n));
        }
        if let Some(last) = s.notices.back() {
            self.last_notice = Some(last.clone());
        }
        let st = (
            s.stats.files,
            s.stats.commits,
            s.stats.merged,
            s.stats.refused,
        );
        if self.stats != Some(st) {
            rec(out, "stats", &stats_fields(&s.stats));
            self.stats = Some(st);
        }
        for h in &s.hints {
            if !self.hints.contains(h) {
                rec(out, "hint", &[("text", (*h).to_owned())]);
                self.hints.push(*h);
            }
        }
    }
}

enum Line {
    Ui(UiCmd),
    Status,
    Help,
}

const HELP: &str =
    "commands: accept [ID] | reject [ID] | confirm yes|no | join N | revoke ID | status | quit";

fn parse_line(line: &str, s: &UiSnapshot) -> Result<Option<Line>, String> {
    let mut it = line.split_whitespace();
    let Some(cmd) = it.next() else {
        return Ok(None);
    };
    let arg = it.next();
    let num = |what: &str| -> Result<u64, String> {
        arg.and_then(|a| a.parse::<u64>().ok())
            .ok_or_else(|| format!("{cmd} needs a numeric {what}"))
    };
    let pairing_peer = || -> Result<u64, String> {
        match arg {
            Some(_) => num("peer id"),
            None => s
                .pairing
                .as_ref()
                .map(|p| p.peer)
                .ok_or_else(|| "no pairing request is pending".to_owned()),
        }
    };
    let out = match cmd.to_ascii_lowercase().as_str() {
        "accept" => Line::Ui(UiCmd::Accept(pairing_peer()?)),
        "reject" => Line::Ui(UiCmd::Reject(pairing_peer()?)),
        "confirm" => match arg.map(str::to_ascii_lowercase).as_deref() {
            Some("yes" | "y") => Line::Ui(UiCmd::Confirm(true)),
            Some("no" | "n") => Line::Ui(UiCmd::Confirm(false)),
            _ => return Err("confirm needs yes or no".into()),
        },
        "yes" => Line::Ui(UiCmd::Confirm(true)),
        "no" => Line::Ui(UiCmd::Confirm(false)),
        "join" => {
            let n = usize::try_from(num("host index")?)
                .map_err(|_| "host index out of range".to_owned())?;
            if n >= s.hosts.len() {
                return Err(format!("no host with index {n}"));
            }
            Line::Ui(UiCmd::Join(n))
        }
        "revoke" => Line::Ui(UiCmd::Revoke(num("peer id")?)),
        "quit" | "exit" => Line::Ui(UiCmd::Quit),
        "status" => Line::Status,
        "help" => Line::Help,
        other => return Err(format!("unknown command '{other}'")),
    };
    Ok(Some(out))
}

fn print(out: &str) -> io::Result<()> {
    if out.is_empty() {
        return Ok(());
    }
    let mut o = io::stdout().lock();
    o.write_all(out.as_bytes())?;
    o.flush()
}

// line-oriented status on stdout and commands on stdin, for scripts, agents and ci
pub fn run_headless(
    bus: &UiBus,
    wake: &Receiver<()>,
    cmds: &Sender<UiCmd>,
    ends: &mut Ends<'_>,
) -> io::Result<()> {
    let done = ends.done;
    let signals = ends.signals;
    let mut sig_open = true;
    let (ltx, lrx) = bounded::<String>(16);
    thread::Builder::new()
        .name("csync-stdin".into())
        .spawn(move || {
            let stdin = io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                match stdin.lock().take(LINE_MAX).read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        if ltx.send(line.trim().to_owned()).is_err() {
                            return;
                        }
                    }
                }
            }
        })?;
    let mut lines_open = true;
    let mut em = Emitter::default();
    let mut out = String::with_capacity(4096);
    em.emit(&bus.read(), &mut out);
    print(&out)?;
    loop {
        out.clear();
        let lines = if lines_open { lrx.clone() } else { never() };
        let sigs = if sig_open { signals.clone() } else { never() };
        select! {
            recv(sigs) -> s => match s {
                Ok(sig) => {
                    let force = on_signal(sig, ends, cmds);
                    rec(&mut out, "signal", &[("number", sig.to_string()), ("action", if force { "exit" } else { "quit" }.into())]);
                    if force {
                        print(&out)?;
                        return Err(forced());
                    }
                }
                Err(_) => sig_open = false,
            },
            recv(wake) -> _ => em.emit(&bus.read(), &mut out),
            recv(lines) -> l => match l {
                Ok(l) => {
                    let snap = bus.read();
                    match parse_line(&l, &snap) {
                        Ok(None) => {}
                        Ok(Some(Line::Ui(c))) => {
                            if cmds.send_timeout(c, CMD_TIMEOUT).is_err() {
                                rec(&mut out, "error", &[("text", "the session is not accepting commands".into())]);
                            }
                        }
                        Ok(Some(Line::Status)) => out.push_str(&report(&snap)),
                        Ok(Some(Line::Help)) => rec(&mut out, "help", &[("text", HELP.into())]),
                        Err(e) => rec(&mut out, "error", &[("text", e)]),
                    }
                }
                Err(_) => lines_open = false,
            },
            recv(done) -> r => {
                em.emit(&bus.read(), &mut out);
                print(&out)?;
                return r.unwrap_or(Ok(()));
            }
        }
        print(&out)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{NoticeKind, RelPath};
    use ratatui::backend::TestBackend;

    fn sample() -> UiSnapshot {
        let mut s = UiSnapshot::new(Role::Host);
        s.project = Some(Name::new("my proj").unwrap());
        s.listen = Some("127.0.0.1:47480".parse().unwrap());
        s.peers.push(PeerView {
            id: 7,
            name: Name::new("vm=1 \x1b").unwrap(),
            fpr: [0x12; 8],
            state: ConnState::Live,
            rtt_us: 250,
        });
        s.peer_io(7).tx = 99;
        s.push_notice(
            1,
            Notice {
                kind: NoticeKind::Merged,
                path: RelPath::new("a b/c%d").unwrap(),
            },
        );
        s
    }

    #[test]
    fn report_lines_round_trip_through_escaping() {
        let text = report(&sample());
        for line in text.lines() {
            assert!(
                line.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "{line}"
            );
            for tok in line.split(' ').skip(1) {
                assert_eq!(tok.matches('=').count(), 1, "{tok}");
            }
        }
        assert!(text.contains("name=vm%3D1%20%1B"));
        assert!(text.contains("path=a%20b/c%25d"));
        assert_eq!(unescape("a%20b/c%25d%zz%"), "a b/c%d%zz%");
    }

    #[test]
    fn the_session_line_names_the_backend_and_how_changes_reach_the_kernel_last() {
        let mut s = UiSnapshot::new(Role::Guest);
        s.mount = Some(PathBuf::from("/m"));
        s.mounted = true;
        let bare = report(&s);
        let first = bare.lines().next().unwrap();
        assert!(first.starts_with("session role=guest") && !first.contains("backend="));
        s.guest.backend = "fskit";
        s.guest.inval = "injected";
        let text = report(&s);
        let line = text.lines().next().unwrap();
        assert!(
            line.ends_with(" mounted=true backend=fskit inval=injected"),
            "{line}"
        );
        let j = report_json(&text);
        assert!(j.contains("\"backend\":\"fskit\",\"inval\":\"injected\""));
    }

    #[test]
    fn report_json_types_and_escapes() {
        let j = report_json(&report(&sample()));
        assert!(j.starts_with("{\"session\":{\"role\":\"host\""));
        assert!(j.contains(
            "\"peers\":[{\"id\":7,\"name\":\"vm=1 \\u001b\",\"fpr\":\"1212121212121212\""
        ));
        assert!(j.contains("\"tx\":99"));
        assert!(j.contains("\"notices\":[{\"ts\":1,\"kind\":\"merged\",\"path\":\"a b/c%d\"}]"));
        assert!(j.ends_with('}'));
    }

    #[test]
    fn notices_are_capped_and_emitted_once() {
        let mut s = sample();
        for i in 0..(NOTICES_MAX as u64 + 5) {
            s.push_notice(
                i + 10,
                Notice {
                    kind: NoticeKind::Refused,
                    path: RelPath::new("x").unwrap(),
                },
            );
        }
        assert_eq!(s.notices.len(), NOTICES_MAX);
        let mut em = Emitter::default();
        let mut out = String::new();
        em.emit(&s, &mut out);
        assert_eq!(
            out.lines().filter(|l| l.starts_with("notice ")).count(),
            NOTICES_MAX
        );
        out.clear();
        em.emit(&s, &mut out);
        assert!(out.is_empty(), "{out}");
        s.push_notice(
            10_000,
            Notice {
                kind: NoticeKind::Merged,
                path: RelPath::new("y").unwrap(),
            },
        );
        s.peers[0].state = ConnState::Disconnected {
            since_ms: 3,
            reason: None,
        };
        em.emit(&s, &mut out);
        assert_eq!(out.lines().filter(|l| l.starts_with("notice ")).count(), 1);
        assert!(out.contains("state=disconnected since_ms=3"));
        assert!(!out.contains("reason="), "{out}");
    }

    #[test]
    fn a_disconnect_reason_is_reported_only_when_there_is_one() {
        let mut s = sample();
        s.peers[0].state = ConnState::Disconnected {
            since_ms: 3,
            reason: Some("host closed the connection".into()),
        };
        let text = report(&s);
        assert!(
            text.contains("state=disconnected since_ms=3 reason=host%20closed%20the%20connection"),
            "{text}"
        );
        let j = report_json(&text);
        assert!(
            j.contains("\"since_ms\":3,\"reason\":\"host closed the connection\""),
            "{j}"
        );
        s.peers[0].state = ConnState::Disconnected {
            since_ms: 3,
            reason: None,
        };
        assert!(!report(&s).contains("reason="));
    }

    // drives the screen the way the interactive loop does: render only when a deadline comes due
    fn run_until(
        sc: &mut Screen,
        term: &mut Terminal<TestBackend>,
        t0: Instant,
        until: Instant,
    ) -> u64 {
        let before = sc.redraws;
        while let Some(d) = sc.deadline().filter(|d| *d <= until) {
            let wall = 1_000_000 + d.saturating_duration_since(t0).as_millis() as u64;
            sc.render(term, d, wall).unwrap();
        }
        sc.redraws - before
    }

    #[test]
    fn steady_live_host_never_redraws_but_waiting_spins_at_10fps() {
        let t0 = Instant::now();
        let mut s = sample();
        s.notices.clear();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut sc = Screen::new(s, Depth::True, t0);
        sc.render(&mut term, t0, 1_000_000).unwrap();
        assert!(sc.vs.trans.is_some(), "the first frame dissolves in");
        let settle = run_until(&mut sc, &mut term, t0, t0 + Duration::from_secs(3));
        assert!(settle >= 10, "intro and pulse should animate, got {settle}");
        assert_eq!(sc.deadline(), None);
        let idle = run_until(&mut sc, &mut term, t0, t0 + Duration::from_secs(13));
        assert_eq!(idle, 0);
        sc.snap.peers.clear();
        let t1 = t0 + Duration::from_secs(13);
        sc.render(&mut term, t1, 1_013_000).unwrap();
        let spins = run_until(&mut sc, &mut term, t0, t1 + Duration::from_secs(10));
        assert!((95..=105).contains(&spins), "{spins}");
    }

    #[test]
    fn pairing_modal_dissolves_in_and_settles_on_the_plain_frame() {
        let t0 = Instant::now();
        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let mut sc = Screen::new(sample(), Depth::True, t0);
        sc.render(&mut term, t0, 1_000_000).unwrap();
        run_until(&mut sc, &mut term, t0, t0 + Duration::from_secs(3));
        let before = sc.shown.clone();
        sc.snap.pairing = Some(PairPrompt {
            peer: 7,
            name: Name::new("g").unwrap(),
            sas: *b"ABCDEFGH",
            expires_ms: 1_100_000,
        });
        let t1 = t0 + Duration::from_secs(4);
        sc.render(&mut term, t1, 1_004_000).unwrap();
        assert_eq!(sc.shown, before, "t=0 of the dissolve is the old frame");
        let mid = t1 + anim::TRANSITION / 2;
        sc.render(&mut term, mid, 1_004_180).unwrap();
        let shaded = sc
            .shown
            .content
            .iter()
            .filter(|c| matches!(c.symbol(), "▒" | "░"))
            .count();
        assert!(shaded > 20, "{shaded}");
        assert_ne!(sc.shown, before);
        let end = t1 + anim::TRANSITION + Duration::from_millis(1);
        sc.render(&mut term, end, 1_004_400).unwrap();
        assert_eq!(sc.vs.trans, None);
        let mut plain = Terminal::new(TestBackend::new(100, 30)).unwrap();
        plain
            .draw(|f| {
                view::draw(f, &sc.snap, &sc.vs);
            })
            .unwrap();
        assert_eq!(&sc.shown, plain.backend().buffer());
        assert!(
            sc.deadline().is_some(),
            "the pairing countdown keeps ticking"
        );
    }

    #[test]
    fn headless_commands_parse_and_validate() {
        let mut s = sample();
        assert!(parse_line("accept", &s).is_err());
        s.pairing = Some(PairPrompt {
            peer: 4,
            name: Name::new("g").unwrap(),
            sas: *b"ABCDEFGH",
            expires_ms: 0,
        });
        assert!(matches!(
            parse_line("accept", &s),
            Ok(Some(Line::Ui(UiCmd::Accept(4))))
        ));
        assert!(matches!(
            parse_line("reject 9", &s),
            Ok(Some(Line::Ui(UiCmd::Reject(9))))
        ));
        assert!(matches!(
            parse_line("confirm yes", &s),
            Ok(Some(Line::Ui(UiCmd::Confirm(true))))
        ));
        assert!(parse_line("join 0", &s).is_err());
        assert!(parse_line("revoke x", &s).is_err());
        assert!(parse_line("frobnicate", &s).is_err());
        assert!(matches!(parse_line("   ", &s), Ok(None)));
    }

    fn key(code: KeyCode, kind: KeyEventKind) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, kind)
    }

    fn pairing(peer: u64) -> PairPrompt {
        PairPrompt {
            peer,
            name: Name::new("g").unwrap(),
            sas: *b"ABCDEFGH",
            expires_ms: 0,
        }
    }

    #[test]
    fn repeated_keys_never_answer_a_prompt_or_quit() {
        let mut s = sample();
        s.pairing = Some(pairing(7));
        let mut vs = ViewState::new(Depth::True, Instant::now());
        let a = KeyCode::Char('a');
        assert!(matches!(
            on_key(key(a, KeyEventKind::Repeat), &s, &mut vs),
            Action::None
        ));
        assert!(matches!(
            on_key(key(a, KeyEventKind::Press), &s, &mut vs),
            Action::Cmd(UiCmd::Accept(7))
        ));
        let q = KeyCode::Char('q');
        assert!(matches!(
            on_key(key(q, KeyEventKind::Repeat), &s, &mut vs),
            Action::None
        ));
        assert!(matches!(
            on_key(key(q, KeyEventKind::Press), &s, &mut vs),
            Action::Quit
        ));
        let ctrl_c =
            |kind| KeyEvent::new_with_kind(KeyCode::Char('c'), KeyModifiers::CONTROL, kind);
        assert!(matches!(
            on_key(ctrl_c(KeyEventKind::Repeat), &s, &mut vs),
            Action::None
        ));
        assert!(matches!(
            on_key(ctrl_c(KeyEventKind::Press), &s, &mut vs),
            Action::Quit
        ));
        assert!(matches!(
            on_key(key(KeyCode::Down, KeyEventKind::Repeat), &s, &mut vs),
            Action::Redraw
        ));
    }

    #[test]
    fn a_repeated_key_leaves_a_pending_revoke_unanswered() {
        let s = sample();
        let mut vs = ViewState::new(Depth::True, Instant::now());
        vs.confirm_revoke = Some(7);
        let y = KeyCode::Char('y');
        assert!(matches!(
            on_key(key(y, KeyEventKind::Repeat), &s, &mut vs),
            Action::None
        ));
        assert_eq!(vs.confirm_revoke, Some(7));
        assert!(matches!(
            on_key(key(y, KeyEventKind::Press), &s, &mut vs),
            Action::Cmd(UiCmd::Revoke(7))
        ));
        assert_eq!(vs.confirm_revoke, None);
    }

    #[test]
    fn guest_confirmation_ignores_repeats() {
        let mut s = UiSnapshot::new(Role::Guest);
        s.pairing = Some(pairing(3));
        let mut vs = ViewState::new(Depth::True, Instant::now());
        let y = KeyCode::Char('y');
        assert!(matches!(
            on_key(key(y, KeyEventKind::Repeat), &s, &mut vs),
            Action::None
        ));
        assert!(matches!(
            on_key(key(y, KeyEventKind::Press), &s, &mut vs),
            Action::Cmd(UiCmd::Confirm(true))
        ));
    }

    #[test]
    fn unfocused_redraws_are_slow_unless_a_prompt_is_waiting() {
        assert_eq!(frame_gap(true, false), FRAME_MIN);
        assert_eq!(frame_gap(false, false), UNFOCUSED_FRAME);
        assert_eq!(frame_gap(false, true), FRAME_MIN);
        assert!(UNFOCUSED_FRAME > FRAME_MIN);
    }

    #[test]
    fn a_prompt_is_noticed_only_when_it_first_appears() {
        let quiet = sample();
        let mut asking = sample();
        asking.pairing = Some(pairing(7));
        assert!(prompt_appeared(&quiet, &asking));
        assert!(!prompt_appeared(&asking, &asking));
        assert!(!prompt_appeared(&asking, &quiet));
        assert!(!prompt_appeared(&quiet, &quiet));
        let mut guest = UiSnapshot::new(Role::Guest);
        let mut waiting = guest.clone();
        waiting.peers.push(PeerView {
            id: 1,
            name: Name::new("h").unwrap(),
            fpr: [1; 8],
            state: ConnState::Pairing { sas: *b"Z9Y8X7W6" },
            rtt_us: 0,
        });
        assert!(prompt_appeared(&guest, &waiting));
        guest.pairing = Some(pairing(1));
        assert!(!prompt_appeared(&guest, &waiting));
    }

    fn press(code: KeyCode) -> KeyEvent {
        key(code, KeyEventKind::Press)
    }

    fn feed_entry(id: u64) -> Entry {
        Entry {
            id,
            ts_ms: id,
            what: feed::What::Modified,
            by: feed::By::Host,
            path: RelPath::new(&format!("f{id}")).unwrap(),
            from: None,
            size: 0,
            old: None,
            new: None,
            ver: 0,
            merged: false,
        }
    }

    // a host showing ids 20 down to 11 of a ring of 20, drawn at x 2..62 from y 5
    fn feed_vs() -> ViewState {
        let mut vs = ViewState::new(Depth::True, Instant::now());
        vs.scene = view::Scene::Host;
        vs.feed.on = true;
        let rows: Vec<Entry> = (11..=20).rev().map(feed_entry).collect();
        let ids = rows.iter().map(|e| e.id).collect();
        vs.feed.set_rows(rows, 20, 10, 1);
        vs.feed.hits = Hits {
            rows: Rect::new(2, 5, 60, 10),
            ids,
            diff: None,
        };
        vs
    }

    fn live_guest() -> UiSnapshot {
        let mut s = UiSnapshot::new(Role::Guest);
        s.host_addr = Some("10.0.0.2:47480".parse().unwrap());
        s.mounted = true;
        s.peers.push(PeerView {
            id: 9,
            name: Name::new("h").unwrap(),
            fpr: [1; 8],
            state: ConnState::Live,
            rtt_us: 100,
        });
        s
    }

    fn text_lines(n: usize) -> DiffView {
        DiffView {
            label: "this change",
            added: 0,
            removed: 0,
            lines: (0..n)
                .map(|i| diff::DiffLine {
                    kind: diff::Kind::Context,
                    text: format!("line {i}"),
                })
                .collect(),
            cut: None,
            unavailable: None,
            detail: None,
        }
    }

    fn with_open_diff(vs: &mut ViewState, lines: usize) {
        vs.feed.diff = Some(view::OpenDiff {
            req: 1,
            entry: feed_entry(20),
            body: view::DiffBody::Ready(text_lines(lines)),
            scroll: 0,
        });
        vs.feed.hits.diff = Some(Rect::new(0, 0, 40, 4));
    }

    fn scroll_of(vs: &ViewState) -> usize {
        vs.feed.diff.as_ref().map_or(usize::MAX, |d| d.scroll)
    }

    #[test]
    fn tab_moves_the_host_focus_and_the_arrows_follow_it() {
        let s = sample();
        let mut vs = feed_vs();
        assert!(matches!(
            on_key(press(KeyCode::Down), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.feed.anchor, None, "the guests list has the focus");
        assert!(matches!(
            on_key(press(KeyCode::Tab), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.feed.focus, Focus::Activity);
        for (code, want) in [
            (KeyCode::Down, 20),
            (KeyCode::Down, 19),
            (KeyCode::Char('j'), 18),
            (KeyCode::Up, 19),
            (KeyCode::Char('k'), 20),
        ] {
            assert!(matches!(on_key(press(code), &s, &mut vs), Action::Redraw));
            assert_eq!(vs.feed.anchor, Some(want), "{code:?}");
        }
        assert!(!vs.feed.follow);
        assert!(matches!(
            on_key(press(KeyCode::Tab), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.feed.focus, Focus::Guests);
        assert_eq!(vs.feed.anchor, Some(20), "tabbing away keeps the selection");
    }

    #[test]
    fn escape_clears_the_selection_and_gives_the_focus_back() {
        let s = sample();
        let mut vs = feed_vs();
        assert!(matches!(
            on_key(press(KeyCode::Esc), &s, &mut vs),
            Action::None
        ));
        on_key(press(KeyCode::Tab), &s, &mut vs);
        on_key(press(KeyCode::Down), &s, &mut vs);
        assert!(vs.feed.anchor.is_some());
        assert!(matches!(
            on_key(press(KeyCode::Esc), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.feed.anchor, None);
        assert_eq!(vs.feed.focus, Focus::Guests);
        assert!(vs.feed.follow);
    }

    #[test]
    fn end_resumes_following_and_home_goes_to_the_oldest_row() {
        let s = sample();
        let mut vs = feed_vs();
        on_key(press(KeyCode::Tab), &s, &mut vs);
        on_key(press(KeyCode::Down), &s, &mut vs);
        on_key(press(KeyCode::Down), &s, &mut vs);
        assert_eq!((vs.feed.anchor, vs.feed.follow), (Some(19), false));
        assert!(matches!(
            on_key(press(KeyCode::Home), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.feed.anchor, Some(1));
        assert!(matches!(
            on_key(press(KeyCode::End), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(
            (vs.feed.anchor, vs.feed.view, vs.feed.follow),
            (None, None, true)
        );
        assert_eq!(vs.feed.focus, Focus::Activity, "end keeps the focus");
    }

    #[test]
    fn page_keys_move_by_the_rows_on_screen() {
        let s = sample();
        let mut vs = feed_vs();
        on_key(press(KeyCode::Tab), &s, &mut vs);
        on_key(press(KeyCode::Down), &s, &mut vs);
        on_key(press(KeyCode::PageDown), &s, &mut vs);
        assert_eq!(vs.feed.anchor, Some(11));
        on_key(press(KeyCode::PageUp), &s, &mut vs);
        assert_eq!(vs.feed.anchor, Some(20));
    }

    #[test]
    fn enter_opens_the_selected_row_and_shows_it_loading() {
        let s = sample();
        let mut vs = feed_vs();
        on_key(press(KeyCode::Tab), &s, &mut vs);
        assert!(matches!(
            on_key(press(KeyCode::Enter), &s, &mut vs),
            Action::None
        ));
        assert!(vs.feed.diff.is_none(), "nothing is selected");
        on_key(press(KeyCode::Down), &s, &mut vs);
        assert!(matches!(
            on_key(key(KeyCode::Enter, KeyEventKind::Repeat), &s, &mut vs),
            Action::None
        ));
        assert!(vs.feed.diff.is_none(), "a held key does not open");
        let act = on_key(press(KeyCode::Enter), &s, &mut vs);
        assert!(matches!(act, Action::Open(ref e) if e.id == 20));
        let d = vs.feed.diff.as_ref().expect("the diff is open");
        assert_eq!((d.req, d.entry.id), (1, 20));
        assert!(matches!(d.body, view::DiffBody::Loading));
    }

    #[test]
    fn an_open_diff_scrolls_closes_and_still_quits() {
        let s = sample();
        let mut vs = feed_vs();
        with_open_diff(&mut vs, 12);
        for (code, want) in [
            (KeyCode::Down, 1),
            (KeyCode::PageDown, 5),
            (KeyCode::Char(' '), 8),
            (KeyCode::Up, 7),
            (KeyCode::Char('k'), 6),
            (KeyCode::PageUp, 2),
            (KeyCode::End, 8),
            (KeyCode::Home, 0),
        ] {
            assert!(matches!(on_key(press(code), &s, &mut vs), Action::Redraw));
            assert_eq!(scroll_of(&vs), want, "{code:?}");
        }
        assert!(matches!(
            on_key(key(KeyCode::Esc, KeyEventKind::Repeat), &s, &mut vs),
            Action::None
        ));
        assert!(vs.feed.diff.is_some());
        assert!(matches!(
            on_key(press(KeyCode::Char('q')), &s, &mut vs),
            Action::Quit
        ));
        assert!(matches!(
            on_key(press(KeyCode::Esc), &s, &mut vs),
            Action::Redraw
        ));
        assert!(vs.feed.diff.is_none());
    }

    #[test]
    fn a_guest_uses_the_arrows_for_the_feed_without_tab() {
        let s = live_guest();
        let mut vs = feed_vs();
        assert!(view::feed_live(&s, &vs));
        assert!(matches!(
            on_key(press(KeyCode::Tab), &s, &mut vs),
            Action::None
        ));
        assert!(matches!(
            on_key(press(KeyCode::Down), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.feed.anchor, Some(20));
        assert!(matches!(
            on_key(press(KeyCode::Esc), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.feed.anchor, None);
    }

    #[test]
    fn peer_and_pairing_keys_are_untouched_while_the_feed_has_the_focus() {
        let mut s = sample();
        let mut vs = feed_vs();
        on_key(press(KeyCode::Tab), &s, &mut vs);
        assert!(matches!(
            on_key(press(KeyCode::Char('x')), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.confirm_revoke, Some(7));
        vs.confirm_revoke = None;
        s.pairing = Some(pairing(7));
        assert!(!view::feed_live(&s, &vs));
        assert!(matches!(
            on_key(press(KeyCode::Char('a')), &s, &mut vs),
            Action::Cmd(UiCmd::Accept(7))
        ));
        assert!(matches!(
            on_key(press(KeyCode::Down), &s, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.feed.anchor, None, "a pairing request takes the arrows");
    }

    #[test]
    fn the_feed_ignores_keys_while_it_is_off() {
        let s = sample();
        let mut vs = feed_vs();
        vs.feed.on = false;
        on_key(press(KeyCode::Tab), &s, &mut vs);
        assert_eq!(vs.feed.focus, Focus::Guests);
        on_key(press(KeyCode::Down), &s, &mut vs);
        assert_eq!(vs.feed.anchor, None);
    }

    fn click(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn left(column: u16, row: u16) -> MouseEvent {
        click(MouseEventKind::Down(MouseButton::Left), column, row)
    }

    #[test]
    fn a_click_selects_a_row_and_a_second_click_on_it_opens_it() {
        let mut vs = feed_vs();
        let hits = vs.feed.hits.clone();
        assert!(matches!(
            on_mouse(left(10, 7), &hits, &mut vs),
            Action::Redraw
        ));
        assert_eq!(vs.feed.anchor, Some(18));
        assert_eq!(vs.feed.focus, Focus::Activity);
        assert!(vs.feed.diff.is_none());
        assert!(matches!(on_mouse(left(61, 7), &hits, &mut vs), Action::Open(ref e) if e.id == 18));
        assert!(vs.feed.diff.is_some());
    }

    #[test]
    fn clicks_off_the_rows_and_other_mouse_events_change_nothing() {
        let mut vs = feed_vs();
        let hits = vs.feed.hits.clone();
        for ev in [
            left(10, 4),
            left(10, 15),
            left(1, 7),
            left(62, 7),
            click(MouseEventKind::Down(MouseButton::Right), 10, 7),
            click(MouseEventKind::Up(MouseButton::Left), 10, 7),
            click(MouseEventKind::Drag(MouseButton::Left), 10, 7),
            click(MouseEventKind::Moved, 10, 7),
            click(MouseEventKind::ScrollLeft, 10, 7),
        ] {
            assert!(
                matches!(on_mouse(ev, &hits, &mut vs), Action::None),
                "{ev:?}"
            );
        }
        assert_eq!(vs.feed.anchor, None);
        assert_eq!(vs.feed.focus, Focus::Guests);
        assert!(vs.feed.follow);
    }

    #[test]
    fn the_wheel_scrolls_the_feed_and_then_the_diff() {
        let mut vs = feed_vs();
        let hits = vs.feed.hits.clone();
        let down = click(MouseEventKind::ScrollDown, 10, 7);
        let up = click(MouseEventKind::ScrollUp, 10, 7);
        assert!(matches!(on_mouse(down, &hits, &mut vs), Action::Redraw));
        assert_eq!((vs.feed.view, vs.feed.follow), (Some(8), false));
        assert!(matches!(on_mouse(up, &hits, &mut vs), Action::Redraw));
        assert_eq!(vs.feed.view, Some(11));
        with_open_diff(&mut vs, 12);
        on_mouse(down, &hits, &mut vs);
        assert_eq!(scroll_of(&vs), 3);
        on_mouse(up, &hits, &mut vs);
        assert_eq!(scroll_of(&vs), 0);
        assert_eq!(vs.feed.view, Some(11), "the feed stays put behind the diff");
    }

    #[test]
    fn the_mouse_is_ignored_where_capture_is_off_and_while_a_diff_is_open() {
        let mut vs = feed_vs();
        let hits = vs.feed.hits.clone();
        vs.scene = view::Scene::HostPair(1);
        assert!(matches!(
            on_mouse(left(10, 7), &hits, &mut vs),
            Action::None
        ));
        vs.scene = view::Scene::Host;
        vs.quitting = true;
        assert!(matches!(
            on_mouse(left(10, 7), &hits, &mut vs),
            Action::None
        ));
        vs.quitting = false;
        with_open_diff(&mut vs, 3);
        assert!(matches!(
            on_mouse(left(10, 7), &hits, &mut vs),
            Action::None
        ));
        assert_eq!(vs.feed.anchor, None);
    }

    #[test]
    fn capture_is_wanted_only_where_the_panel_can_be_clicked() {
        let mut vs = feed_vs();
        for (scene, want) in [
            (view::Scene::Host, true),
            (view::Scene::GuestLive, true),
            (view::Scene::Diff, true),
            (view::Scene::HostPair(1), false),
            (view::Scene::HostRevoke(1), false),
            (view::Scene::GuestPick, false),
            (view::Scene::GuestSetup, false),
            (view::Scene::GuestPrompt, false),
            (view::Scene::Tiny, false),
            (view::Scene::Blank, false),
        ] {
            vs.scene = scene;
            assert_eq!(view::wants_mouse(&vs), want, "{scene:?}");
        }
        vs.scene = view::Scene::Host;
        vs.quitting = true;
        assert!(!view::wants_mouse(&vs));
        vs.quitting = false;
        vs.feed.on = false;
        assert!(!view::wants_mouse(&vs));
    }

    #[test]
    fn the_mouse_command_asks_for_presses_and_the_wheel_but_never_motion() {
        let mut on = String::new();
        MouseMode(true).write_ansi(&mut on).unwrap();
        assert_eq!(on, "\x1b[?1000h\x1b[?1006h");
        let mut off = String::new();
        MouseMode(false).write_ansi(&mut off).unwrap();
        assert_eq!(off, "\x1b[?1000l\x1b[?1006l");
        for motion in ["1002", "1003"] {
            assert!(!on.contains(motion));
        }
    }

    #[test]
    fn mouse_off_is_idempotent_and_clears_the_flag() {
        MOUSE_REPORTING.store(false, Ordering::SeqCst);
        mouse_off();
        assert!(!MOUSE_REPORTING.load(Ordering::SeqCst));
        MOUSE_REPORTING.store(true, Ordering::SeqCst);
        mouse_off();
        assert!(!MOUSE_REPORTING.load(Ordering::SeqCst));
        mouse_off();
        assert!(!MOUSE_REPORTING.load(Ordering::SeqCst));
        let mut on = false;
        mouse_follow(&mut on, false);
        assert!(!on);
    }

    #[test]
    fn a_stale_diff_result_is_dropped_and_the_current_one_shown() {
        let slot = FeedSlot::default();
        let mut vs = feed_vs();
        let mut w = DiffWorker::new();
        vs.feed.select(18);
        assert!(vs.feed.open().is_some());
        let first = vs.feed.req;
        vs.feed.close_diff();
        vs.feed.select(17);
        assert!(vs.feed.open().is_some());
        let second = vs.feed.req;
        w.busy = true;
        assert!(!w.finish(&mut vs, &slot, first, failed_view("old")));
        assert!(!w.busy, "the worker is free again");
        assert!(matches!(
            vs.feed.diff.as_ref().unwrap().body,
            view::DiffBody::Loading
        ));
        w.busy = true;
        assert!(w.finish(&mut vs, &slot, second, failed_view("new")));
        assert!(matches!(
            vs.feed.diff.as_ref().unwrap().body,
            view::DiffBody::Ready(_)
        ));
    }

    #[test]
    fn a_waiting_open_runs_after_the_busy_one_and_a_superseded_one_does_not() {
        let slot = FeedSlot::default();
        let mut vs = feed_vs();
        vs.feed.select(18);
        vs.feed.open();
        let live = vs.feed.req;
        let mut w = DiffWorker::new();
        w.start(live - 1, feed_entry(19), &slot);
        assert!(w.busy);
        w.start(live, feed_entry(18), &slot);
        assert_eq!(w.queued.as_ref().map(|q| q.0), Some(live));
        let (req, _) =
            w.rx.recv_timeout(Duration::from_secs(5))
                .expect("first result");
        assert_eq!(req, live - 1);
        assert!(!w.finish(&mut vs, &slot, req, failed_view("x")));
        assert!(w.busy, "the waiting open started");
        let (req, view) =
            w.rx.recv_timeout(Duration::from_secs(5))
                .expect("second result");
        assert_eq!(req, live);
        assert_eq!(
            view.unavailable.as_deref(),
            Some("no earlier version is kept for this session")
        );
        assert!(w.finish(&mut vs, &slot, req, view));

        w.queued = Some((live + 5, feed_entry(1)));
        w.busy = true;
        w.finish(&mut vs, &slot, 0, failed_view("x"));
        assert!(
            !w.busy && w.queued.is_none(),
            "a waiting open nobody wants is dropped"
        );
    }

    struct Swap;

    impl DiffSource for Swap {
        fn sides(&self, _: &Entry) -> diff::Sides {
            diff::Sides {
                label: "swap",
                old: diff::Side::Bytes(b"a\n".to_vec()),
                new: diff::Side::Bytes(b"b\n".to_vec()),
                note: None,
            }
        }
    }

    struct Boom;

    impl DiffSource for Boom {
        fn sides(&self, _: &Entry) -> diff::Sides {
            panic!("a source that fails")
        }
    }

    #[test]
    fn the_diff_comes_from_the_registered_source_and_survives_a_failing_one() {
        let e = feed_entry(1);
        let src: &dyn DiffSource = &Swap;
        let v = compute_diff(Some(src), &e);
        assert_eq!((v.label, v.added, v.removed), ("swap", 1, 1));
        assert!(v.unavailable.is_none());
        let src: &dyn DiffSource = &Boom;
        let v = compute_diff(Some(src), &e);
        assert_eq!(
            v.unavailable.as_deref(),
            Some("the diff could not be computed")
        );
        assert!(compute_diff(None, &e).unavailable.is_some());
    }

    fn mirrored(bus: &UiBus) -> Vec<Entry> {
        bus.feed().window(None, 10)
    }

    #[test]
    fn a_notice_reaches_the_snapshot_always_and_the_feed_once_it_is_on() {
        let n = |kind| Notice {
            kind,
            path: RelPath::new("a/b").unwrap(),
        };
        let (bus, wake) = UiBus::new(Role::Guest);
        let v0 = bus.ver.load(Ordering::Acquire);
        bus.notice(5, n(NoticeKind::Refused));
        assert_eq!(bus.read().notices.len(), 1);
        assert!(mirrored(&bus).is_empty(), "the feed is off");
        assert!(bus.ver.load(Ordering::Acquire) > v0);
        assert!(wake.try_recv().is_ok());

        bus.feed().enable();
        bus.notice(6, n(NoticeKind::Merged));
        assert_eq!(bus.read().notices.len(), 2);
        let rows = mirrored(&bus);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].what, feed::What::Notice(NoticeKind::Merged));
        assert_eq!(rows[0].by, feed::By::Local);
        assert_eq!(rows[0].path.as_str(), "a/b");
        assert_eq!(rows[0].ts_ms, 6);

        let (host, _) = UiBus::new(Role::Host);
        host.feed().enable();
        host.notice(1, n(NoticeKind::Resynced));
        assert_eq!(mirrored(&host)[0].by, feed::By::Host);
    }

    #[test]
    fn every_update_bumps_the_version_even_when_nothing_changes() {
        let (bus, _wake) = UiBus::new(Role::Host);
        let v0 = bus.ver.load(Ordering::Acquire);
        bus.update(|_| {});
        bus.update(|s| s.hint("h"));
        assert_eq!(bus.ver.load(Ordering::Acquire), v0 + 2);
    }

    #[test]
    fn the_screen_copies_only_the_rows_the_panel_shows() {
        let t0 = Instant::now();
        let (bus, _wake) = UiBus::new(Role::Host);
        bus.feed().enable();
        for i in 1..=100 {
            bus.feed().push_batch([feed_entry(i)]);
        }
        let mut sc = Screen::new(sample(), Depth::True, t0);
        sc.vs.feed.on = true;
        let area = Rect::new(0, 0, 80, 24);
        sc.sync_feed(bus.feed(), area);
        let want = view::feed_rows(&sc.snap, &sc.vs, area);
        assert!(want > 0 && want < 100, "{want}");
        assert_eq!(sc.vs.feed.rows.len(), want);
        assert_eq!(sc.vs.feed.len, 100);
        assert_eq!(sc.vs.feed.rows[0].id, 100);
        assert!(!sc.vs.feed.needs(want, bus.feed().version()));
        bus.feed().push_batch([feed_entry(101)]);
        assert!(sc.vs.feed.needs(want, bus.feed().version()));

        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        sc.sync_feed(bus.feed(), area);
        sc.render(&mut term, t0, 1_000_000).unwrap();
        assert_eq!(sc.vs.feed.hits.ids.len(), want);
        assert_eq!(sc.vs.feed.hits.ids[0], 101);
        assert_eq!(sc.vs.scene, view::Scene::Host);
    }
}
