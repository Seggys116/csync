use super::anim::{
    self, FRAME, Hist, IDLE_AFTER, NOTICE_FADE_MS, PULSE, SAMPLE, SPIN, SPIN_IDLE, SPINNER, Tween,
    breathe, next_spin, progress, spin_index,
};
use super::theme::{self, Depth, Rgb, Theme};
use super::widgets::{
    self, BIG_ROWS, Fill, big_text, big_width, gradient, mid_trunc, put, put_right, str_width,
};
use super::{ConnState, PeerView, UiSnapshot};
use crate::proto::{NoticeKind, hs::Role};
use ratatui::{
    Frame,
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, Padding},
};
use std::time::{Duration, Instant};

const NAME_COLS: usize = 40;
const PATH_COLS: usize = 200;
const TINY_W: u16 = 36;
const TINY_H: u16 = 8;
const COMPACT_H: u16 = 20;
const PAIR_WINDOW_MS: u64 = 120_000;

pub fn is_hidden_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}')
}

// every peer-supplied string goes through here before it reaches the terminal
pub fn clean(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max * 4));
    for (n, c) in s.chars().filter(|&c| !is_hidden_char(c)).enumerate() {
        if n == max {
            out.pop();
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

pub fn sas_text(sas: &[u8; 8]) -> String {
    let mut s = String::with_capacity(9);
    for (i, &b) in sas.iter().enumerate() {
        if i == 4 {
            s.push('-');
        }
        s.push(if b.is_ascii_alphanumeric() {
            b as char
        } else {
            '?'
        });
    }
    s
}

pub fn fpr_text(fpr: &[u8; 8]) -> String {
    crate::crypto::trust::hex(fpr)
}

pub fn fmt_count(n: u64) -> String {
    let d = n.to_string();
    let mut out = String::with_capacity(d.len() + d.len() / 3);
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn fmt_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < U.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else if v < 10.0 {
        format!("{v:.1} {}", U[i])
    } else {
        format!("{v:.0} {}", U[i])
    }
}

pub fn fmt_rate(bps: f64) -> String {
    if bps < 1.0 {
        "-".into()
    } else {
        format!("{}/s", fmt_bytes(bps as u64))
    }
}

pub fn fmt_rtt(us: u32) -> String {
    match us {
        0 => "-".into(),
        1..=9_999 => format!("{:.1} ms", f64::from(us) / 1000.0),
        _ => format!("{} ms", us / 1000),
    }
}

pub fn fmt_secs(s: u64) -> String {
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m{:02}s", s / 60, s % 60),
        _ => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
    }
}

pub fn fmt_utc(ms: u64) -> String {
    let s = ms / 1000;
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

pub fn state_text(st: &ConnState, now_ms: u64) -> String {
    match st {
        ConnState::Waiting => "waiting".into(),
        ConnState::Discovering => "discovering".into(),
        ConnState::Handshaking => "handshaking".into(),
        ConnState::Pairing { .. } => "pairing".into(),
        ConnState::Syncing { done, total } if *total > 0 => {
            format!("syncing {}%", done.saturating_mul(100) / total)
        }
        ConnState::Syncing { .. } => "syncing".into(),
        ConnState::Live => "live".into(),
        ConnState::Disconnected { since_ms } => format!(
            "offline {}",
            fmt_secs(now_ms.saturating_sub(*since_ms) / 1000)
        ),
    }
}

pub fn notice_word(k: NoticeKind) -> &'static str {
    match k {
        NoticeKind::Refused => "refused",
        NoticeKind::Merged => "merged",
        NoticeKind::Promoted => "promoted",
        NoticeKind::Discarded => "discarded",
        NoticeKind::Resynced => "resynced",
        NoticeKind::IgnoreChanged => "rules",
    }
}

fn notice_rgb(k: NoticeKind) -> Rgb {
    match k {
        NoticeKind::Refused => theme::ERR,
        NoticeKind::Discarded => theme::WARN,
        NoticeKind::Merged => theme::VIOLET,
        NoticeKind::Promoted => theme::OK,
        NoticeKind::Resynced => theme::INFO,
        NoticeKind::IgnoreChanged => theme::TEAL,
    }
}

fn ratio(done: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    }
}

// byte counters sampled once a second while traffic flows, idle otherwise
#[derive(Default)]
pub struct Flow {
    at: Option<Instant>,
    tx: u64,
    rx: u64,
    seen: (u64, u64),
    pub tx_hist: Hist,
    pub rx_hist: Hist,
    pub sum: Hist,
}

impl Flow {
    fn busy(&self) -> bool {
        self.sum.any() || self.seen != (self.tx, self.rx)
    }

    fn observe(&mut self, now: Instant, tx: u64, rx: u64) {
        self.seen = (tx, rx);
        let Some(at) = self.at else {
            (self.at, self.tx, self.rx) = (Some(now), tx, rx);
            return;
        };
        if tx < self.tx || rx < self.rx {
            *self = Self::default();
            (self.at, self.tx, self.rx, self.seen) = (Some(now), tx, rx, (tx, rx));
            return;
        }
        if !self.busy() {
            self.at = Some(now);
            return;
        }
        let dt = now.saturating_duration_since(at);
        if dt < SAMPLE {
            return;
        }
        // after an idle stretch the bytes arrived just now, not spread over the gap
        let secs = if dt > SAMPLE * 3 / 2 {
            SAMPLE.as_secs_f32()
        } else {
            dt.as_secs_f32()
        };
        let (t, r) = ((tx - self.tx) as f32 / secs, (rx - self.rx) as f32 / secs);
        self.tx_hist.push(t);
        self.rx_hist.push(r);
        self.sum.push(t + r);
        (self.at, self.tx, self.rx) = (Some(now), tx, rx);
    }

    fn due(&self) -> Option<Instant> {
        self.at.filter(|_| self.busy()).map(|a| a + SAMPLE)
    }

    pub fn rates(&self) -> (f64, f64) {
        (
            f64::from(self.tx_hist.last()),
            f64::from(self.rx_hist.last()),
        )
    }
}

#[derive(Default)]
pub struct Rates {
    peers: Vec<(u64, Flow)>,
    total: Flow,
}

impl Rates {
    pub fn observe(&mut self, s: &UiSnapshot, now: Instant) {
        self.peers
            .retain(|(id, _)| s.io.iter().any(|p| p.id == *id));
        for p in &s.io {
            match self.peers.iter_mut().find(|(id, _)| *id == p.id) {
                Some((_, f)) => f.observe(now, p.tx, p.rx),
                None => {
                    let mut f = Flow::default();
                    f.observe(now, p.tx, p.rx);
                    self.peers.push((p.id, f));
                }
            }
        }
        self.total.observe(now, s.stats.tx, s.stats.rx);
    }

    pub fn flow(&self, id: u64) -> Option<&Flow> {
        self.peers.iter().find(|(x, _)| *x == id).map(|(_, f)| f)
    }

    pub fn peer(&self, id: u64) -> (f64, f64) {
        self.flow(id).map_or((0.0, 0.0), Flow::rates)
    }

    pub fn total(&self) -> (f64, f64) {
        self.total.rates()
    }

    pub fn due(&self) -> Option<Instant> {
        self.peers
            .iter()
            .filter_map(|(_, f)| f.due())
            .chain(self.total.due())
            .min()
    }
}

const N_FILES: usize = 0;
const N_COMMITS: usize = 1;
const N_MERGED: usize = 2;
const N_REFUSED: usize = 3;
const N_HITS: usize = 4;
const N_MISSES: usize = 5;
const N_NUMS: usize = 6;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scene {
    Blank,
    Tiny,
    Host,
    HostPair(u64),
    HostRevoke(u64),
    GuestPick,
    GuestSetup,
    GuestPrompt,
    GuestLive,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Pick,
    Connect,
    Pair,
    Snapshot,
    Mount,
    Warm,
    Live,
    Offline,
}

pub fn phase(s: &UiSnapshot) -> Phase {
    let warming = s.guest.prefetch_total > 0 && s.guest.prefetch_done < s.guest.prefetch_total;
    match s.peers.first().map(|p| &p.state) {
        None if s.discovering || s.host_addr.is_none() => Phase::Pick,
        None => Phase::Connect,
        Some(ConnState::Waiting | ConnState::Discovering | ConnState::Handshaking) => {
            Phase::Connect
        }
        Some(ConnState::Pairing { .. }) => Phase::Pair,
        Some(ConnState::Syncing { .. }) => Phase::Snapshot,
        Some(ConnState::Live) if !s.mounted => Phase::Mount,
        Some(ConnState::Live) if warming => Phase::Warm,
        Some(ConnState::Live) => Phase::Live,
        Some(ConnState::Disconnected { .. }) => Phase::Offline,
    }
}

fn state_kind(st: &ConnState) -> u8 {
    match st {
        ConnState::Waiting => 0,
        ConnState::Discovering => 1,
        ConnState::Handshaking => 2,
        ConnState::Pairing { .. } => 3,
        ConnState::Syncing { .. } => 4,
        ConnState::Live => 5,
        ConnState::Disconnected { .. } => 6,
    }
}

struct Chip {
    id: u64,
    kind: u8,
    at: Instant,
}

pub struct ViewState {
    pub sel: usize,
    pub confirm_revoke: Option<u64>,
    pub quitting: bool,
    pub theme: Theme,
    pub now_ms: u64,
    pub t: Instant,
    pub epoch: Instant,
    pub rates: Rates,
    pub scene: Scene,
    pub trans: Option<Instant>,
    pub focused: bool,
    pub active_at: Instant,
    rtt: Hist,
    rtt_seen: u32,
    nums: [Tween; N_NUMS],
    bars: [Tween; 3],
    chips: Vec<Chip>,
    primed: bool,
}

const BAR_SNAPSHOT: usize = 0;
const BAR_WARM: usize = 1;
const BAR_HITS: usize = 2;

impl ViewState {
    pub fn new(depth: Depth, now: Instant) -> Self {
        Self {
            sel: 0,
            confirm_revoke: None,
            quitting: false,
            theme: Theme::new(depth),
            now_ms: 0,
            t: now,
            epoch: now,
            rates: Rates::default(),
            scene: Scene::Blank,
            trans: None,
            focused: true,
            active_at: now,
            rtt: Hist::default(),
            rtt_seen: 0,
            nums: [Tween::new(0.0, now); N_NUMS],
            bars: [Tween::new(0.0, now); 3],
            chips: Vec::new(),
            primed: false,
        }
    }

    pub fn observe(&mut self, s: &UiSnapshot, now: Instant, wall_ms: u64) {
        self.t = now;
        self.now_ms = wall_ms;
        self.rates.observe(s, now);
        if s.role == Role::Guest
            && let Some(p) = s.peers.first()
            && p.rtt_us > 0
            && p.rtt_us != self.rtt_seen
        {
            self.rtt.push(p.rtt_us as f32);
            self.rtt_seen = p.rtt_us;
        }
        let st = &s.stats;
        let g = &s.guest;
        let nums = [
            st.files, st.commits, st.merged, st.refused, g.hits, g.misses,
        ];
        let snap = match s.peers.first().map(|p| &p.state) {
            _ if s.role == Role::Host => 0.0,
            Some(ConnState::Syncing { done, total }) => ratio(*done, *total),
            Some(ConnState::Live) => 1.0,
            _ => 0.0,
        };
        let bars = [
            snap,
            ratio(g.prefetch_done, g.prefetch_total),
            ratio(g.hits, g.hits + g.misses),
        ];
        for (tw, v) in self.nums.iter_mut().zip(nums) {
            if self.primed {
                tw.set(v as f64, now);
            } else {
                *tw = Tween::new(v as f64, now);
            }
        }
        for (tw, v) in self.bars.iter_mut().zip(bars) {
            if self.primed {
                tw.set(v, now);
            } else {
                *tw = Tween::new(v, now);
            }
        }
        self.chips.retain(|c| s.peers.iter().any(|p| p.id == c.id));
        for p in &s.peers {
            let kind = state_kind(&p.state);
            match self.chips.iter_mut().find(|c| c.id == p.id) {
                Some(c) if c.kind != kind => (c.kind, c.at) = (kind, now),
                Some(_) => {}
                None => self.chips.push(Chip {
                    id: p.id,
                    kind,
                    at: now,
                }),
            }
        }
        self.primed = true;
    }

    fn num(&self, i: usize) -> u64 {
        self.nums[i].value(self.t).round().max(0.0) as u64
    }

    fn bar(&self, i: usize) -> f64 {
        self.bars[i].value(self.t)
    }

    fn pulse(&self, id: u64) -> f32 {
        self.chips
            .iter()
            .find(|c| c.id == id)
            .map_or(0.0, |c| anim::pulse(progress(c.at, self.t, PULSE)))
    }

    // input or a state change brings the ambient spinner back to full speed
    pub fn touch(&mut self, now: Instant) {
        self.active_at = now;
    }

    fn spin_period(&self) -> Duration {
        if self.t.saturating_duration_since(self.active_at) >= IDLE_AFTER {
            SPIN_IDLE
        } else {
            SPIN
        }
    }

    fn spin(&self) -> &'static str {
        SPINNER[spin_index(self.epoch, self.t, self.spin_period())]
    }

    fn breath(&self) -> f32 {
        breathe(self.epoch, self.t)
    }

    fn fast(&self, s: &UiSnapshot) -> bool {
        self.trans.is_some()
            || self.nums.iter().chain(&self.bars).any(|n| n.moving(self.t))
            || self.chips.iter().any(|c| self.t < c.at + PULSE)
            || s.notices
                .back()
                .is_some_and(|(ts, _)| fresh(*ts, self.now_ms))
    }

    // the next instant something on screen changes by itself; none means sleep until an event
    pub fn deadline(&self, s: &UiSnapshot) -> Option<Instant> {
        if !self.focused {
            return None;
        }
        let fast = self.fast(s).then(|| self.t + FRAME);
        let spin = spinning(s, self).then(|| next_spin(self.epoch, self.t, self.spin_period()));
        [fast, spin, self.rates.due()].into_iter().flatten().min()
    }
}

fn fresh(ts: u64, now_ms: u64) -> bool {
    ts <= now_ms + 50 && now_ms.saturating_sub(ts) < NOTICE_FADE_MS
}

fn transitional(st: &ConnState) -> bool {
    matches!(
        st,
        ConnState::Waiting
            | ConnState::Discovering
            | ConnState::Handshaking
            | ConnState::Pairing { .. }
            | ConnState::Syncing { .. }
            | ConnState::Disconnected { .. }
    )
}

fn spinning(s: &UiSnapshot, vs: &ViewState) -> bool {
    if vs.quitting || s.pairing.is_some() {
        return true;
    }
    match s.role {
        Role::Host => s.peers.is_empty() || s.peers.iter().any(|p| transitional(&p.state)),
        Role::Guest => match phase(s) {
            Phase::Live => s.guest.inflight > 0,
            _ => true,
        },
    }
}

pub fn guest_prompt(s: &UiSnapshot) -> Option<(String, [u8; 8])> {
    if let Some(p) = &s.pairing {
        return Some((p.name.as_str().to_owned(), p.sas));
    }
    s.peers.iter().find_map(|p| match p.state {
        ConnState::Pairing { sas } if s.role == Role::Guest => {
            Some((p.name.as_str().to_owned(), sas))
        }
        _ => None,
    })
}

pub fn scene(s: &UiSnapshot, vs: &ViewState, area: Rect) -> Scene {
    if area.width < TINY_W || area.height < TINY_H {
        return Scene::Tiny;
    }
    match s.role {
        Role::Host => match (vs.confirm_revoke, &s.pairing) {
            (Some(id), _) => Scene::HostRevoke(id),
            (None, Some(p)) => Scene::HostPair(p.peer),
            (None, None) => Scene::Host,
        },
        Role::Guest if guest_prompt(s).is_some() => Scene::GuestPrompt,
        Role::Guest => match phase(s) {
            Phase::Pick => Scene::GuestPick,
            Phase::Connect | Phase::Pair | Phase::Snapshot | Phase::Mount => Scene::GuestSetup,
            Phase::Warm | Phase::Live | Phase::Offline => Scene::GuestLive,
        },
    }
}

pub fn draw(f: &mut Frame, s: &UiSnapshot, vs: &ViewState) {
    let area = f.area();
    if area.width < TINY_W || area.height < TINY_H {
        draw_tiny(f.buffer_mut(), area, s, vs);
        return;
    }
    match s.role {
        Role::Host => draw_host(f, area, s, vs),
        Role::Guest => draw_guest(f, area, s, vs),
    }
}

struct Badge {
    glyph: &'static str,
    text: String,
    rgb: Rgb,
}

fn breathing(base: Rgb, vs: &ViewState) -> Rgb {
    theme::FAINT.mix(base, 0.45 + 0.55 * vs.breath())
}

fn host_badge(s: &UiSnapshot, vs: &ViewState) -> Badge {
    let n = s.peers.len();
    let live = s
        .peers
        .iter()
        .filter(|p| p.state == ConnState::Live)
        .count();
    let (glyph, text, rgb) = if vs.quitting {
        (vs.spin(), "stopping".to_owned(), theme::WARN)
    } else if s.pairing.is_some() {
        ("●", "pairing request".into(), breathing(theme::WARN, vs))
    } else if n == 0 {
        (vs.spin(), "waiting for guests".into(), theme::TEAL)
    } else if s.peers.iter().any(|p| transitional(&p.state)) {
        (vs.spin(), format!("{live}/{n} live, syncing"), theme::INFO)
    } else {
        let what = if n == 1 { "guest" } else { "guests" };
        ("●", format!("{n} {what} live"), theme::OK)
    };
    Badge { glyph, text, rgb }
}

fn guest_badge(s: &UiSnapshot, vs: &ViewState) -> Badge {
    let now = vs.now_ms;
    let (glyph, text, rgb) = if vs.quitting {
        (vs.spin(), "unmounting".to_owned(), theme::WARN)
    } else {
        match phase(s) {
            Phase::Pick if s.discovering => (vs.spin(), "scanning".into(), theme::TEAL),
            Phase::Pick => (vs.spin(), "starting".into(), theme::DIM),
            Phase::Connect => (vs.spin(), "connecting".into(), theme::INFO),
            Phase::Pair => ("●", "confirm the code".into(), breathing(theme::WARN, vs)),
            Phase::Snapshot => (
                vs.spin(),
                format!("syncing {:.0}%", vs.bar(BAR_SNAPSHOT) * 100.0),
                theme::INFO,
            ),
            Phase::Mount => (vs.spin(), "mounting".into(), theme::INFO),
            Phase::Warm => (vs.spin(), "live, warming cache".into(), theme::OK),
            Phase::Live => ("●", "live".into(), theme::OK),
            Phase::Offline => {
                let since = match s.peers.first().map(|p| &p.state) {
                    Some(ConnState::Disconnected { since_ms }) => *since_ms,
                    _ => now,
                };
                (
                    "●",
                    format!(
                        "reconnecting, offline {}",
                        fmt_secs(now.saturating_sub(since) / 1000)
                    ),
                    breathing(theme::ERR, vs),
                )
            }
        }
    };
    Badge { glyph, text, rgb }
}

fn badge(s: &UiSnapshot, vs: &ViewState) -> Badge {
    match s.role {
        Role::Host => host_badge(s, vs),
        Role::Guest => guest_badge(s, vs),
    }
}

fn badge_width(b: &Badge) -> u16 {
    (str_width(b.glyph) + 1 + str_width(&b.text)) as u16
}

fn draw_badge(buf: &mut Buffer, x: u16, y: u16, right: u16, b: &Badge, t: &Theme) -> u16 {
    let x = put(buf, x, y, b.glyph, right, t.fg(b.rgb));
    let x = put(buf, x, y, " ", right, Style::new());
    put(buf, x, y, &b.text, right, t.fg(b.rgb))
}

fn role_word(s: &UiSnapshot) -> &'static str {
    match s.role {
        Role::Host => "host",
        Role::Guest => "join",
    }
}

fn project(s: &UiSnapshot) -> String {
    s.project
        .as_ref()
        .map_or_else(|| "-".to_owned(), |n| clean(n.as_str(), NAME_COLS))
}

fn wordmark(buf: &mut Buffer, x: u16, y: u16, right: u16, s: &UiSnapshot, t: &Theme) -> u16 {
    let x = gradient(buf, x, y, "csync", right, t, t.bold);
    put(buf, x, y, &format!(" {}", role_word(s)), right, t.dim)
}

fn header(f: &mut Frame, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.border)
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let buf = f.buffer_mut();
    let right = area.right().saturating_sub(2);
    let y = area.y;
    let mut x = put(buf, area.x + 1, y, " ", right, Style::new());
    x = wordmark(buf, x, y, right, s, t);
    x = put(buf, x, y, " ", right, Style::new());
    let b = badge(s, vs);
    let bw = badge_width(&b) + 2;
    let bx = right.saturating_sub(bw).max(x + 1);
    put(buf, bx, y, " ", right, Style::new());
    let bx = draw_badge(buf, bx + 1, y, right, &b, t);
    put(buf, bx, y, " ", right, Style::new());
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let peer_addr = match s.role {
        Role::Host => s.listen.map(|a| ("listen", a.to_string())),
        Role::Guest => {
            let host = s.peers.first().map(|p| clean(p.name.as_str(), NAME_COLS));
            let addr = s.host_addr.map(|a| a.to_string());
            match (host, addr) {
                (Some(h), Some(a)) => Some(("host", format!("{h}  {a}"))),
                (Some(h), None) => Some(("host", h)),
                (None, Some(a)) => Some(("host", a)),
                (None, None) => None,
            }
        }
    };
    let iw = usize::from(inner.width);
    let (r, y1) = (inner.right(), inner.y);
    let mut used_right = 0;
    if let Some((label, v)) = &peer_addr {
        let room = iw.saturating_sub(24);
        let v = mid_trunc(v, room.saturating_sub(label.len() + 2));
        let full = format!("{label}  {v}");
        let x0 = put_right(buf, inner, y1, &full, t.text);
        put(buf, x0, y1, label, r, t.dim);
        used_right = str_width(&full) + 2;
    }
    let x = put(buf, inner.x, y1, "project  ", r, t.dim);
    let room = iw.saturating_sub(9 + used_right);
    put(buf, x, y1, &mid_trunc(&project(s), room), r, t.bold);
    if inner.height < 2 {
        return;
    }
    let (label, path) = match s.role {
        Role::Host => ("root     ", s.root.as_ref()),
        Role::Guest => ("mount    ", s.mount.as_ref()),
    };
    let p = path.map_or_else(
        || "-".to_owned(),
        |p| clean(&p.to_string_lossy(), PATH_COLS),
    );
    let x = put(buf, inner.x, y1 + 1, label, r, t.dim);
    put(
        buf,
        x,
        y1 + 1,
        &mid_trunc(&p, iw.saturating_sub(9)),
        r,
        t.text,
    );
}

fn header_compact(buf: &mut Buffer, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let right = area.right().saturating_sub(1);
    let mut x = wordmark(buf, area.x + 1, area.y, right, s, t);
    let b = badge(s, vs);
    let bx = right.saturating_sub(badge_width(&b));
    x = put(buf, x, area.y, "  ", bx, Style::new());
    let room = usize::from(bx.saturating_sub(x + 1));
    put(buf, x, area.y, &mid_trunc(&project(s), room), bx, t.bold);
    draw_badge(buf, bx.max(x), area.y, right, &b, t);
}

fn panel<'a>(title: &'a str, t: &Theme) -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.border)
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(title, t.bold),
            Span::raw(" "),
        ]))
        .padding(Padding::horizontal(1))
}

fn keys(buf: &mut Buffer, area: Rect, items: &[(&str, &str)], t: &Theme) {
    let right = area.right();
    let mut x = area.x + 1;
    for (i, (k, what)) in items.iter().enumerate() {
        if i > 0 {
            x = put(buf, x, area.y, "   ", right, Style::new());
        }
        x = put(buf, x, area.y, k, right, t.key);
        x = put(buf, x, area.y, " ", right, Style::new());
        x = put(buf, x, area.y, what, right, t.dim);
    }
}

fn chip(st: &ConnState, vs: &ViewState) -> Badge {
    let (glyph, text, rgb) = match st {
        ConnState::Waiting | ConnState::Discovering | ConnState::Handshaking => {
            (vs.spin(), "connecting".to_owned(), theme::INFO)
        }
        ConnState::Pairing { .. } => ("●", "pairing".into(), breathing(theme::WARN, vs)),
        ConnState::Syncing { done, total } if *total > 0 => (
            vs.spin(),
            format!("sync {}%", done.saturating_mul(100) / total),
            theme::INFO,
        ),
        ConnState::Syncing { .. } => (vs.spin(), "syncing".into(), theme::INFO),
        ConnState::Live => ("●", "live".into(), theme::OK),
        ConnState::Disconnected { since_ms } => (
            "○",
            format!(
                "offline {}",
                fmt_secs(vs.now_ms.saturating_sub(*since_ms) / 1000)
            ),
            breathing(theme::ERR, vs),
        ),
    };
    Badge { glyph, text, rgb }
}

fn draw_chip(buf: &mut Buffer, x: u16, y: u16, right: u16, p: &PeerView, vs: &ViewState) {
    let t = &vs.theme;
    let mut b = chip(&p.state, vs);
    let pulse = vs.pulse(p.id);
    b.rgb = b.rgb.mix(theme::WHITE, pulse * 0.65);
    let x = draw_badge(buf, x, y, right, &b, t);
    if pulse > 0.05 && !t.mono() {
        let start = x.saturating_sub(badge_width(&b));
        for cx in start..x.min(buf.area.right()) {
            buf[(cx, y)].modifier.insert(Modifier::BOLD);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Col {
    Name,
    Fpr,
    State,
    Rtt,
    In,
    Out,
    Traffic,
    Pending,
}

fn guest_cols(w: u16) -> Vec<(Col, u16)> {
    let mut cols = Vec::with_capacity(8);
    if w >= 100 {
        cols.push((Col::Fpr, 9));
    }
    cols.extend([(Col::State, 13), (Col::Rtt, 8)]);
    if w >= 56 {
        cols.extend([(Col::In, 10), (Col::Out, 10)]);
    }
    let pending = w >= 64;
    let used = |c: &[(Col, u16)]| c.iter().map(|(_, w)| w + 1).sum::<u16>();
    if w >= 74 {
        let spark = w
            .saturating_sub(used(&cols) + 8 * u16::from(pending) + 19)
            .clamp(8, 30);
        cols.push((Col::Traffic, spark));
    }
    if pending {
        cols.push((Col::Pending, 7));
    }
    let name = w.saturating_sub(used(&cols) + 1).max(4);
    cols.insert(0, (Col::Name, name));
    cols
}

fn guests(f: &mut Frame, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let count = format!(" {} ", s.peers.len());
    let block =
        panel("Guests", t).title_top(Line::from(Span::styled(count, t.dim)).right_aligned());
    let inner = block.inner(area);
    f.render_widget(block, area);
    let buf = f.buffer_mut();
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let r = inner.right();
    if s.peers.is_empty() {
        let x = put(buf, inner.x, inner.y, vs.spin(), r, t.accent);
        put(
            buf,
            x + 1,
            inner.y,
            "waiting for a guest to connect",
            r,
            t.text,
        );
        if s.listen.is_some() && inner.height > 1 {
            let x = put(buf, inner.x + 2, inner.y + 1, "on the guest run ", r, t.dim);
            put(buf, x, inner.y + 1, "csync join", r, t.accent);
        }
        return;
    }
    let cols = guest_cols(inner.width);
    let mut x = inner.x;
    for (c, w) in &cols {
        let label = match c {
            Col::Name => "guest",
            Col::Fpr => "id",
            Col::State => "state",
            Col::Rtt => "rtt",
            Col::In => "in",
            Col::Out => "out",
            Col::Traffic => "traffic",
            Col::Pending => "queue",
        };
        let lx = if *c == Col::Name { x + 2 } else { x };
        put(buf, lx, inner.y, label, (x + w).min(r), t.faint);
        x += w + 1;
    }
    let rows = usize::from(inner.height.saturating_sub(1));
    let sel = vs.sel.min(s.peers.len() - 1);
    let skip = (sel + 1).saturating_sub(rows);
    for (i, p) in s.peers.iter().enumerate().skip(skip).take(rows) {
        let y = inner.y + 1 + (i - skip) as u16;
        if i == sel {
            buf.set_style(Rect::new(inner.x, y, inner.width, 1), t.sel);
        }
        let io = s.io.iter().find(|x| x.id == p.id);
        let (tx, rx) = vs.rates.peer(p.id);
        let mut x = inner.x;
        for (c, w) in &cols {
            let end = (x + w).min(r);
            match c {
                Col::Name => {
                    let mark = if i == sel { "› " } else { "  " };
                    let nx = put(buf, x, y, mark, end, t.accent);
                    let name = mid_trunc(
                        &clean(p.name.as_str(), NAME_COLS),
                        usize::from(w.saturating_sub(2)),
                    );
                    put(
                        buf,
                        nx,
                        y,
                        &name,
                        end,
                        if i == sel { t.bold } else { t.text },
                    );
                }
                Col::Fpr => {
                    put(buf, x, y, &fpr_text(&p.fpr)[..8], end, t.dim);
                }
                Col::State => draw_chip(buf, x, y, end, p, vs),
                Col::Rtt => {
                    put(buf, x, y, &fmt_rtt(p.rtt_us), end, t.text);
                }
                Col::In => {
                    put(
                        buf,
                        x,
                        y,
                        &fmt_rate(rx),
                        end,
                        if rx > 0.0 { t.text } else { t.faint },
                    );
                }
                Col::Out => {
                    put(
                        buf,
                        x,
                        y,
                        &fmt_rate(tx),
                        end,
                        if tx > 0.0 { t.text } else { t.faint },
                    );
                }
                Col::Traffic => {
                    let cell = Rect::new(x, y, end.saturating_sub(x), 1);
                    match vs.rates.flow(p.id) {
                        Some(fl) => widgets::spark(buf, cell, &fl.sum, fl.sum.max(), t, None),
                        None => widgets::spark(buf, cell, &Hist::default(), 0.0, t, None),
                    }
                }
                Col::Pending => {
                    let n = io.map_or(0, |x| x.pending);
                    let style = if n > 0 { t.warn } else { t.faint };
                    put(buf, x, y, &fmt_count(u64::from(n)), end, style);
                }
            }
            x += w + 1;
        }
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && str_width(&line) + 1 + str_width(word) > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

fn activity(f: &mut Frame, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let block =
        panel("Activity", t).title_top(Line::from(Span::styled(" utc ", t.faint)).right_aligned());
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let buf = f.buffer_mut();
    let r = inner.right();
    let rows = usize::from(inner.height);
    let mut y = inner.y;
    for (ts, n) in s.notices.iter().rev().take(rows) {
        let base = notice_rgb(n.kind);
        let age = fresh(*ts, vs.now_ms)
            .then(|| vs.now_ms.saturating_sub(*ts) as f32 / NOTICE_FADE_MS as f32);
        let glow = age.map_or(0.0, |p| 1.0 - anim::ease_out(p));
        let kind_style = t.fg(base.mix(theme::WHITE, glow * 0.6));
        let path_style = match age {
            Some(p) => t.fg(base
                .mix(theme::WHITE, 0.5)
                .mix(theme::TEXT, anim::ease_out(p))),
            None => t.text,
        };
        let x = put(buf, inner.x, y, &fmt_utc(*ts), r, t.faint);
        let x = put(buf, x, y, "  ", r, Style::new());
        let x = put(buf, x, y, "▍", r, t.fg(base));
        let x = put(
            buf,
            x,
            y,
            &format!("{:<10}", notice_word(n.kind)),
            r,
            kind_style,
        );
        let path = if n.path.is_root() {
            "/".to_owned()
        } else {
            clean(n.path.as_str(), PATH_COLS)
        };
        let room = usize::from(r.saturating_sub(x));
        let x2 = put(buf, x, y, &mid_trunc(&path, room), r, path_style);
        if glow > 0.05 && !t.mono() {
            for cx in x..x2 {
                buf[(cx, y)].modifier.insert(Modifier::BOLD);
            }
        }
        y += 1;
    }
    if s.notices.is_empty() {
        put(buf, inner.x, y, "no activity yet", r, t.faint);
        y += 1;
    }
    let hint_w = usize::from(inner.width.saturating_sub(2));
    for h in &s.hints {
        for (i, l) in wrap(h, hint_w).iter().enumerate() {
            if y >= inner.bottom() {
                return;
            }
            put(
                buf,
                inner.x,
                y,
                if i == 0 { "› " } else { "  " },
                r,
                t.accent,
            );
            put(
                buf,
                inner.x + 2,
                y,
                l,
                r,
                t.dim.add_modifier(Modifier::ITALIC),
            );
            y += 1;
        }
    }
}

fn stat(buf: &mut Buffer, x: u16, y: u16, right: u16, item: (&str, &str, Style), t: &Theme) -> u16 {
    let (k, v, style) = item;
    let x = put(buf, x, y, k, right, t.dim);
    let x = put(buf, x, y, " ", right, Style::new());
    let x = put(buf, x, y, v, right, style);
    put(buf, x, y, "   ", right, Style::new())
}

fn counters(buf: &mut Buffer, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let y = area.y;
    let r = area.right().saturating_sub(1);
    let (tx, rx) = vs.rates.total();
    let flow = format!("↓ {}  ↑ {}", fmt_rate(rx), fmt_rate(tx));
    let fw = str_width(&flow) as u16;
    let spark_w: u16 = if area.width >= 90 { 16 } else { 0 };
    let flow_x = r.saturating_sub(fw + spark_w + u16::from(spark_w > 0));
    let mut x = area.x + 1;
    let refused = vs.num(N_REFUSED);
    for (k, v, style) in [
        ("files", vs.num(N_FILES), t.text),
        ("commits", vs.num(N_COMMITS), t.text),
        ("merged", vs.num(N_MERGED), t.text),
        ("refused", refused, if refused > 0 { t.err } else { t.text }),
    ] {
        x = stat(buf, x, y, flow_x, (k, &fmt_count(v), style), t);
    }
    if s.stats.skew_ms.unsigned_abs() >= 1000 {
        let skew = format!("{} ms", s.stats.skew_ms);
        stat(buf, x, y, flow_x, ("clock skew", &skew, t.err), t);
    }
    {
        let fx = put(
            buf,
            flow_x,
            y,
            &flow,
            r,
            if tx + rx > 0.0 { t.text } else { t.faint },
        );
        if spark_w > 0 {
            let h = &vs.rates.total.sum;
            widgets::spark(
                buf,
                Rect::new(fx + 1, y, spark_w.min(r.saturating_sub(fx + 1)), 1),
                h,
                h.max(),
                t,
                None,
            );
        }
    }
}

fn card(f: &mut Frame, area: Rect, w: u16, h: u16, title: &str, vs: &ViewState) -> Rect {
    let t = &vs.theme;
    let w = w.min(area.width);
    let h = h.min(area.height);
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    f.render_widget(Clear, rect);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(t.accent)
        .title(
            Line::from(vec![
                Span::raw(" "),
                Span::styled(title, t.bold),
                Span::raw(" "),
            ])
            .centered(),
        )
        .padding(Padding::horizontal(2));
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    if !t.mono() {
        let buf = f.buffer_mut();
        let span = f32::from(rect.width.max(2) - 1);
        for y in rect.top()..rect.bottom() {
            for x in rect.left()..rect.right() {
                let edge = y == rect.top()
                    || y + 1 == rect.bottom()
                    || x == rect.left()
                    || x + 1 == rect.right();
                let cell = &mut buf[(x, y)];
                if edge
                    && cell.modifier.is_empty()
                    && cell
                        .symbol()
                        .chars()
                        .all(|c| ('\u{2500}'..='\u{257f}').contains(&c))
                {
                    cell.fg = t.color(Theme::grad_rgb(f32::from(x - rect.x) / span));
                }
            }
        }
    }
    inner
}

fn centre(buf: &mut Buffer, area: Rect, y: u16, s: &str, style: Style) {
    let w = (str_width(s) as u16).min(area.width);
    put(
        buf,
        area.x + (area.width - w) / 2,
        y,
        s,
        area.right(),
        style,
    );
}

fn centre_keys(buf: &mut Buffer, area: Rect, y: u16, items: &[(&str, &str)], t: &Theme) {
    let w: usize = items
        .iter()
        .map(|(k, v)| str_width(k) + 1 + str_width(v))
        .sum::<usize>()
        + 4 * items.len().saturating_sub(1);
    let x0 = area.x + area.width.saturating_sub(w as u16) / 2;
    keys(
        buf,
        Rect::new(
            x0.saturating_sub(1),
            y,
            area.right().saturating_sub(x0.saturating_sub(1)),
            1,
        ),
        items,
        t,
    );
}

struct Pairing<'a> {
    who: &'a str,
    name: &'a str,
    sas: &'a [u8; 8],
    expires_ms: Option<u64>,
    keys: &'a [(&'a str, &'a str)],
    hint: &'a str,
}

fn pairing_card(f: &mut Frame, area: Rect, p: &Pairing<'_>, vs: &ViewState) {
    let t = &vs.theme;
    let code = sas_text(p.sas);
    let big = big_width(&code).filter(|w| w + 6 <= area.width && area.height >= 14);
    let inner_w = big.map_or(34, |w| w.max(44)).max(str_width(p.hint) as u16);
    let h = if big.is_some() { 12 } else { 10 } - u16::from(p.expires_ms.is_none());
    let inner = card(f, area, inner_w + 6, h, "Pairing request", vs);
    let buf = f.buffer_mut();
    let r = inner.right();
    let mut y = inner.y;
    let x = put(buf, inner.x, y, p.who, r, t.dim);
    let x = put(buf, x, y, "  ", r, Style::new());
    put(
        buf,
        x,
        y,
        &mid_trunc(&clean(p.name, NAME_COLS), usize::from(r.saturating_sub(x))),
        r,
        t.bold,
    );
    y += 2;
    let bottom = inner.bottom();
    let shine = (vs.t.saturating_duration_since(vs.epoch).as_secs_f32() / 2.4).fract() * 1.6 - 0.3;
    match big {
        _ if y >= bottom => return,
        Some(w) => {
            let x = inner.x + inner.width.saturating_sub(w) / 2;
            big_text(buf, x, y, &code, t, shine);
            y += BIG_ROWS + 1;
        }
        None => {
            let spaced: String = code.chars().flat_map(|c| [c, ' ']).collect();
            let w = (str_width(spaced.trim_end()) as u16).min(inner.width);
            gradient(
                buf,
                inner.x + (inner.width - w) / 2,
                y,
                spaced.trim_end(),
                r,
                t,
                t.bold,
            );
            y += 2;
        }
    }
    if y >= bottom {
        return;
    }
    centre(buf, inner, y, p.hint, t.dim);
    y += 1;
    if let Some(exp) = p.expires_ms.filter(|_| y < bottom) {
        let left = exp.saturating_sub(vs.now_ms);
        let label = format!(" {}", fmt_secs(left.div_ceil(1000)));
        let lw = str_width(&label) as u16;
        let bw = inner.width.saturating_sub(lw);
        let fill = if left < 20_000 {
            Fill::Solid(theme::WARN)
        } else {
            Fill::Gradient
        };
        widgets::bar(
            buf,
            Rect::new(inner.x, y, bw, 1),
            left as f64 / PAIR_WINDOW_MS as f64,
            t,
            &fill,
        );
        put(
            buf,
            inner.x + bw,
            y,
            &label,
            r,
            if left < 20_000 { t.warn } else { t.dim },
        );
        y += 1;
    }
    y += 1;
    if y < bottom {
        centre_keys(buf, inner, y, p.keys, t);
    }
}

fn revoke_card(f: &mut Frame, area: Rect, s: &UiSnapshot, id: u64, vs: &ViewState) {
    let t = &vs.theme;
    let name = s
        .peers
        .iter()
        .find(|p| p.id == id)
        .map(|p| clean(p.name.as_str(), NAME_COLS))
        .unwrap_or_default();
    let inner = card(f, area, 50, 7, "Revoke guest", vs);
    let buf = f.buffer_mut();
    let r = inner.right();
    let x = put(buf, inner.x, inner.y, "forget ", r, t.text);
    let x = put(
        buf,
        x,
        inner.y,
        &mid_trunc(&name, usize::from(r.saturating_sub(x + 1))),
        r,
        t.bold,
    );
    put(buf, x, inner.y, "?", r, t.text);
    put(
        buf,
        inner.x,
        inner.y + 1,
        "it will have to pair again to connect",
        r,
        t.dim,
    );
    centre_keys(
        buf,
        inner,
        inner.y + 3,
        &[("y", "revoke"), ("any key", "cancel")],
        t,
    );
}

fn draw_host(f: &mut Frame, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let compact = area.height < COMPACT_H;
    let head_h = if compact { 1 } else { 4 };
    let room = area.height.saturating_sub(head_h + 2);
    let want = if s.peers.is_empty() {
        4
    } else {
        s.peers.len() as u16 + 3
    };
    let guests_h = want.clamp(3, (room * 11 / 20).max(3));
    let [head, gs, act, count, key] = Layout::vertical([
        Constraint::Length(head_h),
        Constraint::Length(guests_h),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    if compact {
        header_compact(f.buffer_mut(), head, s, vs);
    } else {
        header(f, head, s, vs);
    }
    guests(f, gs, s, vs);
    activity(f, act, s, vs);
    counters(f.buffer_mut(), count, s, vs);
    let t = &vs.theme;
    let items: &[(&str, &str)] = if vs.confirm_revoke.is_some() {
        &[("y", "revoke"), ("any key", "cancel")]
    } else if s.pairing.is_some() {
        &[("a", "accept"), ("r", "reject"), ("q", "quit")]
    } else {
        &[("q", "quit"), ("↑↓", "select"), ("x", "revoke guest")]
    };
    keys(f.buffer_mut(), key, items, t);
    if let Some(id) = vs.confirm_revoke {
        revoke_card(f, area, s, id, vs);
    } else if let Some(p) = &s.pairing {
        let pr = Pairing {
            who: "guest",
            name: p.name.as_str(),
            sas: &p.sas,
            expires_ms: (p.expires_ms > 0).then_some(p.expires_ms),
            keys: &[("a", "accept"), ("r", "reject")],
            hint: "accept only if the guest shows the same code",
        };
        pairing_card(f, area, &pr, vs);
    }
}

fn hosts(f: &mut Frame, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let block = panel("Hosts on this network", t);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let buf = f.buffer_mut();
    if s.discovering {
        let right = area.right().saturating_sub(2);
        let b = Badge {
            glyph: vs.spin(),
            text: "scanning".into(),
            rgb: theme::TEAL,
        };
        let bx = right.saturating_sub(badge_width(&b) + 2);
        put(buf, bx, area.y, " ", right, Style::new());
        let x = draw_badge(buf, bx + 1, area.y, right, &b, t);
        put(buf, x, area.y, " ", right, Style::new());
    }
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let r = inner.right();
    if s.hosts.is_empty() {
        let mid = inner.y + inner.height.saturating_sub(2) / 2;
        let msg = if s.discovering {
            "looking for csync hosts"
        } else {
            "starting"
        };
        let w = str_width(msg) as u16;
        let x0 = inner.x + inner.width.saturating_sub(w) / 2;
        let sweep_at = vs.t.saturating_duration_since(vs.epoch).as_secs_f32() / 1.8;
        let n = msg.chars().count().max(2) as f32;
        let mut x = x0;
        let mut b = [0u8; 4];
        for (i, c) in msg.chars().enumerate() {
            let d = ((i as f32 / n) - (sweep_at.fract() * 1.4 - 0.2)).abs();
            let rgb = theme::DIM.mix(Theme::grad_rgb(i as f32 / n), 1.0 - (d * 4.0).min(1.0));
            x = put(buf, x, mid, c.encode_utf8(&mut b), r, t.fg(rgb));
        }
        if inner.height > 2 {
            centre(
                buf,
                inner,
                mid + 1,
                "start one on the Mac with  csync host",
                t.faint,
            );
        }
        return;
    }
    let wide = inner.width >= 70;
    let addr_w = 22u16;
    let fpr_w = if wide { 18 } else { 0 };
    let tag_w = 8u16;
    let name_w = inner
        .width
        .saturating_sub(addr_w + fpr_w + tag_w + 3)
        .max(4);
    let head_y = inner.y;
    put(buf, inner.x + 2, head_y, "host", r, t.faint);
    let ax = inner.x + name_w + 1;
    put(buf, ax, head_y, "address", r, t.faint);
    if wide {
        put(buf, ax + addr_w + 1, head_y, "fingerprint", r, t.faint);
    }
    let rows = usize::from(inner.height.saturating_sub(1));
    let sel = vs.sel.min(s.hosts.len() - 1);
    let skip = (sel + 1).saturating_sub(rows);
    for (i, h) in s.hosts.iter().enumerate().skip(skip).take(rows) {
        let y = inner.y + 1 + (i - skip) as u16;
        let on = i == sel;
        if on {
            buf.set_style(Rect::new(inner.x, y, inner.width, 1), t.sel);
        }
        let x = put(buf, inner.x, y, if on { "› " } else { "  " }, r, t.accent);
        let label = mid_trunc(
            &clean(h.label.as_str(), NAME_COLS),
            usize::from(name_w.saturating_sub(2)),
        );
        put(buf, x, y, &label, ax, if on { t.bold } else { t.text });
        put(
            buf,
            ax,
            y,
            &h.addr.to_string(),
            (ax + addr_w).min(r),
            t.text,
        );
        let mut tx = ax + addr_w + 1;
        if wide {
            put(buf, tx, y, &fpr_text(&h.fpr), (tx + fpr_w).min(r), t.dim);
            tx += fpr_w + 1;
        }
        let (g, word, style) = if h.paired {
            ("●", " paired", t.ok)
        } else {
            ("○", " new", t.dim)
        };
        let x = put(buf, tx, y, g, r, style);
        put(buf, x, y, word, r, style);
    }
}

const STEPS: [&str; 5] = ["connect", "pair", "snapshot", "mount", "warm"];

fn step_index(p: Phase) -> usize {
    match p {
        Phase::Pick | Phase::Connect => 0,
        Phase::Pair => 1,
        Phase::Snapshot => 2,
        Phase::Mount => 3,
        Phase::Warm => 4,
        Phase::Live | Phase::Offline => 5,
    }
}

fn stepper(buf: &mut Buffer, area: Rect, cur: usize, vs: &ViewState) {
    let t = &vs.theme;
    let full: usize = STEPS.iter().map(|s| 2 + s.len()).sum::<usize>() + 4 * 4;
    let labels_all = full <= usize::from(area.width);
    let link = if labels_all { " ── " } else { " " };
    let r = area.right();
    let mut x = area.x;
    for (i, name) in STEPS.iter().enumerate() {
        if i > 0 {
            let style = if i <= cur { t.ok } else { t.faint };
            x = put(buf, x, area.y, link, r, style);
        }
        let (g, style) = match i.cmp(&cur) {
            std::cmp::Ordering::Less => ("●", t.ok),
            std::cmp::Ordering::Equal => (vs.spin(), t.accent),
            std::cmp::Ordering::Greater => ("○", t.faint),
        };
        x = put(buf, x, area.y, g, r, style);
        if labels_all || i == cur {
            let ls = match i.cmp(&cur) {
                std::cmp::Ordering::Equal => t.bold,
                std::cmp::Ordering::Less => t.text,
                std::cmp::Ordering::Greater => t.faint,
            };
            x = put(buf, x, area.y, " ", r, Style::new());
            x = put(buf, x, area.y, name, r, ls);
        }
    }
}

fn setup(f: &mut Frame, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let ph = phase(s);
    let block = panel("Joining", t);
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let buf = f.buffer_mut();
    let r = inner.right();
    stepper(
        buf,
        Rect::new(inner.x, inner.y, inner.width, 1),
        step_index(ph),
        vs,
    );
    if inner.height < 3 {
        return;
    }
    let y = inner.y + 2;
    let (done, total) = match s.peers.first().map(|p| &p.state) {
        Some(ConnState::Syncing { done, total }) => (*done, *total),
        _ => (0, 0),
    };
    if ph == Phase::Snapshot && total > 0 {
        let pct = format!(" {:>3.0}%", vs.bar(BAR_SNAPSHOT) * 100.0);
        let bw = inner.width.saturating_sub(str_width(&pct) as u16);
        widgets::bar(
            buf,
            Rect::new(inner.x, y, bw, 1),
            vs.bar(BAR_SNAPSHOT),
            t,
            &Fill::Gradient,
        );
        put(buf, inner.x + bw, y, &pct, r, t.text);
    } else {
        let sweep_at = vs.t.saturating_duration_since(vs.epoch).as_secs_f32() / 1.6;
        widgets::sweep(buf, Rect::new(inner.x, y, inner.width, 1), sweep_at, t);
    }
    if inner.height < 4 {
        return;
    }
    let addr = s
        .host_addr
        .map_or_else(|| "the host".to_owned(), |a| a.to_string());
    let detail = match ph {
        Phase::Pick | Phase::Connect => format!("connecting to {addr}"),
        Phase::Pair => "confirm the pairing code".into(),
        Phase::Snapshot if total > 0 => format!(
            "receiving the file tree  {} / {}",
            fmt_count(done),
            fmt_count(total)
        ),
        Phase::Snapshot => "receiving the file tree".into(),
        Phase::Mount => {
            let m = s
                .mount
                .as_ref()
                .map_or_else(String::new, |m| clean(&m.to_string_lossy(), PATH_COLS));
            format!("mounting at {m}")
        }
        Phase::Warm | Phase::Live | Phase::Offline => "warming the cache".into(),
    };
    put(
        buf,
        inner.x,
        y + 1,
        &mid_trunc(&detail, usize::from(inner.width)),
        r,
        t.dim,
    );
}

#[derive(Clone, Copy)]
enum Row {
    Banner,
    Link,
    Cache,
    Store,
    Fetch,
    Edits,
    Files,
    Data,
    Warm,
    Skew,
}

fn live_rows(s: &UiSnapshot) -> Vec<Row> {
    let mut rows = Vec::with_capacity(10);
    if phase(s) == Phase::Offline {
        rows.push(Row::Banner);
    }
    rows.extend([
        Row::Link,
        Row::Cache,
        Row::Store,
        Row::Fetch,
        Row::Edits,
        Row::Files,
        Row::Data,
    ]);
    if phase(s) == Phase::Warm {
        rows.insert(rows.len() - 3, Row::Warm);
    }
    if s.stats.skew_ms.unsigned_abs() >= 1000 {
        rows.push(Row::Skew);
    }
    rows
}

fn live_row(buf: &mut Buffer, area: Rect, row: Row, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let (x0, y, r) = (area.x, area.y, area.right());
    let label = |buf: &mut Buffer, k: &str| put(buf, x0, y, &format!("{k:<8}"), r, t.dim);
    let st = &s.stats;
    let g = &s.guest;
    match row {
        Row::Banner => {
            let rgb = breathing(theme::ERR, vs);
            let x = put(buf, x0, y, "●", r, t.fg(rgb));
            let x = put(buf, x, y, " host unreachable, reconnecting ", r, t.fg(rgb));
            let x = put(buf, x, y, vs.spin(), r, t.err);
            put(buf, x, y, "  cached files stay readable", r, t.dim);
        }
        Row::Link => {
            let x = label(buf, "link");
            let x = match s.peers.first() {
                Some(p) => {
                    draw_chip(buf, x, y, r, p, vs);
                    let x = x + badge_width(&chip(&p.state, vs)).max(10) + 2;
                    let x = put(buf, x, y, &fmt_rtt(p.rtt_us), r, t.text);
                    x + 2
                }
                None => put(buf, x, y, "-", r, t.faint),
            };
            let w = r.saturating_sub(x).min(30);
            if w >= 6 {
                widgets::spark(
                    buf,
                    Rect::new(x, y, w, 1),
                    &vs.rtt,
                    vs.rtt.max(),
                    t,
                    Some(theme::INFO),
                );
            }
        }
        Row::Cache => {
            let x = label(buf, "cache");
            let hits = vs.num(N_HITS);
            let misses = vs.num(N_MISSES);
            let bw = r.saturating_sub(x).saturating_sub(30).clamp(6, 24);
            widgets::bar(
                buf,
                Rect::new(x, y, bw, 1),
                vs.bar(BAR_HITS),
                t,
                &Fill::Gradient,
            );
            let x = x + bw + 1;
            let pct = if hits + misses == 0 {
                "no reads yet".to_owned()
            } else {
                format!("{:.0}% hits", vs.bar(BAR_HITS) * 100.0)
            };
            let x = put(buf, x, y, &pct, r, t.text);
            put(
                buf,
                x,
                y,
                &format!("  {} / {}", fmt_count(hits), fmt_count(misses)),
                r,
                t.dim,
            );
        }
        Row::Store => {
            let x = label(buf, "store");
            let used = ratio(st.cached_bytes, st.cache_cap);
            let bw = r.saturating_sub(x).saturating_sub(30).clamp(6, 24);
            widgets::bar(
                buf,
                Rect::new(x, y, bw, 1),
                used,
                t,
                &Fill::Solid(theme::INFO),
            );
            let v = format!(
                "{} of {}",
                fmt_bytes(st.cached_bytes),
                fmt_bytes(st.cache_cap)
            );
            put(buf, x + bw + 1, y, &v, r, t.text);
        }
        Row::Fetch => {
            let x = label(buf, "fetch");
            if g.inflight > 0 {
                let x = put(buf, x, y, vs.spin(), r, t.accent);
                put(
                    buf,
                    x + 1,
                    y,
                    &format!("{} in flight", g.inflight),
                    r,
                    t.text,
                );
            } else {
                put(buf, x, y, "idle", r, t.faint);
            }
        }
        Row::Edits => {
            let mut x = label(buf, "edits");
            let refused = vs.num(N_REFUSED);
            for (k, v, style) in [
                ("commits", vs.num(N_COMMITS), t.text),
                ("merged", vs.num(N_MERGED), t.text),
                ("refused", refused, if refused > 0 { t.err } else { t.text }),
            ] {
                x = stat(buf, x, y, r, (k, &fmt_count(v), style), t);
            }
        }
        Row::Files => {
            let x = label(buf, "files");
            let x = put(buf, x, y, &fmt_count(vs.num(N_FILES)), r, t.text);
            let (txt, style) = if st.inject_backlog > 0 {
                (format!("   {} events queued", st.inject_backlog), t.warn)
            } else {
                ("   events in sync".to_owned(), t.dim)
            };
            put(buf, x, y, &txt, r, style);
        }
        Row::Data => {
            let x = label(buf, "data");
            let v = if g.passthrough {
                "kernel passthrough"
            } else {
                "served by csync"
            };
            put(buf, x, y, v, r, t.dim);
        }
        Row::Warm => {
            let x = label(buf, "warm");
            let pct = format!(" {:>3.0}%", vs.bar(BAR_WARM) * 100.0);
            let bw = r
                .saturating_sub(x)
                .saturating_sub(str_width(&pct) as u16 + 18)
                .max(6);
            widgets::bar(
                buf,
                Rect::new(x, y, bw, 1),
                vs.bar(BAR_WARM),
                t,
                &Fill::Gradient,
            );
            let x = put(buf, x + bw, y, &pct, r, t.text);
            put(
                buf,
                x,
                y,
                &format!(
                    "  {} / {}",
                    fmt_count(g.prefetch_done),
                    fmt_count(g.prefetch_total)
                ),
                r,
                t.dim,
            );
        }
        Row::Skew => {
            let msg = format!(
                "clock skew {} ms: build tools comparing mtimes may misbehave",
                st.skew_ms
            );
            put(buf, x0, y, &msg, r, t.err);
        }
    }
}

fn live(f: &mut Frame, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let block = panel("Session", t);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let buf = f.buffer_mut();
    let rows = live_rows(s);
    let two = inner.width >= 100;
    let per = if two {
        rows.len().div_ceil(2)
    } else {
        rows.len()
    };
    let half = inner.width / 2;
    for (i, row) in rows.iter().enumerate() {
        let (col, line) = (i / per.max(1), i % per.max(1));
        let y = inner.y + line as u16;
        if y >= inner.bottom() {
            continue;
        }
        let rect = if two {
            Rect::new(inner.x + col as u16 * half, y, half.saturating_sub(2), 1)
        } else {
            Rect::new(inner.x, y, inner.width, 1)
        };
        live_row(buf, rect, *row, s, vs);
    }
}

pub fn live_height(s: &UiSnapshot, width: u16) -> u16 {
    let n = live_rows(s).len();
    let n = if width.saturating_sub(4) >= 100 {
        n.div_ceil(2)
    } else {
        n
    };
    n as u16 + 2
}

fn draw_guest(f: &mut Frame, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let compact = area.height < COMPACT_H;
    let head_h = if compact { 1 } else { 4 };
    let ph = phase(s);
    let room = area.height.saturating_sub(head_h + 1);
    let (main_h, act_min) = match ph {
        Phase::Pick => (room, 0),
        Phase::Connect | Phase::Pair | Phase::Snapshot | Phase::Mount => (6.min(room), 3),
        _ => (
            live_height(s, area.width).min(room.saturating_sub(3).max(3)),
            3,
        ),
    };
    let [head, main, act, key] = Layout::vertical([
        Constraint::Length(head_h),
        Constraint::Length(main_h),
        Constraint::Min(act_min),
        Constraint::Length(1),
    ])
    .areas(area);
    if compact {
        header_compact(f.buffer_mut(), head, s, vs);
    } else {
        header(f, head, s, vs);
    }
    match ph {
        Phase::Pick => hosts(f, main, s, vs),
        Phase::Connect | Phase::Pair | Phase::Snapshot | Phase::Mount => setup(f, main, s, vs),
        _ => live(f, main, s, vs),
    }
    if act.height > 0 {
        activity(f, act, s, vs);
    }
    let t = &vs.theme;
    let prompt = guest_prompt(s);
    let items: &[(&str, &str)] = if prompt.is_some() {
        &[("y", "codes match"), ("n", "they differ"), ("q", "quit")]
    } else if ph == Phase::Pick {
        &[("↑↓", "select"), ("enter", "join"), ("q", "quit")]
    } else {
        &[("q", "unmount, wipe and quit")]
    };
    keys(f.buffer_mut(), key, items, t);
    if let Some((name, sas)) = &prompt {
        let pr = Pairing {
            who: "host",
            name,
            sas,
            expires_ms: s
                .pairing
                .as_ref()
                .filter(|p| p.expires_ms > 0)
                .map(|p| p.expires_ms),
            keys: &[("y", "codes match"), ("n", "they differ")],
            hint: "compare with the code shown on the host",
        };
        pairing_card(f, area, &pr, vs);
    }
}

fn draw_tiny(buf: &mut Buffer, area: Rect, s: &UiSnapshot, vs: &ViewState) {
    let t = &vs.theme;
    let r = area.right();
    let mut y = area.y;
    let mut line = |buf: &mut Buffer, f: &dyn Fn(&mut Buffer, u16)| {
        if y < area.bottom() {
            f(buf, y);
            y += 1;
        }
    };
    line(buf, &|buf, y| {
        let x = wordmark(buf, area.x, y, r, s, t);
        put(buf, x + 1, y, &project(s), r, t.bold);
    });
    line(buf, &|buf, y| {
        draw_badge(buf, area.x, y, r, &badge(s, vs), t);
    });
    let prompt = guest_prompt(s);
    if let Some((_, sas)) = &prompt {
        line(buf, &|buf, y| {
            let x = put(buf, area.x, y, "code ", r, t.dim);
            gradient(buf, x, y, &sas_text(sas), r, t, t.bold);
        });
    }
    let hint = match (s.role, &prompt, vs.confirm_revoke) {
        (_, _, Some(_)) => "y revoke, any key cancels",
        (Role::Host, Some(_), _) => "a accept  r reject",
        (Role::Guest, Some(_), _) => "y match  n differ",
        _ => "q quit",
    };
    line(buf, &|buf, y| {
        put(buf, area.x, y, hint, r, t.dim);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Name, Notice, RelPath};
    use crate::tui::{FoundHost, PairPrompt, PeerIo, PeerView};
    use ratatui::{Terminal, backend::TestBackend};
    use std::time::Duration;

    #[test]
    fn clean_strips_terminal_escapes_and_bidi() {
        assert_eq!(clean("a\x1b[2Jb\x07c\u{202e}d\r\n", 50), "a[2Jbcd");
        assert_eq!(clean("\u{9b}31m", 50), "31m");
        assert_eq!(clean("abcdef", 4), "abc…");
        assert_eq!(clean("abcd", 4), "abcd");
        assert_eq!(sas_text(b"ABCD\x1bFGH"), "ABCD-?FGH");
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(fmt_count(1_234_567), "1,234,567");
        assert_eq!(fmt_count(12), "12");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_rtt(1500), "1.5 ms");
        assert_eq!(fmt_rtt(25_000), "25 ms");
        assert_eq!(fmt_utc(3_723_000), "01:02:03");
    }

    const EVIL: &str = "vm\x1b[31m\u{202e}\x07";

    fn notice(path: &str) -> Notice {
        Notice {
            kind: NoticeKind::Refused,
            path: RelPath::new(path).unwrap(),
        }
    }

    fn peer(id: u64, state: ConnState) -> PeerView {
        PeerView {
            id,
            name: Name::new(EVIL).unwrap(),
            fpr: [1; 8],
            state,
            rtt_us: 300,
        }
    }

    fn snaps() -> Vec<UiSnapshot> {
        let mut out = Vec::new();
        let mut host = UiSnapshot::new(Role::Host);
        host.project = Some(Name::new("proj\x1b]0;pwn\x07").unwrap());
        host.root = Some("/Users/someone/Projects/\x1b[2Jdeep/nested/code".into());
        host.listen = Some("127.0.0.1:47480".parse().unwrap());
        out.push(host.clone());
        host.peers.push(peer(1, ConnState::Live));
        host.peers
            .push(peer(2, ConnState::Syncing { done: 5, total: 9 }));
        host.io.push(PeerIo {
            id: 1,
            tx: 10,
            rx: 20,
            pending: 2,
        });
        host.push_notice(5_000, notice("src/\x1b[2Jmain.rs"));
        host.hint("pairing is disabled (--no-pair): only trusted guests can connect");
        out.push(host.clone());
        host.pairing = Some(PairPrompt {
            peer: 2,
            name: Name::new(EVIL).unwrap(),
            sas: *b"AB3D7FGH",
            expires_ms: 60_000,
        });
        out.push(host);
        let mut guest = UiSnapshot::new(Role::Guest);
        guest.discovering = true;
        out.push(guest.clone());
        guest.hosts.push(FoundHost {
            label: Name::new(EVIL).unwrap(),
            addr: "10.0.0.2:47480".parse().unwrap(),
            fpr: [2; 8],
            paired: true,
        });
        out.push(guest.clone());
        guest.discovering = false;
        guest.host_addr = Some("10.0.0.2:47480".parse().unwrap());
        guest.mount = Some("/home/\x1b[2Jme/proj".into());
        out.push(guest.clone());
        for st in [
            ConnState::Pairing { sas: *b"Z9Y8X7W6" },
            ConnState::Syncing { done: 3, total: 7 },
            ConnState::Live,
            ConnState::Disconnected { since_ms: 1_000 },
        ] {
            guest.peers = vec![peer(9, st)];
            out.push(guest.clone());
        }
        guest.mounted = true;
        guest.guest.prefetch_total = 10;
        guest.guest.prefetch_done = 4;
        guest.guest.inflight = 3;
        guest.stats.skew_ms = 4000;
        guest.peers = vec![peer(9, ConnState::Live)];
        guest.push_notice(5_000, notice("a\u{202e}b"));
        out.push(guest);
        out
    }

    fn render(s: &UiSnapshot, vs: &mut ViewState, w: u16, h: u16) -> Buffer {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        vs.observe(s, vs.t, 6_000);
        term.draw(|f| draw(f, s, vs)).unwrap();
        term.backend().buffer().clone()
    }

    #[test]
    fn every_state_lays_out_at_every_size_without_escapes() {
        let now = Instant::now();
        let sizes = (1..=200u16)
            .step_by(7)
            .flat_map(|w| (1..=60u16).step_by(5).map(move |h| (w, h)));
        for depth in [Depth::True, Depth::Mono] {
            for s in snaps() {
                for (w, h) in sizes.clone().chain([(60, 16), (80, 24), (200, 60), (1, 1)]) {
                    let mut vs = ViewState::new(depth, now);
                    let buf = render(&s, &mut vs, w, h);
                    for c in &buf.content {
                        assert!(
                            !c.symbol().chars().any(is_hidden_char),
                            "{:?} {w}x{h}: {:?}",
                            s.role,
                            c.symbol()
                        );
                    }
                }
            }
        }
    }

    fn text(buf: &Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn host_text_keeps_one_column_of_padding_inside_borders() {
        let s = &snaps()[1];
        let mut vs = ViewState::new(Depth::True, Instant::now());
        let buf = render(s, &mut vs, 80, 24);
        for y in 0..24u16 {
            let row: Vec<&str> = (0..80).map(|x| buf[(x, y)].symbol()).collect();
            if row[0] == "│" {
                assert_eq!(
                    row[1],
                    " ",
                    "row {y} touches the left border: {}",
                    text(&buf)
                );
                assert_eq!(row[78], " ", "row {y} touches the right border");
            }
        }
        let t = text(&buf);
        assert!(
            t.contains("csync host") && t.contains("Guests") && t.contains("Activity"),
            "{t}"
        );
        assert!(t.contains("[2Jmain.rs") && t.contains("refused"), "{t}");
    }

    #[test]
    fn pairing_code_is_shown_large_and_keys_are_offered() {
        let s = &snaps()[2];
        let mut vs = ViewState::new(Depth::True, Instant::now());
        let t = text(&render(s, &mut vs, 100, 30));
        assert!(t.contains("Pairing request"), "{t}");
        assert!(t.contains("a accept") && t.contains("r reject"), "{t}");
        assert!(t.matches(['█', '▀', '▄']).count() > 80, "{t}");
        let small = text(&render(s, &mut vs, 40, 12));
        assert!(small.contains("A B 3 D - 7 F G H"), "{small}");
        let tiny = text(&render(s, &mut vs, 30, 6));
        assert!(
            tiny.contains("AB3D-7FGH") && tiny.contains("a accept"),
            "{tiny}"
        );
    }

    #[test]
    fn guest_phases_map_to_scenes() {
        let all = snaps();
        let vs = ViewState::new(Depth::True, Instant::now());
        let area = Rect::new(0, 0, 80, 24);
        let scenes: Vec<Scene> = all[3..].iter().map(|s| scene(s, &vs, area)).collect();
        assert_eq!(
            scenes,
            [
                Scene::GuestPick,
                Scene::GuestPick,
                Scene::GuestSetup,
                Scene::GuestPrompt,
                Scene::GuestSetup,
                Scene::GuestSetup,
                Scene::GuestLive,
                Scene::GuestLive,
            ]
        );
        assert_eq!(phase(&all[8]), Phase::Mount);
        assert_eq!(phase(&all[10]), Phase::Warm);
        assert_eq!(scene(&all[0], &vs, Rect::new(0, 0, 20, 20)), Scene::Tiny);
    }

    #[test]
    fn flows_sample_while_busy_and_go_quiet_after() {
        let t0 = Instant::now();
        let mut f = Flow::default();
        f.observe(t0, 0, 0);
        assert_eq!(f.due(), None);
        f.observe(t0 + Duration::from_secs(60), 0, 4096);
        assert_eq!(f.rates(), (0.0, 4096.0));
        let mut ticks = 0;
        while let Some(d) = f.due() {
            f.observe(d, 0, 4096);
            ticks += 1;
            assert!(ticks <= anim::HISTORY, "never went idle");
        }
        assert_eq!(ticks, anim::HISTORY);
        assert_eq!(f.rates(), (0.0, 0.0));
    }

    #[test]
    fn idle_live_host_has_no_deadline_but_animations_do() {
        let t0 = Instant::now();
        let mut s = snaps()[1].clone();
        s.peers.truncate(1);
        let mut vs = ViewState::new(Depth::True, t0);
        vs.observe(&s, t0, 10_000);
        assert!(vs.deadline(&s).is_some(), "a new guest should pulse");
        let later = t0 + Duration::from_secs(3);
        vs.observe(&s, later, 13_000);
        assert_eq!(vs.deadline(&s), None);
        s.stats.commits += 5;
        vs.observe(&s, later, 13_000);
        assert_eq!(vs.deadline(&s), Some(later + FRAME));
        vs.observe(&s, later + Duration::from_secs(1), 14_000);
        assert_eq!(vs.deadline(&s), None);
        s.push_notice(14_000, notice("x"));
        assert!(vs.deadline(&s).is_some());
        vs.observe(&s, later + Duration::from_secs(2), 15_100);
        assert_eq!(vs.deadline(&s), None);
        s.peers.clear();
        vs.observe(&s, later + Duration::from_secs(3), 16_000);
        let d = vs.deadline(&s).expect("waiting host spins");
        assert!(d <= vs.t + anim::SPIN);
    }

    #[test]
    fn unfocused_sleeps_and_long_idle_slows_the_spinner() {
        let t0 = Instant::now();
        let s = UiSnapshot::new(Role::Host);
        let mut vs = ViewState::new(Depth::True, t0);
        let t1 = t0 + Duration::from_secs(5);
        vs.observe(&s, t1, 5_000);
        let d = vs.deadline(&s).expect("waiting host spins");
        assert!(d > t1 && d <= t1 + SPIN, "{d:?}");
        vs.focused = false;
        assert_eq!(vs.deadline(&s), None);
        vs.focused = true;
        let t2 = t0 + IDLE_AFTER + Duration::from_millis(10);
        vs.observe(&s, t2, 40_000);
        let d = vs.deadline(&s).unwrap();
        assert!(d > t2 + SPIN && d <= t2 + SPIN_IDLE, "{:?}", d - t2);
        assert_eq!(d.saturating_duration_since(t0).as_millis() % 500, 0);
        vs.touch(t2);
        let d = vs.deadline(&s).unwrap();
        assert!(d <= t2 + SPIN);
        let mut busy = s.clone();
        busy.stats.commits = 3;
        vs.observe(&busy, t2 + Duration::from_secs(40), 80_000);
        vs.observe(&busy, t2 + Duration::from_secs(41), 81_000);
        assert!(vs.spin_period() == SPIN_IDLE);
        vs.focused = false;
        busy.stats.commits = 4;
        vs.observe(&busy, t2 + Duration::from_secs(42), 82_000);
        assert_eq!(
            vs.deadline(&busy),
            None,
            "tweens do not wake an unfocused terminal"
        );
    }
}
