use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    Mono,
    Ansi16,
    Ansi256,
    True,
}

impl Depth {
    pub fn detect() -> Self {
        let var = |k: &str| std::env::var(k).ok();
        Self::from_env(
            var("NO_COLOR").as_deref(),
            var("COLORTERM").as_deref(),
            var("TERM").as_deref(),
        )
    }

    pub fn from_env(no_color: Option<&str>, colorterm: Option<&str>, term: Option<&str>) -> Self {
        if no_color.is_some_and(|v| !v.is_empty()) || term == Some("dumb") {
            return Self::Mono;
        }
        let ct = colorterm.unwrap_or("").to_ascii_lowercase();
        if ct == "truecolor" || ct == "24bit" {
            return Self::True;
        }
        let term = term.unwrap_or("");
        const RICH: [&str; 5] = ["kitty", "alacritty", "foot", "wezterm", "ghostty"];
        if term.contains("256") || term.contains("direct") || RICH.iter().any(|n| term.contains(n))
        {
            Self::Ansi256
        } else {
            Self::Ansi16
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    pub fn mix(self, o: Self, t: f32) -> Self {
        let t = t.clamp(0.0, 1.0);
        let l = |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * t).round() as u8;
        Self(l(self.0, o.0), l(self.1, o.1), l(self.2, o.2))
    }

    fn dist(self, o: Self) -> u32 {
        let d = |a: u8, b: u8| (i32::from(a) - i32::from(b)).unsigned_abs();
        let (r, g, b) = (d(self.0, o.0), d(self.1, o.1), d(self.2, o.2));
        2 * r * r + 4 * g * g + 3 * b * b
    }
}

pub const TEAL: Rgb = Rgb(45, 212, 191);
pub const VIOLET: Rgb = Rgb(167, 139, 250);
pub const OK: Rgb = Rgb(74, 222, 128);
pub const WARN: Rgb = Rgb(251, 191, 36);
pub const ERR: Rgb = Rgb(248, 113, 113);
pub const INFO: Rgb = Rgb(96, 165, 250);
pub const TEXT: Rgb = Rgb(214, 219, 229);
pub const DIM: Rgb = Rgb(128, 136, 153);
pub const FAINT: Rgb = Rgb(62, 68, 84);
pub const TRACK: Rgb = Rgb(42, 46, 58);
pub const WHITE: Rgb = Rgb(250, 250, 255);

const ANSI16: [(Color, Rgb); 14] = [
    (Color::Red, Rgb(205, 49, 49)),
    (Color::Green, Rgb(13, 188, 121)),
    (Color::Yellow, Rgb(229, 229, 16)),
    (Color::Blue, Rgb(36, 114, 200)),
    (Color::Magenta, Rgb(188, 63, 188)),
    (Color::Cyan, Rgb(17, 168, 205)),
    (Color::Gray, Rgb(204, 204, 204)),
    (Color::DarkGray, Rgb(102, 102, 102)),
    (Color::LightRed, Rgb(241, 76, 76)),
    (Color::LightGreen, Rgb(35, 209, 139)),
    (Color::LightYellow, Rgb(245, 245, 67)),
    (Color::LightBlue, Rgb(59, 142, 234)),
    (Color::LightMagenta, Rgb(214, 112, 214)),
    (Color::LightCyan, Rgb(41, 184, 219)),
];

fn cube(v: u8) -> (u8, u8) {
    const STEPS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let i = STEPS
        .iter()
        .enumerate()
        .min_by_key(|(_, s)| (i32::from(**s) - i32::from(v)).unsigned_abs())
        .map_or(0, |(i, _)| i);
    (i as u8, STEPS[i])
}

fn xterm256(c: Rgb) -> u8 {
    let ((ri, rv), (gi, gv), (bi, bv)) = (cube(c.0), cube(c.1), cube(c.2));
    let cube_idx = 16 + 36 * ri + 6 * gi + bi;
    let avg = ((u16::from(c.0) + u16::from(c.1) + u16::from(c.2)) / 3) as u8;
    let gi = (avg.saturating_sub(3) / 10).min(23);
    let gray = 8 + 10 * gi;
    if Rgb(gray, gray, gray).dist(c) < Rgb(rv, gv, bv).dist(c) {
        232 + gi
    } else {
        cube_idx
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub depth: Depth,
    pub text: Style,
    pub bold: Style,
    pub dim: Style,
    pub faint: Style,
    pub border: Style,
    pub ok: Style,
    pub warn: Style,
    pub err: Style,
    pub info: Style,
    pub accent: Style,
    pub sel: Style,
    pub key: Style,
}

impl Theme {
    pub fn new(depth: Depth) -> Self {
        let mut t = Self {
            depth,
            text: Style::new(),
            bold: Style::new().add_modifier(Modifier::BOLD),
            dim: Style::new(),
            faint: Style::new(),
            border: Style::new(),
            ok: Style::new(),
            warn: Style::new(),
            err: Style::new(),
            info: Style::new(),
            accent: Style::new(),
            sel: Style::new(),
            key: Style::new(),
        };
        if depth == Depth::Mono {
            t.dim = Style::new().add_modifier(Modifier::DIM);
            t.faint = t.dim;
            t.ok = t.bold;
            t.warn = t.bold;
            t.err = t.bold.add_modifier(Modifier::UNDERLINED);
            t.info = Style::new();
            t.accent = t.bold;
            t.sel = Style::new().add_modifier(Modifier::REVERSED);
            t.key = t.bold;
            return t;
        }
        t.dim = Style::new().fg(t.color(DIM));
        t.faint = Style::new().fg(t.color(FAINT));
        t.border = Style::new().fg(t.color(FAINT));
        t.ok = Style::new().fg(t.color(OK));
        t.warn = Style::new().fg(t.color(WARN));
        t.err = Style::new().fg(t.color(ERR));
        t.info = Style::new().fg(t.color(INFO));
        t.accent = Style::new().fg(t.color(TEAL));
        t.key = Style::new().fg(t.color(TEAL)).add_modifier(Modifier::BOLD);
        t.sel = if depth == Depth::Ansi16 {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new().bg(t.color(TRACK))
        };
        if depth == Depth::Ansi16 {
            // bright black can equal the background, so dim text and borders avoid it
            t.dim = Style::new().add_modifier(Modifier::DIM);
            t.faint = Style::new().fg(Color::Gray).add_modifier(Modifier::DIM);
            t.border = Style::new().fg(Color::Gray);
        }
        t
    }

    pub fn mono(&self) -> bool {
        self.depth == Depth::Mono
    }

    pub fn color(&self, c: Rgb) -> Color {
        match self.depth {
            Depth::Mono => Color::Reset,
            Depth::True => Color::Rgb(c.0, c.1, c.2),
            Depth::Ansi256 => Color::Indexed(xterm256(c)),
            Depth::Ansi16 => match c {
                TEAL => Color::Cyan,
                WARN => Color::Yellow,
                ERR => Color::Red,
                OK => Color::Green,
                DIM | FAINT => Color::Gray,
                _ => ANSI16
                    .iter()
                    .min_by_key(|(_, rgb)| rgb.dist(c))
                    .map_or(Color::Reset, |(col, _)| *col),
            },
        }
    }

    pub fn fg(&self, c: Rgb) -> Style {
        if self.mono() {
            self.bold
        } else if self.depth == Depth::Ansi16 && c == DIM {
            self.dim
        } else if self.depth == Depth::Ansi16 && c == FAINT {
            self.faint
        } else {
            Style::new().fg(self.color(c))
        }
    }

    pub fn grad_rgb(t: f32) -> Rgb {
        TEAL.mix(VIOLET, t)
    }

    // signature accent gradient, 0 is teal and 1 is violet
    pub fn grad(&self, t: f32) -> Style {
        self.fg(Self::grad_rgb(t))
    }

    // track colour for bars: a background in rich modes, a glyph in poor ones
    pub fn track(&self) -> Option<Color> {
        matches!(self.depth, Depth::True | Depth::Ansi256).then(|| self.color(TRACK))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_detection_honours_no_color_and_dumb() {
        assert_eq!(
            Depth::from_env(Some("1"), Some("truecolor"), Some("xterm-256color")),
            Depth::Mono
        );
        assert_eq!(
            Depth::from_env(Some(""), Some("truecolor"), None),
            Depth::True
        );
        assert_eq!(Depth::from_env(None, None, Some("dumb")), Depth::Mono);
        assert_eq!(
            Depth::from_env(None, Some("24bit"), Some("xterm")),
            Depth::True
        );
        assert_eq!(
            Depth::from_env(None, None, Some("xterm-256color")),
            Depth::Ansi256
        );
        assert_eq!(Depth::from_env(None, None, Some("xterm")), Depth::Ansi16);
    }

    #[test]
    fn modern_terminals_without_colorterm_get_at_least_256_colours() {
        for term in [
            "xterm-kitty",
            "alacritty",
            "foot",
            "wezterm",
            "xterm-ghostty",
            "screen-256color",
        ] {
            assert_eq!(
                Depth::from_env(None, None, Some(term)),
                Depth::Ansi256,
                "{term}"
            );
        }
        assert_eq!(
            Depth::from_env(Some("1"), None, Some("xterm-kitty")),
            Depth::Mono
        );
        assert_eq!(Depth::from_env(None, None, Some("linux")), Depth::Ansi16);
        assert_eq!(Depth::from_env(None, None, None), Depth::Ansi16);
    }

    #[test]
    fn sixteen_colour_accents_use_fixed_roles_and_never_bright_black() {
        let t = Theme::new(Depth::Ansi16);
        assert_eq!(t.color(TEAL), Color::Cyan);
        assert_eq!(t.color(WARN), Color::Yellow);
        assert_eq!(t.color(ERR), Color::Red);
        assert_eq!(t.color(OK), Color::Green);
        assert_eq!(t.accent.fg, Some(Color::Cyan));
        assert_eq!(t.warn.fg, Some(Color::Yellow));
        assert_eq!(t.err.fg, Some(Color::Red));
        assert_eq!(t.ok.fg, Some(Color::Green));
        assert!(t.dim.add_modifier.contains(Modifier::DIM));
        assert!(t.faint.add_modifier.contains(Modifier::DIM));
        assert_ne!(t.border, t.dim);
        assert_ne!(t.border, t.faint);
        assert_ne!(t.dim, t.faint);
        for s in [t.dim, t.faint, t.border] {
            assert_ne!(s.fg, Some(Color::DarkGray));
            assert_ne!(s.fg, Some(Color::Black));
        }
        assert_eq!(t.fg(DIM), t.dim);
        assert_eq!(t.fg(FAINT), t.faint);
    }

    #[test]
    fn true_and_256_colour_styles_are_unchanged() {
        let t = Theme::new(Depth::True);
        assert_eq!(t.dim, Style::new().fg(Color::Rgb(128, 136, 153)));
        assert_eq!(t.border, Style::new().fg(Color::Rgb(62, 68, 84)));
        assert_eq!(t.err.fg, Some(Color::Rgb(248, 113, 113)));
        let t = Theme::new(Depth::Ansi256);
        assert_eq!(t.dim, Style::new().fg(t.color(DIM)));
        assert_eq!(t.border, t.faint);
        assert!(matches!(t.accent.fg, Some(Color::Indexed(_))));
    }

    #[test]
    fn colours_degrade_per_depth() {
        assert_eq!(Theme::new(Depth::Mono).color(TEAL), Color::Reset);
        assert_eq!(
            Theme::new(Depth::True).color(TEAL),
            Color::Rgb(45, 212, 191)
        );
        assert_eq!(
            Theme::new(Depth::Ansi256).color(Rgb(0, 0, 0)),
            Color::Indexed(16)
        );
        assert_eq!(
            Theme::new(Depth::Ansi256).color(Rgb(255, 255, 255)),
            Color::Indexed(231)
        );
        assert_eq!(
            Theme::new(Depth::Ansi256).color(Rgb(128, 128, 128)),
            Color::Indexed(244)
        );
        assert_eq!(Theme::new(Depth::Ansi16).color(ERR), Color::Red);
        assert_eq!(Theme::new(Depth::Ansi16).color(INFO), Color::LightBlue);
        assert_eq!(Rgb(0, 0, 0).mix(Rgb(200, 100, 50), 0.5), Rgb(100, 50, 25));
        assert_eq!(Rgb(0, 0, 0).mix(Rgb(200, 100, 50), 7.0), Rgb(200, 100, 50));
    }
}
