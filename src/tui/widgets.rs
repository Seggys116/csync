use super::anim::{EIGHTHS, Hist, SPARK, spark_level};
use super::theme::{Rgb, Theme};
use ratatui::{buffer::Buffer, layout::Rect, style::Style, text::Span};

pub fn str_width(s: &str) -> usize {
    Span::raw(s).width()
}

fn char_width(c: char) -> usize {
    let mut b = [0u8; 4];
    str_width(c.encode_utf8(&mut b))
}

// keeps the head and the tail, which carry the most meaning in paths
pub fn mid_trunc(s: &str, max: usize) -> String {
    if str_width(s) <= max {
        return s.to_owned();
    }
    if max == 0 {
        return String::new();
    }
    let keep = max - 1;
    let head_w = keep - keep / 2;
    let mut head = String::with_capacity(max * 2);
    let mut w = 0;
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw > head_w {
            break;
        }
        head.push(c);
        w += cw;
    }
    let tail_w = keep - w;
    let mut tail: Vec<char> = Vec::with_capacity(tail_w);
    let mut tw = 0;
    for c in s.chars().rev() {
        let cw = char_width(c);
        if tw + cw > tail_w {
            break;
        }
        tail.push(c);
        tw += cw;
    }
    head.push('…');
    head.extend(tail.into_iter().rev());
    head
}

// writes clipped to both the buffer and the given right edge; returns the next column
pub fn put(buf: &mut Buffer, x: u16, y: u16, s: &str, right: u16, style: Style) -> u16 {
    let a = buf.area;
    let right = right.min(a.right());
    if y < a.top() || y >= a.bottom() || x < a.left() || x >= right {
        return x;
    }
    buf.set_stringn(x, y, s, usize::from(right - x), style).0
}

pub fn put_right(buf: &mut Buffer, area: Rect, y: u16, s: &str, style: Style) -> u16 {
    let w = (str_width(s) as u16).min(area.width);
    let x = area.right() - w;
    put(buf, x, y, s, area.right(), style);
    x
}

pub fn gradient(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    s: &str,
    right: u16,
    t: &Theme,
    base: Style,
) -> u16 {
    let n = s.chars().count().max(2) - 1;
    let mut cx = x;
    let mut b = [0u8; 4];
    for (i, c) in s.chars().enumerate() {
        let st = base.patch(t.grad(i as f32 / n as f32));
        cx = put(buf, cx, y, c.encode_utf8(&mut b), right, st);
    }
    cx
}

pub enum Fill {
    Gradient,
    Solid(Rgb),
}

// smooth horizontal bar with eighth-cell precision
pub fn bar(buf: &mut Buffer, area: Rect, ratio: f64, t: &Theme, fill: &Fill) {
    let w = usize::from(area.width);
    if w == 0 || area.height == 0 || area.y >= buf.area.bottom() {
        return;
    }
    let eighths = (ratio.clamp(0.0, 1.0) * (w * 8) as f64).round() as usize;
    let (full, part) = (eighths / 8, eighths % 8);
    let track = t.track();
    let y = area.y;
    for i in 0..w {
        let x = area.x + i as u16;
        if x >= buf.area.right() {
            break;
        }
        let colour = match fill {
            Fill::Gradient => Theme::grad_rgb(i as f32 / (w.max(2) - 1) as f32),
            Fill::Solid(c) => *c,
        };
        let cell = &mut buf[(x, y)];
        cell.reset();
        if i < full || (i == full && part > 0) {
            let glyph = if i < full { "█" } else { EIGHTHS[part - 1] };
            cell.set_symbol(glyph);
            cell.set_style(t.fg(colour));
            if let Some(bg) = track {
                cell.bg = bg;
            }
        } else if let Some(bg) = track {
            cell.bg = bg;
        } else {
            cell.set_symbol("·");
            cell.set_style(t.faint);
        }
    }
}

// a bright head sweeping along the track, for waits with no known length
pub fn sweep(buf: &mut Buffer, area: Rect, phase: f32, t: &Theme) {
    let w = area.width;
    if w == 0 || area.y >= buf.area.bottom() {
        return;
    }
    let head = phase.fract() * (f32::from(w) + 8.0) - 4.0;
    let track = t.track();
    for i in 0..w {
        let x = area.x + i;
        if x >= buf.area.right() {
            break;
        }
        let d = (f32::from(i) - head).abs();
        let cell = &mut buf[(x, area.y)];
        cell.reset();
        if let Some(bg) = track {
            cell.bg = bg;
        }
        if d < 4.0 {
            let glow = 1.0 - d / 4.0;
            cell.set_symbol(if glow > 0.5 { "█" } else { "▓" });
            let c = Theme::grad_rgb(f32::from(i) / f32::from(w.max(2) - 1));
            let rgb = super::theme::TRACK.mix(c, glow);
            cell.set_style(t.fg(rgb));
            if t.mono() {
                cell.set_symbol(if glow > 0.5 { "█" } else { "░" });
            }
        } else if track.is_none() {
            cell.set_symbol("·");
            cell.set_style(t.faint);
        }
    }
}

// newest sample on the right; zero samples draw as a faint baseline
pub fn spark(buf: &mut Buffer, area: Rect, h: &Hist, max: f32, t: &Theme, colour: Option<Rgb>) {
    let w = usize::from(area.width);
    if w == 0 || area.y >= buf.area.bottom() {
        return;
    }
    let n = h.len().min(w);
    let first = h.len() - n;
    for i in 0..w {
        let x = area.x + i as u16;
        if x >= buf.area.right() {
            break;
        }
        let slot = (i + n).checked_sub(w).map(|k| h.get(first + k));
        let cell = &mut buf[(x, area.y)];
        match slot.and_then(|v| spark_level(v, max)) {
            Some(l) => {
                let c = colour.unwrap_or_else(|| Theme::grad_rgb(l as f32 / 7.0));
                cell.set_symbol(SPARK[l]).set_style(t.fg(c));
            }
            None => {
                cell.set_symbol("▁").set_style(t.faint);
            }
        }
    }
}

const GLYPHS: [(char, [&str; 5]); 37] = [
    ('0', [".###.", "#..##", "#.#.#", "##..#", ".###."]),
    ('1', ["..#..", ".##..", "..#..", "..#..", ".###."]),
    ('2', ["####.", "....#", ".###.", "#....", "#####"]),
    ('3', ["####.", "....#", ".###.", "....#", "####."]),
    ('4', ["#..#.", "#..#.", "#####", "...#.", "...#."]),
    ('5', ["#####", "#....", "####.", "....#", "####."]),
    ('6', [".###.", "#....", "####.", "#...#", ".###."]),
    ('7', ["#####", "...#.", "..#..", ".#...", ".#..."]),
    ('8', [".###.", "#...#", ".###.", "#...#", ".###."]),
    ('9', [".###.", "#...#", ".####", "....#", ".###."]),
    ('A', [".###.", "#...#", "#####", "#...#", "#...#"]),
    ('B', ["####.", "#...#", "####.", "#...#", "####."]),
    ('C', [".####", "#....", "#....", "#....", ".####"]),
    ('D', ["####.", "#...#", "#...#", "#...#", "####."]),
    ('E', ["#####", "#....", "####.", "#....", "#####"]),
    ('F', ["#####", "#....", "####.", "#....", "#...."]),
    ('G', [".####", "#....", "#..##", "#...#", ".###."]),
    ('H', ["#...#", "#...#", "#####", "#...#", "#...#"]),
    ('I', [".###.", "..#..", "..#..", "..#..", ".###."]),
    ('J', ["..###", "...#.", "...#.", "#..#.", ".##.."]),
    ('K', ["#..#.", "#.#..", "##...", "#.#..", "#..#."]),
    ('L', ["#....", "#....", "#....", "#....", "#####"]),
    ('M', ["#...#", "##.##", "#.#.#", "#...#", "#...#"]),
    ('N', ["#...#", "##..#", "#.#.#", "#..##", "#...#"]),
    ('O', [".###.", "#...#", "#...#", "#...#", ".###."]),
    ('P', ["####.", "#...#", "####.", "#....", "#...."]),
    ('Q', [".###.", "#...#", "#.#.#", "#..#.", ".##.#"]),
    ('R', ["####.", "#...#", "####.", "#..#.", "#...#"]),
    ('S', [".####", "#....", ".###.", "....#", "####."]),
    ('T', ["#####", "..#..", "..#..", "..#..", "..#.."]),
    ('U', ["#...#", "#...#", "#...#", "#...#", ".###."]),
    ('V', ["#...#", "#...#", "#...#", ".#.#.", "..#.."]),
    ('W', ["#...#", "#...#", "#.#.#", "##.##", "#...#"]),
    ('X', ["#...#", ".#.#.", "..#..", ".#.#.", "#...#"]),
    ('Y', ["#...#", ".#.#.", "..#..", "..#..", "..#.."]),
    ('Z', ["#####", "...#.", "..#..", ".#...", "#####"]),
    ('?', [".###.", "#...#", "..##.", ".....", "..#.."]),
];
const DASH: [&str; 5] = ["...", "...", "###", "...", "..."];

fn glyph(c: char) -> Option<&'static [&'static str; 5]> {
    if c == '-' {
        return Some(&DASH);
    }
    GLYPHS.iter().find(|(g, _)| *g == c).map(|(_, rows)| rows)
}

pub const BIG_ROWS: u16 = 3;

pub fn big_width(text: &str) -> Option<u16> {
    let mut w = 0u16;
    for (i, c) in text.chars().enumerate() {
        w += glyph(c)?[0].len() as u16 + u16::from(i > 0);
    }
    Some(w)
}

// five-pixel-tall glyphs folded into three rows of half blocks, shaded with the accent gradient
pub fn big_text(buf: &mut Buffer, x: u16, y: u16, text: &str, t: &Theme, shine: f32) {
    let Some(total) = big_width(text) else {
        return;
    };
    let mut cx = x;
    for (i, c) in text.chars().enumerate() {
        let Some(g) = glyph(c) else {
            return;
        };
        if i > 0 {
            cx += 1;
        }
        let gw = g[0].len() as u16;
        for col in 0..gw {
            let pos = f32::from(cx + col - x) / f32::from(total.max(2) - 1);
            let mut rgb = Theme::grad_rgb(pos);
            let glint = 1.0 - ((pos - shine).abs() * 6.0).min(1.0);
            rgb = rgb.mix(super::theme::WHITE, glint * 0.55);
            let style = t.fg(rgb);
            for row in 0..BIG_ROWS {
                let px = |r: usize| {
                    g.get(r)
                        .is_some_and(|l| l.as_bytes()[usize::from(col)] == b'#')
                };
                let (top, bot) = (px(usize::from(row) * 2), px(usize::from(row) * 2 + 1));
                let sym = match (top, bot) {
                    (true, true) => "█",
                    (true, false) => "▀",
                    (false, true) => "▄",
                    (false, false) => continue,
                };
                put(buf, cx + col, y + row, sym, cx + col + 1, style);
            }
        }
        cx += gw;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::Depth;

    fn row(buf: &Buffer, y: u16) -> String {
        (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect()
    }

    #[test]
    fn middle_truncation_keeps_both_ends_and_fits() {
        assert_eq!(mid_trunc("/a/b", 10), "/a/b");
        let s = mid_trunc("/Users/someone/Projects/Rust/code-syncer", 20);
        assert_eq!(str_width(&s), 20);
        assert!(s.starts_with("/Users/som") && s.ends_with("de-syncer") && s.contains('…'));
        assert_eq!(str_width(&mid_trunc("日本語日本語日本語", 7)), 7);
        assert_eq!(mid_trunc("abc", 0), "");
        assert_eq!(mid_trunc("abcdef", 1), "…");
    }

    #[test]
    fn bar_resolves_eighths_of_a_cell() {
        let t = Theme::new(Depth::Mono);
        let mut buf = Buffer::empty(Rect::new(0, 0, 10, 1));
        bar(
            &mut buf,
            Rect::new(0, 0, 10, 1),
            0.4625,
            &t,
            &Fill::Gradient,
        );
        assert_eq!(row(&buf, 0), "████▋·····");
        bar(&mut buf, Rect::new(0, 0, 10, 1), 1.0, &t, &Fill::Gradient);
        assert_eq!(row(&buf, 0), "██████████");
        bar(&mut buf, Rect::new(0, 0, 10, 1), -1.0, &t, &Fill::Gradient);
        assert_eq!(row(&buf, 0), "··········");
    }

    #[test]
    fn big_code_renders_every_sas_symbol() {
        let t = Theme::new(Depth::True);
        let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        assert_eq!(big_width("ABCD-EFGH"), Some(8 * 5 + 3 + 8));
        assert_eq!(big_width("ab"), None);
        for c in alphabet.chars() {
            let s = c.to_string();
            let mut buf = Buffer::empty(Rect::new(0, 0, 5, 3));
            big_text(&mut buf, 0, 0, &s, &t, 0.0);
            let ink = buf.content.iter().filter(|c| c.symbol() != " ").count();
            assert!(ink >= 5, "{c} drew {ink} cells");
        }
        let mut buf = Buffer::empty(Rect::new(0, 0, 5, 3));
        big_text(&mut buf, 0, 0, "1", &t, 0.0);
        assert_eq!(row(&buf, 0), " ▄█  ");
        assert_eq!(row(&buf, 2), " ▀▀▀ ");
    }

    #[test]
    fn spark_draws_newest_on_the_right() {
        let t = Theme::new(Depth::Mono);
        let mut h = Hist::default();
        for v in [0.0, 1.0, 8.0] {
            h.push(v);
        }
        let mut buf = Buffer::empty(Rect::new(0, 0, 5, 1));
        spark(&mut buf, Rect::new(0, 0, 5, 1), &h, h.max(), &t, None);
        assert_eq!(row(&buf, 0), "▁▁▁▁█");
        let mut buf = Buffer::empty(Rect::new(0, 0, 2, 1));
        spark(&mut buf, Rect::new(0, 0, 2, 1), &h, h.max(), &t, None);
        assert_eq!(row(&buf, 0), "▁█");
    }
}
