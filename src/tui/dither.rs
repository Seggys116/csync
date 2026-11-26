use ratatui::{
    buffer::{Buffer, Cell},
    style::{Color, Modifier},
    text::Span,
};

const BAYER8: [[u8; 8]; 8] = [
    [0, 32, 8, 40, 2, 34, 10, 42],
    [48, 16, 56, 24, 50, 18, 58, 26],
    [12, 44, 4, 36, 14, 46, 6, 38],
    [60, 28, 52, 20, 62, 30, 54, 22],
    [3, 35, 11, 43, 1, 33, 9, 41],
    [51, 19, 59, 27, 49, 17, 57, 25],
    [15, 47, 7, 39, 13, 45, 5, 37],
    [63, 31, 55, 23, 61, 29, 53, 21],
];

// width of the shade band each cell passes through, in units of t
const BAND: f32 = 0.35;

fn threshold(x: u16, y: u16) -> f32 {
    (f32::from(BAYER8[usize::from(y & 7)][usize::from(x & 7)]) + 0.5) / 64.0
}

// 0 shows the previous cell, 1 the next one, anything between is a shade step
pub fn stage(x: u16, y: u16, t: f32) -> f32 {
    ((t.clamp(0.0, 1.0) * (1.0 + BAND) - threshold(x, y)) / BAND).clamp(0.0, 1.0)
}

fn mix(a: Color, b: Color, u: f32) -> Color {
    match (a, b) {
        (Color::Rgb(r0, g0, b0), Color::Rgb(r1, g1, b1)) => {
            let l = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * u).round() as u8;
            Color::Rgb(l(r0, r1), l(g0, g1), l(b0, b1))
        }
        _ if u < 0.5 => a,
        _ => b,
    }
}

fn blank(c: &Cell) -> bool {
    c.symbol().trim().is_empty()
}

fn wide(c: &Cell) -> u16 {
    Span::raw(c.symbol()).width().clamp(1, 2) as u16
}

fn shade(cell: &mut Cell, prev: &Cell, next: &Cell, u: f32) {
    let fg = match (blank(prev), blank(next)) {
        (false, true) => prev.fg,
        (true, false) => next.fg,
        _ => mix(prev.fg, next.fg, u),
    };
    let bg = mix(prev.bg, next.bg, u);
    cell.reset();
    cell.set_symbol(if u < 0.5 { "▒" } else { "░" });
    cell.fg = fg;
    cell.bg = bg;
    if fg == Color::Reset {
        cell.modifier = Modifier::DIM;
    }
}

// ordered-dither dissolve from prev into next, written in place over next
pub fn blend_into(prev: &Buffer, next: &mut Buffer, t: f32) {
    if prev.area != next.area || t >= 1.0 {
        return;
    }
    let area = next.area;
    for y in area.top()..area.bottom() {
        let mut x = area.left();
        while x < area.right() {
            let i = next.index_of(x, y);
            let span = wide(&prev.content[i])
                .max(wide(&next.content[i]))
                .min(area.right() - x);
            let u = stage(x - area.left(), y - area.top(), t);
            let quiet = blank(&prev.content[i])
                && blank(&next.content[i])
                && prev.content[i].bg == next.content[i].bg;
            for k in 0..span {
                let j = i + usize::from(k);
                if u <= 0.0 {
                    next.content[j].clone_from(&prev.content[j]);
                } else if u < 1.0 && !quiet {
                    let (p, n) = (prev.content[j].clone(), next.content[j].clone());
                    shade(&mut next.content[j], &p, &n, u);
                }
            }
            x += span;
        }
    }
}

pub fn dither(prev: &Buffer, next: &Buffer, t: f32) -> Buffer {
    let mut out = next.clone();
    blend_into(prev, &mut out, t);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{layout::Rect, style::Style};

    fn bufs() -> (Buffer, Buffer) {
        let area = Rect::new(0, 0, 37, 11);
        let mut a = Buffer::empty(area);
        let mut b = Buffer::empty(area);
        for y in 0..11 {
            let red = Style::new().fg(Color::Rgb(200, 10, 10));
            let blue = Style::new().fg(Color::Rgb(10, 10, 200));
            a.set_string(0, y, "the quick brown fox jumps over a lazy", red);
            b.set_string(0, y, "PACK MY BOX WITH FIVE DOZEN JUGS  ok!", blue);
        }
        b.set_string(3, 4, "日本語", Style::new());
        (a, b)
    }

    fn matches(out: &Buffer, want: &Buffer) -> usize {
        out.content
            .iter()
            .zip(&want.content)
            .filter(|(x, y)| x == y)
            .count()
    }

    #[test]
    fn endpoints_are_exact() {
        let (a, b) = bufs();
        assert_eq!(dither(&a, &b, 0.0), a);
        assert_eq!(dither(&a, &b, 1.0), b);
        assert_eq!(dither(&a, &b, -3.0), a);
    }

    #[test]
    fn coverage_of_next_grows_monotonically() {
        let (a, b) = bufs();
        let mut last = 0;
        let mut saw_shade = false;
        for i in 0..=100 {
            let out = dither(&a, &b, i as f32 / 100.0);
            let n = matches(&out, &b);
            assert!(n >= last, "step {i}: {n} < {last}");
            last = n;
            for ((o, p), q) in out.content.iter().zip(&a.content).zip(&b.content) {
                let shaded = matches!(o.symbol(), "▒" | "░");
                saw_shade |= shaded;
                assert!(o == p || o == q || shaded, "step {i}: stray cell {o:?}");
            }
        }
        assert!(saw_shade);
        assert_eq!(last, b.content.len());
    }

    #[test]
    fn wide_glyphs_stay_paired() {
        let (a, b) = bufs();
        for i in 0..=40 {
            let out = dither(&a, &b, i as f32 / 40.0);
            for x in [3u16, 5, 7] {
                let lead = &out[(x, 4)];
                if ["日", "本", "語"].contains(&lead.symbol()) {
                    assert_eq!(out[(x + 1, 4)], b[(x + 1, 4)], "t={i} x={x}");
                }
            }
        }
    }

    #[test]
    fn mismatched_areas_show_next() {
        let (a, _) = bufs();
        let b = Buffer::empty(Rect::new(0, 0, 5, 5));
        assert_eq!(dither(&a, &b, 0.3), b);
    }
}
