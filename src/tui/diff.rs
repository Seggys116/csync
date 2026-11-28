use super::feed::Entry;
use super::view::{fmt_bytes, is_hidden_char};
use similar::{DiffOp, DiffTag, TextDiff};
use std::{ops::Range, time::Duration};

pub const DIFF_SIDE_MAX: usize = 1024 * 1024;
pub const DIFF_TIMEOUT: Duration = Duration::from_millis(300);
pub const DIFF_LINES_MAX: usize = 2_000;
pub const DIFF_BYTES_MAX: usize = 256 * 1024;
pub const LINE_CHARS_MAX: usize = 1_000;
const CONTEXT_LINES: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Side {
    Bytes(Vec<u8>),
    Absent,
    // content that cannot be had, with the reason to show
    Gone(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sides {
    // where the content came from, shown as is
    pub label: &'static str,
    pub old: Side,
    pub new: Side,
    pub note: Option<&'static str>,
}

pub trait DiffSource: Send + Sync {
    fn sides(&self, e: &Entry) -> Sides;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Context,
    Add,
    Del,
    Hunk,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: Kind,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffView {
    pub label: &'static str,
    pub added: u32,
    pub removed: u32,
    pub lines: Vec<DiffLine>,
    pub cut: Option<String>,
    pub unavailable: Option<String>,
    pub detail: Option<String>,
}

fn bytes_of(s: &Side) -> Option<&[u8]> {
    match s {
        Side::Bytes(b) => Some(b.as_slice()),
        Side::Absent | Side::Gone(_) => None,
    }
}

fn side_text(s: &Side) -> String {
    match s {
        Side::Bytes(b) => fmt_bytes(b.len() as u64),
        Side::Absent => "none".to_string(),
        Side::Gone(_) => "unavailable".to_string(),
    }
}

// only the first DIFF_SIDE_MAX bytes are looked at, and a character cut by that bound is not a sign of binary
fn is_binary(b: &[u8]) -> bool {
    let head = &b[..b.len().min(DIFF_SIDE_MAX)];
    if head.contains(&0) {
        return true;
    }
    match std::str::from_utf8(head) {
        Ok(_) => false,
        Err(e) => !(head.len() < b.len() && e.error_len().is_none()),
    }
}

// why no diff can be shown, and the sizes that go with it
fn blocked(sides: &Sides) -> Option<(String, Option<String>)> {
    for s in [&sides.old, &sides.new] {
        if let Side::Gone(reason) = s {
            return Some(((*reason).to_string(), None));
        }
    }
    let (old, new) = (bytes_of(&sides.old), bytes_of(&sides.new));
    if old.is_none() && new.is_none() {
        return Some(("no content on either side".to_string(), None));
    }
    let detail = Some(format!(
        "old {}, new {}",
        side_text(&sides.old),
        side_text(&sides.new)
    ));
    if [old, new].into_iter().flatten().any(is_binary) {
        return Some(("binary file".to_string(), detail));
    }
    let biggest = [old, new].into_iter().flatten().map(<[u8]>::len).max();
    if let Some(big) = biggest.filter(|&n| n > DIFF_SIDE_MAX) {
        let why = format!(
            "too large to diff ({}, limit {} MiB)",
            fmt_bytes(big as u64),
            DIFF_SIDE_MAX / (1024 * 1024)
        );
        return Some((why, detail));
    }
    if let (Some(a), Some(b)) = (old, new)
        && a == b
    {
        return Some(("no change in content".to_string(), detail));
    }
    None
}

// a line made safe for the terminal: hidden characters dropped, tabs widened, cut at LINE_CHARS_MAX
fn clean_line(raw: &str) -> String {
    let raw = raw.strip_suffix('\r').unwrap_or(raw);
    let mut out = String::with_capacity(raw.len().min(LINE_CHARS_MAX + 4));
    let mut chars = 0usize;
    for c in raw.chars() {
        let width = if c == '\t' {
            4
        } else if is_hidden_char(c) {
            continue;
        } else {
            1
        };
        if chars + width > LINE_CHARS_MAX {
            out.push('…');
            return out;
        }
        if c == '\t' {
            out.push_str("    ");
        } else {
            out.push(c);
        }
        chars += width;
    }
    out
}

fn split_lines(text: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    lines
}

fn range_text(start: usize, end: usize) -> String {
    let count = end.saturating_sub(start);
    let first = if count == 0 { start } else { start + 1 };
    format!("{first},{count}")
}

#[derive(Default)]
struct Acc {
    lines: Vec<DiffLine>,
    bytes: usize,
    cut: Option<String>,
}

impl Acc {
    // false once a cap is hit; nothing is added after that
    fn push(&mut self, kind: Kind, raw: &str) -> bool {
        if self.cut.is_some() {
            return false;
        }
        let text = clean_line(raw);
        if self.lines.len() >= DIFF_LINES_MAX {
            self.cut = Some(format!("diff cut at {DIFF_LINES_MAX} lines"));
            return false;
        }
        if self.bytes + text.len() > DIFF_BYTES_MAX {
            self.cut = Some(format!("diff cut at {} KiB", DIFF_BYTES_MAX / 1024));
            return false;
        }
        self.bytes += text.len();
        self.lines.push(DiffLine { kind, text });
        true
    }

    fn push_range(&mut self, kind: Kind, lines: &[&str], range: Range<usize>) -> bool {
        for i in range {
            if let Some(line) = lines.get(i)
                && !self.push(kind, line)
            {
                return false;
            }
        }
        true
    }

    fn push_hunk(&mut self, group: &[DiffOp], old: &[&str], new: &[&str]) -> bool {
        let (Some(first), Some(last)) = (group.first(), group.last()) else {
            return true;
        };
        let header = format!(
            "@@ -{} +{} @@",
            range_text(first.old_range().start, last.old_range().end),
            range_text(first.new_range().start, last.new_range().end)
        );
        if !self.push(Kind::Hunk, &header) {
            return false;
        }
        for op in group {
            let (tag, o, n) = op.as_tag_tuple();
            let ok = match tag {
                DiffTag::Equal => self.push_range(Kind::Context, old, o),
                DiffTag::Delete => self.push_range(Kind::Del, old, o),
                DiffTag::Insert => self.push_range(Kind::Add, new, n),
                DiffTag::Replace => {
                    self.push_range(Kind::Del, old, o) && self.push_range(Kind::Add, new, n)
                }
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

fn build(sides: &Sides) -> DiffView {
    let mut view = DiffView {
        label: sides.label,
        added: 0,
        removed: 0,
        lines: Vec::new(),
        cut: None,
        unavailable: None,
        detail: None,
    };
    if let Some((why, detail)) = blocked(sides) {
        view.unavailable = Some(why);
        view.detail = detail;
        return view;
    }
    let text_of = |s: &Side| -> String {
        bytes_of(s)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or_default()
            .to_string()
    };
    let (old_text, new_text) = (text_of(&sides.old), text_of(&sides.new));
    let (old, new) = (split_lines(&old_text), split_lines(&new_text));
    let diff = TextDiff::configure()
        .timeout(DIFF_TIMEOUT)
        .diff_slices(old.as_slice(), new.as_slice());

    let (mut removed, mut added) = (0usize, 0usize);
    for op in diff.ops() {
        let (tag, o, n) = op.as_tag_tuple();
        if tag != DiffTag::Equal {
            removed += o.len();
            added += n.len();
        }
    }
    view.removed = u32::try_from(removed).unwrap_or(u32::MAX);
    view.added = u32::try_from(added).unwrap_or(u32::MAX);

    let mut acc = Acc::default();
    for group in diff.grouped_ops(CONTEXT_LINES) {
        if group.iter().all(|op| op.tag() == DiffTag::Equal) {
            continue;
        }
        if !acc.push_hunk(&group, &old, &new) {
            break;
        }
    }
    view.lines = acc.lines;
    view.cut = acc.cut;
    if view.lines.is_empty() {
        view.unavailable = Some(
            if matches!(sides.old, Side::Absent) || matches!(sides.new, Side::Absent) {
                "empty file".to_string()
            } else {
                "no line changes (only the final newline differs)".to_string()
            },
        );
    }
    view
}

pub fn render(sides: &Sides) -> DiffView {
    let mut view = build(sides);
    if let Some(note) = sides.note {
        view.detail = Some(match view.detail.take() {
            Some(d) => format!("{d}; {note}"),
            None => note.to_string(),
        });
    }
    view
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> Side {
        Side::Bytes(s.as_bytes().to_vec())
    }

    fn sides(old: Side, new: Side) -> Sides {
        Sides {
            label: "test",
            old,
            new,
            note: None,
        }
    }

    fn kinds(v: &DiffView) -> Vec<Kind> {
        v.lines.iter().map(|l| l.kind).collect()
    }

    fn texts(v: &DiffView) -> Vec<&str> {
        v.lines.iter().map(|l| l.text.as_str()).collect()
    }

    #[test]
    fn absent_old_is_all_additions() {
        let v = render(&sides(Side::Absent, bytes("a\nb\n")));
        assert_eq!(v.unavailable, None);
        assert_eq!((v.added, v.removed), (2, 0));
        assert_eq!(kinds(&v), vec![Kind::Hunk, Kind::Add, Kind::Add]);
        assert_eq!(texts(&v), vec!["@@ -0,0 +1,2 @@", "a", "b"]);
        assert_eq!(v.label, "test");
    }

    #[test]
    fn absent_new_is_all_deletions() {
        let v = render(&sides(bytes("a\nb\n"), Side::Absent));
        assert_eq!(v.unavailable, None);
        assert_eq!((v.added, v.removed), (0, 2));
        assert_eq!(kinds(&v), vec![Kind::Hunk, Kind::Del, Kind::Del]);
        assert_eq!(texts(&v), vec!["@@ -1,2 +0,0 @@", "a", "b"]);
    }

    #[test]
    fn both_absent_has_no_content() {
        let v = render(&sides(Side::Absent, Side::Absent));
        assert_eq!(v.unavailable.as_deref(), Some("no content on either side"));
        assert!(v.lines.is_empty());
    }

    #[test]
    fn absent_against_empty_file_is_reported() {
        let v = render(&sides(Side::Absent, bytes("")));
        assert_eq!(v.unavailable.as_deref(), Some("empty file"));
    }

    #[test]
    fn gone_reason_surfaces_even_with_the_other_side_present() {
        let v = render(&sides(Side::Gone("evicted from the cache"), bytes("a\n")));
        assert_eq!(v.unavailable.as_deref(), Some("evicted from the cache"));
        let v = render(&sides(bytes("a\n"), Side::Gone("not fetched")));
        assert_eq!(v.unavailable.as_deref(), Some("not fetched"));
        assert!(v.lines.is_empty());
    }

    #[test]
    fn identical_content_has_no_diff() {
        let v = render(&sides(bytes("a\nb\n"), bytes("a\nb\n")));
        assert_eq!(v.unavailable.as_deref(), Some("no change in content"));
        let v = render(&sides(bytes(""), bytes("")));
        assert_eq!(v.unavailable.as_deref(), Some("no change in content"));
    }

    #[test]
    fn final_newline_only_difference_is_reported() {
        let v = render(&sides(bytes("a"), bytes("a\n")));
        assert!(v.unavailable.is_some());
        assert!(v.lines.is_empty());
    }

    #[test]
    fn binary_content_is_refused() {
        let v = render(&sides(bytes("a\n"), Side::Bytes(vec![b'a', 0, b'b'])));
        assert_eq!(v.unavailable.as_deref(), Some("binary file"));
        assert!(v.detail.is_some());
        let v = render(&sides(Side::Bytes(vec![0xff, 0xfe, b'a']), bytes("a\n")));
        assert_eq!(v.unavailable.as_deref(), Some("binary file"));
        assert!(v.lines.is_empty());
    }

    #[test]
    fn oversized_side_is_refused() {
        let big = Side::Bytes(vec![b'a'; DIFF_SIDE_MAX + 1]);
        let v = render(&sides(bytes("x\n"), big));
        assert_eq!(
            v.unavailable.as_deref(),
            Some("too large to diff (1.0 MiB, limit 1 MiB)")
        );
        assert!(v.lines.is_empty());
    }

    #[test]
    fn side_at_the_limit_is_diffed() {
        let at = Side::Bytes(vec![b'a'; DIFF_SIDE_MAX]);
        let v = render(&sides(Side::Absent, at));
        assert_eq!(v.unavailable, None);
        assert_eq!(v.added, 1);
    }

    #[test]
    fn line_cap_sets_cut() {
        let new: String = (0..DIFF_LINES_MAX + 500)
            .map(|i| format!("line {i}\n"))
            .collect();
        let v = render(&sides(Side::Absent, Side::Bytes(new.into_bytes())));
        assert_eq!(v.lines.len(), DIFF_LINES_MAX);
        assert_eq!(v.cut.as_deref(), Some("diff cut at 2000 lines"));
        assert_eq!(v.added as usize, DIFF_LINES_MAX + 500);
        assert_eq!(v.unavailable, None);
    }

    #[test]
    fn byte_cap_sets_cut() {
        let line = format!("{}\n", "x".repeat(900));
        let new = line.repeat(300);
        let v = render(&sides(Side::Absent, Side::Bytes(new.into_bytes())));
        assert_eq!(v.cut.as_deref(), Some("diff cut at 256 KiB"));
        assert!(v.lines.len() < 300);
        let total: usize = v.lines.iter().map(|l| l.text.len()).sum();
        assert!(total <= DIFF_BYTES_MAX);
    }

    #[test]
    fn small_diff_is_not_cut() {
        let v = render(&sides(bytes("a\n"), bytes("b\n")));
        assert_eq!(v.cut, None);
    }

    #[test]
    fn control_and_bidi_characters_are_removed() {
        let new = "a\u{1b}[31mb\u{202e}c\u{200b}d\u{feff}e\u{7}f\n";
        let v = render(&sides(Side::Absent, bytes(new)));
        assert_eq!(texts(&v)[1], "a[31mbcdef");
    }

    #[test]
    fn tabs_become_four_spaces() {
        let v = render(&sides(Side::Absent, bytes("\tx\ty\n")));
        assert_eq!(texts(&v)[1], "    x    y");
    }

    #[test]
    fn crlf_lines_lose_the_carriage_return() {
        let v = render(&sides(bytes("a\r\nb\r\nc\r\n"), bytes("a\r\nB\r\nc\r\n")));
        assert!(v.lines.iter().all(|l| !l.text.contains('\r')));
        assert_eq!(texts(&v), vec!["@@ -1,3 +1,3 @@", "a", "b", "B", "c"]);
        assert_eq!((v.added, v.removed), (1, 1));
    }

    #[test]
    fn stray_carriage_return_inside_a_line_is_dropped() {
        let v = render(&sides(Side::Absent, bytes("a\rb\n")));
        assert_eq!(texts(&v)[1], "ab");
    }

    #[test]
    fn wide_characters_pass_through() {
        let v = render(&sides(Side::Absent, bytes("日本語 \u{1f600} é\n")));
        assert_eq!(texts(&v)[1], "日本語 \u{1f600} é");
    }

    #[test]
    fn long_line_is_cut_with_an_ellipsis() {
        let long = "x".repeat(LINE_CHARS_MAX + 50);
        let v = render(&sides(Side::Absent, bytes(&format!("{long}\n"))));
        let text = texts(&v)[1];
        assert_eq!(text.chars().count(), LINE_CHARS_MAX + 1);
        assert!(text.ends_with('…'));
        let exact = "y".repeat(LINE_CHARS_MAX);
        let v = render(&sides(Side::Absent, bytes(&format!("{exact}\n"))));
        assert_eq!(texts(&v)[1], exact);
    }

    #[test]
    fn hunk_header_for_a_known_edit() {
        let v = render(&sides(bytes("a\nb\nc\n"), bytes("a\nB\nc\n")));
        assert_eq!(texts(&v), vec!["@@ -1,3 +1,3 @@", "a", "b", "B", "c"]);
        assert_eq!(
            kinds(&v),
            vec![
                Kind::Hunk,
                Kind::Context,
                Kind::Del,
                Kind::Add,
                Kind::Context
            ]
        );
        assert_eq!((v.added, v.removed), (1, 1));
        assert_eq!(v.unavailable, None);
    }

    #[test]
    fn hunk_keeps_three_lines_of_context() {
        let old: String = (1..=10).map(|i| format!("l{i}\n")).collect();
        let new = old.replace("l5\n", "five\n");
        let v = render(&sides(
            Side::Bytes(old.into_bytes()),
            Side::Bytes(new.into_bytes()),
        ));
        assert_eq!(texts(&v)[0], "@@ -2,7 +2,7 @@");
        assert_eq!(v.lines.len(), 1 + 3 + 2 + 3);
        assert_eq!((v.added, v.removed), (1, 1));
    }

    #[test]
    fn distant_edits_make_two_hunks() {
        let old: String = (1..=30).map(|i| format!("l{i}\n")).collect();
        let new = old
            .replace("l2\n", "two\n")
            .replace("l29\n", "twenty-nine\n");
        let v = render(&sides(
            Side::Bytes(old.into_bytes()),
            Side::Bytes(new.into_bytes()),
        ));
        let hunks = v.lines.iter().filter(|l| l.kind == Kind::Hunk).count();
        assert_eq!(hunks, 2);
        assert_eq!((v.added, v.removed), (2, 2));
    }

    #[test]
    fn note_is_added_to_the_detail() {
        let mut s = sides(bytes("a\n"), bytes("b\n"));
        s.note = Some("from the cache");
        let v = render(&s);
        assert_eq!(v.detail.as_deref(), Some("from the cache"));
        let mut s = sides(bytes("a\n"), bytes("a\n"));
        s.note = Some("from the cache");
        let v = render(&s);
        assert!(
            v.detail
                .as_deref()
                .is_some_and(|d| d.ends_with("; from the cache"))
        );
    }
}
