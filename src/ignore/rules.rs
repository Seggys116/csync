use crate::proto::{Bytes, DEPTH_MAX, ExcludeSrc, Hash32, RelPath, path::TMP_PREFIX};
use ::ignore::Match;
use ::ignore::gitignore::{Gitignore, GitignoreBuilder};
use rustc_hash::FxHashMap;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Synced,
    GitRo,
    Ignored,
    Internal,
}

const GITIGNORE: &str = ".gitignore";
const DOTGIT: &str = ".git";
const GUEST_KEYS: usize = 64;

// code points hfs+ skips when it compares names
fn ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}'
    )
}

// the ascii character c becomes under case folding or a canonical singleton, if any
fn fold_ascii(c: char) -> Option<char> {
    if c.is_ascii() {
        return Some(c.to_ascii_lowercase());
    }
    match c {
        '\u{1fef}' => return Some('`'),
        '\u{37e}' => return Some(';'),
        _ => {}
    }
    let mut up = c.to_uppercase();
    let u = up.next()?;
    if up.next().is_some() {
        return None;
    }
    let mut lo = u.to_lowercase();
    let l = lo.next()?;
    (lo.next().is_none() && l.is_ascii()).then_some(l)
}

// compares a name against a lowercase ascii fixed name the way a folding volume resolves it, without allocating
fn folded_match(name: &str, want: &str, prefix: bool) -> bool {
    let w = want.as_bytes();
    let mut i = 0;
    for c in name.chars() {
        if prefix && i == w.len() {
            return true;
        }
        if ignorable(c) {
            continue;
        }
        if i == w.len() || fold_ascii(c) != Some(char::from(w[i])) {
            return false;
        }
        i += 1;
    }
    i == w.len()
}

// every fixed name starts with '.', so any other ascii first byte cannot fold to one
fn may_fold_to_fixed(c: &str) -> bool {
    c.as_bytes()
        .first()
        .is_some_and(|&b| b == b'.' || !b.is_ascii())
}

// files macos itself scatters around (finder, spotlight, time machine, icloud, appledouble on foreign volumes);
// always ignored unless git tracks them, so they never sync, never reach the guest and never conflict
pub const OS_JUNK: [&str; 13] = [
    ".DS_Store",
    ".AppleDouble",
    ".AppleDB",
    ".AppleDesktop",
    ".apdisk",
    ".DocumentRevisions-V100",
    ".fseventsd",
    ".Spotlight-V100",
    ".TemporaryItems",
    ".Trashes",
    ".VolumeIcon.icns",
    ".com.apple.timemachine.donotpresent",
    "Icon\r",
];

// OS_JUNK plus `._*` appledouble twins and `.name.icloud` placeholders of files not downloaded yet
pub fn is_os_junk(c: &str) -> bool {
    match c.as_bytes() {
        [b'.', b'_', ..] => true,
        [b'.', rest @ ..] => {
            (rest.len() > 7 && rest[rest.len() - 7..].eq_ignore_ascii_case(b".icloud"))
                || OS_JUNK.iter().any(|j| c.eq_ignore_ascii_case(j))
        }
        [b'I' | b'i', .., b'\r'] => c.eq_ignore_ascii_case("Icon\r"),
        _ => false,
    }
}

struct Matcher {
    gi: Gitignore,
    text: Box<[u8]>,
}

impl Matcher {
    fn new(text: &[u8], ignore_case: bool) -> Self {
        Self {
            gi: build(text, ignore_case),
            text: text.into(),
        }
    }
}

// one directory's .gitignore; while guest edits are in effect the last host-trusted rules stay as a floor and both apply
#[derive(Default)]
struct DirRules {
    cur: Option<Matcher>,
    floor: Option<Matcher>,
    // contents the guest has written here (None: removed or unreadable); reading one back is never a host edit
    guest: Vec<Option<Hash32>>,
}

impl DirRules {
    fn view(&self, trusted: bool) -> Option<&Matcher> {
        if trusted {
            self.floor.as_ref().or(self.cur.as_ref())
        } else {
            self.cur.as_ref()
        }
    }
}

// git splits on '\n', drops one '\r' before it and a leading utf-8 bom
fn build(text: &[u8], ignore_case: bool) -> Gitignore {
    let mut b = GitignoreBuilder::new(".");
    let _ = b.case_insensitive(ignore_case);
    for (i, raw) in text.split(|&c| c == b'\n').enumerate() {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let line = if i == 0 {
            line.strip_prefix("\u{feff}".as_bytes()).unwrap_or(line)
        } else {
            line
        };
        if line.is_empty() {
            continue;
        }
        let _ = b.add_line(None, &String::from_utf8_lossy(line));
    }
    b.build().unwrap_or_else(|_| Gitignore::empty())
}

struct Repo {
    root: Box<str>,
    gitdir: Option<Box<str>>,
    info_path: Option<Box<str>>,
    info: Option<Matcher>,
    extra: Option<u32>,
    live: bool,
}

impl Repo {
    fn new(root: &str) -> Self {
        Self {
            root: root.into(),
            gitdir: None,
            info_path: None,
            info: None,
            extra: None,
            live: true,
        }
    }
}

#[derive(Clone, Copy)]
struct Cur {
    repo: u32,
    ign: bool,
}

type Ent<'r> = Option<(&'r DirRules, usize)>;

enum Lvl {
    Fixed(Class),
    Pass { ign: bool },
}

// per-directory classification state for classifying many children without re-walking ancestors
pub struct DirCtx<'r> {
    buf: String,
    dir_len: usize,
    stack: Vec<Ent<'r>>,
    cur: Cur,
    fixed: Option<Class>,
}

pub struct Rules {
    repos: Vec<Repo>,
    repo_by_root: FxHashMap<Box<str>, u32>,
    info_files: FxHashMap<Box<str>, u32>,
    dirs: FxHashMap<Box<str>, DirRules>,
    // text that lives outside the tree for a repo: core.excludesFile, then an external info/exclude
    extras: Vec<Option<(Box<str>, Matcher)>>,
    exc_files: FxHashMap<Box<str>, u32>,
    exc_dirs: FxHashMap<Box<str>, u32>,
    ignore_case: bool,
    // a folding volume resolves other spellings of .git, the temp prefix and .gitignore to the real ones
    fold_names: bool,
    fold_known: bool,
    floors: usize,
}

fn join(a: &str, b: &str) -> String {
    if a.is_empty() {
        b.to_owned()
    } else {
        format!("{a}/{b}")
    }
}

fn parent_of(s: &str) -> &str {
    s.rsplit_once('/').map_or("", |(a, _)| a)
}

impl Rules {
    pub fn new(global: &[ExcludeSrc]) -> Self {
        let mut r = Self {
            repos: vec![Repo::new("")],
            repo_by_root: FxHashMap::default(),
            info_files: FxHashMap::default(),
            dirs: FxHashMap::default(),
            extras: Vec::new(),
            exc_files: FxHashMap::default(),
            exc_dirs: FxHashMap::default(),
            ignore_case: false,
            fold_names: false,
            fold_known: false,
            floors: 0,
        };
        r.repo_by_root.insert("".into(), 0);
        for src in global {
            r.set_extra(&src.repo, Some(&src.text.0));
        }
        r
    }

    // gitdir is the directory whose info/exclude applies (the common dir for linked worktrees)
    pub fn add_repo(&mut self, worktree: &RelPath, gitdir: &RelPath) {
        let root = worktree.as_str();
        let idx = match self.repo_by_root.get(root) {
            Some(&i) => i,
            None => {
                let Ok(i) = u32::try_from(self.repos.len()) else {
                    return;
                };
                self.repos.push(Repo::new(root));
                self.repo_by_root.insert(root.into(), i);
                i
            }
        };
        let info: Box<str> = join(gitdir.as_str(), "info/exclude").into();
        let Some(repo) = self.repos.get_mut(idx as usize) else {
            return;
        };
        if repo.info_path.as_deref() != Some(&*info) {
            if let Some(old) = repo.info_path.take() {
                self.info_files.remove(&old);
            }
            repo.info = None;
            self.info_files.insert(info.clone(), idx);
            repo.info_path = Some(info);
        }
        repo.gitdir = Some(gitdir.as_str().into());
        repo.live = true;
        self.relink();
    }

    pub fn remove_repo(&mut self, worktree: &RelPath) -> bool {
        let root = worktree.as_str();
        let Some(&idx) = self.repo_by_root.get(root) else {
            return false;
        };
        let Some(repo) = self.repos.get_mut(idx as usize) else {
            return false;
        };
        if let Some(old) = repo.info_path.take() {
            self.info_files.remove(&old);
        }
        repo.info = None;
        repo.gitdir = None;
        if idx != 0 {
            repo.live = false;
            self.repo_by_root.remove(root);
        }
        let stale: Vec<Box<str>> = self
            .exc_files
            .iter()
            .filter(|(_, r)| **r == idx)
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            self.exc_remove(&k);
        }
        true
    }

    pub fn is_repo(&self, worktree: &RelPath) -> bool {
        self.repo_by_root
            .get(worktree.as_str())
            .and_then(|&i| self.repos.get(i as usize))
            .is_some_and(|r| r.gitdir.is_some())
    }

    pub fn repos(&self) -> Vec<(RelPath, RelPath)> {
        self.repos
            .iter()
            .filter(|r| r.live)
            .filter_map(|r| {
                Some((
                    RelPath::new(&r.root).ok()?,
                    RelPath::new(r.gitdir.as_deref()?).ok()?,
                ))
            })
            .collect()
    }

    fn is_dotgit(&self, c: &str) -> bool {
        c == DOTGIT || (self.fold_names && may_fold_to_fixed(c) && folded_match(c, DOTGIT, false))
    }

    fn is_internal(&self, c: &str) -> bool {
        c.starts_with(TMP_PREFIX)
            || (self.fold_names && may_fold_to_fixed(c) && folded_match(c, TMP_PREFIX, true))
    }

    pub fn is_gitignore_name(&self, c: &str) -> bool {
        c == GITIGNORE
            || (self.fold_names && may_fold_to_fixed(c) && folded_match(c, GITIGNORE, false))
    }

    // the directory a .gitignore governs
    fn gitignore_dir<'p>(&self, file: &'p RelPath) -> Option<&'p str> {
        file.split_last()
            .filter(|(_, n)| self.is_gitignore_name(n))
            .map(|(d, _)| d)
    }

    pub fn is_rule_file(&self, p: &RelPath) -> bool {
        self.gitignore_dir(p).is_some() || self.info_files.contains_key(p.as_str())
    }

    pub fn has_dir_rules(&self, dir: &RelPath) -> bool {
        self.dirs.contains_key(dir.as_str())
    }

    // the subtree whose classification may change when this file changes
    pub fn rule_scope(&self, file: &RelPath) -> RelPath {
        if let Some(dir) = self.gitignore_dir(file) {
            return RelPath::new(dir).unwrap_or_else(|_| RelPath::root());
        }
        match self
            .info_files
            .get(file.as_str())
            .and_then(|&i| self.repos.get(i as usize))
        {
            Some(r) => RelPath::new(&r.root).unwrap_or_else(|_| RelPath::root()),
            None => file.clone(),
        }
    }

    pub fn set_rule_file(&mut self, file: &RelPath, text: Option<&[u8]>) -> RelPath {
        self.update_rule_file(file, text);
        self.rule_scope(file)
    }

    // like set_rule_file, but None when nothing was re-parsed because the content is unchanged
    // content read on the host: a guest-written version only narrows, anything else is a host edit and is trusted
    pub fn update_rule_file(&mut self, file: &RelPath, text: Option<&[u8]>) -> Option<RelPath> {
        let ic = self.ignore_case;
        if let Some(dir) = self.gitignore_dir(file) {
            let cur = self.dirs.get(dir);
            let same = match (cur.and_then(|d| d.cur.as_ref()), text) {
                (Some(m), Some(t)) => *m.text == *t,
                (None, None) => true,
                _ => false,
            };
            if same {
                return None;
            }
            let from_guest = cur.is_some_and(|d| {
                !d.guest.is_empty() && d.guest.contains(&text.map(|t| *blake3::hash(t).as_bytes()))
            });
            let d = match self.dirs.get_mut(dir) {
                Some(d) => d,
                None => self.dirs.entry(dir.into()).or_default(),
            };
            let old = std::mem::replace(&mut d.cur, text.map(|t| Matcher::new(t, ic)));
            if from_guest {
                if d.floor.is_none() {
                    d.floor = Some(old.unwrap_or_else(|| Matcher::new(b"", ic)));
                    self.floors += 1;
                }
            } else if d.floor.take().is_some() {
                self.floors -= 1;
            }
            if d.cur.is_none() && d.floor.is_none() && d.guest.is_empty() {
                self.dirs.remove(dir);
            }
            return Some(self.rule_scope(file));
        }
        let &idx = self.info_files.get(file.as_str())?;
        let repo = self.repos.get_mut(idx as usize)?;
        let changed = match text {
            Some(t) => {
                if repo.info.as_ref().is_some_and(|m| *m.text == *t) {
                    false
                } else {
                    repo.info = Some(Matcher::new(t, ic));
                    true
                }
            }
            None => repo.info.take().is_some(),
        };
        changed.then(|| self.rule_scope(file))
    }

    // returns true when the effective text changed
    pub fn set_extra(&mut self, repo: &RelPath, text: Option<&[u8]>) -> bool {
        let root = repo.as_str();
        let slot = self
            .extras
            .iter()
            .position(|x| x.as_ref().is_some_and(|(r, _)| &**r == root));
        let changed = match (slot, text) {
            (Some(i), Some(t)) => {
                let same = self.extras[i].as_ref().is_some_and(|(_, m)| *m.text == *t);
                if !same {
                    self.extras[i] = Some((root.into(), Matcher::new(t, self.ignore_case)));
                }
                !same
            }
            (None, Some(t)) => {
                let m = Matcher::new(t, self.ignore_case);
                match self.extras.iter().position(Option::is_none) {
                    Some(i) => self.extras[i] = Some((root.into(), m)),
                    None => self.extras.push(Some((root.into(), m))),
                }
                true
            }
            (Some(i), None) => {
                self.extras[i] = None;
                true
            }
            (None, None) => false,
        };
        if changed {
            self.relink();
        }
        changed
    }

    pub fn exclude_srcs(&self) -> Vec<ExcludeSrc> {
        self.extras
            .iter()
            .flatten()
            .filter_map(|(root, m)| {
                Some(ExcludeSrc {
                    repo: RelPath::new(root).ok()?,
                    text: Bytes(m.text.to_vec()),
                })
            })
            .collect()
    }

    // called before the guest changes a .gitignore (content None: removed or made unreadable)
    pub fn note_guest_rule(&mut self, file: &RelPath, content: Option<Hash32>) {
        let Some(dir) = self.gitignore_dir(file) else {
            return;
        };
        let d = match self.dirs.get_mut(dir) {
            Some(d) => d,
            None => self.dirs.entry(dir.into()).or_default(),
        };
        if d.guest.contains(&content) {
            return;
        }
        if d.guest.len() >= GUEST_KEYS {
            d.guest.remove(0);
        }
        d.guest.push(content);
    }

    pub fn guest_wrote(&self, file: &RelPath, content: &Hash32) -> bool {
        self.gitignore_dir(file)
            .and_then(|d| self.dirs.get(d))
            .is_some_and(|d| d.guest.contains(&Some(*content)))
    }

    pub fn fold_known(&self) -> bool {
        self.fold_known
    }

    // the host volume's folding; case folding makes patterns case-insensitive too, as git sets core.ignoreCase there
    pub fn set_fs_fold(&mut self, case_fold: bool, norm_fold: bool) {
        self.set_ignore_case(case_fold);
        self.fold_names = case_fold || norm_fold;
        self.fold_known = true;
    }

    // core.ignoreCase: rebuilds every matcher from its stored text
    pub fn set_ignore_case(&mut self, yes: bool) {
        self.fold_names = yes;
        if self.ignore_case == yes {
            return;
        }
        self.ignore_case = yes;
        for d in self.dirs.values_mut() {
            for m in [d.cur.as_mut(), d.floor.as_mut()].into_iter().flatten() {
                m.gi = build(&m.text, yes);
            }
        }
        for r in &mut self.repos {
            if let Some(m) = r.info.as_mut() {
                m.gi = build(&m.text, yes);
            }
        }
        for (_, m) in self.extras.iter_mut().flatten() {
            m.gi = build(&m.text, yes);
        }
    }

    // tracked files stay synced even when they match ignore rules
    pub fn set_exceptions(&mut self, tracked_ignored: Vec<RelPath>) {
        self.exc_files.clear();
        self.exc_dirs.clear();
        for p in tracked_ignored {
            let repo = self.repo_of(p.as_str());
            self.exc_insert(p.as_str(), repo);
        }
    }

    pub fn repo_exceptions(&self, worktree: &RelPath) -> Vec<RelPath> {
        let Some(&idx) = self.repo_by_root.get(worktree.as_str()) else {
            return Vec::new();
        };
        self.exc_files
            .iter()
            .filter(|(_, r)| **r == idx)
            .filter_map(|(k, _)| RelPath::new(k).ok())
            .collect()
    }

    pub fn set_repo_exceptions(&mut self, worktree: &RelPath, tracked_ignored: Vec<RelPath>) {
        let Some(&idx) = self.repo_by_root.get(worktree.as_str()) else {
            return;
        };
        let stale: Vec<Box<str>> = self
            .exc_files
            .iter()
            .filter(|(_, r)| **r == idx)
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            self.exc_remove(&k);
        }
        for p in tracked_ignored {
            self.exc_insert(p.as_str(), idx);
        }
    }

    pub fn classify(&self, p: &RelPath, is_dir: bool) -> Class {
        let s = p.as_str();
        if s.is_empty() {
            return Class::Synced;
        }
        let mut st: [Ent<'_>; DEPTH_MAX] = [None; DEPTH_MAX];
        let mut n = 0;
        if let Some(d) = self.dirs.get("") {
            st[0] = Some((d, 0));
            n = 1;
        }
        let mut cur = Cur {
            repo: 0,
            ign: false,
        };
        let mut start = 0;
        loop {
            let e = s[start..].find('/').map_or(s.len(), |i| start + i);
            let last = e == s.len();
            match self.level(s, start, e, !last || is_dir, &st[..n], cur) {
                Lvl::Fixed(c) => return c,
                Lvl::Pass { ign } => cur.ign = ign,
            }
            if last {
                return Class::Synced;
            }
            let (repo, gi) = self.descend(&s[..e]);
            if let Some(r) = repo {
                cur = Cur {
                    repo: r,
                    ign: false,
                };
                n = 0;
            }
            if let Some(gi) = gi
                && n < st.len()
            {
                st[n] = Some((gi, e + 1));
                n += 1;
            }
            start = e + 1;
        }
    }

    pub fn dir_ctx(&self, dir: &RelPath) -> DirCtx<'_> {
        let s = dir.as_str();
        let mut ctx = DirCtx {
            buf: String::with_capacity(s.len() + 64),
            dir_len: s.len(),
            stack: Vec::new(),
            cur: Cur {
                repo: 0,
                ign: false,
            },
            fixed: None,
        };
        ctx.buf.push_str(s);
        if let Some(d) = self.dirs.get("") {
            ctx.stack.push(Some((d, 0)));
        }
        if s.is_empty() {
            return ctx;
        }
        let mut start = 0;
        loop {
            let e = s[start..].find('/').map_or(s.len(), |i| start + i);
            match self.level(s, start, e, true, &ctx.stack, ctx.cur) {
                Lvl::Fixed(c) => {
                    ctx.fixed = Some(c);
                    return ctx;
                }
                Lvl::Pass { ign } => ctx.cur.ign = ign,
            }
            let (repo, gi) = self.descend(&s[..e]);
            if let Some(r) = repo {
                ctx.cur = Cur {
                    repo: r,
                    ign: false,
                };
                ctx.stack.clear();
            }
            if let Some(gi) = gi {
                ctx.stack.push(Some((gi, e + 1)));
            }
            if e == s.len() {
                return ctx;
            }
            start = e + 1;
        }
    }

    pub fn classify_in<'r>(&'r self, ctx: &mut DirCtx<'r>, name: &str, is_dir: bool) -> Class {
        if let Some(c) = ctx.fixed {
            return c;
        }
        ctx.buf.truncate(ctx.dir_len);
        if ctx.dir_len > 0 {
            ctx.buf.push('/');
        }
        let start = ctx.buf.len();
        ctx.buf.push_str(name);
        match self.level(&ctx.buf, start, ctx.buf.len(), is_dir, &ctx.stack, ctx.cur) {
            Lvl::Fixed(c) => c,
            Lvl::Pass { .. } => Class::Synced,
        }
    }

    fn descend(&self, prefix: &str) -> (Option<u32>, Option<&DirRules>) {
        let repo = self.repo_by_root.get(prefix).copied();
        (repo, self.dirs.get(prefix))
    }

    fn level(
        &self,
        path: &str,
        start: usize,
        e: usize,
        is_dir: bool,
        stack: &[Ent<'_>],
        cur: Cur,
    ) -> Lvl {
        let comp = &path[start..e];
        if self.is_internal(comp) {
            return Lvl::Fixed(Class::Internal);
        }
        if self.is_dotgit(comp) {
            return Lvl::Fixed(Class::GitRo);
        }
        let prefix = &path[..e];
        let excepted = || {
            !self.exc_files.is_empty()
                && (self.exc_files.contains_key(prefix)
                    || (is_dir && self.exc_dirs.contains_key(prefix)))
        };
        if cur.ign {
            return if excepted() {
                Lvl::Pass { ign: true }
            } else {
                Lvl::Fixed(Class::Ignored)
            };
        }
        if !is_os_junk(comp) && !self.ignored(path, e, is_dir, stack, cur.repo) {
            return Lvl::Pass { ign: false };
        }
        if excepted() {
            Lvl::Pass { ign: is_dir }
        } else {
            Lvl::Fixed(Class::Ignored)
        }
    }

    // ignored by the current rules or, where guest edits are in effect, by the trusted ones they replaced
    fn ignored(&self, path: &str, e: usize, is_dir: bool, stack: &[Ent<'_>], repo: u32) -> bool {
        self.ignored_by(path, e, is_dir, stack, repo, false)
            || (self.floors > 0
                && stack.iter().flatten().any(|(d, _)| d.floor.is_some())
                && self.ignored_by(path, e, is_dir, stack, repo, true))
    }

    // git precedence: deepest .gitignore first, then info/exclude, then core.excludesFile
    fn ignored_by(
        &self,
        path: &str,
        e: usize,
        is_dir: bool,
        stack: &[Ent<'_>],
        repo: u32,
        trusted: bool,
    ) -> bool {
        for &(d, off) in stack.iter().rev().flatten() {
            let Some(m) = d.view(trusted) else {
                continue;
            };
            match m.gi.matched(Path::new(&path[off..e]), is_dir) {
                Match::Ignore(_) => return true,
                Match::Whitelist(_) => return false,
                Match::None => {}
            }
        }
        let Some(r) = self.repos.get(repo as usize) else {
            return false;
        };
        let off = if r.root.is_empty() {
            0
        } else {
            r.root.len() + 1
        };
        let Some(rel) = path.get(off..e) else {
            return false;
        };
        let rel = Path::new(rel);
        let extra = r
            .extra
            .and_then(|i| self.extras.get(i as usize))
            .and_then(Option::as_ref)
            .map(|(_, m)| m);
        for m in [r.info.as_ref(), extra].into_iter().flatten() {
            match m.gi.matched(rel, is_dir) {
                Match::Ignore(_) => return true,
                Match::Whitelist(_) => return false,
                Match::None => {}
            }
        }
        false
    }

    fn relink(&mut self) {
        for i in 0..self.repos.len() {
            let found = self.find_extra(&self.repos[i].root);
            self.repos[i].extra = found;
        }
    }

    // a repo without its own excludes source inherits the nearest enclosing one
    fn find_extra(&self, root: &str) -> Option<u32> {
        let mut cur = root;
        loop {
            if let Some(i) = self
                .extras
                .iter()
                .position(|x| x.as_ref().is_some_and(|(r, _)| &**r == cur))
            {
                return u32::try_from(i).ok();
            }
            if cur.is_empty() {
                return None;
            }
            cur = parent_of(cur);
        }
    }

    fn repo_of(&self, p: &str) -> u32 {
        let mut best = 0;
        for (i, b) in p.bytes().enumerate() {
            if b == b'/'
                && let Some(&r) = self.repo_by_root.get(&p[..i])
            {
                best = r;
            }
        }
        best
    }

    fn exc_insert(&mut self, p: &str, repo: u32) {
        if p.is_empty() || self.exc_files.contains_key(p) {
            return;
        }
        self.exc_files.insert(p.into(), repo);
        for (i, b) in p.bytes().enumerate() {
            if b == b'/' {
                let a = &p[..i];
                match self.exc_dirs.get_mut(a) {
                    Some(c) => *c += 1,
                    None => {
                        self.exc_dirs.insert(a.into(), 1);
                    }
                }
            }
        }
    }

    fn exc_remove(&mut self, p: &str) {
        if self.exc_files.remove(p).is_none() {
            return;
        }
        for (i, b) in p.bytes().enumerate() {
            if b == b'/' {
                let a = &p[..i];
                if let Some(c) = self.exc_dirs.get_mut(a) {
                    *c -= 1;
                    if *c == 0 {
                        self.exc_dirs.remove(a);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap()
    }

    fn src(repo: &str, text: &str) -> ExcludeSrc {
        ExcludeSrc {
            repo: rp(repo),
            text: Bytes(text.as_bytes().to_vec()),
        }
    }

    fn check(r: &Rules, cases: &[(&str, bool, Class)]) {
        for &(p, is_dir, want) in cases {
            let path = rp(p);
            assert_eq!(
                r.classify(&path, is_dir),
                want,
                "classify({p}, dir={is_dir})"
            );
            let (dir, name) = path.split_last().unwrap();
            let mut ctx = r.dir_ctx(&rp(dir));
            assert_eq!(
                r.classify_in(&mut ctx, name, is_dir),
                want,
                "classify_in({p}, dir={is_dir})"
            );
        }
    }

    // expected classes follow `git check-ignore` / gitignore(5) for the same rule files on disk
    fn sample() -> Rules {
        let mut r = Rules::new(&[src("", "*.swp\n.DS_Store\n")]);
        r.add_repo(&RelPath::root(), &rp(".git"));
        let root_rules = "\u{feff}*.log\r\n!keep.log\nbuild/\n/top.txt\ngen/*\n!gen/keep.txt\nout/\n!out/keep.txt\nlogs/**\ndoc/**/*.pdf\nignored_sub/\n*.lock\n# comment.txt\n\\#hash\ntrailing.txt   \n";
        r.set_rule_file(&rp(".gitignore"), Some(root_rules.as_bytes()));
        r.set_rule_file(&rp("sub/.gitignore"), Some(b"!important.log\n*.tmp\n"));
        r.set_rule_file(
            &rp(".git/info/exclude"),
            Some(b"secret.txt\n*.key\n!x.swp\n"),
        );
        r.set_rule_file(&rp("keys/.gitignore"), Some(b"!private.key\n"));
        r.add_repo(&rp("vendor/lib"), &rp(".git/modules/lib"));
        r.set_rule_file(&rp("vendor/lib/.gitignore"), Some(b"*.o\n"));
        r.set_rule_file(&rp(".git/modules/lib/info/exclude"), Some(b"*.gen\n"));
        r.add_repo(&rp("ignored_sub"), &rp(".git/modules/ignored_sub"));
        r
    }

    #[test]
    fn git_semantics_table() {
        use Class::*;
        let r = sample();
        check(
            &r,
            &[
                ("a.log", false, Ignored),
                ("d/b.log", false, Ignored),
                ("keep.log", false, Synced),
                ("d/keep.log", false, Synced),
                ("build", true, Ignored),
                ("build", false, Synced),
                ("build/x.rs", false, Ignored),
                ("src/build", true, Ignored),
                ("top.txt", false, Ignored),
                ("d/top.txt", false, Synced),
                ("gen", true, Synced),
                ("gen/x", false, Ignored),
                ("gen/keep.txt", false, Synced),
                ("out", true, Ignored),
                ("out/keep.txt", false, Ignored),
                ("logs", true, Synced),
                ("logs/a", false, Ignored),
                ("logs/a/b", true, Ignored),
                ("doc/c.pdf", false, Ignored),
                ("doc/a/b/c.pdf", false, Ignored),
                ("doc/c.txt", false, Synced),
                ("comment.txt", false, Synced),
                ("#hash", false, Ignored),
                ("trailing.txt", false, Ignored),
                ("sub/important.log", false, Synced),
                ("sub/deeper/x.log", false, Ignored),
                ("sub/x.tmp", false, Ignored),
                ("x.tmp", false, Synced),
                ("secret.txt", false, Ignored),
                ("d/secret.txt", false, Ignored),
                ("other.key", false, Ignored),
                ("keys/private.key", false, Synced),
                ("keys/other.key", false, Ignored),
                ("a.swp", false, Ignored),
                ("d/.DS_Store", false, Ignored),
                ("x.swp", false, Synced),
                (".gitignore", false, Synced),
                (".git", true, GitRo),
                (".git/config", false, GitRo),
                (".git/info/exclude", false, GitRo),
                (".git/objects/ab", true, GitRo),
                ("vendor", true, Synced),
                ("vendor/lib", true, Synced),
                ("vendor/lib/a.log", false, Synced),
                ("vendor/lib/x.o", false, Ignored),
                ("x.o", false, Synced),
                ("vendor/lib/a.gen", false, Ignored),
                ("a.gen", false, Synced),
                ("vendor/lib/x.swp", false, Ignored),
                ("vendor/lib/.git", false, GitRo),
                ("ignored_sub", true, Ignored),
                ("ignored_sub/f", false, Ignored),
                ("Cargo.lock", false, Ignored),
            ],
        );
    }

    #[test]
    fn tracked_files_are_exceptions() {
        use Class::*;
        let mut r = sample();
        r.set_exceptions(vec![
            rp("Cargo.lock"),
            rp("build/kept.rs"),
            rp("ignored_sub"),
        ]);
        check(
            &r,
            &[
                ("Cargo.lock", false, Synced),
                ("other.lock", false, Ignored),
                ("build", true, Synced),
                ("build/kept.rs", false, Synced),
                ("build/other.rs", false, Ignored),
                ("ignored_sub", true, Synced),
            ],
        );
        r.set_repo_exceptions(&RelPath::root(), vec![rp("Cargo.lock")]);
        check(
            &r,
            &[
                ("Cargo.lock", false, Synced),
                ("build", true, Ignored),
                ("build/kept.rs", false, Ignored),
            ],
        );
        r.set_exceptions(Vec::new());
        check(&r, &[("Cargo.lock", false, Ignored)]);
    }

    #[test]
    fn macos_junk_is_ignored_without_rules_unless_tracked() {
        use Class::*;
        let mut r = Rules::new(&[]);
        check(
            &r,
            &[
                (".DS_Store", false, Ignored),
                ("src/.ds_store", false, Ignored),
                ("src/._main.c", false, Ignored),
                ("._dir", true, Ignored),
                ("._dir/x", false, Ignored),
                ("Icon\r", false, Ignored),
                ("a/Icon\r", false, Ignored),
                (".Spotlight-V100", true, Ignored),
                (".Spotlight-V100/Store-V2/x", false, Ignored),
                (".Trashes", true, Ignored),
                (".fseventsd", true, Ignored),
                (".TemporaryItems", true, Ignored),
                (".DocumentRevisions-V100", true, Ignored),
                (".AppleDouble", true, Ignored),
                ("docs/.notes.md.icloud", false, Ignored),
                ("Icon", false, Synced),
                ("Icon\rx", false, Synced),
                (".icloud", false, Synced),
                ("x.icloud", false, Synced),
                (".DS_Store2", false, Synced),
                ("_x", false, Synced),
                (".gitignore", false, Synced),
                (".git", true, GitRo),
            ],
        );
        r.set_exceptions(vec![rp("assets/.DS_Store")]);
        check(
            &r,
            &[
                ("assets/.DS_Store", false, Synced),
                ("other/.DS_Store", false, Ignored),
            ],
        );
    }

    #[test]
    fn rule_file_updates() {
        let mut r = sample();
        assert!(r.is_rule_file(&rp("sub/.gitignore")));
        assert!(r.is_rule_file(&rp(".git/info/exclude")));
        assert!(r.is_rule_file(&rp(".git/modules/lib/info/exclude")));
        assert!(!r.is_rule_file(&rp("sub/x.txt")));

        assert_eq!(
            r.update_rule_file(&rp("sub/.gitignore"), Some(b"!important.log\n*.tmp\n")),
            None
        );
        assert_eq!(
            r.set_rule_file(&rp("sub/.gitignore"), Some(b"!important.log\n*.tmp\n")),
            rp("sub")
        );
        assert_eq!(
            r.update_rule_file(&rp("sub/.gitignore"), None),
            Some(rp("sub"))
        );
        assert_eq!(r.classify(&rp("sub/important.log"), false), Class::Ignored);
        assert_eq!(r.classify(&rp("sub/x.tmp"), false), Class::Synced);

        assert_eq!(
            r.update_rule_file(&rp(".git/modules/lib/info/exclude"), Some(b"")),
            Some(rp("vendor/lib"))
        );
        assert_eq!(r.classify(&rp("vendor/lib/a.gen"), false), Class::Synced);

        assert_eq!(
            r.update_rule_file(&rp(".gitignore"), Some(b"*.md\n")),
            Some(RelPath::root())
        );
        assert_eq!(r.classify(&rp("a.log"), false), Class::Synced);
        assert_eq!(r.classify(&rp("x/a.md"), true), Class::Ignored);
    }

    #[test]
    fn extras_inherit_and_case_folding() {
        let mut r = Rules::new(&[]);
        r.add_repo(&rp("a"), &rp("a/.git"));
        assert!(r.set_extra(&RelPath::root(), Some(b"*.bak\n")));
        assert!(!r.set_extra(&RelPath::root(), Some(b"*.bak\n")));
        assert_eq!(r.classify(&rp("a/x.bak"), false), Class::Ignored);
        assert!(r.set_extra(&rp("a"), Some(b"")));
        assert_eq!(r.classify(&rp("a/x.bak"), false), Class::Synced);
        assert_eq!(r.classify(&rp("x.bak"), false), Class::Ignored);
        assert_eq!(r.exclude_srcs().len(), 2);
        assert_eq!(r.repos(), vec![(rp("a"), rp("a/.git"))]);

        assert_eq!(r.classify(&rp("X.BAK"), false), Class::Synced);
        r.set_ignore_case(true);
        assert_eq!(r.classify(&rp("X.BAK"), false), Class::Ignored);

        let mut ctx = r.dir_ctx(&RelPath::root());
        assert_eq!(
            r.classify_in(&mut ctx, ".csync~1234", false),
            Class::Internal
        );
        assert!(r.remove_repo(&rp("a")));
        assert!(r.repos().is_empty());
    }

    // a folding volume opens .git for ".GIT", so the host must classify what the kernel will resolve
    #[test]
    fn fixed_names_fold_on_folding_volumes() {
        use Class::*;
        let mut r = Rules::new(&[]);
        r.add_repo(&RelPath::root(), &rp(".git"));
        r.set_rule_file(&rp(".gitignore"), Some(b".env\nsecrets/\n"));
        r.set_fs_fold(false, false);
        check(
            &r,
            &[
                (".GIT/config", false, Synced),
                (".ENV", false, Synced),
                (".CSYNC~1", false, Synced),
            ],
        );
        assert!(!r.is_rule_file(&rp("a/.GITIGNORE")));

        r.set_fs_fold(true, true);
        check(
            &r,
            &[
                (".GIT", true, GitRo),
                (".GIT/hooks/post-checkout", false, GitRo),
                (".Git/config", false, GitRo),
                ("sub/.gIt/config", false, GitRo),
                (".gi\u{200c}t/config", false, GitRo),
                ("\u{feff}.git/config", false, GitRo),
                (".CSYNC~1", false, Internal),
                (".c\u{17f}ync~1", false, Internal),
                ("d/.Csync~x", true, Internal),
                (".ENV", false, Ignored),
                ("SECRETS/key.pem", false, Ignored),
                (".github/x", false, Synced),
                (".gitx", false, Synced),
                (".csync", false, Synced),
                ("src/main.rs", false, Synced),
            ],
        );
        assert!(r.is_rule_file(&rp("a/.GITIGNORE")));
        assert!(r.is_rule_file(&rp(".GitIgnore")));
        assert_eq!(r.rule_scope(&rp("a/.GITIGNORE")), rp("a"));
        assert!(!r.is_rule_file(&rp("a/.gitignores")));

        r.set_fs_fold(false, true);
        check(
            &r,
            &[(".GIT/config", false, GitRo), (".ENV", false, Synced)],
        );
    }

    fn key(t: &[u8]) -> Option<Hash32> {
        Some(*blake3::hash(t).as_bytes())
    }

    #[test]
    fn guest_rule_edits_only_narrow() {
        use Class::*;
        let mut r = Rules::new(&[]);
        r.add_repo(&RelPath::root(), &rp(".git"));
        r.set_rule_file(&rp(".gitignore"), Some(b"secret\n.env\n"));
        check(&r, &[("secret", false, Ignored), ("x.tmp", false, Synced)]);

        let t: &[u8] = b"*.tmp\n!.env\n";
        r.note_guest_rule(&rp(".gitignore"), key(t));
        assert_eq!(
            r.update_rule_file(&rp(".gitignore"), Some(t)),
            Some(RelPath::root())
        );
        check(
            &r,
            &[
                ("secret", false, Ignored),
                (".env", false, Ignored),
                ("x.tmp", false, Ignored),
                ("d/secret", true, Ignored),
                ("ok.rs", false, Synced),
            ],
        );

        let sub: &[u8] = b"!secret\n";
        r.note_guest_rule(&rp("sub/.gitignore"), key(sub));
        r.update_rule_file(&rp("sub/.gitignore"), Some(sub));
        check(&r, &[("sub/secret", false, Ignored)]);

        r.note_guest_rule(&rp(".gitignore"), None);
        assert!(r.update_rule_file(&rp(".gitignore"), None).is_some());
        check(
            &r,
            &[
                ("secret", false, Ignored),
                (".env", false, Ignored),
                ("x.tmp", false, Synced),
            ],
        );
        assert!(r.has_dir_rules(&RelPath::root()));

        // a host edit is trusted and may widen
        r.update_rule_file(&rp(".gitignore"), Some(b"other\n"));
        check(
            &r,
            &[
                ("secret", false, Synced),
                ("other", false, Ignored),
                ("sub/secret", false, Synced),
            ],
        );

        // guest text seen again later still only narrows the host's rules
        r.update_rule_file(&rp(".gitignore"), Some(t));
        check(
            &r,
            &[
                ("other", false, Ignored),
                ("x.tmp", false, Ignored),
                ("secret", false, Synced),
            ],
        );
        r.set_ignore_case(true);
        check(&r, &[("OTHER", false, Ignored), ("X.TMP", false, Ignored)]);
    }
}
