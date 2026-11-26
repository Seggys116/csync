use super::{DEPTH_MAX, LINK_MAX, NAME_MAX, PATH_MAX};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use std::{borrow::Cow, fmt};

pub const TMP_PREFIX: &str = ".csync~";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    Empty,
    Dot,
    Slash,
    Nul,
    TooLong,
    TooDeep,
    Reserved,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty path component",
            Self::Dot => "dot component",
            Self::Slash => "slash in name",
            Self::Nul => "nul byte",
            Self::TooLong => "too long",
            Self::TooDeep => "too deep",
            Self::Reserved => "reserved name",
        })
    }
}

impl std::error::Error for PathError {}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Name(Box<str>);
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct RelPath(Box<str>);
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkTarget(Box<str>);

fn check_name(s: &str) -> Result<(), PathError> {
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s == "." || s == ".." {
        return Err(PathError::Dot);
    }
    if s.len() > NAME_MAX {
        return Err(PathError::TooLong);
    }
    if s.as_bytes().contains(&b'/') {
        return Err(PathError::Slash);
    }
    if s.as_bytes().contains(&0) {
        return Err(PathError::Nul);
    }
    if s.starts_with(TMP_PREFIX) {
        return Err(PathError::Reserved);
    }
    Ok(())
}

fn check_rel(s: &str) -> Result<(), PathError> {
    if s.is_empty() {
        return Ok(());
    }
    if s.len() > PATH_MAX {
        return Err(PathError::TooLong);
    }
    for (depth, c) in s.split('/').enumerate() {
        if depth >= DEPTH_MAX {
            return Err(PathError::TooDeep);
        }
        check_name(c)?;
    }
    Ok(())
}

fn check_link(s: &str) -> Result<(), PathError> {
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s.len() > LINK_MAX {
        return Err(PathError::TooLong);
    }
    if s.as_bytes().contains(&0) {
        return Err(PathError::Nul);
    }
    Ok(())
}

fn fold(s: &str) -> Cow<'_, str> {
    if s.chars().any(|c| !c.to_lowercase().eq(std::iter::once(c))) {
        Cow::Owned(s.to_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

impl Name {
    pub fn new(s: &str) -> Result<Self, PathError> {
        check_name(s)?;
        Ok(Self(s.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    // collision key for case-insensitive host volumes; identity when the host is case sensitive
    pub fn fold_key(&self, case_fold: bool) -> Cow<'_, str> {
        if case_fold {
            fold(&self.0)
        } else {
            Cow::Borrowed(&self.0)
        }
    }
}

impl RelPath {
    pub fn root() -> Self {
        Self(Box::from(""))
    }
    pub fn new(s: &str) -> Result<Self, PathError> {
        check_rel(s)?;
        Ok(Self(s.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }
    pub fn depth(&self) -> usize {
        if self.is_root() {
            0
        } else {
            self.0.bytes().filter(|&b| b == b'/').count() + 1
        }
    }
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|c| !c.is_empty())
    }
    pub fn split_last(&self) -> Option<(&str, &str)> {
        if self.is_root() {
            return None;
        }
        Some(self.0.rsplit_once('/').unwrap_or(("", &*self.0)))
    }
    pub fn parent(&self) -> Option<RelPath> {
        self.split_last().map(|(dir, _)| Self(dir.into()))
    }
    pub fn join(&self, n: &Name) -> Result<Self, PathError> {
        if self.is_root() {
            return Ok(Self(n.0.clone()));
        }
        let len = self.0.len() + 1 + n.0.len();
        if len > PATH_MAX {
            return Err(PathError::TooLong);
        }
        if self.depth() >= DEPTH_MAX {
            return Err(PathError::TooDeep);
        }
        let mut s = String::with_capacity(len);
        s.push_str(&self.0);
        s.push('/');
        s.push_str(&n.0);
        Ok(Self(s.into_boxed_str()))
    }
    pub fn starts_with(&self, dir: &RelPath) -> bool {
        dir.is_root()
            || self.0 == dir.0
            || (self.0.starts_with(&*dir.0) && self.0.as_bytes().get(dir.0.len()) == Some(&b'/'))
    }
    pub fn fold_key(&self, case_fold: bool) -> Cow<'_, str> {
        if case_fold {
            fold(&self.0)
        } else {
            Cow::Borrowed(&self.0)
        }
    }
}

impl LinkTarget {
    pub fn new(s: &str) -> Result<Self, PathError> {
        check_link(s)?;
        Ok(Self(s.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn stays_within(&self, at: &RelPath) -> bool {
        at.depth()
            .checked_sub(1)
            .is_some_and(|d| self.climbs_within(d))
    }

    // only the real directories above the link can be climbed; a `..` after a name may pass back out through a symlink
    pub fn climbs_within(&self, dir_depth: usize) -> bool {
        if self.0.starts_with('/') {
            return false;
        }
        let (mut up, mut named) = (0usize, false);
        for c in self.0.split('/') {
            match c {
                "" | "." => {}
                ".." => {
                    up += 1;
                    if named || up > dir_depth {
                        return false;
                    }
                }
                _ => named = true,
            }
        }
        true
    }
}

struct StrVisitor(fn(&str) -> Result<(), PathError>);

impl<'de> Visitor<'de> for StrVisitor {
    type Value = Box<str>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a valid path string")
    }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<Box<str>, E> {
        (self.0)(s).map_err(E::custom)?;
        Ok(s.into())
    }
    fn visit_string<E: de::Error>(self, s: String) -> Result<Box<str>, E> {
        (self.0)(&s).map_err(E::custom)?;
        Ok(s.into_boxed_str())
    }
}

// one allocation per decoded string, validated before it exists as a typed value
macro_rules! wire_str {
    ($t:ident, $check:path) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                d.deserialize_str(StrVisitor($check)).map($t)
            }
        }
    };
}
wire_str!(Name, check_name);
wire_str!(RelPath, check_rel);
wire_str!(LinkTarget, check_link);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_rejects_bad() {
        assert_eq!(Name::new(""), Err(PathError::Empty));
        assert_eq!(Name::new("."), Err(PathError::Dot));
        assert_eq!(Name::new(".."), Err(PathError::Dot));
        assert_eq!(Name::new("a/b"), Err(PathError::Slash));
        assert_eq!(Name::new("a\0b"), Err(PathError::Nul));
        assert_eq!(Name::new(".csync~tmp1"), Err(PathError::Reserved));
        assert_eq!(
            Name::new(&"x".repeat(NAME_MAX + 1)),
            Err(PathError::TooLong)
        );
        assert!(Name::new(&"x".repeat(NAME_MAX)).is_ok());
        assert!(Name::new("...").is_ok());
        assert!(Name::new(".csync").is_ok());
    }

    #[test]
    fn name_unicode_length_is_bytes() {
        let e = "\u{e9}";
        assert_eq!(e.len(), 2);
        assert!(Name::new(&e.repeat(NAME_MAX / 2)).is_ok());
        assert_eq!(
            Name::new(&e.repeat(NAME_MAX / 2 + 1)),
            Err(PathError::TooLong)
        );
        assert!(Name::new("\u{1f600}\u{200d}x").is_ok());
    }

    #[test]
    fn relpath_traversal() {
        for bad in [
            "..", "../x", "a/../b", "a/..", "./a", "a/./b", "/a", "a/", "a//b", "/", "a/\0",
        ] {
            assert!(RelPath::new(bad).is_err(), "{bad:?}");
        }
        assert_eq!(RelPath::new("a/.csync~x/b"), Err(PathError::Reserved));
        assert!(RelPath::new("").unwrap().is_root());
        let p = RelPath::new("a/b..c/..d").unwrap();
        assert_eq!(p.components().collect::<Vec<_>>(), ["a", "b..c", "..d"]);
    }

    #[test]
    fn relpath_limits() {
        let deep = vec!["d"; DEPTH_MAX].join("/");
        let p = RelPath::new(&deep).unwrap();
        assert_eq!(p.depth(), DEPTH_MAX);
        assert_eq!(RelPath::new(&format!("{deep}/d")), Err(PathError::TooDeep));
        assert_eq!(p.join(&Name::new("d").unwrap()), Err(PathError::TooDeep));
        let long = vec!["x".repeat(200); 21].join("/");
        assert!(long.len() > PATH_MAX);
        assert_eq!(RelPath::new(&long), Err(PathError::TooLong));
        let base = RelPath::new(&vec!["y".repeat(255); 16].join("/")).unwrap();
        assert_eq!(base.as_str().len(), 255 * 16 + 15);
        assert_eq!(
            base.join(&Name::new(&"z".repeat(10)).unwrap()),
            Err(PathError::TooLong)
        );
    }

    #[test]
    fn relpath_helpers() {
        let p = RelPath::new("a/b/c").unwrap();
        assert_eq!(p.split_last(), Some(("a/b", "c")));
        assert_eq!(p.parent().unwrap().as_str(), "a/b");
        assert_eq!(
            RelPath::new("a").unwrap().parent().unwrap(),
            RelPath::root()
        );
        assert_eq!(RelPath::root().parent(), None);
        assert!(p.starts_with(&RelPath::new("a/b").unwrap()));
        assert!(!p.starts_with(&RelPath::new("a/bc").unwrap()));
        assert!(
            !RelPath::new("a/bc")
                .unwrap()
                .starts_with(&RelPath::new("a/b").unwrap())
        );
        assert_eq!(
            RelPath::root()
                .join(&Name::new("x").unwrap())
                .unwrap()
                .as_str(),
            "x"
        );
        assert_eq!(
            p.join(&Name::new("d").unwrap()).unwrap().as_str(),
            "a/b/c/d"
        );
    }

    #[test]
    fn link_targets() {
        assert_eq!(LinkTarget::new(""), Err(PathError::Empty));
        assert_eq!(LinkTarget::new("a\0"), Err(PathError::Nul));
        assert_eq!(
            LinkTarget::new(&"a".repeat(LINK_MAX + 1)),
            Err(PathError::TooLong)
        );
        let at = RelPath::new("d/link").unwrap();
        assert!(LinkTarget::new("x").unwrap().stays_within(&at));
        assert!(LinkTarget::new("..").unwrap().stays_within(&at));
        assert!(LinkTarget::new("./../x/./y").unwrap().stays_within(&at));
        assert!(!LinkTarget::new("../..").unwrap().stays_within(&at));
        assert!(LinkTarget::new("../../x").unwrap().climbs_within(2));
        assert!(!LinkTarget::new("../../x").unwrap().climbs_within(1));
        assert!(!LinkTarget::new("/etc/passwd").unwrap().stays_within(&at));
        assert!(
            !LinkTarget::new("..")
                .unwrap()
                .stays_within(&RelPath::new("link").unwrap())
        );
    }

    // with a -> "." in place, "a/a/../.." would climb two levels above the link's directory
    #[test]
    fn link_targets_get_no_credit_for_names() {
        let at = RelPath::new("d/e/link").unwrap();
        for bad in ["a/a/../..", "a/../../x", "x/..", "a/../b", "../a/.."] {
            assert!(!LinkTarget::new(bad).unwrap().stays_within(&at), "{bad}");
        }
        let top = RelPath::new("b").unwrap();
        assert!(LinkTarget::new(".").unwrap().stays_within(&top));
        assert!(!LinkTarget::new("a/a/../..").unwrap().stays_within(&top));
        assert!(!LinkTarget::new("x").unwrap().stays_within(&RelPath::root()));
    }

    #[test]
    fn fold_keys() {
        let n = Name::new("ReadMe.MD").unwrap();
        assert_eq!(n.fold_key(true), "readme.md");
        assert_eq!(n.fold_key(false), "ReadMe.MD");
        assert!(matches!(
            Name::new("lower").unwrap().fold_key(true),
            Cow::Borrowed(_)
        ));
        assert_eq!(
            Name::new("\u{c9}t\u{c9}").unwrap().fold_key(true),
            "\u{e9}t\u{e9}"
        );
    }

    #[test]
    fn decode_routes_through_validation() {
        let bad = postcard::to_stdvec("a/../b").unwrap();
        assert!(postcard::from_bytes::<RelPath>(&bad).is_err());
        let nul = postcard::to_stdvec("a\0").unwrap();
        assert!(postcard::from_bytes::<Name>(&nul).is_err());
        let res = postcard::to_stdvec(".csync~1").unwrap();
        assert!(postcard::from_bytes::<Name>(&res).is_err());
        let ok = postcard::to_stdvec(&RelPath::new("a/b").unwrap()).unwrap();
        assert_eq!(
            postcard::from_bytes::<RelPath>(&ok).unwrap().as_str(),
            "a/b"
        );
        let invalid_utf8 = [3u8, b'a', 0xff, b'b'];
        assert!(postcard::from_bytes::<Name>(&invalid_utf8).is_err());
    }
}
