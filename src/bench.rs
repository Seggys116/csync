use crate::ignore::rules::Rules;
use crate::index::scan;
use crate::proto::{
    BATCH_MAX, Change, Kind, Meta, Msg, Push, RelPath,
    frame::{Decoder, Encoder, Frame},
};
use crate::tui::json_str;
use std::{
    fmt::Write as _,
    hint::black_box,
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Row {
    pub name: &'static str,
    pub iters: u64,
    pub secs: f64,
    pub bytes: u64,
    pub items: u64,
    pub note: String,
}

impl Row {
    pub fn per_op_us(&self) -> f64 {
        if self.iters == 0 {
            0.0
        } else {
            self.secs * 1e6 / self.iters as f64
        }
    }
    pub fn mib_s(&self) -> f64 {
        if self.secs <= 0.0 {
            0.0
        } else {
            (self.bytes * self.iters) as f64 / self.secs / (1 << 20) as f64
        }
    }
    pub fn items_s(&self) -> f64 {
        if self.secs <= 0.0 {
            0.0
        } else {
            (self.items * self.iters) as f64 / self.secs
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Opts {
    pub path: Option<PathBuf>,
    pub quick: bool,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for c in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
    }
}

// runs f until min_time has passed, at least once
fn time(
    name: &'static str,
    min_time: Duration,
    bytes: u64,
    items: u64,
    mut f: impl FnMut(),
) -> Row {
    f();
    let start = Instant::now();
    let mut iters = 0u64;
    loop {
        f();
        iters += 1;
        if start.elapsed() >= min_time {
            break;
        }
    }
    Row {
        name,
        iters,
        secs: start.elapsed().as_secs_f64(),
        bytes,
        items,
        note: String::new(),
    }
}

pub fn run(o: &Opts) -> io::Result<Vec<Row>> {
    let min = if o.quick {
        Duration::from_millis(100)
    } else {
        Duration::from_millis(600)
    };
    let mut rows = Vec::with_capacity(10);
    if let Some(root) = &o.path {
        rows.extend(bench_scan(root, min)?);
    }
    rows.extend(bench_hash(min));
    rows.push(bench_merge(min)?);
    rows.extend(bench_frame(min)?);
    rows.extend(bench_delta(min));
    rows.push(bench_classify(min));
    Ok(rows)
}

fn bench_scan(root: &std::path::Path, min: Duration) -> io::Result<Vec<Row>> {
    let start = Instant::now();
    let mut rules = Rules::new(&[]);
    let tree = scan::scan(root, &mut rules)?;
    let first = start.elapsed().as_secs_f64();
    let files = tree.len() as u64;
    let mut out = vec![Row {
        name: "scan (first run)",
        iters: 1,
        secs: first,
        bytes: 0,
        items: files,
        note: format!("{files} entries in {}", root.display()),
    }];
    let mut tree = Some(tree);
    let mut err = None;
    let mut re = time("rescan (stat keys reused)", min, 0, files, || {
        let Some(t) = tree.take() else { return };
        let mut r = Rules::new(&[]);
        match scan::rescan(root, &mut r, t) {
            Ok(t) => tree = Some(t),
            Err(e) => err = Some(e),
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    re.note = "warm page cache, no rehash".into();
    out.push(re);
    Ok(out)
}

fn bench_hash(min: Duration) -> Vec<Row> {
    let mut buf = vec![0u8; 64 << 20];
    Rng(0x9e37_79b9_7f4a_7c15).fill(&mut buf);
    let n = buf.len() as u64;
    let mut one = time("blake3, one thread", min, n, 1, || {
        black_box(blake3::hash(black_box(&buf)));
    });
    one.note = "64 MiB buffer".into();
    let mut par = time("blake3, rayon", min, n, 1, || {
        let mut h = blake3::Hasher::new();
        h.update_rayon(black_box(&buf));
        black_box(h.finalize());
    });
    par.note = format!("{} threads", rayon::current_num_threads());
    vec![one, par]
}

fn text_lines(n: usize, tag: &str, every: usize, offset: usize) -> Vec<u8> {
    let mut s = String::with_capacity(n * 48);
    for i in 0..n {
        if every > 0 && i % every == offset {
            let _ = writeln!(s, "    let value_{i} = compute({i}, \"{tag}\");");
        } else {
            let _ = writeln!(s, "    let value_{i} = compute({i}, \"base\");");
        }
    }
    s.into_bytes()
}

fn bench_merge(min: Duration) -> io::Result<Row> {
    const LINES: usize = 20_000;
    let base = text_lines(LINES, "", 0, 0);
    let ours = text_lines(LINES, "ours", 100, 0);
    let theirs = text_lines(LINES, "theirs", 100, 50);
    if crate::merge::merge3(&base, &ours, &theirs).is_err() {
        return Err(io::Error::other("merge3 bench input did not merge cleanly"));
    }
    let mut r = time("merge3, clean", min, base.len() as u64, 1, || {
        black_box(
            crate::merge::merge3(black_box(&base), black_box(&ours), black_box(&theirs)).ok(),
        );
    });
    r.note = format!("{LINES} lines, {} edits per side", LINES / 100);
    Ok(r)
}

fn changes_msg() -> io::Result<Msg> {
    let mut changes = Vec::with_capacity(BATCH_MAX);
    for i in 0..BATCH_MAX {
        let path = RelPath::new(&format!("src/module_{}/file_{i}.rs", i % 64))
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let meta = Meta {
            kind: Kind::File,
            perm: 0o644,
            size: 1000 + i as u64,
            mtime_ns: 1_700_000_000_000_000_000 + i as i64,
            ctime_ns: 1_700_000_000_000_000_000,
            hash: Some(hash),
            link: None,
            git_ro: false,
        };
        changes.push(Change::Upsert {
            path,
            meta,
            ver: 1_000 + i as u64,
        });
    }
    Ok(Msg::Push(Push::Changes { seq: 42, changes }))
}

fn bench_frame(min: Duration) -> io::Result<Vec<Row>> {
    let msg = changes_msg()?;
    let mut enc = Encoder::default();
    let mut segs: Vec<Vec<u8>> = Vec::new();
    let mut wire = 0u64;
    enc.msg(&msg, &mut |s| {
        wire += s.len() as u64;
        segs.push(s.to_vec());
    })
    .map_err(|e| io::Error::other(format!("encode: {e:?}")))?;
    let raw = postcard::to_stdvec(&msg)
        .map_err(|e| io::Error::other(format!("postcard: {e}")))?
        .len() as u64;
    let mut e = time(
        "frame encode (8192 changes)",
        min,
        raw,
        BATCH_MAX as u64,
        || {
            let mut n = 0usize;
            let _ = enc.msg(black_box(&msg), &mut |s| n += s.len());
            black_box(n);
        },
    );
    e.note = format!("{} KiB postcard, {} KiB on the wire", raw >> 10, wire >> 10);
    let mut dec = Decoder::default();
    let mut bad = false;
    let mut d = time(
        "frame decode (8192 changes)",
        min,
        raw,
        BATCH_MAX as u64,
        || {
            for s in &segs {
                match dec.push(black_box(s)) {
                    Ok(Some(Frame::Msg(m))) => {
                        black_box(&m);
                    }
                    Ok(_) => {}
                    Err(_) => bad = true,
                }
            }
        },
    );
    if bad {
        return Err(io::Error::other("frame decode failed on its own encoding"));
    }
    d.note = "includes lz4 and limit validation".into();
    Ok(vec![e, d])
}

fn bench_delta(min: Duration) -> Vec<Row> {
    let mut base = vec![0u8; 16 << 20];
    Rng(0x2545_f491_4f6c_dd1d).fill(&mut base);
    let mut new = base.clone();
    let mut r = Rng(7);
    for _ in 0..64 {
        let at = (r.next() as usize) % (new.len() - 64);
        r.fill(&mut new[at..at + 64]);
    }
    let n = base.len() as u64;
    let mut s = time("delta signatures", min, n, 1, || {
        black_box(crate::delta::sigs(black_box(&base)));
    });
    s.note = "16 MiB".into();
    let sigs = crate::delta::sigs(&base);
    let mut e = time("delta encode", min, n, 1, || {
        black_box(crate::delta::encode(black_box(&new), black_box(&sigs)));
    });
    e.note = "64 scattered 64-byte edits".into();
    vec![s, e]
}

const GITIGNORE: &str = "target/\n*.o\n*.log\nnode_modules/\n/dist\nbuild/\n.env\n*.tmp\n!keep.tmp\ncoverage/\n**/generated/*.rs\n.DS_Store\n*.swp\n";

fn bench_classify(min: Duration) -> Row {
    let mut rules = Rules::new(&[]);
    if let Ok(p) = RelPath::new(".gitignore") {
        rules.set_rule_file(&p, Some(GITIGNORE.as_bytes()));
    }
    let exts = ["rs", "o", "log", "tmp", "toml", "md"];
    let tops = [
        "src",
        "target",
        "node_modules",
        "docs",
        "crates/core",
        "crates/generated",
    ];
    let mut paths = Vec::with_capacity(100_000);
    for i in 0..100_000usize {
        let s = format!(
            "{}/m{}/f{i}.{}",
            tops[i % tops.len()],
            i % 97,
            exts[i % exts.len()]
        );
        if let Ok(p) = RelPath::new(&s) {
            paths.push(p);
        }
    }
    let n = paths.len() as u64;
    let mut r = time("ignore classify", min, 0, n, || {
        for p in &paths {
            black_box(rules.classify(black_box(p), false));
        }
    });
    r.note = format!("{n} paths, {} rules", GITIGNORE.lines().count());
    r
}

fn rate(v: f64) -> String {
    if v <= 0.0 {
        "-".into()
    } else if v >= 1e6 {
        format!("{:.1}M", v / 1e6)
    } else if v >= 1e3 {
        format!("{:.1}k", v / 1e3)
    } else {
        format!("{v:.0}")
    }
}

pub fn render(rows: &[Row]) -> String {
    let w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(9);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<w$}  {:>8}  {:>12}  {:>10}  {:>10}  note",
        "benchmark", "iters", "per op", "MiB/s", "items/s"
    );
    for r in rows {
        let per = r.per_op_us();
        let per = if per >= 1e6 {
            format!("{:.2} s", per / 1e6)
        } else if per >= 1e3 {
            format!("{:.2} ms", per / 1e3)
        } else {
            format!("{per:.1} us")
        };
        let mib = if r.bytes == 0 {
            "-".to_owned()
        } else {
            format!("{:.0}", r.mib_s())
        };
        let _ = writeln!(
            s,
            "{:<w$}  {:>8}  {:>12}  {:>10}  {:>10}  {}",
            r.name,
            r.iters,
            per,
            mib,
            rate(r.items_s()),
            r.note
        );
    }
    s
}

pub fn render_json(rows: &[Row]) -> String {
    let mut s = String::from("[");
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"name\":");
        json_str(&mut s, r.name);
        let _ = write!(
            s,
            ",\"iters\":{},\"secs\":{:.6},\"per_op_us\":{:.3},\"mib_per_s\":{:.3},\"items_per_s\":{:.1},\"note\":",
            r.iters,
            r.secs,
            r.per_op_us(),
            r.mib_s(),
            r.items_s()
        );
        json_str(&mut s, &r.note);
        s.push('}');
    }
    s.push(']');
    s
}
