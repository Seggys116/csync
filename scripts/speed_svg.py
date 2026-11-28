#!/usr/bin/env python3
"""write .github/assets/speed.svg from the medians of three runs of the bench workflow.

usage: speed_svg.py OUT.svg

the numbers below are the medians (and fastest and slowest) of the three runs in the bench workflow run 46144603795
on commit c8da170; update them from the step summary of a newer run and regenerate.
"""
import sys

FONT = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono','DejaVu Sans Mono',monospace"
W, H = 960, 548
groups = [
    ("find -type f", [("native", 31, 31, 34), ("first run", 829, 321, 1033), ("repeat", 315, 72, 951)]),
    ("git status", [("native", 37, 36, 46), ("first run", 405, 263, 476), ("repeat", 131, 62, 159)]),
    ("rg over the tree", [("native", 77, 76, 80), ("first run", 738, 579, 829), ("repeat", 174, 161, 269)]),
]
COL = {"native": "#6e7681", "first run": "#a78bfa", "repeat": "#2dd4bf"}
tiles = [
    ("1.5 ms", "host edit to guest inotify, p90 5.7 ms"),
    ("1.0 ms", "write and close a file on the guest"),
    ("2.0 ms", "save through a temp file and rename"),
    ("120 ms", "join to a usable mount"),
    ("0 CPU", "and 0 wakeups per second when idle"),
]
chips = [
    ("104 ms", "3,000 files changed on the host,", "guest converged"),
    ("298 ms", "2,000 small files written on", "the guest, all on the host"),
    ("734 ms", "first read of a 512 MiB file,", "698 MiB/s"),
    ("7.9 s", "write a 512 MiB file to the", "host, 65 MiB/s"),
]
o = []
a = o.append
desc = ("Medians of three runs on a GitHub-hosted runner with a real host and a real FUSE guest in one container, 15,959 files. "
        "find over the tree: native 31 ms, first run 829 ms, repeat 315 ms. git status: native 37 ms, first run 405 ms, repeat 131 ms. "
        "rg over the tree: native 77 ms, first run 738 ms, repeat 174 ms. Host edit to guest inotify event 1.5 ms median and 5.7 ms p90. "
        "Write and close on the guest 1.0 ms, save through a temp file and rename 2.0 ms, join to a usable mount 120 ms, idle 0 CPU and 0 wakeups. "
        "3,000 host files changed and seen by the guest in 104 ms, 2,000 small guest files all on the host in 298 ms, "
        "first read of 512 MiB in 734 ms, writing 512 MiB to the host in 7.9 s.")
a(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t d" font-family="{FONT}">')
a('<title id="t">csync speed</title>')
a(f'<desc id="d">{desc}</desc>')
a(f'<rect width="{W}" height="{H}" rx="18" fill="#0d1117"/><rect x="1" y="1" width="{W-2}" height="{H-2}" rx="17" fill="none" stroke="#30363d" stroke-width="2"/>')
a('<text x="32" y="38" font-size="13" font-weight="700" fill="#c9d1d9">how fast it is</text>')
a('<text x="928" y="38" text-anchor="end" font-size="11" fill="#8b949e">milliseconds, lower is better</text>')
# left panel
a('<rect x="32" y="56" width="600" height="336" fill="#161b22" stroke="#30363d" stroke-width="2" shape-rendering="crispEdges"/>')
a('<text x="52" y="82" font-size="13" font-weight="700" fill="#c9d1d9">reading a 15,959-file project through the mount</text>')
a('<text x="52" y="100" font-size="10" fill="#8b949e">each command has its own scale; bars are medians, whiskers the fastest to slowest run</text>')
BX, BW = 130, 380
y = 126
for name, rows in groups:
    top = max(r[3] for r in rows)
    a(f'<text x="52" y="{y}" font-size="12" font-weight="700" fill="#c9d1d9">{name}</text>')
    a(f'<text x="612" y="{y}" text-anchor="end" font-size="10" fill="#8b949e">scale 0-{top} ms</text>')
    for i, (label, med, lo, hi) in enumerate(rows):
        ry = y + 12 + i * 22
        c = COL[label]
        w = max(2.0, BW * med / top)
        a(f'<text x="52" y="{ry + 10}" font-size="11" fill="#8b949e">{label}</text>')
        a(f'<rect x="{BX}" y="{ry}" width="{w:.1f}" height="14" fill="{c}" shape-rendering="crispEdges"/>')
        xl, xh = BX + BW * lo / top, BX + BW * hi / top
        if hi - lo > 0 and label != "native":
            a(f'<path d="M{xl:.1f} {ry+7}H{xh:.1f}M{xl:.1f} {ry+3}V{ry+11}M{xh:.1f} {ry+3}V{ry+11}" stroke="#c9d1d9" stroke-width="1.2" fill="none" shape-rendering="crispEdges"/>')
        end = max(BX + w, xh if label != "native" else 0)
        a(f'<text x="{end + 8:.1f}" y="{ry + 11}" font-size="11" fill="#c9d1d9">{med} ms</text>')
    y += 88
# right panel
a('<rect x="652" y="56" width="276" height="336" fill="#161b22" stroke="#30363d" stroke-width="2" shape-rendering="crispEdges"/>')
a('<text x="672" y="82" font-size="13" font-weight="700" fill="#c9d1d9">latency</text>')
a('<text x="672" y="100" font-size="10" fill="#8b949e">medians</text>')
ty = 132
for big, cap in tiles:
    a(f'<text x="672" y="{ty}" font-size="22" font-weight="700" fill="#2dd4bf">{big}</text>')
    a(f'<text x="672" y="{ty + 17}" font-size="10" fill="#8b949e">{cap}</text>')
    ty += 52
# chips
cw, gap = 218, 8
for i, (big, cap, cap2) in enumerate(chips):
    x = 32 + i * (cw + gap)
    a(f'<rect x="{x}" y="410" width="{cw}" height="76" fill="#161b22" stroke="#30363d" stroke-width="2" shape-rendering="crispEdges"/>')
    a(f'<rect x="{x}" y="410" width="4" height="76" fill="#a78bfa" shape-rendering="crispEdges"/>')
    a(f'<text x="{x + 16}" y="436" font-size="16" font-weight="700" fill="#c9d1d9">{big}</text>')
    a(f'<text x="{x + 16}" y="456" font-size="10" fill="#8b949e">{cap}</text>')
    a(f'<text x="{x + 16}" y="470" font-size="10" fill="#8b949e">{cap2}</text>')
a('<text x="32" y="508" font-size="10" fill="#8b949e">a GitHub-hosted ubuntu-24.04 runner, host and guest in one container over loopback; every join starts with an empty cache,</text>')
a('<text x="32" y="524" font-size="10" fill="#8b949e">so first run is what a new session sees and repeat is a repeat in the same session; native is the same command on the host directory</text>')
a('</svg>')
open(sys.argv[1], "w").write("\n".join(o) + "\n")
