#!/usr/bin/env python3
"""record real terminal sessions and write animated svgs for the readme.

usage: tui_capture.py SPEC.json [--save-timeline FILE | --load-timeline FILE] [--frames-dir DIR]

needs pyte (pip install pyte, in a venv). strings in the spec may use ${CAP_NAME} placeholders, filled from
the environment. the spec lists:

  cols, rows   terminal size in cells
  panes        {name: {"cmd": [...], "env": {...}, "cwd": "..."}}, each program runs on its own pty
  steps        run in order: {"start": pane}, {"wait_text": {"pane", "re", "timeout"}}, {"sleep": s},
               {"keys": {"pane", "data"}}, {"run": [argv], "bg": false, "timeout": s}, {"mark": name},
               {"stop": pane}, {"print": pane}
  outputs      [{"file", "pane", "from", "from_offset", "to", "to_offset", "title", "pause", "fps",
               "still", "still_offset"}]; from, to and still name marks, offsets are seconds

every pane is sampled into a timeline of screen states. an output is a window of one timeline drawn as one
svg: rows are split into pieces that are defined once and shown or hidden by css keyframes, glyphs that only
change colour get a colour animation, box, block, braille and circle glyphs are vector shapes. under
prefers-reduced-motion the svg shows the frame at "still" (default: the last frame).
"""
import fcntl
import html
import json
import os
import pickle
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
import unicodedata
from collections import defaultdict

import pyte

BG = "#0d1117"
FG = "#c9d1d9"
BAR_BG = "#161b22"
EDGE = "#30363d"
NAMED = {
    "black": "#0d1117", "red": "#ff7b72", "green": "#3fb950", "brown": "#d29922", "blue": "#58a6ff",
    "magenta": "#bc8cff", "cyan": "#39c5cf", "white": "#c9d1d9", "brightblack": "#6e7681",
    "brightred": "#ffa198", "brightgreen": "#56d364", "brightbrown": "#e3b341", "brightblue": "#79c0ff",
    "brightmagenta": "#d2a8ff", "brightcyan": "#56d4dd", "brightwhite": "#f0f6fc",
}
FONT = "ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','DejaVu Sans Mono',monospace"

CW, CH = 8.4, 18.0
FONT_PX = 14
BASE_Y = 13.4
PAD_X, PAD_B, BAR_H = 14, 14, 30
LW, HW, DG = 1.2, 2.4, 1.7
BLEED = 0.3

BOLD, ITAL, UNDER, STRIKE = 1, 2, 4, 8


def color(name, default):
    if name == "default":
        return default
    if name in NAMED:
        return NAMED[name]
    if len(name) == 6:
        try:
            int(name, 16)
            return "#" + name
        except ValueError:
            pass
    return default


def snap_cell(c, is_cursor):
    fg, bg = color(c.fg, FG), color(c.bg, None)
    if c.reverse != is_cursor:
        fg, bg = (bg or BG), fg
    if bg == BG:
        bg = None
    ch = c.data
    if ch == "":
        return ("",)
    flags = (BOLD if c.bold else 0) | (ITAL if c.italics else 0) | (UNDER if c.underscore else 0) | (STRIKE if c.strikethrough else 0)
    if ch == " " and bg is None and not flags & (UNDER | STRIKE):
        return (" ",)
    return (ch, fg, bg, flags)


class Pane:
    def __init__(self, name, cmd, env, cwd, cols, rows):
        self.name, self.cols, self.rows = name, cols, rows
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.lock = threading.Lock()
        self.row_ids, self.row_table = {}, []
        self.frames = []
        self.t0 = time.monotonic()
        self.dirty, self.last_snap, self.alive = True, 0.0, True
        pid, fd = pty.fork()
        if pid == 0:
            os.environ.update(env)
            os.environ["TERM"] = "xterm-256color"
            os.environ["COLORTERM"] = "truecolor"
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            if cwd:
                os.chdir(cwd)
            os.execvp(cmd[0], cmd)
        self.pid, self.fd = pid, fd
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.thread = threading.Thread(target=self.pump, daemon=True)
        self.thread.start()

    def snapshot(self, now):
        cur = self.screen.cursor
        ids = []
        for y in range(self.rows):
            line = self.screen.buffer[y]
            cells = tuple(snap_cell(line[x], (not cur.hidden) and cur.y == y and cur.x == x) for x in range(self.cols))
            rid = self.row_ids.get(cells)
            if rid is None:
                rid = self.row_ids[cells] = len(self.row_table)
                self.row_table.append(cells)
            ids.append(rid)
        if not self.frames or self.frames[-1][1] != ids:
            self.frames.append((now, ids))
        self.dirty, self.last_snap = False, now

    def pump(self):
        while True:
            r, _, _ = select.select([self.fd], [], [], 0.03)
            now = time.monotonic() - self.t0
            if r:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    data = b""
                if not data:
                    break
                with self.lock:
                    self.stream.feed(data)
                    self.dirty = True
            with self.lock:
                if self.dirty and now - self.last_snap >= 0.03:
                    self.snapshot(now)
        with self.lock:
            self.snapshot(time.monotonic() - self.t0)
            self.alive = False

    def text(self):
        with self.lock:
            return "\n".join(self.screen.display)

    def send(self, data):
        os.write(self.fd, data.encode())

    def stop(self):
        if self.alive:
            try:
                self.send("q")
            except OSError:
                pass
            for _ in range(60):
                if not self.alive:
                    break
                time.sleep(0.1)
        if self.alive:
            try:
                os.kill(self.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
            time.sleep(1.0)
        if self.alive:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass


def build_arms():
    arms = {}
    strength = {"LIGHT": 1, "HEAVY": 2, "DOUBLE": 3, "SINGLE": 1}
    dirs = {"UP": "u", "DOWN": "d", "LEFT": "l", "RIGHT": "r", "VERTICAL": "ud", "HORIZONTAL": "lr"}
    for cp in list(range(0x2500, 0x2504)) + list(range(0x250C, 0x254C)) + list(range(0x2550, 0x256D)) + list(range(0x2574, 0x2580)):
        name = unicodedata.name(chr(cp))[len("BOX DRAWINGS "):]
        a = {"u": 0, "d": 0, "l": 0, "r": 0}
        inherit = 1
        for part in name.split(" AND "):
            words = part.split()
            s = next((strength[w] for w in words if w in strength), None)
            if s is not None:
                inherit = s
            for w in words:
                if w in dirs:
                    for d in dirs[w]:
                        a[d] = s if s is not None else inherit
        arms[cp] = a
    return arms


ARMS = build_arms()
ARCS = {0x256D: ("d", "r", 1), 0x256E: ("d", "l", 0), 0x256F: ("u", "l", 1), 0x2570: ("u", "r", 0)}
DASHES = {0x2504: (3, 1, True), 0x2505: (3, 2, True), 0x2506: (3, 1, False), 0x2507: (3, 2, False),
          0x2508: (4, 1, True), 0x2509: (4, 2, True), 0x250A: (4, 1, False), 0x250B: (4, 2, False),
          0x254C: (2, 1, True), 0x254D: (2, 2, True), 0x254E: (2, 1, False), 0x254F: (2, 2, False)}
OPP = {"l": "r", "r": "l", "u": "d", "d": "u"}
SIGN = {"l": -1, "r": 1, "u": -1, "d": 1}


def block_rects(cp):
    """cell fractions (x0, y0, x1, y1, alpha) for U+2580-259F"""
    if cp == 0x2580:
        return [(0, 0, 1, .5, 1)]
    if 0x2581 <= cp <= 0x2588:
        return [(0, 1 - (cp - 0x2580) / 8, 1, 1, 1)]
    if 0x2589 <= cp <= 0x258F:
        return [(0, 0, (0x2590 - cp) / 8, 1, 1)]
    if cp == 0x2590:
        return [(.5, 0, 1, 1, 1)]
    if 0x2591 <= cp <= 0x2593:
        return [(0, 0, 1, 1, (cp - 0x2590) / 4)]
    if cp == 0x2594:
        return [(0, 0, 1, 1 / 8, 1)]
    if cp == 0x2595:
        return [(7 / 8, 0, 1, 1, 1)]
    quad = {0x2596: "bl", 0x2597: "br", 0x2598: "tl", 0x2599: "tl bl br", 0x259A: "tl br", 0x259B: "tl tr bl",
            0x259C: "tl tr br", 0x259D: "tr", 0x259E: "tr bl", 0x259F: "tr bl br"}
    if cp in quad:
        pos = {"tl": (0, 0, .5, .5), "tr": (.5, 0, 1, .5), "bl": (0, .5, .5, 1), "br": (.5, .5, 1, 1)}
        return [pos[q] + (1,) for q in quad[cp].split()]
    return None


def is_vector(ch):
    cp = ord(ch)
    return cp in ARMS or cp in ARCS or cp in DASHES or 0x2580 <= cp <= 0x259F or cp in (0x2571, 0x2572, 0x2573) \
        or 0x2800 <= cp <= 0x28FF or cp in (0x25CF, 0x25CB)


def arm_rects(a, x0, y0):
    """filled rects for the line arms of one cell, joined exactly at the centre"""
    cx, cy = x0 + CW / 2, y0 + CH / 2
    thick = {1: LW, 2: HW, 3: LW}
    out = []
    for d in "udlr":
        s = a[d]
        if not s:
            continue
        horiz = d in "lr"
        perp = ("u", "d") if horiz else ("l", "r")
        c = cx if horiz else cy
        far = {"l": x0, "r": x0 + CW, "u": y0, "d": y0 + CH}[d]
        sg = SIGN[d]
        t = thick[s]
        offs = [-DG, DG] if s == 3 else [0.0]
        pstr = [a[p] for p in perp]
        for o in offs:
            side = perp[0] if o < 0 else perp[1]
            if s == 3 and a[side] == 3:
                inner = c + sg * (DG - t / 2)
            elif a[OPP[d]]:
                inner = c
            elif 3 in pstr:
                inner = c - sg * (DG + LW / 2)
            elif any(pstr):
                inner = c - sg * max(thick[p] for p in pstr if p) / 2
            else:
                inner = c
            lo, hi = min(far, inner), max(far, inner)
            if horiz:
                out.append((lo, cy + o - t / 2, hi, cy + o + t / 2))
            else:
                out.append((cx + o - t / 2, lo, cx + o + t / 2, hi))
    return out


def fmt(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


BRAILLE_DOTS = [(0, 0, 0x01), (0, 1, 0x02), (0, 2, 0x04), (1, 0, 0x08), (1, 1, 0x10), (1, 2, 0x20), (0, 3, 0x40), (1, 3, 0x80)]


def circle_path(cx, cy, r):
    return f"M{fmt(cx - r)} {fmt(cy)}a{fmt(r)} {fmt(r)} 0 1 0 {fmt(2 * r)} 0a{fmt(r)} {fmt(r)} 0 1 0 {fmt(-2 * r)} 0z"


def glyph_shapes(ch, x0):
    """(rects, strokes, shades, dots) in row-local coordinates for a vector glyph, or None"""
    cp = ord(ch)
    cx, cy = x0 + CW / 2, CH / 2
    if 0x2800 <= cp <= 0x28FF:
        dots = [circle_path(x0 + CW * (0.3 + 0.4 * c), CH * (0.25 + 0.2 * r), 1.15) for c, r, bit in BRAILLE_DOTS if cp & bit]
        return [], [], [], dots
    if cp == 0x25CF:
        return [], [], [], [circle_path(cx, cy, 3.9)]
    if cp == 0x25CB:
        return [], [circle_path(cx, cy, 3.4)], [], []
    g = shapes_basic(ch, x0)
    return None if g is None else g + ([],)


def shapes_basic(ch, x0):
    """(rects, strokes, shades) in row-local coordinates for a box or block glyph, or None"""
    cp = ord(ch)
    y0 = 0.0
    x1, y1 = x0 + CW, y0 + CH
    cx, cy = x0 + CW / 2, y0 + CH / 2
    rects, arcs, shades = [], [], []
    if cp in ARMS:
        return arm_rects(ARMS[cp], x0, y0), arcs, shades
    if cp in ARCS:
        v, h, sweep = ARCS[cp]
        sy = y1 if v == "d" else y0
        ex = x1 if h == "r" else x0
        arcs.append(f"M{fmt(cx)} {fmt(sy)}A{fmt(CW / 2)} {fmt(CH / 2)} 0 0 {sweep} {fmt(ex)} {fmt(cy)}")
        return rects, arcs, shades
    if cp in DASHES:
        n, mult, horizontal = DASHES[cp]
        th = HW if mult == 2 else LW
        for i in range(n):
            if horizontal:
                seg = CW / n
                rects.append((x0 + i * seg + seg * .15, cy - th / 2, x0 + (i + 1) * seg - seg * .15, cy + th / 2))
            else:
                seg = CH / n
                rects.append((cx - th / 2, y0 + i * seg + seg * .15, cx + th / 2, y0 + (i + 1) * seg - seg * .15))
        return rects, arcs, shades
    if cp in (0x2571, 0x2572, 0x2573):
        if cp in (0x2571, 0x2573):
            arcs.append(f"M{fmt(x0)} {fmt(y1)}L{fmt(x1)} {fmt(y0)}")
        if cp in (0x2572, 0x2573):
            arcs.append(f"M{fmt(x0)} {fmt(y0)}L{fmt(x1)} {fmt(y1)}")
        return rects, arcs, shades
    br = block_rects(cp)
    if br is None:
        return None
    for fx0, fy0, fx1, fy1, al in br:
        r = (x0 + fx0 * CW, y0 + fy0 * CH, x0 + fx1 * CW, y0 + fy1 * CH)
        if al == 1:
            rects.append(r)
        else:
            shades.append(r + (al,))
    return rects, arcs, shades


def merge_rects(rects):
    by_y = defaultdict(list)
    for x0, y0, x1, y1 in rects:
        by_y[(round(y0, 3), round(y1, 3))].append([x0, x1])
    out = []
    for (y0, y1), spans in by_y.items():
        spans.sort()
        cur = spans[0]
        for s in spans[1:]:
            if s[0] <= cur[1] + 1e-3:
                cur[1] = max(cur[1], s[1])
            else:
                out.append((cur[0], y0, cur[1], y1))
                cur = s
        out.append((cur[0], y0, cur[1], y1))
    return out


def rect_path(rects):
    parts = []
    for x0, y0, x1, y1 in rects:
        if y0 <= 0.001:
            y0 -= BLEED
        if y1 >= CH - 0.001:
            y1 += BLEED
        if abs(x0 / CW - round(x0 / CW)) < 1e-6:
            x0 -= BLEED
        if abs(x1 / CW - round(x1 / CW)) < 1e-6:
            x1 += BLEED
        parts.append(f"M{fmt(x0)} {fmt(y0)}h{fmt(x1 - x0)}v{fmt(y1 - y0)}h{fmt(x0 - x1)}z")
    return "".join(parts)


class Palette:
    def __init__(self):
        self.ids = {}

    def cls(self, c):
        if c not in self.ids:
            self.ids[c] = len(self.ids)
        return self.ids[c]

    def css(self):
        return "".join(f".f{i}{{fill:{c}}}.s{i}{{fill:none;stroke:{c};stroke-width:{LW}}}" for c, i in self.ids.items())


def is_blank(c):
    return c == (" ",)


def split_pieces(cells):
    """split a row into independent pieces (start cell, cells) at blank gaps so a change redraws only its piece"""
    out = []
    n = len(cells)
    i = 0
    while i < n:
        if is_blank(cells[i]):
            i += 1
            continue
        j = i
        while j < n:
            if not is_blank(cells[j]):
                j += 1
                continue
            k = j
            while k < n and is_blank(cells[k]):
                k += 1
            if k >= n:
                break
            prev, nxt = cells[j - 1], cells[k]
            plain = lambda c: len(c) == 4 and len(c[0]) == 1 and 32 < ord(c[0]) < 127 and c[2] is None
            if k - j == 1 and plain(prev) and plain(nxt) and prev[1] == nxt[1] and prev[3] == nxt[3]:
                j = k
                continue
            break
        out.append((i, tuple(cells[i:j])))
        i = j
    return out


INHERIT = "inherit"


def piece_elements(cells, pal):
    """svg elements for one piece laid out from x=0; fg INHERIT leaves the fill to the referencing element"""

    def fcls(c):
        return "" if c == INHERIT else f' class="f{pal.cls(c)}"'

    bgs, fgs, shades, arcs = defaultdict(list), defaultdict(list), [], defaultdict(list)
    dots = defaultdict(list)
    runs = []
    n = len(cells)
    for i, c in enumerate(cells):
        x0 = i * CW
        if len(c) == 1:
            continue
        ch, fg, bg, flags = c
        wide = i + 1 < n and cells[i + 1] == ("",)
        w = CW * (2 if wide else 1)
        if bg:
            bgs[bg].append((x0, 0, x0 + w, CH))
        if flags & UNDER:
            fgs[fg].append((x0, CH - 3, x0 + w, CH - 2))
        if flags & STRIKE:
            fgs[fg].append((x0, CH / 2 - .5, x0 + w, CH / 2 + .5))
        if ch == " ":
            continue
        if len(ch) == 1 and is_vector(ch):
            g = glyph_shapes(ch, x0)
            if g is not None:
                fgs[fg] += g[0]
                arcs[fg] += g[1]
                shades += [(fg,) + q for q in g[2]]
                dots[fg] += g[3]
                continue
        runs.append((i, ch, fg, flags & (BOLD | ITAL), wide))
    texts = []
    cur = None
    for i, ch, fg, st, wide in runs:
        if not (len(ch) == 1 and 32 <= ord(ch) < 127):
            if cur:
                texts.append(cur)
                cur = None
            texts.append((fg, st, i * CW + (CW if wide else CW / 2), ch, True, 0))
            continue
        if cur and cur[0] == fg and cur[1] == st and abs(i * CW - cur[5]) < 0.01:
            cur = (fg, st, cur[2], cur[3] + ch, False, (i + 1) * CW)
        elif cur and cur[0] == fg and cur[1] == st and abs(i * CW - cur[5] - CW) < 0.01:
            cur = (fg, st, cur[2], cur[3] + " " + ch, False, (i + 1) * CW)
        else:
            if cur:
                texts.append(cur)
            cur = (fg, st, i * CW, ch, False, (i + 1) * CW)
    if cur:
        texts.append(cur)
    out = []
    for fg, rs in bgs.items():
        out.append(f'<path class="f{pal.cls(fg)}" d="{rect_path(merge_rects(rs))}"/>')
    for fg, rs in fgs.items():
        if rs:
            out.append(f'<path{fcls(fg)} d="{rect_path(merge_rects(rs))}"/>')
    by_shade = defaultdict(list)
    for fg, x0, y0, x1, y1, al in shades:
        by_shade[(fg, al)].append((x0, y0, x1, y1))
    for (fg, al), rs in by_shade.items():
        out.append(f'<path{fcls(fg)} fill-opacity="{al:g}" d="{rect_path(merge_rects(rs))}"/>')
    for fg, ds in arcs.items():
        if ds:
            out.append(f'<path class="s{pal.cls(fg)}" d="{"".join(ds)}"/>')
    for fg, ds in dots.items():
        if ds:
            out.append(f'<path{fcls(fg)} d="{"".join(ds)}"/>')
    for fg, st, x0, s, centre, end in texts:
        attrs = "" if centre else f' textLength="{fmt(end - x0)}" lengthAdjust="spacing"'
        if st & BOLD:
            attrs += ' font-weight="700"'
        if st & ITAL:
            attrs += ' font-style="italic"'
        if centre:
            attrs += ' text-anchor="middle"'
        out.append(f'<text{fcls(fg)}{attrs} x="{fmt(x0)}" y="{BASE_Y}">{html.escape(s, quote=False)}</text>')
    return out


def window_states(pane, t_from, t_to, fps):
    """sample a pane timeline on a fixed grid: one list of row ids per grid step"""
    dt = 1.0 / fps
    n = max(1, int(round((t_to - t_from) / dt)) + 1)
    frames = pane["frames"]
    j = 0
    states = []
    for k in range(n):
        t = t_from + k * dt
        while j + 1 < len(frames) and frames[j + 1][0] <= t:
            j += 1
        states.append(frames[j][1])
    return states, dt


STROKE_ONLY = set(ARCS) | {0x2571, 0x2572, 0x2573}
VOLATILE_SHIFTS = 6
EPS = 0.01
COLOUR_TOL = 8


def rgb_of(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


def hex_of(c):
    return "#%02x%02x%02x" % c


def fits(a, b, m):
    """true when point m sits within the tolerance of the straight blend from a to b"""
    t = (m[0] - a[0]) / (b[0] - a[0])
    return all(abs(m[1][i] - (a[1][i] + (b[1][i] - a[1][i]) * t)) <= COLOUR_TOL for i in range(3))


def find_volatile(states, table, rows):
    """locations whose glyph stays put while its colour keeps changing (shimmer, breathing, gradients)"""
    shifts = defaultdict(int)
    for k in range(1, len(states)):
        for y in range(rows):
            a, b = states[k - 1][y], states[k][y]
            if a == b:
                continue
            ra, rb = table[a], table[b]
            for x, (c, d) in enumerate(zip(ra, rb)):
                if len(c) == 4 and len(d) == 4 and c[0] == d[0] and c[1] != d[1] and c[2:] == d[2:] and len(c[0]) == 1 \
                        and c[0] != " " and ord(c[0]) not in STROKE_ONLY and not (x + 1 < len(rb) and rb[x + 1] == ("",)):
                    shifts[(y, x)] += 1
    return {loc for loc, n in shifts.items() if n >= VOLATILE_SHIFTS}


def render_svg(pane, t_from, t_to, title, pause=2.5, fps=10, at=None, label="", still=None):
    cols, rows = pane["cols"], pane["rows"]
    states, dt = window_states(pane, t_from, t_to, fps)
    table = pane["table"]
    n = len(states)
    k_still = n - 1 if still is None else min(n - 1, max(0, int(round(still / dt))))
    total = n * dt + pause
    pal = Palette()
    defs, body, css_frames = [], [], []
    ids = {}

    def define(key, els):
        if key not in ids:
            ids[key] = f"p{len(ids)}"
            if len(els) == 1:
                tag, rest = els[0].split(" ", 1)
                defs.append(f'{tag} id="{ids[key]}" {rest}')
            else:
                defs.append(f'<g id="{ids[key]}">{"".join(els)}</g>')
        return ids[key]

    vol = set() if at is not None else find_volatile(states, table, rows)
    masked = {}

    def pieces(y, rid):
        if (y, rid) not in masked:
            cells = table[rid]
            if vol:
                cells = tuple((" ",) if (y, x) in vol else c for x, c in enumerate(cells))
            masked[(y, rid)] = [(x, define(("p", pc), piece_elements(pc, pal))) for x, pc in split_pieces(cells)]
        return masked[(y, rid)]

    shared = {}

    def pct(k):
        return f"{k * dt / total * 100:.3f}".rstrip("0").rstrip(".") + "%"

    def keyframes(kf):
        if kf not in shared:
            shared[kf] = f"k{len(shared)}"
            css_frames.append(f"@keyframes {shared[kf]}{{{kf}}}")
        return shared[kf]

    def animate(sp):
        """keyframes name for visibility spans [(k0, k1)]"""
        stops = {}
        for k0, k1 in sp:
            stops[k0] = "opacity:1"
            if k1 is not None:
                stops[k1] = "opacity:0"
        stops.setdefault(0, "opacity:0")
        return keyframes("".join(f"{pct(k) if k else '0%'}{{{v}}}" for k, v in sorted(stops.items())))

    def animate_colours(per_step):
        """keyframes name for a glyph whose colour drifts: stops only where a straight blend stops fitting"""
        stops = []
        k = 0
        while k < len(per_step):
            if per_step[k] is None:
                k += 1
                continue
            j = k
            while j + 1 < len(per_step) and per_step[j + 1] is not None:
                j += 1
            pts = [(i, rgb_of(per_step[i])) for i in range(k, j + 1)]
            kept = [pts[0]]
            a = 0
            for b in range(2, len(pts) + 1):
                ok = b < len(pts) and all(fits(pts[a], pts[b], pts[m]) for m in range(a + 1, b))
                if not ok:
                    kept.append(pts[b - 1])
                    a = b - 1
            if k > 0:
                stops.append((k - EPS, "opacity:0"))
            stops += [(i, f"opacity:1;fill:{hex_of(c)}") for i, c in kept]
            if j + 1 < len(per_step):
                stops.append((j + 1 - EPS, f"opacity:1;fill:{hex_of(kept[-1][1])}"))
                stops.append((j + 1, "opacity:0"))
            k = j + 1
        if not stops or stops[0][0] > 0:
            stops.insert(0, (0, "opacity:0"))
        tail = f"100%{{{stops[-1][1]}}}"
        return keyframes("".join(f"{pct(i) if i else '0%'}{{{v}}}" for i, v in stops) + tail)

    if at is not None:
        k_at = min(n - 1, max(0, int(round(at / dt))))
        for y in range(rows):
            for x, pid in pieces(y, states[k_at][y]):
                body.append(f'<use href="#{pid}" x="{fmt(x * CW)}" y="{fmt(y * CH)}"/>')
    else:
        for y in range(rows):
            spans = defaultdict(list)
            prev = set()
            for k, st in enumerate(states):
                cur = set(pieces(y, st[y]))
                for key in cur - prev:
                    spans[key].append([k, None])
                for key in prev - cur:
                    spans[key][-1][1] = k
                prev = cur
            for (x, pid), sp in spans.items():
                pos = f'x="{fmt(x * CW)}" y="{fmt(y * CH)}"'
                if len(sp) == 1 and sp[0][0] == 0 and sp[0][1] is None:
                    body.append(f'<use href="#{pid}" {pos}/>')
                    continue
                shown = any(k0 <= k_still and (k1 is None or k_still < k1) for k0, k1 in sp)
                cls = "a z" if shown else "a"
                body.append(f'<use class="{cls}" style="animation-name:{animate(sp)}" href="#{pid}" {pos}/>')
        for (y, x) in sorted(vol):
            glyphs = defaultdict(lambda: [None] * n)
            for k, st in enumerate(states):
                c = table[st[y]][x]
                if len(c) == 4 and c[0] != " " and len(c[0]) == 1:
                    glyphs[(c[0], c[2], c[3])][k] = c[1]
            for (ch, bg, flags), colours in glyphs.items():
                if ch == " ":
                    continue
                els = piece_elements(((ch, INHERIT, bg, flags),), pal)
                gid = define(("g", ch, bg, flags), els)
                end = colours[k_still]
                cls = f"a v z f{pal.cls(end)}" if end else "a v"
                body.append(f'<use class="{cls}" style="animation-name:{animate_colours(colours)}" href="#{gid}" x="{fmt(x * CW)}" y="{fmt(y * CH)}"/>')

    style = [pal.css()]
    if at is None:
        style.append(f".a{{opacity:0;animation:{fmt(total)}s step-end infinite}}.z{{opacity:1}}")
        style.append(".v{animation-timing-function:linear}")
        style.append("@media (prefers-reduced-motion:reduce){.a{animation:none!important}}")
        style += css_frames
    W = round(cols * CW + 2 * PAD_X)
    H = round(rows * CH + BAR_H + PAD_B)
    cap = html.escape(label or title, quote=True)
    bar_mid = BAR_H / 2
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="{cap}">',
        f"<title>{cap}</title>",
        f'<defs><clipPath id="w"><rect width="{W}" height="{H}" rx="10"/></clipPath>{"".join(defs)}</defs>',
        f"<style>{''.join(style)}</style>",
        f'<g clip-path="url(#w)"><rect width="{W}" height="{H}" fill="{BG}"/>',
        f'<rect width="{W}" height="{BAR_H}" fill="{BAR_BG}"/><rect y="{BAR_H - 1}" width="{W}" height="1" fill="{EDGE}"/>',
        f'<circle cx="18" cy="{bar_mid:g}" r="4.5" fill="#484f58"/><circle cx="34" cy="{bar_mid:g}" r="4.5" fill="#484f58"/><circle cx="50" cy="{bar_mid:g}" r="4.5" fill="#484f58"/>',
        f'<text x="{W / 2:g}" y="{bar_mid + 4:g}" text-anchor="middle" font-family="{FONT}" font-size="12" fill="#8b949e">{html.escape(title, quote=False)}</text>',
        f'<g transform="translate({PAD_X} {BAR_H + 4})" font-family="{FONT}" font-size="{FONT_PX}">{"".join(body)}</g></g>',
        f'<rect x=".5" y=".5" width="{W - 1}" height="{H - 1}" rx="10" fill="none" stroke="{EDGE}"/>',
        "</svg>",
    ]
    return "".join(out)


def run_spec(spec):
    cols, rows = spec.get("cols", 100), spec.get("rows", 30)
    panes, marks = {}, {}
    t_start = time.monotonic()

    def now():
        return time.monotonic() - t_start

    try:
        for step in spec["steps"]:
            if "start" in step:
                p = spec["panes"][step["start"]]
                pane = Pane(step["start"], p["cmd"], p.get("env", {}), p.get("cwd"), cols, rows)
                pane.t0 = t_start
                panes[step["start"]] = pane
            elif "wait_text" in step:
                w = step["wait_text"]
                end = time.monotonic() + w.get("timeout", 60)
                while not re.search(w["re"], panes[w["pane"]].text()):
                    if time.monotonic() > end:
                        raise RuntimeError(f"timeout waiting for {w['re']!r} in {w['pane']}:\n{panes[w['pane']].text()}")
                    time.sleep(0.05)
            elif "sleep" in step:
                time.sleep(step["sleep"])
            elif "keys" in step:
                panes[step["keys"]["pane"]].send(step["keys"]["data"])
            elif "run" in step:
                if step.get("bg"):
                    subprocess.Popen(step["run"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    subprocess.run(step["run"], timeout=step.get("timeout", 120), check=True)
            elif "mark" in step:
                marks[step["mark"]] = now()
            elif "stop" in step:
                panes[step["stop"]].stop()
            elif "print" in step:
                print(f"--- {step['print']} @ {now():.1f}s\n{panes[step['print']].text()}", file=sys.stderr)
        marks["end"] = now()
    finally:
        for pane in panes.values():
            pane.stop()
    timeline = {}
    for name, pane in panes.items():
        with pane.lock:
            timeline[name] = {"cols": cols, "rows": rows, "table": pane.row_table, "frames": pane.frames}
    return {"panes": timeline, "marks": marks}


def emit(spec, tl, frames_dir=None):
    for out in spec["outputs"]:
        pane = tl["panes"][out["pane"]]
        marks = tl["marks"]
        t0 = marks[out["from"]] + out.get("from_offset", 0) if "from" in out else 0.0
        t1 = marks[out["to"]] + out.get("to_offset", 0) if "to" in out else marks["end"]
        still = marks[out["still"]] + out.get("still_offset", 0) - t0 if "still" in out else None
        svg = render_svg(pane, t0, t1, out["title"], out.get("pause", 2.5), out.get("fps", 10), label=out.get("label", ""), still=still)
        with open(out["file"], "w") as f:
            f.write(svg)
        print(f"{out['file']}: {len(svg) / 1024:.0f} KB, {t1 - t0:.1f}s window")
        if frames_dir:
            base = os.path.splitext(os.path.basename(out["file"]))[0]
            for t in out.get("probe", [0, (t1 - t0) / 2, t1 - t0]):
                with open(os.path.join(frames_dir, f"{base}-{t:05.1f}.svg"), "w") as f:
                    f.write(render_svg(pane, t0, t1, out["title"], 0, out.get("fps", 10), at=t))


def expand(v):
    if isinstance(v, str):
        return re.sub(r"\$\{(CAP_[A-Z_]+)\}", lambda m: os.environ[m.group(1)], v)
    if isinstance(v, list):
        return [expand(x) for x in v]
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    return v


def main(argv):
    spec = expand(json.load(open(argv[1])))
    frames_dir = argv[argv.index("--frames-dir") + 1] if "--frames-dir" in argv else None
    if "--load-timeline" in argv:
        tl = pickle.load(open(argv[argv.index("--load-timeline") + 1], "rb"))
    else:
        tl = run_spec(spec)
        if "--save-timeline" in argv:
            pickle.dump(tl, open(argv[argv.index("--save-timeline") + 1], "wb"))
    emit(spec, tl, frames_dir)


if __name__ == "__main__":
    main(sys.argv)
