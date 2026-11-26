import os, pty, sys, time, select, fcntl, termios, struct, signal, json, html, pyte

NAMED = {"black":"#0d1117","red":"#ff7b72","green":"#3fb950","brown":"#d29922","blue":"#58a6ff","magenta":"#bc8cff","cyan":"#39c5cf","white":"#c9d1d9",
         "brightblack":"#6e7681","brightred":"#ffa198","brightgreen":"#56d364","brightbrown":"#e3b341","brightblue":"#79c0ff","brightmagenta":"#d2a8ff","brightcyan":"#56d4dd","brightwhite":"#f0f6fc"}
BG = "#0d1117"; FG = "#c9d1d9"
def col(c, default):
    if c == "default": return default
    if c in NAMED: return NAMED[c]
    if len(c) == 6:
        try: int(c, 16); return "#" + c
        except ValueError: pass
    return default

def svg(screen, cols, rows, title):
    cw, ch = 9.0, 19.0
    W, H = cols*cw + 24, rows*ch + 24
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W:.0f} {H:.0f}" width="{W:.0f}" height="{H:.0f}" role="img" aria-label="{html.escape(title)}">',
           f'<rect width="{W:.0f}" height="{H:.0f}" rx="12" fill="{BG}"/>',
           '<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="15" xml:space="preserve">']
    for y in range(rows):
        row = screen.buffer[y]
        x = 0
        # background runs
        while x < cols:
            c = row[x]; b = col(c.bg, None) if not c.reverse else col(c.fg, FG)
            x2 = x
            while x2 < cols:
                d = row[x2]; bb = col(d.bg, None) if not d.reverse else col(d.fg, FG)
                if bb != b: break
                x2 += 1
            if b and b != BG:
                out.append(f'<rect x="{12+x*cw:.1f}" y="{12+y*ch:.1f}" width="{(x2-x)*cw:.1f}" height="{ch:.1f}" fill="{b}"/>')
            x = x2
        # text runs by fg
        x = 0
        while x < cols:
            c = row[x]
            f = col(c.fg, FG) if not c.reverse else col(c.bg, BG)
            bold = c.bold
            x2 = x; txt = ""
            while x2 < cols:
                d = row[x2]
                ff = col(d.fg, FG) if not d.reverse else col(d.bg, BG)
                if ff != f or d.bold != bold: break
                txt += d.data if d.data else " "; x2 += 1
            if txt.strip():
                w = ' font-weight="700"' if bold else ''
                out.append(f'<text x="{12+x*cw:.1f}" y="{12+y*ch+14:.1f}" fill="{f}"{w} textLength="{(x2-x)*cw:.1f}" lengthAdjust="spacing">{html.escape(txt)}</text>')
            x = x2
    out.append('</g></svg>')
    return "\n".join(out)

def run(cmd, cols, rows, snaps, keys, env_extra):
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(env_extra); os.environ["TERM"]="xterm-256color"; os.environ["COLORTERM"]="truecolor"
        os.execvp(cmd[0], cmd)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    screen = pyte.Screen(cols, rows); stream = pyte.ByteStream(screen)
    t0 = time.time(); out = {}; snaps = sorted(snaps); keys = sorted(keys)
    while snaps or keys:
        now = time.time() - t0
        nxt = min([s[0] for s in snaps] + [k[0] for k in keys])
        r, _, _ = select.select([fd], [], [], max(0, min(0.05, nxt - now)))
        if r:
            try: data = os.read(fd, 65536)
            except OSError: break
            stream.feed(data)
        now = time.time() - t0
        while keys and keys[0][0] <= now:
            os.write(fd, keys.pop(0)[1].encode())
        while snaps and snaps[0][0] <= now:
            t, name = snaps.pop(0); out[name] = svg(screen, cols, rows, name)
    try: os.kill(pid, signal.SIGINT); time.sleep(0.4); os.waitpid(pid, os.WNOHANG)
    except Exception: pass
    return out

if __name__ == "__main__":
    spec = json.load(open(sys.argv[1]))
    res = run(spec["cmd"], spec.get("cols", 100), spec.get("rows", 30), [(t, n) for t, n in spec["snaps"]], [(t, k) for t, k in spec.get("keys", [])], spec.get("env", {}))
    for name, s in res.items():
        open(os.path.join(spec["outdir"], name + ".svg"), "w").write(s)
    print("wrote", ", ".join(res))
