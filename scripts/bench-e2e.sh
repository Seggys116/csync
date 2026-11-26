#!/bin/bash
# end-to-end benchmark: host + FUSE guest in one container. run with the repo mounted at /src and a corpus of source trees at /corpus:
# docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined -v "$PWD":/src -v /path/to/trees:/corpus:ro -v "$PWD"/scripts/bench-e2e.sh:/bench.sh:ro -v /tmp/out:/out -w /src rust:latest bash /bench.sh
set -u
apt-get update -qq >/dev/null && apt-get install -y -qq fuse3 inotify-tools git ripgrep >/dev/null 2>&1
cd /src && cargo build --release --locked 2>&1 | tail -1
BIN=/target/release/csync
T() { local s e; s=$(date +%s%N); "$@" >/dev/null 2>&1; e=$(date +%s%N); echo $(( (e-s)/1000000 )); }
rm -rf /data && mkdir -p /data/proj /data/mnt /data/hh /data/gh
for d in $(ls -d /corpus/*/* | head -${CRATES:-1500}); do cp -a "$d" /data/proj/ 2>/dev/null; done
cd /data/proj && printf 'target/\nnode_modules/\n' > .gitignore && git init -q . && git add -A >/dev/null 2>&1 && git -c user.email=a@b -c user.name=n commit -qm init
FILES=$(find /data/proj -path /data/proj/.git -prune -o -type f -print | wc -l)
echo "corpus files (non-.git): $FILES"
echo "native find ms: $(T find /data/proj -type f)"
echo "native git status ms: $(cd /data/proj && T git status --porcelain)"
echo "native rg ms: $(T rg -c 'fn ' /data/proj --no-ignore -g '!.git')"
HK=$(CSYNC_HOME=/data/hh $BIN key show); GK=$(CSYNC_HOME=/data/gh $BIN key show)
CSYNC_HOME=/data/hh $BIN trust add "$GK" --role guest --name g >/dev/null
CSYNC_HOME=/data/gh $BIN trust add "$HK" --role host --name h >/dev/null
HS=$(date +%s%N)
(tail -f /dev/null | CSYNC_HOME=/data/hh $BIN --no-tui host /data/proj --listen 127.0.0.1:47000 --no-pair --no-mdns > /data/host.log 2>&1) &
while ! grep -E 'stats files=[1-9]' /data/host.log >/dev/null 2>&1; do sleep 0.02; done
echo "host start to indexed ms: $(( ($(date +%s%N)-HS)/1000000 ))"
JS=$(date +%s%N)
(tail -f /dev/null | CSYNC_HOME=/data/gh $BIN --no-tui join /data/mnt --connect 127.0.0.1:47000 --host h > /data/guest.log 2>&1) &
while ! mountpoint -q /data/mnt; do sleep 0.005; done
echo "join to mounted ms: $(( ($(date +%s%N)-JS)/1000000 ))"
echo "guest find (cold) ms: $(T find /data/mnt -type f)"
echo "guest find (warm) ms: $(T find /data/mnt -type f)"
echo "guest git status (cold) ms: $(cd /data/mnt && T git -c safe.directory='*' status --porcelain)"
echo "guest git status (warm) ms: $(cd /data/mnt && T git -c safe.directory='*' status --porcelain)"
echo "guest rg (cold) ms: $(T rg -c 'fn ' /data/mnt --no-ignore -g '!.git')"
echo "guest rg (warm) ms: $(T rg -c 'fn ' /data/mnt --no-ignore -g '!.git')"
D0=$(find /data/proj -mindepth 1 -maxdepth 1 -type d ! -name .git | head -1 | xargs basename); F=$D0/zz_probe.txt
: > /data/proj/$F; sleep 1
python3 - "/data/proj/$F" "/data/mnt/$F" <<'PY'
import ctypes, os, struct, sys, time, select
host, guest = sys.argv[1], sys.argv[2]
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.inotify_init1(os.O_NONBLOCK)
IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE = 0x2, 0x4, 0x8
libc.inotify_add_watch(fd, guest.encode(), IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE)
out = []
w = os.open(host, os.O_WRONLY | os.O_APPEND)
p = select.poll(); p.register(fd, select.POLLIN)
for i in range(200):
    time.sleep(0.02)
    try:
        while os.read(fd, 4096): pass
    except BlockingIOError: pass
    t0 = time.monotonic_ns(); os.write(w, b"x\n")
    if p.poll(3000):
        out.append((time.monotonic_ns() - t0) / 1000)
        time.sleep(0.01)
out.sort()
n = len(out)
if n:
    print("host edit -> guest inotify us (watcher kept open): n=%d p50=%d p90=%d p99=%d max=%d" % (n, out[n//2], out[int(n*0.9)], out[min(n-1, int(n*0.99))], out[-1]))
else:
    print("host edit -> guest inotify: no events seen")
PY
W=/data/mnt/$F; LAT=()
for i in $(seq 1 60); do S0=$(date +%s%N); echo "g$i" > $W; E0=$(date +%s%N); LAT+=($(( (E0-S0)/1000 ))); done
printf '%s\n' "${LAT[@]}" | sort -n | awk '{a[NR]=$1} END{print "guest write+close us: p50="a[int(NR*0.5)+1]" p90="a[int(NR*0.9)+1]" max="a[NR]}'
LAT=(); for i in $(seq 1 60); do S0=$(date +%s%N); echo "t$i" > $W.tmp; mv $W.tmp $W; E0=$(date +%s%N); LAT+=($(( (E0-S0)/1000 ))); done
printf '%s\n' "${LAT[@]}" | sort -n | awk '{a[NR]=$1} END{print "guest atomic save us: p50="a[int(NR*0.5)+1]" p90="a[int(NR*0.9)+1]" max="a[NR]}'
HP=$(pgrep -f 'csync.*host' | head -1); GP=$(pgrep -f 'csync.*join' | head -1)
jif() { awk '{print $14+$15}' /proc/$1/stat; }
ctx() { awk '/voluntary_ctxt_switches/ && !/nonvol/ {print $2}' /proc/$1/status; }
CLK=$(getconf CLK_TCK)
sleep 3; a=$(jif $HP); b=$(jif $GP); c=$(ctx $HP); d=$(ctx $GP); sleep 5
echo "idle 5s: host cpu_ms=$(( ($(jif $HP)-a)*1000/CLK )) wakeups/s=$(( ($(ctx $HP)-c)/5 )); guest cpu_ms=$(( ($(jif $GP)-b)*1000/CLK )) wakeups/s=$(( ($(ctx $GP)-d)/5 )); host rss_kb=$(awk '/VmRSS/{print $2}' /proc/$HP/status) guest rss_kb=$(awk '/VmRSS/{print $2}' /proc/$GP/status)"
a=$(jif $HP); S0=$(date +%s%N); mkdir -p /data/proj/target/storm; for i in $(seq 1 300); do mkdir -p /data/proj/target/storm/d$i; for j in $(seq 1 100); do : > /data/proj/target/storm/d$i/f$j; done; done; E0=$(date +%s%N); sleep 2
echo "storm: 30000 ignored files in $(( (E0-S0)/1000000 )) ms; host csync cpu_ms=$(( ($(jif $HP)-a)*1000/CLK ))"
cd /data/proj && git ls-files | grep -v '^\.' | head -3000 > /data/churn.lst
LASTF=$(tail -1 /data/churn.lst); a=$(jif $HP); g=$(jif $GP); S0=$(date +%s%N)
while read -r f; do echo "// churn" >> "$f"; done < /data/churn.lst
E1=$(date +%s%N)
until tail -c 9 "/data/mnt/$LASTF" 2>/dev/null | grep -q churn; do sleep 0.01; done
E2=$(date +%s%N)
echo "churn 3000 files: host wrote in $(( (E1-S0)/1000000 )) ms; guest saw last in $(( (E2-S0)/1000000 )) ms; host cpu_ms=$(( ($(jif $HP)-a)*1000/CLK )) guest cpu_ms=$(( ($(jif $GP)-g)*1000/CLK ))"
mkdir -p /data/mnt/gw; a=$(jif $HP); g=$(jif $GP); S0=$(date +%s%N)
for i in $(seq 1 2000); do echo "file $i" > /data/mnt/gw/f$i.txt; done
E1=$(date +%s%N)
until [ "$(ls /data/proj/gw | wc -l)" = 2000 ]; do sleep 0.01; done
E2=$(date +%s%N)
echo "guest bulk write 2000 files: $(( (E1-S0)/1000000 )) ms through mount; all on host after $(( (E2-S0)/1000000 )) ms; host cpu_ms=$(( ($(jif $HP)-a)*1000/CLK )) guest cpu_ms=$(( ($(jif $GP)-g)*1000/CLK ))"
dd if=/dev/urandom of=/data/proj/big.bin bs=1M count=512 2>/dev/null; sleep 1
S0=$(date +%s%N); cat /data/mnt/big.bin > /dev/null; E1=$(date +%s%N)
echo "guest read 512MiB cold: $(( (E1-S0)/1000000 )) ms ($(( 512*1000/ ((E1-S0)/1000000) )) MiB/s)"
S0=$(date +%s%N); cat /data/mnt/big.bin > /dev/null; E1=$(date +%s%N)
echo "guest read 512MiB warm: $(( (E1-S0)/1000000 )) ms"
S0=$(date +%s%N); dd if=/data/mnt/big.bin of=/data/mnt/big2.bin bs=1M 2>/dev/null; sync; until [ "$(stat -c %s /data/proj/big2.bin 2>/dev/null)" = 536870912 ]; do sleep 0.02; done; E1=$(date +%s%N)
echo "guest write 512MiB to host: $(( (E1-S0)/1000000 )) ms ($(( 512*1000/ ((E1-S0)/1000000) )) MiB/s)"
echo "host log errors: $(grep -ciE 'error|panic' /data/host.log)"
cp /data/host.log /data/guest.log /out/ 2>/dev/null; fusermount3 -u /data/mnt 2>/dev/null; pkill -f csync; sleep 0.5
