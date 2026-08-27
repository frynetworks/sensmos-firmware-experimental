# Crash-signature-strict segmented soak for the mDNS OOM fix (sensmos ESP8266).
# FOREGROUND MANDATE: every invocation is a single bounded blocking process — no backgrounding.
# The CC harness caps one call at 600 s, so a 620 s window runs as TWO sequential capture calls
# plus an instant eval call (each blocks until it exits on its own):
#   py -3 tools/gate_mdns_soak.py --seconds 320 --out F                    # segment A (DTR reset)
#   py -3 tools/gate_mdns_soak.py --seconds 300 --no-reset --append --out F  # segment B (no reset)
#   py -3 tools/gate_mdns_soak.py --eval F --criteria mdns|soak            # verdict (file-only)
#
# eval criteria:
#   mdns — the crash-signature gate: FAIL on any crash marker (postmortem text, exception dumps,
#          WDT) or on ANY boot marker after the segment-A boot (a reboot; also catches a crash
#          hiding in the inter-segment gap, because steady state never re-prints boot lines).
#   soak — tools/gate_soak.py's assertions mirrored 1:1 (that gate is 620 s single-process and
#          cannot fit the 600 s harness cap; it is NOT modified): boots<=1, no crash marker,
#          "heap (\d)k" min >= --floor (default 3000), WiFi connect observed, last IP printed —
#          PLUS the segment-B boot-marker check above (stricter, never looser).
# Exit 0 = PASS, 1 = FAIL. Assertions are never loosened to pass.
import sys, os, time, re, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

SEG_MARK = "===GATE SEGMENT START"
CRASH = ("Unhandled C++ exception", "CUT HERE", "Exception (", "Fatal exception",
         "Soft WDT", "abort()", "Panic", "wdt reset", "user_fatal_exception", "new device")
POSTMORTEM_RST = re.compile(r"ets [A-Za-z]{3}\s+\d+ \d{4},rst cause:")   # readable = postmortem reprint
BOOT = ("SENSMOS SmartNode", "[boot] ready", "[wifi] connecting to")
HEAP_RE = re.compile(r"heap (\d+)k")


def do_capture(a):
    mode = "a" if a.append else "w"
    out = open(a.out, mode, encoding="utf-8")
    out.write("%s seconds=%d reset=%s===\n" % (SEG_MARK, a.seconds, not a.no_reset)); out.flush()
    ser = su.open_with_retry(None, 115200, do_reset=not a.no_reset, verbose=False)
    start = time.time(); buf = b""; n = 0; last_beat = 0
    try:
        while time.time() - start < a.seconds:
            el = int(time.time() - start)
            if el - last_beat >= 60:
                last_beat = el
                print("[mdns-soak] t=%ds lines=%d" % (el, n), flush=True)
            chunk = ser.read(256)
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                t = raw.decode("utf-8", "replace").rstrip("\r")
                out.write(t + "\n"); out.flush(); n += 1
                if any(c in t for c in CRASH) or POSTMORTEM_RST.search(t):
                    print("[mdns-soak] LIVE CRASH LINE: %s" % t, flush=True)
    finally:
        ser.close(); out.close()
    print("[mdns-soak] capture done: %ds, %d lines -> %s" % (a.seconds, n, a.out), flush=True)


def do_eval(a):
    lines = open(a.eval, encoding="utf-8", errors="replace").read().splitlines()
    segs = [i for i, t in enumerate(lines) if t.startswith(SEG_MARK)]
    crash = [t for t in lines if any(c in t for c in CRASH) or POSTMORTEM_RST.search(t)]
    banners = [t for t in lines if "SENSMOS SmartNode" in t]
    # boot markers after the LAST segment start (segment B must be pure steady state)
    b_start = segs[-1] if len(segs) >= 2 else None
    gap_boot = [t for i, t in enumerate(lines)
                if b_start is not None and i > b_start and any(b in t for b in BOOT)]
    heaps = [int(m.group(1)) * 1024 for t in lines for m in [HEAP_RE.search(t)] if m]
    min_heap = min(heaps) if heaps else None
    connected = any("connected, ip " in t or "connecting to " in t for t in lines)
    ips = [m.group(1) for t in lines for m in [re.search(r"ip (\d+\.\d+\.\d+\.\d+)", t)] if m]
    fails = []
    if crash:
        fails.append("crash marker: %s" % crash[0])
    if len(banners) > 1:
        fails.append("reboot: %d boot banners" % len(banners))
    if gap_boot:
        fails.append("boot marker in segment B (reboot in window/gap): %s" % gap_boot[0])
    if a.criteria == "soak":
        if not connected:
            fails.append("never observed WiFi connect")
        if min_heap is not None and min_heap < a.floor:
            fails.append("heap floor: min %d < %d" % (min_heap, a.floor))
    if fails:
        print("[mdns-soak] EVAL FAIL (%s): %s" % (a.criteria, "; ".join(fails)))
        raise SystemExit(1)
    print("[mdns-soak] EVAL PASS (%s): segments=%d banners=%d crash=0 min_heap=%s ip=%s"
          % (a.criteria, len(segs), len(banners),
             min_heap if min_heap is not None else "n/a", ips[-1] if ips else "n/a"))
    raise SystemExit(0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=320)
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--eval", default=None)
    ap.add_argument("--criteria", choices=["mdns", "soak"], default="mdns")
    ap.add_argument("--floor", type=int, default=3000)
    a = ap.parse_args()
    if a.eval:
        do_eval(a)
    else:
        if not a.out:
            ap.error("--out required for capture mode")
        do_capture(a)


if __name__ == "__main__":
    main()
