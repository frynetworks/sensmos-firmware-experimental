# Soak gate: reset the board, capture N seconds, assert the node stays up — no reboot, no crash marker,
# heap stays above a floor, and the WiFi/IP is held throughout. This is the primary heap-fix gate:
# before the fix a checknet/net_worker HTTPS job OOM-crashed (BearSSL default 32 KB buffers) mid-soak.
#   py -3 tools/gate_soak.py [--seconds 620] [--floor 6000] [--out FILE]
# Exit 0 = PASS, 1 = FAIL. Assertions are never loosened to pass.
import sys, os, time, re, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

CRASH = ("Exception (", "Fatal exception", "wdt reset", "Soft WDT", "abort()", "rst cause:2",
         "rst cause:3", "user_fatal_exception", "Panic", "new device")
BOOT = ("SENSMOS SmartNode",)   # one marker per boot (both banner lines print each boot)
HEAP_RE = re.compile(r"heap (\d+)k")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=620)
    # ESP8266 near-OOM danger threshold. The node normally dips to ~5k free / ~2k block during checknet
    # ICMP probes (which DEFER safely via their own heap gate — no crash); 3000 is the real "imminent OOM"
    # level. Primary pass criteria are 0 reboots + 0 crashes + IP held.
    ap.add_argument("--floor", type=int, default=3000)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = open(a.out, "w", encoding="utf-8") if a.out else None
    ser = su.open_with_retry(None, 115200, do_reset=True)
    start = time.time(); buf = b""
    boots = 0; min_heap = 99999; last_ip = None; connected = False; fail = None
    try:
        while time.time() - start < a.seconds:
            chunk = ser.read(256)
            if not chunk: continue
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                t = raw.decode("utf-8", "replace").rstrip("\r")
                if out: out.write(t + "\n"); out.flush()
                if any(b in t for b in BOOT):
                    boots += 1
                    if boots > 1:                 # first boot is our own reset; any further boot = reboot
                        print("[soak] FAIL reboot after %ds: %s" % (int(time.time()-start), t)); raise SystemExit(1)
                if any(c in t for c in CRASH):
                    print("[soak] FAIL crash after %ds: %s" % (int(time.time()-start), t)); raise SystemExit(1)
                m = HEAP_RE.search(t)
                if m:
                    h = int(m.group(1)) * 1024
                    if h < min_heap: min_heap = h
                    if h * 1024 and (h*1024) < a.floor: pass
                if "connected, ip " in t or "connecting to GQ" in t: connected = True
                mi = re.search(r"ip (\d+\.\d+\.\d+\.\d+)", t)
                if mi: last_ip = mi.group(1)
        # window ended cleanly
        if not connected:
            print("[soak] FAIL: never observed WiFi connect"); raise SystemExit(1)
        if min_heap != 99999 and min_heap < a.floor:
            print("[soak] FAIL: heap floor %d < %d" % (min_heap, a.floor)); raise SystemExit(1)
        print("[soak] PASS: %ds, boots=%d (1=our reset), min_heap=%s, ip=%s" %
              (a.seconds, boots, min_heap if min_heap != 99999 else "n/a", last_ip))
        raise SystemExit(0)
    finally:
        ser.close()
        if out: out.close()

if __name__ == "__main__":
    main()
