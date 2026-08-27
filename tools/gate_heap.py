# Heap gate: reset the board, capture N seconds, assert the node reaches steady state ("ready — heap"),
# stays above the OOM-crash floor, and produces no crash marker. (Note: the sensmos ESP8266 node
# legitimately runs at ~10k steady-state; the heap fix reduces the TLS *peak* 32k->9k so BearSSL fits,
# it does not raise steady-state. The meaningful differential is that TLS/registration no longer OOMs —
# see gate_soak.py and the register 200 proof.)
#   py -3 tools/gate_heap.py [--seconds 90] [--floor 3000] [--out FILE]
# Exit 0 = PASS, 1 = FAIL. Never loosen the assertions to pass.
#
# FLOOR CALIBRATION (2026-08-11, post mDNS-retire fix): the gate's job is to catch OOM-level
# regressions, not to alert on normal operational dips. Measured over 3x180s captures on the
# shipping build: steady-state 10-11k, lowest gate-visible dip 3072 ("heap 3k->6k" during a 6-job
# checknet/ICMP worker pass that DEFERs safely — by design, non-crashing). Default floor =
# max(min_observed - 1000, 3000) = max(2072, 3000) = 3000 — the clamp binds; 3000 is the ESP8266
# near-OOM level where small allocations start failing (same principled floor as gate_soak.py).
# The previous default (6000) was arbitrary and false-failed healthy ~5k dips. RE-MEASURE and
# recompute after any change to heap consumers (new module, buffer sizing, script limits).
import sys, os, time, re, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

CRASH = ("Exception (", "Fatal exception", "wdt reset", "Soft WDT", "abort()", "rst cause:2", "rst cause:3", "Panic")
READY_RE = re.compile(r"ready . heap (\d+)k free, blk (\d+)k")
HEAP_RE = re.compile(r"heap (\d+)k")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--floor", type=int, default=3000)   # see FLOOR CALIBRATION header
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = open(a.out, "w", encoding="utf-8") if a.out else None
    ser = su.open_with_retry(None, 115200, do_reset=True)
    start = time.time(); buf = b""
    ready_heap = None; min_heap = 99999; crash = None
    try:
        while time.time() - start < a.seconds:
            chunk = ser.read(256)
            if not chunk: continue
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                t = raw.decode("utf-8", "replace").rstrip("\r")
                if out: out.write(t + "\n"); out.flush()
                if any(c in t for c in CRASH):
                    print("[heap] FAIL crash: %s" % t); raise SystemExit(1)
                rm = READY_RE.search(t)
                if rm: ready_heap = int(rm.group(1)) * 1024
                m = HEAP_RE.search(t)
                if m:
                    h = int(m.group(1)) * 1024
                    if h < min_heap: min_heap = h
        if ready_heap is None:
            print("[heap] FAIL: node never reached steady state ('ready — heap')"); raise SystemExit(1)
        if min_heap != 99999 and min_heap < a.floor:
            print("[heap] FAIL: min heap %d < floor %d" % (min_heap, a.floor)); raise SystemExit(1)
        print("[heap] PASS: ready_heap=%d, min_heap=%d, floor=%d, no crash in %ds" %
              (ready_heap, min_heap if min_heap != 99999 else ready_heap, a.floor, a.seconds))
        raise SystemExit(0)
    finally:
        ser.close()
        if out: out.close()

if __name__ == "__main__":
    main()
