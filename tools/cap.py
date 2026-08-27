# Bounded serial capture for the sensmos ESP8266 WiFi debug run.
#   py -3 tools/cap.py --seconds N --out FILE [--reset] [--baud 115200]
#   py -3 tools/cap.py --proof-noreset          # 10s, assert opening does NOT reset the board
# Opens with DTR/RTS de-asserted so opening the port does not reset the board.
# --reset explicitly pulses a run-mode reset. Timestamps every line (ms since start),
# tees stdout + file, exits on its own after N seconds. NEVER an infinite loop.
import sys, os, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

BOOT_MARKERS = ("SENSMOS SmartNode", "[boot]", "[id] sign self-test", "chip esp8266", "ets Jan")


def read_loop(ser, seconds, out_fh):
    start = time.time()
    buf = b""
    lines = []
    while time.time() - start < seconds:
        try:
            chunk = ser.read(256)
        except Exception as e:
            sys.stderr.write("[cap] read error: %s\n" % e)
            break
        if chunk:
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                ms = int((time.time() - start) * 1000)
                text = raw.decode("utf-8", "replace").rstrip("\r")
                line = "[%7dms] %s" % (ms, text)
                print(line, flush=True)
                if out_fh:
                    out_fh.write(line + "\n"); out_fh.flush()
                lines.append(text)
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--out", default=None)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--proof-noreset", action="store_true")
    a = ap.parse_args()

    if a.proof_noreset:
        # Open WITHOUT reset; if a boot banner shows, the no-reset open is broken.
        ser = su.open_with_retry(None, a.baud, do_reset=False)
        print("[cap] proof-noreset: opened without reset, watching 10s for a boot banner...", flush=True)
        lines = read_loop(ser, 10, None)
        ser.close()
        banner = [l for l in lines if any(m in l for m in BOOT_MARKERS)]
        if banner:
            print("[cap] PROOF FAIL: boot banner appeared on open (open resets board):", flush=True)
            for l in banner[:3]:
                print("   " + l, flush=True)
            sys.exit(2)
        print("[cap] PROOF PASS: no boot banner in 10s (open does not reset). lines=%d" % len(lines), flush=True)
        sys.exit(0)

    out_fh = open(a.out, "w", encoding="utf-8") if a.out else None
    ser = su.open_with_retry(None, a.baud, do_reset=a.reset)
    if a.reset:
        print("[cap] reset pulsed; capturing %ds" % a.seconds, flush=True)
    else:
        print("[cap] capturing %ds (no reset)" % a.seconds, flush=True)
    try:
        read_loop(ser, a.seconds, out_fh)
    finally:
        ser.close()
        if out_fh:
            out_fh.close()
    print("[cap] done (%ds)" % a.seconds, flush=True)


if __name__ == "__main__":
    main()
