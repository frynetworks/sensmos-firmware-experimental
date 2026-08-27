# Flaky-rate harness: loops the set_wifi serial command in ONE session (no reboots -> no force_ble
# poisoning, no LittleFS-remount noise). Each set_wifi drives one wifi_connect() attempt.
# Reports success rate (real DHCP lease / GOT_IP) over N attempts, plus the ac= (auto_connect) reading.
#   py -3 tools/rate.py --n 5 --ssid GQThePromisedNeverLAN --password '...' [--per 95] [--out FILE]
import sys, os, time, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su


def send_setwifi(ser, ssid, pw):
    obj = {"cmd": "set_wifi", "ssid": ssid, "password": pw}
    ser.write((json.dumps(obj, separators=(",", ":")) + "\n").encode()); ser.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--password", default="")
    ap.add_argument("--per", type=int, default=95)   # max seconds to wait for one attempt to resolve
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    out_fh = open(a.out, "w", encoding="utf-8") if a.out else None
    ser = su.open_with_retry(None, 115200, do_reset=False)   # attach to already-booted board
    time.sleep(0.5)
    ser.reset_input_buffer()
    results = []
    try:
        for i in range(1, a.n + 1):
            print("[rate] attempt %d/%d: sending set_wifi" % (i, a.n), flush=True)
            send_setwifi(ser, a.ssid, a.password)
            start = time.time()
            buf = b""
            verdict = None
            last_ac = None
            while time.time() - start < a.per:
                chunk = ser.read(256)
                if not chunk:
                    continue
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    t = raw.decode("utf-8", "replace").rstrip("\r")
                    if out_fh:
                        out_fh.write(t + "\n"); out_fh.flush()
                    if "ac=" in t:
                        try: last_ac = t.split("ac=", 1)[1].split()[0]
                        except Exception: pass
                    # success signals
                    if ('"cmd":"set_wifi","ip":"' in t and '"ip":"0.0.0.0"' not in t) \
                       or ("[wifi] connected, ip " in t) or ("sdk=5" in t):
                        verdict = ("OK", t.strip()); break
                    # failure signal
                    if '"msg":"wifi_failed"' in t:
                        verdict = ("FAIL", t.strip()); break
                if verdict:
                    break
            if not verdict:
                verdict = ("TIMEOUT", "no resolution in %ds" % a.per)
            results.append((i, verdict[0], last_ac, verdict[1]))
            print("[rate] attempt %d -> %s (ac=%s)" % (i, verdict[0], last_ac), flush=True)
            time.sleep(2)
    finally:
        ser.close()
        if out_fh:
            out_fh.close()
    ok = sum(1 for r in results if r[1] == "OK")
    print("[rate] SUCCESS_RATE=%d/%d  ac_last=%s" % (ok, a.n, results[-1][2] if results else "?"), flush=True)
    for r in results:
        print("   attempt %d: %s ac=%s :: %s" % r, flush=True)


if __name__ == "__main__":
    main()
