# Serial provisioning + command helper for the sensmos ESP8266 run.
#   py -3 tools/provision.py set-wifi --ssid X --password Y [--wait 75]
#   py -3 tools/provision.py register --owner 0x.. --ts <unix> [--sig-wallet ..] [--wait 20]
#   py -3 tools/provision.py cmd --json '{"cmd":"get_info"}' [--wait 5]
# Resets the board (unless --no-reset), waits for the "[serial] ready" banner, sends ONE JSON
# line, then captures the response for --wait seconds. Bounded; never loops forever.
# NOTE: set_wifi saves creds BEFORE attempting connect, so it re-provisions even if connect fails.
import sys, os, time, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

READY = "[serial] ready"


def wait_for_ready(ser, timeout=25):
    start = time.time(); buf = b""
    while time.time() - start < timeout:
        chunk = ser.read(256)
        if chunk:
            buf += chunk
            txt = buf.decode("utf-8", "replace")
            for ln in txt.splitlines():
                print("  " + ln.rstrip(), flush=True)
            if READY in txt:
                return True
            buf = buf[-256:]
    return False


def send_and_capture(ser, obj, wait):
    line = json.dumps(obj, separators=(",", ":"))
    # never print secrets verbatim in a password provisioning line
    safe = dict(obj)
    if "password" in safe:
        safe["password"] = "<%d chars>" % len(safe["password"])
    print("[prov] send: %s" % json.dumps(safe, separators=(",", ":")), flush=True)
    ser.write((line + "\n").encode("utf-8")); ser.flush()
    start = time.time(); buf = b""; out = []
    while time.time() - start < wait:
        chunk = ser.read(256)
        if chunk:
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                t = raw.decode("utf-8", "replace").rstrip("\r")
                print("  " + t, flush=True); out.append(t)
    return out


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    sw = sub.add_parser("set-wifi"); sw.add_argument("--ssid", required=True); sw.add_argument("--password", default=""); sw.add_argument("--wait", type=int, default=75)
    rg = sub.add_parser("register"); rg.add_argument("--owner", required=True); rg.add_argument("--ts", type=int, required=True); rg.add_argument("--sig-wallet", default=""); rg.add_argument("--wait", type=int, default=20)
    cm = sub.add_parser("cmd"); cm.add_argument("--json", required=True); cm.add_argument("--wait", type=int, default=5)
    for p in (sw, rg, cm):
        p.add_argument("--no-reset", action="store_true")
    a = ap.parse_args()

    do_reset = not getattr(a, "no_reset", False)
    ser = su.open_with_retry(None, 115200, do_reset=do_reset)
    try:
        if do_reset:
            if not wait_for_ready(ser):
                print("[prov] WARNING: no [serial] ready banner seen; sending anyway", flush=True)
        if a.mode == "set-wifi":
            out = send_and_capture(ser, {"cmd": "set_wifi", "ssid": a.ssid, "password": a.password}, a.wait)
        elif a.mode == "register":
            obj = {"cmd": "register", "owner": a.owner, "timestamp": a.ts}
            if a.sig_wallet:
                obj["sig_wallet"] = a.sig_wallet
            out = send_and_capture(ser, obj, a.wait)
        else:
            obj = json.loads(a.json)
            out = send_and_capture(ser, obj, a.wait)
        ok = any('"status":"ok"' in l for l in out)
        print("[prov] result: %s" % ("OK" if ok else "see-output-above"), flush=True)
    finally:
        ser.close()


if __name__ == "__main__":
    main()
