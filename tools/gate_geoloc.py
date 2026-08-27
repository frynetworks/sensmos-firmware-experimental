# Geolocation acceptance gate for the sensmos ESP8266 run. Foreground, bounded, never loosened.
#   py -3 tools/gate_geoloc.py --mode red     # PASS iff get_location -> no_location_stored
#   py -3 tools/gate_geoloc.py --mode green   # PASS iff [geo] acquired/cached seen AND
#                                             #   get_location returns in-range non-zero coords
#                                             #   with a valid source tag
#   py -3 tools/gate_geoloc.py --mode cached  # PASS iff boot logs "[geo] cached" and NO new
#                                             #   "[geo] location acquired" line (no redundant call)
# Exit 0 = PASS, 1 = FAIL. Prints the deciding lines verbatim.
import sys, os, time, json, re, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

READY = "[serial] ready"
VALID_SOURCES = ("ip_api", "manual", "local_http", "portal", "backend")


def read_for(ser, seconds, log, stop_marks=None):
    start = time.time(); buf = b""; lines = []
    while time.time() - start < seconds:
        chunk = ser.read(256)
        if not chunk:
            continue
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            t = raw.decode("utf-8", "replace").rstrip("\r")
            lines.append(t)
            if log:
                log.write(t + "\n"); log.flush()
            if stop_marks and any(m in t for m in stop_marks):
                return lines, t
    return lines, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["red", "green", "cached"])
    ap.add_argument("--boot-window", type=int, default=75)
    ap.add_argument("--expect-push", action="store_true",
                    help="green/cached also require the '[geo] pushed location to backend' line "
                         "that ws_client on_identified() emits after the WS session is up")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    log = open(a.out, "w", encoding="utf-8") if a.out else None

    ser = su.open_with_retry(None, 115200, do_reset=True, verbose=False)
    try:
        lines, _ = read_for(ser, 25, log, [READY])
        if not any(READY in t for t in lines):
            print("[geoloc-gate] FAIL: no serial-ready banner"); raise SystemExit(1)
        # wait for the boot sequence to finish (loop() drains serial only after setup ends;
        # a command sent during the blocking WiFi connect would sit unanswered in the buffer)
        boot_lines, boot_done = read_for(ser, 60, log, ["[boot] ready", "portal] started"])
        lines += boot_lines
        if not boot_done:
            print("[geoloc-gate] FAIL: boot never completed in 60s"); raise SystemExit(1)

        geo_line = None
        if a.mode in ("green", "cached"):
            # the [geo] outcome line prints DURING the boot sequence (before "[boot] ready"),
            # so first scan what we already captured, and only wait longer if it isn't there
            geo_line = next((t for t in lines
                             if "[geo] location acquired" in t or "[geo] cached" in t), None)
            if not geo_line:
                more, hit = read_for(ser, a.boot_window, log,
                                     ["[geo] location acquired", "[geo] cached"])
                lines += more
                geo_line = hit
            if geo_line:
                print("[geoloc-gate] geo line: %s" % geo_line)

        push_line = None
        if a.expect_push:
            # the push fires from ws_client on_identified(), i.e. after the WS session comes up —
            # later than the [geo] acquired/cached line
            push_line = next((t for t in lines if "[geo] pushed location to backend" in t), None)
            if not push_line:
                more, hit = read_for(ser, a.boot_window, log,
                                     ["[geo] pushed location to backend", "location push failed"])
                lines += more
                push_line = hit
            print("[geoloc-gate] push line: %s" % (push_line or "<none>"))

        ser.write(b'{"cmd":"get_location"}\n'); ser.flush()
        reply_lines, _ = read_for(ser, 8, log, ['"cmd":"get_location"'])
        reply = next((t for t in reply_lines if '"cmd":"get_location"' in t), None)
        print("[geoloc-gate] get_location reply: %s" % (reply or "<none>"))

        if a.mode == "red":
            ok = reply is not None and "no_location_stored" in reply
            print("[geoloc-gate] %s (red: expect no_location_stored)" % ("PASS" if ok else "FAIL"))
            raise SystemExit(0 if ok else 1)

        if reply is None:
            print("[geoloc-gate] FAIL: no get_location reply"); raise SystemExit(1)
        m = re.search(r'\{.*\}', reply)
        try:
            d = json.loads(m.group(0)) if m else {}
        except ValueError:
            d = {}
        lat = float(d.get("lat", "0") or 0)
        lon = float(d.get("lon", "0") or 0)
        src = d.get("source", "")
        coords_ok = (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0
                     and not (lat == 0.0 and lon == 0.0))
        src_ok = src in VALID_SOURCES

        push_ok = (not a.expect_push) or (push_line is not None
                                          and "pushed location to backend" in push_line)

        if a.mode == "green":
            geo_ok = geo_line is not None
            ok = coords_ok and src_ok and geo_ok and push_ok
            print("[geoloc-gate] %s (green: coords_ok=%s src=%s geo_line=%s push_ok=%s)"
                  % ("PASS" if ok else "FAIL", coords_ok, src, bool(geo_line), push_ok))
            raise SystemExit(0 if ok else 1)

        # cached mode: must be the cached line, and NO fresh acquisition in this boot
        acquired = any("[geo] location acquired" in t for t in lines)
        cached = geo_line is not None and "[geo] cached" in (geo_line or "")
        ok = cached and not acquired and coords_ok and src_ok and push_ok
        print("[geoloc-gate] %s (cached: cached_line=%s no_new_acquire=%s coords_ok=%s push_ok=%s)"
              % ("PASS" if ok else "FAIL", cached, not acquired, coords_ok, push_ok))
        raise SystemExit(0 if ok else 1)
    finally:
        ser.close()
        if log:
            log.close()


if __name__ == "__main__":
    main()
