# Durable WiFi regression gate for the sensmos ESP8266 run.
#   py -3 tools/gate_wifi.py [--subnet 192.168.0.0/20] [--seconds 90] [--ssid <name>] [--out FILE]
# Resets the board, captures up to --seconds, PASS iff a success line reports a station IP that is
#   non-zero AND not in 192.168.4.0/24 (the ESP's own softAP) AND inside --subnet,
#   with NO crash marker and NO reboot after success inside the window.
# The raw wifi_get_ip_info deep-diag line is preferred over Arduino-layer prints when present.
# Exit 0 = PASS, 1 = FAIL. Prints the deciding lines. Assertions are NEVER loosened to pass.
import sys, os, time, re, argparse, ipaddress
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
SOFTAP_NET = ipaddress.ip_network("192.168.4.0/24")

CRASH_MARKERS = ("Exception (", "Fatal exception", "wdt reset", "Soft WDT",
                 "abort()", "user_fatal_exception", "rst cause:2", "Panic")
BOOT_MARKERS = ("SENSMOS SmartNode", "chip esp8266 @")

# success-line extractors: return an IP string or None
def extract_success_ip(line):
    if "[gate] WIFI_OK" in line and "ip=" in line:
        m = IP_RE.search(line.split("ip=", 1)[1])
        return m.group(1) if m else None
    if "[wifi] DHCP lease" in line:
        m = IP_RE.search(line); return m.group(1) if m else None
    if "[wifi] connected, ip" in line:
        m = IP_RE.search(line.split("ip", 1)[1]); return m.group(1) if m else None
    # raw deep-diag line with a GOT_IP indicator (sdk=5) and a non-zero ip= field
    if "sdk=5" in line and "ip=" in line:
        m = IP_RE.search(line.split("ip=", 1)[1]); return m.group(1) if m else None
    return None


def valid_station_ip(ipstr, subnet):
    try:
        ip = ipaddress.ip_address(ipstr)
    except ValueError:
        return False, "unparseable"
    if str(ip) == "0.0.0.0":
        return False, "zero"
    if ip in SOFTAP_NET:
        return False, "in-softAP-range-192.168.4.x"
    if ip not in subnet:
        return False, "outside-subnet-%s" % subnet
    return True, "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subnet", default="192.168.0.0/20")
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--ssid", default=None)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    subnet = ipaddress.ip_network(a.subnet, strict=False)
    print("[gate] subnet=%s ssid=%s window=%ds" % (subnet, a.ssid, a.seconds), flush=True)

    out_fh = open(a.out, "w", encoding="utf-8") if a.out else None
    ser = su.open_with_retry(None, 115200, do_reset=True)
    start = time.time()
    buf = b""
    passed_ip = None
    pass_time = None
    fail_reason = None
    try:
        while time.time() - start < a.seconds:
            if passed_ip and (time.time() - pass_time) > 3.0:
                break   # confirmed GOT_IP + 3s clean tail (no crash/reboot) -> PASS; stop early
            chunk = ser.read(256)
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                ms = int((time.time() - start) * 1000)
                text = raw.decode("utf-8", "replace").rstrip("\r")
                if out_fh:
                    out_fh.write("[%7dms] %s\n" % (ms, text)); out_fh.flush()
                # crash marker -> immediate FAIL
                if any(m in text for m in CRASH_MARKERS):
                    fail_reason = "crash marker: %s" % text
                    print("[gate] FAIL (crash): %s" % text, flush=True)
                    raise SystemExit(1)
                # reboot after a success -> FAIL (instability in window)
                if passed_ip and any(m in text for m in BOOT_MARKERS):
                    fail_reason = "rebooted after success: %s" % text
                    print("[gate] FAIL (reboot after GOT_IP): %s" % text, flush=True)
                    raise SystemExit(1)
                ipstr = extract_success_ip(text)
                if ipstr and not passed_ip:
                    ok, why = valid_station_ip(ipstr, subnet)
                    if ok:
                        passed_ip = ipstr
                        pass_time = time.time()
                        print("[gate] success line: %s" % text, flush=True)
                        print("[gate] station IP %s valid in %s" % (ipstr, subnet), flush=True)
                        # keep watching a short tail (3s) for an immediate crash/reboot
                    else:
                        print("[gate] candidate ip %s rejected (%s): %s" % (ipstr, why, text), flush=True)
        # window ended
        if passed_ip:
            print("[gate] PASS ip=%s" % passed_ip, flush=True)
            raise SystemExit(0)
        print("[gate] FAIL: no valid station IP in %ds window" % a.seconds, flush=True)
        raise SystemExit(1)
    finally:
        ser.close()
        if out_fh:
            out_fh.close()


if __name__ == "__main__":
    main()
