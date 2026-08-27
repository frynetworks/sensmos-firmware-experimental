# pre: extra_script — build-time monitoring wygasniecia kotwicy pinningu (src/ca_cert.h).
#
# Parsuje tablice DER wprost z naglowka (jedno zrodlo prawdy w repo), wyciaga notAfter
# z X.509 Validity (czysty Python, bez zaleznosci: Validity = pierwsza SEKWENCJA dwoch
# czasow UTCTime(0x17)/GeneralizedTime(0x18) w TBS) i liczy dni do wygasniecia.
#   < WARN_DAYS (domyslnie 180) -> wyrazne OSTRZEZENIE z instrukcja rotacji
#   < 30 dni                    -> baner bledu (nadal exit 0 — build ma przejsc,
#                                  cert wciaz WAZNY; nie blokujemy shipowania)
# Prog nadpisywalny env CERT_EXPIRY_WARN_DAYS (test triggera bez edycji skryptu).
# Rotacja: patrz blok ROTACJA w src/ca_cert.h + tools/gen_ca_cert_h.py.

Import("env")
import os
import re
import datetime

WARN_DAYS = int(os.environ.get("CERT_EXPIRY_WARN_DAYS", "180"))


def der_from_header(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    m = re.search(r"CA_ANCHOR_DER\[\]\s*PROGMEM\s*=\s*\{(.*?)\};", content, re.S)
    if not m:
        return None
    return bytes(int(h, 16) for h in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))


def parse_notafter(der):
    # Validity: SEQUENCE { Time, Time } — szukamy pierwszej pary czasow w TBS.
    times = []
    i = 0
    while i < len(der) - 2 and len(times) < 2:
        tag = der[i]
        if tag in (0x17, 0x18):
            ln = der[i + 1]
            raw = der[i + 2:i + 2 + ln].decode("ascii", "replace")
            times.append((tag, raw))
            i += 2 + ln
        else:
            i += 1
    if len(times) < 2:
        return None
    tag, raw = times[1]   # notAfter = drugi czas
    try:
        if tag == 0x17:   # UTCTime YYMMDDHHMMSSZ
            yy = int(raw[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return datetime.datetime(year, int(raw[2:4]), int(raw[4:6]),
                                     int(raw[6:8]), int(raw[8:10]))
        else:             # GeneralizedTime YYYYMMDDHHMMSSZ
            return datetime.datetime(int(raw[0:4]), int(raw[4:6]), int(raw[6:8]),
                                     int(raw[8:10]), int(raw[10:12]))
    except (ValueError, IndexError):
        return None


def check():
    hdr = os.path.join(env.subst("$PROJECT_SRC_DIR"), "ca_cert.h")
    if not os.path.isfile(hdr):
        print("[cert-expiry] SKIPPED — %s not found" % hdr)
        return
    der = der_from_header(hdr)
    if not der:
        print("[cert-expiry] WARNING: CA_ANCHOR_DER array not parseable in ca_cert.h")
        return
    not_after = parse_notafter(der)
    if not not_after:
        print("[cert-expiry] WARNING: could not parse notAfter from DER")
        return
    days = (not_after - datetime.datetime.utcnow()).days
    if days < 30:
        print("=" * 76)
        print("[cert-expiry] !!! BLAD-POZIOM: kotwica pinningu wygasa za %d dni (%s) !!!"
              % (days, not_after.date()))
        print("[cert-expiry] ROTUJ TERAZ: instrukcje w src/ca_cert.h (gen_ca_cert_h.py)")
        print("=" * 76)
    elif days < WARN_DAYS:
        print("-" * 76)
        print("[cert-expiry] OSTRZEZENIE: kotwica pinningu wygasa za %d dni (%s)"
              % (days, not_after.date()))
        print("[cert-expiry] Zaplanuj rotacje: instrukcje w src/ca_cert.h")
        print("-" * 76)
    else:
        print("[cert-expiry] OK — kotwica wazna jeszcze %d dni (do %s)"
              % (days, not_after.date()))


check()
