#!/usr/bin/env python3
"""Generator src/ca_cert.h z certyfikatu DER (rotacja kotwicy pinningu TLS).

Uzycie:
    py -3 tools/gen_ca_cert_h.py <cert.der> <out.h> "<opis, np. subject + expiry>"

Przed uzyciem zweryfikuj cert:
    openssl x509 -inform DER -in cert.der -noout -subject -dates
i sprawdz, ze NOWY lancuch serwera (openssl s_client -showcerts) domyka sie do tej
kotwicy przy mozliwie MALEJ liczbie weryfikacji P-384 — kazda to ~2.7s ciaglego
liczenia na 160MHz, a HW WDT (~8.4s, niewylaczalny) ogranicza pelny handshake
do ~dwoch takich weryfikacji. Patrz README sekcja TLS (historia wyboru Root YE).
"""
import sys


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    der_path, out_path, desc = sys.argv[1], sys.argv[2], sys.argv[3]
    der = open(der_path, "rb").read()
    rows = []
    for i in range(0, len(der), 12):
        rows.append("    " + ", ".join("0x%02X" % b for b in der[i:i + 12]) + ",")
    rows[-1] = rows[-1].rstrip(",")
    body = "\n".join(rows)

    out = """#pragma once
// Kotwica zaufania (pinning) dla api.sensmos.com — %s
// DER, %d bajtow, PROGMEM (flash, nie DRAM).
// Wygenerowane przez tools/gen_ca_cert_h.py — przy rotacji NIE edytuj tablicy recznie.
//
// ============ ROTACJA ============
// 1. Pobierz nowy cert (DER) z https://letsencrypt.org/certificates/ lub wyciagnij
//    z lancucha: openssl s_client -connect api.sensmos.com:443 -showcerts
// 2. Zweryfikuj: openssl x509 -inform DER -in nowy.der -noout -subject -dates
// 3. py -3 tools/gen_ca_cert_h.py nowy.der src/ca_cert.h "<subject, wygasa YYYY-MM-DD>"
// 4. Przebuduj i sflashuj; zweryfikuj na urzadzeniu: "cert pinning active" +
//    "connected: version=..." BEZ linii "verify disabled (degraded)".
// tools/check_cert_expiry.py (pre-build) ostrzega <180 dni przed wygasnieciem.
// =================================
//
// UWAGA: ten naglowek wlacza TYLKO ws_tls.cpp. NIE dolaczac do ws_tls.h — tamten
// naglowek jest wstrzykiwany do TU biblioteki WebSockets i tablica by sie zduplikowala.
#ifdef SENSMOS_USE_TLS
#include <pgmspace.h>

static const uint8_t CA_ANCHOR_DER[] PROGMEM = {
%s
};
static const unsigned int CA_ANCHOR_DER_LEN = sizeof(CA_ANCHOR_DER);

#endif // SENSMOS_USE_TLS
""" % (desc, len(der), body)

    with open(out_path, "w", newline="\n") as f:
        f.write(out)
    print("wrote %s (%d-byte DER)" % (out_path, len(der)))


if __name__ == "__main__":
    main()
