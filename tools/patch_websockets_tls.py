# pre: extra_script — od flipu TLS-do-shippingu uruchamiany dla KAZDEGO env (nodemcuv2,
# nodemcuv2_diag, alias nodemcuv2_tls); patchuje kopie WebSockets w libdeps WLASNEGO env
# ($PIOENV). Dwie NIEZALEZNE, idempotentne latki (osobne markery — wspolny marker
# short-circuitowalby druga latke na zawsze):
#
# A) Klasa SSL: arduinoWebSockets 2.7.3 twardo definiuje
#    WEBSOCKETS_NETWORK_SSL_CLASS=WiFiClientSecure (galaz NETWORK_ESP8266, bez #ifndef —
#    -D z build_flags jest po cichu nadpisywane) i sam `new`-uje te klase
#    (WebSocketsClient.cpp:262-263). Podmieniamy na warunkowa definicje wstrzykujaca
#    wolfSSL-owy WsTlsClient (esp8266/src/ws_tls.h) SCIEZKA BEZWZGLEDNA (kopia libdeps
#    jest lokalna, nigdy nie commitowana; -Isrc odpada — src/ ma shimy WiFi.h itd.).
#
# B) WEBSOCKETS_MAX_DATA_SIZE: ta sama klasa buga — naglowek definiuje (15 * 1024) bez
#    #ifndef (WebSockets.h:66), wiec -DWEBSOCKETS_MAX_DATA_SIZE=4096 z platformio.ini
#    NIGDY nie dzialal (gcc: "warning: redefined", naglowek wygrywa). Cap jest
#    reject-before-malloc (WebSockets.cpp:438 + malloc per-ramka :455) — twardnienie,
#    zero oszczednosci heapu. Owijamy w #ifndef, zeby flaga builda wygrywala.
#
# Reversal: usunac wpis z extra_scripts + skasowac .pio/libdeps/<env>/WebSockets
# (pio odtworzy czysta kopie).

Import("env")
import os

# ── Latka A: klasa SSL -> WsTlsClient pod SENSMOS_USE_TLS ──
MARKER_A = "WsTlsClient"
ANCHOR_A = (
    "#include <ESP31BWiFi.h>\n"
    "#endif\n"
    "#define WEBSOCKETS_NETWORK_CLASS WiFiClient\n"
    "#define WEBSOCKETS_NETWORK_SSL_CLASS WiFiClientSecure\n"
)

# ── Latka B: #ifndef wokol MAX_DATA_SIZE (galaz ESP8266/ESP32, linia ~66) ──
MARKER_B = "#ifndef WEBSOCKETS_MAX_DATA_SIZE"
ANCHOR_B = "#define WEBSOCKETS_MAX_DATA_SIZE (15 * 1024)\n"
REPLACE_B = (
    "#ifndef WEBSOCKETS_MAX_DATA_SIZE\n"
    "#define WEBSOCKETS_MAX_DATA_SIZE (15 * 1024)\n"
    "#endif\n"
)


def patch():
    lib_dir = env.subst("$PROJECT_LIBDEPS_DIR")
    pioenv = env.subst("$PIOENV")
    ws_h = os.path.join(lib_dir, pioenv, "WebSockets", "src", "WebSockets.h")
    if not os.path.isfile(ws_h):
        print("[websockets-patch] SKIPPED (libdeps not installed yet): %s" % ws_h)
        return
    with open(ws_h, "r") as f:
        content = f.read()
    changed = False

    # A: SSL class swap
    if MARKER_A in content:
        print("[websockets-patch] A(ssl-class) already patched")
    elif ANCHOR_A not in content:
        print("[websockets-patch] ERROR: A anchor not found — ssl-class NOT patched")
    else:
        ws_tls_h = os.path.join(env.subst("$PROJECT_SRC_DIR"), "ws_tls.h").replace("\\", "/")
        replacement = (
            "#include <ESP31BWiFi.h>\n"
            "#endif\n"
            "#define WEBSOCKETS_NETWORK_CLASS WiFiClient\n"
            "#if defined(SENSMOS_USE_TLS)\n"
            "#include \"%s\"\n"
            "#define WEBSOCKETS_NETWORK_SSL_CLASS WsTlsClient\n"
            "#else\n"
            "#define WEBSOCKETS_NETWORK_SSL_CLASS WiFiClientSecure\n"
            "#endif\n"
        ) % ws_tls_h
        content = content.replace(ANCHOR_A, replacement, 1)
        changed = True
        print("[websockets-patch] A(ssl-class) patched (-> WsTlsClient under SENSMOS_USE_TLS)")

    # B: MAX_DATA_SIZE #ifndef guard (first occurrence = the ESP8266/ESP32 branch)
    if MARKER_B in content:
        print("[websockets-patch] B(max-data-size) already patched")
    elif ANCHOR_B not in content:
        print("[websockets-patch] ERROR: B anchor not found — max-data-size NOT patched")
    else:
        content = content.replace(ANCHOR_B, REPLACE_B, 1)
        changed = True
        print("[websockets-patch] B(max-data-size) patched (#ifndef guard — -D flag now wins)")

    if changed:
        with open(ws_h, "w") as f:
            f.write(content)


patch()
