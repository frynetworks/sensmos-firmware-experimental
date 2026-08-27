#ifdef SENSMOS_USE_TLS
#include "ws_tls.h"
#include "log.h"
#include <Arduino.h>
#include <ESP8266WiFi.h>
#ifdef MMU_IRAM_HEAP
#include <umm_malloc/umm_heap_select.h>   // HeapSelectIram — patrz log.cpp/tunnel.cpp
#endif
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include "ca_cert.h"   // kotwica pinningu (PROGMEM) — tylko ten TU, patrz komentarz w ca_cert.h

// Trwały transport wss:// dla arduinoWebSockets (WsTlsClient) + jednorazowy PoC pomiarowy.
// CTX wolfSSL jest współdzielony i inicjalizowany RAZ (nigdy nie zwalniany) — biblioteka
// kasuje i tworzy instancję klienta przy każdym reconnect'cie (WebSocketsClient.cpp:252-263),
// sesje TLS są per-instancja.

static const unsigned long HS_DEADLINE_MS = 30000;   // twardy limit handshake'u (WANT_READ retry)

static WOLFSSL_CTX* g_ctx = nullptr;

// Zapisana sesja TLS (bilet NST) — przezywa cykl zycia WsTlsClient (biblioteka kasuje
// i tworzy klienta przy kazdym reconnec'cie). RAM-only, single-boot (materia biletu
// wiazana z zegarem ms). Save: w stop() PRZED wolfSSL_free — bilety NST przychodza
// PO handshake'u, a wczesniejszy get1_session podbija refcount i SetTicket forkuje
// sesje (HaveUniqueSessionObj) — zapisany uchwyt zostalby bez biletu NA ZAWSZE.
static WOLFSSL_SESSION* g_session = nullptr;

#ifdef SENSMOS_TEST_FORCE_RECONNECT
// Hak testowy (flaga NIGDY nie definiowana w envach; wlaczana per-test przez
// PLATFORMIO_BUILD_FLAGS): raz, ~90s po pierwszym handshake'u, transport sam sie
// rozlacza — biblioteka reconnectuje po 5s i drugi handshake cwiczy resumption.
// Jedyny deterministyczny trigger bez WiFi-credow i bez rebootu (reboot traci sesje).
static bool s_test_forced = false;
static unsigned long s_test_hs_at = 0;
#endif

static void ws_tls_ticket_seen_cb_reg(WOLFSSL* ssl);   // fwd

// [tls-heap] line is DELIBERATELY not in the "heap <N>k" shape — see log.cpp's [mem] comment:
// tools/gate_heap.py's HEAP_RE would otherwise vacuum these readings into its min_heap gate.
// Od flipu 2026-08-24 ten transport JEST w shippingowym buildzie (SENSMOS_USE_TLS domyslne);
// dyscyplina nazewnicza heap= obowiazuje tym bardziej.
static void ws_tls_print_heap(const char* label) {
    uint32_t dram_free = ESP.getFreeHeap();
    uint32_t dram_blk  = ESP.getMaxFreeBlockSize();
    uint32_t frag       = ESP.getHeapFragmentation();
#ifdef MMU_IRAM_HEAP
    uint32_t iram_free = 0, iram_blk = 0;
    {
        HeapSelectIram ephemeral;
        iram_free = ESP.getFreeHeap();
        iram_blk  = ESP.getMaxFreeBlockSize();
    }
    LOGI("tls-heap", "%s dram_free=%u dram_blk=%u frag=%u%% iram_free=%u iram_blk=%u",
         label, (unsigned)dram_free, (unsigned)dram_blk, (unsigned)frag,
         (unsigned)iram_free, (unsigned)iram_blk);
#else
    LOGI("tls-heap", "%s dram_free=%u dram_blk=%u frag=%u%%",
         label, (unsigned)dram_free, (unsigned)dram_blk, (unsigned)frag);
#endif
}

// Custom wolfSSL I/O — ESP8266 Arduino's WiFiClient has no POSIX fd, so wolfSSL_set_fd()
// is not usable; wire wolfSSL's transport callbacks straight to the INHERITED WiFiClient.
// io_recv zwraca WANT_READ NATYCHMIAST gdy brak danych (bez 5s spinu jak w PoC) — czekanie
// dostarcza pętla retry w connect(); w steady-state loop() nie może być blokowany.
int ws_tls_io_send_cb(struct WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    (void)ssl;
    WsTlsClient* self = (WsTlsClient*)ctx;
    size_t sent = self->WiFiClient::write((const uint8_t*)buf, (size_t)sz);
    if (sent == 0) return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return (int)sent;
}

int ws_tls_io_recv_cb(struct WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    (void)ssl;
    WsTlsClient* self = (WsTlsClient*)ctx;
    if (self->WiFiClient::available() <= 0) {
        if (!self->WiFiClient::connected()) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    int rd = self->WiFiClient::read((uint8_t*)buf, (size_t)sz);
    return rd > 0 ? rd : WOLFSSL_CBIO_ERR_WANT_READ;
}

static bool ws_tls_ctx_ensure() {
    if (g_ctx) return true;
    ws_tls_print_heap("baseline");
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        LOGE("tls", "wolfSSL_Init failed");
        return false;
    }
    ws_tls_print_heap("post-wolfssl-init");
    // v23 = TLS1.3-preferowany Z downgrade=1 (wolfTLSv1_3_client_method ma downgrade=0
    // i odrzuca ServerHello 1.2 jako err -326). NO_OLD_TLS przybija WOLFSSL_MIN_DOWNGRADE
    // do TLS1.2 — nizej nie zejdzie, bez zadnego SetMinVersion.
    g_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (!g_ctx) {
        LOGW("tls", "TLS1.3 CTX unavailable, falling back to TLS1.2");
        g_ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    }
    if (!g_ctx) {
        LOGE("tls", "CTX_new failed (1.3 and 1.2 both unavailable)");
        wolfSSL_Cleanup();
        return false;
    }
    // Pinning: ISRG Root YE jako kotwica (ca_cert.h — dlaczego nie X2/X1: czas P-384 vs HW WDT).
    // PROGMEM -> tymczasowy bufor heap (CA_ANCHOR_DER_LEN, 682B): XMEMCPY wolfSSL-a nie jest pgm-aware.
    // Degradacja: gdy load padnie (malloc/format), VERIFY_NONE + log — node ma dzialac,
    // nie cegla; degradacje widac w serialu i mozna ja zlapac w QA.
    {
        bool pinned = false;
        uint8_t* ca = (uint8_t*)malloc(CA_ANCHOR_DER_LEN);
        if (ca) {
            memcpy_P(ca, CA_ANCHOR_DER, CA_ANCHOR_DER_LEN);
            // DATE_ERR_OKAY: load leci przy boocie, czesto PRZED zsynchronizowaniem NTP
            // (zegar 1970 -> notBefore kotwicy "w przyszlosci" -> ASN_BEFORE_DATE_E -150 i
            // degradacja do VERIFY_NONE). Daty certow PEER-a i tak sa sprawdzane przy
            // kazdym handshake'u — race NTP konczy sie retry'em reconnectu, nie dziura.
            int ret = wolfSSL_CTX_load_verify_buffer_ex(g_ctx, ca, CA_ANCHOR_DER_LEN,
                                                        WOLFSSL_FILETYPE_ASN1, 0,
                                                        WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY);
            free(ca);
            if (ret == WOLFSSL_SUCCESS) {
                pinned = true;
            } else {
                LOGW("tls", "CA load failed ret=%d — verify disabled (degraded)", ret);
            }
        } else {
            LOGW("tls", "CA buffer alloc failed (dram_free=%u) — verify disabled (degraded)",
                 (unsigned)ESP.getFreeHeap());
        }
        wolfSSL_CTX_set_verify(g_ctx, pinned ? WOLFSSL_VERIFY_PEER : WOLFSSL_VERIFY_NONE,
                               nullptr);
        if (pinned) LOGI("tls", "cert pinning active: ISRG Root YE, VERIFY_PEER");
    }
    // HAVE_ECC384 (potrzebny TYLKO do weryfikacji lancucha P-384) reklamowalby tez
    // secp384r1 w key_share — serwer moglby go wybrac, a keygen P-384 idzie na
    // generycznym sp_int = powrot OOM err -125. Wymiana kluczy przybita do P-256.
    {
        int groups[] = { WOLFSSL_ECC_SECP256R1 };
        wolfSSL_CTX_set_groups(g_ctx, groups, 1);
    }
    wolfSSL_CTX_SetIOSend(g_ctx, ws_tls_io_send_cb);
    wolfSSL_CTX_SetIORecv(g_ctx, ws_tls_io_recv_cb);
    // Wewnetrzny cache sesji wylaczony w runtime (AddSession no-op, wiersz cache'a
    // nigdy nie alokowany) — sesje trzymamy sami w g_session przez refcount.
    wolfSSL_CTX_set_session_cache_mode(g_ctx, WOLFSSL_SESS_CACHE_OFF);
    ws_tls_print_heap("post-ctx-new");
    return true;
}

// Notyfikacja przyjscia biletu NST (TYLKO log — snapshot sesji robi stop();
// wolfSSL_set_SessionTicket nie przenosi sekretu resumption, patrz ssl.c:3845).
static int ws_tls_ticket_cb(WOLFSSL* ssl, const unsigned char* ticket, int ticketSz,
                            void* cb_ctx) {
    (void)ssl; (void)ticket; (void)cb_ctx;
    LOGI("tls", "session ticket received (len=%d)", ticketSz);
    return 0;
}
static void ws_tls_ticket_seen_cb_reg(WOLFSSL* ssl) {
    wolfSSL_set_SessionTicket_cb(ssl, ws_tls_ticket_cb, nullptr);
}

WsTlsClient::~WsTlsClient() {
    WsTlsClient::stop();
}

int WsTlsClient::connect(const char* host, uint16_t port) {
    // DNS tutaj — bazowe WiFiClient::connect(host,...) woła WIRTUALNE connect(IPAddress,...)
    // i wpadłoby z powrotem w nasz override (nieskończona rekursja).
    IPAddress ip;
    if (!WiFi.hostByName(host, ip)) {
        LOGE("tls", "DNS resolve failed for %s", host);
        return 0;
    }
    return tlsConnect(ip, port, host);
}

int WsTlsClient::connect(IPAddress ip, uint16_t port) {
    return tlsConnect(ip, port, nullptr);   // bez SNI — lib łączy po hoście, ta ścieżka to komplet interfejsu
}

int WsTlsClient::tlsConnect(IPAddress ip, uint16_t port, const char* sniHost) {
    if (!ws_tls_ctx_ensure()) return 0;
    ws_tls_print_heap("pre-connect");

    if (!WiFiClient::connect(ip, port)) {   // kwalifikowane = nie-wirtualne, prosto w bazę
        LOGE("tls", "TCP connect to %s:%u failed",
             sniHost ? sniHost : ip.toString().c_str(), (unsigned)port);
        return 0;
    }
    ws_tls_print_heap("post-tcp-connect");

#ifdef MMU_IRAM_HEAP
    // Route the ~2.9 KB _ssl (WOLFSSL obj + I/O buffers) to the idle IRAM second heap so the DRAM
    // max-free-block stays large for the P-384 chain verify inside wolfSSL_connect (which runs
    // OUTSIDE this scope → its verify temporaries stay on DRAM → fast, no HW-WDT risk from slow
    // IRAM crypto). Fixes handshake err=-155 (ASN_SIG_CONFIRM_E) that hit when the DRAM block dipped
    // ~10.7k, just under the ~11k the SP_384 verify needs. free() is address-routed, so later DRAM
    // wolfSSL_read/write frees stay correct; low-traffic wss makes the IRAM I/O-buffer cost trivial.
    { HeapSelectIram ephemeral; _ssl = wolfSSL_new(g_ctx); }
#else
    _ssl = wolfSSL_new(g_ctx);
#endif
    if (!_ssl) {
        LOGE("tls", "SSL_new failed");
        WiFiClient::stop();
        return 0;
    }
    wolfSSL_SetIOReadCtx(_ssl, this);
    wolfSSL_SetIOWriteCtx(_ssl, this);
    if (sniHost)
        wolfSSL_UseSNI(_ssl, WOLFSSL_SNI_HOST_NAME, sniHost, (word16)strlen(sniHost));
    ws_tls_ticket_seen_cb_reg(_ssl);
    // Wznowienie: bilet z poprzedniej sesji -> PSK 1-RTT (omija ~5.4s weryfikacji
    // lancucha P-384). Wygasly bilet -> WOLFSSL_FAILURE PRZED ustawieniem resuming
    // = czysty pelny handshake; zwalniamy uchwyt (inaczej refcount 2 = fork-tax
    // przy nastepnym SetTicket) i zlapiemy swiezy przy stop().
    if (g_session) {
        if (wolfSSL_set_session(_ssl, g_session) != WOLFSSL_SUCCESS) {
            LOGI("tls", "saved session rejected/expired — full handshake");
            wolfSSL_SESSION_free(g_session);
            g_session = nullptr;
        }
    }
    ws_tls_print_heap("post-ssl-new");

    // Handshake z ograniczonym retry na WANT_READ/WANT_WRITE — naprawia jednostrzałowy
    // wolfSSL_connect z PoC (io_recv po 5s idle ubijał handshake na stałe). delay(5)+yield()
    // karmią SW+HW WDT (patrz main.cpp: ESP.wdtEnable(8000)); jedyny koszt to kosmetyczny
    // "[loop] slow pass" przy reconnect'cie.
    LOGI("tls", "handshake starting: %s:%u", sniHost ? sniHost : "(ip)", (unsigned)port);
    // SW WDT na 8266 ma STALE ~3.2s (parametr wdtEnable jest ignorowany przez core),
    // a lancuch P-384 to >3s nieprzerwanego liczenia w JEDNYM wolfSSL_connect
    // (ProcessPeerCerts robi wszystkie weryfikacje ciurkiem — nic nie woła yield).
    // SW WDT wyłączony NA CZAS handshake'u; HW WDT (~8.4s, niewyłączalny) zostaje
    // jako backstop — pełne SP liczy chain w ~3-5s, mieści się.
    ESP.wdtDisable();
    unsigned long hs_start = millis();
    unsigned long deadline = hs_start + HS_DEADLINE_MS;
    int ret;
    for (;;) {
        ret = wolfSSL_connect(_ssl);
        if (ret == WOLFSSL_SUCCESS) break;
        int err = wolfSSL_get_error(_ssl, ret);
        if ((err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) &&
            (long)(deadline - millis()) > 0) {
            delay(5);
            yield();
            continue;
        }
        ESP.wdtEnable(8000);
        char errBuf[WOLFSSL_MAX_ERROR_SZ];
        wolfSSL_ERR_error_string(err, errBuf);
        LOGE("tls", "handshake failed: err=%d (%s)", err, errBuf);
        ws_tls_print_heap("post-handshake-fail");
        wolfSSL_free(_ssl); _ssl = nullptr;
        WiFiClient::stop();
        return 0;
    }
    ESP.wdtEnable(8000);

    _hsDone = true;
#ifdef SENSMOS_TEST_FORCE_RECONNECT
    s_test_hs_at = millis();
#endif
    ws_tls_print_heap("post-handshake-ok");
    LOGI("tls", "connected: version=%s cipher=%s hs_ms=%lu resumed=%d",
         wolfSSL_get_version(_ssl), wolfSSL_get_cipher(_ssl),
         (unsigned long)(millis() - hs_start), wolfSSL_session_reused(_ssl));
    return 1;
}

size_t WsTlsClient::write(uint8_t b) {
    return write(&b, 1);
}

size_t WsTlsClient::write(const uint8_t* buf, size_t size) {
    if (!_ssl || size == 0) return 0;
    int w = wolfSSL_write(_ssl, buf, (int)size);
    if (w > 0) return (size_t)w;
    // WANT_WRITE (bufor TX pełny) => 0 — pętla zapisu biblioteki retry'uje z timeoutem 5s
    // (WebSockets.cpp:690-710). Błąd fatalny też daje 0; connected() zaraz zgłosi zgon.
    return 0;
}

int WsTlsClient::available() {
    if (!_ssl) return 0;
#ifdef SENSMOS_TEST_FORCE_RECONNECT
    // Raz na boot: wymuszony reconnect ~90s po handshake'u (test resumption).
    if (!s_test_forced && _hsDone && s_test_hs_at &&
        (long)(millis() - s_test_hs_at) > 90000) {
        s_test_forced = true;
        LOGI("tls", "TEST: forcing disconnect to exercise session resumption");
        stop();
        return 0;
    }
#endif
    int p = wolfSSL_pending(_ssl);
    if (p > 0) return p;
    if (WiFiClient::available() > 0) {
        // Pompka: przetwórz zalegle rekordy TLS (nieblokująco — io_recv zwraca WANT_READ
        // natychmiast przy niekompletnym rekordzie; stan parsera trzyma obiekt _ssl).
        uint8_t b;
        if (wolfSSL_peek(_ssl, &b, 1) > 0) return wolfSSL_pending(_ssl);
    }
    return 0;
}

int WsTlsClient::read() {
    uint8_t b;
    return read(&b, 1) == 1 ? (int)b : -1;
}

int WsTlsClient::read(uint8_t* buf, size_t size) {
    if (!_ssl || size == 0) return 0;
    int r = wolfSSL_read(_ssl, buf, (int)size);
    return r > 0 ? r : 0;
}

int WsTlsClient::peek() {
    if (!_ssl) return -1;
    uint8_t b;
    return wolfSSL_peek(_ssl, &b, 1) > 0 ? (int)b : -1;
}

void WsTlsClient::flush() {
    // wolfSSL_write pisze rekordy na wylot — na poziomie TLS nie ma nic do spłukania.
    WiFiClient::flush();
}

uint8_t WsTlsClient::connected() {
    if (_ssl && wolfSSL_pending(_ssl) > 0) return 1;   // zbuforowany plaintext do wyczytania
    return (_ssl != nullptr && WiFiClient::connected()) ? 1 : 0;
}

void WsTlsClient::stop() {
    if (_ssl) {
        // Snapshot sesji (z biletem NST) PRZED free — jedyny bezpieczny punkt:
        // bilety przyszly w trakcie zycia polaczenia; get1_session adoptuje przez
        // refcount (bez kopii), free tylko zdejmuje referencje.
        if (_hsDone) {
            WOLFSSL_SESSION* s = wolfSSL_get1_session(_ssl);
            if (s) {
                if (g_session && g_session != s) wolfSSL_SESSION_free(g_session);
                g_session = s;
            }
        }
        wolfSSL_shutdown(_ssl);   // pojedyncza, nieblokująca próba close_notify
        wolfSSL_free(_ssl);
        _ssl = nullptr;
        if (_hsDone) {
            _hsDone = false;
            ws_tls_print_heap("post-disconnect");
        }
    }
    WiFiClient::stop();
}

// ── Jednorazowy PoC pomiarowy (diagnostyka; nieużywany w obrazie -> gc-sections wytnie) ──
void ws_tls_run_poc_test() {
    LOGI("tls", "=== wolfSSL TLS PoC start ===");
    {
        WsTlsClient c;
        if (c.connect("httpbin.org", 443)) {
            ws_tls_print_heap("steady-state");
            const char* req = "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
            c.write((const uint8_t*)req, strlen(req));
            unsigned long deadline = millis() + 5000;
            char resp[192];
            int rd = 0;
            while ((long)(deadline - millis()) > 0 && rd <= 0) {
                if (c.available() > 0) rd = c.read((uint8_t*)resp, sizeof(resp) - 1);
                else { delay(5); yield(); }
            }
            if (rd > 0) {
                resp[rd] = '\0';
                LOGI("tls", "response (%d bytes, truncated): %.100s", rd, resp);
            } else {
                LOGW("tls", "no response body read (rd=%d)", rd);
            }
            c.stop();
        } else {
            LOGE("tls", "PoC handshake did not complete");
        }
    }
    ws_tls_print_heap("post-cleanup");
    LOGI("tls", "=== wolfSSL TLS PoC end ===");
}

#endif // SENSMOS_USE_TLS
