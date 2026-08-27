/**
 * SENSMOS — RemoteTerminal (tunnel.cpp), port ESP8266.
 *
 * ESP32: osobny task FreeRTOS był JEDYNYM właścicielem socketu LAN, a bajty szły
 * przez kolejki do loop(). ESP8266 (NONOS, jeden kontekst): task i kolejki znikają —
 * wszystko dzieje się w tunnel_tick()/handlerach (ten sam kontekst co WS).
 * Flow-control zostaje IDENTYCZNY w skutkach: czytamy z socketu TYLKO tyle, ile
 * faktycznie wyślemy przez WS w tym ticku (throttle okna + stop przy send-fail);
 * nadmiar zostaje w buforze TCP → okno się zamyka → host zwalnia. Zero dropu.
 */
#include "tunnel.h"
#include "log.h"
#include "ws_client.h"
#include "data_sender.h"   // g_tx_scratch / TX_SCRATCH_LEN (bufor TX loop-only)
#include <WiFi.h>
#include <Preferences.h>
#include <mbedtls/base64.h>
#ifdef MMU_IRAM_HEAP
#include <umm_malloc/umm_heap_select.h>   // HeapSelectIram — drugi heap w IRAM
#endif

// ── Parametry (1:1 z ESP32 poza task/queue) ────────────────────
#define TUN_CHUNK        1024          // bajtów na porcję (base64 → ~1420B JSON, mieści się w enc seal)
#define TUN_WIN_MS       100
#define TUN_READ_PER_WIN 3072          // 3KB/100ms ≈ 30KB/s — wolno, ale komplet i stabilnie
#define TUN_CONNECT_MS   8000          // timeout connect do celu LAN
#define TUN_IDLE_MS      (5UL*60*1000) // brak bajtów → auto-close (chroni socket)
#define TUN_SESSION_MS   (2UL*60*60*1000UL) // twardy limit sesji
#define TUN_TICK_MAX     4             // ile porcji LAN→BE max na jeden tick (nie zajeżdżaj loop)
#define TUN_TEARDOWN_MS  (2UL*60*1000) // linger po sesji zanim podsystem odda RAM

enum { S_IDLE = 0, S_OPEN = 1 };

// ── Stan podsystemu ────────────────────────────────────────────
static bool          s_up      = false;   // bufory zaalokowane
static bool          s_enabled = false;   // NVS remote_ok
static WiFiClient    s_cli;
static int           s_state = S_IDLE;
static int           s_tid   = 0;
// Bufory robocze na HEAP (jak 0.71): nody z remote_ok=false nigdy nie alokują.
static uint8_t*      s_chunk = nullptr;   // TUN_CHUNK
static uint8_t*      s_b64   = nullptr;   // base64 scratch (TUN_CHUNK*2)
static unsigned long s_idle_since = 0;
static unsigned long s_lastAct = 0, s_openedAt = 0;

// ── Helpers ────────────────────────────────────────────────────
static bool nvs_get_remote_ok() {
    Preferences p; p.begin("sensmos", true);
    bool v = p.getBool("remote_ok", false); p.end();
    return v;
}
static void nvs_set_remote_ok(bool v) {
    Preferences p; p.begin("sensmos", false);
    p.putBool("remote_ok", v); p.end();
}

// RFC1918 / CGNAT / loopback / link-local — tylko prywatne cele (nigdy publiczny internet)
static bool is_private(const IPAddress& ip) {
    uint8_t a = ip[0], b = ip[1];
    if (a == 10 || a == 127)                 return true;
    if (a == 192 && b == 168)                return true;
    if (a == 172 && b >= 16 && b <= 31)      return true;
    if (a == 169 && b == 254)                return true;   // link-local
    if (a == 100 && b >= 64 && b <= 127)     return true;   // CGNAT 100.64/10
    return false;
}

// Ten sam kontekst co WS → stan raportujemy bezpośrednio.
static void send_state(int tid, const char* st, const char* msg) {
    char buf[128];
    snprintf_P(buf, sizeof(buf), PSTR("{\"type\":\"tun_state\",\"tid\":%d,\"st\":\"%s\",\"msg\":\"%s\"}"), tid, st, msg ? msg : "");
    ws_client_send_raw(buf);
}

static void do_close(const char* reason) {
    if (s_state == S_IDLE) return;
    s_cli.stop();
    int tid = s_tid;
    s_state = S_IDLE; s_tid = 0;
    send_state(tid, "closed", reason);
    LOGI("tun", "closed tid=%d (%s)", tid, reason ? reason : "");
}

static void tun_free_all() {
    free(s_chunk); free(s_b64);
    s_chunk = nullptr; s_b64 = nullptr;
    s_up = false; s_idle_since = 0;
}

static bool tun_spin_up() {
    if (s_up) return true;
    // ~3KB sesyjne do IRAM second heap — bulk base64/chunk, latency-tolerant.
#ifdef MMU_IRAM_HEAP
    HeapSelectIram ephemeral;
#endif
    s_chunk = (uint8_t*)malloc(TUN_CHUNK);
    s_b64   = (uint8_t*)malloc(TUN_CHUNK * 2);
    if (!s_chunk || !s_b64) {
        LOGE("tun", "spin-up alloc failed — rollback");
        tun_free_all();
        return false;
    }
    s_up = true; s_idle_since = 0;
    LOGI("tun", "spin-up (~3KB heap - session only)");
    return true;
}

// ── Init ───────────────────────────────────────────────────────
void tunnel_init() {
    s_enabled = nvs_get_remote_ok();         // boot: tylko polityka, zero alokacji
}

bool tunnel_enabled() { return s_enabled; }
bool tunnel_active()  { return s_state == S_OPEN; }

// ── Dispatch z ws_client (kontekst loop) ───────────────────────
void tunnel_on_open(int tid, const char* ip, int port) {
    if (!s_enabled) { send_state(tid, "error", "remote access disabled"); return; }
    if (!s_up && !tun_spin_up()) { send_state(tid, "error", "low memory, retry"); return; }
    if (s_state != S_IDLE) { send_state(tid, "error", "busy (one tunnel at a time)"); return; }
    IPAddress addr;
    if (!ip || !addr.fromString(ip)) { send_state(tid, "error", "target must be a literal IP"); return; }
    if (!is_private(addr))           { send_state(tid, "error", "only private LAN addresses allowed"); return; }

    s_cli.setTimeout(TUN_CONNECT_MS);
    LOGI("tun", "open tid=%d → %s:%u", tid, ip, (unsigned)port);
    if (!s_cli.connect(addr, (uint16_t)port)) {
        send_state(tid, "error", "connect failed");
        return;
    }
    s_cli.setNoDelay(true);
    s_tid = tid; s_state = S_OPEN;
    s_lastAct = s_openedAt = millis();
    send_state(tid, "open", "connected");
}

void tunnel_on_data(int tid, const char* b64) {
    if (!s_up || !b64) return;
    if (s_state != S_OPEN || tid != s_tid) return;   // brak aktywnego tunelu o tym id → drop
    size_t inlen = strlen(b64), olen = 0;
    if (mbedtls_base64_decode(s_chunk, TUN_CHUNK, &olen, (const uint8_t*)b64, inlen) != 0 || olen == 0) return;
    s_cli.write(s_chunk, olen);                      // bezpośrednio do socketu (jeden kontekst)
    s_lastAct = millis();
}

void tunnel_on_close(int tid) {
    (void)tid;
    if (s_state == S_OPEN) do_close("closed by user");
}

void tunnel_set_enabled(bool on) {
    nvs_set_remote_ok(on);
    s_enabled = on;
    if (!on && s_state == S_OPEN) do_close("disabled");
    LOGI("tun", "remote access %s", on ? "ENABLED (policy)" : "DISABLED");
}

// ── Tick (kontekst loop — WS-safe) ─────────────────────────────
void tunnel_tick() {
    if (!s_up) return;

    if (s_state == S_OPEN) {
        // LAN → BE: czytaj TYLKO tyle, ile realnie wyślemy (throttle okna + stop przy
        // send-fail). Nieprzeczytane bajty zostają w buforze TCP → okno się zamyka →
        // flow-control jak na ESP32, bez kolejek i bez dropu.
        static unsigned long s_win = 0;
        static uint32_t s_read = 0;
        unsigned long now = millis();
        if (now - s_win >= TUN_WIN_MS) { s_win = now; s_read = 0; }
        for (int i = 0; i < TUN_TICK_MAX; i++) {
            if (s_cli.available() <= 0 || s_read >= TUN_READ_PER_WIN) break;
            uint32_t room = TUN_READ_PER_WIN - s_read;
            int n = s_cli.read(s_chunk, room < TUN_CHUNK ? (int)room : TUN_CHUNK);
            if (n <= 0) break;
            size_t olen = 0;
            if (mbedtls_base64_encode(s_b64, TUN_CHUNK * 2, &olen, s_chunk, n) != 0) break;
            s_b64[olen] = '\0';
            char* out = g_tx_scratch;   // współdzielony bufor TX (loop-only)
            int m = snprintf_P(out, TX_SCRATCH_LEN, PSTR("{\"type\":\"tun_data\",\"tid\":%d,\"d\":\"%s\"}"), s_tid, (char*)s_b64);
            if (m <= 0 || m >= TX_SCRATCH_LEN) break;
            if (!ws_client_send_raw(out)) break;     // WS zapchany → przestań czytać (backpressure)
            s_read += (uint32_t)n;
            s_lastAct = millis();
        }
        // peer zamknął?
        if (!s_cli.connected() && s_cli.available() == 0) { do_close("peer closed"); }
        // timeouty
        else if (millis() - s_lastAct  > TUN_IDLE_MS)    { do_close("idle timeout"); }
        else if (millis() - s_openedAt > TUN_SESSION_MS) { do_close("session limit"); }
    }

    // on-demand: sesja zamknięta → linger TUN_TEARDOWN_MS i oddaj RAM; disable → od razu
    if (s_state == S_IDLE) {
        if (!s_enabled) { tun_free_all(); LOGI("tun", "teardown — heap returned"); return; }
        if (!s_idle_since) s_idle_since = millis();
        else if (millis() - s_idle_since > TUN_TEARDOWN_MS) {
            tun_free_all();
            LOGI("tun", "teardown — heap returned");
        }
    } else s_idle_since = 0;
}
