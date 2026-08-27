/**
 * SENSMOS Firmware — net worker, port ESP8266.
 * ESP32: osobny task FreeRTOS + kolejki. ESP8266 (NONOS, jeden rdzeń, zero FreeRTOS):
 * te same joby wykonywane SYNCHRONICZNIE — net_worker_tick() (wołane z loop()) bierze
 * JEDEN job na przebieg i wykonuje go w miejscu. Kolejki = statyczne ring-buffery.
 * Semantyka dla reszty FW bez zmian: enqueue → (tick) → poll(NetResult).
 * Blokujące sondy karmią WDT przez delay()/yield() w pętlach oczekiwania.
 */
#include "net_worker.h"
#include "config.h"
#include "log.h"
#include "wifi_manager.h"
#include "http_internal.h"      // http_begin_url (fetch/webhook)
#include "http_client_util.h"   // http_post_json (webhook)
#include "rdns.h"               // PTR last-hopa (walidacja geo trace)
#include "punch.h"              // UDP hole punch (stun/punch executory + gate)
#include "node_integration.h"   // NW_INTEGRATION: ciało batcha telemetrycznego
#include "traceroute.h"         // icmp_ping (port 8266) + trace
#include <WiFi.h>
#include <HTTPClient.h>
#ifdef MMU_IRAM_HEAP
#include <umm_malloc/umm_heap_select.h>   // HeapSelectIram — drugi heap w IRAM (MMU 16/48)
#endif
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <math.h>
#include "tunnel.h"   // tunnel_active() — przy sesji terminalowej TLS czeka na większy blok

// ── Ring-buffery zamiast kolejek FreeRTOS (jeden kontekst — bez locków) ──
template <typename T, int N>
struct Ring {
    T buf[N];
    volatile int head = 0, count = 0;
    bool push(const T& v) {
        if (count >= N) return false;
        buf[(head + count) % N] = v;
        count++;
        return true;
    }
    bool pop(T& out) {
        if (count == 0) return false;
        out = buf[head];
        head = (head + 1) % N;
        count--;
        return true;
    }
    int size() const { return count; }
};

static Ring<NetJob,    NET_JOBQ_DEPTH>* s_hiQ  = nullptr;
static Ring<NetJob,    NET_JOBQ_DEPTH>* s_loQ  = nullptr;
static Ring<NetResult, NET_RESQ_DEPTH>* s_resQ = nullptr;
static volatile bool s_busy = false;
// metryki (telemetria — jeden kontekst, wyścigów brak)
static volatile uint32_t s_busy_acc_ms = 0;   // suma czasu wykonywania w oknie
static volatile float    s_wait_ema    = 0;   // EMA czekania joba w kolejce (ms)
static uint32_t          s_win_start   = 0;   // początek okna busy%
static uint8_t           s_last_busy   = 0;   // ostatni policzony busy%

// ── ICMP: icmp_ping (traceroute.cpp, wspólny raw pcb) zamiast esp_ping ──
static void nw_probe_icmp(CnJob& j, CnResult& r) {
    int cnt = j.count > 0 ? j.count : CHECKNET_PING_COUNT;
    float rtt = 0, jit = 0, loss = 100; int samples = 0;
    bool ok = icmp_ping(j.host, cnt, CHECKNET_PING_TIMEOUT_MS, CHECKNET_PING_INTERVAL_MS,
                        &rtt, &jit, &loss, &samples);
    r.samples = samples;
    r.rtt_ms = rtt; r.jitter_ms = jit; r.loss_pct = loss; r.ok = ok;
}

// ── Fetch (skrypty): GET + JSON-path ──────────────────────────
// (logika 1:1 z ESP32 — wartosc po sciezce "a.b.0.c")
static float nw_json_path(JsonDocument& doc, const char* path) {
    if (!path || strlen(path) == 0) {
        if (doc.is<JsonObject>()) {
            for (JsonPair kv : doc.as<JsonObject>()) {
                if (kv.value().is<float>() || kv.value().is<int>())
                    return kv.value().as<float>();
            }
        } else if (doc.is<float>() || doc.is<int>()) {
            return doc.as<float>();
        }
        return NAN;
    }
    char buf[64]; strncpy(buf, path, sizeof(buf)-1); buf[sizeof(buf)-1] = '\0';
    JsonVariant node = doc.as<JsonVariant>();
    char* tok = strtok(buf, ".");
    while (tok && !node.isNull()) {
        bool is_num = true;
        for (int i = 0; tok[i]; i++) if (!isdigit(tok[i])) { is_num = false; break; }
        if (is_num && node.is<JsonArray>()) node = node.as<JsonArray>()[atoi(tok)];
        else                                node = node[tok];
        tok = strtok(nullptr, ".");
    }
    if (node.is<float>() || node.is<int>()) return node.as<float>();
    if (node.is<const char*>()) {
        float v = atof(node.as<const char*>());
        return (v != 0.0f || strcmp(node.as<const char*>(), "0") == 0) ? v : NAN;
    }
    return NAN;
}

// Guard TLS: poczekaj na ciagly blok. BearSSL (MFLN 512) potrzebuje ~7-9KB —
// progi przeskalowane w config.h dla 8266. Retry do 3s (krotsze niz na ESP32:
// czekanie blokuje TU loop(), nie osobny task).
static bool nw_wait_tls_heap(uint32_t* out_blk) {
    const uint32_t need = MONITORS_HTTP_MIN_HEAP + (tunnel_active() ? TUNNEL_TLS_RESERVE : 0);
    uint32_t blk = ESP.getMaxFreeBlockSize();
    for (int t = 0; t < 30 && blk < need; t++) {
        delay(100);
        blk = ESP.getMaxFreeBlockSize();
    }
    if (out_blk) *out_blk = blk;
    return blk >= need;
}

static bool nw_tls_defer(const char* url, uint32_t* out_blk) {
    if (strncmp(url, "https://", 8) != 0) return false;
    return !nw_wait_tls_heap(out_blk);
}

// UNIWERSALNA bramka RAM per job (progi 8266 w config.h).
static uint32_t nw_gate_min_free(const char* k) {
    if (!strcmp(k, "http") || !strcmp(k, "fetch") || !strcmp(k, "whook"))
        return HEAP_GATE_TLS + (tunnel_active() ? TUNNEL_TLS_RESERVE : 0);
    if (!strcmp(k, "trace")) return HEAP_GATE_MED;
    return HEAP_GATE_LIGHT;
}
static bool nw_heap_gate(const char* k, uint32_t* out_free, uint32_t* out_blk) {
    bool tls = (!strcmp(k, "http") || !strcmp(k, "fetch") || !strcmp(k, "whook"));
    uint32_t need = nw_gate_min_free(k), freeh = 0, blk = 0;
    for (int t = 0; t < 5; t++) {   // krótki retry (~500ms) — transientne dołki mijają
        freeh = ESP.getFreeHeap(); blk = ESP.getMaxFreeBlockSize();
        if (freeh >= need && (!tls || blk >= MONITORS_HTTP_MIN_HEAP)) break;
        delay(100);
    }
    if (out_free) *out_free = freeh;
    if (out_blk)  *out_blk  = blk;
    return freeh >= need && (!tls || blk >= MONITORS_HTTP_MIN_HEAP);
}

// Strumieniowy odbiór body z twardym capem (1:1 z ESP32).
struct FetchCapStream : public Stream {
    char*  buf;
    size_t cap, len = 0;
    FetchCapStream(char* b, size_t c) : buf(b), cap(c) {}
    size_t write(uint8_t c) override {
        if (len >= cap) return 0;
        if (c >= 0x20 || c == '\0') buf[len++] = (char)c;
        return 1;
    }
    size_t write(const uint8_t* d, size_t n) override {
        size_t i = 0;
        for (; i < n; i++) if (!write(d[i])) break;
        return i;
    }
    int available() override { return 0; }
    int read()      override { return -1; }
    int peek()      override { return -1; }
};

static void nw_run_fetch(NetJob& nj, NetResult& out) {
    CnResult& r = out.res;
    if (nw_tls_defer(nj.url, &out.heap_largest)) { out.deferred = true; return; }
    HTTPClient http;
    WiFiClientSecure sec;
    if (!http_begin_url(http, sec, String(nj.url))) { r.ok = false; return; }
    http.setTimeout(HTTP_TIMEOUT_FETCH);
    http.setUserAgent(HTTP_PROBE_UA);
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
    http.setRedirectLimit(HTTP_PROBE_REDIRECT_MAX);
    int code = http.GET();
    r.status_code = code;
    if (code != 200) {
        http.end();
        r.ok = false;
        snprintf_P(out.payload, sizeof(out.payload), PSTR("{\"http_error\":%d,\"status\":%d}"), code, code);
        return;
    }
    char* buf;
    {
        // 4KB transientu do IRAM — najwiekszy nie-TLS skok; dostep bajtowy, ale bulk
        // i rzadki (fetch joby), wiec handler non-32bit nie gra roli.
#ifdef MMU_IRAM_HEAP
        HeapSelectIram ephemeral;
#endif
        buf = (char*)malloc(FETCH_BODY_LIMIT + 1);
    }
    if (!buf) {
        http.end();
        r.ok = false;
        snprintf_P(out.payload, sizeof(out.payload), PSTR("{\"http_error\":-1,\"status\":0}"));
        return;
    }
    FetchCapStream capw(buf, FETCH_BODY_LIMIT);
    http.writeToStream(&capw);
    http.end();
    buf[capw.len] = 0;
    r.ok = true;
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, buf);
    if (!err) {
        float val = nw_json_path(doc, nj.fetch_path[0] ? nj.fetch_path : nullptr);
        if (!isnan(val)) {
            out.has_value = true; out.store_val = val;
            snprintf_P(out.payload, sizeof(out.payload), PSTR("{\"value\":%.4f,\"path\":\"%s\"}"), val, nj.fetch_path);
        } else {
            serializeJson(doc, out.payload, sizeof(out.payload));
        }
    } else {
        float plain = atof(buf);
        if (plain != 0.0f) {
            out.has_value = true; out.store_val = plain;
            snprintf_P(out.payload, sizeof(out.payload), PSTR("{\"value\":%.4f}"), plain);
        } else {
            r.ok = false;
            snprintf_P(out.payload, sizeof(out.payload), PSTR("{\"parse_error\":0,\"status\":0}"));
        }
    }
    free(buf);
}

static void nw_run_webhook(NetJob& nj, NetResult& out) {
    if (nw_tls_defer(nj.url, &out.heap_largest)) { out.deferred = true; return; }
    const char* body = (nj.src == NW_INTEGRATION) ? node_integration_wor_body()
                                                  : (nj.body[0] ? nj.body : "{}");
    int code = http_post_json(nj.url, body, HTTP_TIMEOUT_WEBHOOK);
    out.res.status_code = code;
    out.res.ok = (code >= 200 && code < 400);
}

// ── Skan WiFi (NW_SYSTEM) ─────────────────────────────────────
static void nw_run_scan(NetResult& out) {
    WiFi.scanDelete();
    WiFi.scanNetworks(true);                       // async start
    int n = WIFI_SCAN_RUNNING;
    unsigned long t0 = millis();
    while ((n = WiFi.scanComplete()) == WIFI_SCAN_RUNNING && millis() - t0 < 30000UL)
        delay(200);
    out.res.ok = n >= 0;
    out.res.samples = n > 0 ? n : 0;
    WiFi.scanDelete();
    LOGD("net", "wifi scan: %d nets in %lums", n, millis() - t0);
}

// SSRF guard (operator-side) — 1:1 z ESP32.
static bool nw_target_public(const char* host) {
    IPAddress r;
    if (!r.fromString(host)) {
        if (!WiFi.hostByName(host, r)) return true;
    }
    uint8_t a = r[0], b = r[1];
    if (a == 10 || a == 127 || a == 0)      return false;
    if (a == 169 && b == 254)               return false;   // link-local
    if (a == 172 && b >= 16 && b <= 31)     return false;   // 172.16/12
    if (a == 192 && b == 168)               return false;   // 192.168/16
    if (a == 100 && b >= 64 && b <= 127)    return false;   // CGNAT 100.64/10
    if (a >= 224)                            return false;   // multicast/reserved
    return true;
}

// ── Wykonanie jednego joba (1:1 z ESP32 poza icmp) ────────────
static void nw_execute(NetJob& j, NetResult& out) {
    memset(&out, 0, sizeof(out));
    out.src = j.src; out.ref_id = j.ref_id; out.ref_idx = j.ref_idx;
    CnResult& r = out.res; r.loss_pct = 100;
    const char* k = j.job.kind;

    bool gw_self = (j.src == NW_CHECKNET) && !strcmp(k, "icmp") &&
                   j.job.host[0] && WiFi.gatewayIP().toString() == j.job.host;
    if (!gw_self &&
        (j.src == NW_MONITOR || j.src == NW_CHECKNET) &&
        (!strcmp(k, "icmp") || !strcmp(k, "tcp") || !strcmp(k, "http")) &&
        !nw_target_public(j.job.host)) {
        LOGW("net", "blocked target %s (%s) - private/unresolvable (SSRF guard)", j.job.host, k);
        r.ok = false;
        out.blocked = true;
        out.deferred = (j.src != NW_MONITOR);
        return;
    }

    {
        uint32_t gf = 0, gb = 0;
        if (!nw_heap_gate(k, &gf, &gb)) {
            out.deferred = true; r.ok = false; out.heap_largest = gb;
            LOGW("wor", "DEFER %s %s | heap=%uk blk=%uk < prog", k, j.job.host, gf / 1024, gb / 1024);
            return;
        }
    }

    if (!strcmp(k, "trace")) {
        out.is_trace = true;
        out.hop_n = (int16_t)traceroute_run(j.job.host, out.hops, TR_MAX_HOPS, 1000, &out.reached);
        r.ok = out.hop_n > 0;
        for (int h = out.hop_n - 1; h >= 0; h--) {
            uint32_t ip = out.hops[h].ip;
            if (!ip) continue;
            uint8_t o1 = ip & 0xFF, o2 = (ip >> 8) & 0xFF;
            if (o1 == 10 || (o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168) ||
                (o1 == 100 && o2 >= 64 && o2 <= 127) || (o1 == 169 && o2 == 254)) continue;
            rdns_ptr(ip, out.lh_host, sizeof(out.lh_host), 2000);
            break;
        }
        return;
    }
    if (!strcmp(k, "stun"))  { punch_exec_stun(j, out);  return; }
    if (!strcmp(k, "punch")) { punch_exec_punch(j, out); return; }
    if (!strcmp(k, "fetch")) { nw_run_fetch(j, out);   return; }
    if (!strcmp(k, "whook")) { nw_run_webhook(j, out); return; }
    if (!strcmp(k, "scan"))  { nw_run_scan(out);       return; }
    if (!strcmp(k, "http")) { cn_probe_http(j.job, r); return; }
    if (!strcmp(k, "tcp"))  { cn_probe_tcp(j.job, r); return; }
    if (!strcmp(k, "dns"))  { cn_probe_dns(j.job, r); return; }
    if (!strcmp(k, "icmp")) { nw_probe_icmp(j.job, r); return; }
    // nieznany kind → out.res.ok=false (loss 100)
}

static const char* nw_src_name(uint8_t s) {
    switch (s) {
        case NW_CHECKNET: return "CN";
        case NW_MONITOR:  return "MON";
        case NW_SCRIPT:   return "SCRIPT";
        case NW_SYSTEM:   return "SYS";
        case NW_PUNCH:    return "PUNCH";
        case NW_CHECKNOW: return "CHECKNOW";
        case NW_INTEGRATION: return "NI";
        default:          return "?";
    }
}

// ── Tick: JEDEN job na wywołanie (wołane z loop()) ────────────
static bool     s_pass_run = false;
static uint32_t s_pass_t0 = 0, s_pass_h0 = 0;
static int      s_pass_n = 0;

void net_worker_tick() {
    if (!s_hiQ) return;
    NetJob j;
    // punch-gate: po STUN nie zaczynaj lo-jobów (trace = 30s) — okno punch by przepadło
    bool got = s_hiQ->pop(j) || (!punch_gate_active() && s_loQ->pop(j));
    if (!got) {
        if (s_pass_run) {
            LOGI("wor", "END pass: %d job%s | %ums | heap=%uk->%uk",
                 s_pass_n, s_pass_n == 1 ? "" : "s", millis() - s_pass_t0,
                 s_pass_h0 / 1024, ESP.getFreeHeap() / 1024);
            s_pass_run = false;
        }
        return;
    }
    if (!s_pass_run) {
        s_pass_run = true; s_pass_t0 = millis(); s_pass_n = 0; s_pass_h0 = ESP.getFreeHeap();
        LOGI("wor", "BEG pass | heap=%uk blk=%uk", s_pass_h0 / 1024, ESP.getMaxFreeBlockSize() / 1024);
    }
    s_pass_n++;
    s_busy = true;
    uint32_t wait = millis() - j.enq_ms;
    s_wait_ema = (s_wait_ema == 0) ? (float)wait : s_wait_ema * 0.7f + (float)wait * 0.3f;
    uint32_t t0 = millis(), jh0 = ESP.getFreeHeap();
    NetResult out;
    nw_execute(j, out);
    uint32_t dt = millis() - t0;
    s_busy_acc_ms += dt;
    LOGI("wor", "  %s %s %s | heap %uk->%uk blk %uk | %ums %s",
         nw_src_name(j.src), j.job.kind, j.job.host, jh0 / 1024, ESP.getFreeHeap() / 1024,
         ESP.getMaxFreeBlockSize() / 1024, dt, out.deferred ? "DEFER" : (out.res.ok ? "OK" : "FAIL"));
    if (!s_resQ->push(out)) LOGW("wor", "result queue full — dropped");
    s_busy = false;
}

// ── API ───────────────────────────────────────────────────────
bool net_worker_init() {
    // Ringi (~7.2KB, rezydentne od bootu) do IRAM second heap: dostep to wylacznie
    // struct-copy push/pop (wyrownane memcpy slowami), wiec kara non-32bit jest pomijalna,
    // a DRAM odzyskuje najwiekszy stały blok heapu.
#ifdef MMU_IRAM_HEAP
    HeapSelectIram ephemeral;
#endif
    s_hiQ  = new Ring<NetJob,    NET_JOBQ_DEPTH>();
    s_loQ  = new Ring<NetJob,    NET_JOBQ_DEPTH>();
    s_resQ = new Ring<NetResult, NET_RESQ_DEPTH>();
    if (!s_hiQ || !s_loQ || !s_resQ) { LOGE("net", "queue alloc failed"); return false; }
    LOGI("net", "worker up (cooperative tick, 8266)");
    return true;
}

bool net_worker_enqueue(const NetJob& j, bool hi) {
    Ring<NetJob, NET_JOBQ_DEPTH>* q = hi ? s_hiQ : s_loQ;
    if (!q) return false;
    NetJob stamped = j;
    stamped.enq_ms = millis();
    return q->push(stamped);
}

bool net_worker_poll(NetResult& out) {
    if (!s_resQ) return false;
    return s_resQ->pop(out);
}

uint16_t net_worker_pending() {
    if (!s_hiQ || !s_loQ) return 0;
    return (uint16_t)(s_hiQ->size() + s_loQ->size());
}

bool net_worker_busy() { return s_busy; }

void net_worker_stats(uint16_t* wait_ms, uint8_t* busy_pct, uint16_t* depth) {
    uint32_t now = millis();
    uint32_t win = now - s_win_start;
    if (wait_ms)  *wait_ms  = (uint16_t)(s_wait_ema > 65535 ? 65535 : s_wait_ema);
    uint32_t pct = win > 0 ? (100UL * s_busy_acc_ms) / win : 0;
    if (pct > 100) pct = 100;
    s_last_busy = (uint8_t)pct;
    if (busy_pct) *busy_pct = s_last_busy;
    if (depth) *depth = net_worker_pending() + (s_busy ? 1 : 0);
    s_busy_acc_ms = 0;            // nowe okno od tego odczytu
    s_win_start   = now;
}

uint8_t net_worker_last_busy() { return s_last_busy; }
