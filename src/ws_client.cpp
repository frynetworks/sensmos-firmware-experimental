#include "node_integration.h"
/**
 * SENSMOS Firmware — WebSocket Client
 * Połączenie z backendem, routing wiadomości.
 */
#include "ws_client.h"
#include "ota.h"
#include "entity_store.h"
#include "identity.h"
#include "ble_config.h"
#include "wifi_manager.h"
#include "subscription_map.h"
#include "http_server.h"
#include "node_log.h"
#include "message_router.h"
#include "checknet.h"
#include "checknow.h"
#include "punch.h"
#include "monitors.h"
#include "tunnel.h"
#include "geolocation.h"
#include "data_sender.h"
#include "ws_enc.h"
#include "log.h"
#include <ArduinoJson.h>
#include <WebSocketsClient.h>
#include <esp_random.h>

static WebSocketsClient ws;
static bool             g_ws_connected = false;
static unsigned long    g_last_reconnect = 0;
#define RECONNECT_INTERVAL 5000

// Ghost-session resilience: WS moze wstac + odpowiadac na WS-ping, ale BE NIGDY nie
// przyśle "identified" (przetrzymuje starą sesję dla tego device_id ~35s po brudnym
// zamknięciu) → g_ws_connected wisi false na zawsze. Brak app-level timeoutu na
// identify. Śledzimy moment wysłania identify; jeśli po IDENTIFY_TIMEOUT_MS nadal
// !connected → ws.disconnect() (wymusza reconnect + świeży identify), z narastającym
// backoffem. Reap-okno BE ~35s, więc timeout musi je pokryć w kilku próbach.
static unsigned long s_identify_sent_ms = 0;
static uint8_t       s_identify_tries   = 0;
#define IDENTIFY_TIMEOUT_MS 12000UL

// Nonce sesji wygenerowany w send_identify — pół soli klucza (druga połowa: be_nonce z identified).
static uint8_t s_fw_nonce[16] = {0};
// JEDEN bufor enc (loop-only) dla TX i RX — oszczędza ~3KB .bss. Bezpieczne bo half-duplex w loop:
// RX plaintext jest w CAŁOŚCI skopiowany do JsonDocument przez deserializeJson (handle_message bierze
// `const char*` → ArduinoJson w trybie KOPIUJĄCYM) ZANIM ruszy dispatch; handlery które synchronicznie
// wysyłają (push/script) czytają z własnych buforów i pieczętują tutaj, nadpisując już-martwe bajty RX.
// ⚠️ INWARIANT: handle_message MUSI zostać na `const char*`. Gdyby przyjął zapisywalny `char*` (zero-copy),
// doc aliasowałby ten bufor i TX z handlera by go zepsuł w trakcie dispatchu. Rozmiar = max tasks_update.
static uint8_t s_enc[TX_SCRATCH_LEN + 32];

// ── Parsowanie URL ─────────────────────────────────────────────
static bool parseUrl(const char* url, char* host, int* port, char* path_out, bool* secure) {
    const char* p = url;
    *secure = false;
    int defPort = 80;
    if      (strncmp(p, "https://", 8) == 0) { p += 8; *secure = true; defPort = 443; }
    else if (strncmp(p, "http://",  7) == 0) { p += 7; }

    const char* colon = strchr(p, ':');
    const char* slash = strchr(p, '/');

    // host = bufor char[64] u wywolujacego → clamp do 63, inaczej dlugi host = stack overflow
    const size_t HOST_MAX = 63;
    if (colon && (!slash || colon < slash)) {
        size_t n = (size_t)(colon - p); if (n > HOST_MAX) n = HOST_MAX;
        strncpy(host, p, n); host[n] = '\0';
        *port = atoi(colon + 1);
    } else if (slash) {
        size_t n = (size_t)(slash - p); if (n > HOST_MAX) n = HOST_MAX;
        strncpy(host, p, n); host[n] = '\0';
        *port = defPort;
    } else {
        strncpy(host, p, HOST_MAX); host[HOST_MAX] = '\0';
        *port = defPort;
    }

    if (slash) snprintf_P(path_out, 64, PSTR("%s/ws"), slash);
    else       strcpy(path_out, "/v1/ws");
    return true;
}

// ── Identify ──────────────────────────────────────────────────
static void send_identify() {
    unsigned long ts = millis() / 1000;

    // Nonce sesji (16B) — wchodzi do PODPISYWANEGO stringa razem z flagą e1: MITM nie zdejmie
    // szyfrowania ani nie podmieni nonce bez złamania podpisu (downgrade → rozłączenie, nie plaintext).
    esp_fill_random(s_fw_nonce, 16);
    char enonce_hex[33];
    bytes_to_hex(s_fw_nonce, 16, enonce_hex);

    char msg_to_sign[160];
    snprintf_P(msg_to_sign, sizeof(msg_to_sign),
        PSTR("identify:%s:%lu:e1:%s"), g_device_id, ts, enonce_hex);

    uint8_t hash[32];
    sha256_string(msg_to_sign, hash);
    uint8_t sig[72]; size_t sig_len = 0;
    identity_sign(hash, sig, &sig_len);
    char sig_hex[145];
    bytes_to_hex(sig, sig_len, sig_hex);

    JsonDocument doc;
    doc["type"]      = "identify";
    doc["device_id"] = g_device_id;
    doc["timestamp"] = (uint32_t)ts;
    doc["msg"]       = msg_to_sign;
    doc["signature"] = sig_hex;
    doc["enc"]       = 1;             // wymagam szyfrowania kanału (ws_enc)
    doc["enonce"]    = enonce_hex;    // pół soli klucza sesji
    doc["firmware"]  = FW_VERSION;
    if (tunnel_enabled()) doc["remote"] = 1;   // remote-access ON → BE omija ten node w doborze monitorów
    // Dane plytki RAZ na polaczenie (nie w kazdym batchu): model/rev/MHz/flash ->
    // devices.chip; korelacja czasow TLS/probe ze sprzetem
    static char s_chip[48] = {0};
    if (!s_chip[0])   // 8266: brak getChipModel/getChipRevision — stały model + realny flash
        snprintf_P(s_chip, sizeof(s_chip), PSTR("ESP8266 @%luMHz %luMB"),
                 (unsigned long)ESP.getCpuFreqMHz(),
                 (unsigned long)(ESP.getFlashChipRealSize() / (1024UL*1024UL)));
    doc["chip"] = s_chip;

    String packet;
    serializeJson(doc, packet);
    ws.sendTXT(packet);
    s_identify_sent_ms = millis();   // start zegara odpowiedzi (ghost-session guard)
    LOGD("ws", "identify sent (%dB)", packet.length());
}

// Czyste zamknięcie WS (ramka close 1000) PRZED ESP.restart() — twardy reset nie
// woła destruktorów, więc bez tego BE nie widzi close i trzyma sesję-ducha ~35s.
void ws_client_graceful_close() {
    if (ws.isConnected()) {
        ws.disconnect();
        delay(50);   // daj ramce close wyjść na drut przed restartem
    }
}

// ── Zapis danych subskrypcji do entity_store ──────────────────
// Prefix z lokalnej mapy subskrypcji po device_id nadawcy (from); default "sub".
static void push_remote_entities(JsonObject user_obj, JsonArray pub_arr,
                                 const char* from) {
    char prefix[16];
    if (!from || !sub_map_get(from, prefix, sizeof(prefix)))
        strcpy(prefix, "sub");

    if (!user_obj.isNull()) {
        for (JsonPair kv : user_obj) {
            const char* k = kv.key().c_str();
            if (strncmp(k, "pub.", 4) == 0) k += 4;
            char eid[64], val[64];
            snprintf_P(eid, sizeof(eid), PSTR("%s.%s"), prefix, k);
            if (kv.value().is<const char*>()) {
                strncpy(val, kv.value().as<const char*>(), 63);
            } else {
                float fv = kv.value().as<float>();
                (fv == (int)fv)
                    ? snprintf_P(val, sizeof(val), PSTR("%d"),   (int)fv)
                    : snprintf_P(val, sizeof(val), PSTR("%.2f"), fv);
            }
            entity_push(eid, val, "");
        }
    }

    if (!pub_arr.isNull()) {
        for (JsonObject e : pub_arr) {
            const char* eid  = e["entity_id"] | "";
            const char* val  = e["value"]     | "";
            const char* unit = e["unit"]      | "";
            const char* base = (strncmp(eid, "pub.", 4) == 0) ? eid + 4 : eid;
            char full_eid[64];
            snprintf_P(full_eid, sizeof(full_eid), PSTR("%s.%s"), prefix, base);
            entity_push(full_eid, val, unit);
        }
    }
}

// Geolokalizacja: push odłożony z on_identified() do ws_client_tick() — patrz komentarz tam.
static bool s_geo_push_pending = false;

// ── Handlery per typ wiadomości ───────────────────────────────
static void on_identified(JsonDocument& doc) {
    uint32_t st = doc["server_time"] | 0;   // czas serwera (informacyjnie)

    // Ustanów klucz sesji: be_nonce (hex) z identified + s_fw_nonce z identify → ECDH+HKDF.
    // Dopiero po sukcesie oznaczamy WS jako gotowy — od tej chwili wszystko idzie szyfrowane (BIN).
    const char* be_hex = doc["enonce"] | "";
    if (strlen(be_hex) != 32) { LOGE("ws", "identified without enonce - BE lacks enc support; disconnecting"); ws.disconnect(); return; }
    uint8_t be_nonce[16];
    for (int i = 0; i < 16; i++) { unsigned v; if (sscanf(be_hex + i*2, "%2x", &v) != 1) { ws.disconnect(); return; } be_nonce[i] = (uint8_t)v; }
    if (!ws_enc_derive(s_fw_nonce, be_nonce)) { LOGE("ws", "key derive failed - disconnecting"); ws.disconnect(); return; }

    g_ws_connected = true;
    s_identify_sent_ms = 0;   // odpowiedź przyszła — rozbrój ghost-guard
    s_identify_tries   = 0;
    node_integration_push("ws_connected", "{}");

    // 0.64: udany identify = BE zna device i wpuścił → onboarding potwierdzony.
    // Rozbraja watchdog factory-resetu, gdy apka nie mogła strzelić lokalnego
    // /node/confirm (telefon w innej podsieci niż node — mDNS nie przechodzi).
    watchdog_confirm();

    // Załaduj native_entities
    int loaded = 0;
    for (JsonObject e : doc["entities"].as<JsonArray>()) {
        const char* eid = e["entity_id"] | "";
        if (strlen(eid) > 0) { entity_load_native(eid); loaded++; }
    }

    LOGI("ws", "identified+enc (%d native entities, server_time=%u)", loaded, st);

    // Report the device-local (coarse, IP-derived) position so the app has SOME location before
    // anyone opens it near the node — idempotent BE-side, and an app GPS fix overrides it via the
    // usual setAppLocation path (see geolocation.h). DEFERRED to the next tick on purpose: we are
    // still inside handle_message(), where the whole identified payload (40+ entities) is alive in
    // a JsonDocument, so the heap here is at its tightest of the whole session.
    s_geo_push_pending = true;
}

static void on_message_recv(JsonDocument& doc) {
    const char* from       = doc["from"]    | "unknown";
    const char* message_id = doc["eid"]     | "unknown";
    const char* pl         = doc["payload"] | "";

    http_inbox_push(from, message_id, pl);
    LOGD("ws", "message %s from %.8s", message_id, from);
    message_router_dispatch(from, message_id, pl);
}

static void on_message_sent(JsonDocument& doc) {
    bool delivered = doc["delivered"] | false;
    if (!delivered) LOGD("ws", "message: recipient offline");
}

static void on_batch_ack(JsonDocument& doc) {
    int saved = doc["entities_saved"] | 0;
    LOGD("ws", "batch ack: %d entities", saved);
    char detail[32], sse[64];
    snprintf_P(detail, sizeof(detail), PSTR("%d entities saved"), saved);
    snprintf_P(sse,    sizeof(sse),    PSTR("{\"entities_saved\":%d}"), saved);
    node_log_push("batch", detail, true);
    node_integration_push("batch_sent", sse);
}

static void on_batch_error(JsonDocument& doc) {
    LOGW("ws", "batch error: %s", doc["error"] | "?");
}

static void on_tasks_update(JsonDocument& doc) {
    extern int script_engine_load(const JsonArray&);
    extern int script_engine_load_user();
    int n = script_engine_load(doc["scripts"].as<JsonArray>());
    script_engine_load_user();
    LOGD("ws", "tasks: %d BE scripts", n);
}

static void on_tasks_clear(JsonDocument& doc) {
    extern void script_engine_clear();
    script_engine_clear();
    LOGD("ws", "scripts cleared");
}

// Komendy zmieniające stan przychodzą WYŁĄCZNIE przez zaszyfrowany kanał (ramka BIN, tag GCM =
// autentyczność). Plaintext (WStype_TEXT) po aktywacji enc jest DROPOWANY w wsEvent, więc MITM na
// ws://:80 nie wstrzyknie fałszywej komendy. Ten guard = pas bezpieczeństwa (dispatch komend i tak
// leci tylko z ramek BIN). Zastąpił K3 (podpisy per-komenda + pula nonce).
static bool cmd_enc_guard(const char* type) {
    if (!ws_enc_active()) { LOGW("ws", "%s outside encryption — rejected", type); return false; }
    return true;
}

// Zdalny restart (BE admin) — czyści wyciekłą pamięć bez fizycznego dostępu.
static void on_reboot(JsonDocument& doc) {
    if (!cmd_enc_guard("reboot")) return;
    LOGW("ws", "remote reboot — restarting");
    ws_client_graceful_close();   // ramka close → BE reapuje sesję od razu (bez ducha)
    delay(300);
    ESP.restart();
}

// Owner skasował noda z apki (BE→WS). TRZYMAMY tożsamość/klucze, ale przechodzimy w BLE onboarding
// (flaga NVS + reboot) — czekamy na ponowne dodanie. Bez factory resetu.
static void on_deleted(JsonDocument& doc) {
    if (!cmd_enc_guard("deleted")) return;
    LOGW("ws", "owner deleted node — entering BLE onboarding (identity kept)");
    node_deleted_set(true);
    ws_client_graceful_close();   // ramka close → BE reapuje sesję od razu (bez ducha)
    delay(300);
    ESP.restart();
}

static void on_subscription_push(JsonDocument& doc) {
    const char* from = doc["from"] | "?";
    char detail[48], sse[96];
    snprintf_P(detail, sizeof(detail), PSTR("from:%.8s"), from);
    snprintf_P(sse,    sizeof(sse),    PSTR("{\"from\":\"%.8s...\"}"),  from);
    node_log_push("sub_push", detail, true);
    node_integration_push("sub_received", sse);
    LOGD("ws", "sub push from %.8s", from);
    push_remote_entities(
        doc["user"].as<JsonObject>(),
        doc["pub"].as<JsonArray>(),
        from
    );
}

static void on_error(JsonDocument& doc) {
    LOGW("ws", "backend error: %s", doc["msg"] | "?");
}

static void on_check_jobs(JsonDocument& doc) {
    checknet_on_jobs(doc["jobs"].as<JsonArray>());
}

// Check-now (UpFromWhere, 0.56+): zmierz URL wskazany przez usera na landingu. Tylko przez enc —
// bez tego rogue-WS mógłby kazać nodowi strzelać w dowolny adres.
static void on_check(JsonDocument& doc) {
    if (!cmd_enc_guard("check")) return;
    checknow_on_cmd(doc);
}

// Config checknetu z BE (interwał adaptacyjny wg floty + limity). Stary FW ignoruje ten typ.
static void on_cn_config(JsonDocument& doc) {
    bool     en  = doc["enabled"]    | true;
    uint32_t iv  = (uint32_t)(doc["interval_s"] | 600) * 1000UL;
    int      mj  = doc["max_jobs"]   | 6;
    int      pc  = doc["ping_count"] | 5;
    uint32_t tcd = doc["trace_cd_s"] | 300;
    checknet_set_config(en, iv, mj, pc, tcd);
}

// UDP hole punch (v0.43): BE koordynuje pary — patrz punch.h
static void on_cn_stun(JsonDocument& doc)  { punch_on_stun(doc); }
static void on_cn_punch(JsonDocument& doc) { punch_on_punch(doc); }

// R3 monitory kierowane (v0.30+): deskryptor/odwolanie z BE. Stary FW ignoruje te typy.
static void on_monitor_set(JsonDocument& doc) {
    monitors_on_set(doc["monitor"].as<JsonObject>());
}
static void on_monitor_clear(JsonDocument& doc) {
    monitors_on_clear((int32_t)(doc["id"] | 0));
}

// OTA (v0.35+): podpis BE nad parametrami weryfikuje ota_handle. Stary FW ignoruje typ.
static void on_ota(JsonDocument& doc) {
    ota_handle(doc);
}

// RemoteTerminal (v0.65+): tunel TCP do LAN-u. Owner-only egzekwuje BE; node ma lokalny gate
// (NVS remote_ok) + tylko prywatne cele. Stary FW ignoruje te typy.
static void on_tun_open(JsonDocument& doc) {
    tunnel_on_open((int)(doc["tid"] | 0), doc["ip"] | "", (int)(doc["port"] | 0));
}
static void on_tun_data(JsonDocument& doc) {
    tunnel_on_data((int)(doc["tid"] | 0), doc["d"] | "");
}
static void on_tun_close(JsonDocument& doc) {
    tunnel_on_close((int)(doc["tid"] | 0));
}
static void on_tun_cfg(JsonDocument& doc) {
    tunnel_set_enabled((bool)(doc["enable"] | false));
}

// ── Tablica dispatchu ─────────────────────────────────────────
typedef void (*ws_handler_t)(JsonDocument&);
struct WsEntry { const char* type; ws_handler_t fn; };

static const WsEntry WS_TABLE[] = {
    { "identified",        on_identified },
    { "message",           on_message_recv },
    { "message_sent",      on_message_sent },
    { "batch_ack",         on_batch_ack },
    { "batch_error",       on_batch_error },
    { "tasks_update",      on_tasks_update },
    { "tasks_clear",       on_tasks_clear },
    { "reboot",            on_reboot },
    { "deleted",           on_deleted },
    { "subscription_push", on_subscription_push },
    { "check_jobs",        on_check_jobs },
    { "check",             on_check },
    { "cn_config",         on_cn_config },
    { "cn_stun",           on_cn_stun },
    { "cn_punch",          on_cn_punch },
    { "monitor_set",       on_monitor_set },
    { "monitor_clear",     on_monitor_clear },
    { "ota",               on_ota },
    { "tun_open",          on_tun_open },
    { "tun_data",          on_tun_data },
    { "tun_close",         on_tun_close },
    { "tun_cfg",           on_tun_cfg },
    { "error",             on_error },
};

// ── Obsługa wiadomości ────────────────────────────────────────
static void handle_message(const char* payload) {
    JsonDocument doc;
    DeserializationError err;
    if (!ws_enc_active()) {
        // Pre-enc jedyne legalne ramki to identified/error, a identified urosła (2026-08-18)
        // do ~3.7KB bogatych obiektów (45 encji × entity_id/category/name/unit). Pełny parse
        // potrzebuje ~2× tyle heapu, ile mamy w najciaśniejszym punkcie sesji → NoMemory →
        // "JSON parse error" i martwa sesja. Filtr trzyma TYLKO pola, które faktycznie
        // czytamy (on_identified: enonce/server_time/entities[].entity_id; on_error: msg).
        JsonDocument filter;
        filter["type"] = true;
        filter["msg"] = true;
        filter["enonce"] = true;
        filter["server_time"] = true;
        filter["entities"][0]["entity_id"] = true;
        err = deserializeJson(doc, payload, DeserializationOption::Filter(filter));
    } else {
        err = deserializeJson(doc, payload);
    }
    if (err) {
        LOGW("ws", "JSON parse error");
        return;
    }
    const char* type = doc["type"] | "";

    if (strcmp(type, "pong") == 0) return;

    // Pre-enc (handshake) akceptujemy TYLKO identified/error. Reszta (tasks_update/check_jobs/
    // monitor_set/cn_*) MUSI przyjść szyfrowana (BIN) — inaczej rogue-AP wstrzyknąłby skrypty/config
    // w plaintext, trzymając noda przed identified. Po aktywacji enc plaintext TEXT i tak jest dropowany.
    if (!ws_enc_active() && strcmp(type, "identified") != 0 && strcmp(type, "error") != 0) {
        LOGW("ws", "%s before enc — dropped", type);
        return;
    }

    for (const WsEntry& e : WS_TABLE) {
        if (strcmp(type, e.type) == 0) { e.fn(doc); return; }
    }
    LOGD("ws", "unknown type: %s", type);
}

// ── WS Events ─────────────────────────────────────────────────
static void wsEvent(WStype_t event, uint8_t* payload, size_t length) {
    switch (event) {
        case WStype_CONNECTED:
            LOGI("ws", "connected (heap %uk)", ESP.getFreeHeap() / 1024);
            send_identify();
            break;
        case WStype_DISCONNECTED:
            g_ws_connected = false;
            s_identify_sent_ms = 0;   // socket padł — zegar identify nieaktualny
            ws_enc_reset();   // świeży klucz przy następnym handshake
            if (payload && length) LOGW("ws", "disconnected: %.*s", (int)length, (char*)payload);
            else                   LOGW("ws", "disconnected");
            break;
        case WStype_TEXT:
            // Po ustaleniu klucza cały ruch to BIN — plaintext TEXT = próba wstrzyknięcia (MITM), drop.
            if (ws_enc_active()) { LOGW("ws", "plaintext after enc — dropped"); break; }
            handle_message((char*)payload);
            break;
        case WStype_BIN: {
            if (!ws_enc_active()) { LOGW("ws", "BIN before enc — dropped"); break; }
            int n = ws_enc_open(payload, length, s_enc, sizeof(s_enc) - 1);
            if (n < 0) { LOGW("ws", "enc open failed — reconnect"); ws.disconnect(); break; }
            s_enc[n] = 0;
            handle_message((char*)s_enc);
            break;
        }
        case WStype_ERROR:
            if (payload && length) LOGE("ws", "error: %.*s", (int)length, (char*)payload);
            else                   LOGE("ws", "error");
            break;
        case WStype_PING: LOGD("ws", "ping"); break;
        case WStype_PONG: LOGD("ws", "pong"); break;
        default: break;
    }
}

// ── API ───────────────────────────────────────────────────────
void ws_client_init() {
    if (!g_wifi_connected || strlen(g_backend_url) == 0) return;

    char host[64] = {0}, path[64] = {0};
    int  port = 80; bool secure = false;
    if (!parseUrl(g_backend_url, host, &port, path, &secure)) {
        LOGE("ws", "URL parse error");
        return;
    }

#if WS_PLAINTEXT && !defined(SENSMOS_USE_TLS)
    secure = false;               // WS bez TLS → ~70KB heapu więcej (dane i tak podpisane)
    port   = WS_PLAINTEXT_PORT;   // ws://host:80/v1/ws (nginx → :3000). Fetch/HTTP zostają https.
#endif
    // Env TLS (SENSMOS_USE_TLS): powyższy downgrade wyłączony — parseUrl z https backend_url
    // daje secure=true/port 443, beginSSL() dostaje wolfSSL-owy WsTlsClient (patrz ws_tls.h
    // + tools/patch_websockets_tls.py). ws_enc (szyfrowanie aplikacyjne) działa bez zmian.

    LOGI("ws", "connecting %s://%s:%d%s", secure ? "wss" : "ws", host, port, path);
    if (secure) ws.beginSSL(host, port, path);
    else        ws.begin(host, port, path);
    ws.onEvent(wsEvent);
    ws.setReconnectInterval(RECONNECT_INTERVAL);
    ws.enableHeartbeat(30000, 10000, 2);  // ping co 30s, timeout 10s
}

void ws_client_send_push(const char* title, const char* body) {
    // Wysyła token + treść do BE — BE wysyła FCM
    // Token nie jest przechowywany na BE — wysyłany przy każdym pushu
    extern String push_get_token();
    String token = push_get_token();
    if (token.length() == 0) {
        LOGD("push", "no token — push skipped");
        return;
    }
    char buf[384];
    snprintf_P(buf, sizeof(buf),
        PSTR("{\"type\":\"push\","
        "\"push_token\":\"%s\","
        "\"push_title\":\"%s\","
        "\"push_body\":\"%s\"}"),
        token.c_str(), title, body);
    ws_client_send_raw(buf);
    LOGD("push", "sent: %s", title);
}

bool ws_client_send_raw(const char* json_msg) {
    if (!g_ws_connected) return false;
    if (ws_enc_active()) {
        int n = ws_enc_seal((const uint8_t*)json_msg, strlen(json_msg), s_enc, sizeof(s_enc));
        if (n < 0) { LOGW("ws", "enc seal failed (payload too big?)"); return false; }
        return ws.sendBIN(s_enc, n);
    }
    return ws.sendTXT(json_msg);   // tylko faza pre-handshake (identify idzie plaintextem)
}

bool ws_client_connected() { return g_ws_connected; }
void ws_client_tick() {
    ws.loop();
    // Ghost-session guard: identify wyszedł, BE milczy (trzyma starą sesję) → po
    // narastającym timeoucie zrywamy socket, żeby lib zrobił świeży reconnect+identify.
    // Backoff: 12s, +tries*6s, cap 36s — pokrywa reap-okno BE (~35s) w ~3 próbach.
    if (!g_ws_connected && s_identify_sent_ms) {
        unsigned long wait = IDENTIFY_TIMEOUT_MS + (unsigned long)s_identify_tries * 6000UL;
        if (wait > 36000UL) wait = 36000UL;
        if (millis() - s_identify_sent_ms > wait) {
            LOGW("ws", "identify unanswered %lums (try %u) — forcing reconnect heap=%uk",
                 wait, (unsigned)s_identify_tries, ESP.getFreeHeap() / 1024);
            s_identify_sent_ms = 0;
            if (s_identify_tries < 250) s_identify_tries++;
            ws.disconnect();   // → WStype_DISCONNECTED → 5s reconnect → świeży identify
        }
    }
    if (s_geo_push_pending && g_ws_connected) {   // poza handle_message() — heap już zwolniony
        s_geo_push_pending = false;
        geoloc_push_ws();
    }
}
