/**
 * self_register.cpp — samo-rejestracja noda w BE (v0.2.0).
 *
 * Kontrakt BE zweryfikowany sondą (POST https://api.sensmos.com/v1/register):
 *   {}                        -> 400 {"error":"missing fields: message, pubkey, sig_esp"}
 *   stary ts                  -> 400 {"error":"timestamp expired"}
 *   świeży ts + zły podpis    -> 401 {"error":"invalid esp signature"}
 * Czyli: pole nazywa się `pubkey` (NIE `pubkey_esp`), `proof` nie jest wymagany,
 * a ts musi być świeży → NTP jest twardym warunkiem wstępnym.
 *
 * Payload budujemy TAK SAMO jak sprawdzone do_register() z serial_cmd.cpp — nie
 * przekazujemy zapisanego `reg_payload` (to format dla apki: pubkey_esp+proof).
 * Samego do_register() nie da się użyć wprost: kończy się ESP.restart().
 */
#include "self_register.h"
#include "config.h"
#include "identity.h"
#include "ble_config.h"        // g_owner_address, g_backend_url, watchdog_confirm()
#include "wifi_manager.h"      // g_wifi_connected
#include "ntp_time.h"          // ntp_synced(), ntp_unix_time()
#include "http_internal.h"     // http_begin_url — jedyne miejsce z logiką TLS klienta
#include "node_log.h"
#include "log.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <Preferences.h>

#define SELFREG_INTERVAL_MS   60000UL   // jedna próba na minutę
#define SELFREG_FIRST_DELAY_MS 15000UL  // daj WS/NTP dojść do głosu po boocie
#define SELFREG_MAX_REJECTS   10        // tyle 4xx i przestajemy (payload zostaje do debugu)

static bool          s_done      = false;
static bool          s_gave_up   = false;
static uint8_t       s_rejects   = 0;
static unsigned long s_last_try  = 0;

void self_register_init() {
    Preferences p; p.begin("sensmos", true);
    s_done    = p.getBool("reg_done",   false);
    s_gave_up = p.getBool("reg_giveup", false);
    p.end();
    s_last_try = millis() - SELFREG_INTERVAL_MS + SELFREG_FIRST_DELAY_MS;
    LOGI("selfreg", "init: done=%d giveup=%d owner=%s", (int)s_done, (int)s_gave_up,
         strlen(g_owner_address) ? g_owner_address : "(none)");
}

static void mark_done() {
    Preferences p; p.begin("sensmos", false);
    p.putBool("reg_done", true);
    p.remove("reg_payload");     // zarejestrowany — payload nie jest już potrzebny
    p.end();
    s_done = true;
}

// Core registration POST. NO delay/interval/heap guards — the caller decides when heap is safe.
// Returns the HTTP code (200/201 registered, 4xx rejected, <=0 transient). Requires owner + backend + NTP.
static int self_register_attempt_now() {
    if (!strlen(g_backend_url)) { LOGW("selfreg", "no backend url"); return -1; }

    // message podpisywany 1:1 jak w do_register() (serial_cmd.cpp)
    char message[256];
    snprintf_P(message, sizeof(message),
        PSTR("{\"device_id\":\"%s\",\"owner\":\"%s\",\"ts\":%u}"),
        g_device_id, g_owner_address, (unsigned)ntp_unix_time());

    uint8_t hash[32];
    sha256_string(message, hash);
    uint8_t sig[72]; size_t sig_len = 0;
    if (!identity_sign(hash, sig, &sig_len)) { LOGE("selfreg", "sign failed"); return -1; }
    char sig_esp_hex[145];
    bytes_to_hex(sig, sig_len, sig_esp_hex);
    char pubkey_hex[131];
    identity_get_pubkey_hex(pubkey_hex, sizeof(pubkey_hex));

    JsonDocument doc;
    doc["message"] = message;
    doc["pubkey"]  = pubkey_hex;
    doc["sig_esp"] = sig_esp_hex;
    String payload;
    serializeJson(doc, payload);

    String url = String(g_backend_url) + "/register";
    LOGI("selfreg", "attempting registration to %s (heap %uk blk %uk)", url.c_str(),
         ESP.getFreeHeap() / 1024, ESP.getMaxFreeBlockSize() / 1024);

    HTTPClient http;
    WiFiClientSecure sec;
    if (!http_begin_url(http, sec, url)) { LOGW("selfreg", "http begin failed"); return -1; }
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(HTTP_TIMEOUT_BACKEND);
    int code = http.POST(payload);
    String body = (code > 0) ? http.getString() : String();
    http.end();

    LOGI("selfreg", "POST response: %d", code);

    if (code == 200 || code == 201) {
        mark_done();
        watchdog_confirm();     // BE zna noda → onboarding domknięty
        LOGI("selfreg", "registered! node_confirmed=true");
        node_log_push("selfreg", "registered", true);
    } else if (code >= 400 && code < 500) {
        LOGW("selfreg", "rejected: %s", body.c_str());
        node_log_push("selfreg", body.c_str(), false);
        if (++s_rejects >= SELFREG_MAX_REJECTS) {
            s_gave_up = true;
            Preferences p; p.begin("sensmos", false); p.putBool("reg_giveup", true); p.end();
            LOGE("selfreg", "permanently rejected after %d attempts — payload kept for debug", s_rejects);
        }
    } else {
        // 5xx / timeout / -1: przejściowe — spróbuj w następnym cyklu
        LOGW("selfreg", "transient failure (%d) — retry next cycle", code);
    }
    return code;
}

// One-shot registration at boot, called from setup() in the HIGH-heap window (after ws_client_init,
// before the heavy modules load). BearSSL TLS needs ~9k contiguous; the steady-state loop heap (~10k
// free / ~9k block) is too tight and OOM-crashes, but the boot window has ~17k free / 17k block.
void self_register_boot_attempt() {
    if (s_done || s_gave_up) return;
    if (!g_wifi_connected || !ntp_synced()) return;
    if (!strlen(g_owner_address)) return;   // unclaimed — self_register_tick logs the skip
    self_register_attempt_now();
}

void self_register_tick() {
    if (s_done || s_gave_up) return;
    if (!g_wifi_connected) return;
    if (millis() - s_last_try < SELFREG_INTERVAL_MS) return;
    s_last_try = millis();

    // BE odrzuca stary ts ZANIM sprawdzi podpis — bez NTP nie ma sensu próbować.
    if (!ntp_synced()) { LOGD("selfreg", "waiting for NTP"); return; }
    if (!strlen(g_owner_address)) {          // node nieprzypisany — nie ma czego zgłaszać
        LOGI("selfreg", "no owner set — skipping (unclaimed node)");
        s_gave_up = true;
        return;
    }

    // TLS (BearSSL) potrzebuje ciągłego bloku — w pętli heap bywa za ciasny (boot-attempt jest głównym
    // torem rejestracji na 8266); tu tylko fallback, gdy heap chwilowo urośnie ponad próg.
    uint32_t freeh = ESP.getFreeHeap(), blk = ESP.getMaxFreeBlockSize();
    if (freeh < HEAP_GATE_TLS || blk < MONITORS_HTTP_MIN_HEAP) {
        LOGW("selfreg", "heap gate: free=%uk blk=%uk — retry next cycle", freeh / 1024, blk / 1024);
        return;
    }
    self_register_attempt_now();
}
