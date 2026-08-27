// ota.cpp — port ESP8266. Update.h (ESP32, dwa sloty OTA + rollback) → Updater (8266):
// nowy obraz zapisywany w wolnej przestrzeni flash NAD szkicem i podmieniany przy reboocie.
// ESP8266 NIE MA drugiego slotu → rollback po nieudanym boocie NIEMOŻLIWY (różnica
// zachowania udokumentowana w README); logika potwierdzenia przez WS zostaje.
#include "ota.h"
#include "config.h"
#include "identity.h"
#include "data_sender.h"   // FW_VERSION
#include "ws_client.h"
#include "ws_enc.h"        // komenda ota tylko przez szyfrowany kanał
#include "log.h"
#include "node_log.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>

#define OTA_CHIP "esp8266"

#define NVS_NS_OTA "sensmos_ota"

static bool          s_confirm_armed = false;
static unsigned long s_boot_ms       = 0;

// ── Pobierz bin i zapisz do wolnej przestrzeni flash ──────────
// sha256 liczony na streamie; commit (Update.end) DOPIERO po zgodności hasha.
static bool ota_download_flash(const char* url, const char* sha_expect) {
    WiFiClientSecure sec;
    WiFiClient       plain;
    HTTPClient       http;
    bool https = !strncmp(url, "https://", 8);
    if (https) {
        sec.setInsecure();
        sec.setBufferSizes(512, 512);   // MFLN — BearSSL mieści się w heapie 8266
        if (!http.begin(sec, url)) return false;
    } else {
        if (!http.begin(plain, url)) return false;
    }
    http.setTimeout(20000);

    int code = http.GET();
    if (code != 200) {
        LOGE("ota", "HTTP %d", code);
        http.end(); return false;
    }
    int len = http.getSize();
    if (len <= 0) { LOGE("ota", "no Content-Length"); http.end(); return false; }
    if (!Update.begin(len)) {
        LOGE("ota", "Update.begin failed (bin %dB too big for free space?)", len);
        http.end(); return false;
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);

    WiFiClient* s = http.getStreamPtr();
    uint8_t buf[2048];
    size_t done = 0;
    unsigned long last_data = millis(), last_log = 0;
    while (done < (size_t)len) {
        size_t av = s->available();
        if (av) {
            int r = s->readBytes(buf, av > sizeof(buf) ? sizeof(buf) : av);
            if (r <= 0) break;
            mbedtls_sha256_update(&sha, buf, r);
            if (Update.write(buf, r) != (size_t)r) {
                LOGE("ota", "write failed (err %d)", (int)Update.getError());
                Update.end(false); http.end(); return false;
            }
            done += r; last_data = millis();
            if (millis() - last_log > 3000) {
                LOGI("ota", "downloading %u/%d KB", done / 1024, len / 1024);
                last_log = millis();
            }
        } else {
            if (!s->connected()) break;
            if (millis() - last_data > 20000) { LOGW("ota", "stall 20s"); break; }
            delay(1);
        }
        yield();   // karmi WDT 8266 przy wolnym łączu
    }
    http.end();

    if (done != (size_t)len) {
        LOGE("ota", "incomplete download %u/%d", done, len);
        Update.end(false); return false;
    }
    uint8_t h[32]; char h_hex[65];
    mbedtls_sha256_finish(&sha, h);
    mbedtls_sha256_free(&sha);
    bytes_to_hex(h, 32, h_hex);
    if (strcasecmp(h_hex, sha_expect) != 0) {
        LOGE("ota", "sha256 mismatch (got %.16s want %.16s) — rejected", h_hex, sha_expect);
        Update.end(false); return false;
    }
    if (!Update.end(true)) {
        LOGE("ota", "Update.end failed (err %d)", (int)Update.getError());
        return false;
    }
    return true;
}

// ── Handler WS "ota" ──────────────────────────────────────────
// Autentyczność komendy = zaszyfrowana ramka (tag GCM). Integralność binarki = sha256 na streamie.
void ota_handle(JsonDocument& doc) {
    if (!ws_enc_active()) { LOGW("ota", "cmd outside encryption — rejected"); return; }
    const char* version = doc["version"] | "";
    JsonObject  t       = doc["targets"][OTA_CHIP];
    if (t.isNull()) { LOGD("ota", "no target for %s — ignored", OTA_CHIP); return; }
    const char* url     = t["url"]    | "";
    const char* sha     = t["sha256"] | "";
    if (!*version || !*url || strlen(sha) != 64) {
        LOGW("ota", "incomplete message — rejected");
        node_log_push("ota", "incomplete msg — rejected", false); return;
    }
    if (!strcmp(version, FW_VERSION)) { LOGD("ota", "already on %s — ignored", version); return; }

    LOGI("ota", "%s -> %s", FW_VERSION, version);
    node_log_push("ota", version, true);   // start pobierania
    if (!ota_download_flash(url, sha)) {
        LOGE("ota", "failed — staying on %s", FW_VERSION);
        node_log_push("ota", "download/flash FAILED (space? http?)", false); return; }

    Preferences p; p.begin(NVS_NS_OTA, false);
    p.putString("pending", version);
    p.end();
    LOGI("ota", "ok — restarting into %s", version);
    delay(500);
    ESP.restart();
}

// ── Potwierdzenie po boocie ───────────────────────────────────
// 8266: rollback NIEMOŻLIWY (jeden slot). Flaga pending służy tylko diagnostyce —
// brak WS po aktualizacji jest logowany, node zostaje na nowej wersji.
void ota_init() {
    Preferences p; p.begin(NVS_NS_OTA, true);
    String pend = p.getString("pending", "");
    p.end();
    if (!pend.length()) return;
    if (pend == FW_VERSION) {
        s_confirm_armed = true;
        s_boot_ms = millis();
        LOGI("ota", "first boot %s — awaiting WS (%lus; NO rollback on 8266)",
             FW_VERSION, OTA_CONFIRM_TIMEOUT_MS / 1000UL);
    } else {
        Preferences w; w.begin(NVS_NS_OTA, false); w.remove("pending"); w.end();
        LOGW("ota", "boot %s with pending=%s — flag cleared", FW_VERSION, pend.c_str());
    }
}

void ota_tick() {
    if (!s_confirm_armed) return;
    if (ws_client_connected()) {
        s_confirm_armed = false;
        Preferences p; p.begin(NVS_NS_OTA, false); p.remove("pending"); p.end();
        LOGI("ota", "%s confirmed (WS online)", FW_VERSION);
        return;
    }
    if (millis() - s_boot_ms > OTA_CONFIRM_TIMEOUT_MS) {
        s_confirm_armed = false;
        Preferences p; p.begin(NVS_NS_OTA, false); p.remove("pending"); p.end();
        // ESP32 robił tu Update.rollBack(); na 8266 nie ma drugiego slotu.
        LOGE("ota", "no WS after update — ROLLBACK IMPOSSIBLE on ESP8266, staying on %s", FW_VERSION);
        node_log_push("ota", "no WS post-update; no rollback (8266)", false);
    }
}
