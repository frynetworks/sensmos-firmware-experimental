#include "serial_cmd.h"
#include "data_sender.h"
#include "identity.h"
#include "ble_config.h"
#include "message_router.h"
#include "push_notify.h"
#include "wifi_manager.h"
#include "http_server.h"
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include "http_internal.h"
#include <Preferences.h>
#include <LittleFS.h>
#include "geolocation.h"
#include "log.h"

static String serial_buffer = "";

// ── Wyślij odpowiedź przez Serial (odpowiednik BLE notify) ────
static void serial_respond(const char* status, const char* cmd,
                           const char* msg = nullptr) {
    char resp[256];
    if (msg) {
        snprintf_P(resp, sizeof(resp),
            PSTR("{\"status\":\"%s\",\"cmd\":\"%s\",\"msg\":\"%s\"}"),
            status, cmd, msg);
    } else {
        snprintf_P(resp, sizeof(resp),
            PSTR("{\"status\":\"%s\",\"cmd\":\"%s\"}"), status, cmd);
    }
    Serial.printf_P(PSTR("[serial] %s\n"), resp);
}

// ── Obsługa register — wysyła do backendu ────────────────────
// Registration POST needs ~9k contiguous heap for BearSSL TLS, which is unavailable in steady-state
// operation (~10k free / ~9k block → OOM/WDT). So the serial `register` command PERSISTS the owner and
// reboots; the actual TLS POST runs in the high-heap boot window via self_register_boot_attempt()
// (setup(), after ws_client_init, ~17k free). sig_wallet/timestamp are dropped — the self_register
// contract (POST {message,pubkey,sig_esp}) does not require them.
static void do_register(const char* owner, const char* sig_wallet,
                        uint32_t timestamp) {
    (void)sig_wallet; (void)timestamp;
    if (strlen(g_backend_url) == 0) {
        serial_respond("error", "register", "no_backend_url"); return;
    }
    strncpy(g_owner_address, owner, sizeof(g_owner_address) - 1);
    Preferences prefs;
    prefs.begin("sensmos", false);
    prefs.putString("owner_addr", owner);
    prefs.remove("reg_done");      // force a fresh registration attempt on the next boot
    prefs.remove("reg_giveup");
    prefs.end();
    serial_respond("ok", "register", "owner_set_registering_on_restart");
    Serial.println(F("[serial] owner set — restarting to self-register at boot (high heap)"));
    delay(500);
    LittleFS.end();   // flush/unmount so the owner write is committed before the SDK restart
    delay(200);
    ESP.restart();
}

// ── Handlery komend (każdy dostaje doc + nazwę cmd) ──────────
static void cmd_set_wifi(JsonDocument& doc, const char* cmd) {
    const char* ssid = doc["ssid"];
    const char* pass = doc["password"];
    if (!ssid || strlen(ssid) == 0) {
        serial_respond("error", cmd, "no_ssid"); return;
    }
    wifi_save_config(ssid, pass ? pass : "");
    if (wifi_connect(ssid, pass ? pass : "")) {
        char resp[128];
        snprintf_P(resp, sizeof(resp),
            PSTR("{\"status\":\"ok\",\"cmd\":\"set_wifi\",\"ip\":\"%s\"}"),
            g_local_ip);
        Serial.printf_P(PSTR("[serial] %s\n"), resp);
    } else {
        serial_respond("error", cmd, "wifi_failed");
    }
}

static void cmd_set_backend(JsonDocument& doc, const char* cmd) {
    const char* url = doc["url"];
    if (!url || strlen(url) < 7) {
        serial_respond("error", cmd, "invalid_url"); return;
    }
    strncpy(g_backend_url, url, sizeof(g_backend_url) - 1);
    Preferences prefs;
    prefs.begin("sensmos", false);
    prefs.putString("backend_url", url);
    prefs.end();
    Serial.printf_P(PSTR("[serial] backend: %s\n"), g_backend_url);
    serial_respond("ok", cmd);
}

static void cmd_set_pin(JsonDocument& doc, const char* cmd) {
    const char* pin = doc["pin"];
    if (!pin || strlen(pin) < 4 || strlen(pin) > 15) {
        serial_respond("error", cmd, "pin_invalid_length"); return;
    }
    if (strcmp(pin, "123456") == 0 || strcmp(pin, "000000") == 0) {
        serial_respond("error", cmd, "pin_too_simple"); return;
    }
    { Preferences p; p.begin("sensmos", false);
      p.putString("ble_pin", pin); p.end(); }
    serial_respond("ok", cmd);
}

static void cmd_register(JsonDocument& doc, const char* cmd) {
    const char* owner      = doc["owner"];
    const char* sig_wallet = doc["sig_wallet"] | "";
    uint32_t    timestamp  = doc["timestamp"]  | 0;
    if (!owner || strlen(owner) != 42) {
        serial_respond("error", cmd, "invalid_owner"); return;
    }
    do_register(owner, sig_wallet, timestamp);
}

static void cmd_unregister(JsonDocument& doc, const char* cmd) {
    const char* owner = doc["owner"];
    if (!owner || strcmp(owner, g_owner_address) != 0) {
        serial_respond("error", cmd, "owner_mismatch"); return;
    }
    memset(g_owner_address, 0, sizeof(g_owner_address));
    Preferences prefs;
    prefs.begin("sensmos", false);
    prefs.remove("owner_addr");
    prefs.end();
    serial_respond("ok", cmd);
    Serial.println(F("[serial] node unregistered"));
}

static void cmd_get_info(JsonDocument& doc, const char* cmd) {
    char pubkey_hex[131];
    identity_get_pubkey_hex(pubkey_hex, sizeof(pubkey_hex));
    char resp[600];
    snprintf_P(resp, sizeof(resp),
        PSTR("{\"status\":\"ok\",\"cmd\":\"get_info\","
        "\"device_id\":\"%s\","
        "\"eth_address\":\"%s\","
        "\"owner_address\":\"%s\","
        "\"ip\":\"%s\","
        "\"backend\":\"%s\","
        "\"pubkey\":\"%.32s...\","
        "\"registered\":%s,"
        "\"firmware\":\"" FW_VERSION "\"}"),
        g_device_id, g_eth_address, g_owner_address,
        g_local_ip,
        g_backend_url, pubkey_hex,
        strlen(g_owner_address) > 0 ? "true" : "false");
    Serial.printf_P(PSTR("[serial] %s\n"), resp);
}

static void cmd_get_token(JsonDocument& doc, const char* cmd) {
    char resp[128];
    snprintf_P(resp, sizeof(resp),
        PSTR("{\"status\":\"ok\",\"cmd\":\"get_token\",\"token\":\"%s\"}"),
        g_api_token);
    Serial.printf_P(PSTR("[serial] %s\n"), resp);
}

static void cmd_done(JsonDocument& doc, const char* cmd) {
    serial_respond("ok", cmd);
    Serial.println(F("[serial] session ended - restarting in 1s"));
    delay(1000);
    ESP.restart();
}

static void cmd_factory_reset(JsonDocument& doc, const char* cmd) {
    Serial.println(F("[serial] FACTORY RESET..."));
    Preferences prefs;
    prefs.begin("sensmos",      false); prefs.clear(); prefs.end();
    prefs.begin("sensmos_wifi", false); prefs.clear(); prefs.end();
    prefs.begin("sensmos_api",  false); prefs.clear(); prefs.end();
    Serial.println(F("[serial] NVS cleared. restarting in 3s"));
    delay(3000);
    ESP.restart();
}

static void cmd_help(JsonDocument& doc, const char* cmd) {
    Serial.println(F("\n[serial] JSON commands (same as BLE):"));
    Serial.println(F("  {\"cmd\":\"set_wifi\",\"ssid\":\"...\",\"password\":\"...\"}"));
    Serial.println(F("  {\"cmd\":\"set_backend\",\"url\":\"http://IP:3000/v1\"}"));
    Serial.println(F("  {\"cmd\":\"set_pin\",\"pin\":\"YourPin\"}"));
    Serial.println(F("  {\"cmd\":\"register\",\"owner\":\"0x...\",\"sig_wallet\":\"0x...\",\"timestamp\":123}"));
    Serial.println(F("  {\"cmd\":\"unregister\",\"owner\":\"0x...\"}"));
    Serial.println(F("  {\"cmd\":\"get_info\"}"));
    Serial.println(F("  {\"cmd\":\"get_token\"}"));
    Serial.println(F("  {\"cmd\":\"factory_reset\"}  <- serial only"));
    Serial.println(F("  {\"cmd\":\"help\"}            <- serial only\n"));
}

// ── Lokalizacja (geolocation.h — ns sensmos_loc, źródło-tagowana) ─────────────
static void cmd_get_location(JsonDocument& doc, const char* cmd) {
    char frag[160];
    if (!geoloc_get_json(frag, sizeof(frag))) {
        serial_respond("error", cmd, "no_location_stored");
        return;
    }
    char resp[224];
    snprintf_P(resp, sizeof(resp),
        PSTR("{\"status\":\"ok\",\"cmd\":\"get_location\",%s}"), frag);
    Serial.printf_P(PSTR("[serial] %s\n"), resp);
}

static void cmd_set_location(JsonDocument& doc, const char* cmd) {
    if (doc["clear"] | false) {
        geoloc_clear();
        serial_respond("ok", cmd, "location_cleared");
        return;
    }
    float lat = doc["lat"] | 999.0f;
    float lon = doc["lon"] | 999.0f;
    if (lat < -90.0f || lat > 90.0f || lon < -180.0f || lon > 180.0f ||
        (lat == 0.0f && lon == 0.0f)) {
        serial_respond("error", cmd, "invalid_coords");
        return;
    }
    uint32_t acc = doc["accuracy"] | 10;
    char latS[16], lonS[16];
    snprintf_P(latS, sizeof(latS), PSTR("%.6f"), (double)lat);
    snprintf_P(lonS, sizeof(lonS), PSTR("%.6f"), (double)lon);
    if (!geoloc_store(latS, lonS, acc, "manual", g_wifi_ssid)) {
        serial_respond("error", cmd, "store_failed");
        return;
    }
    LOGI("geo", "location set manually: lat=%s lon=%s accuracy=%um", latS, lonS, (unsigned)acc);
    serial_respond("ok", cmd);
}

static void cmd_get_message_config(JsonDocument& doc, const char* cmd) {
    String cfg = message_router_get_config_json();
    Serial.printf_P(PSTR("[serial] {\"status\":\"ok\",\"cmd\":\"%s\",%s}\n"),
        cmd, cfg.c_str());
}

static void cmd_set_push_token(JsonDocument& doc, const char* cmd) {
    const char* token = doc["token"] | "";
    if (strlen(token) < 10) {
        serial_respond("error", cmd, "invalid_token"); return;
    }
    push_set_token(token);
    serial_respond("ok", cmd);
}

static void cmd_get_push_token(JsonDocument& doc, const char* cmd) {
    char resp[256];
    snprintf_P(resp, sizeof(resp),
        PSTR("{\"status\":\"ok\",\"cmd\":\"get_push_token\","
        "\"available\":%s}"),
        push_available() ? "true" : "false");
    Serial.printf_P(PSTR("[serial] %s\n"), resp);
}

// ── Tablica dispatchu ─────────────────────────────────────────
typedef void (*cmd_handler_t)(JsonDocument&, const char*);
struct CmdEntry { const char* cmd; cmd_handler_t fn; };

static const CmdEntry CMD_TABLE[] = {
    { "set_wifi",        cmd_set_wifi },
    { "set_backend",     cmd_set_backend },
    { "set_pin",         cmd_set_pin },
    { "register",        cmd_register },
    { "unregister",      cmd_unregister },
    { "get_info",        cmd_get_info },
    { "get_token",       cmd_get_token },
    { "done",            cmd_done },
    { "factory_reset",   cmd_factory_reset },
    { "help",            cmd_help },
    { "get_webhook",     cmd_get_message_config },
    { "get_message_config", cmd_get_message_config },
    { "set_push_token",  cmd_set_push_token },
    { "get_push_token",  cmd_get_push_token },
    { "set_location",    cmd_set_location },
    { "get_location",    cmd_get_location },
};

// ── Główna funkcja — przetwarza JSON identyczny z BLE ────────
static void process_json(String json) {
    JsonDocument doc;
    if (deserializeJson(doc, json)) {
        Serial.println(F("[serial] JSON parse error"));
        return;
    }

    const char* cmd = doc["cmd"];
    if (!cmd) { Serial.println(F("[serial] missing 'cmd' field")); return; }

    for (const CmdEntry& e : CMD_TABLE) {
        if (strcmp(cmd, e.cmd) == 0) { e.fn(doc, cmd); return; }
    }
    serial_respond("error", cmd, "unknown_cmd");
}

void serial_cmd_init() {
    Serial.println(F("[serial] ready. type {\"cmd\":\"help\"} for commands."));
}

void serial_cmd_tick() {
    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') {
            if (serial_buffer.length() > 0) {
                process_json(serial_buffer);
                serial_buffer = "";
            }
        } else {
            serial_buffer += c;
            if (serial_buffer.length() > 512) serial_buffer = "";
        }
    }
}