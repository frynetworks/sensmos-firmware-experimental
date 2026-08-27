/**
 * SENSMOS captive portal — port ESP8266 (zastępuje ble_config.cpp / NimBLE).
 *
 * Flow (protokół komend 1:1 z BLE, transport = HTTP na AP):
 *  1. Node bez configu → softAP "SENSMOS-<id6>" (open), IP 192.168.4.1, DNS catch-all.
 *  2. Telefon/laptop łączy się z AP; system wykrywa captive portal → strona formularza.
 *  3. Strona (JS) woła POST /api/cmd tymi samymi komendami co BLE:
 *     auth {pin} → {device_id, nonce}; [set_device_id]; register {owner, sig_wallet,
 *     backend_url, ssid, password} → {sig_esp, pubkey_esp, proof, ts}.
 *  4. RÓŻNICA vs BLE: klient portalu NIE MA internetu → nie może od razu POST-ować
 *     /v1/register do BE. Payload rejestracyjny jest PERSYSTOWANY (NVS "sensmos":
 *     reg_payload) i: (a) pokazany na stronie sukcesu (skopiuj), (b) dostępny po
 *     połączeniu z WiFi pod GET /node/reg-payload na LAN. [ZAŁOŻENIE PORTU]
 *  5. trust_round/trust_sign działają po HTTP; pole "ble_mac" atestu niesie MAC STA
 *     (8266 nie ma BT). Timing po WiFi ≈ dowód obecności/liveness, nie odległości.
 *     [ZAŁOŻENIE PORTU]
 *  6. Watchdog onboardingu (60 s na /node/confirm lub WS identify) — bez zmian.
 */
#include "ble_config.h"
#include "wifi_manager.h"
#include "geolocation.h"       // geoloc_store — lokalizacja z telefonu przez portal
#include "identity.h"
#include "log.h"
#include "http_internal.h"     // extern WebServer server (rejestracja trasy LAN po WiFi)
#include "config.h"            // DEFAULT_BACKEND_URL
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>
#include "esp_random.h"
#include "esp_mac.h"

// ── Watchdog ──────────────────────────────────────────────────
// 60 s po WiFi na potwierdzenie onboardingu, potem powrót do provisioningu. Potwierdzenie =
// lokalny POST /node/confirm od apki ALBO udany WS identify.
static unsigned long s_wdg_deadline = 0;
static bool          s_wdg_active   = false;
static bool          s_wdg_confirmed= false;

void watchdog_start() {
    Preferences p;
    p.begin("sensmos", true);
    bool already = p.getBool("node_confirmed", false);
    p.end();
    if (already) {
        s_wdg_active    = false;
        s_wdg_confirmed = true;
        LOGD("wdg", "node already confirmed — inactive");
        return;
    }
    s_wdg_deadline  = millis() + 60UL * 1000;
    s_wdg_active    = true;
    s_wdg_confirmed = false;
    LOGI("wdg", "armed — 60s for /node/confirm");
}
void watchdog_confirm() {
    if (s_wdg_confirmed) return;
    s_wdg_confirmed = true;
    Preferences p;
    p.begin("sensmos", false);
    p.putBool("node_confirmed", true);
    p.end();
    LOGI("wdg", "confirmed and saved");
}
void watchdog_tick() {
    if (!s_wdg_active || s_wdg_confirmed) return;
    if (millis() > s_wdg_deadline) {
        // Onboarding nie domknął się → wróć do provisioningu. TOŻSAMOŚĆ ZOSTAJE (jak ESP32).
        LOGW("wdg", "timeout - back to portal provisioning (identity kept)");
        Preferences p;
        p.begin("sensmos", false);
        p.remove("owner_addr");
        p.remove("node_confirmed");
        p.end();
        p.begin("sensmos_wifi", false); p.clear(); p.end();
        delay(500); ESP.restart();
    }
}

// ── Globals ───────────────────────────────────────────────────
bool g_ble_active       = false;
char g_owner_address[43]= {0};
char g_backend_url[128] = {0};

static void (*s_on_wifi_ready)() = nullptr;
void ble_set_wifi_ready_cb(void (*cb)()) { s_on_wifi_ready = cb; }

// ── Internal ──────────────────────────────────────────────────
static ESP8266WebServer* s_srv = nullptr;
static DNSServer*        s_dns = nullptr;
static bool   s_auth_ok      = false;
static bool   s_wifi_pending = false;
static char   s_pin[32]      = {0};
static char   s_nonce[65]    = {0};   // 32 bajty hex
static unsigned long s_portal_start_ms = 0;
static unsigned long s_restart_at_ms   = 0;   // opóźniony restart (odpowiedź HTTP musi wyjść)

// Trust ceremony — rundy challenge-response + podpis atestu (1:1 z BLE).
#define TRUST_MAX_ROUNDS 8
#define NVS_NS_WALLET "wallet_bak"
#define ROUNDS_BUF_LEN (TRUST_MAX_ROUNDS * 128 + 1)
static char* s_rounds_buf   = nullptr;
static int   s_rounds_count = 0;

// Duże bufory na HEAP (cont-stack loop() na 8266 ma tylko 4KB!)
union PortalBuf {
    struct { char resp[256]; } auth;
    struct { char message[256]; char sig_esp_hex[145]; char pubkey_hex[131];
             char proof_input[512]; char resp[700]; } reg;
    struct { char input[140]; } round;
    struct { char attest[480]; char sig_hex[145]; char pubkey_hex[131]; char resp[512]; } sign;
    struct { char resp[700]; } wallet;
};
static PortalBuf* s_buf_p = nullptr;
#define s_buf (*s_buf_p)

// Cache skanu WiFi (zebrany PRZED softAP — skan w trybie AP bywa zawodny).
// Lazy-calloc w ble_start() (−432B .bss) — zarejestrowany node nigdy nie wchodzi w portal,
// więc nie płaci ani .bss, ani heapu. Nigdy nie zwalniany (portal kończy się ESP.restart()).
#define SCAN_MAX 12
struct ScanEnt { char ssid[33]; int16_t rssi; };
static ScanEnt* s_scan = nullptr;
static int s_scan_n = 0;

// Rate limiter (1:1 z BLE)
static unsigned long s_req_times[10] = {0};
static int           s_req_idx = 0;
static bool rate_ok() {
    unsigned long now = millis();
    int n = 0;
    for (int i = 0; i < 10; i++)
        if (s_req_times[i] && now - s_req_times[i] < 60000) n++;
    s_req_times[s_req_idx++ % 10] = now;
    return n < 10;
}

// ── Helpers ───────────────────────────────────────────────────
static void send_json(const char* json) {
    if (s_srv) s_srv->send(200, "application/json", json);
    LOGD("portal", "-> %s", json);
}
static void send_ok(const char* cmd) {
    char b[64]; snprintf_P(b, sizeof(b), PSTR("{\"status\":\"ok\",\"cmd\":\"%s\"}"), cmd);
    send_json(b);
}
static void send_err(const char* cmd, const char* msg) {
    LOGW("portal", "reject cmd=%s: %s", cmd, msg);   // always-visible: onboarding failures self-explain on serial
    char b[96]; snprintf_P(b, sizeof(b), PSTR("{\"status\":\"error\",\"cmd\":\"%s\",\"msg\":\"%s\"}"), cmd, msg);
    send_json(b);
}

static void gen_nonce() {
    uint8_t rnd[32];
    esp_fill_random(rnd, 32);
    bytes_to_hex(rnd, 32, s_nonce);
}

static void load_config() {
    Preferences p; p.begin("sensmos", true);
    p.getString("ble_pin",     "").toCharArray(s_pin,           sizeof(s_pin));
    p.getString("owner_addr",  "").toCharArray(g_owner_address, sizeof(g_owner_address));
    p.getString("backend_url", "").toCharArray(g_backend_url,   sizeof(g_backend_url));
    p.end();
    if (!strlen(s_pin)) strcpy(s_pin, "123456");
    if (!strlen(g_backend_url)) strcpy(g_backend_url, DEFAULT_BACKEND_URL);
}
void ble_load_config() { load_config(); }

// ── Strona portalu (PROGMEM, <4KB, zero zewnętrznych zasobów) ─
static const char PORTAL_HTML[] PROGMEM = R"HTML(<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SENSMOS Setup</title><style>
body{font-family:-apple-system,sans-serif;margin:0;padding:16px;background:#0a0e27;color:#fff}
.c{max-width:400px;margin:24px auto}h1{font-size:22px;text-align:center}label{font-size:13px;display:block;margin-top:10px}
input,select{width:100%;padding:10px;margin:4px 0;border:1px solid #444;border-radius:4px;background:#1a1e37;color:#fff;font-size:15px;box-sizing:border-box}
button{width:100%;padding:12px;margin-top:14px;background:#00d9ff;color:#000;border:0;border-radius:4px;font-weight:bold;font-size:15px}
button:disabled{opacity:.5}.st{margin-top:14px;padding:10px;border-radius:4px;display:none;text-align:center}
.st.l{background:#1a1e37;display:block}.st.s{background:#00d944;color:#000;display:block}.st.e{background:#ff3b30;display:block}
.pl{background:#1a1e37;padding:10px;border-radius:4px;margin-top:10px;font-family:monospace;word-break:break-all;font-size:11px;max-height:180px;overflow-y:auto;display:none}
.pl.v{display:block}.cp{background:#666;color:#fff;padding:6px 10px;border:0;border-radius:3px;font-size:12px;margin-top:6px;width:auto}
</style></head><body><div class="c"><h1>SENSMOS Node Setup</h1><form id="f">
<label>PIN</label><input type="password" id="pin" value="123456">
<label>WiFi network</label><select id="ss"><option value="">Loading…</option></select>
<input type="text" id="sc" placeholder="…or type SSID manually">
<label>WiFi password</label><input type="password" id="pw">
<label>Owner wallet address (optional)</label><input type="text" id="ow" maxlength="42" placeholder="0x…">
<label>Device ID restore (optional, 64 hex)</label><input type="text" id="di" maxlength="64">
<button type="submit" id="go">Register &amp; connect</button></form>
<div class="st" id="m"></div><div class="pl" id="p"></div></div><script>
const $=i=>document.getElementById(i);const m=$('m'),p=$('p');
async function cmd(o){const r=await fetch('/api/cmd',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});return r.json()}
fetch('/api/scan').then(r=>r.json()).then(d=>{$('ss').innerHTML='<option value="">Select network</option>';(d.networks||[]).forEach(n=>{const o=document.createElement('option');o.value=n.ssid;o.textContent=n.ssid+' ('+n.rssi+' dBm)';$('ss').appendChild(o)})}).catch(()=>{});
$('f').addEventListener('submit',async e=>{e.preventDefault();$('go').disabled=true;m.textContent='Registering…';m.className='st l';p.className='pl';
try{const a=await cmd({cmd:'auth',pin:$('pin').value});if(a.status!=='ok')throw Error(a.msg||'auth failed');
if($('di').value){const d=await cmd({cmd:'set_device_id',id:$('di').value});if(d.status!=='ok')throw Error(d.msg||'set_device_id failed')}
const ssid=$('sc').value||$('ss').value;if(!ssid)throw Error('choose a WiFi network');
const ow=$('ow').value;if(ow&&(!ow.startsWith('0x')||ow.length!==42))throw Error('wallet must be 0x + 40 hex (or leave blank)');
const r=await cmd({cmd:'register',owner:ow,ssid:ssid,password:$('pw').value});
if(r.status!=='ok')throw Error(r.msg||'register failed');
m.textContent='Saved! Node restarts and joins your WiFi. Submit the payload below to the backend (also at http://<node-ip>/node/reg-payload).';m.className='st s';
p.textContent=JSON.stringify(r,null,1);p.className='pl v';
const b=document.createElement('button');b.textContent='Copy payload';b.className='cp';b.onclick=()=>navigator.clipboard.writeText(JSON.stringify(r));p.appendChild(b);
}catch(err){m.textContent=err.message;m.className='st e'}finally{$('go').disabled=false}});
</script></body></html>)HTML";

// ── Komendy (protokół 1:1 z ble_config.cpp; transport HTTP) ───
static void process_cmd(const char* body) {
    if (!rate_ok()) { send_err("?", "rate_limit"); return; }
    LOGD("portal", "<- (%d B)", (int)strlen(body));

    JsonDocument doc;
    if (deserializeJson(doc, body)) { send_err("?", "invalid_json"); return; }
    const char* cmd = doc["cmd"];
    if (!cmd) { send_err("?", "no_cmd"); return; }

    // ── factory_reset ────────────────────────────────────
    if (!strcmp(cmd, "factory_reset")) {
        send_ok(cmd);
        Preferences p;
        p.begin("sensmos",      false); p.clear(); p.end();
        p.begin("sensmos_wifi", false); p.clear(); p.end();
        p.begin("sensmos_api",  false); p.clear(); p.end();
        // wallet_bak NIE czyszczone — kopia portfela przeżywa reset
        s_restart_at_ms = millis() + 800;
        return;
    }

    // ── auth {pin} ────────────────────────────────────────
    if (!strcmp(cmd, "auth")) {
        const char* pin = doc["pin"];
        if (!pin) { send_err(cmd, "missing_pin"); return; }

        bool first;
        { Preferences p; p.begin("sensmos", true); first = !p.isKey("ble_pin"); p.end(); }

        if (first) {
            Preferences p; p.begin("sensmos", false);
            p.putString("ble_pin", pin); p.end();
            strncpy(s_pin, pin, sizeof(s_pin)-1);
        } else if (strcmp(pin, s_pin)) {
            send_err(cmd, "wrong_pin"); return;
        }

        s_auth_ok = true;
        gen_nonce();
        s_rounds_buf[0] = '\0';
        s_rounds_count  = 0;

        char* resp = s_buf.auth.resp;
        snprintf_P(resp, sizeof(s_buf.auth.resp),
            PSTR("{\"status\":\"ok\",\"cmd\":\"auth\","
            "\"device_id\":\"%s\",\"nonce\":\"%s\",\"first_time\":%s}"),
            g_device_id, s_nonce, first ? "true" : "false");
        send_json(resp);
        return;
    }

    if (!s_auth_ok) { send_err(cmd, "not_authenticated"); return; }

    // ── set_device_id {id} — odtworzenie ID po reflashu ──
    if (!strcmp(cmd, "set_device_id")) {
        const char* id = doc["id"];
        if (!id || !identity_set_override(id)) { send_err(cmd, "bad_id"); return; }
        char resp[160];
        snprintf_P(resp, sizeof(resp),
            PSTR("{\"status\":\"ok\",\"cmd\":\"set_device_id\",\"device_id\":\"%s\"}"),
            g_device_id);
        send_json(resp);
        return;
    }

    // ── register {ssid, password, [owner]} ──
    // v0.2.0: backend_url wkompilowany (DEFAULT_BACKEND_URL) — user go nie wpisuje.
    // owner/sig_wallet opcjonalne: bez portfela node rejestruje sie jako nieprzypisany.
    if (!strcmp(cmd, "register")) {
        const char* owner       = doc["owner"] | "";
        const char* ssid        = doc["ssid"];
        const char* password    = doc["password"] | "";

        // ssid opcjonalny: pusty + WiFi juz skonfigurowane => aktualizacja SAMEJ lokalizacji
        // (telefon ustawia GPS bez wpisywania hasla WiFi). Z ssid => pelne provisionowanie.
        bool have_ssid = ssid && strlen(ssid);
        LOGI("portal", "register recv: ssid=%s owner_len=%u lat/lon=%d",
             have_ssid ? ssid : "(none)", (unsigned)strlen(owner),
             (doc["lat"].is<float>() && doc["lon"].is<float>()) ? 1 : 0);
        if (!have_ssid && !wifi_has_config())        { send_err(cmd, "missing_ssid"); return; }
        if (strlen(owner) && strlen(owner) != 42)    { send_err(cmd, "bad_owner"); return; }

        strncpy(g_owner_address, owner,               sizeof(g_owner_address)-1);
        strncpy(g_backend_url,   DEFAULT_BACKEND_URL, sizeof(g_backend_url)-1);
        if (have_ssid) wifi_save_config(ssid, password);   // bez ssid: zostaja obecne creds
        optimistic_yield(1000);   // feed WDT: handler does 4 NVS namespaces + ECDSA. optimistic_yield
        // (NOT raw yield): NVS = flash writes with interrupts locked → can_yield()==false → raw yield panics.

        // Lokalizacja z telefonu (opcjonalna) — PO wifi_save_config, z KANONICZNYM
        // g_wifi_ssid (przycietym). geoloc_boot_attempt trzyma manualna lokalizacje tylko
        // gdy zapisany ssid == g_wifi_ssid po reboot'cie; uzycie surowego ssid z JSON
        // (nieprzyciety) grozilo niedopasowaniem → IP-geoloc nadpisywalby GPS telefonu.
        if (doc["lat"].is<float>() && doc["lon"].is<float>()) {
            float lat = doc["lat"] | 999.0f;
            float lon = doc["lon"] | 999.0f;
            if (lat >= -90.0f && lat <= 90.0f && lon >= -180.0f && lon <= 180.0f &&
                !(lat == 0.0f && lon == 0.0f)) {
                uint32_t acc = doc["acc"] | 10;
                char latS[16], lonS[16];
                snprintf_P(latS, sizeof(latS), PSTR("%.6f"), (double)lat);
                snprintf_P(lonS, sizeof(lonS), PSTR("%.6f"), (double)lon);
                if (geoloc_store(latS, lonS, acc, "manual", g_wifi_ssid))
                    LOGI("portal", "location set from phone: lat=%s lon=%s acc=%um",
                         latS, lonS, (unsigned)acc);
            }
            optimistic_yield(1000);
        }
        LOGI("portal", "config: backend=%s ssid=%s owner=%s", g_backend_url,
             have_ssid ? ssid : "(kept)", strlen(owner) ? owner : "(unclaimed)");

        Preferences p; p.begin("sensmos", false);
        p.putString("owner_addr",  owner);
        p.putString("backend_url", DEFAULT_BACKEND_URL);
        p.end();
        optimistic_yield(1000);

        // Challenge-Response — message podpisywany dokładnie jak w BLE
        char* message = s_buf.reg.message;
        snprintf_P(message, sizeof(s_buf.reg.message),
            PSTR("{\"device_id\":\"%s\",\"owner\":\"%s\",\"nonce\":\"%s\",\"ts\":0}"),
            g_device_id, owner, s_nonce);

        uint8_t msg_hash[32];
        sha256_string(message, msg_hash);
        optimistic_yield(1000);

        uint8_t sig_raw[72]; size_t sig_len = 0;
        char* sig_esp_hex = s_buf.reg.sig_esp_hex; sig_esp_hex[0] = 0;
        if (identity_sign(msg_hash, sig_raw, &sig_len)) {   // ECDSA secp256k1 — najdłuższy krok
            bytes_to_hex(sig_raw, sig_len, sig_esp_hex);
        }
        optimistic_yield(1000);

        char* pubkey_hex = s_buf.reg.pubkey_hex;
        identity_get_pubkey_hex(pubkey_hex, sizeof(s_buf.reg.pubkey_hex));

        // proof = sha256(nonce + sig_esp_hex + device_id)
        char* proof_input = s_buf.reg.proof_input;
        snprintf_P(proof_input, sizeof(s_buf.reg.proof_input), PSTR("%s%s%s"),
            s_nonce, sig_esp_hex, g_device_id);
        uint8_t proof_hash[32];
        sha256_string(proof_input, proof_hash);
        char proof_hex[65] = {0};
        bytes_to_hex(proof_hash, 32, proof_hex);

        char* resp = s_buf.reg.resp;
        snprintf_P(resp, sizeof(s_buf.reg.resp),
            PSTR("{\"status\":\"ok\",\"cmd\":\"register\","
            "\"sig_esp\":\"%s\",\"pubkey_esp\":\"%s\",\"proof\":\"%s\",\"ts\":%lu}"),
            sig_esp_hex, pubkey_hex, proof_hex, millis()/1000);

        // ZAŁOŻENIE PORTU: klient portalu nie ma internetu → payload rejestracyjny
        // persystowany; po WiFi dostępny pod GET /node/reg-payload (LAN).
        {
            // STATIC, not stack: a 900 B local here overflowed the ~4 KB cont stack —
            // the register path is already deep (handleClient → process_cmd) and the
            // Preferences/littlefs commit recurses (lfs_dir_orphaningcommit →
            // relocatingcommit → traverse), giving Exception(0) (illegal instruction,
            // corrupted return address) under the portal's low heap. Off-stacking this
            // buffer restores the headroom the littlefs commit needs. Handler is
            // single-request, so a function-static buffer is safe (not re-entrant).
            static char payload[900];
            snprintf_P(payload, sizeof(payload),
                PSTR("{\"message\":%s,\"sig_esp\":\"%s\",\"pubkey_esp\":\"%s\",\"proof\":\"%s\"}"),
                message, sig_esp_hex, pubkey_hex, proof_hex);
            Preferences pp; pp.begin("sensmos", false);
            pp.putString("reg_payload", payload);
            pp.end();
        }
        optimistic_yield(1000);

        LOGD("portal", "register resp: %d B", (int)strlen(resp));
        send_json(resp);
        s_wifi_pending = true;
        return;
    }

    // ── trust_round {c} ───────────────────────────────────
    if (!strcmp(cmd, "trust_round")) {
        const char* c = doc["c"];
        if (!c || strlen(c) < 16 || strlen(c) > 64) {
            send_err(cmd, "bad_challenge"); return;
        }
        if (s_rounds_count >= TRUST_MAX_ROUNDS) {
            send_err(cmd, "too_many_rounds"); return;
        }
        char* input = s_buf.round.input;
        snprintf_P(input, sizeof(s_buf.round.input), PSTR("%s%s"), c, g_device_id);
        uint8_t h[32];
        sha256_string(input, h);
        char r_hex[65];
        bytes_to_hex(h, 32, r_hex);
        size_t used = strlen(s_rounds_buf);
        snprintf_P(s_rounds_buf + used, ROUNDS_BUF_LEN - used, PSTR("%s%s"), c, r_hex);
        s_rounds_count++;
        char resp[128];
        snprintf_P(resp, sizeof(resp),
            PSTR("{\"status\":\"ok\",\"cmd\":\"trust_round\",\"r\":\"%s\",\"i\":%d}"),
            r_hex, s_rounds_count);
        send_json(resp);
        return;
    }

    // ── trust_sign {seed, owner, resume?, gps?} ───────────
    if (!strcmp(cmd, "trust_sign")) {
        const char* seed   = doc["seed"];
        const char* owner  = doc["owner"];
        bool        resume = doc["resume"] | false;
        if (!seed || strlen(seed) < 16 || strlen(seed) > 64) { send_err(cmd, "bad_seed"); return; }
        if (!owner || strlen(owner) < 20) { send_err(cmd, "missing_owner"); return; }

        uint8_t nrnd[8]; char nonce_hex[17];
        esp_fill_random(nrnd, 8);
        bytes_to_hex(nrnd, 8, nonce_hex);

        char rounds_hex[65];
        if (s_rounds_count > 0) {
            uint8_t rh[32];
            sha256_string(s_rounds_buf, rh);
            bytes_to_hex(rh, 32, rounds_hex);
        } else {
            strcpy(rounds_hex, "-");
        }

        // 8266: brak BT → pole "ble_mac" atestu niesie MAC STA [ZAŁOŻENIE PORTU]
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_BT);
        char ble_mac[18];
        snprintf_P(ble_mac, sizeof(ble_mac), PSTR("%02x:%02x:%02x:%02x:%02x:%02x"),
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        char efuse_mac[13];
        bytes_to_hex(mac, 6, efuse_mac);

        unsigned long up = millis() / 1000;

        const char* gps_lat = doc["gps_lat"] | "";
        const char* gps_lon = doc["gps_lon"] | "";
        bool has_gps = strlen(gps_lat) > 0 && strlen(gps_lon) > 0 &&
                       strlen(gps_lat) < 16 && strlen(gps_lon) < 16;

        char* attest = s_buf.sign.attest;
        if (has_gps) {
            snprintf_P(attest, sizeof(s_buf.sign.attest),
                PSTR("{\"v\":2,\"device_id\":\"%s\",\"owner\":\"%s\","
                "\"seed\":\"%s\",\"nonce\":\"%s\",\"ble_mac\":\"%s\","
                "\"efuse_mac\":\"%s\",\"rounds\":\"%s\",\"uptime_s\":%lu,"
                "\"gps_lat\":\"%s\",\"gps_lon\":\"%s\"}"),
                g_device_id, owner, seed, nonce_hex, ble_mac,
                efuse_mac, rounds_hex, up, gps_lat, gps_lon);
        } else {
            snprintf_P(attest, sizeof(s_buf.sign.attest),
                PSTR("{\"v\":1,\"device_id\":\"%s\",\"owner\":\"%s\","
                "\"seed\":\"%s\",\"nonce\":\"%s\",\"ble_mac\":\"%s\","
                "\"efuse_mac\":\"%s\",\"rounds\":\"%s\",\"uptime_s\":%lu}"),
                g_device_id, owner, seed, nonce_hex, ble_mac,
                efuse_mac, rounds_hex, up);
        }

        uint8_t ah[32];
        sha256_string(attest, ah);
        uint8_t sig_raw[72]; size_t sig_len = 0;
        char* sig_hex = s_buf.sign.sig_hex; sig_hex[0] = 0;
        if (!identity_sign(ah, sig_raw, &sig_len)) {
            send_err(cmd, "sign_failed"); return;
        }
        bytes_to_hex(sig_raw, sig_len, sig_hex);

        char* pubkey_hex = s_buf.sign.pubkey_hex;
        identity_get_pubkey_hex(pubkey_hex, sizeof(s_buf.sign.pubkey_hex));

        char* resp = s_buf.sign.resp;
        snprintf_P(resp, sizeof(s_buf.sign.resp),
            PSTR("{\"status\":\"ok\",\"cmd\":\"trust_sign\","
            "\"n\":\"%s\",\"bm\":\"%s\",\"em\":\"%s\",\"rd\":\"%s\","
            "\"up\":%lu,\"sig\":\"%s\",\"pk\":\"%s\",\"gv\":%d}"),
            nonce_hex, ble_mac, efuse_mac, rounds_hex, up,
            sig_hex, pubkey_hex, has_gps ? 2 : 1);

        LOGD("portal", "trust_sign: %d rounds, resp %d B%s",
            s_rounds_count, (int)strlen(resp), resume ? " (resume)" : "");

        s_rounds_buf[0] = '\0';
        s_rounds_count  = 0;

        send_json(resp);
        if (resume) s_wifi_pending = true;
        return;
    }

    // ── wallet_status ─────────────────────────────────────
    if (!strcmp(cmd, "wallet_status")) {
        Preferences p; p.begin(NVS_NS_WALLET, true);
        bool has = p.isKey("blob");
        String addr = p.getString("addr", "");
        p.end();
        char resp[180];
        snprintf_P(resp, sizeof(resp),
            PSTR("{\"status\":\"ok\",\"cmd\":\"wallet_status\","
            "\"has_backup\":%s,\"configured\":%s,\"addr\":\"%s\"}"),
            has ? "true" : "false",
            wifi_has_config() ? "true" : "false",
            addr.c_str());
        send_json(resp);
        return;
    }

    // ── wallet_backup {blob, addr} ────────────────────────
    if (!strcmp(cmd, "wallet_backup")) {
        const char* blob = doc["blob"];
        const char* addr = doc["addr"] | "";
        if (!blob || strlen(blob) < 16 || strlen(blob) > 600) {
            send_err(cmd, "bad_blob"); return;
        }
        Preferences p; p.begin(NVS_NS_WALLET, false);
        p.putString("blob", blob);
        p.putString("addr", addr);
        p.end();
        LOGI("portal", "wallet_backup saved (%d B, %.10s)", (int)strlen(blob), addr);
        send_ok(cmd);
        return;
    }

    // ── wallet_restore ────────────────────────────────────
    if (!strcmp(cmd, "wallet_restore")) {
        Preferences p; p.begin(NVS_NS_WALLET, true);
        String blob = p.getString("blob", "");
        String addr = p.getString("addr", "");
        p.end();
        if (blob.length() == 0) { send_err(cmd, "no_backup"); return; }
        char* resp = s_buf.wallet.resp;
        snprintf_P(resp, sizeof(s_buf.wallet.resp),
            PSTR("{\"status\":\"ok\",\"cmd\":\"wallet_restore\",\"blob\":\"%s\",\"addr\":\"%s\"}"),
            blob.c_str(), addr.c_str());
        send_json(resp);
        return;
    }

    // ── wifi_set {ssid, password} ─────────────────────────
    if (!strcmp(cmd, "wifi_set")) {
        const char* ssid = doc["ssid"];
        const char* password = doc["password"] | "";
        if (!ssid || !strlen(ssid)) { send_err(cmd, "missing_ssid"); return; }
        wifi_save_config(ssid, password);
        LOGI("portal", "WiFi changed: ssid=%s", ssid);
        send_ok(cmd);
        s_wifi_pending = true;
        return;
    }

    send_err(cmd, "unknown");
}

// ── Routes ────────────────────────────────────────────────────
static void handle_root() {
    s_srv->send_P(200, "text/html", PORTAL_HTML);
}
static void handle_captive_probe() {
    s_srv->sendHeader("Location", "http://192.168.4.1/", true);
    s_srv->send(302, "text/plain", "");
}
static void handle_scan() {
    String out = "{\"networks\":[";
    for (int i = 0; i < s_scan_n; i++) {
        if (i) out += ',';
        out += "{\"ssid\":\"";
        // proste escapowanie cudzysłowu/backslasha w SSID
        for (const char* c = s_scan[i].ssid; *c; c++) {
            if (*c == '"' || *c == '\\') out += '\\';
            out += *c;
        }
        out += "\",\"rssi\":";
        out += String((int)s_scan[i].rssi);
        out += '}';
    }
    out += "]}";
    s_srv->send(200, "application/json", out);
}
static void handle_cmd() {
    if (!s_srv->hasArg("plain")) { send_err("?", "no_body"); return; }
    process_cmd(s_srv->arg("plain").c_str());
}

// ── Public API (nazwy BLE zachowane — patrz ble_config.h) ─────
void ble_start() {
    if (g_ble_active) return;
    load_config();

    if (!s_buf_p)      s_buf_p      = (PortalBuf*)calloc(1, sizeof(PortalBuf));
    if (!s_rounds_buf) s_rounds_buf = (char*)calloc(1, ROUNDS_BUF_LEN);
    if (!s_scan)       s_scan       = (ScanEnt*)calloc(SCAN_MAX, sizeof(ScanEnt));
    if (!s_buf_p || !s_rounds_buf || !s_scan) { LOGE("portal", "buf alloc failed"); return; }

    // Pre-scan w STA ZANIM wstanie AP (skan w trybie AP bywa zawodny) → cache do pickera
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    int n = WiFi.scanNetworks(false, true);
    s_scan_n = 0;
    for (int i = 0; i < n && s_scan_n < SCAN_MAX; i++) {
        String ss = WiFi.SSID(i);
        if (!ss.length()) continue;                        // ukryte pomijamy w pickerze
        bool dup = false;
        for (int k = 0; k < s_scan_n; k++)
            if (!strcmp(s_scan[k].ssid, ss.c_str())) { dup = true; break; }
        if (dup) continue;
        strlcpy(s_scan[s_scan_n].ssid, ss.c_str(), sizeof(s_scan[0].ssid));
        s_scan[s_scan_n].rssi = (int16_t)WiFi.RSSI(i);
        s_scan_n++;
    }
    WiFi.scanDelete();
    LOGI("portal", "pre-scan: %d networks cached", s_scan_n);

    char name[24];
    snprintf_P(name, sizeof(name), PSTR("SENSMOS-%.6s"), g_device_id);

    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
    WiFi.softAP(name);                                     // open AP (jak BLE bez PIN na łączu)

    if (!s_dns) s_dns = new DNSServer();
    s_dns->setErrorReplyCode(DNSReplyCode::NoError);
    s_dns->start(53, "*", IPAddress(192,168,4,1));         // captive catch-all

    if (!s_srv) s_srv = new ESP8266WebServer(80);
    s_srv->on("/", HTTP_GET, handle_root);
    s_srv->on("/api/cmd",  HTTP_POST, handle_cmd);
    s_srv->on("/api/scan", HTTP_GET,  handle_scan);
    // Sondy captive-portal (Android/iOS/Windows) → redirect na formularz
    s_srv->on("/generate_204",        handle_captive_probe);
    s_srv->on("/gen_204",             handle_captive_probe);
    s_srv->on("/hotspot-detect.html", handle_captive_probe);
    s_srv->on("/connecttest.txt",     handle_captive_probe);
    s_srv->on("/ncsi.txt",            handle_captive_probe);
    s_srv->on("/fwlink",              handle_captive_probe);
    s_srv->on("/favicon.ico", []() { s_srv->send(204, "text/plain", ""); });
    s_srv->onNotFound(handle_captive_probe);
    s_srv->begin();

    g_ble_active     = true;
    s_wifi_pending   = false;
    s_auth_ok        = false;
    s_portal_start_ms = millis();
    s_restart_at_ms  = 0;
    LOGI("portal", "started: AP %s @ 192.168.4.1 — heap %uk free, blk %uk",
         name, ESP.getFreeHeap() / 1024, ESP.getMaxFreeBlockSize() / 1024);
}

void ble_stop() {
    if (!g_ble_active) return;
    if (s_srv) s_srv->stop();
    if (s_dns) s_dns->stop();
    WiFi.softAPdisconnect(true);
    g_ble_active = false;
    s_auth_ok    = false;
    LOGI("portal", "stopped");
}

void ble_tick() {
    if (!g_ble_active) return;

    // Portal-under-load HW WDT (rst cause:4): when a phone associates to the
    // SoftAP it floods captive-portal detection (a DNS burst + several parallel
    // TCP probes). The NONOS SDK/lwIP path servicing association+DHCP+DNS+TCP can
    // monopolise the CPU; handing the SDK more service windows per loop pass is
    // the only sketch-side lever. MUST use optimistic_yield(), NOT raw yield():
    // during the storm (and during the register handler's NVS flash writes) a
    // critical section is often active, so can_yield() is false and a raw yield()
    // aborts with `Panic core_esp8266_main.cpp __yield` (observed on device,
    // rst cause:2). optimistic_yield() checks can_yield()/critical-section
    // internally and no-ops when unsafe, so it feeds when it can and never panics.
    // With the register handler no longer crashing (optimistic_yield + off-stack
    // payload buffer, see below), these bounded yields keep the loop fed through
    // the storm — device-verified: full onboarding with no rst cause:4/2 crash.
    if (s_dns) {
        for (int i = 0; i < 8; i++) {   // drain the DNS burst, bounded + fed
            s_dns->processNextRequest();
            optimistic_yield(1000);
        }
    }
    optimistic_yield(1000);
    if (s_srv) s_srv->handleClient();
    optimistic_yield(1000);

    if (s_restart_at_ms && millis() > s_restart_at_ms) {   // factory_reset — po wysłaniu odpowiedzi
        delay(200); ESP.restart();
    }

    if (s_wifi_pending) {
        // Odpowiedź HTTP już wyszła (handleClient wyżej) — chwila na ACK TCP i restart w STA
        s_wifi_pending = false;
        LOGI("portal", "config saved — restarting into WiFi in 2s");
        delay(2000);
        ESP.restart();
        return;
    }

    // Tryb re-atestacji (force portal przy skonfigurowanym WiFi):
    // bez aktywności w 5 min → wróć do WiFi (jak BLE timeout na ESP32)
    if (wifi_has_config() && millis() - s_portal_start_ms > 300000UL) {
        LOGI("portal", "portal timeout — back to WiFi");
        delay(300);
        ESP.restart();
    }
}

// ── Trasa LAN po WiFi: podpisany payload rejestracyjny ────────
void portal_register_lan_routes() {
    server.on("/node/reg-payload", HTTP_GET, []() {
        Preferences p; p.begin("sensmos", true);
        String pl = p.getString("reg_payload", "");
        p.end();
        if (!pl.length()) { server.send(404, "application/json", "{\"error\":\"no_payload\"}"); return; }
        server.send(200, "application/json", pl);
    });
}
