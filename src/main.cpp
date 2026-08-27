// main.cpp — port ESP8266 z SENSMOS_Firmware.ino.
// Zmiany vs ESP32: BLE → captive portal (te same nazwy ble_*), brak esp_bt/esp_log/
// esp_task_wdt (watchdog = sprzętowy WDT 8266 + 120s self-check na millis()),
// Preferences → PrefsStore (LittleFS), MDNS.update() w loop.
#include "identity.h"
#include "ble_config.h"
#include "ota.h"
#include "wifi_manager.h"
#include "http_server.h"
#include "node_integration.h"
#include "entity_store.h"
#include "message_router.h"
#include "ws_client.h"
#include "data_sender.h"
#include "script_engine.h"
#include "ntp_time.h"
#include "serial_cmd.h"
#include "subscription_map.h"
#include "checknet.h"
#include "checknow.h"
#include "punch.h"
#include "monitors.h"
#include "net_worker.h"
#include "self_register.h"
#include "geolocation.h"
#include "tunnel.h"
#include "ws_tls.h"
#include "log.h"
#include "config.h"
#include <Preferences.h>
#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>

bool node_running = false;

// mDNS OOM guard state — patrz config.h MDNS_RETIRE_MS. Raz retired, nigdy z powrotem
// (runtime set_wifi reconnect re-otwiera responder — loop() zamyka go ponownie).
static bool s_mdns_retired = false;

// Flaga w NVS — przeżywa ESP.restart(). Ustawiana gdy WiFi nie połączyło: następny boot
// idzie prosto w portal. (Nazwa klucza "force_ble" zachowana dla ciągłości z ESP32.)
static bool boot_force_ble_get() {
    Preferences p; p.begin("sensmos", true);
    bool v = p.getBool("force_ble", false); p.end();
    return v;
}
static void boot_force_ble_set(bool v) {
    Preferences p; p.begin("sensmos", false);
    p.putBool("force_ble", v); p.end();
}

// ── Przycisk serwisowy (GPIO0) ────────────────────────────────
// Przytrzymaj 3s → tryb portal serwisowy; 10s → factory reset.
// wallet_bak (kopia portfela) NIE jest czyszczona — przeżywa reset.
static unsigned long s_btn_down_ms = 0;
static bool          s_btn_down    = false;
static int           s_btn_stage   = 0;  // 0 brak, 1 zapowiedź portalu, 2 zapowiedź resetu

static void button_tick() {
    bool down = (digitalRead(SERVICE_BUTTON_PIN) == LOW);
    unsigned long now = millis();

    if (down && !s_btn_down) {
        s_btn_down = true; s_btn_down_ms = now; s_btn_stage = 0;
    } else if (down && s_btn_down) {
        unsigned long held = now - s_btn_down_ms;
        if (held >= SERVICE_BTN_RESET_MS && s_btn_stage < 2) {
            s_btn_stage = 2;
            Serial.println(F("[BTN] >=10s - release for FACTORY RESET"));
        } else if (held >= SERVICE_BTN_BLE_MS && s_btn_stage < 1) {
            s_btn_stage = 1;
            Serial.println(F("[BTN] >=3s - release for portal mode"));
        }
    } else if (!down && s_btn_down) {
        unsigned long held = now - s_btn_down_ms;
        s_btn_down = false;
        if (held >= SERVICE_BTN_RESET_MS) {
            Serial.println(F("[BTN] FACTORY RESET"));
            Preferences p;
            p.begin("sensmos",      false); p.clear(); p.end();
            p.begin("sensmos_wifi", false); p.clear(); p.end();
            p.begin("sensmos_api",  false); p.clear(); p.end();
            // wallet_bak NIE czyszczone — kopia portfela przeżywa reset
            delay(300); ESP.restart();
        } else if (held >= SERVICE_BTN_BLE_MS) {
            Serial.println(F("[BTN] portal service mode"));
            boot_force_ble_set(true);
            delay(300); ESP.restart();
        }
    }
}

// ── Loop-stall self-check (zamiennik esp_task_wdt z ESP32) ────
// Sprzętowy WDT 8266 (~8s, karmiony przez delay/yield) łapie twarde zwisy.
// Do tego 120s self-check jak na ESP32: jeśli loop() nie obrócił się przez 120s
// (licznik czyszczony co obrót), sytuacji i tak nie ma jak obsłużyć w tym samym
// wątku — realne zabezpieczenie daje HW WDT; self-check loguje długie obroty.
static unsigned long s_loop_slowest = 0;
static void loop_health_tick() {
    static unsigned long s_last = 0;
    unsigned long now = millis();
    if (s_last) {
        unsigned long gap = now - s_last;
        if (gap > s_loop_slowest) s_loop_slowest = gap;
        if (gap > 5000) LOGW("loop", "slow pass: %lums (worst %lums)", gap, s_loop_slowest);
    }
    s_last = now;
}

void setup() {
    Serial.begin(115200);
    delay(500);
    LOGI("boot", "SENSMOS SmartNode v%s", FW_VERSION);
    LOGI("boot", "chip esp8266 @%uMHz flash %uMB",
         (unsigned)ESP.getCpuFreqMHz(), (unsigned)(ESP.getFlashChipRealSize() / (1024UL*1024UL)));

    // 8266: SDK trzyma creds WiFi we wlasnym obszarze flasha i auto-laczy sie do nich
    // JESZCZE PRZED setup(). Stary/nieaktualny wpis => stacja wisi w STATION_CONNECTING,
    // a nasze begin() nie ma szans dojsc do glosu. Wylacz jedno i drugie na starcie.
    WiFi.persistent(false);
    WiFi.setAutoConnect(false);

    pinMode(SERVICE_BUTTON_PIN, INPUT_PULLUP);

    ESP.wdtEnable(8000);   // SW WDT (HW WDT i tak czuwa); delay()/yield() karmią oba

    if (!identity_init()) {
        LOGE("boot", "identity init failed — halting"); while (true) delay(1000);
    }
    ble_load_config();  // wczytaj backend_url, owner itp. przed WiFi
    entity_store_init();
    sub_map_init();
    serial_cmd_init();
    ble_set_wifi_ready_cb(nullptr);  // nie używamy callbacku — restart zamiast

    // Owner skasował noda (BE przysłał podpisaną komendę WS „deleted") → boot prosto
    // w portal onboarding, TRZYMAJĄC tożsamość/klucze.
    if (node_deleted_get()) {
        LOGI("boot", "node deleted by owner — portal onboarding (identity kept)");
        ble_start();
        return;
    }

    // Wymuszony portal po nieudanym WiFi
    if (boot_force_ble_get()) {
        boot_force_ble_set(false);
        LOGI("boot", "forced portal mode (previous WiFi attempt failed)");
        ble_start();
        return;
    }

    if (wifi_has_config()) {
        // (ESP32 zwalniał tu pamięć kontrolera BT — na 8266 nie ma czego zwalniać)
        if (wifi_init()) {
            data_sender_init();
            self_register_init();
            http_server_init();
            portal_register_lan_routes();   // GET /node/reg-payload (payload rejestracyjny)
            ntp_init();
            LOGI("boot", "heap@post-ntp %uk free blk %uk", ESP.getFreeHeap()/1024, ESP.getMaxFreeBlockSize()/1024);
            ws_client_init();
            LOGI("boot", "heap@post-ws %uk free blk %uk", ESP.getFreeHeap()/1024, ESP.getMaxFreeBlockSize()/1024);
            // One-time self-registration here, in the high-heap boot window (~17k free): BearSSL TLS
            // needs ~9k contiguous and the steady-state loop heap (~10k / ~9k block) is too tight.
            self_register_boot_attempt();
            geoloc_boot_attempt();   // plain-HTTP IP geolocation — same window, no TLS cost
            if (ntp_synced()) data_sender_fetch_entities();
            script_engine_init();
            node_integration_init();
            message_router_init();
            checknet_init();
            monitors_init();
            net_worker_init();   // po traceroute_init (w checknet_init) — worker używa traceroute
            ota_init();
            tunnel_init();       // czyta tylko flagę NVS; RAM dopiero przy tun_open
            // mDNS OOM guard: na zarejestrowanym nodzie discovery jest zbędne — retire PRZED
            // ws-connect burstem, który zbija heap (patrz config.h MDNS_RETIRE_MS).
            {
                Preferences p; p.begin("sensmos", true);
                bool regd = p.getBool("reg_done", false); p.end();
                if (regd) {
                    MDNS.close(); s_mdns_retired = true;
                    LOGI("mdns", "retired at boot (registered node — OOM guard)");
                }
            }
            LOGI("boot", "ready — heap %uk free, blk %uk",
                 ESP.getFreeHeap() / 1024, ESP.getMaxFreeBlockSize() / 1024);
            // (env TLS: wolfSSL jest teraz trwałym transportem wss:// w ws_client —
            //  jednorazowy PoC ws_tls_run_poc_test() usunięty; otwierałby DRUGĄ sesję TLS.)
            node_running = true;
            watchdog_start();  // nieaktywny jeśli node_confirmed=true w NVS
        } else {
            // WiFi nie działa (złe creds / router down) — restart w czysty tryb portalu.
            LOGW("boot", "WiFi failed — restarting into portal mode");
            boot_force_ble_set(true);
            delay(1000);
            ESP.restart();
        }
    } else {
        LOGI("boot", "new device — portal provisioning");
        ble_start();
    }
}

void loop() {
    loop_health_tick();
    log_heap_sample();   // frag floor (min largest-block) — pokazywany w [health]
    serial_cmd_tick();
    button_tick();
    watchdog_tick();
    if (node_running) {
        wifi_maintain();     // reconnect po zerwaniu WiFi + reboot gdy długo down
        if (!s_mdns_retired) {
            if (millis() > MDNS_RETIRE_MS) {   // koniec okna discovery (onboarding) — OOM guard
                MDNS.close(); s_mdns_retired = true;
                LOGI("mdns", "retired (discovery grace %lus elapsed)",
                     (unsigned long)(MDNS_RETIRE_MS / 1000));
            } else {
                MDNS.update();   // 8266: mDNS wymaga update() w loop (ESP32 nie)
            }
        } else if (MDNS.isRunning()) {
            MDNS.close();        // runtime set_wifi reconnect re-otworzył responder — retire ponownie
        }
        http_server_handle();
        ws_client_tick();
        ntp_tick();
        script_engine_tick();
        node_integration_update();
        data_sender_tick();
        self_register_tick();   // v0.2.0: node rejestruje sie sam w BE (raz)
        checknet_update();
        monitors_update();
        tunnel_tick();       // RemoteTerminal — no-op gdy tunel nieaktywny
        net_worker_tick();   // 8266: JEDEN job sieciowy na obrót (zamiast taska FreeRTOS)
        // Dispatch wyników z net_worker → właściwy moduł (single-writer: store tylko tu).
        NetResult nr;
        while (net_worker_poll(nr)) {
            if      (nr.src == NW_CHECKNET) checknet_on_net_result(nr);
            else if (nr.src == NW_MONITOR)  monitors_on_net_result(nr);
            else if (nr.src == NW_SCRIPT)   script_engine_on_net_result(nr);
            else if (nr.src == NW_PUNCH)    punch_on_net_result(nr);
            else if (nr.src == NW_CHECKNOW) checknow_on_net_result(nr);
            else if (nr.src == NW_INTEGRATION) node_integration_on_result(nr);
            else                            data_sender_on_net_result(nr);
        }
    }
    if (g_ble_active) ble_tick();
    ota_tick();
    delay(10);   // karmi HW+SW WDT
}
