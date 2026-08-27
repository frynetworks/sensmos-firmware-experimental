#ifndef BLE_CONFIG_H
#define BLE_CONFIG_H
#include <Arduino.h>

// ── PORT ESP8266: BLE → CAPTIVE PORTAL ────────────────────────
// ESP8266 nie ma Bluetooth. Provisioning = softAP "SENSMOS-<id6>" + DNS catch-all +
// strona konfiguracyjna na 192.168.4.1 (captive_portal.cpp). Nagłówek i NAZWY funkcji
// zostają jak w wersji BLE (ble_start/ble_tick/...), żeby reszta firmware kompilowała
// się bez zmian — implementacja jest portalem, nie BLE.

extern bool g_ble_active;            // = portal aktywny
extern char g_owner_address[43];
extern char g_backend_url[128];

void ble_load_config();  // wczytaj config z NVS
void ble_start();        // start portalu (AP + DNS + HTTP)
void ble_set_wifi_ready_cb(void (*cb)());
void ble_stop();
void ble_tick();         // DNS + HTTP handleClient + timeouty (wołaj z loop())
void watchdog_start();
void watchdog_confirm();
void watchdog_tick();    // wywołuj z loop()

// Rejestracja tras portalu na GŁÓWNYM serwerze HTTP noda (po WiFi):
// GET /node/reg-payload — podpisany payload rejestracyjny (apka/operator wysyła go do BE,
// bo klient portalu nie ma internetu w trakcie provisioningu).
void portal_register_lan_routes();
#endif
