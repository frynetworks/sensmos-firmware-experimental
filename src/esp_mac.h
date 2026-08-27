#pragma once
// Shim: ESP32 <esp_mac.h> → ESP8266. Only the calls upstream uses.
#include "esp8266_compat.h"

typedef enum { ESP_MAC_WIFI_STA = 0, ESP_MAC_BT = 1 } esp_mac_type_t;

// BT MAC does not exist on ESP8266 — both types return the STA MAC.
// (Attestation "ble_mac" field carries the softAP/STA MAC — logged port assumption.)
static inline int esp_read_mac(uint8_t* mac, esp_mac_type_t type) {
    (void)type;
    wifi_get_macaddr(STATION_IF, mac);
    return 0;
}
