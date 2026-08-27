#pragma once
// ESP8266 compatibility layer — sensmos-esp8266 port.
// Maps the ESP32-isms used by upstream sensmos-firmware onto the ESP8266 Arduino core.
#include <Arduino.h>
#include <ESP8266WiFi.h>

extern "C" {
#include <user_interface.h>   // wifi_get_macaddr, system_get_*
}

// Hardware RNG register (documented in ESP8266 TRM; fed by RF noise).
#ifndef RANDOM_REG32
#define RANDOM_REG32 (*(volatile uint32_t*)0x3FF20E44)
#endif

// ESP.getMaxFreeBlockSize() (ESP32) → largest free block on ESP8266.
#define COMPAT_MAX_ALLOC_HEAP() (ESP.getMaxFreeBlockSize())

// configTzTime(tz, s1, s2, s3): the ESP8266 core exposes the same functionality
// as configTime(const char* tz, ...) since core 2.7.
#ifndef configTzTime
#define configTzTime configTime
#endif

// Chip info used by ws_client identify — no getChipModel/getChipRevision on ESP8266.
static inline const char* compat_chip_model() { return "ESP8266"; }
static inline int compat_chip_revision() { return 0; }
