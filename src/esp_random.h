#pragma once
// Shim: ESP32 <esp_random.h> → ESP8266 hardware RNG.
// Whitened RANDOM_REG32 reads (RF-noise fed). Same call surface as ESP-IDF.
#include "esp8266_compat.h"

static inline uint32_t esp_random(void) {
    // Two spaced reads XOR-folded with a cycle counter — cheap whitening.
    uint32_t a = RANDOM_REG32;
    uint32_t c = ESP.getCycleCount();
    uint32_t b = RANDOM_REG32;
    return a ^ ((b << 13) | (b >> 19)) ^ (c * 2654435761u);
}

static inline void esp_fill_random(void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    while (len) {
        uint32_t r = esp_random();
        size_t n = len < 4 ? len : 4;
        memcpy(p, &r, n);
        p += n; len -= n;
    }
}
