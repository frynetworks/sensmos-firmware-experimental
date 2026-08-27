#pragma once
// Samo-rejestracja noda (v0.2.0). Na ESP32 payload rejestracyjny wysyłała APKA
// (BLE → telefon → POST /v1/register). Klient portalu na 8266 nie ma internetu,
// więc po wejściu w tryb STA node rejestruje się SAM — ten sam kontrakt BE:
// POST {backend}/register {message, pubkey, sig_esp}.

void self_register_init();
void self_register_boot_attempt();   // one-shot at boot in the high-heap window (setup(), after ws_client_init)
void self_register_tick();   // wołaj z loop() w trybie node (po WiFi/NTP) — fallback tor rejestracji
