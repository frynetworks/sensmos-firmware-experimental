# Bug: ESP.wdtEnable(ms) argument silently ignored — SW WDT fixed at ~3.2 s

Prepared for filing against `esp8266/Arduino`. All evidence collected on real hardware.

## Environment

- ESP8266 Arduino core **3.1.2** (`ARDUINO_ESP8266_RELEASE "3.1.2"`,
  PlatformIO `framework-arduinoespressif8266 3.30102.0`)
- Board: NodeMCU v2 (ESP-12E), 160 MHz, NONOS SDK 2.2.x

## Problem

`ESP.wdtEnable(uint32_t timeout_ms)` accepts a timeout argument and silently discards
it. The software watchdog period is fixed (~3.2 s observed) regardless of the value
passed. Nothing in the API surface hints the parameter is dead.

## Core source (cores/esp8266/Esp.cpp:94-115, verbatim)

```cpp
void EspClass::wdtEnable(uint32_t timeout_ms)
{
    (void) timeout_ms;
    /// This API can only be called if software watchdog is stopped
    system_soft_wdt_restart();
}

void EspClass::wdtEnable(WDTO_t timeout_ms)
{
    wdtEnable((uint32_t) timeout_ms);
}

void EspClass::wdtDisable(void)
{
    /// Please don't stop software watchdog too long (less than 6 seconds),
    /// otherwise it will trigger hardware watchdog reset.
    system_soft_wdt_stop();
}
```

`Esp.h` declares `static void wdtEnable(uint32_t timeout_ms = 0);` — a defaulted,
typed parameter that is `(void)`-cast in the implementation.

## On-device evidence

Firmware called `ESP.wdtEnable(8000)` at boot, then ran a CPU-bound TLS P-384
certificate verification (no `yield()`/`delay()` inside the math). Serial capture:

```
[   9888ms] [tls] handshake starting: api.sensmos.com:443
[  12008ms] [wolfd] wolfSSL Entering ProcessPeerCerts
[  15375ms] Soft WDT reset
[  15793ms]  ets Jan  8 2013,rst cause:2, boot mode:(3,6)
```

`ProcessPeerCerts` → `Soft WDT reset` = **3,367 ms**, not the requested 8,000 ms.
Reproduced in a loop (3 identical cycles per capture).

## Expected behavior

Either honor the requested timeout, or document/deprecate the parameter (e.g. emit a
compile-time deprecation on the `uint32_t` overload) so users don't build timing
assumptions on it.

## Impact + workaround

Code performing legitimately long uninterruptible computation (TLS handshakes with
P-384 chains on this hardware class) cannot extend the SW WDT and must bracket with
`ESP.wdtDisable()` / `ESP.wdtEnable(...)`, relying on the hardware WDT as backstop.

## Related documentation mismatch

The `wdtDisable` comment says exceeding ~6 s without the SW WDT "will trigger hardware
watchdog reset" — on this hardware the HW WDT consistently fired at **~8.2-8.4 s**
(`rst cause:4` captured at 8,218 ms into a compute stretch). Minor, but the 6 s figure
appears conservative/stale.
