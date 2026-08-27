#pragma once
/**
 * SENSMOS Firmware — Konfiguracja globalna
 * Wszystkie stałe kompilacji w jednym miejscu.
 */

// ── Script engine ─────────────────────────────────────────────
// TESTY: 30s. Docelowo (produkcja): 5000
// ── Backend ──────────────────────────────────────────────────
// Adres BE wkompilowany: user nie wpisuje go w portalu (v0.2.0). Nadal trafia do
// PrefsStore przy provisioningu, wiec ws_client/serial_cmd czytaja go jak dotad.
#define DEFAULT_BACKEND_URL  "https://api.sensmos.com/v1"

// ── Awaryjny adres statyczny (fallback DHCP) ─────────────────
// Zmierzone na sprzecie: sa AP, ktore poprawnie autoryzuja i asocjuja stacje, ale nie
// wydaja dzierzawy (station wisi w STATION_CONNECTING, brak eventu DHCP timeout).
// Wtedy zamiast restartu w kolko probujemy raz z adresem statycznym. 0 = wylaczone.
#define WIFI_STATIC_FALLBACK   1
#define WIFI_STATIC_IP         192,168,15,230
#define WIFI_STATIC_GW         192,168,1,1
#define WIFI_STATIC_MASK       255,255,240,0
#define WIFI_STATIC_DNS        192,168,1,1

// ── WiFi deep diagnostics (debug builds only; default OFF -> compiled out) ─────
// Ground-truth STA state every 500ms during the connect wait: raw wifi_get_ip_info(STATION_IF),
// SDK connect status, opmode, dhcpc/dhcps status, auto_connect readback, heap; netif walk + printDiag
// every 2s; a machine-parseable "[gate] WIFI_OK ip=..." marker the moment ANY source shows a station IP.
// Observer-effect safe: one pre-allocated static buffer, snprintf_P/PROGMEM, no String/heap in the hot path.
// Enable with -DWIFI_DEEP_DIAG=1 in platformio.ini build_flags. MUST default 0 in the shipping build.
#ifndef WIFI_DEEP_DIAG
#define WIFI_DEEP_DIAG 0
#endif

// ── mDNS lifecycle (OOM guard) ────────────────────────────────────────────────
// LEAmDNS parses incoming mDNS UDP in the lwIP RX callback (sys context) and allocates per
// answer record (observed panic: _readRRAnswer -> operator new, 288/540 B failing at ~4k free /
// 2-3k max block right after [ws] connected). Gating MDNS.update() cannot stop that — the parse
// runs on packet arrival, not in update(). The responder is therefore RETIRED (MDNS.close():
// UDP context freed, multicast groups left -> crash path unreachable) once LAN discovery is no
// longer needed: immediately at boot on a registered node, or after this grace window on an
// unregistered (onboarding) one.
#define MDNS_RETIRE_MS 120000   // onboarding discovery grace (unregistered nodes only)

// ── IP geolocation (device-local, supplementary — see geolocation.h) ──────────
// One PLAIN-HTTP call per network (ip-api.com free tier is HTTP-only, which conveniently avoids
// the BearSSL ~9k-contiguous TLS budget entirely). Runs in the setup() boot window; skipped when
// a fix for the current SSID is already stored, or when heap is unexpectedly low at call time.
// City-level accuracy only (~5-25 km) — recorded as GEOLOC_ACCURACY_IP_M.
#define GEOLOC_MIN_HEAP        8000    // free-heap gate for the boot-window HTTP call
#define GEOLOC_ACCURACY_IP_M   25000   // documented IP-geolocation accuracy bound (meters)

#define TICK_INTERVAL_MS     30000

#define MAX_DATASCRIPTS      3    // 8266: bylo 5 (ESP32)    // skrypty z BE (align z limitem 5/node w BE)
#define MAX_USERSCRIPTS      1    // 8266: bylo 2 (ESP32)    // skrypty usera (NVS)
#define MAX_SCRIPTS          (MAX_DATASCRIPTS + MAX_USERSCRIPTS)
#define MAX_STEPS            4    // kroków per skrypt
#define MAX_EXPR_LEN         48
#define MAX_ID_LEN           20
#define MAX_ENTITY_LEN       28
#define MAX_DATA_LEN         96   // url itp.

// ── Entity store ──────────────────────────────────────────────
#define ENTITY_PUB_MAX       10   // 8266: bylo 16 (ESP32) — .bss   // telemetria NET poszla do mon[] (mon-split), wiec pub[] znowu ma zapas:
                                  // realny node ma max 9 sensorow nie-NET. 40 przekraczalo TX_SCRATCH_LEN
                                  // (~3365B > 3072) = CICHY drop calego batcha.
#define ENTITY_MON_MAX        8   // 8266: bylo 12 (ESP32)   // telemetria NET (mon.*) — zamkniety zbior 11 encji, 12 = zapas
#define ENTITY_OWN_MAX        8   // 8266: bylo 16 (ESP32)
#define ENTITY_TMP_MAX        4   // 8266: bylo 8 (ESP32)
#define ENTITY_POOL_MAX      8    // 8266: bylo 16 (ESP32); sub.* rzadko >8   // sub.* — bylo 64 (7.4KB); 16 starcza, heap dla TLS/monitorow
                                  // (uwaga: >16 sub.* subskrypcji -> ten sam flapping co pub; sticky w HA 0.4.11 maskuje)
// own.* nieodświeżone przez ten czas są usuwane z bufora (anty „wiszące" encje).
// Musi być > cyklu odświeżania źródła (HA pushuje ~5 min). 0 = wyłączone.
#define OWN_TTL_S          1800

// ── Message router ────────────────────────────────────────────
#define MAX_MESSAGE_SLOTS     2   // 8266: bylo 3 (ESP32)

// ── Przycisk serwisowy ────────────────────────────────────────
// BOOT/GPIO0 (active LOW, INPUT_PULLUP). 3s→tryb BLE serwisowy, 10s→factory reset.
// Zmień na inny GPIO jeśli Twoja płytka ma dedykowany przycisk.
#define SERVICE_BUTTON_PIN     0
#define SERVICE_BTN_BLE_MS     3000
#define SERVICE_BTN_RESET_MS  10000

// ── WebSocket ─────────────────────────────────────────────────
// Od 2026-08-24 SENSMOS_USE_TLS jest zdefiniowane w SHIPPINGOWYM buildzie (platformio.ini)
// — transport to wss:// przez wolfSSL (WsTlsClient, pinning ISRG Root X2, ~2.9KB rezydenta),
// a ponizszy downgrade plaintext jest WYLACZONY na stale (gate w ws_client.cpp:
// `#if WS_PLAINTEXT && !defined(SENSMOS_USE_TLS)`). WS_PLAINTEXT zostaje jako szczatkowy
// przelacznik dla hipotetycznego builda bez TLS-a. ws_enc (szyfrowanie aplikacyjne
// ECDH+AES-GCM) dziala bez zmian — TLS to warstwa NIZEJ.
#define WS_PLAINTEXT          1
#define WS_PLAINTEXT_PORT     80

// ── HTTP server (node) ────────────────────────────────────────
#define INBOX_SIZE            3   // 8266: bylo 6 (ESP32) — inbox ~356B/slot
#define NODE_LOG_SIZE         6   // 8266: bylo 12 (ESP32)

// ── Timeouty HTTP (ms) ────────────────────────────────────────
#define HTTP_TIMEOUT_WEBHOOK   3000
#define HTTP_TIMEOUT_FETCH     4000
#define HTTP_TIMEOUT_BACKEND   8000
#define HTTP_TIMEOUT_QUERY    10000

// ── Fetch (akcja skryptu, wykonywana na net_worker) ───────────
#define FETCH_BODY_LIMIT     4096   // 8266: bylo 8192 (ESP32)   // max body w RAM

// ── Data sender ───────────────────────────────────────────────
#define BATCH_MIN_INTERVAL_MS   (1UL * 60 * 1000)   // min odstęp między batchami
#define BATCH_FORCE_INTERVAL_MS (3UL * 60 * 1000)   // wymuszony batch
#define MON_INTERVAL_MS         (3UL * 60 * 1000)   // ramka telemetrii NET; checknet i tak liczy co ~600s

// ── checknet (sondy jakości internetu) ────────────────────────
#define CHECKNET_MAX_JOBS          4      // 8266: bylo 6 (ESP32) — CnJob/CnResult ~0.25KB/slot      // ile jobów na cykl (BE wysyła max 6: 2 cele + 4 peery)
#define CHECKNET_PING_COUNT        5      // pakietów ICMP na pomiar (jitter/loss)
#define CHECKNET_PING_TIMEOUT_MS   1000   // timeout jednego pakietu
#define CHECKNET_PING_INTERVAL_MS  200    // odstęp między pakietami
#define CHECKNET_ASSIGN_TIMEOUT_MS 10000  // ile czekać na check_jobs z BE

// checknet w RDZENIU (v0.28+): sam napędza cykl, kadencję nadpisuje BE przez cn_config.
// Poniższe to TYLKO fallback offline — BE stroi interwał adaptacyjnie wg rozmiaru floty.
#define CHECKNET_ENABLED_DEFAULT       true
#define CHECKNET_INTERVAL_MS_DEFAULT   600000UL  // 10 min — konserwatywny fallback (anty-stampede)
#define CHECKNET_JITTER_MS             20000UL   // ±20s losowy rozrzut per node (anty thundering-herd)
#define CHECKNET_START_DELAY_MS        45000UL   // nie odpalaj tuż po boot (WS/NTP/batch najpierw)

// ── R3 monitory kierowane (v0.30+): deskryptory z BE (monitor_set), persist NVS ──
// v0.40: pomiary na net_worker (nie blokują loop) → slotów 32, ale to tylko BEZPIECZNIK
// RAM (32×~0.4KB=12.6KB .bss). Realny limit steruje BE z metryki q_lag (admission/shed —
// ASYNC-QUEUE §10). Stare FW (<0.39, blokująca pętla) dostają od BE max 6.
#define MONITORS_MAX_SLOTS          6     // 8266: mniejszy .bss (bylo 16 na ESP32)     // bezpiecznik RAM (0.72: 24→16, ~2.3KB BSS); realną liczbę steruje BE (q_lag + workerSlots)
#define MONITORS_RING_MAX          20     // 8266: mniejszy .bss (bylo 40)     // próbki rtt do percentyli rollupu (per slot, uint16 ms)
#define MONITORS_START_DELAY_MS    60000UL // pierwszy pomiar po boot (WS/NTP najpierw)
// mbedTLS alokuje bufory in/out OSOBNO (po ~17KB) — nie potrzebuje 45KB jednym kawalkiem.
// 45000 bylo przestrzelone: fragmentacja (drobiazg pety w srodku regionu po TLS) regularnie
// zbija largest do ~38K, a sondy i tak dzialaly. 30K = 17K + margines na najgorszy podzial.
#define MONITORS_HTTP_MIN_HEAP      9000  // 8266: ciagly blok dla buforow BearSSL (MFLN 512)  // TLS wymaga ~34KB CIAGLEGO bloku (2x16.4KB in/out mbedTLS osobno)
#define TUNNEL_TLS_RESERVE          6000  // 8266: rezerwa nad progiem TLS przy aktywnym tunelu  // gdy tunel aktywny — dodatkowa rezerwa nad progiem TLS (ochrona sesji terminalowej)
// 0.71 — UNIWERSALNA bramka RAM wora (gate na TOTAL free, nie tylko blok — to byla dziura 0.70 OOM).
// Jeden WiFiClientSecure GET zjada ~50KB TOTALU; nie startuj joba, jesli po jego szczycie zostaloby
// za malo dla loop()/WebServer (crash: WebServer `new` na wyczerpanym heapie → bad_alloc → terminate).
#define HEAP_GATE_TLS              15000  // 8266: BearSSL MFLN 512 ~9KB peak + ~6KB zapasu na loop/WS/WebServer
                                          // (zmierzone na sprzecie: ~17KB wolnego heapu w trybie portalu)
#define HEAP_GATE_MED              12000  // 8266: trace pbufy/rdns  // trace: pbufy/rdns
#define HEAP_GATE_LIGHT             8000  // 8266: icmp/tcp/dns/punch/scan  // icmp/tcp/dns/punch/stun/scan: kilka KB + zapas

// ── Trace (v0.37) ─────────────────────────────────────────────
#define TRACE_COOLDOWN_MS   600000UL  // ten sam cel nie jest re-trace'owany przez 10 min
#define TRACE_COOLDOWN_SLOTS 10       // rolling lista ostatnio trace'owanych celi

// ── Async net worker ("wór", v0.39+) — DOCS/dev/ASYNC-QUEUE.md ─
// Jeden task na core 1 serializuje CALA prace sieciowa (checknet+monitory): zawsze
// max 1 TLS naraz (heap-safe), a loop() nie blokuje sie na sondach. Stos zmierzony
// spikiem: TLS GET zjada ~3.7KB → 8KB z zapasem na podpisywane requesty.
#define NET_WORKER_STACK    8192
#define NET_JOBQ_DEPTH      4         // per kolejka (hi=monitory, lo=checknet+skrypty); NetJob ~0.6KB →
                                      // 16 slotów było ~21KB heapu. Backpressure (retry przy pełnej)
                                      // jest u WSZYSTKICH callerów, więc 8 wystarcza (RAM-AUDIT 0.49).
#define NET_RESQ_DEPTH      4
#define NET_COLLECT_TIMEOUT_MS 60000UL // checknet: awaryjny limit zebrania wynikow cyklu
// Skrypty na worze (v0.39, ASYNC-QUEUE §8): krok sieciowy zawiesza skrypt, wynik wznawia
// od kroku+1. Timeout = awaryjne wznowienie jako fail (zgubiony wynik nie wiesza skryptu).
#define NET_AWAIT_TIMEOUT_MS       20000UL
#define SCRIPT_NET_COOLDOWN_MIN_S  60     // min cooldown akcji sieciowych (defensywnie; BE też tnie)

// ── Zewnętrzne sondy (checknow/monitor/fetch): widzieć stronę JAK BROWSER ──────
// UA: wiele serwerów odsyła śmieci/redirect nieznanemu klientowi (domyślny to "ESP32HTTPClient").
// Follow-redirects: goły 301 (kanonizacja www/https) bez tego kończył sondę na przekierowaniu —
// fałszywe "301" na check-now i zła strona do change-watchera. NIE dotyczy podpisanych wywołań do BE.
#define HTTP_PROBE_UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
#define HTTP_PROBE_REDIRECT_MAX 5

// ── OTA (v0.35+) ──────────────────────────────────────────────
#define OTA_CONFIRM_TIMEOUT_MS  300000UL  // brak WS w 5 min po aktualizacji -> rollback na stary slot

// traceroute last-hop robi teraz BE (serwerowy, peer_probes) — node nie dotyka raw-socketu.
