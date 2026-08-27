# Sensmos — ESP8266 Firmware Port

An **ESP8266MOD port** of the Sensmos DePIN sensor-node firmware.

> Based on **[Galusz/sensmos-firmware](https://github.com/Galusz/sensmos-firmware)** (ESP32, Arduino).
> All protocol design, module architecture and node logic are the upstream project's work.
> This repository only adapts that firmware to the ESP8266 (no Bluetooth, single core, ~80 KB RAM)
> and is offered back to the Sensmos project.

Sensmos is a DePIN sensor network: nodes measure the real world, publish to a shared map, trade
data peer-to-peer, and earn the GALU token. The network powers
[UpFromWhere](https://upfromwhere.com). See [sensmos.com](https://sensmos.com).

## Status

| | |
|---|---|
| Version | `0.1.0-esp8266` |
| Build | `pio run` — clean (Flash 62.8 % of 1 MB, RAM 69.2 % static) |
| Hardware | flashed and boot-verified on real ESP8266 (ESP-12 / FT232R, 4 MB flash) |
| Boot QA | 2 consecutive boots, no exceptions / WDT resets, ~17 KB free heap in portal mode |
| Over-the-air portal test | **not** run by the porting harness — see [Onboarding](#onboarding) |
| Upstream sync | verified current with Galusz/sensmos-firmware:main — 0 commits behind (GitHub compare API, `ahead_by:0`) as of the commits already merged into this fork's history |

## Onboarding

ESP8266 has no Bluetooth. Onboarding uses a captive portal instead of the Sensmos mobile app's
BLE flow:

1. Power on the node — it creates a WiFi AP named `SENSMOS-xxxxxx`
2. Connect your phone/laptop to that AP
3. Open a browser — the setup page loads automatically (or navigate to 192.168.4.1)
4. Enter your WiFi credentials, backend URL, and owner wallet address
5. Submit — the node saves config, restarts, and connects to your WiFi

The `register` command also accepts an optional **`lat`/`lon`** pair (the onboarding phone's
GPS), so the app can set the node's location during provisioning. When present it is stored via
the same path as the serial `set_location` command, tagged with the WiFi SSID being provisioned
so the boot-time IP-geolocation does not overwrite it. `ssid` is optional: if omitted while the
node already has WiFi configured, `register` updates only the location (a phone can re-set the
node's position without re-entering the WiFi password).

The Sensmos mobile app (`frynetworks/sensmos-app`) now has a **WiFi Portal** onboarding path
that drives exactly this: it joins the node's SoftAP, `auth`s with the portal PIN, and POSTs
`register` with the home WiFi credentials plus the phone GPS.

### Registration payload

In the BLE flow the phone keeps its own internet connection, so it can POST the signed
registration to the backend immediately. A phone joined to the node's AP **has no internet**, so
the node instead:

* returns the signed payload (`message`, `sig_esp`, `pubkey_esp`, `proof`) on the portal success
  page, with a copy button, and
* persists it, serving it after the node joins your WiFi at `GET http://<node-ip>/node/reg-payload`.

Submit that payload to the Sensmos backend to complete registration. The signed bytes are
identical to the BLE flow's.

## What changed versus upstream

| Area | Upstream (ESP32) | This port (ESP8266) |
|---|---|---|
| Provisioning | BLE GATT (NimBLE), `ble_config.cpp` | Captive portal — softAP + DNS catch-all + HTTP form (`captive_portal.cpp`); same JSON command set (`auth`, `set_device_id`, `register`, `trust_round`, `trust_sign`, `wallet_*`, `wifi_set`, `factory_reset`) |
| Crypto | mbedTLS ECDSA/ECDH/GCM | [micro-ecc](https://github.com/kmackay/micro-ecc) (secp256k1, RFC6979-style deterministic k) + BearSSL (SHA-256, HMAC, AES-128-GCM). **Wire format unchanged**: DER signatures, same HKDF salt/info, same `[ver|seq|tag|ct]` frame |
| Storage | NVS via `Preferences` | LittleFS-backed `PrefsStore` with the same API and the same namespaces/keys (binary values base64-encoded) |
| Async work | FreeRTOS `net_worker` task + queues | Cooperative `net_worker_tick()` — static ring buffers, one job per `loop()` pass |
| Remote terminal | FreeRTOS task + 4 queues | Single-context tick pump; TCP-window backpressure preserved (reads only what it can forward) |
| ICMP / traceroute | `esp_ping` + lwIP raw pcb via `tcpip_callback` | One shared lwIP raw pcb, called directly (NONOS has no tcpip thread); `icmp_ping()` replaces `esp_ping` |
| OTA | dual slot + `Update.rollBack()` | `Updater` single slot — **no rollback**; the post-update WS confirmation is kept and logs when it fails |
| Watchdog | `esp_task_wdt` (120 s) | ESP8266 HW/SW WDT fed from `loop()` + slow-pass logging |
| WiFi region | `esp_wifi_set_country` | NONOS `wifi_set_country` (channels 1–13) |
| Log/format strings | `.rodata` in flash | `PSTR`/`printf_P` — on ESP8266 `.rodata` lives in DRAM, so literals would otherwise eat the heap |
| Buffer sizing | tuned for ~150 KB heap | entity pools, monitor slots, inbox, job queues and TX scratch retuned for ~25 KB; heap gates rescaled to BearSSL's footprint |

Everything else — entity store, script engine, message router, monitors, checknet, punch/STUN,
subscriptions, HTTP API, NTP, node log — is the upstream logic with mechanical include/API swaps.

## Hardware

ESP8266MOD boards with 4 MB flash: NodeMCU v2 / v3, ESP-12E, ESP-12F, Wemos D1 mini.
Flash layout `eagle.flash.4m1m` (1 MB sketch, 1 MB LittleFS). Service button on GPIO0
(3 s → portal mode, 10 s → factory reset), as upstream.

## Build & flash

```bash
pip install platformio          # or: uv tool install platformio
pio run                         # build
pio run -t upload --upload-port COM12   # flash (use your port)
pio device monitor -b 115200    # serial log
```

## Layout

```
src/
  main.cpp             entry point (ported from SENSMOS_Firmware.ino)
  captive_portal.cpp   provisioning portal (replaces ble_config.cpp)
  identity.cpp         secp256k1 keypair, DER signing (micro-ecc + BearSSL)
  ws_enc.cpp           ECDH + HKDF + AES-128-GCM WS channel
  prefs_store.*        Preferences-compatible LittleFS store
  net_worker.cpp       cooperative network job executor
  traceroute.cpp       lwIP raw ICMP: traceroute + ping
  esp8266_compat.h     ESP32→ESP8266 shims (RNG, MAC, heap, chip info)
  WiFi.h WebServer.h HTTPClient.h Preferences.h ESPmDNS.h Update.h mbedtls/
                       header shims so upstream modules compile unchanged
  ws_tls.*             wolfSSL TLS PoC — gated behind SENSMOS_USE_TLS, see below
  …                    upstream modules (entity store, scripts, monitors, HTTP API, …)
tools/
  gate_heap.py          heap-gate serial harness — see Measured performance
  patch_wolfssl_settings.py
                        pre-build hook for the nodemcuv2_tls env (see TLS upgrade path)
```

## Known limitations

* **No OTA rollback** — the ESP8266 has a single sketch slot.
* **TLS is heap-gated.** BearSSL with MFLN needs ~9 KB; jobs defer when the heap is below the
  gate, so HTTPS fetches/monitors run less aggressively than on ESP32.
* **Attestation timing.** `trust_round`/`trust_sign` run over the AP's HTTP transport; the
  attestation's `ble_mac` field carries the station MAC. Treat the timing as a liveness/proximity
  signal (the client must join the node's AP), not as the BLE timing channel.
* Over-the-air portal interaction was verified structurally (routes, page size, DNS catch-all) and
  by compile + hardware boot; the browser flow itself is a manual test.
* **Portal onboarding under association load — fixed & device-verified (2026-08-25).** When a phone
  associates to the SoftAP and POSTs `register`, the handler ran heavy work (four NVS namespace
  writes + a secp256k1 ECDSA sign) synchronously inside `handleClient()` under the portal's low heap
  (~19 KB) and the SDK's association storm. Three distinct crashes were traced and fixed:
    1. **`rst cause:4` (HW WDT, ~19 s)** — the register handler over-ran the ~8.4 s hardware WDT under
       load. The `ble_tick` serving path now drains DNS in a bounded loop and yields around
       `handleClient()`, and the handler completes fast enough once the crashes below are gone.
    2. **`Panic core_esp8266_main.cpp __yield` (`rst cause:2`)** — the register-path and `ble_tick`
       `yield()`s fired while a critical section was active (an NVS flash write, or the WiFi MAC
       storm), so `can_yield()` was false and raw `yield()` aborts. Fixed by using `optimistic_yield()`
       everywhere in the portal, which checks `can_yield()` internally and no-ops when unsafe.
    3. **`Exception(0)` (illegal instruction, `rst cause:2`)** — a 900 B `payload` stack local, on top
       of the deep `handleClient → process_cmd` chain and the recursive littlefs directory commit
       (`lfs_dir_orphaningcommit → relocatingcommit → traverse`), overflowed the ~4 KB cont stack and
       corrupted a return address. Fixed by moving that buffer to `.bss` (`static`).
  **Verified end-to-end on hardware (S22 → node):** association storm → `register` accepted with the
  phone's GPS → clean reboot to STA → `DHCP` → `wss://` TLS 1.3 handshake (cert-pinned ISRG Root YE)
  → worker running, with **zero** crash markers across a 160 s capture and steady heap (~19 KB at
  `ready`, ~13 KB under wss + a worker pass — above the 3 KB OOM floor).

### Ghost-session resilience (2026-08-25)

The backend retains a WS session for a device_id for ~35 s after an unclean close and withholds
the `identified` reply to a reconnecting node until the old session is reaped. Two fixes:

* **Prevention — clean close before reboot.** Reboot-bearing teardowns (`on_reboot`, `on_deleted`)
  now call `ws_client_graceful_close()` (a WebSocket close frame, code 1000) before `ESP.restart()`
  — a hard reset runs no destructors, so without this the server never sees a close and keeps the
  session. (WiFi-loss / boot-failure reboots are excluded: the link is already down, so no close
  frame can be sent.)
* **Recovery — identify timeout.** There was no application-level timeout on the `identified`
  reply; the protocol heartbeat stays green even when the backend withholds it, so a node could
  wait forever with `ws=down`. `ws_client_tick()` now tracks the identify send time and, if no
  `identified` arrives within a growing window (12 s → cap 36 s, covering the reap window), forces
  a reconnect for a fresh identify.

## ESP8266 Hardware Specifications & Memory Budget

A technical report on what the ESP8266 gives us, what this port achieved and measured, why the
60 KB free-heap guideline exists and when it applies, and the upgrade path if TLS is required.

### Hardware constraints

* Total user DRAM: **~80 KB** (81,920 B) — versus ~520 KB SRAM on the upstream ESP32 target.
* A bare WiFi sketch (SDK + WiFi stack, no application) leaves ~40–45 KB free.
* This firmware's static allocation (`.bss` + `.data` + `.rodata`): **~57 KB (69.3 %)**.
* What remains (~23 KB) covers the WiFi/lwIP runtime residents (~19 KB) plus every heap allocation.
* The allocator is umm_malloc (first-fit): **fragmentation matters** — `MaxFreeBlockSize` is the
  number that predicts allocation success, not total `FreeHeap`. The `[health]`/`[mem]` log lines
  report both, plus `getHeapFragmentation()`.
* No Bluetooth (unlike ESP32) — no BT/WiFi coexistence overhead.

### Why the 60 KB free-heap guideline applies to ESP32, not ESP8266

**On ESP32 (the upstream target), 60 KB free is the right rule.** With ~520 KB SRAM, a TLS
WebSocket (`wss://`) whose handshake spikes ~28 KB (≈22 KB BearSSL/mbedTLS buffers + ~6 KB
stack), and WiFi + Bluetooth coexistence reserving additional RAM, keeping 60 KB free ensures
the TLS spike never crashes the node while still leaving ~460 KB for the application. It is a
sound guideline in that context.

**On ESP8266, the same number is not applicable — the conditions it protects against don't
exist here:**

* 60 KB free out of 80 KB total would leave 20 KB for SDK + WiFi + application static — which
  alone consume ~57 KB. The number is unreachable by roughly a factor of three before the first
  `malloc`.
* This port runs **plaintext WS by design** (`WS_PLAINTEXT=1` in `config.h`) — the ~28 KB TLS
  handshake spike that motivates the ESP32 rule never happens on the WS path.
* The transport is not unprotected: every frame is already encrypted and authenticated at the
  **application layer** (ECDH + HKDF + AES-128-GCM, `ws_enc.cpp` — see below).
* No Bluetooth, single-purpose sensor workload — the overhead profile is fundamentally different.
* Industry reference points for production-stable ESP8266 firmware without TLS on the main
  connection: Tasmota runs at ~20–26 KB free, ESPHome targets >30 KB. This port's measured
  **~25 KB total addressable** free memory is inside that production-safe range.

**When 60 KB would become relevant here:** if full BearSSL TLS were mandated on the WS
connection, its ~28 KB handshake exceeds everything this chip can free — at that point the
hardware answer is an ESP32/ESP32-C3, and the software answer worth testing first is wolfSSL
(see the TLS upgrade path below).

### Measured performance (after optimization)

Numbers from bounded serial captures (`tools/gate_heap.py`) on real hardware (ESP-12, 160 MHz),
verified over 90–180 s windows with the node connected, encrypted, and acked by the backend:

| Metric | Before optimization | After optimization |
|---|---:|---:|
| DRAM steady-state free | ~5,120 B | ~12,288 B |
| DRAM max free block | ~4,096 B | ~11,264 B |
| DRAM heap fragmentation | not instrumented | 7 % |
| IRAM second heap free | 0 B | 12,520 B |
| **Total addressable free** | **~5,120 B** | **~24,800 B** |
| 180 s stability gate | PASS (floor 3000) | PASS (floor 6000, min 13,312) |
| WDT / OOM / crash events | 0 | 0 |

"Total addressable" = DRAM free + IRAM second heap. The IRAM heap requires 32-bit-aligned
access (byte access works via the core's non32xfer handler, at a cost); the allocations routed
there via `HeapSelectIram` are the net_worker job/result rings (~7.2 KB resident), the 4 KB
HTTP-fetch transient, and the ~3 KB tunnel session buffers — bulk, alignment-friendly, and
latency-tolerant.

### Optimizations applied

**Explicit in this port:**

* IRAM second heap — `PIO_FRAMEWORK_ARDUINO_MMU_CACHE16_IRAM48_SECHEAP_SHARED` (+12.5 KB IRAM
  heap; +7 KB steady DRAM from routing the buffers above)
* LWIP2 low-memory variant (`TCP_MSS=536`)
* MFLN 512 B buffers on the HTTPClient TLS shim (transient HTTPS fetches only)
* Fixed-scratch JSON serialization + **field-filtered parsing** of pre-encryption frames
  (the `identified` catalog reached 45 rich entity objects / 3,686 B — a full parse OOMs at the
  tightest point of the session; the filter keeps only the fields the firmware reads)
* `WEBSOCKETS_SAVE_RAM` (headers to flash, −476 B static) and `WEBSOCKETS_MAX_DATA_SIZE`
  capped 15 KB → 4 KB (2 KB was tested and rejected: it is smaller than the `identified` frame)
* 160 MHz CPU — no RAM-map change, but peak-memory windows (crypto/JSON/TLS fetches) close
  twice as fast, reducing fragmentation pressure
* `F()`/PROGMEM discipline — 262+ string literals in flash (on ESP8266 `.rodata` lives in DRAM)
* Entity/batch buffers retuned (batch 10 vs ESP32's 16), stack-scoped crypto contexts (zero
  resident heap for ECDH/AES-GCM), `WiFi.persistent(false)`, AP teardown after provisioning,
  mDNS responder retired at runtime (documented OOM guard)

**Framework defaults, verified active in this build:**

* `-Os`, `-ffunction-sections`, `-fdata-sections`, `--gc-sections`, `-fno-exceptions`
* `VTABLES_IN_FLASH`
* Extra 4 K heap (cont-stack overlap)

### Application-layer encryption (current state)

The sensmos protocol encrypts **all** data before it reaches the WebSocket:

* Key exchange: ECDH (secp256k1) — a per-session shared secret negotiated at connect time,
  expanded via HKDF-SHA256 with both peers' nonces.
* Payload protection: AES-128-GCM — authenticated encryption; every frame in both directions
  carries a GCM tag and an anti-replay sequence number.
* Implementation: `ws_enc.cpp` (micro-ecc + BearSSL primitives, stack-scoped contexts, zero
  resident heap). The backend's public key is a compiled constant.

So the payload is already encrypted and integrity-protected in transit, even over plaintext WS.
What application-layer crypto does **not** provide, and TLS would add: **server certificate
verification** (proving the node talks to the real sensmos backend rather than an impersonator
at the DNS/routing layer) and **protocol downgrade protection**.

### TLS upgrade path (if required)

From lightest to heaviest:

**Option 1 — current: plaintext WS + application-layer crypto (recommended on ESP8266).**
Zero memory overhead beyond the measured budget; production-safe at ~25 KB total addressable.
Missing: server certificate verification and downgrade protection. Appropriate while the WS
endpoint is trusted via DNS/infrastructure security.

**Option 2 — application-layer key pinning (lightest addition).**
The ECDH infrastructure already pins the backend's identity key as a compiled constant; this
option formalizes it — verify the server's session key material against the pinned backend
identity during the handshake, and optionally pin a hash of the backend's TLS certificate key
for out-of-band checks. Cost: ~32–64 B. Adds server authentication with no TLS stack at all.
Missing: record-layer protection and protocol negotiation.

**Option 3 — wolfSSL — THE SHIPPING TRANSPORT (2026-08-24): wss:// with cert-pinned VERIFY_PEER
is now the default `nodemcuv2` build.**
`SENSMOS_USE_TLS` moved into the shipping env: every flashed node connects to
`wss://api.sensmos.com:443/v1/ws` (nginx terminates TLS on the same `/v1/ws` route — verified
101 Switching Protocols) through `WsTlsClient` (`ws_tls.h`/`ws_tls.cpp`, a `WiFiClient`
subclass), verifies the server chain against a pinned CA, completes the app-layer identify/ECDH
handshake over TLS, and runs normally. `nodemcuv2_tls` remains as a legacy alias;
`nodemcuv2_diag` inherits TLS. Shipping build: **54,404 B RAM (66.4 %), 898,839 B flash
(86.1 %)**. `WS_PLAINTEXT` is vestigial (permanently overridden by `SENSMOS_USE_TLS`).

* **Certificate pinning (VERIFY_PEER):** the anchor is **ISRG Root YE** (Let's Encrypt's 2026
  P-384 intermediate hierarchy: leaf P-256 ← YE2 P-384 ← Root YE P-384 ← [X2-cross]), embedded
  DER in PROGMEM (`src/ca_cert.h`, 682 B) and loaded once with
  `WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY` (the load runs before NTP settles; peer-cert dates are
  still checked at every handshake). Three hard-won findings baked into the config:
  `WOLFSSL_ALT_CERT_CHAINS` (the server's chain ends with an X2-cross-signed-by-X1 cert wolfSSL
  would otherwise demand a signer for → −188), `WOLFSSL_SP_384` full-speed (generic-math P-384
  ECDSA verify returned −155 on every signature; and the `WOLFSSL_SP_SMALL` variant needed >6 s
  per verify → hardware-WDT reset loop — full SP does ~2.7 s), and the anchor deliberately
  placed at Root YE, not ISRG Root X2: each P-384 verify is ~2.7 s of uninterruptible compute
  and the ESP8266's HW WDT (~8.4 s, cannot be disabled) killed the 3-verify chain to X2; two
  verifies fit (~6.6 s total handshake). The SW WDT (fixed ~3.2 s — `wdtEnable`'s argument is
  ignored by the core) is disabled for the handshake window only. Not X1 either: its RSA-4096
  signature would force `SP_INT_BITS 4096` = +256 B on every bignum. Key exchange stays pinned
  to P-256 via `wolfSSL_CTX_set_groups` — `HAVE_ECC384` would otherwise advertise secp384r1 in
  key_share and P-384 keygen on generic math would repeat the old −125 OOM. Graceful
  degradation: if the CA can't load (malloc/format), the node logs `verify disabled (degraded)`
  and continues with VERIFY_NONE rather than bricking. Anchor expires 2032-09-02; on Let's
  Encrypt hierarchy rotation, re-extract the chain (`openssl s_client -showcerts`) and rebuild
  `ca_cert.h`.
* **TLS 1.3 session resumption (2026-08-24):** the transport saves the NewSessionTicket
  session at teardown (`wolfSSL_get1_session` inside `stop()`, before `wolfSSL_free` — the
  ONLY safe point: tickets arrive post-handshake, and an earlier save bumps the refcount so
  `SetTicket`'s `HaveUniqueSessionObj` forks the session and the saved handle stays
  ticketless forever) and restores it before the next `wolfSSL_connect`. **Measured
  on-device: full handshake 6,891 ms → resumed 865-883 ms (`resumed=1`), ~7.9× faster** —
  which matters for safety, not just latency: the full handshake's ~6.8 s of P-384 compute
  sits ~1.6 s under the non-disableable HW WDT, while a resumed handshake skips chain
  verification entirely. Five consecutive save/restore cycles showed flat heap (leak-free
  recycling); nginx issues a fresh ticket (2 NSTs, ~32 B each) per session. Config: the
  `NO_SESSION_CACHE` era is over — it compiled `get1_session/set_session` OUT; replaced by
  `HAVE_SESSION_TICKET` + micro-cache defines with the cache disabled at runtime
  (`WOLFSSL_SESS_CACHE_OFF`; net ~+24 B .bss). Two traps burned into the config comments:
  `NO_PSK` MUST stay (dropping it costs +1,538 B `ENCRYPT_LEN`), and `MAX_PSK_ID_LEN` MUST
  be capped (384) — the PSK identity buffers are gated `(HAVE_SESSION_TICKET || !NO_PSK)`,
  and the 1536 default silently added ~3.1 KB to every `ssl->arrays` + ~1.5 KB to the CTX,
  OOM-ing the first handshake. Session is RAM-only/single-boot (ticket age math uses the
  ms clock). Test hook: `-DSENSMOS_TEST_FORCE_RECONNECT` (via `PLATFORMIO_BUILD_FLAGS`)
  forces one disconnect 90 s post-handshake to exercise resumption; note the backend holds
  a ghost session ~35 s after an abrupt close and rejects re-identify until reaped — a
  pre-existing server behavior surfaced by the test, not a client bug.
* **Anchor rotation monitoring:** `tools/check_cert_expiry.py` (pre-build) parses the DER
  inside `src/ca_cert.h` and prints days-to-expiry every build — warning <180 days,
  error-banner <30 days (threshold override: `CERT_EXPIRY_WARN_DAYS` env). Root YE expires
  **2032-09-02**. Rotation procedure lives in `src/ca_cert.h` + `tools/gen_ca_cert_h.py`.
* **Upstream bug reports** (evidence-complete, ready to file):
  `docs/upstream-reports/wolfssl-p384-verify-xtensa.md` (generic-math P-384 ECDSA verify
  returns −155 on valid chains; SP_384 fixes it) and
  `docs/upstream-reports/esp8266-wdtenable-noop.md` (`ESP.wdtEnable(ms)` argument
  `(void)`-cast; SW WDT fixed ~3.2 s).
* **`WEBSOCKETS_MAX_DATA_SIZE=4096` finally works** — and the truth about it: the library
  hard-defines 15 KB with no `#ifndef` (WebSockets.h:66), so the `-D` flag had been silently
  clobbered since it was added; the effective inbound cap on every prior build was 15 KB. The
  patch script now wraps the define so the flag wins. This is **hardening, not a heap win**:
  the cap is a reject-before-malloc bound (the RX buffer is a per-frame `malloc(payloadLen)`,
  not a static allocation) — it limits the largest transient allocation a malicious or buggy
  peer can induce.
* **arduinoWebSockets 2.7.3 hard-codes its SSL class** (`WEBSOCKETS_NETWORK_SSL_CLASS
  WiFiClientSecure`, WebSockets.h:213, no `#ifndef` — `-D` overrides are silently clobbered)
  and `new`s it internally (`_client.tcp = _client.ssl`, so the SSL class must derive
  `WiFiClient`). Solved with `tools/patch_websockets_tls.py` (`pre:` script on the shipping
  env, same pattern as the wolfSSL config hook): it patches the *libdeps copy* of WebSockets.h
  to select `WsTlsClient` under `SENSMOS_USE_TLS` and to guard `MAX_DATA_SIZE`, injecting the
  header by absolute path (deliberately not `-Isrc` — `src/` carries `WiFi.h`/`HTTPClient.h`
  compat shims that would shadow library headers in every TU).
* **`WsTlsClient` details that matter:** all I/O rides the virtual `Client` interface (verified
  against the core headers); WiFiClient's zero-copy peek-buffer API is overridden OFF (it reads
  raw lwIP pbufs = ciphertext); BearSSL-named config calls (`setInsecure` — called twice by the
  library — `setFingerprint`, `setTrustAnchors`, `setClientRSACert`) are no-op stubs; the base
  `WiFiClient` IS the raw TCP socket, so the library's non-virtual `setNoDelay`/`setTimeout`
  land on the correct socket. One trap found live: `WiFiClient::connect(host,…)` resolves DNS
  and then calls the *virtual* `connect(IPAddress,…)` — a subclass override that routes back
  through the host path recurses infinitely; `WsTlsClient` resolves DNS itself and enters the
  base class only via qualified (non-virtual) calls.
* **WANT_READ retry fixed** (the known gap at the old ws_tls.cpp:128): the recv callback now
  returns `WANT_READ` immediately (no 5 s blocking spin — a persistent transport cannot stall
  `loop()`), and `wolfSSL_connect` runs in a bounded retry loop (30 s deadline, `delay(5)` +
  `yield()` per iteration, feeding both WDTs). Steady-state reads are fully non-blocking; record
  reassembly state lives in the wolfSSL session across `WANT_READ` returns.
* **Live results (COM12, real backend):** TLS handshake ~2.0-2.2 s negotiating
  **TLSv1.3 / TLS_AES_128_GCM_SHA256** (first on-device TLS 1.3 — the httpbin PoC negotiated
  1.2), WS upgrade + `identified+enc` (45 native entities) over TLS, geolocation push, checknet
  worker passes, heartbeat ping/pong sustained. **300 s stability run: zero reconnects, heap
  flat at 12 k free (min 9-10 k, all heap gates clear), fragmentation flat 15 %, IRAM second
  heap untouched.** Resident TLS session cost ≈ 2.9 KB DRAM vs the plaintext build (15 k → 12 k
  steady), exactly the PoC's measured session footprint. App-layer `ws_enc` (ECDH + AES-128-GCM)
  runs unchanged on top — TLS is transport-layer, independent of it.
* Certificate verification remains `WOLFSSL_VERIFY_NONE` (PoC posture) — pinning the backend
  cert is the production follow-up.

Historical build/bring-up findings (static-RAM shrink, rodata relocation, err −326, SP math)
below — all still accurate for the underlying wolfSSL port:

* **wolfSSL's `wolfssl/wolfssl` PlatformIO package (5.7.2) ships its own bundled
  `user_settings.h`, tuned for ESP-IDF/ESP32.** `wolfssl/wolfcrypt/settings.h` auto-defines
  `WOLFSSL_USER_SETTINGS` and quoted-`#include`s that bundled file itself — project-side `-D`
  build flags cannot override a `#define` inside a header included *after* them. Worked around
  with a PlatformIO `extra_scripts` pre-build hook (`tools/patch_wolfssl_settings.py`) that
  overwrites the package's copy with an ESP8266-Arduino-appropriate config before every build.
* **ESP8266 Arduino (NONOS SDK) has no BSD sockets layer.** wolfSSL's built-in socket I/O
  (`wolfio.h`) assumes one exists for any target named `ESP8266`, and needs `socklen_t` /
  `struct iovec` that don't exist here. Fixed with `WOLFSSL_USER_IO` + `WOLFSSL_NO_SOCK` and
  custom transport callbacks (`wolfSSL_CTX_SetIORecv`/`SetIOSend`) wired directly to
  `WiFiClient::read()`/`write()` — this part works cleanly.
* **The library compiles.** After the above, plus `NO_CRYPT_TEST`/`NO_CRYPT_BENCHMARK` (wolfSSL's
  own test/benchmark harnesses reference ESP-IDF-only `ESP_LOGE`/`sdkconfig.h` and don't apply
  here) and satisfying TLS 1.3's real prerequisites (`HAVE_HKDF`, `WC_RSA_PSS`), every wolfSSL
  source file builds without error against the ESP8266 Arduino toolchain.
* **It initially did not link.** In the maximally trimmed configuration — `NO_SESSION_CACHE`, a
  single ECC curve (`ECC_USER_CURVES` + `HAVE_ECC256` only), `RSA_LOW_MEM`, `NO_DH`,
  single-threaded, small-stack — the link failed: `.bss` overflowed the ESP8266's 80 KB
  `dram0_0_seg` by **1,488 bytes** on top of this firmware's then ~56.7 KB static baseline.
  wolfSSL's own *direct* `.bss` is trivial (~136–192 B); the overflow was cumulative image cost.
  **Resolved (2026-08-24) by freeing 2,664 B of static DRAM in the existing firmware** — four
  targeted edits, applied to both envs, shipping build improved from 56,736 B to 54,072 B (66.0 %):
  `monitors.cpp` status snapshot now reuses the shared `g_tx_scratch` TX buffer instead of its own
  576 B static (same loop-only single-writer pattern as `punch.cpp`/`tunnel.cpp`); `checknet.cpp`
  traceroute cooldown stores 4-byte FNV-1a host hashes instead of `char[46]` names (−440 B);
  `captive_portal.cpp` WiFi pre-scan cache became portal-only lazy-calloc (−432 B); and
  `node_integration.cpp` queue+batch moved into a lazy-calloc'd `NiState` allocated once at
  init/set_url only when an integration URL is configured (−1,227 B; unconfigured nodes pay
  nothing, and the buffer is never freed so the in-flight webhook body pointer stays valid).
* **Linking was necessary but not sufficient: the linked image reset-looped on boot.** With
  wolfSSL's **~26.1 KB of `.rodata` in DRAM** (this linker script places `.rodata` in
  `dram0_0_seg`), the TLS image's static footprint was 80,732 B — leaving ~1.2 KB of boot heap.
  The NONOS SDK OOMs before `setup()` even runs: 72 consecutive `rst cause:2` resets in a 180 s
  capture with zero readable output. **Fixed by relocating `libwolfssl.a`'s `.rodata` to flash**
  (`tools/relocate_wolfssl_rodata.py`, a TLS-env-only `post:` extra_script that patches the
  *generated* `$BUILD_DIR/ld/local.eagle.app.v6.common.ld`, adding
  `*libwolfssl.a:(.rodata .rodata.* .rodata1)` to the `.irom0.text` collection). Safe because this
  build's MMU config (`MMU_IRAM_HEAP`, NONOS SDK 2.2.x) already installs the non32xfer exception
  handler, so 8/16-bit reads from flash work — slowly, which is acceptable for a PoC measurement
  path. Result: TLS image DRAM static **80,732 → 54,616 B (66.5 %)**, boot heap ≈ 27 KB, on par
  with the shipping build. The shipping `nodemcuv2` env never loads this script and is untouched.
* **The first flashed build then failed its handshake with err −326 (record layer version
  error) — root-caused to a silent config gap, since fixed.** wolfSSL 5.7.2 gates BOTH the
  `supported_groups` and the TLS 1.3 `key_share` ClientHello extensions solely on
  `HAVE_SUPPORTED_CURVES` (no `#error` catches its absence), while still advertising
  `supported_versions: 1.3` — producing a ClientHello no server can complete TLS 1.3 against.
  httpbin.org answers with a TLS 1.2 ServerHello, and `wolfTLSv1_3_client_method()` (which sets
  `downgrade=0`) rejects that as −326. Three-part fix: (1) `HAVE_SUPPORTED_CURVES` added to the
  generated `user_settings.h`; (2) `wolfSSLv23_client_method()` in `ws_tls.cpp` — TLS 1.3-preferred
  with `downgrade=1`, floor clamped to TLS 1.2 via `NO_OLD_TLS`'s `WOLFSSL_MIN_DOWNGRADE`;
  (3) `WOLFSSL_HAVE_SP_ECC` + `WOLFSSL_HAVE_SP_RSA` + `WOLFSSL_SP_SMALL` — the generic `sp_int`
  backend sizes every bignum for RSA (≈1 KB each; an `ecc_point` embeds three), so the key_share
  P-256 keygen exceeded the free block transiently and died with −125/MEMORY_E
  (`EccMakeKey → ecc_make_pub_ex failed`, confirmed via a temporary `DEBUG_WOLFSSL` trace build);
  the dedicated SP routines use small fixed buffers and are far faster. Cost: +27.8 KB flash
  (82.8 % total), +0 B DRAM.
* **On-device `[tls-heap]` measurements — SUCCESSFUL handshake (nodemcuv2, 160 MHz):**

  | Stage | DRAM free | Max block | Frag | IRAM free | Δ vs baseline |
  |---|---:|---:|---:|---:|---:|
  | baseline (pre-wolfSSL) | 20,752 | 20,168 | 3 % | 12,520 | — |
  | post-wolfSSL_Init | 20,752 | 20,168 | 3 % | 12,520 | 0 |
  | post-CTX_new | 20,608 | 20,168 | 3 % | 12,520 | −144 |
  | post-config | 20,608 | 20,168 | 3 % | 12,520 | −144 |
  | pre-connect | 20,608 | 20,168 | 3 % | 12,520 | −144 |
  | post-tcp-connect | 20,224 | 20,056 | 1 % | 12,520 | −528 |
  | post-SSL_new | 17,864 | 17,784 | 1 % | 12,520 | −2,888 |
  | post-handshake-ok | 17,904 | 13,368 | 24 % | 12,520 | −2,848 |
  | steady-state | 17,904 | 13,368 | 24 % | 12,520 | −2,848 |
  | post-disconnect | 19,912 | 13,368 | 29 % | 12,520 | −840 |
  | post-cleanup | 20,528 | 13,368 | 28 % | 12,520 | −224 |

  **Handshake: PASS in ~1.28 s — `TLSv1.2`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, SNI on,
  `HTTP/1.1 200 OK` received** from `https://httpbin.org/get` (191 B read). The stage snapshots
  bound the *resident* cost; the transient keygen/handshake peak between snapshots is what the SP
  routines keep inside the free block (the max-block drop 17,784 → 13,368 with frag 24 % is the
  handshake churn's footprint). Post-cleanup recovers to within 224 B of baseline. IRAM (second
  heap) is untouched throughout — wolfSSL allocates purely from the DRAM heap (no XMALLOC/IRAM
  routing in this PoC).

**Conclusion: wolfSSL fits this port and completes a real TLS handshake against a public
endpoint.** Measured on-device cost: ~54 KB flash total (26.1 KB relocated `.rodata` + 27.8 KB SP
P-256/RSA-2048 code) + ~0.5 KB extra DRAM static vs the shipping build + **≈ 2.9 KB resident DRAM
heap for an open TLS session** (SSL object dominant), with handshake transients absorbed inside a
~17 KB free block and full recovery (−224 B) after cleanup. Handshake time ~1.28 s at 160 MHz.
The earlier conclusion that only ESP32-class hardware could host wolfSSL is superseded; the
remaining engineering for a production TLS WS transport is integration work (persistent session
handling, reconnect policy, coexistence with the ~10-11 k steady-state heap while a batch is in
flight), not feasibility. wolfSSL's published figures below remain useful context.

<details>
<summary>wolfSSL's published numbers (context, not achieved here)</summary>

* I/O buffers default to **128 B** (`RECORD_SIZE`) versus BearSSL's 16 KB RX default — the
  single biggest memory difference between the stacks, in principle.
* Per-session RAM: **1–36 KB depending on configuration** (buffer sizes, key algorithm, math
  library) — configurable toward the low end when both endpoints are controlled, as here.
* wolfSSL has demonstrated TLS 1.3 in 32 KB total RAM on an Arduino Nano 33 — a different chip
  with more headroom than the ESP8266 has after this firmware's own static allocation.
* `WOLFSSL_SMALL_STACK` (used in the PoC) cuts stack use from ~23–42 KB to ~2.1 KB, shifting that
  usage to the heap rather than eliminating it — irrelevant to the `.bss`/static-image overflow
  found here, which happens before any stack or heap accounting begins.
* Licensing: **GPLv2 / commercial dual license** — GPLv2 is free and compatible with an
  open-source deployment like this fork.

</details>

**Option 4 — BearSSL TLS on the WS path → requires ESP32-class hardware.**
BearSSL (the Arduino core's built-in stack) needs ~28 KB per connection for a persistent
session (≈22 KB buffers + ~6 KB stack) — more than the ~25 KB this port can free in total.
The MFLN 512 B trick this port already uses for HTTPS *fetches* (~9 KB, heap-gated) works
because those connections are short-lived and deferrable; a persistent `wss://` session would
hold the buffers forever and additionally depends on the server negotiating MFLN. If BearSSL
TLS is mandated on the WS connection, the hardware answer is an ESP32 (520 KB) or ESP32-C3
(400 KB).

**Also considered:** Mbed TLS (~26 KB reported integration footprint on ESP8266 — same class
as BearSSL, does not fit); axTLS (deprecated in ESP8266 Arduino core 2.5.0, fully removed in
3.0.0 — do not use).

### Hardware ceiling

* ~80 KB DRAM − ~57 KB static − ~19 KB WiFi/lwIP residents ≈ **4–5 KB free unoptimized**.
* With every software optimization applied: **~12 KB DRAM + ~12.5 KB IRAM ≈ ~25 KB total.**
* 60 KB free DRAM is not achievable on this chip — it exceeds what remains after minimum static
  allocation by ~37 KB. 60 KB combined (DRAM + IRAM) would still need ~35 KB more than exists
  after all optimizations.
* The path to substantially more memory is hardware: **ESP32 (~520 KB) or ESP32-C3 (~400 KB)**
  removes the constraint entirely. The ESP8266 core also supports external SPI SRAM (23LC1024,
  `PIO_FRAMEWORK_ARDUINO_MMU_EXTERNAL_128K`) at the cost of a hardware modification
  (an extra chip on GPIO12–15).

## Upstream project

| | |
|---|---|
| 🌐 Website | https://sensmos.com |
| 🔧 Firmware (ESP32) | https://github.com/Galusz/sensmos-firmware |
| 📱 App | https://github.com/Galusz/sensmos-app |
| 🏠 Home Assistant | https://github.com/Galusz/sensmos-homeassistant |
| 📜 Protocol | https://github.com/Galusz/sensmos-protocol |

## License

MIT — see [LICENSE](LICENSE). The upstream firmware carries no license file; this port is
published in good faith as a contribution back to the Sensmos project, and the upstream author
retains all rights to the original work.
