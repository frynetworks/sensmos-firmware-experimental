#ifndef GEOLOCATION_H
#define GEOLOCATION_H

#include <Arduino.h>

// Device-local geolocation store (LittleFS ns "sensmos_loc" — own file, so location writes never
// rewrite the identity/wifi namespaces). SUPPLEMENTARY to the app-proof geo flow: the BE anchor
// set via POST /config -> WS node_config (http_config.cpp) stays the backend's source of truth;
// this store only feeds the serial `get_location` report and is source-tagged.
// lat/lon are kept as %.6f strings (PrefsStore has no double; 1e-6 deg ≈ 0.11 m — ample).

// Store a location fix. src: "ip_api" | "manual" | "local_http" | "portal" | "backend".
// ssid = network the fix was acquired on (re-acquisition trigger on SSID change).
bool geoloc_store(const char* lat, const char* lon, uint32_t accuracy_m,
                  const char* src, const char* ssid);

// Fill buf with the stored-location JSON fragment:
//   "lat":"..","lon":"..","accuracy_m":N,"source":".."
// Returns false (buf untouched) when no location is stored.
bool geoloc_get_json(char* buf, size_t buflen);

// Remove the stored location (namespace file deleted).
void geoloc_clear();

// One-shot IP-geolocation acquisition, called from setup() in the boot window (after
// self_register_boot_attempt). Skips when a fix for the current SSID is already stored
// (re-acquires after an SSID change or a clear), or when heap < GEOLOC_MIN_HEAP.
void geoloc_boot_attempt();

// Send the stored fix to the backend as a node_config WS message (same shape the app's
// POST /config handler forwards). Called from ws_client on_identified(), so it re-sends on
// every connect/reconnect — the update is idempotent backend-side. No-op when nothing is
// stored or heap is below GEOLOC_MIN_HEAP.
void geoloc_push_ws();

// ── Accuracy model (why there are two location paths) ─────────────────────────
// IP geolocation is SUPPLEMENTARY and COARSE: ~25 km (city-level), derived from the WAN IP's
// registry entry, and outright wrong behind a VPN or CGNAT. Its only job is to give the backend
// SOME position for a node that has never had the app opened next to it.
// The precise path is unchanged and remains the source of truth: the sensmos app posts phone GPS
// to the node (POST /config gps_lat/gps_lon), the node forwards it over WS node_config, and the
// backend's setAppLocation applies it (with fuzz). An app fix therefore overrides the coarse IP
// fix backend-side — accuracy improves as soon as a user opens the app near the device.
// The firmware never treats itself as an authoritative location source; it only reports.

#endif
