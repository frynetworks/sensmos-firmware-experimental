// Device-local geolocation store + IP-geolocation acquisition — see geolocation.h.
#include "geolocation.h"
#include "Preferences.h"
#include "log.h"
#include "config.h"
#include "wifi_manager.h"
#include "ws_client.h"
#include "http_internal.h"
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>

#define GEOLOC_NS "sensmos_loc"

bool geoloc_store(const char* lat, const char* lon, uint32_t accuracy_m,
                  const char* src, const char* ssid) {
    Preferences p;
    if (!p.begin(GEOLOC_NS, false)) return false;
    p.putString("lat",  lat);
    p.putString("lon",  lon);
    p.putUInt  ("acc",  accuracy_m);
    p.putString("src",  src);
    p.putString("ssid", ssid ? ssid : "");
    p.end();
    return true;
}

bool geoloc_get_json(char* buf, size_t buflen) {
    Preferences p;
    if (!p.begin(GEOLOC_NS, true)) return false;
    String lat = p.getString("lat", "");
    String lon = p.getString("lon", "");
    uint32_t acc = p.getUInt("acc", 0);
    String src = p.getString("src", "");
    p.end();
    if (lat.length() == 0 || lon.length() == 0) return false;
    snprintf_P(buf, buflen,
        PSTR("\"lat\":\"%s\",\"lon\":\"%s\",\"accuracy_m\":%u,\"source\":\"%s\""),
        lat.c_str(), lon.c_str(), (unsigned)acc, src.c_str());
    return true;
}

void geoloc_clear() {
    Preferences p;
    if (p.begin(GEOLOC_NS, false)) {
        p.clear();   // PrefsStore::clear() removes the namespace file
        p.end();
    }
    LOGI("geo", "stored location cleared");
}

// ── IP-geolocation acquisition (plain HTTP — no TLS heap cost) ────────────────

static bool geoloc_store_fix(float lat, float lon) {
    if (lat < -90.0f || lat > 90.0f || lon < -180.0f || lon > 180.0f) return false;
    if (lat == 0.0f && lon == 0.0f) return false;             // null island = no fix
    char latS[16], lonS[16];
    snprintf_P(latS, sizeof(latS), PSTR("%.6f"), (double)lat);
    snprintf_P(lonS, sizeof(lonS), PSTR("%.6f"), (double)lon);
    if (!geoloc_store(latS, lonS, GEOLOC_ACCURACY_IP_M, "ip_api", g_wifi_ssid)) return false;
    LOGI("geo", "location acquired: lat=%s lon=%s accuracy=~%dm source=ip_api",
         latS, lonS, GEOLOC_ACCURACY_IP_M);
    return true;
}

// ip-api.com: {"status":"success","lat":44.02,"lon":-92.46,...}
static bool geoloc_fetch_ipapi() {
    HTTPClient http; WiFiClientSecure sec;
    if (!http_begin_url(http, sec, F("http://ip-api.com/json"))) return false;
    http.setTimeout(HTTP_TIMEOUT_BACKEND);
    int code = http.GET();
    if (code != 200) { LOGW("geo", "ip-api.com HTTP %d", code); http.end(); return false; }
    String body = http.getString(); http.end();
    JsonDocument doc;
    if (deserializeJson(doc, body)) { LOGW("geo", "ip-api.com parse error"); return false; }
    if (strcmp(doc["status"] | "", "success") != 0) {
        LOGW("geo", "ip-api.com status=%s", doc["status"] | "?"); return false;
    }
    return geoloc_store_fix(doc["lat"] | 999.0f, doc["lon"] | 999.0f);
}

// ipinfo.io (keyless fallback): {"loc":"44.0121,-92.4802",...}
static bool geoloc_fetch_ipinfo() {
    HTTPClient http; WiFiClientSecure sec;
    if (!http_begin_url(http, sec, F("http://ipinfo.io/json"))) return false;
    http.setTimeout(HTTP_TIMEOUT_BACKEND);
    int code = http.GET();
    if (code != 200) { LOGW("geo", "ipinfo.io HTTP %d", code); http.end(); return false; }
    String body = http.getString(); http.end();
    JsonDocument doc;
    if (deserializeJson(doc, body)) { LOGW("geo", "ipinfo.io parse error"); return false; }
    const char* loc = doc["loc"] | "";
    float lat = 999.0f, lon = 999.0f;
    if (sscanf(loc, "%f,%f", &lat, &lon) != 2) {
        LOGW("geo", "ipinfo.io loc unparseable"); return false;
    }
    return geoloc_store_fix(lat, lon);
}

void geoloc_push_ws() {
    Preferences p;
    if (!p.begin(GEOLOC_NS, true)) {
        LOGW("geo", "push: prefs open failed — retries on next WS connect");
        return;
    }
    String lat = p.getString("lat", "");
    String lon = p.getString("lon", "");
    String src = p.getString("src", "");
    p.end();
    if (lat.length() == 0 || lon.length() == 0) {
        LOGI("geo", "no stored location to push");
        return;
    }
    uint32_t freeh = ESP.getFreeHeap();
    if (freeh < GEOLOC_MIN_HEAP) {
        LOGW("geo", "heap %uk < gate — skipping push (retries on next WS connect)", freeh / 1024);
        return;
    }
    // Same node_config shape the app path forwards (http_config.cpp): BE applies fuzz and owns
    // the anchor; an app GPS fix overrides this coarse one.
    char msg[180];
    snprintf_P(msg, sizeof(msg),
        PSTR("{\"type\":\"node_config\",\"gps_lat\":%s,\"gps_lon\":%s,\"fuzz\":true}"),
        lat.c_str(), lon.c_str());
    if (ws_client_send_raw(msg))
        LOGI("geo", "pushed location to backend: lat=%s lon=%s source=%s",
             lat.c_str(), lon.c_str(), src.c_str());
    else
        LOGW("geo", "location push failed (ws send) — retries on next WS connect");
}

void geoloc_boot_attempt() {
    if (!g_wifi_connected) return;
    Preferences p; p.begin(GEOLOC_NS, true);
    String lat  = p.getString("lat", "");
    String ssid = p.getString("ssid", "");
    p.end();
    if (lat.length() && ssid == String(g_wifi_ssid)) {
        LOGI("geo", "cached (lat=%s, ssid unchanged)", lat.c_str());
        return;
    }
    uint32_t freeh = ESP.getFreeHeap();
    if (freeh < GEOLOC_MIN_HEAP) {
        LOGW("geo", "heap %uk < gate — defer to next boot", freeh / 1024);
        return;
    }
    if (!geoloc_fetch_ipapi() && !geoloc_fetch_ipinfo())
        LOGW("geo", "acquisition failed (both APIs) — retry next boot");
}
