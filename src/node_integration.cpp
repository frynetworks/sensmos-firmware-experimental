#include "node_integration.h"
#include "identity.h"
#include "net_worker.h"
#include "log.h"
#include <Preferences.h>
#include <WiFi.h>
#include <ArduinoJson.h>

#define NI_QUEUE_SIZE 3  // max zdarzeń w kolejce
#define NI_FLUSH_INTERVAL_MS 60000UL  // 0.73: zbiorczy POST co 60s (batch), nie per-event

struct NiEvent {
    char action [24];
    char payload[128];
    bool pending;
};

static String    _url = "";
// 0.73: batch idzie na wór. batch trzyma ciało POST między enqueue a wykonaniem na worze
// (jeden job w locie — _inflight). 768B (8266; bylo 1280 na ESP32) pokrywa 3 zdarzenia
// × (action24+payload128) + narzut JSON.
// Kolejka+batch w lazy-calloc NiState (−1,227B .bss): alokacja RAZ w init/set_url gdy URL
// skonfigurowany (okno bootu, sterta ciągła — celowo NIE przy pierwszym push, który wypada
// w dołku heapu po ws_connected). NIGDY nie zwalniany — set_url("") w runtime nie może
// unieważnić batcha, bo zakolejkowany whook job czyta go później przez
// node_integration_wor_body() (net_worker.cpp). Nieskonfigurowany node nie płaci nic —
// spójne z intencją heap-contiguity z entity_store.cpp.
struct NiState {
    NiEvent queue[NI_QUEUE_SIZE];
    char    batch[768];
};
static NiState*  _st = nullptr;
static int       _q_head = 0;
static int       _q_tail = 0;
static int       _q_count = 0;
static unsigned long _last_flush_ms = 0;
static bool _inflight = false;

static bool ni_ensure() {
    if (_st) return true;
    _st = (NiState*)calloc(1, sizeof(NiState));
    if (!_st) LOGW("ni", "state alloc failed — event dropped");
    return _st != nullptr;
}

void node_integration_init() {
    Preferences p; p.begin("ni", true);
    _url = p.getString("url", "");
    p.end();
    if (_url.length() > 0) {
        ni_ensure();   // alokacja w oknie bootu (calloc zeruje — memset zbędny)
        LOGI("ni", "integration URL: %s", _url.c_str());
    }
}

void node_integration_set_url(const char* url) {
    _url = String(url);
    Preferences p; p.begin("ni", false);
    p.putString("url", _url);
    p.end();
    if (_url.length() > 0) ni_ensure();
    LOGI("ni", "integration URL set: %s", url);
}

String node_integration_get_url() { return _url; }

void node_integration_push(const char* action, const char* payload_json) {
    if (_url.length() == 0) return;  // nie skonfigurowany — skip
    if (!ni_ensure()) return;        // brak stanu (alloc fail) — drop, retry przy następnym evencie
    if (_q_count >= NI_QUEUE_SIZE) {
        // Kolejka pełna — nadpisz najstarszy
        LOGD("ni", "queue full — dropping oldest");
        _q_tail = (_q_tail + 1) % NI_QUEUE_SIZE;
        _q_count--;
    }
    NiEvent& e = _st->queue[_q_head];
    strncpy(e.action,  action,       sizeof(e.action)  - 1);
    strncpy(e.payload, payload_json, sizeof(e.payload) - 1);
    e.pending = true;
    _q_head = (_q_head + 1) % NI_QUEUE_SIZE;
    _q_count++;
    LOGD("ni", "queued: %s (%d in queue)", action, _q_count);
}

// Zbuduj batch z kolejki (peek — NIE opróżnia; drenaż dopiero po udanym enqueue).
static int build_batch() {
    JsonDocument doc;
    doc["device_id"] = g_device_id;
    doc["window_s"]  = (int)(NI_FLUSH_INTERVAL_MS / 1000);
    JsonArray evs = doc["events"].to<JsonArray>();
    int idx = _q_tail, n = 0;
    for (int i = 0; i < _q_count; i++) {
        NiEvent& e = _st->queue[idx];
        if (e.pending) {
            JsonObject o = evs.add<JsonObject>();
            o["action"] = e.action;
            if (strlen(e.payload) > 2) {
                JsonDocument pd;
                if (!deserializeJson(pd, e.payload)) o["data"] = pd;   // payload był JSON
                else                                 o["data"] = e.payload;
            }
            n++;
        }
        idx = (idx + 1) % NI_QUEUE_SIZE;
    }
    size_t len = serializeJson(doc, _st->batch, sizeof(_st->batch));
    if (len == 0 || len >= sizeof(_st->batch)) { _st->batch[0] = 0; return -1; }  // overflow — nie wysyłaj śmieci
    return n;
}

void node_integration_update() {
    if (_inflight)              return;   // poprzedni batch nadal na worze
    if (_q_count == 0)          return;
    if (_url.length() == 0)     return;
    if (!_st)                   return;   // stan niezaalokowany (alloc fail) — nic do wysłania
    if (WiFi.status() != WL_CONNECTED) return;
    unsigned long now = millis();
    if (now - _last_flush_ms < NI_FLUSH_INTERVAL_MS) return;
    _last_flush_ms = now;

    int n = build_batch();
    if (n <= 0) return;   // pusto / overflow

    NetJob nj{};
    nj.src = NW_INTEGRATION;
    strlcpy(nj.job.kind, "whook", sizeof(nj.job.kind));
    strlcpy(nj.url, _url.c_str(), sizeof(nj.url));
    nj.body[0] = 0;   // ciało czytane z _batch przez node_integration_wor_body()

    if (net_worker_enqueue(nj, false)) {
        // sukces — usuń zbatchowane zdarzenia z kolejki (drenaż FIFO)
        for (int i = 0; i < n && _q_count > 0; ) {
            if (_st->queue[_q_tail].pending) { _st->queue[_q_tail].pending = false; i++; }
            _q_tail = (_q_tail + 1) % NI_QUEUE_SIZE;
            _q_count--;
        }
        _inflight = true;
        LOGD("ni", "batch %d events -> queue", n);
    } else {
        _last_flush_ms = now - NI_FLUSH_INTERVAL_MS + 2000;  // kolejka wora pełna — retry za 2s, batch nietknięty
    }
}

// Null-guard obowiązkowy: wywoływane z net_worker.cpp BEZ bramki _url (job whook może
// teoretycznie przeżyć wyczyszczenie configu) — pusty string zamiast deref nullptr.
const char* node_integration_wor_body() { return _st ? _st->batch : ""; }

void node_integration_on_result(const NetResult& nr) {
    _inflight = false;
    if (nr.deferred) {
        // heap za niski w chwili próby (rzadkie) — batch przepadł, następny cykl wyśle nowe zdarzenia
        LOGW("ni", "batch deferred (low heap) — dropped");
        return;
    }
    LOGD("ni", "batch HTTP %d", nr.res.status_code);
}
