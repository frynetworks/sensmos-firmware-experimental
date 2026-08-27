// PrefsStore — Preferences-compatible LittleFS JSON store (sensmos-esp8266 port).
#include "prefs_store.h"
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <libb64/cencode.h>
#include <libb64/cdecode.h>

static bool s_fs_mounted = false;

static bool fs_ensure() {
    if (s_fs_mounted) return true;
    s_fs_mounted = LittleFS.begin();
    if (!s_fs_mounted) {                    // first boot: format once, retry
        LittleFS.format();
        s_fs_mounted = LittleFS.begin();
    }
    return s_fs_mounted;
}

static JsonDocument& doc_of(void* p) { return *(JsonDocument*)p; }

bool PrefsStore::begin(const char* ns, bool readOnly) {
    if (_open) end();
    if (!fs_ensure()) return false;
    snprintf_P(_path, sizeof(_path), PSTR("/ns_%s.json"), ns);
    _readOnly = readOnly;
    _doc = new JsonDocument();
    if (!_doc) return false;
    load();
    _open = true;
    _dirty = false;
    return true;
}

bool PrefsStore::load() {
    // Drop a stale <path>.tmp left by a write interrupted before its atomic rename.
    char tmp[80];
    snprintf_P(tmp, sizeof(tmp), PSTR("%s.tmp"), _path);
    if (LittleFS.exists(tmp)) LittleFS.remove(tmp);
    File f = LittleFS.open(_path, "r");
    if (!f) return false;
    DeserializationError e = deserializeJson(doc_of(_doc), f);
    f.close();
    if (e) doc_of(_doc).clear();            // corrupt file → defaults
    return !e;
}

bool PrefsStore::save() {
    if (_readOnly) return false;
    // Crash-safe write: serialize to <path>.tmp, flush+close, then atomically rename over <path>.
    // LittleFS rename is an atomic metadata op, so a reset mid-write leaves either the complete old
    // file (crash before rename) or the complete new file (crash after) — never a truncated file.
    // (The previous open(_path,"w") truncated the live file before writing, so any reset in the
    // serialize window wiped WiFi creds / identity — the "new device" corruption.)
    char tmp[80];
    snprintf_P(tmp, sizeof(tmp), PSTR("%s.tmp"), _path);
    File f = LittleFS.open(tmp, "w");
    if (!f) return false;
    serializeJson(doc_of(_doc), f);
    f.flush();
    f.close();
    if (!LittleFS.rename(tmp, _path)) {   // rename should not fail; if it does, drop the temp
        LittleFS.remove(tmp);
        return false;
    }
    _dirty = false;
    return true;
}

void PrefsStore::end() {
    if (!_open) return;
    if (_dirty) save();
    delete (JsonDocument*)_doc;
    _doc = nullptr;
    _open = false;
}

String PrefsStore::getString(const char* key, const String& defaultValue) {
    if (!_open) return defaultValue;
    JsonVariant v = doc_of(_doc)[key];
    if (v.is<const char*>()) return String(v.as<const char*>());
    return defaultValue;
}

size_t PrefsStore::getString(const char* key, char* value, size_t maxLen) {
    String s = getString(key, "");
    strlcpy(value, s.c_str(), maxLen);
    return strlen(value);
}

size_t PrefsStore::putString(const char* key, const char* value) {
    if (!_open || _readOnly) return 0;
    doc_of(_doc)[key] = value;              // ArduinoJson copies the string
    save();
    return strlen(value);
}

bool PrefsStore::getBool(const char* key, bool defaultValue) {
    if (!_open) return defaultValue;
    JsonVariant v = doc_of(_doc)[key];
    return v.is<bool>() ? v.as<bool>() : defaultValue;
}
size_t PrefsStore::putBool(const char* key, bool value) {
    if (!_open || _readOnly) return 0;
    doc_of(_doc)[key] = value; save(); return 1;
}

int32_t PrefsStore::getInt(const char* key, int32_t defaultValue) {
    if (!_open) return defaultValue;
    JsonVariant v = doc_of(_doc)[key];
    return v.is<int32_t>() ? v.as<int32_t>() : defaultValue;
}
size_t PrefsStore::putInt(const char* key, int32_t value) {
    if (!_open || _readOnly) return 0;
    doc_of(_doc)[key] = value; save(); return 4;
}

uint32_t PrefsStore::getUInt(const char* key, uint32_t defaultValue) {
    if (!_open) return defaultValue;
    JsonVariant v = doc_of(_doc)[key];
    return v.is<uint32_t>() ? v.as<uint32_t>() : defaultValue;
}
size_t PrefsStore::putUInt(const char* key, uint32_t value) {
    if (!_open || _readOnly) return 0;
    doc_of(_doc)[key] = value; save(); return 4;
}
uint32_t PrefsStore::getULong(const char* key, uint32_t defaultValue) { return getUInt(key, defaultValue); }
size_t   PrefsStore::putULong(const char* key, uint32_t value)        { return putUInt(key, value); }

uint8_t PrefsStore::getUChar(const char* key, uint8_t defaultValue) {
    return (uint8_t)getUInt(key, defaultValue);
}
size_t PrefsStore::putUChar(const char* key, uint8_t value) { return putUInt(key, value) ? 1 : 0; }

// Binary values: stored as "b64:<base64>" strings (round-trips privkey/pubkey exactly).
size_t PrefsStore::putBytes(const char* key, const void* value, size_t len) {
    if (!_open || _readOnly) return 0;
    size_t b64cap = ((len + 2) / 3) * 4 + 8;
    char* b64 = (char*)malloc(b64cap + 4);
    if (!b64) return 0;
    memcpy(b64, "b64:", 4);
    base64_encodestate st; base64_init_encodestate(&st);
    int n = base64_encode_block((const char*)value, len, b64 + 4, &st);
    n += base64_encode_blockend(b64 + 4 + n, &st);
    // libb64 appends '\n' at blockend — strip trailing whitespace
    while (n > 0 && (b64[4 + n - 1] == '\n' || b64[4 + n - 1] == '\r')) n--;
    b64[4 + n] = 0;
    doc_of(_doc)[key] = b64;
    free(b64);
    save();
    return len;
}

size_t PrefsStore::getBytes(const char* key, void* buf, size_t maxLen) {
    if (!_open) return 0;
    JsonVariant v = doc_of(_doc)[key];
    if (!v.is<const char*>()) return 0;
    const char* s = v.as<const char*>();
    if (strncmp(s, "b64:", 4) != 0) return 0;
    s += 4;
    size_t slen = strlen(s);
    char* tmp = (char*)malloc(slen + 4);
    if (!tmp) return 0;
    base64_decodestate st; base64_init_decodestate(&st);
    int n = base64_decode_block(s, slen, tmp, &st);
    size_t out = (n < 0) ? 0 : ((size_t)n > maxLen ? maxLen : (size_t)n);
    if (out) memcpy(buf, tmp, out);
    free(tmp);
    return out;
}

size_t PrefsStore::getBytesLength(const char* key) {
    if (!_open) return 0;
    JsonVariant v = doc_of(_doc)[key];
    if (!v.is<const char*>()) return 0;
    const char* s = v.as<const char*>();
    if (strncmp(s, "b64:", 4) != 0) return 0;
    size_t slen = strlen(s + 4), pad = 0;
    if (slen >= 1 && s[4 + slen - 1] == '=') pad++;
    if (slen >= 2 && s[4 + slen - 2] == '=') pad++;
    return (slen / 4) * 3 - pad;
}

bool PrefsStore::isKey(const char* key) {
    if (!_open) return false;
    return !doc_of(_doc)[key].isNull();
}

bool PrefsStore::remove(const char* key) {
    if (!_open || _readOnly) return false;
    doc_of(_doc).remove(key);
    return save();
}

bool PrefsStore::clear() {
    if (!_open || _readOnly) return false;
    doc_of(_doc).clear();
    LittleFS.remove(_path);
    return true;
}
