#pragma once
// PrefsStore — ESP32 Preferences-compatible key-value store on LittleFS.
// One JSON file per namespace (/ns_<name>.json); binary values base64-encoded.
// Write-through; a corrupt/missing file falls back to defaults.
#include <Arduino.h>

class PrefsStore {
public:
    bool begin(const char* ns, bool readOnly = false);
    void end();

    String getString(const char* key, const String& defaultValue = "");
    size_t getString(const char* key, char* value, size_t maxLen);
    size_t putString(const char* key, const char* value);
    size_t putString(const char* key, const String& value) { return putString(key, value.c_str()); }

    bool    getBool(const char* key, bool defaultValue = false);
    size_t  putBool(const char* key, bool value);
    int32_t getInt(const char* key, int32_t defaultValue = 0);
    size_t  putInt(const char* key, int32_t value);
    uint32_t getUInt(const char* key, uint32_t defaultValue = 0);
    size_t   putUInt(const char* key, uint32_t value);
    uint32_t getULong(const char* key, uint32_t defaultValue = 0);
    size_t   putULong(const char* key, uint32_t value);
    uint8_t getUChar(const char* key, uint8_t defaultValue = 0);
    size_t  putUChar(const char* key, uint8_t value);

    size_t getBytes(const char* key, void* buf, size_t maxLen);
    size_t putBytes(const char* key, const void* value, size_t len);
    size_t getBytesLength(const char* key);

    bool isKey(const char* key);
    bool remove(const char* key);
    bool clear();

private:
    char _path[40] = {0};
    bool _open = false;
    bool _readOnly = false;
    bool _dirty = false;
    void* _doc = nullptr;   // JsonDocument* (opaque here — keeps ArduinoJson out of this header)
    bool load();
    bool save();
};
