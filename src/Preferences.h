#pragma once
// Shim: ESP32 <Preferences.h> → LittleFS-backed PrefsStore (identical call surface).
// Lets upstream modules compile verbatim on ESP8266.
#include "prefs_store.h"
using Preferences = PrefsStore;
