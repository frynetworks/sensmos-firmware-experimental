#pragma once
// Shim: ESP32 <Update.h> → ESP8266 <Updater.h>. Same global `Update` object.
// ESP8266 differences handled in ota.cpp: no rollback slots, getErrorString().
#include <Updater.h>
