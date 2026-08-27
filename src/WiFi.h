#pragma once
// Shim: ESP32 <WiFi.h> → ESP8266WiFi. Upstream modules compile verbatim.
#include <ESP8266WiFi.h>
#include "esp8266_compat.h"
