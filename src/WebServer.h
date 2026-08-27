#pragma once
// Shim: ESP32 <WebServer.h> → ESP8266WebServer (API-compatible for our usage).
#include <ESP8266WebServer.h>
using WebServer = ESP8266WebServer;
