#pragma once
// Shim: ESP32 <ESPmDNS.h> → ESP8266mDNS. Same global `MDNS` object; the
// begin/addService/addServiceTxt calls upstream makes exist on both cores.
// NOTE: ESP8266 additionally needs MDNS.update() in loop() (done in main.cpp).
#include <ESP8266mDNS.h>
