#pragma once
// Shim: ESP32 <HTTPClient.h> → ESP8266HTTPClient z przywróconym begin(url)
// (nowe rdzenie 8266 wymagają begin(WiFiClient&, url)). Podklasa trzyma własny
// WiFiClient/BearSSL::WiFiClientSecure zależnie od schematu — call-site'y z ESP32
// (http.begin("https://…")) kompilują się bez zmian. Macro-alias na końcu podmienia
// nazwę w całym firmware (guard nagłówka bazowego zapobiega re-parsowaniu).
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecure.h>

class SensmosHTTPClient : public HTTPClient {
public:
    // UWAGA: bez `using HTTPClient::begin` — bazowy begin(String) jest oznaczony
    // attribute-error i robił ambiguity; potrzebne warianty forwardujemy jawnie.
    bool begin(WiFiClient& client, const String& url) { return HTTPClient::begin(client, url); }
    bool begin(WiFiClient& client, const String& host, uint16_t port, const String& uri = "/", bool https = false) {
        return HTTPClient::begin(client, host, port, uri, https);
    }
    bool begin(const String& url) {
        bool secure = url.startsWith("https://");
        if (secure) {
            if (!_sec) _sec = new BearSSL::WiFiClientSecure();
            _sec->setInsecure();                 // upstream też jedzie setInsecure()
            _sec->setBufferSizes(512, 512);      // MFLN — BearSSL mieści się w heapie 8266
            return HTTPClient::begin(*_sec, url);
        }
        if (!_plain) _plain = new WiFiClient();
        return HTTPClient::begin(*_plain, url);
    }
    bool begin(const char* url) { return begin(String(url)); }
    ~SensmosHTTPClient() { end(); delete _sec; delete _plain; }
private:
    BearSSL::WiFiClientSecure* _sec = nullptr;
    WiFiClient* _plain = nullptr;
};

#define HTTPClient SensmosHTTPClient
