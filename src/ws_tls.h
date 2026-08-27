#pragma once
#ifdef SENSMOS_USE_TLS
#include <ESP8266WiFi.h>

// Forward tag — wolfssl/ssl.h robi `typedef struct WOLFSSL WOLFSSL;`, więc `struct WOLFSSL*`
// jest zgodny. Dzięki temu ten nagłówek NIE potrzebuje include-patha wolfSSL-a — a jest
// wstrzykiwany do WebSockets.h biblioteki (patrz tools/patch_websockets_tls.py), której
// jednostki kompilacji ścieżek wolfSSL-a nie mają.
struct WOLFSSL;

int ws_tls_io_send_cb(struct WOLFSSL* ssl, char* buf, int sz, void* ctx);
int ws_tls_io_recv_cb(struct WOLFSSL* ssl, char* buf, int sz, void* ctx);

// WsTlsClient — wolfSSL-owy zamiennik WiFiClientSecure dla arduinoWebSockets (env TLS).
// Biblioteka sama `new`-uje klasę SSL (WebSocketsClient.cpp:262-263, `_client.tcp =
// _client.ssl`) — stąd dziedziczenie po WiFiClient jest OBOWIĄZKOWE, a całe I/O idzie
// przez wirtualne metody Client/WiFiClient. Surowy socket TCP to odziedziczony WiFiClient
// (self = transport), więc nie-wirtualne setNoDelay/setTimeout biblioteki trafiają we
// właściwy ClientContext.
class WsTlsClient : public WiFiClient {
public:
    WsTlsClient() {}
    virtual ~WsTlsClient();

    virtual int connect(const char* host, uint16_t port) override;   // TCP + SNI + handshake (bounded retry)
    virtual int connect(IPAddress ip, uint16_t port) override;       // bez SNI — nieużywane przez lib (łączy po hoście)

    virtual size_t write(uint8_t b) override;
    virtual size_t write(const uint8_t* buf, size_t size) override;  // WANT_WRITE -> 0 (pętla zapisu lib retry'uje)

    virtual int available() override;                                // plaintext pending (+ pompka rekordu przez peek)
    virtual int read() override;
    virtual int read(uint8_t* buf, size_t size) override;
    virtual int peek() override;
    virtual void flush() override;
    virtual void stop() override;                                    // shutdown + free sesji + stop socketu
    virtual uint8_t connected() override;
    virtual operator bool() override { return connected() != 0; }

    // Zero-copy peek-buffer WiFiClienta czyta surowe pbuf-y lwIP = SZYFROGRAM. Wyłączone,
    // inaczej Stream::readStringUntil biblioteki dostałby ciphertext zamiast plaintextu.
    virtual bool hasPeekBufferAPI() const override { return false; }
    virtual size_t peekAvailable() override { return 0; }
    virtual const char* peekBuffer() override { return nullptr; }
    virtual void peekConsume(size_t consume) override { (void)consume; }

    // Stuby pod nazwy BearSSL — gałąź SSL_BARESSL WebSocketsClient.cpp kompiluje te
    // wywołania bezwarunkowo (setInsecure woła DWA razy: :300 i :983 — idempotentne).
    // Weryfikacja certu: pinning ISRG Root YE + VERIFY_PEER (ws_tls.cpp; degradacja
    // do VERIFY_NONE tylko gdy load kotwicy padnie).
    void setInsecure() {}
    void setFingerprint(const uint8_t* fp) { (void)fp; }
    void setTrustAnchors(const BearSSL::X509List* ta) { (void)ta; }
    void setClientRSACert(const BearSSL::X509List* cert, const BearSSL::PrivateKey* key) { (void)cert; (void)key; }

private:
    struct WOLFSSL* _ssl = nullptr;
    bool _hsDone = false;

    // TCP (kwalifikowane, nie-wirtualne wywołanie bazy!) + handshake. sniHost==nullptr → bez SNI.
    // Uwaga: WiFiClient::connect(host,port) sam robi DNS i woła WIRTUALNE connect(IPAddress,...)
    // — nasze override'y NIE mogą wracać przez bazową ścieżkę hostową (rekursja).
    int tlsConnect(IPAddress ip, uint16_t port, const char* sniHost);

    friend int ws_tls_io_send_cb(struct WOLFSSL* ssl, char* buf, int sz, void* ctx);
    friend int ws_tls_io_recv_cb(struct WOLFSSL* ssl, char* buf, int sz, void* ctx);
};

// Jednorazowy PoC pomiarowy (httpbin) — zostaje jako narzędzie diagnostyczne; nieużywany
// w obrazie (gc-sections wytnie), instrumentacja [tls-heap] żyje teraz w transporcie.
void ws_tls_run_poc_test();

#endif // SENSMOS_USE_TLS
