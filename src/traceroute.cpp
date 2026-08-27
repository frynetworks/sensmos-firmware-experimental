// traceroute.cpp — ESP8266 port. lwIP raw API jak w oryginale; różnice:
// - NONOS lwIP (NO_SYS): brak wątku tcpip → tcpip_callback zastąpione bezpośrednim
//   wywołaniem (operacje na pcb z kontekstu Arduino są tu poprawne — jeden kontekst).
// - dodane icmp_ping() na tym samym pcb (zastępuje esp_ping z ESP32, którego 8266 nie ma).
#include "traceroute.h"
#include "log.h"
#include <WiFi.h>
#include "lwip/raw.h"
#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"          // punch-trace: UDP z portu sesji, TTL per-pakiet (pcb->ttl)

#define TR_ID          0x534D      // 'SM' — nasz identyfikator ICMP echo (filtr w recv)
#define TR_PKT_LEN     12          // 8B nagłówek echo + 4B magic
#define TR_TOTAL_BUDGET_MS 30000UL // twardy limit całego trace (nie blokuj pętli w nieskończoność)
#define TR_MAX_SILENT      5       // tyle głuchych TTL z rzędu = koniec trasy (za last-hopem cisza)

static struct raw_pcb*   s_pcb     = nullptr;   // JEDEN, nigdy nie zamykany
static volatile bool     s_waiting = false;
static volatile uint16_t s_seq     = 0;
static volatile uint8_t  s_ttl     = 1;
static volatile uint32_t s_hop_ip  = 0;
static volatile bool     s_reached = false;
static volatile bool     s_got     = false;
static volatile uint32_t s_reply_ms = 0;        // millis() odebrania (icmp_ping: dokładny RTT)
static ip_addr_t         s_target;
// Tryb UDP (v0.60, punch-trace przez dziurę): probe = UDP z portu sesji, a nie ICMP echo.
static volatile bool     s_udp_mode = false;
static volatile uint16_t s_udp_src  = 0;
static volatile uint16_t s_udp_dst  = 0;
static struct udp_pcb*   s_upcb     = nullptr;

// ── recv: zjadamy TYLKO nasze pakiety, resztę oddajemy ───────────────────────
static u8_t tr_recv_cb(void*, struct raw_pcb*, struct pbuf* p, const ip_addr_t* addr) {
    if (!s_waiting || !p) return 0;
    uint8_t buf[64];
    u16_t n = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    if (n < 28) return 0;                              // IP(20) + ICMP(8) minimum
    int ihl = (buf[0] & 0x0F) * 4;
    if (n < (u16_t)(ihl + 8)) return 0;
    uint8_t type = buf[ihl];

    if (type == ICMP_ER) {                             // echo reply — czy nasz?
        uint16_t id  = ((uint16_t)buf[ihl + 4] << 8) | buf[ihl + 5];
        uint16_t seq = ((uint16_t)buf[ihl + 6] << 8) | buf[ihl + 7];
        if (id != TR_ID || seq != s_seq) return 0;     // nie nasz — oddaj
        s_hop_ip = ip_addr_get_ip4_u32(addr);
        s_reached = true; s_got = true; s_reply_ms = millis();
        pbuf_free(p);
        return 1;
    }
    if (type == ICMP_TE) {                             // time exceeded: w środku NASZ probe?
        int inner = ihl + 8;
        if (n < (u16_t)(inner + 20 + 8)) return 0;
        int iihl = (buf[inner] & 0x0F) * 4;
        if (n < (u16_t)(inner + iihl + 8)) return 0;
        if (s_udp_mode) {                              // punch-trace: wewn. pakiet to UDP (proto 17)
            uint8_t  iproto = buf[inner + 9];
            uint16_t isrc   = ((uint16_t)buf[inner + iihl + 0] << 8) | buf[inner + iihl + 1];
            uint16_t idst   = ((uint16_t)buf[inner + iihl + 2] << 8) | buf[inner + iihl + 3];
            if (iproto != 17 || isrc != s_udp_src || idst != s_udp_dst) return 0;
        } else {                                       // zwykły trace: wewn. ICMP echo (TR_ID/seq)
            uint8_t  itype = buf[inner + iihl];
            uint16_t iid   = ((uint16_t)buf[inner + iihl + 4] << 8) | buf[inner + iihl + 5];
            uint16_t iseq  = ((uint16_t)buf[inner + iihl + 6] << 8) | buf[inner + iihl + 7];
            if (itype != ICMP_ECHO || iid != TR_ID || iseq != s_seq) return 0;
        }
        s_hop_ip = ip_addr_get_ip4_u32(addr);
        s_reached = false; s_got = true; s_reply_ms = millis();
        pbuf_free(p);
        return 1;
    }
    return 0;                                          // inne ICMP — nie nasze
}

// ── init + send: bezpośrednio (NONOS — jeden kontekst lwIP) ──────────────────
static void tr_init_direct() {
    if (s_pcb) return;
    s_pcb = raw_new(IP_PROTO_ICMP);
    if (s_pcb) {
        raw_recv(s_pcb, tr_recv_cb, nullptr);
        raw_bind(s_pcb, IP_ADDR_ANY);
    }
}

static void tr_send_direct() {
    if (!s_pcb) return;
    struct pbuf* p = pbuf_alloc(PBUF_IP, TR_PKT_LEN, PBUF_RAM);
    if (!p) return;
    struct icmp_echo_hdr* h = (struct icmp_echo_hdr*)p->payload;
    ICMPH_TYPE_SET(h, ICMP_ECHO);
    ICMPH_CODE_SET(h, 0);
    h->id     = lwip_htons(TR_ID);
    h->seqno  = lwip_htons(s_seq);
    ((uint8_t*)p->payload)[8]  = 'S';
    ((uint8_t*)p->payload)[9]  = 'N';
    ((uint8_t*)p->payload)[10] = 'M';
    ((uint8_t*)p->payload)[11] = 'S';
    h->chksum = 0;
    h->chksum = inet_chksum(h, TR_PKT_LEN);
    s_pcb->ttl = s_ttl;
    raw_sendto(s_pcb, p, &s_target);
    pbuf_free(p);                                      // nasz pbuf — zwalniamy ZAWSZE
}

void traceroute_init() {
    tr_init_direct();
}

static bool tr_resolve(const char* host) {
    memset(&s_target, 0, sizeof(s_target));
    if (ipaddr_aton(host, &s_target) == 0) {
        IPAddress ip;
        if (!WiFi.hostByName(host, ip)) return false;
        IP_ADDR4(&s_target, ip[0], ip[1], ip[2], ip[3]);
    }
    return true;
}

int traceroute_run(const char* host, TrHop* hops, int max_hops,
                   uint32_t per_hop_ms, bool* reached) {
    *reached = false;
    s_udp_mode = false;
    if (!host || !*host || max_hops < 1) return 0;
    if (!s_pcb) {
        traceroute_init();
        if (!s_pcb) { LOGW("trace", "no pcb"); return 0; }
    }
    if (!tr_resolve(host)) return 0;

    int n = 0, silent = 0;
    unsigned long t_start = millis();
    for (int ttl = 1; ttl <= max_hops && n < max_hops; ttl++) {
        if (millis() - t_start > TR_TOTAL_BUDGET_MS) break;
        if (silent >= TR_MAX_SILENT) break;
        s_seq++;
        s_ttl     = (uint8_t)ttl;
        s_hop_ip  = 0;
        s_got     = false;
        s_waiting = true;
        unsigned long t0 = millis();
        tr_send_direct();
        while (!s_got && millis() - t0 < per_hop_ms) delay(10);
        s_waiting = false;

        hops[n].ttl = (uint8_t)ttl;
        hops[n].ip  = s_got ? s_hop_ip : 0;
        hops[n].ms  = s_got ? (float)(millis() - t0) : -1.0f;
        n++;
        silent = s_got ? 0 : silent + 1;
        if (s_got && s_reached) { *reached = true; break; }
        yield();
    }
    LOGD("trace", "%s: %d hops, reached=%d", host, n, *reached);
    return n;
}

// ── icmp_ping (port 8266) — zastępuje esp_ping z ESP32 ───────────────────────
// N sond echo TTL=64 na wspólnym pcb; wynik: rtt/jitter/loss jak esp_ping w net_worker.
bool icmp_ping(const char* host, int count, uint32_t timeout_ms, uint32_t interval_ms,
               float* rtt_ms, float* jitter_ms, float* loss_pct, int* samples) {
    *rtt_ms = 0; *jitter_ms = 0; *loss_pct = 100; *samples = 0;
    if (!host || !*host || count < 1) return false;
    if (!s_pcb) { traceroute_init(); if (!s_pcb) return false; }
    s_udp_mode = false;
    if (!tr_resolve(host)) return false;

    float sum = 0, sumsq = 0; int recv = 0;
    for (int i = 0; i < count; i++) {
        s_seq++;
        s_ttl     = 64;
        s_hop_ip  = 0;
        s_got     = false;
        s_reached = false;
        s_waiting = true;
        unsigned long t0 = millis();
        tr_send_direct();
        while (!s_got && millis() - t0 < timeout_ms) delay(5);
        s_waiting = false;
        if (s_got && s_reached) {
            float el = (float)(s_reply_ms - t0);
            recv++; sum += el; sumsq += el * el;
        }
        if (i + 1 < count) delay(interval_ms);
        yield();
    }
    *samples = recv;
    if (recv > 0) {
        float avg = sum / recv;
        float var = sumsq / recv - avg * avg; if (var < 0) var = 0;
        *rtt_ms = avg; *jitter_ms = sqrtf(var);
        *loss_pct = 100.0f * (count - recv) / count;
        return true;
    }
    return false;
}

// ── Tryb UDP (v0.60): trace PRZEZ wybitą dziurę NAT ──────────────────────────
static void tr_udp_init_direct(uint16_t srcPort) {
    if (s_upcb) { udp_remove(s_upcb); s_upcb = nullptr; }
    struct udp_pcb* pcb = udp_new();
    if (!pcb) return;
    ip_set_option(pcb, SOF_REUSEADDR);                 // port dopiero co zwolniony przez WiFiUDP
    if (udp_bind(pcb, IP_ADDR_ANY, srcPort) != ERR_OK) { udp_remove(pcb); return; }
    s_upcb = pcb;
}
static void tr_udp_remove_direct() {
    if (s_upcb) { udp_remove(s_upcb); s_upcb = nullptr; }
}
static void tr_udp_send_direct() {
    if (!s_upcb) return;
    struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, 8, PBUF_RAM);
    if (!p) return;
    memcpy(p->payload, "SPTsnms", 7); ((char*)p->payload)[7] = 0;
    s_upcb->ttl = s_ttl;                               // rosnący TTL = kolejny hop
    udp_sendto(s_upcb, p, &s_target, s_udp_dst);
    pbuf_free(p);
}

int traceroute_run_udp(const char* host, uint16_t dstPort, uint16_t srcPort,
                       TrHop* hops, int max_hops, uint32_t per_hop_ms, bool* reached) {
    *reached = false;
    if (!host || !*host || dstPort == 0 || max_hops < 1) return 0;
    if (!s_pcb) { traceroute_init(); if (!s_pcb) { LOGW("trace", "no pcb"); return 0; } }
    if (!tr_resolve(host)) return 0;

    tr_udp_init_direct(srcPort);
    if (!s_upcb) { LOGW("trace", "udp bind %u failed", srcPort); return 0; }

    s_udp_mode = true; s_udp_src = srcPort; s_udp_dst = dstPort;
    int n = 0, silent = 0;
    unsigned long t_start = millis();
    for (int ttl = 1; ttl <= max_hops && n < max_hops; ttl++) {
        if (millis() - t_start > TR_TOTAL_BUDGET_MS) break;
        if (silent >= TR_MAX_SILENT) break;
        s_ttl = (uint8_t)ttl; s_hop_ip = 0; s_got = false; s_waiting = true;
        unsigned long t0 = millis();
        tr_udp_send_direct();
        while (!s_got && millis() - t0 < per_hop_ms) delay(10);
        s_waiting = false;
        hops[n].ttl = (uint8_t)ttl;
        hops[n].ip  = s_got ? s_hop_ip : 0;
        hops[n].ms  = s_got ? (float)(millis() - t0) : -1.0f;
        n++;
        silent = s_got ? 0 : silent + 1;
        yield();
    }
    s_udp_mode = false;
    tr_udp_remove_direct();
    LOGD("trace", "udp %s:%u: %d hops", host, dstPort, n);
    return n;
}
