#include "wifi_manager.h"
#include "identity.h"
#include "log.h"
#include <WiFi.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include "data_sender.h"  // FW_VERSION
#include "config.h"       // WIFI_STATIC_* (fallback DHCP)
extern "C" {
#include <user_interface.h>   // wifi_station_get_connect_status, wifi_get_opmode
}
#if WIFI_DEEP_DIAG
extern "C" {
#include <lwip/netif.h>       // netif_list walk (ground-truth L3 state)
#include <lwip/ip_addr.h>     // ipaddr_ntoa
}
#endif

bool g_wifi_connected = false;
char g_wifi_ssid[64]  = {0};
char g_local_ip[16]   = {0};

// Region WiFi: bez tego ESP32 NIE widzi AP na kanałach 12-13 (legalne i częste w EU) →
// NO_AP_FOUND mimo działającego radia (potwierdzone: NerdMiner na tej samej płytce łączył się,
// nasz FW nie — bo nie ustawialiśmy regionu). "01"+MANUAL 1-13 = całe pasmo 2.4GHz, globalnie.
static void wifi_apply_country() {
    // Port 8266: NIE ustawiamy juz kraju recznie. "01" to konwencja ESP-IDF (world-safe);
    // NONOS SDK jej nie zna, a policy MANUAL z nieznanym cc potrafi zablokowac asocjacje
    // (stacja wisi w STATION_CONNECTING mimo widocznego AP na dozwolonym kanale).
    // Domyslny region SDK obejmuje kanaly 1-13, czyli to, po co ta funkcja istniala.
}

bool wifi_has_config() {
    Preferences prefs;
    prefs.begin("sensmos_wifi", true);
    bool has = prefs.isKey("ssid");
    prefs.end();
    return has;
}

// TRIM SSID: apka/klawiatura telefonu potrafi dokleić spację/CR/LF na końcu (autocomplete).
// Zapisany "GladiLANtor " ≠ realny "GladiLANtor" → skan „NOT VISIBLE" + connect NO_AP_FOUND,
// mimo że AP jest o -16 dBm obok. (Diagnoza 2026-07-12, N16R8 gościa.) Whitespace = zawsze błąd
// w SSID. Hasła NIE trimujemy (spacja w haśle bywa poprawna).
static void trim_ws(char* s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\r'||s[n-1]=='\n')) s[--n] = 0;
    size_t i = 0; while (s[i]==' '||s[i]=='\t'||s[i]=='\r'||s[i]=='\n') i++;
    if (i) memmove(s, s+i, strlen(s+i)+1);
}
// Normalizacja do OSTATNIEJ deski ratunku przy dopasowaniu do WIDZIANEGO AP: usuń WSZYSTKIE
// białe znaki + lowercase (ASCII). Bezpieczne, bo i tak łączymy po BSSID realnie widzianego AP
// (nie po nazwie) — łapie „My Home WiFi" gdy user wpisał „MyHomeWiFi"/„myhome wifi" itp.
static void norm_ssid(char* dst, size_t dsz, const char* src) {
    size_t j = 0;
    for (size_t i = 0; src && src[i] && j + 1 < dsz; i++) {
        char ch = src[i];
        if (ch==' '||ch=='\t'||ch=='\r'||ch=='\n') continue;   // pomiń wszystkie spacje
        if (ch>='A'&&ch<='Z') ch = (char)(ch + 32);            // lowercase
        dst[j++] = ch;
    }
    dst[j] = 0;
}
// Usuń TYLKO spacje (wielkość liter ZACHOWANA) — do próby na UKRYTY SSID, który wymaga
// dokładnej nazwy: user mógł dokleić/pominąć spacje, ale case wpisał świadomie.
static void strip_spaces(char* dst, size_t dsz, const char* src) {
    size_t j = 0;
    for (size_t i = 0; src && src[i] && j + 1 < dsz; i++) {
        char ch = src[i];
        if (ch==' '||ch=='\t'||ch=='\r'||ch=='\n') continue;
        dst[j++] = ch;
    }
    dst[j] = 0;
}
void wifi_save_config(const char* ssid, const char* password) {
    char clean[64]; strncpy(clean, ssid ? ssid : "", sizeof(clean)-1); clean[sizeof(clean)-1]=0;
    trim_ws(clean);
    if (strcmp(clean, ssid ? ssid : "") != 0)
        LOGW("wifi", "SSID trimmed: '%s' -> '%s' (had leading/trailing whitespace)", ssid, clean);
    Preferences prefs;
    prefs.begin("sensmos_wifi", false);
    prefs.putString("ssid",     clean);
    prefs.putString("password", password);
    prefs.end();
    node_deleted_set(false);   // zapis nowego WiFi = re-onboarding → zdejmij flagę „deleted"
    LOGI("wifi", "config saved: '%s'", clean);
}

// Flaga „deleted" (owner skasował noda z apki; BE przysłał podpisaną komendę WS „deleted").
// Node TRZYMA tożsamość/klucze, ale bootuje prosto w BLE onboarding — czeka na ponowne dodanie.
// NS „sensmos" wspólny z boot_force_ble. Czyszczona przy zapisie nowego configu WiFi (wyżej).
bool node_deleted_get() {
    Preferences p; p.begin("sensmos", true);
    bool v = p.getBool("deleted", false); p.end();
    return v;
}
void node_deleted_set(bool v) {
    Preferences p; p.begin("sensmos", false);
    p.putBool("deleted", v); p.end();
}

void wifi_clear_config() {
    Preferences prefs;
    prefs.begin("sensmos_wifi", false);
    prefs.clear();
    prefs.end();
    LOGI("wifi", "config cleared");
}

// Ostatni kod przyczyny rozłączenia (ESP-IDF wifi_err_reason_t) — do diagnozy „connect failed".
static volatile uint8_t g_last_disc_reason = 0;
static volatile bool    g_l2_assoc = false;   // ustawiane w onStationModeConnected
static const char* wifi_reason_name(uint8_t r) {
    switch (r) {
        case 2:   return "AUTH_EXPIRE";
        case 4:   return "ASSOC_EXPIRE";
        case 15:  return "4WAY_HANDSHAKE_TIMEOUT/bad-password";
        case 201: return "NO_AP_FOUND (RF/antenna/wrong SSID/5GHz-only)";
        case 202: return "AUTH_FAIL (bad password)";
        case 203: return "ASSOC_FAIL";
        case 204: return "HANDSHAKE_TIMEOUT";
        case 205: return "CONNECTION_FAIL";
        default:  return "see esp_wifi_types.h";
    }
}
uint8_t wifi_last_disc_reason() { return g_last_disc_reason; }
// Czeka na połączenie do maxAttempts×500ms; true jeśli WL_CONNECTED.
// 8266: status stacji siedzi w STATION_CONNECTING az do STATION_GOT_IP, wiec sama
// asocjacja L2 go NIE zmienia. Na wolnym DHCP (siec gosc) 20 s bywa za malo i FW
// oglaszal porazke juz PO udanej asocjacji, po czym restartowal i zaczynal od zera.
// Dlatego: po zdarzeniu asocjacji wydluzamy okno o DHCP_EXTRA_ATTEMPTS.
#define DHCP_EXTRA_ATTEMPTS 90   // +45 s na sam lease

#if WIFI_DEEP_DIAG
// Ground-truth STA diagnostics. Observer-effect-safe: ONE static buffer, snprintf_P/PROGMEM,
// no String and no dynamic allocation in the 500ms hot path (heap is 15-22k; a leak here would
// itself trigger the pbuf-starvation failure this is meant to observe).
static char s_diag[248];
static void wifi_diag_emit(int loopn) {
    struct ip_info ipi; wifi_get_ip_info(STATION_IF, &ipi);
    uint32_t a = ipi.ip.addr, g = ipi.gw.addr, m = ipi.netmask.addr;
    const uint8_t* bp = WiFi.BSSID();
    uint8_t b0=0,b1=0,b2=0,b3=0,b4=0,b5=0;
    if (bp) { b0=bp[0]; b1=bp[1]; b2=bp[2]; b3=bp[3]; b4=bp[4]; b5=bp[5]; }
    snprintf_P(s_diag, sizeof(s_diag), PSTR(
        "[diag] L%d wl=%d sdk=%d op=%d/%d dhcpc=%d dhcps=%d ac=%d l2=%d "
        "ip=%u.%u.%u.%u gw=%u.%u.%u.%u mask=%u.%u.%u.%u rssi=%d ch=%d "
        "bssid=%02x:%02x:%02x:%02x:%02x:%02x heap=%u blk=%u"),
        loopn, (int)WiFi.status(), (int)wifi_station_get_connect_status(),
        (int)wifi_get_opmode(), (int)wifi_get_opmode_default(),
        (int)wifi_station_dhcpc_status(), (int)wifi_softap_dhcps_status(),
        (int)wifi_station_get_auto_connect(), (int)g_l2_assoc,
        a&0xFF,(a>>8)&0xFF,(a>>16)&0xFF,(a>>24)&0xFF,
        g&0xFF,(g>>8)&0xFF,(g>>16)&0xFF,(g>>24)&0xFF,
        m&0xFF,(m>>8)&0xFF,(m>>16)&0xFF,(m>>24)&0xFF,
        (int)WiFi.RSSI(), (int)WiFi.channel(),
        b0,b1,b2,b3,b4,b5,
        (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxFreeBlockSize());
    Serial.println(s_diag);
    // Machine-parseable success marker — ONLY on a genuine working connection (GOT_IP / WL_CONNECTED).
    // The static-fallback sentinel (192.168.15.230 with sdk stuck CONNECTING) must NOT trip this.
    if (wifi_station_get_connect_status() == STATION_GOT_IP && a != 0) {
        snprintf_P(s_diag, sizeof(s_diag), PSTR("[gate] WIFI_OK ip=%u.%u.%u.%u ch=%d rssi=%d src=sdk"),
            a&0xFF,(a>>8)&0xFF,(a>>16)&0xFF,(a>>24)&0xFF, (int)WiFi.channel(), (int)WiFi.RSSI());
        Serial.println(s_diag);
    } else if (WiFi.status() == WL_CONNECTED) {
        uint32_t la = (uint32_t)WiFi.localIP();
        snprintf_P(s_diag, sizeof(s_diag), PSTR("[gate] WIFI_OK ip=%u.%u.%u.%u ch=%d rssi=%d src=poll"),
            la&0xFF,(la>>8)&0xFF,(la>>16)&0xFF,(la>>24)&0xFF, (int)WiFi.channel(), (int)WiFi.RSSI());
        Serial.println(s_diag);
    }
}
static void wifi_diag_netif() {
    for (struct netif* n = netif_list; n; n = n->next) {
        snprintf_P(s_diag, sizeof(s_diag), PSTR("[diag] netif %c%c num=%d flags=0x%02x up=%d ip=%s"),
            n->name[0], n->name[1], (int)n->num, (unsigned)n->flags,
            (int)netif_is_up(n), ipaddr_ntoa(&n->ip_addr));
        Serial.println(s_diag);
    }
    WiFi.printDiag(Serial);
}
#endif

static bool wifi_wait_connected(int maxAttempts) {
    int a = 0, budget = maxAttempts;
    bool extended = false;
    while (WiFi.status() != WL_CONNECTED && a < budget) {
        delay(500);
        a++;
#if WIFI_DEEP_DIAG
        wifi_diag_emit(a);
        if (a % 4 == 0) wifi_diag_netif();   // ~every 2s
#endif
        if (g_l2_assoc && !extended) {          // asocjacja przeszla — daj DHCP dokonczyc
            extended = true;
            budget = a + DHCP_EXTRA_ATTEMPTS;
            LOGI("wifi", "associated — extending wait for DHCP (+%ds)", DHCP_EXTRA_ATTEMPTS / 2);
        }
    }
    return WiFi.status() == WL_CONNECTED;
}

bool wifi_connect(const char* ssid, const char* password) {
    LOGI("wifi", "connecting to %s", ssid);
    // 8266: po trybie portalu (WIFI_AP) SDK wstaje z zapisanym opmode i softAP dalej
    // trzyma radio — samo WiFi.mode(WIFI_STA) tego nie sprząta i stacja wisi w
    // STATION_CONNECTING (status=7, zero eventow). Najpierw zdejmij AP, potem STA.
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
    WiFi.setSleepMode(WIFI_NONE_SLEEP);   // 8266: odpowiednik WiFi.setSleep(false)
    // Force 802.11g PHY. The ESP8266 default (802.11n) has marginal frame reception with some APs:
    // the station associates (STAMODE_CONNECTED fires) but the DHCP OFFER is intermittently dropped,
    // so wifi_station_get_connect_status() stays STATION_CONNECTING and no lease is ever obtained
    // (the static-IP fallback also never yields a working netif). Confirmed on-hardware against
    // GQThePromisedNeverLAN ch9: default 11n ~10-25% GOT_IP, forced 11g 17/17. Throughput is
    // irrelevant for this small-telemetry node, and 11g RX is more robust on the ESP8266.
    WiFi.setPhyMode(WIFI_PHY_MODE_11G);
    delay(100);                            // daj SDK dokonczyc zmiane trybu
    wifi_apply_country();    // kanały 12-13 (EU)
    g_last_disc_reason = 0;
    g_l2_assoc = false;
    // 8266: handler eventu musi ŻYĆ (WiFiEventHandler) — static, rejestracja raz.
    // Kody reason NONOS SDK są zgodne z ESP32 (2/15/201/202...).
    static WiFiEventHandler s_evt_disc, s_evt_conn, s_evt_ip, s_evt_dhcpto;
    if (!s_evt_disc) {
        s_evt_disc = WiFi.onStationModeDisconnected([](const WiFiEventStationModeDisconnected& e) {
            g_last_disc_reason = (uint8_t)e.reason;
        });
        // Rozdzielenie L2 vs DHCP: STATION_CONNECTING trzyma sie tak samo, gdy asocjacja
        // nie ruszyla, jak i gdy przeszla, ale nie przyszedl adres. Te trzy eventy mowia
        // ktora to sytuacja — bez nich reason=0/status=7 jest nieodroznialne.
        s_evt_conn = WiFi.onStationModeConnected([](const WiFiEventStationModeConnected& e) {
            g_l2_assoc = true;
            LOGI("wifi", "L2 ASSOCIATED to '%s' ch%d — waiting for DHCP", e.ssid.c_str(), e.channel);
        });
        s_evt_ip = WiFi.onStationModeGotIP([](const WiFiEventStationModeGotIP& e) {
            LOGI("wifi", "DHCP lease %s", e.ip.toString().c_str());
        });
        s_evt_dhcpto = WiFi.onStationModeDHCPTimeout([]() {
            LOGE("wifi", "DHCP TIMEOUT — associated but the AP never leased an address");
        });
    }
    // Skan na CZYSTYM radiu PRZED connectem (skan PO begin zwracał fałszywe 0). ROBUST: łączymy
    // do AP który REALNIE widzimy — dopasowanie luźne (trim+case-insensitive), potem connect po
    // DOKŁADNYCH bajtach + BSSID + kanale tego AP. Omija każdą różnicę w SSID (spacja/unicode/
    // ukryty znak/literówka — po którejkolwiek stronie). Hex zapisanego SSID obnaża ukryty znak.
    WiFi.scanDelete();
    int n = WiFi.scanNetworks(false, true);
    LOGI("wifi", "scan: %d APs visible", n < 0 ? 0 : n);
    char want[64]; strncpy(want, ssid ? ssid : "", sizeof(want)-1); want[sizeof(want)-1]=0; trim_ws(want);
    { char hx[130] = ""; for (size_t k = 0; ssid && ssid[k] && k < 32; k++) sprintf_P(hx+strlen(hx), PSTR("%02X "), (uint8_t)ssid[k]);
      LOGI("wifi", "cfg SSID hex: %s(len %d)", hx, ssid ? (int)strlen(ssid) : 0); }
    // Hasła NIE trimujemy (spacja bywa legalną częścią WPA), więc doklejona przez klawiaturę/
    // autouzupełnianie jest niewidoczna i daje reason=15 nie do odróżnienia od literówki.
    // Logujemy SAMĄ DŁUGOŚĆ (nigdy treści) + jawne ostrzeżenie o spacji na brzegu.
    { size_t pl = password ? strlen(password) : 0;
      bool edge_sp = pl && (password[0] == ' ' || password[pl-1] == ' ');
      LOGI("wifi", "cfg password len=%u%s", (unsigned)pl,
           edge_sp ? "  <-- WARNING: leading/trailing space in password!" : ""); }
    // Dopasowanie 3-poziomowe do WIDZIANEGO AP (łączymy potem po jego BSSID):
    //   exact  = bajt-w-bajt,
    //   loose  = trim brzegów, case-SENSITIVE (whitespace na brzegach),
    //   fuzzy  = bez WSZYSTKICH spacji + lowercase (ostatnia deska — pomyłka w spacjach/wielkości).
    // Priorytet exact>loose>fuzzy; wśród pasujących (mesh/2 pasma) NAJSILNIEJSZY.
    // Nie łapie ukrytego SSID (w skanie pusty) — ten idzie fallbackiem WiFi.begin(dokładna nazwa).
    char wantN[64]; norm_ssid(wantN, sizeof(wantN), ssid);
    int exactIdx = -1, exactR = -999, looseIdx = -1, looseR = -999, fuzzyIdx = -1, fuzzyR = -999;
    for (int i = 0; i < n; i++) {   // iterate all scan results (was capped at 20 — missed APs beyond index 20)
        String s = WiFi.SSID(i);
        bool em = (s == ssid);
        char g[64]; strncpy(g, s.c_str(), sizeof(g)-1); g[sizeof(g)-1]=0; trim_ws(g);
        bool lm = !em && (strcmp(g, want) == 0);   // case-sensitive: nie łapie sąsiada o innym case
        char gN[64]; norm_ssid(gN, sizeof(gN), s.c_str());
        bool fm = !em && !lm && gN[0] && (strcmp(gN, wantN) == 0);   // bez spacji + lowercase
        int r = WiFi.RSSI(i);
        if (em && r > exactR) { exactIdx = i; exactR = r; }
        else if (lm && r > looseR) { looseIdx = i; looseR = r; }
        else if (fm && r > fuzzyR) { fuzzyIdx = i; fuzzyR = r; }
        LOGI("wifi", "  %s%s rssi=%d ch=%d enc=%d",
             em ? "*>" : (lm ? "~>" : (fm ? "?>" : "  ")), s.c_str(), r, WiFi.channel(i), (int)WiFi.encryptionType(i));
    }
    bool exact = (exactIdx >= 0);
    int matchIdx = exact ? exactIdx : (looseIdx >= 0 ? looseIdx : fuzzyIdx);   // exact>loose>fuzzy
    // Zapamiętaj dane dopasowanego AP PRZED scanDelete (potem WiFi.SSID/BSSID znikają)
    char apSsid[64] = ""; uint8_t apBssid[6] = {0}; int apCh = 0; bool haveMatch = (matchIdx >= 0);
    if (haveMatch) { strncpy(apSsid, WiFi.SSID(matchIdx).c_str(), sizeof(apSsid)-1);
                     memcpy(apBssid, WiFi.BSSID(matchIdx), 6); apCh = WiFi.channel(matchIdx); }
    LOGI("wifi", "target '%s' %s", ssid,
         exact ? "VISIBLE" : (haveMatch ? "LOOSE-MATCH - SSID differs byte-wise, connecting by BSSID"
                                        : "NOT VISIBLE (5GHz-only? out of range? hidden?)"));
    WiFi.scanDelete();

    // ── Próby połączenia ──
    // Wyczysc stan stacji PRZED begin(): bez tego SDK potrafi dalej probowac starego
    // SSID (auto-connect z flasha) i nasz begin() nigdy nie dochodzi do skutku.
    WiFi.disconnect(true);
    delay(100);
    const char* connName = ssid;   // nazwa, którą realnie się połączyliśmy (do g_wifi_ssid)
    if (haveMatch && !exact) {
        LOGW("wifi", "connect via seen AP '%s' ch%d BSSID %02X:%02X:%02X:%02X:%02X:%02X (saved SSID byte-mismatch)",
             apSsid, apCh, apBssid[0],apBssid[1],apBssid[2],apBssid[3],apBssid[4],apBssid[5]);
        WiFi.begin(apSsid, password, apCh, apBssid);
        connName = apSsid;
    } else {
        WiFi.begin(ssid, password);   // dokładna nazwa — obsługuje też UKRYTY SSID (supplicant probuje)
    }
    bool ok = wifi_wait_connected(40);   // ~20s (+45s gdy asocjacja przeszla)

#if WIFI_STATIC_FALLBACK
    // Asocjacja OK, ale AP nie dal adresu — sprobuj raz ze statykiem zamiast restartowac.
    if (!ok && g_l2_assoc) {
        LOGW("wifi", "associated but no DHCP lease — retrying with a static address");
        WiFi.config(IPAddress(WIFI_STATIC_IP), IPAddress(WIFI_STATIC_GW),
                    IPAddress(WIFI_STATIC_MASK), IPAddress(WIFI_STATIC_DNS));
        WiFi.begin(ssid, password);
        ok = wifi_wait_connected(30);   // ~15s — bez DHCP powinno byc natychmiast
        if (!ok) WiFi.config(IPAddress(0,0,0,0), IPAddress(0,0,0,0), IPAddress(0,0,0,0));  // wroc do DHCP
    }
#endif

    // UKRYTY SSID z inną liczbą spacji niż user wpisał: brak widocznego dopasowania + SSID ma
    // wewnętrzne spacje → próba bez spacji (case zachowany — ukryty AP wymaga dokładnej nazwy).
    // Jak zaskoczy, zapisz poprawioną nazwę → następny boot łączy od razu (bez tej próby).
    if (!ok && !haveMatch) {
        char noSp[64]; strip_spaces(noSp, sizeof(noSp), ssid);
        if (noSp[0] && strcmp(noSp, ssid) != 0) {
            LOGW("wifi", "hidden? retry without space: '%s'", noSp);
            WiFi.disconnect(false); delay(200);
            WiFi.begin(noSp, password);
            ok = wifi_wait_connected(30);   // ~15s
            if (ok) {
                connName = noSp;
                Preferences p; p.begin("sensmos_wifi", false); p.putString("ssid", noSp); p.end();
                LOGI("wifi", "saved corrected SSID: '%s'", noSp);
            }
        }
    }

    if (ok && WiFi.status() == WL_CONNECTED) {
        g_wifi_connected = true;
        WiFi.setAutoReconnect(true);   // 0.74: driver też sam próbuje po zerwaniu (obok wifi_maintain)
        strncpy(g_wifi_ssid, connName, sizeof(g_wifi_ssid));
        strncpy(g_local_ip, WiFi.localIP().toString().c_str(), sizeof(g_local_ip));
        LOGI("wifi", "connected, ip %s", g_local_ip);
        wifi_setup_mdns();
        return true;
    }

    // reason= z eventu (wiarygodne — złe hasło daje 15, brak sieci 201). Skan wyżej (pre-connect).
    // reason=0 znaczy, że NIE przyszedł żaden event rozłączenia — sama asocjacja nie ruszyła.
    // Wtedy status()/heap są jedyną diagnostyką (8266: handshake WPA2 alokuje z ciasnego heapu).
    LOGW("wifi", "connect failed reason=%u (%s) status=%d sdk_status=%d opmode=%d heap=%uk blk=%uk",
         g_last_disc_reason, wifi_reason_name(g_last_disc_reason), (int)WiFi.status(),
         (int)wifi_station_get_connect_status(), (int)wifi_get_opmode(),
         ESP.getFreeHeap() / 1024, ESP.getMaxFreeBlockSize() / 1024);
    // sdk_status: 0 IDLE 1 CONNECTING 2 WRONG_PASSWORD 3 NO_AP_FOUND 4 CONNECT_FAIL 5 GOT_IP.
    // opmode: 1 STA 2 AP 3 STA+AP — 2/3 tutaj znaczy, ze softAP nadal trzyma radio.
    WiFi.printDiag(Serial);
    g_wifi_connected = false;
    return false;
}

// ── Watchdog WiFi (0.74) — wołany co pętlę z loop() w trybie node ──────────────────────────
// Do 0.73 FW łączył się solidnie TYLKO przy boocie — w trakcie działania NIE było odzyskiwania:
// po restarcie routera (nocny reboot / drop ISP) node wisiał offline aż do wyjęcia z prądu
// (potwierdzone na flocie: nody padały ~co noc o stałej godzinie = zaplanowany reboot routera).
// Teraz: co 5s sprawdzamy link; przy zerwaniu WiFi.reconnect() co 20s (szybka ścieżka), a po
// WIFI_DOWN_REBOOT_MS twardy ESP.restart() — czysty boot odpala pełny scan-connect, który ogarnia
// zmianę kanału/BSSID po reboocie routera (reconnect() bywa przypięty do starego BSSID).
#ifndef WIFI_DOWN_REBOOT_MS
#define WIFI_DOWN_REBOOT_MS (4UL * 60 * 1000)   // 4 min bez sieci → reboot (batch i tak co ~kilka min)
#endif
void wifi_maintain() {
    static unsigned long s_lost = 0, s_lastTry = 0, s_lastCheck = 0;
    unsigned long now = millis();
    if (now - s_lastCheck < 5000) return;   // sprawdzaj co 5s (tanie)
    s_lastCheck = now;
    if (WiFi.status() == WL_CONNECTED) {
        if (s_lost) { LOGI("wifi", "link back up"); s_lost = 0; g_wifi_connected = true; }
        return;
    }
    g_wifi_connected = false;
    if (!s_lost) { s_lost = now; s_lastTry = 0; LOGW("wifi", "link DOWN — recovering"); }
    unsigned long down = now - s_lost;
    if (now - s_lastTry >= 20000) {         // co 20s próba reconnect (bez reboota)
        s_lastTry = now;
        WiFi.reconnect();
        LOGW("wifi", "reconnect() (down %lus)", down / 1000);
    }
    if (down >= WIFI_DOWN_REBOOT_MS) {      // twardy fallback
        LOGE("wifi", "WiFi down %lus — ESP.restart()", down / 1000);
        delay(200);
        ESP.restart();
    }
}

bool wifi_init() {
    if (!wifi_has_config()) {
        LOGW("wifi", "no config — needs BLE provisioning");
        return false;
    }

    Preferences prefs;
    prefs.begin("sensmos_wifi", true);
    char ssid[64]     = {0};
    char password[64] = {0};
    prefs.getString("ssid",     ssid,     sizeof(ssid));
    prefs.getString("password", password, sizeof(password));
    prefs.end();

    return wifi_connect(ssid, password);
}

// ── mDNS — wykrywalność w sieci lokalnej (dla apki) ───────────
void wifi_setup_mdns() {
    // Nazwa hosta: sensmos-XXXXXX (6 znaków device_id)
    char hostname[32];
    snprintf_P(hostname, sizeof(hostname), PSTR("sensmos-%.6s"), g_device_id);

    if (MDNS.begin(hostname)) {
        // Ogłoś usługę sensmos przez mDNS
        MDNS.addService("sensmos", "tcp", 80);
        MDNS.addServiceTxt("sensmos", "tcp", "device_id", (const char*)g_device_id);
        MDNS.addServiceTxt("sensmos", "tcp", "version", (const char*)FW_VERSION);
        // Standardowy HTTP też
        MDNS.addService("http", "tcp", 80);
        LOGI("wifi", "mDNS: %s.local", hostname);
    } else {
        LOGW("wifi", "mDNS start failed");
    }
}