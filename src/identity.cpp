// identity.cpp — ESP8266 port: mbedtls ECDSA → micro-ecc (uECC) + BearSSL SHA256.
// Wire format unchanged: secp256k1, uncompressed 65B pubkey, DER-encoded signatures.
#include "identity.h"
#include "log.h"
#include "esp_random.h"
#include <bearssl/bearssl.h>
#include <uECC.h>

uint8_t g_privkey[32]    = {0};
uint8_t g_pubkey[65]     = {0};
char    g_device_id[67]  = {0};
char    g_eth_address[43]= {0};
char    g_api_token[65]  = {0};

void bytes_to_hex(const uint8_t* bytes, size_t len, char* out) {
    for (size_t i = 0; i < len; i++) {
        sprintf_P(out + i * 2, PSTR("%02x"), bytes[i]);
    }
    out[len * 2] = '\0';
}

void sha256_string(const char* input, uint8_t* output) {
    br_sha256_context ctx;
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, (const uint8_t*)input, strlen(input));
    br_sha256_out(&ctx, output);
}

static void compute_eth_address(const uint8_t* pubkey65) {
    uint8_t hash[32];
    br_sha256_context ctx;
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, pubkey65 + 1, 64);
    br_sha256_out(&ctx, hash);
    g_eth_address[0] = '0';
    g_eth_address[1] = 'x';
    bytes_to_hex(hash + 12, 20, g_eth_address + 2);
}

static void compute_device_id() {
    char input[200];
    char pubkey_hex[131];
    bytes_to_hex(g_pubkey, 65, pubkey_hex);
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char mac_hex[13];
    bytes_to_hex(mac, 6, mac_hex);
    snprintf_P(input, sizeof(input), PSTR("%s%s"), pubkey_hex, mac_hex);
    uint8_t hash[32];
    sha256_string(input, hash);
    bytes_to_hex(hash, 32, g_device_id);
}

// ── uECC plumbing ─────────────────────────────────────────────
static int uecc_rng(uint8_t* dest, unsigned size) {
    esp_fill_random(dest, size);
    return 1;
}

// BearSSL-backed uECC_HashContext — enables deterministic (RFC6979-style) k,
// eliminating nonce-reuse risk from the HW RNG.
struct BrShaHash {
    uECC_HashContext uECC;
    br_sha256_context ctx;
    uint8_t tmp[128];
};
static void br_init_hash(const uECC_HashContext* base) {
    br_sha256_init(&((BrShaHash*)base)->ctx);
}
static void br_update_hash(const uECC_HashContext* base, const uint8_t* message, unsigned message_size) {
    br_sha256_update(&((BrShaHash*)base)->ctx, message, message_size);
}
static void br_finish_hash(const uECC_HashContext* base, uint8_t* hash_result) {
    br_sha256_out(&((BrShaHash*)base)->ctx, hash_result);
}

// Minimalny koder DER: SEQUENCE(INTEGER r, INTEGER s). Strip wiodących zer,
// prepend 0x00 gdy najwyższy bit ustawiony (ASN.1). Max 72B — jak mbedtls.
static size_t der_encode_int(const uint8_t v[32], uint8_t* dst) {
    size_t skip = 0;
    while (skip < 31 && v[skip] == 0) skip++;
    size_t len = 32 - skip;
    bool pad = (v[skip] & 0x80) != 0;
    dst[0] = 0x02;
    dst[1] = (uint8_t)(len + (pad ? 1 : 0));
    size_t o = 2;
    if (pad) dst[o++] = 0x00;
    memcpy(dst + o, v + skip, len);
    return o + len;
}
static size_t der_encode_sig(const uint8_t rs[64], uint8_t* out) {
    uint8_t body[72];
    size_t n = der_encode_int(rs, body);
    n += der_encode_int(rs + 32, body + n);
    out[0] = 0x30;
    out[1] = (uint8_t)n;
    memcpy(out + 2, body, n);
    return n + 2;
}

bool identity_set_override(const char* id) {
    if (!id || strlen(id) != 64) return false;
    char norm[67];
    for (int i = 0; i < 64; i++) {
        char c = tolower((unsigned char)id[i]);
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        norm[i] = c;
    }
    norm[64] = 0;
    Preferences p; p.begin("sensmos", false);
    p.putString("id_ovr", norm);
    p.end();
    strlcpy(g_device_id, norm, sizeof(g_device_id));
    LOGI("id", "device_id override set: %.16s…", g_device_id);
    return true;
}

bool identity_regenerate_token() {
    uint8_t token_bytes[32];
    esp_fill_random(token_bytes, 32);
    bytes_to_hex(token_bytes, 32, g_api_token);
    Preferences prefs;
    prefs.begin("sensmos", false);
    prefs.putBytes("api_token", token_bytes, 32);
    prefs.end();
    LOGD("id", "new API token generated");
    return true;
}

bool identity_init() {
    uECC_set_rng(uecc_rng);

    Preferences prefs;
    prefs.begin("sensmos", false);
    bool has_key = prefs.isKey("privkey");

    if (!has_key) {
        LOGI("id", "generating new keypair (uECC secp256k1)...");
        uint8_t pub64[64];
        bool ok = false;
        for (int t = 0; t < 4 && !ok; t++) {
            ok = uECC_make_key(pub64, g_privkey, uECC_secp256k1()) == 1;
            yield();
        }
        if (!ok) { prefs.end(); LOGE("id", "uECC_make_key failed"); return false; }
        g_pubkey[0] = 0x04;
        memcpy(g_pubkey + 1, pub64, 64);

        prefs.putBytes("privkey", g_privkey, 32);
        prefs.putBytes("pubkey",  g_pubkey,  65);
        LOGD("id", "keypair saved");
    } else {
        prefs.getBytes("privkey", g_privkey, 32);
        prefs.getBytes("pubkey",  g_pubkey,  65);
        LOGD("id", "keypair loaded");
    }

    if (!prefs.isKey("api_token")) {
        uint8_t token_bytes[32];
        esp_fill_random(token_bytes, 32);
        bytes_to_hex(token_bytes, 32, g_api_token);
        prefs.putBytes("api_token", token_bytes, 32);
    } else {
        uint8_t token_bytes[32];
        prefs.getBytes("api_token", token_bytes, 32);
        bytes_to_hex(token_bytes, 32, g_api_token);
    }

    // Override device_id (odtworzenie tożsamości z apki po reflashu): stały ID noda,
    // klucze świeże. Czyszczone przy factory reset (clear NS "sensmos").
    String ovr = prefs.getString("id_ovr", "");
    prefs.end();
    compute_device_id();
    if (ovr.length() == 64) {
        strlcpy(g_device_id, ovr.c_str(), sizeof(g_device_id));
        LOGI("id", "device_id restored from override");
    }
    compute_eth_address(g_pubkey);

    // Self-test podpisu przy starcie: znany hash → sign → verify + DER re-parse.
    {
        uint8_t h[32]; sha256_string("sensmos-esp8266-selftest", h);
        uint8_t der[72]; size_t dl = 0;
        if (!identity_sign(h, der, &dl) || dl < 8 || der[0] != 0x30 || der[1] != dl - 2) {
            LOGE("id", "sign self-test FAILED");
            return false;
        }
        LOGI("id", "sign self-test OK (DER %uB)", (unsigned)dl);
    }

    LOGI("id", "device %s", g_device_id);
    LOGI("id", "wallet %s", g_eth_address);
    return true;
}

bool identity_sign(const uint8_t* hash, uint8_t* sig_out, size_t* sig_len) {
    uint8_t rs[64];
    BrShaHash hctx;
    hctx.uECC.init_hash   = br_init_hash;
    hctx.uECC.update_hash = br_update_hash;
    hctx.uECC.finish_hash = br_finish_hash;
    hctx.uECC.block_size  = 64;
    hctx.uECC.result_size = 32;
    hctx.uECC.tmp         = hctx.tmp;

    int ok = uECC_sign_deterministic(g_privkey, hash, 32, &hctx.uECC, rs, uECC_secp256k1());
    if (ok != 1) {
        // Fallback: RNG-based k (HW RNG). Logowane — jakość k zależna od RNG.
        LOGW("id", "deterministic sign failed — falling back to RNG k");
        ok = uECC_sign(g_privkey, hash, 32, rs, uECC_secp256k1());
        if (ok != 1) return false;
    }
    if (uECC_verify(g_pubkey + 1, hash, 32, rs, uECC_secp256k1()) != 1) {
        LOGE("id", "self-verify failed");
        return false;
    }
    *sig_len = der_encode_sig(rs, sig_out);
    return true;
}

// Klucz publiczny BE (secp256k1 uncompressed) — wbudowany. Do ECDH sesji WS (ws_enc):
// shared = ECDH(node_priv, BE_pub). Publiczny → bezpieczny w firmware; priv trzyma tylko
// serwer (.env BE_SIGN_PRIV, ta sama para co dawniej podpisywała komendy K3).
static const char* BE_PUBKEY_HEX =
    "042e5d120dcd4324edb14b7a694b0868f1df9ef0f3b8ecd7580702482413f58183b6f10b55ea2b643cfcf01880ef120db3cfadbda87f62c487b458d0a3000d5117";

bool identity_be_pubkey(uint8_t out[65]) {
    for (int i = 0; i < 65; i++) { unsigned v; if (sscanf(BE_PUBKEY_HEX + i*2, "%2x", &v) != 1) return false; out[i] = (uint8_t)v; }
    return true;
}

void identity_get_pubkey_hex(char* out, size_t len) {
    bytes_to_hex(g_pubkey, 65, out);
}
