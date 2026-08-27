// ws_enc.cpp — ESP8266 port: mbedtls ECDH/HKDF/GCM → micro-ecc + BearSSL.
// Ramka i derywacja klucza BYTE-IDENTICAL z wersją ESP32 (kompatybilność BE):
// klucz = HKDF-SHA256( ECDH(node_priv, BE_pub).X, salt = fw_nonce||be_nonce ),
// ramka [0x01|seq(8 BE)|tag(16)|ct] = AES-128-GCM, IV = 0x00000000||seq, AAD = ramka[0..9).
#include "ws_enc.h"
#include "identity.h"
#include "log.h"
#include <string.h>
#include <bearssl/bearssl.h>
#include <uECC.h>

static bool     s_ready   = false;
static uint8_t  s_key_tx[16] = {0};   // FW→BE
static uint8_t  s_key_rx[16] = {0};   // BE→FW
static uint64_t s_seq_tx  = 0;
static uint64_t s_seq_rx  = 0;
static bool     s_rx_init = false;

void ws_enc_reset() {
    s_ready = false; s_seq_tx = 0; s_seq_rx = 0; s_rx_init = false;
    memset(s_key_tx, 0, 16); memset(s_key_rx, 0, 16);
}
bool ws_enc_active() { return s_ready; }

static void hmac_sha256(const uint8_t* key, size_t klen,
                        const uint8_t* d, size_t dlen, uint8_t out[32]) {
    br_hmac_key_context kc;
    br_hmac_key_init(&kc, &br_sha256_vtable, key, klen);
    br_hmac_context hc;
    br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, d, dlen);
    br_hmac_out(&hc, out);
}

// ECDH(node_priv, BE_pub) → shared.X, potem HKDF-SHA256 → dwa podklucze 16B.
// FW: tx = okm[0:16] (FW→BE), rx = okm[16:32] (BE→FW). BE bierze odwrotnie.
bool ws_enc_derive(const uint8_t fw_nonce[16], const uint8_t be_nonce[16]) {
    ws_enc_reset();
    uint8_t be_pub[65];
    if (!identity_be_pubkey(be_pub)) { LOGE("wsenc", "no BE pubkey"); return false; }

    // uECC przyjmuje pubkey bez prefiksu 0x04 (64B); wynik = współrzędna X (32B),
    // identycznie jak mbedtls_ecdh_compute_shared.
    uint8_t shared[32];
    if (uECC_shared_secret(be_pub + 1, g_privkey, shared, uECC_secp256k1()) != 1) {
        LOGE("wsenc", "ECDH failed");
        return false;
    }

    // HKDF-SHA256 (extract + jedno expand — L=32 = hashlen)
    uint8_t salt[32]; memcpy(salt, fw_nonce, 16); memcpy(salt + 16, be_nonce, 16);
    uint8_t prk[32];  hmac_sha256(salt, 32, shared, 32, prk);
    const char* istr = "sensmos-ws-v1"; size_t il = strlen(istr);
    uint8_t info[16]; memcpy(info, istr, il); info[il] = 0x01;
    uint8_t okm[32];  hmac_sha256(prk, 32, info, il + 1, okm);
    memcpy(s_key_tx, okm, 16);
    memcpy(s_key_rx, okm + 16, 16);

    s_ready = true;
    LOGI("wsenc", "session key derived");
    return true;
}

static void put_seq(uint8_t* p, uint64_t seq) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(seq >> (8 * (7 - i))); }
static uint64_t get_seq(const uint8_t* p) { uint64_t s = 0; for (int i = 0; i < 8; i++) s = (s << 8) | p[i]; return s; }

// BearSSL GCM: br_gcm_run szyfruje IN-PLACE; encrypt=1, decrypt=0;
// br_gcm_check_tag zwraca 1 przy poprawnym tagu.
static bool gcm_frame(const uint8_t key[16], const uint8_t iv[12],
                      const uint8_t* aad, size_t aad_len,
                      uint8_t* data, size_t len, int encrypt, uint8_t tag[16]) {
    br_aes_ct_ctr_keys bc;
    br_aes_ct_ctr_init(&bc, key, 16);
    br_gcm_context gc;
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);
    br_gcm_reset(&gc, iv, 12);
    br_gcm_aad_inject(&gc, aad, aad_len);
    br_gcm_flip(&gc);
    br_gcm_run(&gc, encrypt, data, len);
    if (encrypt) { br_gcm_get_tag(&gc, tag); return true; }
    return br_gcm_check_tag(&gc, tag) == 1;
}

int ws_enc_seal(const uint8_t* pt, size_t pt_len, uint8_t* out, size_t out_cap) {
    if (!s_ready) return -1;
    size_t need = 25 + pt_len;
    if (need > out_cap) return -1;
    out[0] = 0x01; put_seq(out + 1, s_seq_tx);
    uint8_t iv[12] = {0}; memcpy(iv + 4, out + 1, 8);   // IV = 0x00000000 || seq(8)
    uint8_t* tag = out + 9;
    uint8_t* ct  = out + 25;
    memcpy(ct, pt, pt_len);                              // GCM in-place na ct
    if (!gcm_frame(s_key_tx, iv, out, 9, ct, pt_len, 1, tag)) return -1;
    s_seq_tx++;
    return (int)need;
}

int ws_enc_open(const uint8_t* frame, size_t len, uint8_t* out, size_t out_cap) {
    if (!s_ready) return -1;
    if (len < 25 || frame[0] != 0x01) return -1;
    uint64_t seq = get_seq(frame + 1);
    if (s_rx_init && seq <= s_seq_rx) return -1;         // replay / reorder
    size_t ct_len = len - 25;
    if (ct_len > out_cap) return -1;
    uint8_t iv[12] = {0}; memcpy(iv + 4, frame + 1, 8);
    uint8_t tag[16]; memcpy(tag, frame + 9, 16);
    memcpy(out, frame + 25, ct_len);                     // GCM in-place na out
    if (!gcm_frame(s_key_rx, iv, frame, 9, out, ct_len, 0, tag)) return -1;
    s_seq_rx = seq; s_rx_init = true;
    return (int)ct_len;
}
