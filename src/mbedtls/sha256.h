#pragma once
// Shim: mbedtls/sha256.h → BearSSL (bundled with the ESP8266 Arduino core).
// Only the call surface upstream uses (init/starts/update/finish/free).
#include <bearssl/bearssl.h>

typedef br_sha256_context mbedtls_sha256_context;

static inline void mbedtls_sha256_init(mbedtls_sha256_context* ctx) { (void)ctx; }
static inline int  mbedtls_sha256_starts(mbedtls_sha256_context* ctx, int is224) {
    (void)is224; br_sha256_init(ctx); return 0;
}
static inline int mbedtls_sha256_update(mbedtls_sha256_context* ctx, const unsigned char* input, size_t ilen) {
    br_sha256_update(ctx, input, ilen); return 0;
}
static inline int mbedtls_sha256_finish(mbedtls_sha256_context* ctx, unsigned char output[32]) {
    br_sha256_out(ctx, output); return 0;
}
static inline void mbedtls_sha256_free(mbedtls_sha256_context* ctx) { (void)ctx; }
