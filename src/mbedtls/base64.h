#pragma once
// Shim: mbedtls/base64.h → libb64 (bundled with the ESP8266 Arduino core).
#include <stddef.h>
#include <string.h>
#include <libb64/cencode.h>
#include <libb64/cdecode.h>

#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL -0x002A
#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER -0x002C

static inline int mbedtls_base64_encode(unsigned char* dst, size_t dlen, size_t* olen,
                                        const unsigned char* src, size_t slen) {
    size_t need = ((slen + 2) / 3) * 4 + 1;
    *olen = need - 1;
    if (dlen < need) return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
    base64_encodestate st; base64_init_encodestate(&st);
    int n = base64_encode_block((const char*)src, slen, (char*)dst, &st);
    n += base64_encode_blockend((char*)dst + n, &st);
    while (n > 0 && (dst[n - 1] == '\n' || dst[n - 1] == '\r')) n--;
    dst[n] = 0;
    *olen = (size_t)n;
    return 0;
}

static inline int mbedtls_base64_decode(unsigned char* dst, size_t dlen, size_t* olen,
                                        const unsigned char* src, size_t slen) {
    size_t maxout = (slen / 4) * 3 + 3;
    if (dlen < maxout) return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
    base64_decodestate st; base64_init_decodestate(&st);
    int n = base64_decode_block((const char*)src, slen, (char*)dst, &st);
    if (n < 0) return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
    *olen = (size_t)n;
    return 0;
}
