# Bug: Generic-math (SP_MATH_ALL fallback) P-384 ECDSA verify fails with ASN_SIG_CONFIRM_E (-155) on Xtensa LX106

Prepared for filing against `wolfssl/wolfssl`. All evidence collected on real hardware.

## Environment

- wolfSSL **5.7.2** (`LIBWOLFSSL_VERSION_STRING "5.7.2"`, `LIBWOLFSSL_VERSION_HEX 0x05007002`), PlatformIO package `wolfssl/wolfssl@^5.7.2`
- Platform: **ESP8266 (Xtensa LX106, 32-bit, 160 MHz)**, NodeMCU v2
- Framework: Arduino core 3.1.2 (`framework-arduinoespressif8266 3.30102.0`), NONOS SDK 2.2.x
- Toolchain: xtensa-lx106-elf-gcc 10.3.0
- Relevant build config (`WOLFSSL_USER_SETTINGS`):
  `SINGLE_THREADED, NO_FILESYSTEM, WOLFSSL_SMALL_STACK, NO_OLD_TLS, WOLFSSL_TLS13,
  HAVE_HKDF, WC_RSA_PSS, NO_DH, NO_PSK, HAVE_ECC, ECC_USER_CURVES, HAVE_ECC256,
  HAVE_ECC384, HAVE_AESGCM, RSA_LOW_MEM, WOLFSSL_USER_IO, WOLFSSL_NO_SOCK, HAVE_SNI,
  HAVE_TLS_EXTENSIONS, HAVE_SUPPORTED_CURVES, WOLFSSL_HAVE_SP_ECC, WOLFSSL_HAVE_SP_RSA,
  WOLFSSL_SHA384, WOLFSSL_ALT_CERT_CHAINS` — math backend is the default
  `WOLFSSL_SP_MATH_ALL` (generic `sp_int`); **`WOLFSSL_SP_384` NOT defined**, so P-384
  field arithmetic takes the generic fallback path (`ecc.c` `#if !defined(WOLFSSL_SP_MATH)`
  branch → `wc_ecc_mulmod_ex` and friends on generic `sp_int`).

## Problem

With `HAVE_ECC384` enabled and the generic math fallback in use, **every** ECDSA P-384
signature verification during TLS certificate-chain processing fails with
`ASN_SIG_CONFIRM_E` (-155), for a chain that OpenSSL validates cleanly. The failure is
deterministic — 26 consecutive handshake attempts, 26 identical failures.

The server chain is Let's Encrypt's 2026 ECDSA hierarchy (all P-384/SHA-384 signatures):
`leaf (P-256 key, ecdsa-with-SHA384 sig) <- YE2 (P-384) <- Root YE (P-384) <- [X2 cross]`.
Cross-validation: `openssl verify -CAfile isrg-root-x2.pem -untrusted intermediates.pem
leaf.pem` → `OK` on the same captured chain.

## Steps to reproduce

1. Build a TLS 1.3 client with the config above (P-384 enabled, no `WOLFSSL_SP_384`).
2. Load ISRG Root X2 (or Root YE) as the trust anchor, `WOLFSSL_VERIFY_PEER`.
3. `wolfSSL_connect()` to a server presenting a P-384-signed chain
   (e.g. any current Let's Encrypt "Root YE" hierarchy site).
4. Handshake fails at certificate processing with -155.

## Expected / Actual

- Expected: chain verifies (it is valid; OpenSSL agrees).
- Actual: `ConfirmSignature` returns -155 at the first CA verification.

## DEBUG_WOLFSSL trace (verbatim, on-device)

```
[wolfd] wolfSSL Entering DecodeCrlDist
[wolfd] CA found
[wolfd] wolfSSL Entering ConfirmSignature
[wolfd] wolfSSL Leaving ConfirmSignature, return -155
[wolfd] Confirm signature failed
[wolfd] Failed to verify CA from chain
[wolfd] wolfSSL error occurred, error = -155
[wolfd] wolfSSL Entering SendAlert
[wolfd] SendAlert: 42 bad_certificate
[wolfd] wolfSSL Leaving ProcessPeerCerts, return -155
[wolfd] wolfSSL Leaving DoTls13Certificate, return -155
```

## Workaround (confirmed)

Defining **`WOLFSSL_SP_384`** (dedicated single-precision P-384 implementation,
`sp_c32.c`) makes the identical chain verify successfully — same device, same server,
same anchor. This isolates the fault to the generic-math P-384 path.

## Secondary performance observation

With `WOLFSSL_SP_384` **plus `WOLFSSL_SP_SMALL`**, a single P-384 ECDSA verification
exceeds ~6 s of uninterrupted computation at 160 MHz — on the ESP8266 this trips the
non-disableable hardware watchdog (~8.4 s) once two verifications occur in one
`wolfSSL_connect`, producing a reset loop (`rst cause:4`). Without `WOLFSSL_SP_SMALL`,
a P-384 verify is ~2.7 s. Worth a documentation note for constrained 32-bit targets.

## Analysis pointer

The generic path produces a *wrong verification result* (not a resource error — the
device had >10 KB free heap at failure, and smaller P-256 operations on the same
generic backend behave correctly for key exchange when SP is disabled for them).
Suspect the generic `sp_int` P-384 field arithmetic on 32-bit Xtensa
(carry/normalization at the 384-bit boundary with `SP_INT_BITS`-sized words shared
with RSA-3072 sizing). Full serial captures and the exact `user_settings.h` available
on request.
