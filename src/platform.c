#include "platform.h"
#include <string.h>
#include <stdint.h>

#ifdef __APPLE__
/* ─── macOS: CommonCrypto ──────────────────────────────────────────────── */
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonDigest.h>

void platform_hmac_sha256(const void *key, size_t key_len,
                           const void *data, size_t data_len,
                           unsigned char out[32]) {
    CCHmac(kCCHmacAlgSHA256, key, key_len, data, data_len, out);
}

void platform_pbkdf2_sha256(const char *password, size_t pwd_len,
                              const unsigned char *salt, size_t salt_len,
                              unsigned int iterations,
                              unsigned char *out, size_t out_len) {
    CCKeyDerivationPBKDF(kCCPBKDF2,
                         password, pwd_len,
                         salt,     salt_len,
                         kCCPRFHmacAlgSHA256, iterations,
                         out, out_len);
}

void platform_random(void *buf, size_t len) {
    arc4random_buf(buf, len);
}

void platform_sha256(const void *data, size_t data_len, unsigned char out[32]) {
    CC_SHA256(data, (CC_LONG)data_len, out);
}

#else
/* ─── Linux: OpenSSL ───────────────────────────────────────────────────── */
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>

void platform_hmac_sha256(const void *key, size_t key_len,
                           const void *data, size_t data_len,
                           unsigned char out[32]) {
    unsigned int out_len = 32;
    HMAC(EVP_sha256(), key, (int)key_len,
         (const unsigned char *)data, data_len,
         out, &out_len);
}

void platform_pbkdf2_sha256(const char *password, size_t pwd_len,
                              const unsigned char *salt, size_t salt_len,
                              unsigned int iterations,
                              unsigned char *out, size_t out_len) {
    PKCS5_PBKDF2_HMAC(password, (int)pwd_len,
                       salt,     (int)salt_len,
                       (int)iterations,
                       EVP_sha256(),
                       (int)out_len, out);
}

void platform_random(void *buf, size_t len) {
    /* /dev/urandom から読む (getrandom(2) がない古い環境にも対応) */
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { fprintf(stderr, "cannot open /dev/urandom\n"); abort(); }
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    if (n != len) { fprintf(stderr, "short read from /dev/urandom\n"); abort(); }
}

void platform_sha256(const void *data, size_t data_len, unsigned char out[32]) {
    SHA256((const unsigned char *)data, data_len, out);
}
#endif
