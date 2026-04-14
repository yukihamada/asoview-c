#pragma once
#include <stddef.h>
#include <stdint.h>

/*
 * クロスプラットフォーム暗号プリミティブ
 *   macOS : CommonCrypto  (no extra link flags)
 *   Linux : OpenSSL       (-lssl -lcrypto)
 */

/* HMAC-SHA256 — out に 32 バイト書き込む */
void platform_hmac_sha256(const void   *key,  size_t key_len,
                           const void   *data, size_t data_len,
                           unsigned char out[32]);

/* PBKDF2-SHA256 */
void platform_pbkdf2_sha256(const char    *password, size_t pwd_len,
                              const unsigned char *salt, size_t salt_len,
                              unsigned int  iterations,
                              unsigned char *out,       size_t out_len);

/* 暗号学的乱数 */
void platform_random(void *buf, size_t len);

/* SHA-256 ダイジェスト長 */
#define PLATFORM_SHA256_LEN 32
