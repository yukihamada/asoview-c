#include "utils.h"
#include "platform.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

/* ─── UUID v4 ────────────────────────────────────────────────────────────── */

void generate_uuid(char *buf) {
    uint8_t b[16];
    platform_random(b, sizeof(b));
    b[6] = (b[6] & 0x0f) | 0x40; /* version 4 */
    b[8] = (b[8] & 0x3f) | 0x80; /* variant  */
    snprintf(buf, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
}

/* ─── PBKDF2-SHA256 ──────────────────────────────────────────────────────── */

int hash_password(const char *password, char *hash_out, size_t out_len) {
    uint8_t salt[16], dk[32];
    platform_random(salt, sizeof(salt));

    platform_pbkdf2_sha256(password, strlen(password),
                           salt, sizeof(salt), 100000,
                           dk, sizeof(dk));

    char salt_hex[33], dk_hex[65];
    for (int i = 0; i < 16; i++) snprintf(salt_hex + i*2, 3, "%02x", salt[i]);
    for (int i = 0; i < 32; i++) snprintf(dk_hex  + i*2, 3, "%02x", dk[i]);

    snprintf(hash_out, out_len, "pbkdf2$%s$%s", salt_hex, dk_hex);
    return 0;
}

int verify_password(const char *password, const char *stored_hash) {
    char salt_hex[33], dk_hex[65];
    if (sscanf(stored_hash, "pbkdf2$%32s$%64s", salt_hex, dk_hex) != 2) return 0;

    uint8_t salt[16], dk[32], expected[32];
    for (int i = 0; i < 16; i++) sscanf(salt_hex + i*2, "%2hhx", &salt[i]);
    for (int i = 0; i < 32; i++) sscanf(dk_hex   + i*2, "%2hhx", &expected[i]);

    platform_pbkdf2_sha256(password, strlen(password),
                           salt, sizeof(salt), 100000,
                           dk, sizeof(dk));

    /* constant-time compare */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= dk[i] ^ expected[i];
    return diff == 0;
}

/* ─── String helpers ─────────────────────────────────────────────────────── */

char *str_lower(char *s) {
    for (char *p = s; *p; p++) *p = (char)tolower((unsigned char)*p);
    return s;
}

int str_starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* ─── Email validation ───────────────────────────────────────────────────── */

int is_valid_email(const char *email) {
    if (!email || !*email) return 0;
    const char *at = strchr(email, '@');
    if (!at || at == email) return 0;          /* '@' なし、または先頭が '@' */
    const char *dot = strchr(at + 1, '.');
    if (!dot || dot == at + 1 || !*(dot + 1)) return 0; /* ドメイン部に '.' なし */
    if (strchr(dot + 1, '\0') == dot + 1) return 0;     /* TLD が空 */
    return 1;
}

/* ─── SHA-256 hex ─────────────────────────────────────────────────────────── */

void sha256_hex(const char *input, size_t input_len, char out[65]) {
    unsigned char hash[32];
    platform_sha256(input, input_len, hash);
    for (int i = 0; i < 32; i++) snprintf(out + i*2, 3, "%02x", hash[i]);
    out[64] = '\0';
}

/* ─── LIKE escape ────────────────────────────────────────────────────────── */

void escape_like(const char *src, char *dst, size_t dst_len) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < dst_len; i++) {
        if (src[i] == '%' || src[i] == '_' || src[i] == '\\')
            dst[j++] = '\\';
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

/* ─── Base64url helpers (file-internal) ──────────────────────────────────── */

static void b64url_encode(const uint8_t *src, size_t src_len, char *out) {
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i = 0, j = 0;
    while (i + 2 < src_len) {
        uint32_t t = ((uint32_t)src[i]<<16)|((uint32_t)src[i+1]<<8)|src[i+2];
        out[j++]=T[(t>>18)&63]; out[j++]=T[(t>>12)&63];
        out[j++]=T[(t>>6)&63];  out[j++]=T[t&63];
        i += 3;
    }
    if (i < src_len) {
        uint32_t t = (uint32_t)src[i]<<16;
        if (i+1 < src_len) t |= (uint32_t)src[i+1]<<8;
        out[j++]=T[(t>>18)&63]; out[j++]=T[(t>>12)&63];
        if (i+1 < src_len) out[j++]=T[(t>>6)&63];
    }
    out[j]='\0';
}

static int b64url_char_val(char c) {
    if (c>='A'&&c<='Z') return c-'A';
    if (c>='a'&&c<='z') return c-'a'+26;
    if (c>='0'&&c<='9') return c-'0'+52;
    if (c=='-') return 62;
    if (c=='_') return 63;
    return -1;
}

/* returns decoded length or -1 */
static int b64url_decode(const char *src, size_t src_len, uint8_t *out, size_t out_cap) {
    size_t j = 0;
    for (size_t i = 0; i < src_len; ) {
        int v[4] = {-1,-1,-1,-1}; int k;
        for (k=0; k<4 && i<src_len; k++,i++) {
            v[k] = b64url_char_val(src[i]);
            if (v[k]<0) return -1;
        }
        if (k<2) return -1;
        if (j>=out_cap) return -1;
        out[j++]=(uint8_t)((v[0]<<2)|(v[1]>>4));
        if (k>=3&&j<out_cap) out[j++]=(uint8_t)((v[1]<<4)|(v[2]>>2));
        if (k==4&&j<out_cap) out[j++]=(uint8_t)((v[2]<<6)|v[3]);
    }
    return (int)j;
}

/* ─── JWT HS256 ──────────────────────────────────────────────────────────── */

char *jwt_create(long user_id, const char *secret) {
    /* header */
    const char *hdr = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char hdr_b64[64];
    b64url_encode((const uint8_t*)hdr, strlen(hdr), hdr_b64);

    /* payload — jti は乱数で一意性を保証（同秒内の複数発行でも衝突しない） */
    time_t now = time(NULL);
    time_t exp = now + 7*24*3600;
    unsigned jti = (unsigned)rand() ^ (unsigned)(now & 0xFFFF);
    char pay[160];
    snprintf(pay, sizeof(pay),
             "{\"sub\":\"%ld\",\"iat\":%ld,\"exp\":%ld,\"jti\":%u}",
             user_id, (long)now, (long)exp, jti);
    char pay_b64[256];
    b64url_encode((const uint8_t*)pay, strlen(pay), pay_b64);

    /* signing input */
    char si[512];
    snprintf(si, sizeof(si), "%s.%s", hdr_b64, pay_b64);

    /* HMAC-SHA256 */
    uint8_t mac[32];
    platform_hmac_sha256(secret, strlen(secret), si, strlen(si), mac);
    char sig[64];
    b64url_encode(mac, 32, sig);

    /* assemble */
    size_t tlen = strlen(si) + 1 + strlen(sig) + 1;
    char *tok = malloc(tlen);
    if (!tok) return NULL;
    snprintf(tok, tlen, "%s.%s", si, sig);
    return tok;
}

long jwt_verify(const char *token, const char *secret) {
    const char *p1 = strchr(token, '.');
    if (!p1) return -1;
    const char *p2 = strchr(p1+1, '.');
    if (!p2) return -1;

    /* verify signature */
    size_t si_len = (size_t)(p2 - token);
    uint8_t mac[32];
    platform_hmac_sha256(secret, strlen(secret), token, si_len, mac);
    char expected[64];
    b64url_encode(mac, 32, expected);
    if (strcmp(expected, p2+1) != 0) return -1;

    /* decode payload */
    const char *pay_b64 = p1+1;
    size_t pay_b64_len = (size_t)(p2 - pay_b64);
    uint8_t pay_json[256];
    int pay_len = b64url_decode(pay_b64, pay_b64_len, pay_json, sizeof(pay_json)-1);
    if (pay_len < 0) return -1;
    pay_json[pay_len] = '\0';

    /* parse exp */
    const char *ep = strstr((char*)pay_json, "\"exp\":");
    if (!ep) return -1;
    long exp = strtol(ep+6, NULL, 10);
    if (time(NULL) > exp) return -1;  /* expired */

    /* parse sub */
    const char *sp = strstr((char*)pay_json, "\"sub\":\"");
    if (!sp) return -1;
    long uid = strtol(sp+7, NULL, 10);
    if (uid <= 0) return -1;
    return uid;
}
