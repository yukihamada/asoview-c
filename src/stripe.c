#include "stripe.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonDigest.h>

/* ─── HTTP レスポンス蓄積バッファ ─────────────────────────────────── */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} Buf;

static size_t write_cb(void *ptr, size_t sz, size_t n, void *ud) {
    Buf *b = (Buf *)ud;
    size_t add = sz * n;
    if (b->len + add + 1 > b->cap) {
        size_t newcap = (b->len + add + 1) * 2;
        char *tmp = realloc(b->data, newcap);
        if (!tmp) return 0;
        b->data = tmp;
        b->cap  = newcap;
    }
    memcpy(b->data + b->len, ptr, add);
    b->len += add;
    b->data[b->len] = '\0';
    return add;
}

/* ─── Stripe PaymentIntent 作成 ───────────────────────────────────── */

int stripe_create_payment_intent(long amount_jpy,
                                 const char *booking_id,
                                 char *pi_id_out,         size_t pi_id_size,
                                 char *client_secret_out, size_t cs_size) {
    const char *sk = getenv("STRIPE_SECRET_KEY");
    if (!sk || !*sk) return -1;

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    /* form-encoded ボディ */
    char post[512];
    /* JPY は最小単位が円（cents なし）なので amount をそのまま渡す */
    snprintf(post, sizeof(post),
        "amount=%ld"
        "&currency=jpy"
        "&payment_method_types[]=card"
        "&metadata[booking_id]=%s",
        amount_jpy, booking_id);

    /* Authorization ヘッダー */
    char auth_hdr[256];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", sk);

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, auth_hdr);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");

    Buf buf = { calloc(1, 512), 0, 512 };

    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://api.stripe.com/v1/payment_intents");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    post);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);
    /* TLS 証明書検証は有効のまま（デフォルト）*/

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !buf.data) {
        fprintf(stderr, "[stripe] curl error: %s\n", curl_easy_strerror(res));
        free(buf.data);
        return -1;
    }

    cJSON *j = cJSON_Parse(buf.data);
    free(buf.data);
    if (!j) return -1;

    /* エラーレスポンスを確認 */
    cJSON *err = cJSON_GetObjectItem(j, "error");
    if (err) {
        const char *msg = cJSON_GetStringValue(cJSON_GetObjectItem(err, "message"));
        fprintf(stderr, "[stripe] API error: %s\n", msg ? msg : "(unknown)");
        cJSON_Delete(j);
        return -1;
    }

    const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(j, "id"));
    const char *cs = cJSON_GetStringValue(cJSON_GetObjectItem(j, "client_secret"));

    int ok = 0;
    if (id && cs) {
        strncpy(pi_id_out, id, pi_id_size - 1);
        pi_id_out[pi_id_size - 1] = '\0';
        strncpy(client_secret_out, cs, cs_size - 1);
        client_secret_out[cs_size - 1] = '\0';
        ok = 1;
    }
    cJSON_Delete(j);
    return ok ? 0 : -1;
}

/* ─── Webhook 署名検証 ────────────────────────────────────────────── */

static void hex_encode(const unsigned char *src, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[src[i] >> 4];
        out[i * 2 + 1] = hex[src[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

int stripe_verify_webhook(const char *sig_header,
                           const char *payload, size_t payload_len,
                           const char *webhook_secret) {
    if (!sig_header || !payload || !webhook_secret || !*webhook_secret) return 0;

    /* "t=TIMESTAMP,v1=SIG,v1=SIG2,..." を解析 */
    char ts[32] = {0};
    char v1[128] = {0};

    const char *p = sig_header;
    while (*p) {
        if (strncmp(p, "t=", 2) == 0) {
            p += 2;
            int i = 0;
            while (*p && *p != ',' && i < (int)sizeof(ts) - 1) ts[i++] = *p++;
            ts[i] = '\0';
        } else if (strncmp(p, "v1=", 3) == 0) {
            p += 3;
            /* 最初の v1= だけ使用 */
            if (!v1[0]) {
                int i = 0;
                while (*p && *p != ',' && i < (int)sizeof(v1) - 1) v1[i++] = *p++;
                v1[i] = '\0';
            } else {
                while (*p && *p != ',') p++;
            }
        } else {
            while (*p && *p != ',') p++;
        }
        if (*p == ',') p++;
    }

    if (!ts[0] || !v1[0]) return 0;

    /* タイムスタンプ検証: ±5分以内のイベントのみ受理（リプレイ攻撃防止） */
    long ts_time = strtol(ts, NULL, 10);
    long now     = (long)time(NULL);
    if (ts_time <= 0 || (now - ts_time) > 300 || (ts_time - now) > 300) return 0;

    /* 署名対象: "TIMESTAMP.PAYLOAD" */
    size_t ts_len     = strlen(ts);
    size_t signed_len = ts_len + 1 + payload_len;
    char  *signed_buf = malloc(signed_len);
    if (!signed_buf) return 0;
    memcpy(signed_buf,           ts,      ts_len);
    signed_buf[ts_len] = '.';
    memcpy(signed_buf + ts_len + 1, payload, payload_len);

    /* HMAC-SHA256 */
    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,
           webhook_secret, strlen(webhook_secret),
           signed_buf, signed_len,
           mac);
    free(signed_buf);

    char computed[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    hex_encode(mac, CC_SHA256_DIGEST_LENGTH, computed);

    /* 定数時間比較（タイミング攻撃対策）*/
    int diff = 0;
    size_t expected_len = strlen(v1);
    if (expected_len != CC_SHA256_DIGEST_LENGTH * 2) return 0;
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH * 2; i++) {
        diff |= (unsigned char)computed[i] ^ (unsigned char)v1[i];
    }
    return diff == 0 ? 1 : 0;
}
