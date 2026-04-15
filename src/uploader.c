/*
 * AWS S3 Presigned PUT URL 生成（SigV4）
 *
 * 環境変数:
 *   AWS_ACCESS_KEY_ID     — IAM アクセスキー
 *   AWS_SECRET_ACCESS_KEY — IAM シークレット
 *   AWS_S3_BUCKET         — バケット名
 *   AWS_S3_REGION         — リージョン (例: ap-northeast-1)
 *
 * 有効期限: 1時間 (3600秒)
 */
#include "uploader.h"
#include "handlers.h"
#include "platform.h"
#include "utils.h"
#include "cJSON.h"
#include "mongoose.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ─── 内部ヘルパー ────────────────────────────────────────────────────────── */

static void to_hex(const unsigned char *in, int len, char *out) {
    for (int i = 0; i < len; i++) snprintf(out + i*2, 3, "%02x", in[i]);
    out[len*2] = '\0';
}

static void url_encode(const char *src, char *dst, size_t dst_len) {
    static const char *safe =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 4 < dst_len; i++) {
        if (strchr(safe, (unsigned char)src[i])) {
            dst[j++] = src[i];
        } else {
            snprintf(dst + j, dst_len - j, "%%%02X", (unsigned char)src[i]);
            j += 3;
        }
    }
    dst[j] = '\0';
}

static void hmac_hex(const unsigned char *key, size_t key_len,
                     const char *data, size_t data_len, char out[65]) {
    unsigned char mac[32];
    platform_hmac_sha256(key, key_len, data, data_len, mac);
    to_hex(mac, 32, out);
}

static void hmac_raw(const unsigned char *key, size_t key_len,
                     const char *data, size_t data_len, unsigned char out[32]) {
    platform_hmac_sha256(key, key_len, data, data_len, out);
}

/* SigV4 署名鍵の導出 */
static void derive_signing_key(const char *secret, const char *date,
                                const char *region, unsigned char kout[32]) {
    char kraw[256];
    size_t pfx = 4;
    size_t sec_len = strlen(secret);
    if (pfx + sec_len >= sizeof(kraw)) return;
    memcpy(kraw, "AWS4", pfx);
    memcpy(kraw + pfx, secret, sec_len);

    unsigned char kdate[32], kregion[32], kservice[32];
    hmac_raw((unsigned char *)kraw, pfx + sec_len, date, strlen(date), kdate);
    hmac_raw(kdate, 32, region, strlen(region), kregion);
    hmac_raw(kregion, 32, "s3", 2, kservice);
    hmac_raw(kservice, 32, "aws4_request", 12, kout);
}

static int make_presigned_put_url(const char *bucket, const char *region,
                                   const char *access_key, const char *secret_key,
                                   const char *object_key,
                                   char *url_out, size_t url_len) {
    time_t now = time(NULL);
    struct tm *tm_gmt = gmtime(&now);
    char date[9], datetime[17];
    strftime(date,     sizeof(date),     "%Y%m%d",         tm_gmt);
    strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%SZ", tm_gmt);

    char host[256];
    snprintf(host, sizeof(host), "%s.s3.%s.amazonaws.com", bucket, region);

    char scope[256];
    snprintf(scope, sizeof(scope), "%s/%s/%s/s3/aws4_request",
             access_key, date, region);

    char key_enc[512];
    url_encode(object_key, key_enc, sizeof(key_enc));

    char scope_enc[512];
    url_encode(scope, scope_enc, sizeof(scope_enc));

    char cqs[2048];
    snprintf(cqs, sizeof(cqs),
        "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=%s"
        "&X-Amz-Date=%s"
        "&X-Amz-Expires=3600"
        "&X-Amz-SignedHeaders=host",
        scope_enc, datetime);

    char canon[4096];
    snprintf(canon, sizeof(canon),
        "PUT\n/%s\n%s\nhost:%s\n\nhost\nUNSIGNED-PAYLOAD",
        key_enc, cqs, host);

    char canon_hash[65];
    sha256_hex(canon, strlen(canon), canon_hash);

    char sts[1024];
    snprintf(sts, sizeof(sts),
        "AWS4-HMAC-SHA256\n%s\n%s/%s/s3/aws4_request\n%s",
        datetime, date, region, canon_hash);

    unsigned char kSign[32];
    derive_signing_key(secret_key, date, region, kSign);
    char sig[65];
    hmac_hex(kSign, 32, sts, strlen(sts), sig);

    snprintf(url_out, url_len,
        "https://%s/%s?%s&X-Amz-Signature=%s",
        host, key_enc, cqs, sig);
    return 0;
}

static const char *ext_from_content_type(const char *ct) {
    if (!ct) return "bin";
    if (strstr(ct, "jpeg") || strstr(ct, "jpg")) return "jpg";
    if (strstr(ct, "png"))  return "png";
    if (strstr(ct, "gif"))  return "gif";
    if (strstr(ct, "webp")) return "webp";
    if (strstr(ct, "pdf"))  return "pdf";
    return "bin";
}

/* ─── 管理者キー検証（定数時間比較） ────────────────────────────────────── */

static int check_admin_key(struct mg_http_message *hm) {
    struct mg_str *hdr = mg_http_get_header(hm, "X-Admin-Key");
    if (!hdr) return 0;
    const char *expected = getenv("ADMIN_KEY");
    if (!expected || !*expected) expected = "asoview-admin-dev";
    size_t exp_len = strlen(expected);
    unsigned char diff = (unsigned char)(hdr->len != exp_len);
    size_t n = hdr->len < exp_len ? hdr->len : exp_len;
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned char)hdr->buf[i] ^ (unsigned char)expected[i];
    return diff == 0;
}

/* ─── ハンドラ ───────────────────────────────────────────────────────────── */

void handle_admin_get_upload_url(struct mg_connection *c,
                                  struct mg_http_message *hm, sqlite3 *db) {
    (void)db;

    if (!check_admin_key(hm)) {
        send_error_json(c, 403, "管理者キーが必要です");
        return;
    }

    const char *access_key = getenv("AWS_ACCESS_KEY_ID");
    const char *secret_key = getenv("AWS_SECRET_ACCESS_KEY");
    const char *bucket     = getenv("AWS_S3_BUCKET");
    const char *region     = getenv("AWS_S3_REGION");

    if (!access_key || !*access_key || !secret_key || !*secret_key ||
        !bucket     || !*bucket     || !region     || !*region) {
        send_error_json(c, 503, "S3 credentials not configured");
        return;
    }

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *content_type =
        cJSON_GetStringValue(cJSON_GetObjectItem(body, "content_type"));
    if (!content_type) content_type = "application/octet-stream";
    const char *filename =
        cJSON_GetStringValue(cJSON_GetObjectItem(body, "filename"));

    char uuid_str[37]; generate_uuid(uuid_str);
    const char *ext;
    if (filename) {
        const char *dot = strrchr(filename, '.');
        ext = dot ? dot + 1 : "bin";
    } else {
        ext = ext_from_content_type(content_type);
    }
    char object_key[256];
    snprintf(object_key, sizeof(object_key), "uploads/%s.%s", uuid_str, ext);
    cJSON_Delete(body);

    char url[2048];
    if (make_presigned_put_url(bucket, region, access_key, secret_key,
                                object_key, url, sizeof(url)) != 0) {
        send_error_json(c, 500, "failed to generate presigned URL");
        return;
    }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "url", url);
    cJSON_AddStringToObject(res, "key", object_key);
    char *s = cJSON_PrintUnformatted(res);
    cJSON_Delete(res);
    /* uploader 側は handlers.h の send_json_str を使う */
    send_json_str(c, 200, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n", s);
    cJSON_free(s);
}
