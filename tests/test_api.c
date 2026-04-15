/*
 * あそビュー C版 統合テスト
 * ビルド: make test
 * 依存: libcurl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <curl/curl.h>
#include <time.h>
/* cJSON はコンパイル時に deps/ から */
#include "../deps/cJSON.h"

/* ─── Test framework ──────────────────────────────────────────────────── */
static int passed = 0, failed = 0;
static const char *BASE_URL;
static char g_token[512]  = {0}; /* taro@example.com のJWT */
static char g_token2[512] = {0}; /* hanako@example.com のJWT */

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL %s:%d — %s\n", __func__, __LINE__, msg); \
        failed++; return; \
    } \
} while(0)

#define PASS() do { printf("  PASS %s\n", __func__); passed++; } while(0)

/* ─── HTTP helpers ────────────────────────────────────────────────────── */
typedef struct { char *data; size_t size; } Buf;

static size_t write_cb(void *ptr, size_t sz, size_t n, void *ud) {
    Buf *b = (Buf *)ud;
    size_t total = sz * n;
    b->data = realloc(b->data, b->size + total + 1);
    memcpy(b->data + b->size, ptr, total);
    b->size += total;
    b->data[b->size] = '\0';
    return total;
}

typedef struct { char *body; long status; } Resp;

static Resp http_get(const char *url) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_easy_cleanup(curl);
    return r;
}

static Resp http_get_auth(const char *url, const char *token) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    char auth_hdr[600];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", token);
    struct curl_slist *hdrs = curl_slist_append(NULL, auth_hdr);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

static Resp http_post(const char *url, const char *json_body) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    struct curl_slist *hdrs =
        curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

static void resp_free(Resp *r) { free(r->body); r->body = NULL; }

/* Bearer トークン付き POST */
static Resp http_post_auth(const char *url, const char *json_body, const char *token) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    char auth_hdr[600];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", token);
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, auth_hdr);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

/* Bearer トークン付き PATCH */
static Resp http_patch_auth(const char *url, const char *token) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    char auth_hdr[600];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", token);
    struct curl_slist *hdrs = curl_slist_append(NULL, auth_hdr);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

/* 管理者キー付き POST */
static Resp http_post_admin(const char *url, const char *json_body) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "X-Admin-Key: asoview-admin-dev");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

/* 管理者キー付き PUT */
static Resp http_put_admin(const char *url, const char *json_body) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "X-Admin-Key: asoview-admin-dev");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

/* 管理者キー付き DELETE */
static Resp http_delete_admin(const char *url) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    struct curl_slist *hdrs = curl_slist_append(NULL, "X-Admin-Key: asoview-admin-dev");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

/* 任意ヘッダ付き GET */
static Resp http_get_with_header(const char *url, const char *hdr_name, const char *hdr_val) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    char hdr[512];
    snprintf(hdr, sizeof(hdr), "%s: %s", hdr_name, hdr_val);
    struct curl_slist *hdrs = curl_slist_append(NULL, hdr);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

/* Bearer トークン + Body 付き PATCH */
static Resp http_patch_auth_body(const char *url, const char *json_body, const char *token) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    char auth_hdr[600];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", token);
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, auth_hdr);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

/* ─── レスポンスヘッダーキャプチャ用グローバル ───────────────────────────── */
static char        g_captured_header_val[256] = {0};
static const char *g_header_to_capture        = NULL;

static size_t generic_header_cb(void *ptr, size_t sz, size_t nmemb, void *ud) {
    (void)ud;
    size_t len = sz * nmemb;
    if (!g_header_to_capture) return len;
    char line[512] = {0};
    size_t cp = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
    memcpy(line, ptr, cp);
    size_t hl = strlen(g_header_to_capture);
    if (strncasecmp(line, g_header_to_capture, hl) == 0 && line[hl] == ':') {
        char *val = line + hl + 1;
        while (*val == ' ') val++;
        size_t vl = strlen(val);
        while (vl > 0 && (val[vl-1] == '\r' || val[vl-1] == '\n')) { val[--vl] = '\0'; }
        strncpy(g_captured_header_val, val, sizeof(g_captured_header_val) - 1);
        g_captured_header_val[sizeof(g_captured_header_val) - 1] = '\0';
    }
    return len;
}

/* 特定のレスポンスヘッダーをキャプチャする GET */
static Resp http_get_capture_header(const char *url, const char *header_name) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    g_header_to_capture = header_name;
    g_captured_header_val[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, generic_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, NULL);
    curl_easy_perform(curl);
    g_header_to_capture = NULL;
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_easy_cleanup(curl);
    return r;
}

/* If-None-Match ヘッダー付き GET（ETag 検証用） */
static Resp http_get_if_none_match(const char *url, const char *etag) {
    return http_get_with_header(url, "If-None-Match", etag);
}

/* ─── Stripe Webhook テスト用ヘルパー ──────────────────────────────────── */
extern void platform_hmac_sha256(const char *key, size_t klen,
                                  const void *data, size_t dlen,
                                  void *mac_out);
#define WH_HMAC_LEN 32

static void hex_encode_wh(const unsigned char *src, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hex[src[i] >> 4];
        out[i*2+1] = hex[src[i] & 0x0f];
    }
    out[len*2] = '\0';
}

/* 有効な Stripe-Signature を計算して POST する */
static Resp http_post_stripe(const char *url, const char *payload,
                              const char *secret) {
    long ts = (long)time(NULL);
    char ts_str[32]; snprintf(ts_str, sizeof(ts_str), "%ld", ts);
    size_t ts_len  = strlen(ts_str);
    size_t pay_len = strlen(payload);

    /* 署名対象: "TIMESTAMP.PAYLOAD" */
    char *signed_msg = malloc(ts_len + 1 + pay_len + 1);
    memcpy(signed_msg, ts_str, ts_len);
    signed_msg[ts_len] = '.';
    memcpy(signed_msg + ts_len + 1, payload, pay_len + 1);

    unsigned char mac[WH_HMAC_LEN];
    platform_hmac_sha256(secret, strlen(secret),
                          signed_msg, ts_len + 1 + pay_len, mac);
    free(signed_msg);

    char sig_hex[WH_HMAC_LEN * 2 + 1];
    hex_encode_wh(mac, WH_HMAC_LEN, sig_hex);

    char stripe_sig_hdr[320];
    snprintf(stripe_sig_hdr, sizeof(stripe_sig_hdr),
             "Stripe-Signature: t=%s,v1=%s", ts_str, sig_hex);

    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, stripe_sig_hdr);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

/* ─── Tests ───────────────────────────────────────────────────────────── */

static void test_health(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/health", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(j != NULL, "valid JSON");
    ASSERT(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(j, "status")), "ok") == 0,
           "status=ok");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_list_areas(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/areas", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *arr = cJSON_Parse(r.body);
    ASSERT(cJSON_IsArray(arr), "response is array");
    ASSERT(cJSON_GetArraySize(arr) > 0, "not empty");
    int found_tokyo = 0, found_kanto = 0;
    cJSON *a;
    cJSON_ArrayForEach(a, arr) {
        const char *nm = cJSON_GetStringValue(cJSON_GetObjectItem(a, "name"));
        if (nm && strcmp(nm, "東京都") == 0) found_tokyo = 1;
        if (nm && strcmp(nm, "関東")   == 0) found_kanto = 1;
    }
    ASSERT(found_tokyo, "found 東京都");
    ASSERT(found_kanto, "found 関東");
    cJSON_Delete(arr); resp_free(&r);
    PASS();
}

static void test_list_categories(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/categories", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *arr = cJSON_Parse(r.body);
    ASSERT(cJSON_IsArray(arr) && cJSON_GetArraySize(arr) > 0, "not empty");
    int has_diving = 0;
    cJSON *c;
    cJSON_ArrayForEach(c, arr) {
        const char *sl = cJSON_GetStringValue(cJSON_GetObjectItem(c, "slug"));
        if (sl && strcmp(sl, "diving") == 0) has_diving = 1;
    }
    ASSERT(has_diving, "found diving category");
    cJSON_Delete(arr); resp_free(&r);
    PASS();
}

static void test_list_venues(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/venues", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetNumberValue(cJSON_GetObjectItem(j, "total")) >= 6, "total >= 6");
    ASSERT(cJSON_IsArray(cJSON_GetObjectItem(j, "venues")), "venues is array");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_list_venues_area_filter(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/venues?area_id=11", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    cJSON *venues = cJSON_GetObjectItem(j, "venues");
    ASSERT(cJSON_GetArraySize(venues) > 0, "not empty");
    int found = 0;
    cJSON *v;
    cJSON_ArrayForEach(v, venues) {
        const char *nm = cJSON_GetStringValue(cJSON_GetObjectItem(v, "name"));
        if (nm && strstr(nm, "OCEANUS")) found = 1;
    }
    ASSERT(found, "found OCEANUS in okinawa");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_get_venue(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/venues/1", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "id")) == 1, "id=1");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_get_venue_not_found(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/venues/99999", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 404, "expected 404");
    resp_free(&r);
    PASS();
}

static void test_list_plans(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/plans", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetNumberValue(cJSON_GetObjectItem(j, "total")) >= 10, "total >= 10");
    cJSON *plans = cJSON_GetObjectItem(j, "plans");
    cJSON *p = cJSON_GetArrayItem(plans, 0);
    ASSERT(cJSON_IsArray(cJSON_GetObjectItem(p, "prices")), "prices is array");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_list_plans_filter_category(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/plans?category_id=6", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    cJSON *plans = cJSON_GetObjectItem(j, "plans");
    ASSERT(cJSON_GetArraySize(plans) > 0, "not empty");
    cJSON *p;
    cJSON_ArrayForEach(p, plans) {
        ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(p, "category_id")) == 6,
               "category_id=6");
    }
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_list_plans_filter_date(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/plans?date=2026-04-20&adults=2", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetArraySize(cJSON_GetObjectItem(j, "plans")) > 0, "not empty");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_get_plan(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/plans/1", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "id")) == 1, "id=1");
    cJSON *prices = cJSON_GetObjectItem(j, "prices");
    ASSERT(cJSON_GetArraySize(prices) > 0, "prices not empty");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_list_schedules(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/plans/1/schedules", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *arr = cJSON_Parse(r.body);
    ASSERT(cJSON_IsArray(arr) && cJSON_GetArraySize(arr) > 0, "not empty");
    cJSON *s = cJSON_GetArrayItem(arr, 0);
    ASSERT(cJSON_GetNumberValue(cJSON_GetObjectItem(s, "available")) > 0, "has available");
    cJSON_Delete(arr); resp_free(&r);
    PASS();
}

static void test_list_schedules_by_date(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/plans/1/schedules?date=2026-04-20", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *arr = cJSON_Parse(r.body);
    ASSERT(cJSON_GetArraySize(arr) > 0, "not empty");
    cJSON *s;
    cJSON_ArrayForEach(s, arr) {
        ASSERT(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(s, "date")), "2026-04-20") == 0,
               "date=2026-04-20");
    }
    cJSON_Delete(arr); resp_free(&r);
    PASS();
}

static void test_create_user(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/users", BASE_URL);
    Resp r = http_post(url,
        "{\"email\":\"ctest@example.com\",\"name\":\"Cテストユーザー\","
        "\"phone\":\"090-0000-9999\",\"password\":\"securepass123\"}");
    ASSERT(r.status == 201, "expected 201");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(j,"email")),
                  "ctest@example.com") == 0, "email matches");
    ASSERT(cJSON_GetObjectItem(j, "password_hash") == NULL, "no hash in response");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_create_user_duplicate(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/users", BASE_URL);
    const char *body = "{\"email\":\"dup2@example.com\",\"name\":\"重複\",\"password\":\"pass1234\"}";
    http_post(url, body); /* first: ignore result */
    Resp r = http_post(url, body);
    ASSERT(r.status == 409, "expected 409");
    resp_free(&r);
    PASS();
}

static void test_create_user_short_password(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/users", BASE_URL);
    Resp r = http_post(url,
        "{\"email\":\"short@example.com\",\"name\":\"短い\",\"password\":\"1234567\"}");
    ASSERT(r.status == 400, "expected 400");
    resp_free(&r);
    PASS();
}

static void test_login(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/auth/login", BASE_URL);
    Resp r = http_post(url,
        "{\"email\":\"taro@example.com\",\"password\":\"password123\"}");
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetNumberValue(cJSON_GetObjectItem(j, "user_id")) >= 1, "user_id >= 1");
    const char *tok = cJSON_GetStringValue(cJSON_GetObjectItem(j, "token"));
    ASSERT(tok && strlen(tok) > 10, "token present");
    strncpy(g_token, tok, sizeof(g_token)-1);
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_login_token2(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/auth/login", BASE_URL);
    Resp r = http_post(url,
        "{\"email\":\"hanako@example.com\",\"password\":\"password123\"}");
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    const char *tok = cJSON_GetStringValue(cJSON_GetObjectItem(j, "token"));
    ASSERT(tok && strlen(tok) > 10, "token2 present");
    strncpy(g_token2, tok, sizeof(g_token2)-1);
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_login_wrong_password(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/auth/login", BASE_URL);
    Resp r = http_post(url,
        "{\"email\":\"taro@example.com\",\"password\":\"wrongpassword\"}");
    ASSERT(r.status == 400, "expected 400");
    resp_free(&r);
    PASS();
}

static char g_booking_id[64] = {0}; /* キャンセルテスト用 */

static void test_create_and_get_booking(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/bookings", BASE_URL);
    /* unit_price/label はサーバー側で確定するので不要 */
    Resp r = http_post_auth(url,
        "{\"plan_id\":1,\"schedule_id\":1,"
        "\"participants\":[{\"participant_type\":\"adult\",\"count\":2}],"
        "\"note\":\"海が初めてです\"}",
        g_token);
    ASSERT(r.status == 201, "expected 201");
    cJSON *j = cJSON_Parse(r.body);
    /* plan_prices: adult=7980（実際のasoview価格）, 2名 → 15960 */
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "total_price")) == 15960,
           "total_price=15960 (server-side calc)");
    const char *bid = cJSON_GetStringValue(cJSON_GetObjectItem(j, "id"));
    ASSERT(bid && strlen(bid) == 36, "id is UUID");
    strncpy(g_booking_id, bid, sizeof(g_booking_id)-1);

    /* GET (JWT 必須) */
    char get_url[300];
    snprintf(get_url, sizeof(get_url), "%s/api/v1/bookings/%s", BASE_URL, bid);
    Resp r2 = http_get_auth(get_url, g_token);
    ASSERT(r2.status == 200, "GET booking 200");
    cJSON *j2 = cJSON_Parse(r2.body);
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j2, "total_price")) == 15960,
           "total_price matches");

    cJSON_Delete(j); cJSON_Delete(j2); resp_free(&r); resp_free(&r2);
    PASS();
}

static void test_booking_capacity_check(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/bookings", BASE_URL);
    Resp r = http_post_auth(url,
        "{\"plan_id\":1,\"schedule_id\":2,"
        "\"participants\":[{\"participant_type\":\"adult\",\"count\":9}]}",
        g_token);
    ASSERT(r.status == 409, "expected 409 capacity exceeded");
    resp_free(&r);
    PASS();
}

static void test_list_user_bookings(void) {
    /* hanako (user2) のトークンで予約作成 */
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/bookings", BASE_URL);
    Resp rb = http_post_auth(url,
        "{\"plan_id\":4,\"schedule_id\":23,"
        "\"participants\":[{\"participant_type\":\"adult\",\"count\":1}]}",
        g_token2);
    ASSERT(rb.status == 201, "hanako booking created");
    resp_free(&rb);

    snprintf(url, sizeof(url), "%s/api/v1/users/2/bookings", BASE_URL);
    Resp r = http_get_auth(url, g_token2);
    ASSERT(r.status == 200, "expected 200");
    cJSON *arr = cJSON_Parse(r.body);
    ASSERT(cJSON_IsArray(arr) && cJSON_GetArraySize(arr) > 0, "not empty");
    cJSON_Delete(arr); resp_free(&r);
    PASS();
}

static void test_create_review(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/reviews", BASE_URL);
    /* taro は plan_id=1 を予約済み（test_create_and_get_booking）。booking_id を渡す */
    char body[256];
    snprintf(body, sizeof(body),
        "{\"plan_id\":1,\"rating\":5,\"comment\":\"最高でした！\",\"booking_id\":\"%s\"}",
        g_booking_id);
    Resp r = http_post_auth(url, body, g_token);
    ASSERT(r.status == 201, "expected 201");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "rating")) == 5, "rating=5");
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "user_id")) == 1, "user_id from JWT");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_create_review_unbooked(void) {
    /* 予約していないユーザー(hanako)がplan_id=1にレビューしようとする → 403 */
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/reviews", BASE_URL);
    Resp r = http_post_auth(url,
        "{\"plan_id\":1,\"rating\":3,\"comment\":\"未予約でも投稿できる？\"}",
        g_token2);
    ASSERT(r.status == 403, "unbooked review → 403");
    resp_free(&r);
    PASS();
}

static void test_create_review_invalid_rating(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/reviews", BASE_URL);
    Resp r = http_post_auth(url, "{\"plan_id\":1,\"rating\":6}", g_token);
    ASSERT(r.status == 400, "expected 400");
    resp_free(&r);
    PASS();
}

static void test_booking_access_control(void) {
    /* 未認証で GET /bookings/:id → 401 */
    char url[300];
    snprintf(url, sizeof(url), "%s/api/v1/bookings/%s", BASE_URL, g_booking_id);
    Resp r = http_get(url);
    ASSERT(r.status == 401, "no auth → 401");
    resp_free(&r);

    /* hanako が taro の予約を取得しようとする → 403 */
    Resp r2 = http_get_auth(url, g_token2);
    ASSERT(r2.status == 403, "other user → 403");
    resp_free(&r2);

    /* taro 自身は取得できる */
    Resp r3 = http_get_auth(url, g_token);
    ASSERT(r3.status == 200, "owner → 200");
    resp_free(&r3);
    PASS();
}

static void test_booking_list_access_control(void) {
    /* 未認証で GET /users/1/bookings → 401 */
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/users/1/bookings", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 401, "no auth → 401");
    resp_free(&r);

    /* hanako が taro の予約一覧を取得しようとする → 403 */
    Resp r2 = http_get_auth(url, g_token2);
    ASSERT(r2.status == 403, "other user → 403");
    resp_free(&r2);
    PASS();
}

/* ── レビューページング ─────────────────────────────────────────────── */

static void test_reviews_pagination(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/plans/1/reviews?page=1&limit=5", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(j != NULL, "valid JSON");
    ASSERT(cJSON_GetObjectItem(j, "reviews") != NULL, "has reviews array");
    ASSERT(cJSON_GetObjectItem(j, "total")   != NULL, "has total");
    ASSERT(cJSON_GetObjectItem(j, "page")    != NULL, "has page");
    ASSERT(cJSON_GetObjectItem(j, "limit")   != NULL, "has limit");
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "limit")) == 5, "limit=5");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

/* ── ブックマーク認証 ────────────────────────────────────────────────── */

static void test_bookmark_list_auth(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/users/1/bookmarks", BASE_URL);
    /* 未認証 → 401 */
    Resp r = http_get(url);
    ASSERT(r.status == 401, "no auth → 401");
    resp_free(&r);
    /* hanako が taro のブックマークを取得 → 403 */
    Resp r2 = http_get_auth(url, g_token2);
    ASSERT(r2.status == 403, "other user → 403");
    resp_free(&r2);
    /* taro 自身 → 200 */
    Resp r3 = http_get_auth(url, g_token);
    ASSERT(r3.status == 200, "owner → 200");
    resp_free(&r3);
    PASS();
}

/* ── Admin 一覧 ──────────────────────────────────────────────────────── */

static void test_admin_list_venues(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/admin/venues?page=1&limit=5", BASE_URL);
    Resp r = http_get_with_header(url, "X-Admin-Key", "asoview-admin-dev");
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(j != NULL, "valid JSON");
    ASSERT(cJSON_IsArray(cJSON_GetObjectItem(j, "venues")), "has venues array");
    ASSERT(cJSON_GetObjectItem(j, "total") != NULL, "has total");
    ASSERT(cJSON_GetArraySize(cJSON_GetObjectItem(j, "venues")) <= 5, "limit respected");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_admin_list_plans(void) {
    char url[256];
    /* is_active=0 のみ → 管理者は非アクティブも見える */
    snprintf(url, sizeof(url), "%s/api/v1/admin/plans?is_active=0&limit=50", BASE_URL);
    Resp r = http_get_with_header(url, "X-Admin-Key", "asoview-admin-dev");
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(j != NULL, "valid JSON");
    ASSERT(cJSON_IsArray(cJSON_GetObjectItem(j, "plans")), "has plans array");
    ASSERT(cJSON_GetObjectItem(j, "total") != NULL, "has total");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

/* ── パスワード変更 ──────────────────────────────────────────────────── */

static void test_change_password(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/auth/change-password", BASE_URL);

    /* 現在のパスワードが間違っている → 400 */
    Resp r1 = http_patch_auth_body(url,
        "{\"current_password\":\"wrongpass\",\"new_password\":\"newpass123\"}",
        g_token);
    ASSERT(r1.status == 400, "wrong current password → 400");
    resp_free(&r1);

    /* 新しいパスワードが短すぎる → 400 */
    Resp r2 = http_patch_auth_body(url,
        "{\"current_password\":\"password123\",\"new_password\":\"short\"}",
        g_token);
    ASSERT(r2.status == 400, "too short → 400");
    resp_free(&r2);

    /* 正常変更 → 200 */
    Resp r3 = http_patch_auth_body(url,
        "{\"current_password\":\"password123\",\"new_password\":\"newpassword123\"}",
        g_token);
    ASSERT(r3.status == 200, "change success → 200");
    resp_free(&r3);

    /* 変更後の新しいパスワードでログイン → 成功 */
    char login_url[256];
    snprintf(login_url, sizeof(login_url), "%s/api/v1/auth/login", BASE_URL);
    Resp r4 = http_post(login_url,
        "{\"email\":\"taro@example.com\",\"password\":\"newpassword123\"}");
    ASSERT(r4.status == 200, "login with new password → 200");
    /* g_token を更新（以降のテストのために） */
    cJSON *j = cJSON_Parse(r4.body);
    if (j) {
        const char *tok = cJSON_GetStringValue(cJSON_GetObjectItem(j, "token"));
        if (tok && strlen(tok) > 10) strncpy(g_token, tok, sizeof(g_token)-1);
        cJSON_Delete(j);
    }
    resp_free(&r4);
    PASS();
}

/* ── パスワードリセット ───────────────────────────────────────────────── */

static void test_forgot_reset_password(void) {
    char url[256];

    /* forgot-password: 存在しないメール → 200（列挙攻撃防止） */
    snprintf(url, sizeof(url), "%s/api/v1/auth/forgot-password", BASE_URL);
    Resp r1 = http_post(url, "{\"email\":\"noone@example.com\"}");
    ASSERT(r1.status == 200, "unknown email → 200 (anti-enumeration)");
    resp_free(&r1);

    /* forgot-password: taro のメール → トークン取得 */
    Resp r2 = http_post(url, "{\"email\":\"taro@example.com\"}");
    ASSERT(r2.status == 200, "forgot-password → 200");
    cJSON *j2 = cJSON_Parse(r2.body);
    ASSERT(j2 != NULL, "valid JSON");
    const char *token_ptr = cJSON_GetStringValue(cJSON_GetObjectItem(j2, "reset_token"));
    ASSERT(token_ptr && strlen(token_ptr) == 32, "got 32-char token");
    char reset_token[33] = {0};
    strncpy(reset_token, token_ptr, 32);
    cJSON_Delete(j2); resp_free(&r2);

    /* reset-password: 無効トークン → 400 */
    snprintf(url, sizeof(url), "%s/api/v1/auth/reset-password", BASE_URL);
    Resp r3 = http_post(url,
        "{\"token\":\"deadbeefdeadbeefdeadbeefdeadbeef\","
        "\"new_password\":\"resetpass456\"}");
    ASSERT(r3.status == 400, "invalid token → 400");
    resp_free(&r3);

    /* reset-password: 有効トークン → 200 */
    char body[256];
    snprintf(body, sizeof(body),
        "{\"token\":\"%s\",\"new_password\":\"resetpass456\"}", reset_token);
    Resp r4 = http_post(url, body);
    ASSERT(r4.status == 200, "reset → 200");
    resp_free(&r4);

    /* トークン再利用 → 400 */
    Resp r5 = http_post(url, body);
    ASSERT(r5.status == 400, "used token → 400");
    resp_free(&r5);

    /* 新パスワードでログイン → 成功 */
    snprintf(url, sizeof(url), "%s/api/v1/auth/login", BASE_URL);
    Resp r6 = http_post(url,
        "{\"email\":\"taro@example.com\",\"password\":\"resetpass456\"}");
    ASSERT(r6.status == 200, "login with reset password → 200");
    cJSON *j6 = cJSON_Parse(r6.body);
    if (j6) {
        const char *tok = cJSON_GetStringValue(cJSON_GetObjectItem(j6, "token"));
        if (tok && strlen(tok) > 10) strncpy(g_token, tok, sizeof(g_token)-1);
        cJSON_Delete(j6);
    }
    resp_free(&r6);
    PASS();
}

static void test_search_keyword(void) {
    char url[256];
    /* q=ダイビング URL-encoded */
    static const char *DIVING = "/api/v1/search?q=%E3%83%80%E3%82%A4%E3%83%93%E3%83%B3%E3%82%B0";
    snprintf(url, sizeof(url), "%s%s", BASE_URL, DIVING);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetArraySize(cJSON_GetObjectItem(j, "plans")) > 0, "found results");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_search_no_results(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/search?q=XYZNOTEXIST12345", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "total")) == 0, "total=0");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

/* ─── JWT / 認証テスト ─────────────────────────────────────────────────── */

static void test_booking_requires_auth(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/bookings", BASE_URL);
    Resp r = http_post(url,
        "{\"plan_id\":1,\"schedule_id\":3,"
        "\"participants\":[{\"participant_type\":\"adult\",\"count\":1}]}");
    ASSERT(r.status == 401, "no auth → 401");
    resp_free(&r);
    PASS();
}

static void test_cancel_booking(void) {
    /* g_booking_id は test_create_and_get_booking で設定済み */
    ASSERT(g_booking_id[0] != '\0', "booking id available");
    char url[300];
    snprintf(url, sizeof(url), "%s/api/v1/bookings/%s/cancel", BASE_URL, g_booking_id);
    Resp r = http_patch_auth(url, g_token);
    ASSERT(r.status == 200, "cancel 200");

    /* 再確認: status が cancelled */
    char get_url[300];
    snprintf(get_url, sizeof(get_url), "%s/api/v1/bookings/%s", BASE_URL, g_booking_id);
    Resp r2 = http_get_auth(get_url, g_token);
    cJSON *j = cJSON_Parse(r2.body);
    ASSERT(j != NULL, "cancel GET response is JSON");
    ASSERT(strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(j, "status")), "cancelled") == 0,
           "status=cancelled");

    /* 二重キャンセルは 400 */
    Resp r3 = http_patch_auth(url, g_token);
    ASSERT(r3.status == 400, "double cancel 400");

    cJSON_Delete(j); resp_free(&r); resp_free(&r2); resp_free(&r3);
    PASS();
}

static void test_cancel_booking_unauthorized(void) {
    /* taro の予約を hanako がキャンセルしようとする → 403 */
    /* まず taro で新規予約作成 */
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/bookings", BASE_URL);
    Resp rb = http_post_auth(url,
        "{\"plan_id\":1,\"schedule_id\":3,"
        "\"participants\":[{\"participant_type\":\"adult\",\"count\":1}]}",
        g_token);
    ASSERT(rb.status == 201, "taro booking created");
    cJSON *bj = cJSON_Parse(rb.body);
    const char *bid = cJSON_GetStringValue(cJSON_GetObjectItem(bj, "id"));
    char cancel_url[300];
    snprintf(cancel_url, sizeof(cancel_url), "%s/api/v1/bookings/%s/cancel", BASE_URL, bid);

    Resp r = http_patch_auth(cancel_url, g_token2); /* hanako のトークン */
    ASSERT(r.status == 403, "other user cancel → 403");
    cJSON_Delete(bj); resp_free(&rb); resp_free(&r);
    PASS();
}

/* ─── 管理者APIテスト ────────────────────────────────────────────────────── */

static void test_admin_no_key(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/venues", BASE_URL);
    Resp r = http_post(url, "{\"name\":\"test\",\"area_id\":6}");
    ASSERT(r.status == 403, "no admin key → 403");
    resp_free(&r);
    PASS();
}

static long g_test_venue_id = 0; /* admin_create_venue で設定 */
static long g_test_plan_id  = 0; /* admin_create_plan で設定 */

static void test_admin_create_venue(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/venues", BASE_URL);
    Resp r = http_post_admin(url,
        "{\"name\":\"テスト施設\",\"description\":\"テスト用\","
        "\"area_id\":6,\"address\":\"東京都渋谷区\","
        "\"latitude\":35.6595,\"longitude\":139.7004,\"phone\":\"03-9999-0000\"}");
    ASSERT(r.status == 201, "create venue 201");
    cJSON *j = cJSON_Parse(r.body);
    long vid = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "id"));
    ASSERT(vid > 0, "id > 0");
    g_test_venue_id = vid;
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_admin_create_plan_with_prices(void) {
    /* test_admin_create_venue で作成した venue を使う */
    char body[512];
    snprintf(body, sizeof(body),
        "{\"venue_id\":%ld,\"category_id\":12,\"title\":\"テスト陶芸体験\","
        "\"description\":\"テスト用プラン\",\"duration_minutes\":60,"
        "\"min_participants\":1,\"max_participants\":4,"
        "\"prices\":["
        "{\"participant_type\":\"adult\",\"label\":\"大人\",\"price\":3000},"
        "{\"participant_type\":\"child\",\"label\":\"子供\",\"price\":1500}"
        "]}", g_test_venue_id);
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/plans", BASE_URL);
    Resp r = http_post_admin(url, body);
    ASSERT(r.status == 201, "create plan 201");
    cJSON *j = cJSON_Parse(r.body);
    g_test_plan_id = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "id"));
    ASSERT(g_test_plan_id > 0, "plan id > 0");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_admin_create_schedule(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/plans/%ld/schedules", BASE_URL, g_test_plan_id);
    Resp r = http_post_admin(url,
        "{\"date\":\"2026-05-01\",\"start_time\":\"10:00\","
        "\"end_time\":\"11:00\",\"capacity\":5}");
    ASSERT(r.status == 201, "create schedule 201");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetNumberValue(cJSON_GetObjectItem(j, "id")) > 0, "schedule id > 0");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_admin_update_plan(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/plans/%ld", BASE_URL, g_test_plan_id);
    /* CURLOPT_CUSTOMREQUEST で PATCH を送る */
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "X-Admin-Key: asoview-admin-dev");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"title\":\"更新後タイトル\"}");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r2 = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r2.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    ASSERT(r2.status == 200, "update plan 200");
    resp_free(&r2);
    PASS();
}

static void test_admin_set_prices(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/plans/%ld/prices", BASE_URL, g_test_plan_id);
    Resp r = http_put_admin(url,
        "[{\"participant_type\":\"adult\",\"label\":\"大人（更新）\",\"price\":3500}]");
    ASSERT(r.status == 200, "set prices 200");
    resp_free(&r);

    /* 価格が更新されたか確認 */
    char purl[256]; snprintf(purl, sizeof(purl), "%s/api/v1/plans/%ld", BASE_URL, g_test_plan_id);
    Resp r2 = http_get(purl);
    cJSON *j = cJSON_Parse(r2.body);
    cJSON *prices = cJSON_GetObjectItem(j, "prices");
    ASSERT(cJSON_GetArraySize(prices) == 1, "1 price after replace");
    ASSERT((long)cJSON_GetNumberValue(
               cJSON_GetObjectItem(cJSON_GetArrayItem(prices, 0), "price")) == 3500,
           "price=3500");
    cJSON_Delete(j); resp_free(&r2);
    PASS();
}

static void test_admin_delete_plan(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/plans/%ld", BASE_URL, g_test_plan_id);
    Resp r = http_delete_admin(url);
    ASSERT(r.status == 200, "delete (soft) 200");
    resp_free(&r);

    /* 非公開になったか確認 (is_active=0 → list に出なくなる) */
    char purl[256]; snprintf(purl, sizeof(purl), "%s/api/v1/plans/%ld", BASE_URL, g_test_plan_id);
    Resp r2 = http_get(purl);
    ASSERT(r2.status == 404, "soft-deleted plan → 404");
    resp_free(&r2);
    PASS();
}

static void test_admin_delete_venue(void) {
    /* test_admin_create_venue で作成した venue を削除 */
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/admin/venues/%ld", BASE_URL, g_test_venue_id);
    Resp r = http_delete_admin(url);
    ASSERT(r.status == 200, "delete venue 200");
    resp_free(&r);
    PASS();
}

static void test_search_area_category(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/search?area_id=11&category_id=6", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetArraySize(cJSON_GetObjectItem(j, "plans")) > 0, "found results");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

/* Bearer トークン付き DELETE */
static Resp http_delete_auth(const char *url, const char *token) {
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    char auth_hdr[600];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", token);
    struct curl_slist *hdrs = curl_slist_append(NULL, auth_hdr);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return r;
}

/* ─── ブックマークテスト ─────────────────────────────────────────────────── */

static void test_create_bookmark(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/bookmarks", BASE_URL);
    Resp r = http_post_auth(url, "{\"plan_id\":2}", g_token);
    ASSERT(r.status == 201, "create bookmark 201");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "plan_id")) == 2, "plan_id=2");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_list_user_bookmarks(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/users/1/bookmarks", BASE_URL);
    /* JWT 必須になった → g_token (taro=user_id 1) で取得 */
    Resp r = http_get_auth(url, g_token);
    ASSERT(r.status == 200, "list bookmarks 200");
    cJSON *arr = cJSON_Parse(r.body);
    ASSERT(cJSON_IsArray(arr) && cJSON_GetArraySize(arr) > 0, "has bookmarks");
    cJSON *bm = cJSON_GetArrayItem(arr, 0);
    ASSERT(cJSON_GetObjectItem(bm, "plan_title") != NULL, "has plan_title");
    ASSERT(cJSON_GetObjectItem(bm, "venue_name") != NULL, "has venue_name");
    cJSON_Delete(arr); resp_free(&r);
    PASS();
}

static void test_delete_bookmark(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/bookmarks/2", BASE_URL);
    Resp r = http_delete_auth(url, g_token);
    ASSERT(r.status == 200, "delete bookmark 200");
    resp_free(&r);

    /* 削除後は404 */
    Resp r2 = http_delete_auth(url, g_token);
    ASSERT(r2.status == 404, "already deleted → 404");
    resp_free(&r2);
    PASS();
}

/* ─── DELETE /reviews/:id ────────────────────────────────────────────── */

static long g_review_id = 0; /* test_delete_review で設定 */

static void test_delete_review(void) {
    /* g_token (taro) で予約を作成してレビューを投稿し、削除する */
    /* まず予約 */
    char burl[256]; snprintf(burl, sizeof(burl), "%s/api/v1/bookings", BASE_URL);
    Resp rb = http_post_auth(burl,
        "{\"plan_id\":2,\"schedule_id\":15,"
        "\"participants\":[{\"participant_type\":\"adult\",\"count\":1}]}",
        g_token);
    ASSERT(rb.status == 201, "booking for review test 201");
    cJSON *bj = cJSON_Parse(rb.body);
    const char *bid = cJSON_GetStringValue(cJSON_GetObjectItem(bj, "id"));
    char bid_buf[64] = {0};
    if (bid) strncpy(bid_buf, bid, sizeof(bid_buf)-1);
    cJSON_Delete(bj); resp_free(&rb);

    /* レビュー投稿 */
    char rev_body[256];
    snprintf(rev_body, sizeof(rev_body),
        "{\"plan_id\":2,\"rating\":4,\"comment\":\"削除テスト\",\"booking_id\":\"%s\"}", bid_buf);
    char rurl[256]; snprintf(rurl, sizeof(rurl), "%s/api/v1/reviews", BASE_URL);
    Resp rr = http_post_auth(rurl, rev_body, g_token);
    ASSERT(rr.status == 201, "create review for delete test");
    cJSON *rj = cJSON_Parse(rr.body);
    g_review_id = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(rj, "id"));
    ASSERT(g_review_id > 0, "review id > 0");
    cJSON_Delete(rj); resp_free(&rr);

    /* 他人が削除しようとする → 403 */
    char del_url[256]; snprintf(del_url, sizeof(del_url), "%s/api/v1/reviews/%ld", BASE_URL, g_review_id);
    Resp r403 = http_delete_auth(del_url, g_token2);
    ASSERT(r403.status == 403, "other user delete → 403");
    resp_free(&r403);

    /* 本人が削除 → 200 */
    Resp r200 = http_delete_auth(del_url, g_token);
    ASSERT(r200.status == 200, "own review delete → 200");
    resp_free(&r200);

    /* 再度削除 → 404 */
    Resp r404 = http_delete_auth(del_url, g_token);
    ASSERT(r404.status == 404, "already deleted → 404");
    resp_free(&r404);

    /* 認証なし → 401 */
    Resp r401;
    CURL *c = curl_easy_init();
    Buf b401 = { malloc(1), 0 };
    curl_easy_setopt(c, CURLOPT_URL, del_url);
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &b401);
    curl_easy_perform(c);
    r401.body = b401.data;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r401.status);
    curl_easy_cleanup(c);
    ASSERT(r401.status == 401, "no auth → 401");
    resp_free(&r401);
    PASS();
}

/* ─── GET /admin/bookings ─────────────────────────────────────────────── */

static void test_admin_list_bookings(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/bookings", BASE_URL);
    Resp r = http_get_with_header(url, "X-Admin-Key", "asoview-admin-dev");
    ASSERT(r.status == 200, "admin list bookings 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetObjectItem(j, "bookings") != NULL, "has bookings");
    ASSERT(cJSON_GetObjectItem(j, "total")    != NULL, "has total");
    long tot = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "total"));
    ASSERT(tot > 0, "at least 1 booking");

    /* status フィルタ */
    char furl[256]; snprintf(furl, sizeof(furl), "%s/api/v1/admin/bookings?status=cancelled", BASE_URL);
    Resp rf = http_get_with_header(furl, "X-Admin-Key", "asoview-admin-dev");
    ASSERT(rf.status == 200, "filter by status 200");
    cJSON *jf = cJSON_Parse(rf.body);
    cJSON *arr = cJSON_GetObjectItem(jf, "bookings");
    int n = cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        cJSON *b = cJSON_GetArrayItem(arr, i);
        const char *st = cJSON_GetStringValue(cJSON_GetObjectItem(b, "status"));
        ASSERT(st && strcmp(st, "cancelled") == 0, "all status=cancelled");
    }

    /* auth なし → 403 */
    Resp ra = http_get(url);
    ASSERT(ra.status == 403, "no admin key → 403");

    cJSON_Delete(j); cJSON_Delete(jf); resp_free(&r); resp_free(&rf); resp_free(&ra);
    PASS();
}

/* ─── PATCH /admin/schedules/:id ─────────────────────────────────────── */

static long g_test_schedule_id = 0;

static void test_admin_update_schedule(void) {
    /* 既存スケジュール(id=1)の capacity を更新する */
    g_test_schedule_id = 1;
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/schedules/%ld", BASE_URL, g_test_schedule_id);

    /* capacity を 999 に更新 */
    CURL *curl = curl_easy_init();
    Buf buf = { malloc(1), 0 };
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "X-Admin-Key: asoview-admin-dev");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"capacity\":999}");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_perform(curl);
    Resp r = { buf.data, 0 };
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs); curl_easy_cleanup(curl);
    ASSERT(r.status == 200, "update schedule capacity → 200");
    resp_free(&r);

    /* 容量を booked_count (0) 未満の -1 にしようとする → 400 */
    CURL *c2 = curl_easy_init();
    Buf b2 = { malloc(1), 0 };
    struct curl_slist *h2 = curl_slist_append(NULL, "Content-Type: application/json");
    h2 = curl_slist_append(h2, "X-Admin-Key: asoview-admin-dev");
    curl_easy_setopt(c2, CURLOPT_URL, url);
    curl_easy_setopt(c2, CURLOPT_HTTPHEADER, h2);
    curl_easy_setopt(c2, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(c2, CURLOPT_POSTFIELDS, "{\"capacity\":-1}");
    curl_easy_setopt(c2, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c2, CURLOPT_WRITEDATA, &b2);
    curl_easy_perform(c2);
    Resp r2 = { b2.data, 0 };
    curl_easy_getinfo(c2, CURLINFO_RESPONSE_CODE, &r2.status);
    curl_slist_free_all(h2); curl_easy_cleanup(c2);
    ASSERT(r2.status == 400, "capacity below booked → 400");
    resp_free(&r2);

    /* 存在しないスケジュール */
    char nourl[256]; snprintf(nourl, sizeof(nourl), "%s/api/v1/admin/schedules/999999", BASE_URL);
    CURL *c3 = curl_easy_init();
    Buf b3 = { malloc(1), 0 };
    struct curl_slist *h3 = curl_slist_append(NULL, "Content-Type: application/json");
    h3 = curl_slist_append(h3, "X-Admin-Key: asoview-admin-dev");
    curl_easy_setopt(c3, CURLOPT_URL, nourl);
    curl_easy_setopt(c3, CURLOPT_HTTPHEADER, h3);
    curl_easy_setopt(c3, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(c3, CURLOPT_POSTFIELDS, "{\"capacity\":10}");
    curl_easy_setopt(c3, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c3, CURLOPT_WRITEDATA, &b3);
    curl_easy_perform(c3);
    Resp r3 = { b3.data, 0 };
    curl_easy_getinfo(c3, CURLINFO_RESPONSE_CODE, &r3.status);
    curl_slist_free_all(h3); curl_easy_cleanup(c3);
    ASSERT(r3.status == 404, "nonexistent schedule → 404");
    resp_free(&r3);
    PASS();
}

/* ─── GET /admin/reviews ──────────────────────────────────────────────── */

static void test_admin_list_reviews(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/reviews", BASE_URL);
    Resp r = http_get_with_header(url, "X-Admin-Key", "asoview-admin-dev");
    ASSERT(r.status == 200, "admin list reviews 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetObjectItem(j, "reviews") != NULL, "has reviews array");
    ASSERT(cJSON_GetObjectItem(j, "total")   != NULL, "has total");

    /* rating フィルタ */
    char furl[256]; snprintf(furl, sizeof(furl), "%s/api/v1/admin/reviews?rating=5", BASE_URL);
    Resp rf = http_get_with_header(furl, "X-Admin-Key", "asoview-admin-dev");
    ASSERT(rf.status == 200, "rating filter 200");
    cJSON *jf = cJSON_Parse(rf.body);
    cJSON *arr = cJSON_GetObjectItem(jf, "reviews");
    for (int i = 0; i < cJSON_GetArraySize(arr); i++) {
        cJSON *rv = cJSON_GetArrayItem(arr, i);
        ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(rv, "rating")) == 5,
               "all rating=5");
    }

    /* 認証なし → 403 */
    Resp ra = http_get(url);
    ASSERT(ra.status == 403, "no admin key → 403");

    cJSON_Delete(j); cJSON_Delete(jf); resp_free(&r); resp_free(&rf); resp_free(&ra);
    PASS();
}

/* ─── DELETE /admin/reviews/:id ──────────────────────────────────────── */

static void test_admin_delete_review(void) {
    /* まずレビューを1件作成してから削除する */
    char burl[256]; snprintf(burl, sizeof(burl), "%s/api/v1/bookings", BASE_URL);
    Resp rb = http_post_auth(burl,
        "{\"plan_id\":3,\"schedule_id\":21,"
        "\"participants\":[{\"participant_type\":\"adult\",\"count\":1}]}",
        g_token);
    ASSERT(rb.status == 201, "booking for admin delete review");
    cJSON *bj = cJSON_Parse(rb.body);
    const char *bid = cJSON_GetStringValue(cJSON_GetObjectItem(bj, "id"));
    char bid_buf[64] = {0};
    if (bid) strncpy(bid_buf, bid, sizeof(bid_buf)-1);
    cJSON_Delete(bj); resp_free(&rb);

    char rev_body[256];
    snprintf(rev_body, sizeof(rev_body),
        "{\"plan_id\":3,\"rating\":2,\"comment\":\"管理者削除テスト\",\"booking_id\":\"%s\"}", bid_buf);
    char rurl[256]; snprintf(rurl, sizeof(rurl), "%s/api/v1/reviews", BASE_URL);
    Resp rr = http_post_auth(rurl, rev_body, g_token);
    ASSERT(rr.status == 201, "review created 201");
    cJSON *rj = cJSON_Parse(rr.body);
    long rid = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(rj, "id"));
    ASSERT(rid > 0, "review id > 0");
    cJSON_Delete(rj); resp_free(&rr);

    /* 管理者が削除 */
    char del_url[256]; snprintf(del_url, sizeof(del_url), "%s/api/v1/admin/reviews/%ld", BASE_URL, rid);
    Resp rd = http_delete_admin(del_url);
    ASSERT(rd.status == 200, "admin delete review → 200");
    resp_free(&rd);

    /* 再削除 → 404 */
    Resp rd2 = http_delete_admin(del_url);
    ASSERT(rd2.status == 404, "already deleted → 404");
    resp_free(&rd2);

    /* 認証なし → 403 */
    CURL *c = curl_easy_init();
    Buf b = { malloc(1), 0 };
    curl_easy_setopt(c, CURLOPT_URL, del_url);
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &b);
    curl_easy_perform(c);
    long st403; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &st403);
    curl_easy_cleanup(c); free(b.data);
    ASSERT(st403 == 403, "no admin key → 403");
    PASS();
}

/* ─── GET /admin/users ────────────────────────────────────────────────── */

static void test_admin_list_users(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/users", BASE_URL);
    Resp r = http_get_with_header(url, "X-Admin-Key", "asoview-admin-dev");
    ASSERT(r.status == 200, "admin list users 200");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT(cJSON_GetObjectItem(j, "users") != NULL, "has users array");
    long tot = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "total"));
    ASSERT(tot > 0, "at least 1 user");

    cJSON *users = cJSON_GetObjectItem(j, "users");
    cJSON *first = cJSON_GetArrayItem(users, 0);
    ASSERT(cJSON_GetObjectItem(first, "email")         != NULL, "has email");
    ASSERT(cJSON_GetObjectItem(first, "booking_count") != NULL, "has booking_count");

    /* email 検索 */
    char furl[256]; snprintf(furl, sizeof(furl), "%s/api/v1/admin/users?q=taro", BASE_URL);
    Resp rf = http_get_with_header(furl, "X-Admin-Key", "asoview-admin-dev");
    ASSERT(rf.status == 200, "email search 200");
    cJSON *jf = cJSON_Parse(rf.body);
    cJSON *arr = cJSON_GetObjectItem(jf, "users");
    for (int i = 0; i < cJSON_GetArraySize(arr); i++) {
        const char *email = cJSON_GetStringValue(
            cJSON_GetObjectItem(cJSON_GetArrayItem(arr, i), "email"));
        ASSERT(email && strstr(email, "taro"), "email contains 'taro'");
    }

    /* 認証なし → 403 */
    Resp ra = http_get(url);
    ASSERT(ra.status == 403, "no admin key → 403");

    cJSON_Delete(j); cJSON_Delete(jf); resp_free(&r); resp_free(&rf); resp_free(&ra);
    PASS();
}

/* ── Batch 3: セキュリティ・新機能テスト ─────────────────────────────── */

/* GET /users/:id は JWT 必須、他人のプロフィールは 403 */
static void test_get_user_auth(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/users/1", BASE_URL);

    /* 未認証 → 401 */
    Resp r1 = http_get(url);
    ASSERT(r1.status == 401, "no auth → 401");
    resp_free(&r1);

    /* 本人 (taro, id=1) → 200 */
    Resp r2 = http_get_auth(url, g_token);
    ASSERT(r2.status == 200, "own profile → 200");
    cJSON *j = cJSON_Parse(r2.body);
    ASSERT(cJSON_GetObjectItem(j, "email") != NULL, "has email");
    cJSON_Delete(j); resp_free(&r2);

    /* 他人 (hanako=id2 が id=1 を取得) → 403 */
    Resp r3 = http_get_auth(url, g_token2);
    ASSERT(r3.status == 403, "other user → 403");
    resp_free(&r3);

    PASS();
}

/* POST /users に無効なメールアドレス → 400 */
static void test_create_user_invalid_email(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/users", BASE_URL);

    const char *cases[] = {
        "{\"email\":\"notanemail\",\"name\":\"X\",\"password\":\"pass1234\"}",
        "{\"email\":\"@example.com\",\"name\":\"X\",\"password\":\"pass1234\"}",
        "{\"email\":\"user@\",\"name\":\"X\",\"password\":\"pass1234\"}",
    };
    for (int i = 0; i < 3; i++) {
        Resp r = http_post(url, cases[i]);
        ASSERT(r.status == 400, "invalid email → 400");
        resp_free(&r);
    }
    PASS();
}

/* POST /auth/refresh — 有効なトークンで新しいトークンを発行 */
static void test_auth_refresh(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/auth/refresh", BASE_URL);

    /* 有効なトークン → 200 + 新しいトークン */
    Resp r = http_post_auth(url, "", g_token);
    ASSERT(r.status == 200, "refresh with valid token → 200");
    cJSON *j = cJSON_Parse(r.body);
    const char *new_tok = cJSON_GetStringValue(cJSON_GetObjectItem(j, "token"));
    ASSERT(new_tok && strlen(new_tok) > 10, "has new token");
    cJSON_Delete(j); resp_free(&r);

    /* 未認証 → 401 */
    Resp r2 = http_post(url, "");
    ASSERT(r2.status == 401, "no auth → 401");
    resp_free(&r2);

    PASS();
}

/* POST /admin/upload-url — S3 presigned URL 取得 */
static void test_admin_upload_url(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/admin/upload-url", BASE_URL);

    /* S3 認証情報が未設定 → 503 */
    const char *body = "{\"filename\":\"test.jpg\",\"content_type\":\"image/jpeg\"}";
    Resp r = http_post_admin(url, body);
    /* S3 env vars が設定されていなければ 503、設定されていれば 200 */
    ASSERT(r.status == 503 || r.status == 200, "upload-url returns 503 or 200");
    resp_free(&r);

    /* 管理者キーなし → 403 */
    Resp r2 = http_post(url, body);
    ASSERT(r2.status == 403, "no admin key → 403");
    resp_free(&r2);

    PASS();
}

/* ── 管理者ダッシュボード HTML ────────────────────────────────────────── */

static void test_admin_dashboard(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/admin", BASE_URL);

    /* GET /admin → 200 HTML */
    Resp r = http_get(url);
    ASSERT(r.status == 200, "GET /admin → 200");
    ASSERT(r.body && strstr(r.body, "Asoview Admin"), "contains title");
    ASSERT(r.body && strstr(r.body, "管理エンドポイント"), "contains 管理エンドポイント");
    ASSERT(r.body && strstr(r.body, "/api/v1/metrics"), "contains metrics link");
    resp_free(&r);

    /* /admin/ (trailing slash) も同じ */
    char url2[256]; snprintf(url2, sizeof(url2), "%s/admin/", BASE_URL);
    Resp r2 = http_get(url2);
    ASSERT(r2.status == 200, "GET /admin/ → 200");
    resp_free(&r2);

    PASS();
}

/* ── Prometheus メトリクス ────────────────────────────────────────────── */

static void test_metrics(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/metrics", BASE_URL);

    Resp r = http_get(url);
    ASSERT(r.status == 200, "GET /metrics → 200");
    ASSERT(r.body && strstr(r.body, "asoview_requests_total"),
           "has requests_total counter");
    ASSERT(r.body && strstr(r.body, "asoview_errors_4xx_total"),
           "has 4xx counter");
    ASSERT(r.body && strstr(r.body, "asoview_errors_5xx_total"),
           "has 5xx counter");
    ASSERT(r.body && strstr(r.body, "asoview_uptime_seconds"),
           "has uptime gauge");
    resp_free(&r);

    /* カウンターが 0 より大きい（テストが進んだ後なので確実に > 0）*/
    Resp r2 = http_get(url);
    cJSON *j = cJSON_Parse(r2.body);
    /* Prometheus テキストフォーマット（JSON ではない）— body に数値が含まれること */
    ASSERT(r2.body && strlen(r2.body) > 20, "non-empty Prometheus text");
    cJSON_Delete(j); resp_free(&r2);

    PASS();
}

/* ── X-Request-ID ────────────────────────────────────────────────────── */

static void test_x_request_id(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/health", BASE_URL);

    Resp r = http_get_capture_header(url, "X-Request-ID");
    ASSERT(r.status == 200, "health → 200");
    ASSERT(g_captured_header_val[0] != '\0', "X-Request-ID header present");
    /* UUID 形式: 8-4-4-4-12 = 36文字 */
    ASSERT(strlen(g_captured_header_val) >= 32, "X-Request-ID has UUID-like length");
    resp_free(&r);

    /* 2回連続で異なる X-Request-ID */
    char first_id[256];
    strncpy(first_id, g_captured_header_val, sizeof(first_id) - 1);
    Resp r2 = http_get_capture_header(url, "X-Request-ID");
    ASSERT(r2.status == 200, "second request → 200");
    ASSERT(strcmp(first_id, g_captured_header_val) != 0, "X-Request-ID is unique per request");
    resp_free(&r2);

    PASS();
}

/* ── ETag キャッシング ───────────────────────────────────────────────── */

static void test_etag_caching(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/venues", BASE_URL);

    /* 最初のリクエスト → 200 + ETag */
    Resp r1 = http_get_capture_header(url, "ETag");
    ASSERT(r1.status == 200, "first request → 200");
    ASSERT(g_captured_header_val[0] != '\0', "ETag header present");
    char etag[256];
    strncpy(etag, g_captured_header_val, sizeof(etag) - 1);
    resp_free(&r1);

    /* If-None-Match が一致 → 304 Not Modified */
    Resp r2 = http_get_if_none_match(url, etag);
    ASSERT(r2.status == 304, "If-None-Match match → 304");
    resp_free(&r2);

    /* 異なる ETag → 200 */
    Resp r3 = http_get_if_none_match(url, "\"0000000000000000\"");
    ASSERT(r3.status == 200, "wrong ETag → 200");
    resp_free(&r3);

    /* /api/v1/plans も ETag 対応 */
    char purl[256]; snprintf(purl, sizeof(purl), "%s/api/v1/plans", BASE_URL);
    Resp r4 = http_get_capture_header(purl, "ETag");
    ASSERT(r4.status == 200, "plans → 200");
    ASSERT(g_captured_header_val[0] != '\0', "plans has ETag");
    char plan_etag[256];
    strncpy(plan_etag, g_captured_header_val, sizeof(plan_etag) - 1);
    resp_free(&r4);

    Resp r5 = http_get_if_none_match(purl, plan_etag);
    ASSERT(r5.status == 304, "plans If-None-Match → 304");
    resp_free(&r5);

    PASS();
}

/* ── ウェイトリスト CRUD ─────────────────────────────────────────────── */

static long g_waitlist_id = 0;

static void test_waitlist(void) {
    char url[256];

    /* 未認証で POST → 401 */
    snprintf(url, sizeof(url), "%s/api/v1/waitlist", BASE_URL);
    Resp r0 = http_post(url, "{\"schedule_id\":10}");
    ASSERT(r0.status == 401, "no auth → 401");
    resp_free(&r0);

    /* schedule_id 欠落 → 400 */
    Resp r_bad = http_post_auth(url, "{}", g_token);
    ASSERT(r_bad.status == 400, "missing schedule_id → 400");
    resp_free(&r_bad);

    /* 存在しない schedule_id → 404 */
    Resp r_nf = http_post_auth(url, "{\"schedule_id\":999999}", g_token);
    ASSERT(r_nf.status == 404, "unknown schedule → 404");
    resp_free(&r_nf);

    /* 正常登録 → 201 */
    Resp r1 = http_post_auth(url, "{\"schedule_id\":10}", g_token);
    ASSERT(r1.status == 201, "create waitlist → 201");
    cJSON *j1 = cJSON_Parse(r1.body);
    ASSERT(j1 != NULL, "valid JSON");
    ASSERT(cJSON_GetNumberValue(cJSON_GetObjectItem(j1, "id")) >= 1, "id >= 1");
    ASSERT(cJSON_GetNumberValue(cJSON_GetObjectItem(j1, "position")) >= 1, "position >= 1");
    g_waitlist_id = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(j1, "id"));
    cJSON_Delete(j1); resp_free(&r1);

    /* 重複登録 → 409 */
    Resp r2 = http_post_auth(url, "{\"schedule_id\":10}", g_token);
    ASSERT(r2.status == 409, "duplicate → 409");
    resp_free(&r2);

    /* hanako も同じスケジュールに登録 (position=2 になるはず) */
    Resp r3 = http_post_auth(url, "{\"schedule_id\":10}", g_token2);
    ASSERT(r3.status == 201, "hanako waitlist → 201");
    cJSON *j3 = cJSON_Parse(r3.body);
    ASSERT(cJSON_GetNumberValue(cJSON_GetObjectItem(j3, "position")) == 2, "hanako is position 2");
    long hanako_wid = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(j3, "id"));
    cJSON_Delete(j3); resp_free(&r3);

    /* GET ウェイトリスト一覧 */
    snprintf(url, sizeof(url), "%s/api/v1/waitlist/schedule/10", BASE_URL);
    Resp r4 = http_get(url);
    ASSERT(r4.status == 200, "list waitlist → 200");
    cJSON *j4 = cJSON_Parse(r4.body);
    cJSON *wl = cJSON_GetObjectItem(j4, "waitlist");
    ASSERT(cJSON_IsArray(wl) && cJSON_GetArraySize(wl) == 2, "2 entries");
    cJSON_Delete(j4); resp_free(&r4);

    /* 他人のエントリを削除 → 404（hanako が taro のエントリを削除） */
    char del_url[256];
    snprintf(del_url, sizeof(del_url), "%s/api/v1/waitlist/%ld", BASE_URL, g_waitlist_id);
    Resp r5 = http_delete_auth(del_url, g_token2);
    ASSERT(r5.status == 404, "delete other's entry → 404");
    resp_free(&r5);

    /* 自分のエントリを削除 */
    snprintf(del_url, sizeof(del_url), "%s/api/v1/waitlist/%ld", BASE_URL, hanako_wid);
    Resp r6 = http_delete_auth(del_url, g_token2);
    ASSERT(r6.status == 200, "hanako self-delete → 200");
    resp_free(&r6);

    /* taro も削除 */
    snprintf(del_url, sizeof(del_url), "%s/api/v1/waitlist/%ld", BASE_URL, g_waitlist_id);
    Resp r7 = http_delete_auth(del_url, g_token);
    ASSERT(r7.status == 200, "taro self-delete → 200");
    resp_free(&r7);

    /* 削除後はリストが空 */
    snprintf(url, sizeof(url), "%s/api/v1/waitlist/schedule/10", BASE_URL);
    Resp r8 = http_get(url);
    cJSON *j8 = cJSON_Parse(r8.body);
    ASSERT(cJSON_GetArraySize(cJSON_GetObjectItem(j8, "waitlist")) == 0, "empty after delete");
    cJSON_Delete(j8); resp_free(&r8);

    PASS();
}

/* ── JWT ログアウト / ブラックリスト ───────────────────────────────────── */

static void test_auth_logout(void) {
    char login_url[256], logout_url[256], profile_url[256];
    snprintf(login_url,   sizeof(login_url),   "%s/api/v1/auth/login",   BASE_URL);
    snprintf(logout_url,  sizeof(logout_url),  "%s/api/v1/auth/logout",  BASE_URL);
    snprintf(profile_url, sizeof(profile_url), "%s/api/v1/users/1",      BASE_URL);

    /* ログアウト専用の新規トークンを取得（g_token は汚染しない） */
    Resp lr = http_post(login_url,
        "{\"email\":\"taro@example.com\",\"password\":\"resetpass456\"}");
    ASSERT(lr.status == 200, "re-login → 200");
    cJSON *lj = cJSON_Parse(lr.body);
    const char *tp = cJSON_GetStringValue(cJSON_GetObjectItem(lj, "token"));
    ASSERT(tp && strlen(tp) > 10, "got logout_token");
    char logout_tok[512] = {0};
    strncpy(logout_tok, tp, sizeof(logout_tok) - 1);
    cJSON_Delete(lj); resp_free(&lr);

    /* 認証なしでログアウト → 401 */
    Resp r1 = http_post(logout_url, "");
    ASSERT(r1.status == 401, "logout without token → 401");
    resp_free(&r1);

    /* ログアウト前にトークンは有効 */
    Resp r2 = http_get_auth(profile_url, logout_tok);
    ASSERT(r2.status == 200, "token valid before logout");
    resp_free(&r2);

    /* ログアウト → 200 */
    Resp r3 = http_post_auth(logout_url, "", logout_tok);
    ASSERT(r3.status == 200, "logout → 200");
    resp_free(&r3);

    /* ログアウト済みトークンは 401 */
    Resp r4 = http_get_auth(profile_url, logout_tok);
    ASSERT(r4.status == 401, "blacklisted token → 401");
    resp_free(&r4);

    /* g_token は別のトークンなので影響なし */
    Resp r5 = http_get_auth(profile_url, g_token);
    ASSERT(r5.status == 200, "g_token still valid after other logout");
    resp_free(&r5);

    PASS();
}

/* ── アカウントロックアウト ──────────────────────────────────────────── */

static void test_account_lockout(void) {
    char reg_url[256], login_url[256];
    snprintf(reg_url,   sizeof(reg_url),   "%s/api/v1/users",      BASE_URL);
    snprintf(login_url, sizeof(login_url), "%s/api/v1/auth/login", BASE_URL);

    /* テスト専用ユーザー作成 */
    Resp r0 = http_post(reg_url,
        "{\"email\":\"lockme@example.com\",\"name\":\"LockTest\","
        "\"password\":\"LockPass123\"}");
    ASSERT(r0.status == 201, "create locktest user → 201");
    resp_free(&r0);

    /* 5回連続ログイン失敗（それぞれ 400）*/
    for (int i = 0; i < 5; i++) {
        Resp rf = http_post(login_url,
            "{\"email\":\"lockme@example.com\",\"password\":\"wrongpass\"}");
        ASSERT(rf.status == 400, "wrong password → 400");
        resp_free(&rf);
    }

    /* 6回目 → 429 (アカウントロック) */
    Resp rl = http_post(login_url,
        "{\"email\":\"lockme@example.com\",\"password\":\"wrongpass\"}");
    ASSERT(rl.status == 429, "6th attempt → 429 locked");
    cJSON *jl = cJSON_Parse(rl.body);
    ASSERT(jl != NULL, "valid JSON on lockout");
    const char *errmsg = cJSON_GetStringValue(cJSON_GetObjectItem(jl, "error"));
    ASSERT(errmsg && strstr(errmsg, "ロック"), "error mentions lockout");
    cJSON_Delete(jl); resp_free(&rl);

    /* 正しいパスワードでも locked_until が切れるまで 429 */
    Resp rl2 = http_post(login_url,
        "{\"email\":\"lockme@example.com\",\"password\":\"LockPass123\"}");
    ASSERT(rl2.status == 429, "correct pass during lock → 429");
    resp_free(&rl2);

    PASS();
}

/* ── Webhook 冪等性 ──────────────────────────────────────────────────── */

static void test_webhook_idempotency(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/webhooks/stripe", BASE_URL);
    const char *secret  = "whtest-secret";
    /* 固有の event_id を持つテストペイロード */
    const char *payload =
        "{\"id\":\"evt_test_idempotency_9001\","
        "\"type\":\"payment_intent.payment_failed\","
        "\"data\":{\"object\":{\"metadata\":{}}}}";

    /* 1回目: 正常受信 → 200 {"received":true} */
    Resp r1 = http_post_stripe(url, payload, secret);
    ASSERT(r1.status == 200, "first webhook → 200");
    ASSERT(r1.body && strstr(r1.body, "received"), "body has 'received'");
    resp_free(&r1);

    /* 2回目: 同一 event_id → 200 {"status":"already processed"} */
    Resp r2 = http_post_stripe(url, payload, secret);
    ASSERT(r2.status == 200, "duplicate webhook → 200");
    ASSERT(r2.body && strstr(r2.body, "already processed"),
           "body has 'already processed'");
    resp_free(&r2);

    /* 3回目も冪等（何度送っても同じ） */
    Resp r3 = http_post_stripe(url, payload, secret);
    ASSERT(r3.status == 200, "third webhook → 200");
    ASSERT(r3.body && strstr(r3.body, "already processed"),
           "third also 'already processed'");
    resp_free(&r3);

    /* 別の event_id → 新規受信 */
    const char *payload2 =
        "{\"id\":\"evt_test_idempotency_9002\","
        "\"type\":\"payment_intent.payment_failed\","
        "\"data\":{\"object\":{\"metadata\":{}}}}";
    Resp r4 = http_post_stripe(url, payload2, secret);
    ASSERT(r4.status == 200, "new event_id → 200");
    ASSERT(r4.body && strstr(r4.body, "received"), "new event has 'received'");
    resp_free(&r4);

    /* 署名なし → 400 */
    Resp r5 = http_post(url, payload);
    ASSERT(r5.status == 400, "no Stripe-Signature → 400");
    resp_free(&r5);

    PASS();
}

/* ── POST /api/v1/checkout/session ──────────────────────────────────── */

static void test_checkout_session(void) {
    char url[256];
    snprintf(url, sizeof(url), "%s/api/v1/checkout/session", BASE_URL);

    /* 未認証 → 401 */
    Resp r_unauth = http_post(url, "{\"success_url\":\"http://localhost/ok\","
                                    "\"cancel_url\":\"http://localhost/cancel\"}");
    ASSERT(r_unauth.status == 401, "checkout no auth → 401");
    resp_free(&r_unauth);

    /* 不正な success_url (SSRF 防止) → 400 */
    Resp r_ssrf = http_post_auth(url,
        "{\"success_url\":\"javascript:alert(1)\","
        "\"cancel_url\":\"http://localhost/cancel\"}",
        g_token);
    ASSERT(r_ssrf.status == 400, "checkout javascript: url → 400");
    resp_free(&r_ssrf);

    /* cancel_url が不正 → 400 */
    Resp r_ssrf2 = http_post_auth(url,
        "{\"success_url\":\"http://localhost/ok\","
        "\"cancel_url\":\"file:///etc/passwd\"}",
        g_token);
    ASSERT(r_ssrf2.status == 400, "checkout file: url → 400");
    resp_free(&r_ssrf2);

    /* Stripe キー未設定なので 502 になる（Stripe APIへの接続失敗） */
    Resp r_ok = http_post_auth(url,
        "{\"success_url\":\"http://localhost/ok\","
        "\"cancel_url\":\"http://localhost/cancel\"}",
        g_token);
    ASSERT(r_ok.status == 502 || r_ok.status == 200,
           "checkout with no Stripe key → 502 (or 200 if key is set)");
    resp_free(&r_ok);

    /* success_url / cancel_url 省略時はデフォルトを使う → 同じく 502/200 */
    Resp r_def = http_post_auth(url, "{}", g_token);
    ASSERT(r_def.status == 502 || r_def.status == 200,
           "checkout defaults → 502/200");
    resp_free(&r_def);

    PASS();
}

/* ─── Server startup (fork) ──────────────────────────────────────────── */

static int wait_for_port(int port, int timeout_ms) {
    for (int i = 0; i < timeout_ms / 50; i++) {
        usleep(50000);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int rc = connect(fd, (struct sockaddr*)&sa, sizeof(sa));
        close(fd);
        if (rc == 0) return 0;
    }
    return -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* line-buffered so output appears immediately */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* 前回の残留プロセスをクリーンアップ */
    system("pkill -f 'asoview-c.*3998' 2>/dev/null; true");
    usleep(200000); /* 200ms 待機 */

    const char *db_path = "/tmp/asoview_c_test.db";
    unlink(db_path);
    unlink("/tmp/asoview_c_test.db-wal");
    unlink("/tmp/asoview_c_test.db-shm");

    /* Webhook テスト用シークレットを子プロセスに継承させる */
    setenv("STRIPE_WEBHOOK_SECRET", "whtest-secret", 1);

    /* Start server as child process */
    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        execlp("./asoview-c", "./asoview-c", db_path, "3998", NULL);
        perror("exec"); exit(1);
    }

    /* Wait for server to start */
    if (wait_for_port(3998, 5000) != 0) {
        fprintf(stderr, "Server did not start in time\n");
        kill(pid, 9);
        return 1;
    }

    BASE_URL = "http://127.0.0.1:3998";
    printf("\n=== あそビュー C版 統合テスト ===\n\n");

    /* ── 基本エンドポイント ── */
    test_health();
    test_list_areas();
    test_list_categories();
    test_list_venues();
    test_list_venues_area_filter();
    test_get_venue();
    test_get_venue_not_found();
    test_list_plans();
    test_list_plans_filter_category();
    test_list_plans_filter_date();
    test_get_plan();
    test_list_schedules();
    test_list_schedules_by_date();
    /* ── ユーザー / 認証 ── */
    test_create_user();
    test_create_user_duplicate();
    test_create_user_short_password();
    test_login();             /* g_token を設定 */
    test_login_token2();      /* g_token2 を設定 */
    test_login_wrong_password();
    /* ── 予約 (JWT必須) ── */
    test_booking_requires_auth();
    test_create_and_get_booking(); /* g_booking_id を設定 */
    test_booking_capacity_check();
    test_list_user_bookings();
    /* ── キャンセル ── */
    test_cancel_booking();
    test_cancel_booking_unauthorized();
    /* ── レビュー / 検索 ── */
    test_create_review();
    test_create_review_invalid_rating();
    test_create_review_unbooked();
    test_search_keyword();
    test_search_no_results();
    test_search_area_category();
    /* ── 管理者API ── */
    test_admin_no_key();
    test_admin_create_venue();
    test_admin_create_plan_with_prices();
    test_admin_create_schedule();
    test_admin_update_plan();
    test_admin_set_prices();
    test_admin_delete_plan();
    test_admin_delete_venue();
    /* ── ブックマーク ── */
    test_create_bookmark();
    test_list_user_bookmarks();
    test_delete_bookmark();
    /* ── アクセス制御 ── */
    test_booking_access_control();
    test_booking_list_access_control();
    /* ── 新機能 ── */
    test_reviews_pagination();
    test_bookmark_list_auth();
    test_admin_list_venues();
    test_admin_list_plans();
    test_change_password();
    test_forgot_reset_password();
    /* ── 新機能 (Batch 2) ── */
    test_delete_review();
    test_admin_list_bookings();
    test_admin_update_schedule();
    test_admin_list_reviews();
    test_admin_delete_review();
    test_admin_list_users();

    /* ── Batch 3: セキュリティ・新機能 ── */
    test_get_user_auth();
    test_create_user_invalid_email();
    test_auth_refresh();
    test_admin_upload_url();

    /* ── Batch 4: 11機能の新規テスト ── */
    test_admin_dashboard();
    test_metrics();
    test_x_request_id();
    test_etag_caching();
    test_waitlist();
    test_auth_logout();
    test_account_lockout();
    test_webhook_idempotency();

    /* ── Batch 5: Checkout Session ── */
    test_checkout_session();

    kill(pid, 15);

    printf("\n=== 結果: %d passed, %d failed ===\n\n", passed, failed);
    curl_global_cleanup();
    return failed == 0 ? 0 : 1;
}
