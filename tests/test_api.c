/*
 * あそビュー C版 統合テスト
 * ビルド: make test
 * 依存: libcurl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <curl/curl.h>
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

    /* GET */
    char get_url[300];
    snprintf(get_url, sizeof(get_url), "%s/api/v1/bookings/%s", BASE_URL, bid);
    Resp r2 = http_get(get_url);
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
        "{\"plan_id\":4,\"schedule_id\":12,"
        "\"participants\":[{\"participant_type\":\"adult\",\"count\":1}]}",
        g_token2);
    ASSERT(rb.status == 201, "hanako booking created");
    resp_free(&rb);

    snprintf(url, sizeof(url), "%s/api/v1/users/2/bookings", BASE_URL);
    Resp r = http_get(url);
    ASSERT(r.status == 200, "expected 200");
    cJSON *arr = cJSON_Parse(r.body);
    ASSERT(cJSON_IsArray(arr) && cJSON_GetArraySize(arr) > 0, "not empty");
    cJSON_Delete(arr); resp_free(&r);
    PASS();
}

static void test_create_review(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/reviews", BASE_URL);
    Resp r = http_post(url,
        "{\"user_id\":1,\"plan_id\":1,\"rating\":5,"
        "\"comment\":\"最高でした！\"}");
    ASSERT(r.status == 201, "expected 201");
    cJSON *j = cJSON_Parse(r.body);
    ASSERT((long)cJSON_GetNumberValue(cJSON_GetObjectItem(j, "rating")) == 5, "rating=5");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_create_review_invalid_rating(void) {
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/reviews", BASE_URL);
    Resp r = http_post(url, "{\"user_id\":1,\"plan_id\":1,\"rating\":6}");
    ASSERT(r.status == 400, "expected 400");
    resp_free(&r);
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
    Resp r2 = http_get(get_url);
    cJSON *j = cJSON_Parse(r2.body);
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
    ASSERT(cJSON_GetNumberValue(cJSON_GetObjectItem(j, "id")) > 0, "plan id > 0");
    cJSON_Delete(j); resp_free(&r);
    PASS();
}

static void test_admin_create_schedule(void) {
    /* plan_id は seed の最後(22) + 1 = 23 */
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/plans/23/schedules", BASE_URL);
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
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/plans/23", BASE_URL);
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
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/plans/23/prices", BASE_URL);
    Resp r = http_put_admin(url,
        "[{\"participant_type\":\"adult\",\"label\":\"大人（更新）\",\"price\":3500}]");
    ASSERT(r.status == 200, "set prices 200");
    resp_free(&r);

    /* 価格が更新されたか確認 */
    char purl[256]; snprintf(purl, sizeof(purl), "%s/api/v1/plans/23", BASE_URL);
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
    char url[256]; snprintf(url, sizeof(url), "%s/api/v1/admin/plans/23", BASE_URL);
    Resp r = http_delete_admin(url);
    ASSERT(r.status == 200, "delete (soft) 200");
    resp_free(&r);

    /* 非公開になったか確認 (is_active=0 → list に出なくなる) */
    char purl[256]; snprintf(purl, sizeof(purl), "%s/api/v1/plans/23", BASE_URL);
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

    const char *db_path = "/tmp/asoview_c_test.db";
    unlink(db_path);

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

    kill(pid, 15);

    printf("\n=== 結果: %d passed, %d failed ===\n\n", passed, failed);
    curl_global_cleanup();
    return failed == 0 ? 0 : 1;
}
