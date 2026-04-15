#include "handlers.h"
#include "db.h"
#include "utils.h"
#include "stripe.h"
#include "mailer.h"
#include "metrics.h"
#include "waitlist.h"
#include "rate_limit.h"
#include "audit.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <zlib.h>
#include <curl/curl.h>

#define MAX_BUF 256

/* ─── X-Request-ID（main.c から設定される） ──────────────────────────────── */
char g_request_id[40] = "none";

/* ─── Per-request フラグ（シングルスレッドなのでグローバルで安全） ────────── */
int g_accept_gzip = 0;   /* 1 = クライアントが gzip を受け付ける */
int g_lang_en     = 0;   /* 1 = Accept-Language: en */

/* ─── i18n ヘルパー ─────────────────────────────────────────────────────── */
#define T(ja, en) (g_lang_en ? (en) : (ja))

/* ─── gzip 圧縮ヘルパー ─────────────────────────────────────────────────── */
static int gzip_compress(const char *src, size_t src_len,
                          char **dst_out, size_t *dst_len_out) {
    z_stream zs = {0};
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return -1;
    size_t bound = deflateBound(&zs, (uLong)src_len) + 64;
    char *buf = malloc(bound);
    if (!buf) { deflateEnd(&zs); return -1; }
    zs.next_in  = (Bytef*)src;
    zs.avail_in = (uInt)src_len;
    zs.next_out  = (Bytef*)buf;
    zs.avail_out = (uInt)bound;
    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        free(buf); deflateEnd(&zs); return -1;
    }
    *dst_len_out = (size_t)zs.total_out;
    deflateEnd(&zs);
    *dst_out = buf;
    return 0;
}

/* ─── ETag: DJB2 ハッシュ ───────────────────────────────────────────────── */
static uint32_t djb2_hash(const char *s, size_t len) {
    uint32_t h = 5381;
    for (size_t i = 0; i < len; i++) h = h * 33 ^ (unsigned char)s[i];
    return h;
}

/* ─── 動的 CORS ヘッダー（CORS_ORIGIN 環境変数 + X-Request-ID 対応） ─────── */

static const char *get_cors_headers(void) {
    static char buf[700];
    const char *origin = getenv("CORS_ORIGIN");
    if (!origin || !*origin) origin = "*";
    /* FORCE_HTTPS=true のとき（Nginx TLS 終端時）HSTS を付与 */
    const char *force_https = getenv("FORCE_HTTPS");
    int add_hsts = (force_https && (strcmp(force_https, "true") == 0 ||
                                    strcmp(force_https, "1") == 0));
    snprintf(buf, sizeof(buf),
             "Content-Type: application/json\r\n"
             "Access-Control-Allow-Origin: %s\r\n"
             "X-Request-ID: %s\r\n"
             "%s",
             origin, g_request_id,
             add_hsts ? "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" : "");
    return buf;
}
#define CORS_HEADERS get_cors_headers()

/* ─── Helpers ────────────────────────────────────────────────────────────── */

void send_json_str(struct mg_connection *c, int status,
                   const char *extra_hdrs, const char *body) {
    mg_http_reply(c, status,
                  extra_hdrs ? extra_hdrs : CORS_HEADERS,
                  "%s", body);
}

/* ─── ETag ヘッダーを含む CORS ヘッダー文字列を生成 ─────────────────────── */
static const char *cors_headers_with_etag(uint32_t etag_val, int gzipped) {
    static char buf[800];
    const char *origin = getenv("CORS_ORIGIN");
    if (!origin || !*origin) origin = "*";
    const char *force_https = getenv("FORCE_HTTPS");
    int add_hsts = (force_https && (strcmp(force_https, "true") == 0 ||
                                    strcmp(force_https, "1") == 0));
    snprintf(buf, sizeof(buf),
             "Content-Type: application/json\r\n"
             "Access-Control-Allow-Origin: %s\r\n"
             "X-Request-ID: %s\r\n"
             "ETag: \"%08x\"\r\n"
             "Cache-Control: public, max-age=30\r\n"
             "%s%s",
             origin, g_request_id, etag_val,
             gzipped ? "Content-Encoding: gzip\r\n" : "",
             add_hsts ? "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" : "");
    return buf;
}

/* 現在のリクエストの If-None-Match ヘッダーをグローバルに保持（main.c からも参照） */
struct mg_http_message *g_hm_current = NULL;

static void send_cjson(struct mg_connection *c, int status, cJSON *obj) {
    char *s = cJSON_PrintUnformatted(obj);
    if (!s) { send_error_json(c, 500, "OOM"); return; }
    size_t slen = strlen(s);

    /* ETag 計算 */
    uint32_t etag_val = djb2_hash(s, slen);
    char etag_str[16];
    snprintf(etag_str, sizeof(etag_str), "\"%08x\"", etag_val);

    /* If-None-Match チェック (GET/HEAD のみ) */
    if (status == 200 && g_hm_current) {
        struct mg_str *inm = mg_http_get_header(g_hm_current, "If-None-Match");
        if (inm && inm->len == strlen(etag_str) &&
            strncmp(inm->buf, etag_str, inm->len) == 0) {
            mg_http_reply(c, 304, CORS_HEADERS, "");
            cJSON_free(s);
            return;
        }
    }

    /* gzip 圧縮 */
    if (g_accept_gzip && slen > 512) {
        char *gz = NULL; size_t gz_len = 0;
        if (gzip_compress(s, slen, &gz, &gz_len) == 0) {
            char hbuf[1024];
            int hlen = snprintf(hbuf, sizeof(hbuf),
                "HTTP/1.1 %d OK\r\n%sContent-Length: %zu\r\n\r\n",
                status, cors_headers_with_etag(etag_val, 1), gz_len);
            mg_send(c, hbuf, (size_t)hlen);
            mg_send(c, gz, gz_len);
            free(gz);
            cJSON_free(s);
            return;
        }
    }

    /* 通常送信（ETag 付き） — body は mg_send で送って % エスケープ問題を回避 */
    {
        char hbuf[1024];
        int hlen = snprintf(hbuf, sizeof(hbuf),
            "HTTP/1.1 %d OK\r\n%sContent-Length: %zu\r\n\r\n",
            status, cors_headers_with_etag(etag_val, 0), slen);
        mg_send(c, hbuf, (size_t)hlen);
        mg_send(c, s, slen);
    }
    cJSON_free(s);
}

void send_error_json(struct mg_connection *c, int status, const char *msg) {
    if (status >= 500) metrics_incr_5xx();
    else if (status >= 400) metrics_incr_4xx();
    cJSON *e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "error", msg);
    send_cjson(c, status, e);
    cJSON_Delete(e);
}

/* ─── IP ヘルパー ────────────────────────────────────────────────────────── */
static void get_client_ip(struct mg_connection *c, char *buf, size_t sz) {
    mg_snprintf(buf, sz, "%M", mg_print_ip, &c->rem);
}

/* ─── Auth helper ────────────────────────────────────────────────────────── */

/* Authorization: Bearer <token> を検証し user_id を返す。失敗時は 401 を送信して -1 */
static long require_auth(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    struct mg_str *hdr = mg_http_get_header(hm, "Authorization");
    if (!hdr || hdr->len <= 7) {
        send_error_json(c, 401, "認証が必要です"); return -1;
    }
    if (strncasecmp(hdr->buf, "Bearer ", 7) != 0) {
        send_error_json(c, 401, "Bearer トークンが必要です"); return -1;
    }
    size_t tok_len = hdr->len - 7;
    char tok[512];
    if (tok_len >= sizeof(tok)) { send_error_json(c, 401, "token too long"); return -1; }
    memcpy(tok, hdr->buf + 7, tok_len);
    tok[tok_len] = '\0';

    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "asoview-jwt-secret-dev";
    char tok_type[16] = {0};
    long uid = jwt_verify_typed(tok, secret, tok_type, sizeof(tok_type));
    /* JWT ローテーション: 新 secret で失敗した場合は旧 secret を試す */
    if (uid <= 0) {
        const char *prev_secret = getenv("JWT_SECRET_PREV");
        if (prev_secret && *prev_secret)
            uid = jwt_verify_typed(tok, prev_secret, tok_type, sizeof(tok_type));
    }
    if (uid <= 0) { send_error_json(c, 401, "トークンが無効または期限切れです"); return -1; }
    /* refresh token は API 認証に使用不可 */
    if (strcmp(tok_type, "refresh") == 0) {
        send_error_json(c, 401, "refresh token は API 認証に使用できません");
        return -1;
    }

    /* JWT ブラックリスト確認（署名部分 = jti として使用） */
    if (db) {
        const char *sig = strrchr(tok, '.');
        if (sig && sig[1]) {
            sig++;  /* '.' をスキップ */
            DbStmt *bl = NULL;
            bl = db_prepare(db,
                "SELECT 1 FROM jwt_blocklist WHERE jti=?");
            db_bind_text(bl, 1, sig);
            int blocked = (db_step(bl) == 1);
            db_finalize(bl);
            if (blocked) {
                send_error_json(c, 401, "トークンは無効化されています（ログアウト済み）");
                return -1;
            }
        }
    }

    return uid;
}

/* ─── ETag ヘルパー（djb2 ハッシュ → 304 対応） ─────────────────────────── */
static void send_cjson_etag(struct mg_connection *c, struct mg_http_message *hm, cJSON *obj) {
    char *s = cJSON_PrintUnformatted(obj);
    unsigned long h = 5381;
    for (const char *p = s; *p; p++) h = ((h << 5) + h) ^ (unsigned char)*p;
    char etag[32]; snprintf(etag, sizeof(etag), "\"%016lx\"", h);

    struct mg_str *inm = mg_http_get_header(hm, "If-None-Match");
    if (inm && inm->len == strlen(etag) && strncmp(inm->buf, etag, inm->len) == 0) {
        char hdrs[700];
        snprintf(hdrs, sizeof(hdrs), "%sETag: %s\r\n", CORS_HEADERS, etag);
        mg_http_reply(c, 304, hdrs, "");
        cJSON_free(s);
        return;
    }
    char hdrs[700];
    snprintf(hdrs, sizeof(hdrs), "%sETag: %s\r\n", CORS_HEADERS, etag);
    mg_http_reply(c, 200, hdrs, "%s", s);
    cJSON_free(s);
}

static long query_long(struct mg_http_message *hm, const char *k, long def) {
    char buf[32] = {0};
    return mg_http_get_var(&hm->query, k, buf, sizeof(buf)) > 0
           ? strtol(buf, NULL, 10) : def;
}

static int query_str(struct mg_http_message *hm, const char *k,
                     char *out, size_t len) {
    return mg_http_get_var(&hm->query, k, out, len) > 0;
}

/* ─── マルチテナント: X-Tenant-ID ヘッダーを tenant.id に解決 ─────────────
   戻り値:  0  = ヘッダーなし（テナント指定なし）
            >0 = 解決済み tenant_id
            -1 = 不明なテナント（404 を送信済み）                         */
static long resolve_tenant_id(struct mg_connection *c,
                               struct mg_http_message *hm, DbConn *db) {
    struct mg_str *hdr = mg_http_get_header(hm, "X-Tenant-ID");
    if (!hdr || hdr->len == 0) return 0;
    char slug[64] = {0};
    size_t slen = hdr->len < sizeof(slug)-1 ? hdr->len : sizeof(slug)-1;
    memcpy(slug, hdr->buf, slen);
    slug[slen] = '\0';
    DbStmt *st = db_prepare(db,
        "SELECT id FROM tenants WHERE slug=? AND is_active=1");
    db_bind_text(st, 1, slug);
    long tid = -1;
    if (db_step(st) == 1) tid = db_col_int(st, 0);
    db_finalize(st);
    if (tid <= 0) {
        send_error_json(c, 404, "テナントが見つかりません");
        return -1;
    }
    return tid;
}

/* plan の価格一覧を cJSON array として返す */
static cJSON *fetch_prices(DbConn *db, long plan_id) {
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT id,participant_type,label,price FROM plan_prices WHERE plan_id=? ORDER BY id");
    db_bind_int(st, 1, plan_id);
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *p = cJSON_CreateObject();
        cJSON_AddNumberToObject(p, "id",               db_col_int(st, 0));
        cJSON_AddStringToObject(p, "participant_type", db_col_text(st, 1));
        cJSON_AddStringToObject(p, "label",            db_col_text(st, 2));
        cJSON_AddNumberToObject(p, "price",            db_col_int(st, 3));
        cJSON_AddItemToArray(arr, p);
    }
    db_finalize(st);
    return arr;
}

/* booking の参加者リストを cJSON array として返す */
static cJSON *fetch_participants(DbConn *db, const char *booking_id) {
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT participant_type,label,count,unit_price FROM booking_participants WHERE booking_id=?");
    db_bind_text(st, 1, booking_id);
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *p = cJSON_CreateObject();
        cJSON_AddStringToObject(p, "participant_type", db_col_text(st, 0));
        cJSON_AddStringToObject(p, "label",      db_col_text(st, 1));
        cJSON_AddNumberToObject(p, "count",      db_col_int(st, 2));
        cJSON_AddNumberToObject(p, "unit_price", db_col_int(st, 3));
        cJSON_AddItemToArray(arr, p);
    }
    db_finalize(st);
    return arr;
}

/* ─── Health ──────────────────────────────────────────────────────────────── */

void handle_health(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    (void)hm;
    /* DB 疎通確認 */
    const char *db_status = "ok";
    DbStmt *ping = db_prepare(db, "SELECT 1");
    if (!ping || db_step(ping) != 1) db_status = "error";
    db_finalize(ping);
    char buf[128];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"ok\",\"service\":\"asoview\",\"version\":\"0.1.0\",\"db\":\"%s\"}",
             db_status);
    send_json_str(c, 200, CORS_HEADERS, buf);
}

/* ─── Areas ───────────────────────────────────────────────────────────────── */

void handle_list_areas(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    (void)hm;
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT id,name,name_kana,parent_id,level,slug FROM areas ORDER BY level,id");
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddNumberToObject(a, "id",    db_col_int(st, 0));
        cJSON_AddStringToObject(a, "name",  db_col_text(st, 1));
        if (!db_col_is_null(st, 2))
            cJSON_AddStringToObject(a, "name_kana", db_col_text(st, 2));
        else cJSON_AddNullToObject(a, "name_kana");
        if (!db_col_is_null(st, 3))
            cJSON_AddNumberToObject(a, "parent_id", db_col_int(st, 3));
        else cJSON_AddNullToObject(a, "parent_id");
        cJSON_AddNumberToObject(a, "level", db_col_int(st, 4));
        cJSON_AddStringToObject(a, "slug",  db_col_text(st, 5));
        cJSON_AddItemToArray(arr, a);
    }
    db_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── Categories ──────────────────────────────────────────────────────────── */

void handle_list_categories(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    (void)hm;
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT id,name,slug,parent_id,icon FROM categories ORDER BY id");
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddNumberToObject(a, "id",   db_col_int(st, 0));
        cJSON_AddStringToObject(a, "name", db_col_text(st, 1));
        cJSON_AddStringToObject(a, "slug", db_col_text(st, 2));
        if (!db_col_is_null(st, 3))
            cJSON_AddNumberToObject(a, "parent_id", db_col_int(st, 3));
        else cJSON_AddNullToObject(a, "parent_id");
        if (!db_col_is_null(st, 4))
            cJSON_AddStringToObject(a, "icon", db_col_text(st, 4));
        else cJSON_AddNullToObject(a, "icon");
        cJSON_AddItemToArray(arr, a);
    }
    db_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── Venues ──────────────────────────────────────────────────────────────── */

static cJSON *venue_row(DbStmt *st) {
    cJSON *v = cJSON_CreateObject();
    cJSON_AddNumberToObject(v, "id",     db_col_int(st, 0));
    cJSON_AddStringToObject(v, "name",   db_col_text(st, 1));
    if (!db_col_is_null(st, 2))
        cJSON_AddStringToObject(v, "description", db_col_text(st, 2));
    else cJSON_AddNullToObject(v, "description");
    cJSON_AddNumberToObject(v, "area_id", db_col_int(st, 3));
    if (!db_col_is_null(st, 4))
        cJSON_AddStringToObject(v, "area_name", db_col_text(st, 4));
    else cJSON_AddNullToObject(v, "area_name");
    if (!db_col_is_null(st, 5))
        cJSON_AddStringToObject(v, "address", db_col_text(st, 5));
    else cJSON_AddNullToObject(v, "address");
    cJSON_AddNumberToObject(v, "latitude",     db_col_double(st, 6));
    cJSON_AddNumberToObject(v, "longitude",    db_col_double(st, 7));
    cJSON_AddNumberToObject(v, "review_count", db_col_int(st, 8));
    cJSON_AddNumberToObject(v, "review_avg",   db_col_double(st, 9));
    cJSON_AddStringToObject(v, "created_at",   db_col_text(st, 10));
    return v;
}

void handle_list_venues(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long limit   = query_long(hm, "limit", 20); if (limit > 100) limit = 100;
    long area_id = query_long(hm, "area_id", 0);
    long after   = query_long(hm, "after", 0);  /* cursor: id > after */

    /* offset-based fallback (backward compat) */
    long page   = query_long(hm, "page", 1);  if (page < 1) page = 1;
    long offset = after > 0 ? 0 : (page - 1) * limit;

    /* テナントフィルタ (0 = 全テナント, >0 = 特定テナント) */
    long tid = resolve_tenant_id(c, hm, db);
    if (tid < 0) return;  /* 不明テナント (404 送信済み) */

    /* total */
    DbStmt *ct = NULL;
    ct = db_prepare(db,
        "SELECT COUNT(*) FROM venues v "
        "WHERE (? = 0 OR v.area_id = ?) "
        "AND (? = 0 OR v.tenant_id IS NULL OR v.tenant_id = ?)");
    db_bind_int(ct, 1, area_id);
    db_bind_int(ct, 2, area_id);
    db_bind_int(ct, 3, tid);
    db_bind_int(ct, 4, tid);
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    if (after > 0) {
        /* cursor-based: WHERE id > after */
        st = db_prepare(db,
            "SELECT v.id,v.name,v.description,v.area_id,a.name,"
            "v.address,v.latitude,v.longitude,v.review_count,v.review_avg,v.created_at "
            "FROM venues v LEFT JOIN areas a ON a.id=v.area_id "
            "WHERE v.id > ? AND (? = 0 OR v.area_id = ?) "
            "AND (? = 0 OR v.tenant_id IS NULL OR v.tenant_id = ?) "
            "ORDER BY v.id LIMIT ?");
        db_bind_int(st, 1, after);
        db_bind_int(st, 2, area_id);
        db_bind_int(st, 3, area_id);
        db_bind_int(st, 4, tid);
        db_bind_int(st, 5, tid);
        db_bind_int(st, 6, limit);
    } else {
        st = db_prepare(db,
            "SELECT v.id,v.name,v.description,v.area_id,a.name,"
            "v.address,v.latitude,v.longitude,v.review_count,v.review_avg,v.created_at "
            "FROM venues v LEFT JOIN areas a ON a.id=v.area_id "
            "WHERE (? = 0 OR v.area_id = ?) "
            "AND (? = 0 OR v.tenant_id IS NULL OR v.tenant_id = ?) "
            "ORDER BY v.id LIMIT ? OFFSET ?");
        db_bind_int(st, 1, area_id);
        db_bind_int(st, 2, area_id);
        db_bind_int(st, 3, tid);
        db_bind_int(st, 4, tid);
        db_bind_int(st, 5, limit);
        db_bind_int(st, 6, offset);
    }

    cJSON *venues = cJSON_CreateArray();
    long last_id = 0;
    while (db_step(st) == 1) {
        last_id = db_col_int(st, 0);
        cJSON_AddItemToArray(venues, venue_row(st));
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "venues", venues);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    /* cursor for next page */
    long cnt = (long)cJSON_GetArraySize(cJSON_GetObjectItem(res, "venues"));
    if (cnt == limit && last_id > 0)
        cJSON_AddNumberToObject(res, "next_after", last_id);
    else
        cJSON_AddNullToObject(res, "next_after");
    send_cjson_etag(c, hm, res);
    cJSON_Delete(res);
}

void handle_get_venue(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id) {
    (void)hm;
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT v.id,v.name,v.description,v.area_id,a.name,"
        "v.address,v.latitude,v.longitude,v.review_count,v.review_avg,v.created_at "
        "FROM venues v LEFT JOIN areas a ON a.id=v.area_id WHERE v.id=?");
    db_bind_int(st, 1, id);
    if (db_step(st) == 1) {
        cJSON *v = venue_row(st);
        db_finalize(st);
        send_cjson(c, 200, v);
        cJSON_Delete(v);
    } else {
        db_finalize(st);
        send_error_json(c, 404, "venue not found");
    }
}

/* ─── Plans ───────────────────────────────────────────────────────────────── */

static cJSON *plan_row(DbStmt *st) {
    cJSON *p = cJSON_CreateObject();
    cJSON_AddNumberToObject(p, "id",          db_col_int(st, 0));
    cJSON_AddNumberToObject(p, "venue_id",    db_col_int(st, 1));
    cJSON_AddStringToObject(p, "venue_name",  db_col_text(st, 2));
    cJSON_AddNumberToObject(p, "category_id", db_col_int(st, 3));
    cJSON_AddStringToObject(p, "category_name",db_col_text(st, 4));
    cJSON_AddStringToObject(p, "title",       db_col_text(st, 5));
    if (!db_col_is_null(st, 6))
        cJSON_AddStringToObject(p, "description", db_col_text(st, 6));
    else cJSON_AddNullToObject(p, "description");
    if (!db_col_is_null(st, 7))
        cJSON_AddNumberToObject(p, "duration_minutes", db_col_int(st, 7));
    else cJSON_AddNullToObject(p, "duration_minutes");
    cJSON_AddNumberToObject(p, "min_participants", db_col_int(st, 8));
    if (!db_col_is_null(st, 9))
        cJSON_AddNumberToObject(p, "max_participants", db_col_int(st, 9));
    else cJSON_AddNullToObject(p, "max_participants");
    if (!db_col_is_null(st, 10))
        cJSON_AddNumberToObject(p, "min_age", db_col_int(st, 10));
    else cJSON_AddNullToObject(p, "min_age");
    /* images / tags stored as JSON strings */
    const char *imgs = db_col_text(st, 11);
    const char *tags = db_col_text(st, 12);
    cJSON *imgs_arr = cJSON_Parse(imgs ? imgs : "[]");
    cJSON *tags_arr = cJSON_Parse(tags ? tags : "[]");
    cJSON_AddItemToObject(p, "images", imgs_arr ? imgs_arr : cJSON_CreateArray());
    cJSON_AddItemToObject(p, "tags",   tags_arr ? tags_arr : cJSON_CreateArray());
    cJSON_AddBoolToObject(p, "is_active", (int)db_col_int(st, 13) == 1);
    cJSON_AddStringToObject(p, "created_at", db_col_text(st, 14));
    /* キャンセルポリシー（cols 15-17） */
    cJSON_AddNumberToObject(p, "cancel_days_full",    db_col_int(st, 15));
    cJSON_AddNumberToObject(p, "cancel_days_partial", db_col_int(st, 16));
    cJSON_AddNumberToObject(p, "cancel_pct_partial",  db_col_int(st, 17));
    return p;
}

static const char *PLAN_SELECT =
    "SELECT p.id,p.venue_id,v.name,p.category_id,c.name,"
    "p.title,p.description,p.duration_minutes,"
    "p.min_participants,p.max_participants,p.min_age,"
    "p.images,p.tags,p.is_active,p.created_at,"
    "p.cancel_days_full,p.cancel_days_partial,p.cancel_pct_partial "
    "FROM plans p "
    "JOIN venues v ON v.id=p.venue_id "
    "JOIN categories c ON c.id=p.category_id";

void handle_list_plans(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long limit     = query_long(hm, "limit", 20);   if (limit > 100) limit = 100;
    long area_id   = query_long(hm, "area_id", 0);
    long cat_id    = query_long(hm, "category_id", 0);
    long adults    = query_long(hm, "adults", 0);
    long children  = query_long(hm, "children", 0);
    long required  = (adults + children) > 0 ? adults + children : 1;
    long after     = query_long(hm, "after", 0);   /* cursor-based pagination */
    char date[32]  = {0};
    int has_date   = query_str(hm, "date", date, sizeof(date));

    /* offset-based fallback (backward compat) */
    long page   = query_long(hm, "page", 1);  if (page < 1) page = 1;
    long offset = after > 0 ? 0 : (page - 1) * limit;

    char cnt_sql[512], qsql[1200];

    if (after > 0) {
        /* cursor-based: WHERE p.id > after */
        snprintf(cnt_sql, sizeof(cnt_sql),
            "SELECT COUNT(DISTINCT p.id) FROM plans p "
            "JOIN venues v ON v.id=p.venue_id "
            "WHERE p.is_active=1 AND p.id > ? "
            "AND (? = 0 OR p.category_id = ?) "
            "AND (? = 0 OR v.area_id = ?) "
            "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
            "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?))");
        snprintf(qsql, sizeof(qsql),
            "%s WHERE p.is_active=1 AND p.id > ? "
            "AND (? = 0 OR p.category_id = ?) "
            "AND (? = 0 OR v.area_id = ?) "
            "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
            "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?)) "
            "ORDER BY p.id LIMIT ?", PLAN_SELECT);
    } else {
        snprintf(cnt_sql, sizeof(cnt_sql),
            "SELECT COUNT(DISTINCT p.id) FROM plans p "
            "JOIN venues v ON v.id=p.venue_id "
            "WHERE p.is_active=1 "
            "AND (? = 0 OR p.category_id = ?) "
            "AND (? = 0 OR v.area_id = ?) "
            "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
            "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?))");
        snprintf(qsql, sizeof(qsql),
            "%s WHERE p.is_active=1 "
            "AND (? = 0 OR p.category_id = ?) "
            "AND (? = 0 OR v.area_id = ?) "
            "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
            "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?)) "
            "ORDER BY p.id LIMIT ? OFFSET ?", PLAN_SELECT);
    }

    DbStmt *ct = NULL;
    ct = db_prepare(db, cnt_sql);
    if (after > 0) {
        db_bind_int(ct, 1, after);
        db_bind_int(ct, 2, cat_id); db_bind_int(ct, 3, cat_id);
        db_bind_int(ct, 4, area_id); db_bind_int(ct, 5, area_id);
        db_bind_int(ct, 6, has_date ? 1 : 0);
        db_bind_text(ct, 7, date);
        db_bind_int(ct, 8, required);
    } else {
        db_bind_int(ct, 1, cat_id); db_bind_int(ct, 2, cat_id);
        db_bind_int(ct, 3, area_id); db_bind_int(ct, 4, area_id);
        db_bind_int(ct, 5, has_date ? 1 : 0);
        db_bind_text(ct, 6, date);
        db_bind_int(ct, 7, required);
    }
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    st = db_prepare(db, qsql);
    if (after > 0) {
        db_bind_int(st, 1, after);
        db_bind_int(st, 2, cat_id); db_bind_int(st, 3, cat_id);
        db_bind_int(st, 4, area_id); db_bind_int(st, 5, area_id);
        db_bind_int(st, 6, has_date ? 1 : 0);
        db_bind_text(st, 7, date);
        db_bind_int(st, 8, required);
        db_bind_int(st, 9, limit);
    } else {
        db_bind_int(st, 1, cat_id); db_bind_int(st, 2, cat_id);
        db_bind_int(st, 3, area_id); db_bind_int(st, 4, area_id);
        db_bind_int(st, 5, has_date ? 1 : 0);
        db_bind_text(st, 6, date);
        db_bind_int(st, 7, required);
        db_bind_int(st, 8, limit); db_bind_int(st, 9, offset);
    }

    cJSON *plans = cJSON_CreateArray();
    long last_id = 0;
    while (db_step(st) == 1) {
        long plan_id = db_col_int(st, 0);
        last_id = plan_id;
        cJSON *p = plan_row(st);
        cJSON_AddItemToObject(p, "prices", fetch_prices(db, plan_id));
        cJSON_AddItemToArray(plans, p);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "plans", plans);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    /* cursor for next page */
    long cnt = (long)cJSON_GetArraySize(cJSON_GetObjectItem(res, "plans"));
    if (cnt == limit && last_id > 0)
        cJSON_AddNumberToObject(res, "next_after", last_id);
    else
        cJSON_AddNullToObject(res, "next_after");
    send_cjson_etag(c, hm, res);
    cJSON_Delete(res);
}

void handle_get_plan(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id) {
    (void)hm;
    char qsql[512];
    snprintf(qsql, sizeof(qsql), "%s WHERE p.id=? AND p.is_active=1", PLAN_SELECT);
    DbStmt *st = NULL;
    st = db_prepare(db, qsql);
    db_bind_int(st, 1, id);
    if (db_step(st) == 1) {
        cJSON *p = plan_row(st);
        db_finalize(st);
        cJSON_AddItemToObject(p, "prices", fetch_prices(db, id));
        send_cjson(c, 200, p);
        cJSON_Delete(p);
    } else {
        db_finalize(st);
        send_error_json(c, 404, "plan not found");
    }
}

/* ─── Schedules ───────────────────────────────────────────────────────────── */

void handle_list_schedules(struct mg_connection *c, struct mg_http_message *hm,
                           DbConn *db, long plan_id) {
    char date[32] = {0};
    int has_date = query_str(hm, "date", date, sizeof(date));

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT id,plan_id,date,start_time,end_time,capacity,booked_count "
        "FROM schedules WHERE plan_id=? AND (? = 0 OR date=?) ORDER BY date,start_time");
    db_bind_int(st, 1, plan_id);
    db_bind_int(st, 2, has_date ? 1 : 0);
    db_bind_text(st, 3, date);

    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        long cap    = db_col_int(st, 5);
        long booked = db_col_int(st, 6);
        cJSON *s = cJSON_CreateObject();
        cJSON_AddNumberToObject(s, "id",          db_col_int(st, 0));
        cJSON_AddNumberToObject(s, "plan_id",     db_col_int(st, 1));
        cJSON_AddStringToObject(s, "date",        db_col_text(st, 2));
        cJSON_AddStringToObject(s, "start_time",  db_col_text(st, 3));
        if (!db_col_is_null(st, 4))
            cJSON_AddStringToObject(s, "end_time",db_col_text(st, 4));
        else cJSON_AddNullToObject(s, "end_time");
        cJSON_AddNumberToObject(s, "capacity",    cap);
        cJSON_AddNumberToObject(s, "booked_count",booked);
        cJSON_AddNumberToObject(s, "available",   cap - booked);
        cJSON_AddItemToArray(arr, s);
    }
    db_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── Users ───────────────────────────────────────────────────────────────── */

void handle_create_user(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *email    = cJSON_GetStringValue(cJSON_GetObjectItem(body, "email"));
    const char *name     = cJSON_GetStringValue(cJSON_GetObjectItem(body, "name"));
    const char *password = cJSON_GetStringValue(cJSON_GetObjectItem(body, "password"));
    const char *phone    = cJSON_GetStringValue(cJSON_GetObjectItem(body, "phone"));

    if (!email || !*email || !name || !*name || !password || strlen(password) < 8) {
        send_error_json(c, 400, "email, name は必須。password は8文字以上");
        cJSON_Delete(body); return;
    }
    if (strlen(email) > 254 || strlen(name) > 100 || strlen(password) > 128) {
        send_error_json(c, 400, "email は254字以内、name は100字以内、password は128字以内");
        cJSON_Delete(body); return;
    }
    if (!is_valid_email(email)) {
        send_error_json(c, 400, "メールアドレスの形式が正しくありません");
        cJSON_Delete(body); return;
    }

    char email_lower[256];
    strncpy(email_lower, email, sizeof(email_lower) - 1);
    email_lower[sizeof(email_lower)-1] = '\0';
    str_lower(email_lower);

    char hash[128];
    hash_password(password, hash, sizeof(hash));

    DbStmt *st = NULL;
    st = db_prepare(db,
        "INSERT INTO users(email,name,phone,password_hash) VALUES(?,?,?,?)");
    db_bind_text(st, 1, email_lower);
    db_bind_text(st, 2, name);
    db_bind_text(st, 3, phone);
    db_bind_text(st, 4, hash);

    int rc = db_step(st);
    db_finalize(st);
    cJSON_Delete(body);

    if (rc == -1) {
        const char *errmsg = db_errmsg(db);
        if (errmsg && (strstr(errmsg, "UNIQUE") || strstr(errmsg, "unique") ||
                       strstr(errmsg, "duplicate") || strstr(errmsg, "Duplicate")))
            send_error_json(c, 409, "このメールアドレスは既に登録されています");
        else
            send_error_json(c, 500, "database error");
        return;
    }

    long uid = db_last_id(db);
    DbStmt *sel = NULL;
    sel = db_prepare(db,
        "SELECT id,email,name,phone,created_at FROM users WHERE id=?");
    db_bind_int(sel, 1, uid);
    cJSON *u = NULL;
    if (db_step(sel) == 1) {
        u = cJSON_CreateObject();
        cJSON_AddNumberToObject(u, "id",    db_col_int(sel, 0));
        cJSON_AddStringToObject(u, "email", db_col_text(sel, 1));
        cJSON_AddStringToObject(u, "name",  db_col_text(sel, 2));
        if (!db_col_is_null(sel, 3))
            cJSON_AddStringToObject(u, "phone", db_col_text(sel, 3));
        else cJSON_AddNullToObject(u, "phone");
        cJSON_AddStringToObject(u, "created_at", db_col_text(sel, 4));
    }
    db_finalize(sel);

    if (u) { send_cjson(c, 201, u); cJSON_Delete(u); }
    else     send_error_json(c, 500, "failed to fetch created user");
}

void handle_login(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *email    = cJSON_GetStringValue(cJSON_GetObjectItem(body, "email"));
    const char *password = cJSON_GetStringValue(cJSON_GetObjectItem(body, "password"));
    if (!email || !password) {
        send_error_json(c, 400, "email と password は必須");
        cJSON_Delete(body);
        return;
    }

    char email_lower[256];
    strncpy(email_lower, email, sizeof(email_lower)-1);
    email_lower[sizeof(email_lower)-1] = '\0';
    str_lower(email_lower);

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT id,name,password_hash,failed_logins,locked_until FROM users WHERE email=?");
    db_bind_text(st, 1, email_lower);

    if (db_step(st) != 1) {
        db_finalize(st);
        cJSON_Delete(body);
        send_error_json(c, 400, "メールアドレスまたはパスワードが違います");
        return;
    }

    long uid           = db_col_int(st, 0);
    const char *nm     = db_col_text(st, 1);
    const char *hash   = db_col_text(st, 2);
    long failed_logins = db_col_int(st, 3);
    const char *locked = db_col_text(st, 4);  /* NULL or datetime */
    char name_buf[128] = {0};
    strncpy(name_buf, nm ? nm : "", sizeof(name_buf)-1);
    char hash_buf[128] = {0};
    strncpy(hash_buf, hash ? hash : "", sizeof(hash_buf)-1);
    char locked_buf[32] = {0};
    strncpy(locked_buf, locked ? locked : "", sizeof(locked_buf)-1);
    db_finalize(st);

    /* アカウントロックアウト確認 */
    if (locked_buf[0]) {
        DbStmt *lk = NULL;
        lk = db_prepare(db,
            "SELECT CASE WHEN locked_until > " SQL_NOW_STR " THEN 1 ELSE 0 END FROM users WHERE id=?");
        db_bind_int(lk, 1, uid);
        db_step(lk);
        int still_locked = (int)db_col_int(lk, 0);
        db_finalize(lk);
        if (still_locked) {
            cJSON_Delete(body);
            send_error_json(c, 429,
                "アカウントがロックされています。15分後に再試行してください");
            return;
        }
    }

    if (!verify_password(password, hash_buf)) {
        cJSON_Delete(body);
        /* 失敗回数を増やす。5回以上で15分ロック */
        long new_failed = failed_logins + 1;
        DbStmt *upd = NULL;
        if (new_failed >= 5) {
            upd = db_prepare(db,
                "UPDATE users SET failed_logins=?, locked_until=" SQL_NOW_PLUS_MIN(15) " WHERE id=?");
        } else {
            upd = db_prepare(db,
                "UPDATE users SET failed_logins=? WHERE id=?");
        }
        db_bind_int(upd, 1, new_failed);
        db_bind_int(upd, 2, uid);
        db_step(upd); db_finalize(upd);
        send_error_json(c, 400, "メールアドレスまたはパスワードが違います");
        return;
    }
    cJSON_Delete(body);

    /* ログイン成功 → 失敗カウントをリセット */
    DbStmt *rst = NULL;
    rst = db_prepare(db,
        "UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?");
    db_bind_int(rst, 1, uid);
    db_step(rst); db_finalize(rst);

    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "asoview-jwt-secret-dev";
    char *tok         = jwt_create(uid, secret);
    char *refresh_tok = jwt_create_refresh(uid, secret);

    /* 監査ログ */
    {
        char ip[48] = {0}; get_client_ip(c, ip, sizeof(ip));
        char uid_str[24]; snprintf(uid_str, sizeof(uid_str), "%ld", uid);
        audit_log(db, uid_str, "login", "user", uid_str, email_lower, ip);
    }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "user_id",       uid);
    cJSON_AddStringToObject(res, "name",          name_buf);
    cJSON_AddStringToObject(res, "token",         tok         ? tok         : "");
    cJSON_AddStringToObject(res, "refresh_token", refresh_tok ? refresh_tok : "");
    cJSON_AddStringToObject(res, "message",       "ログインしました");
    send_cjson(c, 200, res);
    cJSON_Delete(res);
    free(tok);
    free(refresh_tok);
}

void handle_list_user_bookings(struct mg_connection *c, struct mg_http_message *hm,
                                DbConn *db, long user_id) {
    /* JWT 必須 + 自分の予約のみ */
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;
    if (auth_uid != user_id) {
        send_error_json(c, 403, "他のユーザーの予約一覧は取得できません"); return;
    }
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT b.id,b.user_id,b.plan_id,p.title,b.schedule_id,"
        "s.date,s.start_time,b.status,b.total_price,b.note,b.created_at "
        "FROM bookings b "
        "JOIN plans p ON p.id=b.plan_id "
        "JOIN schedules s ON s.id=b.schedule_id "
        "WHERE b.user_id=? ORDER BY b.created_at DESC");
    db_bind_int(st, 1, user_id);

    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        const char *bid = db_col_text(st, 0);
        cJSON *b = cJSON_CreateObject();
        cJSON_AddStringToObject(b, "id",         bid);
        cJSON_AddNumberToObject(b, "user_id",    db_col_int(st, 1));
        cJSON_AddNumberToObject(b, "plan_id",    db_col_int(st, 2));
        cJSON_AddStringToObject(b, "plan_title", db_col_text(st, 3));
        cJSON_AddNumberToObject(b, "schedule_id",db_col_int(st, 4));
        cJSON_AddStringToObject(b, "schedule_date", db_col_text(st, 5));
        cJSON_AddStringToObject(b, "schedule_start_time",db_col_text(st, 6));
        cJSON_AddStringToObject(b, "status",     db_col_text(st, 7));
        cJSON_AddNumberToObject(b, "total_price",db_col_int(st, 8));
        if (!db_col_is_null(st, 9))
            cJSON_AddStringToObject(b, "note",   db_col_text(st, 9));
        else cJSON_AddNullToObject(b, "note");
        cJSON_AddStringToObject(b, "created_at",db_col_text(st, 10));
        cJSON_AddItemToObject(b, "participants", fetch_participants(db, bid));
        cJSON_AddItemToArray(arr, b);
    }
    db_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── Bookings ────────────────────────────────────────────────────────────── */

/* 参加者ごとの価格情報を一時保存するバッファ */
#define MAX_PART_TYPES 8
typedef struct { char pt[32]; char lb[128]; long cnt; long unit_price; } PartEntry;

void handle_create_booking(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    /* JWT 認証 */
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    /* ユーザー単位書き込みレート制限 */
    if (rate_check_uid(auth_uid)) {
        send_error_json(c, 429, "リクエスト数が多すぎます。しばらく経ってから再試行してください");
        return;
    }

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    long plan_id       = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "plan_id"));
    long sched_id      = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "schedule_id"));
    cJSON *parts       = cJSON_GetObjectItem(body, "participants");
    const char *note   = cJSON_GetStringValue(cJSON_GetObjectItem(body, "note"));
    const char *coupon_code_raw = cJSON_GetStringValue(cJSON_GetObjectItem(body, "coupon_code"));

    if (note && strlen(note) > 500) {
        send_error_json(c, 400, "note は 500 字以内");
        cJSON_Delete(body); return;
    }
    if (plan_id <= 0 || sched_id <= 0 ||
        !parts || !cJSON_IsArray(parts) || cJSON_GetArraySize(parts) == 0) {
        send_error_json(c, 400, "plan_id, schedule_id, participants は必須です");
        cJSON_Delete(body);
        return;
    }

    /* note フィールドの長さ上限（DoS防止） */
    if (note && strlen(note) > 1000) {
        send_error_json(c, 400, "note は1000文字以内で入力してください");
        cJSON_Delete(body);
        return;
    }

    /* サーバー側で価格を確定（トランザクション前に価格を取得） */
    int n = cJSON_GetArraySize(parts);
    if (n > MAX_PART_TYPES) n = MAX_PART_TYPES;
    PartEntry entries[MAX_PART_TYPES];
    long total_people = 0, total_price = 0;

    for (int i = 0; i < n; i++) {
        cJSON *p = cJSON_GetArrayItem(parts, i);
        const char *pt = cJSON_GetStringValue(cJSON_GetObjectItem(p, "participant_type"));
        long cnt = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(p, "count"));
        if (!pt || cnt < 1) {
            cJSON_Delete(body);
            send_error_json(c, 400, "participant_type と count は必須です"); return;
        }
        /* plan_prices から価格を取得 */
        DbStmt *ps = NULL;
        ps = db_prepare(db,
            "SELECT label,price FROM plan_prices WHERE plan_id=? AND participant_type=?");
        db_bind_int(ps, 1, plan_id);
        db_bind_text(ps, 2, pt);
        if (db_step(ps) != 1) {
            db_finalize(ps); cJSON_Delete(body);
            send_error_json(c, 400, "指定された participant_type の価格がありません"); return;
        }
        strncpy(entries[i].pt, pt, sizeof(entries[i].pt)-1);
        entries[i].pt[sizeof(entries[i].pt)-1] = '\0';
        const char *lb = db_col_text(ps, 0);
        strncpy(entries[i].lb, lb ? lb : "", sizeof(entries[i].lb)-1);
        entries[i].lb[sizeof(entries[i].lb)-1] = '\0';
        entries[i].cnt        = cnt;
        entries[i].unit_price = db_col_int(ps, 1);
        db_finalize(ps);

        total_people += cnt;
        total_price  += cnt * entries[i].unit_price;
    }

    /* ── クーポン検証 ───────────────────────────────────────────────────── */
    long coupon_id      = 0;
    long discount_amount = 0;
    char coupon_code[64] = {0};
    if (coupon_code_raw && coupon_code_raw[0]) {
        strncpy(coupon_code, coupon_code_raw, sizeof(coupon_code)-1);
        DbStmt *cst = db_prepare(db,
            "SELECT id,discount_type,discount_value,max_uses,used_count,expires_at,is_active"
            " FROM coupons WHERE code=? COLLATE NOCASE");
        db_bind_text(cst, 1, coupon_code);
        if (db_step(cst) != 1) {
            db_finalize(cst); cJSON_Delete(body);
            send_error_json(c, 400, "クーポンコードが見つかりません"); return;
        }
        long cid        = db_col_int(cst, 0);
        const char *dtp = db_col_text(cst, 1);
        long dval       = db_col_int(cst, 2);
        long max_uses   = db_col_int(cst, 3);
        long used_cnt   = db_col_int(cst, 4);
        const char *exp = db_col_text(cst, 5);
        int active      = (int)db_col_int(cst, 6);
        db_finalize(cst);

        if (!active) { cJSON_Delete(body); send_error_json(c, 400, "このクーポンは無効です"); return; }
        if (max_uses > 0 && used_cnt >= max_uses) { cJSON_Delete(body); send_error_json(c, 400, "クーポンの使用回数上限に達しています"); return; }
        if (exp && *exp) {
            time_t now = time(NULL); char now_str[20];
            strftime(now_str, sizeof(now_str), "%Y-%m-%d", gmtime(&now));
            if (strcmp(now_str, exp) > 0) { cJSON_Delete(body); send_error_json(c, 400, "クーポンの有効期限が切れています"); return; }
        }
        /* 割引額計算 */
        if (dtp && strcmp(dtp, "fixed") == 0) {
            discount_amount = dval;
        } else {
            discount_amount = total_price * dval / 100;
        }
        if (discount_amount > total_price) discount_amount = total_price;
        coupon_id = cid;
    }
    long final_price = total_price - discount_amount;

    /* ── 書き込みロックを取得してから空き枠を再確認（競合防止） ── */
    db_begin(db);

    /* 空き枠チェック（ロック内で再チェック） */
    DbStmt *cap_st = NULL;
#if defined(USE_POSTGRES) || defined(USE_MYSQL)
    cap_st = db_prepare(db,
        "SELECT capacity,booked_count FROM schedules WHERE id=? AND plan_id=? FOR UPDATE");
#else
    cap_st = db_prepare(db,
        "SELECT capacity,booked_count FROM schedules WHERE id=? AND plan_id=?");
#endif
    db_bind_int(cap_st, 1, sched_id);
    db_bind_int(cap_st, 2, plan_id);
    if (db_step(cap_st) != 1) {
        db_finalize(cap_st);
        db_rollback(db);
        cJSON_Delete(body);
        send_error_json(c, 404, "schedule not found"); return;
    }
    long cap    = db_col_int(cap_st, 0);
    long booked = db_col_int(cap_st, 1);
    db_finalize(cap_st);

    if (cap - booked < total_people) {
        char msg[64];
        snprintf(msg, sizeof(msg), "空き枠が不足しています（残 %ld 席）", cap - booked);
        db_rollback(db);
        send_error_json(c, 409, msg);
        cJSON_Delete(body); return;
    }

    char booking_id[37];
    generate_uuid(booking_id);

    /* STRIPE_SECRET_KEY が設定されていれば pending_payment で作成 */
    const char *stripe_sk = getenv("STRIPE_SECRET_KEY");
    const char *init_status = (stripe_sk && *stripe_sk) ? "pending_payment" : "confirmed";

    DbStmt *ins = NULL;
    int rc;
    if (coupon_id > 0) {
        /* クーポン適用あり: coupon_id / discount_amount を含む INSERT */
        ins = db_prepare(db,
            "INSERT INTO bookings(id,user_id,plan_id,schedule_id,status,total_price,note,coupon_id,discount_amount)"
            " VALUES(?,?,?,?,?,?,?,?,?)");
        db_bind_text(ins, 1, booking_id);
        db_bind_int(ins, 2, auth_uid);
        db_bind_int(ins, 3, plan_id);
        db_bind_int(ins, 4, sched_id);
        db_bind_text(ins, 5, init_status);
        db_bind_int(ins, 6, final_price);
        db_bind_text(ins, 7, note ? note : "");
        db_bind_int(ins, 8, coupon_id);
        db_bind_int(ins, 9, discount_amount);
    } else {
        /* クーポンなし: coupon_id は NULL（FK 制約回避） */
        ins = db_prepare(db,
            "INSERT INTO bookings(id,user_id,plan_id,schedule_id,status,total_price,note)"
            " VALUES(?,?,?,?,?,?,?)");
        db_bind_text(ins, 1, booking_id);
        db_bind_int(ins, 2, auth_uid);
        db_bind_int(ins, 3, plan_id);
        db_bind_int(ins, 4, sched_id);
        db_bind_text(ins, 5, init_status);
        db_bind_int(ins, 6, final_price);
        db_bind_text(ins, 7, note ? note : "");
    }
    rc = db_step(ins);
    db_finalize(ins);

    if (rc == -1) {
        db_rollback(db);
        cJSON_Delete(body);
        send_error_json(c, 500, "failed to create booking"); return;
    }

    /* 参加者挿入（確定済み価格を使用） */
    for (int i = 0; i < n; i++) {
        DbStmt *pi = NULL;
        pi = db_prepare(db,
            "INSERT INTO booking_participants(booking_id,participant_type,label,count,unit_price)"
            " VALUES(?,?,?,?,?)");
        db_bind_text(pi, 1, booking_id);
        db_bind_text(pi, 2, entries[i].pt);
        db_bind_text(pi, 3, entries[i].lb);
        db_bind_int(pi, 4, entries[i].cnt);
        db_bind_int(pi, 5, entries[i].unit_price);
        db_step(pi);
        db_finalize(pi);
    }

    db_commit(db);

    /* クーポン使用回数インクリメント */
    if (coupon_id > 0) {
        DbStmt *cup = db_prepare(db,
            "UPDATE coupons SET used_count=used_count+1 WHERE id=?");
        db_bind_int(cup, 1, coupon_id);
        db_step(cup); db_finalize(cup);
    }

    cJSON_Delete(body);

    /* Stripe PaymentIntent 作成 */
    char pi_id[128]         = {0};
    char client_secret[256] = {0};
    int stripe_ok = 0;
    if (stripe_sk && *stripe_sk) {
        if (stripe_create_payment_intent(total_price, booking_id,
                                         pi_id, sizeof(pi_id),
                                         client_secret, sizeof(client_secret)) == 0) {
            /* booking に stripe_payment_intent_id を保存 */
            DbStmt *upd = NULL;
            upd = db_prepare(db,
                "UPDATE bookings SET stripe_payment_intent_id=? WHERE id=?");
            db_bind_text(upd, 1, pi_id);
            db_bind_text(upd, 2, booking_id);
            db_step(upd);
            db_finalize(upd);
            stripe_ok = 1;
        } else {
            /* Stripe 呼び出し失敗 → booking を削除してエラーを返す */
            DbStmt *del = NULL;
            del = db_prepare(db,
                "DELETE FROM bookings WHERE id=?");
            db_bind_text(del, 1, booking_id);
            db_step(del);
            db_finalize(del);
            send_error_json(c, 502, "Stripe への接続に失敗しました");
            return;
        }
    }

    /* 返却 */
    DbStmt *sel = NULL;
    sel = db_prepare(db,
        "SELECT b.id,b.user_id,b.plan_id,p.title,b.schedule_id,"
        "s.date,s.start_time,b.status,b.total_price,b.note,b.created_at "
        "FROM bookings b JOIN plans p ON p.id=b.plan_id "
        "JOIN schedules s ON s.id=b.schedule_id WHERE b.id=?");
    db_bind_text(sel, 1, booking_id);
    cJSON *bk = NULL;
    if (db_step(sel) == 1) {
        const char *bid = db_col_text(sel, 0);
        bk = cJSON_CreateObject();
        cJSON_AddStringToObject(bk, "id", bid);
        cJSON_AddNumberToObject(bk, "user_id",    db_col_int(sel, 1));
        cJSON_AddNumberToObject(bk, "plan_id",    db_col_int(sel, 2));
        cJSON_AddStringToObject(bk, "plan_title", db_col_text(sel, 3));
        cJSON_AddNumberToObject(bk, "schedule_id",db_col_int(sel, 4));
        cJSON_AddStringToObject(bk, "schedule_date",       db_col_text(sel, 5));
        cJSON_AddStringToObject(bk, "schedule_start_time", db_col_text(sel, 6));
        cJSON_AddStringToObject(bk, "status",          db_col_text(sel, 7));
        cJSON_AddNumberToObject(bk, "total_price",     db_col_int(sel, 8));
        if (discount_amount > 0) {
            cJSON_AddNumberToObject(bk, "discount_amount", discount_amount);
            cJSON_AddNumberToObject(bk, "original_price",  total_price);
        }
        if (!db_col_is_null(sel, 9))
            cJSON_AddStringToObject(bk, "note",   db_col_text(sel, 9));
        else cJSON_AddNullToObject(bk, "note");
        cJSON_AddStringToObject(bk, "created_at",db_col_text(sel, 10));
        cJSON_AddItemToObject(bk, "participants", fetch_participants(db, bid));
        /* Stripe client_secret をレスポンスに含める */
        if (stripe_ok && client_secret[0]) {
            cJSON_AddStringToObject(bk, "client_secret",        client_secret);
            cJSON_AddStringToObject(bk, "stripe_payment_intent_id", pi_id);
        }
    }
    db_finalize(sel);

    /* Stripe 未使用時 (status='confirmed') はここで確定メールを送信
     * Stripe 使用時は payment_intent.succeeded webhook で送信 */
    if (!stripe_ok && bk) {
        char umail[256] = {0};
        DbStmt *eml = NULL;
        eml = db_prepare(db, "SELECT email FROM users WHERE id=?");
        db_bind_int(eml, 1, auth_uid);
        if (db_step(eml) == 1) {
            const char *em = db_col_text(eml, 0);
            if (em) strncpy(umail, em, sizeof(umail) - 1);
        }
        db_finalize(eml);
        if (umail[0]) {
            send_booking_confirmation_email(
                umail,
                cJSON_GetStringValue(cJSON_GetObjectItem(bk, "id")),
                cJSON_GetStringValue(cJSON_GetObjectItem(bk, "plan_title")),
                cJSON_GetStringValue(cJSON_GetObjectItem(bk, "schedule_date")),
                cJSON_GetStringValue(cJSON_GetObjectItem(bk, "schedule_start_time")),
                (long)cJSON_GetNumberValue(cJSON_GetObjectItem(bk, "total_price")));
        }
    }

    if (bk) {
        /* 監査ログ */
        char ip[48] = {0}; get_client_ip(c, ip, sizeof(ip));
        char uid_str[24]; snprintf(uid_str, sizeof(uid_str), "%ld", auth_uid);
        const char *new_bid = cJSON_GetStringValue(cJSON_GetObjectItem(bk, "id"));
        audit_log(db, uid_str, "booking.create", "booking", new_bid, NULL, ip);
        send_cjson(c, 201, bk); cJSON_Delete(bk);
    } else {
        send_error_json(c, 500, "failed to fetch booking");
    }
}

void handle_get_booking(struct mg_connection *c, struct mg_http_message *hm,
                        DbConn *db, const char *id) {
    /* JWT 必須 + 予約のオーナーのみ */
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT b.id,b.user_id,b.plan_id,p.title,b.schedule_id,"
        "s.date,s.start_time,b.status,b.total_price,b.note,b.created_at "
        "FROM bookings b JOIN plans p ON p.id=b.plan_id "
        "JOIN schedules s ON s.id=b.schedule_id WHERE b.id=?");
    db_bind_text(st, 1, id);

    if (db_step(st) != 1) {
        db_finalize(st);
        send_error_json(c, 404, "booking not found"); return;
    }
    long owner_id = db_col_int(st, 1);
    if (owner_id != auth_uid) {
        db_finalize(st);
        send_error_json(c, 403, "この予約にアクセスする権限がありません"); return;
    }
    const char *bid = db_col_text(st, 0);
    cJSON *bk = cJSON_CreateObject();
    cJSON_AddStringToObject(bk, "id", bid);
    cJSON_AddNumberToObject(bk, "user_id",    owner_id);
    cJSON_AddNumberToObject(bk, "plan_id",    db_col_int(st, 2));
    cJSON_AddStringToObject(bk, "plan_title", db_col_text(st, 3));
    cJSON_AddNumberToObject(bk, "schedule_id",db_col_int(st, 4));
    cJSON_AddStringToObject(bk, "schedule_date",       db_col_text(st, 5));
    cJSON_AddStringToObject(bk, "schedule_start_time", db_col_text(st, 6));
    cJSON_AddStringToObject(bk, "status",     db_col_text(st, 7));
    cJSON_AddNumberToObject(bk, "total_price",db_col_int(st, 8));
    if (!db_col_is_null(st, 9))
        cJSON_AddStringToObject(bk, "note",   db_col_text(st, 9));
    else cJSON_AddNullToObject(bk, "note");
    cJSON_AddStringToObject(bk, "created_at",db_col_text(st, 10));
    cJSON_AddItemToObject(bk, "participants", fetch_participants(db, bid));
    db_finalize(st);
    send_cjson(c, 200, bk);
    cJSON_Delete(bk);
}

/* ─── Reviews ─────────────────────────────────────────────────────────────── */

void handle_create_review(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    /* JWT 認証 — user_id はトークンから取得（ボディの値は無視） */
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    /* ユーザー単位書き込みレート制限 */
    if (rate_check_uid(auth_uid)) {
        send_error_json(c, 429, "リクエスト数が多すぎます。しばらく経ってから再試行してください");
        return;
    }

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    long user_id = auth_uid; /* JWT から取得した値のみ使用 */
    long plan_id = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "plan_id"));
    long rating  = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "rating"));
    const char *comment    = cJSON_GetStringValue(cJSON_GetObjectItem(body, "comment"));
    const char *booking_id = cJSON_GetStringValue(cJSON_GetObjectItem(body, "booking_id"));

    if (plan_id <= 0) {
        send_error_json(c, 400, "plan_id は必須です");
        cJSON_Delete(body); return;
    }
    if (rating < 1 || rating > 5) {
        send_error_json(c, 400, "rating は 1〜5 で指定してください");
        cJSON_Delete(body); return;
    }
    if (comment && strlen(comment) > 2000) {
        send_error_json(c, 400, "comment は 2000 字以内");
        cJSON_Delete(body); return;
    }

    /* 予約確認: このユーザーがこのプランを予約済みか（confirmed または cancelled） */
    if (booking_id && *booking_id) {
        /* booking_id 指定ありの場合: そのbookingがユーザーのものでplan_idが一致するか */
        DbStmt *bchk = NULL;
        bchk = db_prepare(db,
            "SELECT id FROM bookings WHERE id=? AND user_id=? AND plan_id=?");
        db_bind_text(bchk, 1, booking_id);
        db_bind_int(bchk, 2, auth_uid);
        db_bind_int(bchk, 3, plan_id);
        int found = (db_step(bchk) == 1);
        db_finalize(bchk);
        if (!found) {
            send_error_json(c, 403, "指定された予約はこのプランの予約ではありません");
            cJSON_Delete(body); return;
        }
    } else {
        /* booking_id なしの場合: confirmed/cancelled 予約が少なくとも1件あるか */
        DbStmt *bchk = NULL;
        bchk = db_prepare(db,
            "SELECT id FROM bookings WHERE user_id=? AND plan_id=? AND status IN ('confirmed','cancelled') LIMIT 1");
        db_bind_int(bchk, 1, auth_uid);
        db_bind_int(bchk, 2, plan_id);
        int found = (db_step(bchk) == 1);
        db_finalize(bchk);
        if (!found) {
            send_error_json(c, 403, "このプランを予約したユーザーのみレビューを投稿できます");
            cJSON_Delete(body); return;
        }
    }

    DbStmt *st = NULL;
    st = db_prepare(db,
        "INSERT INTO reviews(booking_id,user_id,plan_id,rating,comment) VALUES(?,?,?,?,?)");
    db_bind_text(st, 1, booking_id ? booking_id : NULL);
    db_bind_int(st, 2, user_id);
    db_bind_int(st, 3, plan_id);
    db_bind_int(st, 4, rating);
    db_bind_text(st, 5, comment ? comment : NULL);
    db_step(st);
    db_finalize(st);
    cJSON_Delete(body);

    long rid = db_last_id(db);
    DbStmt *sel = NULL;
    sel = db_prepare(db,
        "SELECT r.id,r.user_id,u.name,r.plan_id,r.rating,r.comment,r.created_at "
        "FROM reviews r LEFT JOIN users u ON u.id=r.user_id WHERE r.id=?");
    db_bind_int(sel, 1, rid);
    if (db_step(sel) == 1) {
        cJSON *rv = cJSON_CreateObject();
        cJSON_AddNumberToObject(rv, "id",      db_col_int(sel, 0));
        cJSON_AddNumberToObject(rv, "user_id", db_col_int(sel, 1));
        if (!db_col_is_null(sel, 2))
            cJSON_AddStringToObject(rv, "user_name", db_col_text(sel, 2));
        else cJSON_AddNullToObject(rv, "user_name");
        cJSON_AddNumberToObject(rv, "plan_id", db_col_int(sel, 3));
        cJSON_AddNumberToObject(rv, "rating",  db_col_int(sel, 4));
        if (!db_col_is_null(sel, 5))
            cJSON_AddStringToObject(rv, "comment", db_col_text(sel, 5));
        else cJSON_AddNullToObject(rv, "comment");
        cJSON_AddStringToObject(rv, "created_at", db_col_text(sel, 6));
        db_finalize(sel);
        send_cjson(c, 201, rv);
        cJSON_Delete(rv);
    } else {
        db_finalize(sel);
        send_error_json(c, 500, "failed to fetch review");
    }
}

/* ─── Search ──────────────────────────────────────────────────────────────── */

void handle_search(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long page     = query_long(hm, "page", 1);   if (page < 1) page = 1;
    long limit    = query_long(hm, "limit", 20);  if (limit > 100) limit = 100;
    long offset   = (page - 1) * limit;
    long area_id  = query_long(hm, "area_id", 0);
    long cat_id   = query_long(hm, "category_id", 0);
    long adults   = query_long(hm, "adults", 1);  if (adults < 1) adults = 1;
    char date[32] = {0};
    int has_date  = query_str(hm, "date", date, sizeof(date));
    char q_raw[256] = {0};
    int has_q = query_str(hm, "q", q_raw, sizeof(q_raw));

    /* FTS5 全文検索 vs LIKE フォールバック */
    int kw_flag = (has_q && q_raw[0]) ? 1 : 0;

    char q_esc[512] = {0};
    if (kw_flag) escape_like(q_raw, q_esc, sizeof(q_esc));
    char kw[520] = {0};
    if (kw_flag && q_esc[0]) snprintf(kw, sizeof(kw), "%%%s%%", q_esc);

    /* FTS サブクエリ方式（バックエンド別マクロで自動切替） */
    const char *cnt_fts_sql =
        "SELECT COUNT(DISTINCT p.id) FROM plans p "
        "JOIN venues v ON v.id=p.venue_id "
        "WHERE p.is_active=1 "
        "AND " SQL_FTS_MATCH(p.id, "?") " "
        "AND (? = 0 OR p.category_id=?) "
        "AND (? = 0 OR v.area_id=?) "
        "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
        "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?))";

    const char *cnt_like_sql =
        "SELECT COUNT(DISTINCT p.id) FROM plans p "
        "JOIN venues v ON v.id=p.venue_id "
        "WHERE p.is_active=1 "
        "AND (? = 0 OR p.title LIKE ? ESCAPE '!' OR p.description LIKE ? ESCAPE '!' OR v.name LIKE ? ESCAPE '!') "
        "AND (? = 0 OR p.category_id=?) "
        "AND (? = 0 OR v.area_id=?) "
        "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
        "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?))";

    char qsql_fts[1200], qsql_like[1200];
    snprintf(qsql_fts, sizeof(qsql_fts),
        "%s WHERE p.is_active=1 "
        "AND " SQL_FTS_MATCH(p.id, "?") " "
        "AND (? = 0 OR p.category_id=?) "
        "AND (? = 0 OR v.area_id=?) "
        "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
        "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?)) "
        "ORDER BY p.id LIMIT ? OFFSET ?", PLAN_SELECT);
    snprintf(qsql_like, sizeof(qsql_like),
        "%s WHERE p.is_active=1 "
        "AND (? = 0 OR p.title LIKE ? ESCAPE '!' OR p.description LIKE ? ESCAPE '!' OR v.name LIKE ? ESCAPE '!') "
        "AND (? = 0 OR p.category_id=?) "
        "AND (? = 0 OR v.area_id=?) "
        "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
        "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?)) "
        "ORDER BY p.id LIMIT ? OFFSET ?", PLAN_SELECT);

    long total = 0;
    DbStmt *ct = NULL, *st = NULL;
    int use_fts = 0;

    if (kw_flag && q_raw[0]) {
        /* FTS5 を試みる（サブクエリ方式） */
        DbStmt *fts_ct = NULL;
        if ((fts_ct = db_prepare(db, cnt_fts_sql)) != NULL) {
            db_bind_text(fts_ct, 1, q_raw);
            db_bind_int(fts_ct, 2, cat_id); db_bind_int(fts_ct, 3, cat_id);
            db_bind_int(fts_ct, 4, area_id); db_bind_int(fts_ct, 5, area_id);
            db_bind_int(fts_ct, 6, has_date ? 1 : 0);
            db_bind_text(fts_ct, 7, date);
            db_bind_int(fts_ct, 8, adults);
            if (db_step(fts_ct) == 1) {
                total = db_col_int(fts_ct, 0);
                use_fts = (total > 0);  /* 結果がある場合のみ FTS を採用 */
            }
            db_finalize(fts_ct);
        }
    }

    if (!use_fts) {
        /* LIKE フォールバック */
        ct = db_prepare(db, cnt_like_sql);
        db_bind_int(ct, 1, kw_flag);
        db_bind_text(ct, 2, kw);
        db_bind_text(ct, 3, kw);
        db_bind_text(ct, 4, kw);
        db_bind_int(ct, 5, cat_id); db_bind_int(ct, 6, cat_id);
        db_bind_int(ct, 7, area_id); db_bind_int(ct, 8, area_id);
        db_bind_int(ct, 9, has_date ? 1 : 0);
        db_bind_text(ct, 10, date);
        db_bind_int(ct, 11, adults);
        db_step(ct);
        total = db_col_int(ct, 0);
        db_finalize(ct); ct = NULL;
    }

    if (use_fts) {
        st = db_prepare(db, qsql_fts);
        db_bind_text(st, 1, q_raw);
        db_bind_int(st, 2, cat_id); db_bind_int(st, 3, cat_id);
        db_bind_int(st, 4, area_id); db_bind_int(st, 5, area_id);
        db_bind_int(st, 6, has_date ? 1 : 0);
        db_bind_text(st, 7, date);
        db_bind_int(st, 8, adults);
        db_bind_int(st, 9, limit); db_bind_int(st, 10, offset);
    } else {
        st = db_prepare(db, qsql_like);
        db_bind_int(st, 1, kw_flag);
        db_bind_text(st, 2, kw);
        db_bind_text(st, 3, kw);
        db_bind_text(st, 4, kw);
        db_bind_int(st, 5, cat_id); db_bind_int(st, 6, cat_id);
        db_bind_int(st, 7, area_id); db_bind_int(st, 8, area_id);
        db_bind_int(st, 9, has_date ? 1 : 0);
        db_bind_text(st, 10, date);
        db_bind_int(st, 11, adults);
        db_bind_int(st, 12, limit); db_bind_int(st, 13, offset);
    }

    cJSON *plans = cJSON_CreateArray();
    while (db_step(st) == 1) {
        long pid = db_col_int(st, 0);
        cJSON *p = plan_row(st);
        cJSON_AddItemToObject(p, "prices", fetch_prices(db, pid));
        cJSON_AddItemToArray(plans, p);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "plans", plans);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* ─── Cancel Booking ──────────────────────────────────────────────────────── */

/* YYYY-MM-DD の日付文字列から今日までの日数差を返す（負の場合は 0） */
static long calculate_days_until(const char *date_str) {
    int yy = 0, mm = 0, dd = 0;
    if (sscanf(date_str, "%d-%d-%d", &yy, &mm, &dd) != 3) return 0;
    time_t now = time(NULL);
    struct tm today = *gmtime(&now);
    struct tm target;
    memset(&target, 0, sizeof(target));
    target.tm_year = yy - 1900;
    target.tm_mon  = mm - 1;
    target.tm_mday = dd;
    time_t t_target = mktime(&target);
    time_t t_today  = mktime(&today);
    double diff = difftime(t_target, t_today);
    return diff > 0 ? (long)(diff / 86400.0) : 0;
}

void handle_cancel_booking(struct mg_connection *c, struct mg_http_message *hm,
                            DbConn *db, const char *id) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    DbStmt *st = NULL;
    /* col: 0=user_id, 1=status, 2=schedule_id, 3=stripe_pi_id, 4=email, 5=plan_title,
     *      6=schedule_date, 7=total_price, 8=cancel_days_full, 9=cancel_days_partial, 10=cancel_pct_partial */
    st = db_prepare(db,
        "SELECT b.user_id, b.status, b.schedule_id, b.stripe_payment_intent_id, "
        "u.email, p.title, s.date, b.total_price, "
        "p.cancel_days_full, p.cancel_days_partial, p.cancel_pct_partial "
        "FROM bookings b "
        "JOIN users u ON u.id = b.user_id "
        "JOIN plans p ON p.id = b.plan_id "
        "JOIN schedules s ON s.id = b.schedule_id "
        "WHERE b.id=?");
    db_bind_text(st, 1, id);
    if (db_step(st) != 1) {
        db_finalize(st);
        send_error_json(c, 404, "booking not found"); return;
    }
    long owner_id = db_col_int(st, 0);
    char status_buf[32] = {0};
    const char *sv = db_col_text(st, 1);
    strncpy(status_buf, sv ? sv : "", sizeof(status_buf)-1);
    long sched_id = db_col_int(st, 2);
    char pi_id[128] = {0};
    const char *piv = db_col_text(st, 3);
    if (piv) strncpy(pi_id, piv, sizeof(pi_id)-1);
    char user_email[256] = {0};
    const char *uev = db_col_text(st, 4);
    if (uev) strncpy(user_email, uev, sizeof(user_email)-1);
    char plan_title[256] = {0};
    const char *ptv = db_col_text(st, 5);
    if (ptv) strncpy(plan_title, ptv, sizeof(plan_title)-1);
    char sched_date[32] = {0};
    const char *sdv = db_col_text(st, 6);
    if (sdv) strncpy(sched_date, sdv, sizeof(sched_date)-1);
    long total_price_orig   = db_col_int(st, 7);
    long cancel_days_full   = db_col_int(st, 8);
    long cancel_days_partial= db_col_int(st, 9);
    long cancel_pct_partial = db_col_int(st, 10);
    db_finalize(st);

    if (owner_id != auth_uid) {
        send_error_json(c, 403, "この予約をキャンセルする権限がありません"); return;
    }
    if (strcmp(status_buf, "cancelled") == 0) {
        send_error_json(c, 400, "既にキャンセル済みです"); return;
    }

    /* キャンセルポリシー計算 */
    long days_until    = calculate_days_until(sched_date);
    long refund_amount = 0;
    const char *refund_type = "none";
    if (days_until >= cancel_days_full) {
        refund_amount = total_price_orig;
        refund_type   = "full";
    } else if (days_until >= cancel_days_partial) {
        refund_amount = total_price_orig * cancel_pct_partial / 100;
        refund_type   = "partial";
    }

    /* 参加者合計 → booked_count を戻す */
    DbStmt *pst = NULL;
    pst = db_prepare(db,
        "SELECT COALESCE(SUM(count),0) FROM booking_participants WHERE booking_id=?");
    db_bind_text(pst, 1, id);
    db_step(pst);
    long total_people = db_col_int(pst, 0);
    db_finalize(pst);

    DbStmt *upd = NULL;
    upd = db_prepare(db, "UPDATE bookings SET status='cancelled' WHERE id=?");
    db_bind_text(upd, 1, id);
    db_step(upd); db_finalize(upd);

    DbStmt *dec = NULL;
    dec = db_prepare(db,
        "UPDATE schedules SET booked_count = CASE WHEN booked_count > ? THEN booked_count - ? ELSE 0 END WHERE id=?");
    db_bind_int(dec, 1, total_people);
    db_bind_int(dec, 2, total_people);
    db_bind_int(dec, 3, sched_id);
    db_step(dec); db_finalize(dec);

    /* Stripe 返金（payment_intent_id がある場合）*/
    int refunded = 0;
    if (pi_id[0] && refund_amount > 0) {
        refunded = (stripe_create_refund(pi_id) == 0) ? 1 : 0;
        if (refunded)
            fprintf(stdout, "[stripe] refund issued for booking %s (pi=%s, amount=%ld, type=%s)\n",
                    id, pi_id, refund_amount, refund_type);
    }

    /* キャンセルメール送信 */
    if (user_email[0]) {
        send_booking_cancellation_email(user_email, id, plan_title, refunded);
    }

    /* 監査ログ */
    {
        char ip[48] = {0}; get_client_ip(c, ip, sizeof(ip));
        char uid_str[24]; snprintf(uid_str, sizeof(uid_str), "%ld", auth_uid);
        audit_log(db, uid_str, "booking.cancel", "booking", id, refund_type, ip);
    }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "予約をキャンセルしました");
    cJSON_AddNumberToObject(res, "refund_amount", refund_amount);
    cJSON_AddStringToObject(res, "refund_type",   refund_type);
    if (refunded) cJSON_AddBoolToObject(res, "refunded", 1);
    send_cjson(c, 200, res);
    cJSON_Delete(res);

    /* ウェイトリストの先頭ユーザーに空き通知 */
    notify_waitlist(db, sched_id);
}

/* ─── GET /api/v1/plans/:id/reviews ────────────────────────────────────────── */

void handle_list_plan_reviews(struct mg_connection *c, struct mg_http_message *hm,
                               DbConn *db, long plan_id) {
    long page  = query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit = query_long(hm, "limit", 20); if (limit > 100) limit = 100;
    long offset = (page - 1) * limit;

    /* 総件数 */
    DbStmt *ct = NULL;
    ct = db_prepare(db, "SELECT COUNT(*) FROM reviews WHERE plan_id=?");
    db_bind_int(ct, 1, plan_id);
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT r.id, r.user_id, u.name, r.rating, r.comment, r.created_at "
        "FROM reviews r "
        "LEFT JOIN users u ON u.id = r.user_id "
        "WHERE r.plan_id = ? "
        "ORDER BY r.created_at DESC LIMIT ? OFFSET ?");
    db_bind_int(st, 1, plan_id);
    db_bind_int(st, 2, limit);
    db_bind_int(st, 3, offset);

    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *rv = cJSON_CreateObject();
        cJSON_AddNumberToObject(rv, "id",      db_col_int(st, 0));
        cJSON_AddNumberToObject(rv, "user_id", db_col_int(st, 1));
        if (!db_col_is_null(st, 2))
            cJSON_AddStringToObject(rv, "user_name", db_col_text(st, 2));
        else cJSON_AddNullToObject(rv, "user_name");
        cJSON_AddNumberToObject(rv, "rating",  db_col_int(st, 3));
        if (!db_col_is_null(st, 4))
            cJSON_AddStringToObject(rv, "comment", db_col_text(st, 4));
        else cJSON_AddNullToObject(rv, "comment");
        cJSON_AddStringToObject(rv, "created_at", db_col_text(st, 5));
        cJSON_AddItemToArray(arr, rv);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "reviews", arr);
    cJSON_AddNumberToObject(res, "total",  total);
    cJSON_AddNumberToObject(res, "page",   page);
    cJSON_AddNumberToObject(res, "limit",  limit);
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/venues/:id/plans ─────────────────────────────────────────── */

void handle_list_venue_plans(struct mg_connection *c, struct mg_http_message *hm,
                              DbConn *db, long venue_id) {
    (void)hm;
    char qsql[512];
    snprintf(qsql, sizeof(qsql),
        "%s WHERE p.venue_id=? AND p.is_active=1 ORDER BY p.id", PLAN_SELECT);
    DbStmt *st = NULL;
    st = db_prepare(db, qsql);
    db_bind_int(st, 1, venue_id);

    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        long pid = db_col_int(st, 0);
        cJSON *p = plan_row(st);
        cJSON_AddItemToObject(p, "prices", fetch_prices(db, pid));
        cJSON_AddItemToArray(arr, p);
    }
    db_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── GET /api/v1/users/:id ────────────────────────────────────────────────── */

void handle_get_user(struct mg_connection *c, struct mg_http_message *hm,
                     DbConn *db, long id) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;
    if (auth_uid != id) {
        send_error_json(c, 403, "他のユーザーのプロフィールは取得できません"); return;
    }
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT id,email,name,phone,created_at FROM users WHERE id=?");
    db_bind_int(st, 1, id);
    if (db_step(st) != 1) {
        db_finalize(st);
        send_error_json(c, 404, "user not found"); return;
    }
    cJSON *u = cJSON_CreateObject();
    cJSON_AddNumberToObject(u, "id",     db_col_int(st, 0));
    cJSON_AddStringToObject(u, "email",  db_col_text(st, 1));
    cJSON_AddStringToObject(u, "name",   db_col_text(st, 2));
    if (!db_col_is_null(st, 3))
        cJSON_AddStringToObject(u, "phone", db_col_text(st, 3));
    else cJSON_AddNullToObject(u, "phone");
    cJSON_AddStringToObject(u, "created_at", db_col_text(st, 4));
    db_finalize(st);
    send_cjson(c, 200, u);
    cJSON_Delete(u);
}

/* ─── PATCH /api/v1/users/:id ──────────────────────────────────────────────── */

void handle_update_user(struct mg_connection *c, struct mg_http_message *hm,
                        DbConn *db, long id) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;
    if (auth_uid != id) {
        send_error_json(c, 403, "他のユーザーの情報は変更できません"); return;
    }

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    cJSON *it;
    it = cJSON_GetObjectItem(body, "name");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL;
        u = db_prepare(db, "UPDATE users SET name=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id);
        db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "phone");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL;
        u = db_prepare(db, "UPDATE users SET phone=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id);
        db_step(u); db_finalize(u);
    }
    cJSON_Delete(body);

    /* 更新後のユーザーを返す */
    DbStmt *sel = NULL;
    sel = db_prepare(db,
        "SELECT id,email,name,phone,created_at FROM users WHERE id=?");
    db_bind_int(sel, 1, id);
    if (db_step(sel) != 1) {
        db_finalize(sel);
        send_error_json(c, 404, "user not found"); return;
    }
    cJSON *u = cJSON_CreateObject();
    cJSON_AddNumberToObject(u, "id",     db_col_int(sel, 0));
    cJSON_AddStringToObject(u, "email",  db_col_text(sel, 1));
    cJSON_AddStringToObject(u, "name",   db_col_text(sel, 2));
    if (!db_col_is_null(sel, 3))
        cJSON_AddStringToObject(u, "phone", db_col_text(sel, 3));
    else cJSON_AddNullToObject(u, "phone");
    cJSON_AddStringToObject(u, "created_at", db_col_text(sel, 4));
    db_finalize(sel);
    send_cjson(c, 200, u);
    cJSON_Delete(u);
}

/* ─── POST /api/v1/checkout/session ─────────────────────────────────────────
 * 4ページ目の Stripe Checkout（¥50,000 固定）。
 * リクエスト JSON:
 *   { "success_url": "...", "cancel_url": "...", "metadata": { "key": "val" } }
 * レスポンス JSON:
 *   { "session_id": "cs_...", "url": "https://checkout.stripe.com/..." }
 * ─────────────────────────────────────────────────────────────────────────── */

#define CHECKOUT_AMOUNT_JPY 50000L  /* ¥50,000 固定 */

void handle_create_checkout_session(struct mg_connection *c,
                                    struct mg_http_message *hm, DbConn *db) {
    (void)db;
    /* JWT 認証必須 */
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *success_url = cJSON_GetStringValue(cJSON_GetObjectItem(body, "success_url"));
    const char *cancel_url  = cJSON_GetStringValue(cJSON_GetObjectItem(body, "cancel_url"));

    /* デフォルト URL（Host ヘッダーから組み立て）*/
    char default_base[256] = "http://localhost:3001";
    struct mg_str *host_h  = mg_http_get_header(hm, "Host");
    struct mg_str *proto_h = mg_http_get_header(hm, "X-Forwarded-Proto");
    if (host_h && host_h->len > 0) {
        const char *scheme = (proto_h && mg_strcmp(*proto_h, mg_str("https")) == 0)
                             ? "https" : "http";
        snprintf(default_base, sizeof(default_base), "%s://%.*s",
                 scheme, (int)host_h->len, host_h->buf);
    }
    char default_success[300], default_cancel[300];
    snprintf(default_success, sizeof(default_success), "%s/payment/success", default_base);
    snprintf(default_cancel,  sizeof(default_cancel),  "%s/payment/cancel",  default_base);

    if (!success_url || !*success_url) success_url = default_success;
    if (!cancel_url  || !*cancel_url ) cancel_url  = default_cancel;

    /* SSRF 防止: http:// または https:// で始まる URL のみ許可 */
    if (strncmp(success_url, "http://", 7) != 0 && strncmp(success_url, "https://", 8) != 0) {
        cJSON_Delete(body);
        send_error_json(c, 400, "success_url は http:// または https:// で始まる必要があります");
        return;
    }
    if (strncmp(cancel_url, "http://", 7) != 0 && strncmp(cancel_url, "https://", 8) != 0) {
        cJSON_Delete(body);
        send_error_json(c, 400, "cancel_url は http:// または https:// で始まる必要があります");
        return;
    }

    /* metadata: 最初のキー・バリューペアを使用 */
    const char *meta_key = "user_id";
    char meta_val[64];
    snprintf(meta_val, sizeof(meta_val), "%ld", auth_uid);

    cJSON *meta = cJSON_GetObjectItem(body, "metadata");
    if (meta && cJSON_IsObject(meta)) {
        cJSON *item = meta->child;
        if (item) {
            meta_key = item->string;
            const char *v = cJSON_GetStringValue(item);
            if (v) snprintf(meta_val, sizeof(meta_val), "%s", v);
        }
    }

    char session_id[128] = {0};
    char checkout_url[512] = {0};

    if (stripe_create_checkout_session(
            CHECKOUT_AMOUNT_JPY,
            meta_key, meta_val,
            success_url, cancel_url,
            session_id, sizeof(session_id),
            checkout_url, sizeof(checkout_url)) != 0) {
        cJSON_Delete(body);
        send_error_json(c, 502, "Stripe Checkout Session の作成に失敗しました");
        return;
    }
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "session_id", session_id);
    cJSON_AddStringToObject(res, "url",        checkout_url);
    cJSON_AddNumberToObject(res, "amount",     (double)CHECKOUT_AMOUNT_JPY);
    char *s = cJSON_PrintUnformatted(res);
    send_json_str(c, 200, CORS_HEADERS, s);
    cJSON_free(s);
    cJSON_Delete(res);
}

/* ─── POST /api/v1/webhooks/stripe ─────────────────────────────────────────── */

void handle_stripe_webhook(struct mg_connection *c, struct mg_http_message *hm,
                            DbConn *db) {
    const char *webhook_secret = getenv("STRIPE_WEBHOOK_SECRET");
    if (!webhook_secret || !*webhook_secret) {
        send_error_json(c, 503, "Stripe webhook not configured"); return;
    }

    /* Stripe-Signature ヘッダー取得 */
    struct mg_str *sig_hdr = mg_http_get_header(hm, "Stripe-Signature");
    if (!sig_hdr || sig_hdr->len == 0) {
        send_error_json(c, 400, "Stripe-Signature header missing"); return;
    }
    char sig_buf[512] = {0};
    size_t sig_copy = sig_hdr->len < sizeof(sig_buf) - 1
                      ? sig_hdr->len : sizeof(sig_buf) - 1;
    memcpy(sig_buf, sig_hdr->buf, sig_copy);
    sig_buf[sig_copy] = '\0';

    /* 署名検証 */
    if (!stripe_verify_webhook(sig_buf,
                                hm->body.buf, hm->body.len,
                                webhook_secret)) {
        send_error_json(c, 400, "webhook signature invalid"); return;
    }

    /* イベント解析 */
    cJSON *event = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!event) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *evt_type = cJSON_GetStringValue(cJSON_GetObjectItem(event, "type"));
    if (!evt_type) { cJSON_Delete(event); send_error_json(c, 400, "missing event type"); return; }

    /* 冪等性チェック: 同一イベントを重複処理しない */
    const char *evt_id = cJSON_GetStringValue(cJSON_GetObjectItem(event, "id"));
    if (evt_id && *evt_id) {
        DbStmt *dup = NULL;
        dup = db_prepare(db,
            "SELECT 1 FROM webhook_events WHERE event_id=?");
        db_bind_text(dup, 1, evt_id);
        int already = (db_step(dup) == 1);
        db_finalize(dup);
        if (already) {
            cJSON_Delete(event);
            send_json_str(c, 200, "Content-Type: application/json\r\n",
                          "{\"status\":\"already processed\"}");
            return;
        }
        /* 処理済みとして記録 */
        DbStmt *ins = NULL;
        ins = db_prepare(db,
            SQL_INSERT_OR_IGNORE " INTO webhook_events(event_id) VALUES(?)" SQL_ON_CONFLICT_IGNORE);
        db_bind_text(ins, 1, evt_id);
        db_step(ins); db_finalize(ins);
    }

    if (strcmp(evt_type, "payment_intent.succeeded") == 0) {
        /* data.object.metadata.booking_id を取得 */
        cJSON *data   = cJSON_GetObjectItem(event, "data");
        cJSON *object = data ? cJSON_GetObjectItem(data, "object") : NULL;
        cJSON *meta   = object ? cJSON_GetObjectItem(object, "metadata") : NULL;
        const char *booking_id = meta
            ? cJSON_GetStringValue(cJSON_GetObjectItem(meta, "booking_id"))
            : NULL;

        if (booking_id && *booking_id) {
            DbStmt *upd = NULL;
            upd = db_prepare(db,
                "UPDATE bookings SET status='confirmed' WHERE id=? AND status='pending_payment'");
            db_bind_text(upd, 1, booking_id);
            db_step(upd);
            int changed = db_changes(db);
            db_finalize(upd);
            fprintf(stdout, "[stripe] booking %s confirmed via webhook\n", booking_id);

            /* 支払い確定メール送信 */
            if (changed > 0) {
                DbStmt *info = NULL;
                info = db_prepare(db,
                    "SELECT u.email, p.title, s.date, s.start_time, b.total_price "
                    "FROM bookings b JOIN users u ON u.id=b.user_id "
                    "JOIN plans p ON p.id=b.plan_id "
                    "JOIN schedules s ON s.id=b.schedule_id "
                    "WHERE b.id=?");
                db_bind_text(info, 1, booking_id);
                if (db_step(info) == 1) {
                    const char *email = db_col_text(info, 0);
                    const char *title = db_col_text(info, 1);
                    const char *date  = db_col_text(info, 2);
                    const char *stime = db_col_text(info, 3);
                    long total = db_col_int(info, 4);
                    if (email)
                        send_booking_confirmation_email(email, booking_id, title, date, stime, total);
                }
                db_finalize(info);
            }
        }

    } else if (strcmp(evt_type, "checkout.session.completed") == 0) {
        /* Checkout Session 経由の支払い完了
         * data.object.metadata.booking_id があれば予約を confirmed に更新する */
        cJSON *data   = cJSON_GetObjectItem(event, "data");
        cJSON *object = data ? cJSON_GetObjectItem(data, "object") : NULL;
        cJSON *meta   = object ? cJSON_GetObjectItem(object, "metadata") : NULL;
        const char *booking_id = meta
            ? cJSON_GetStringValue(cJSON_GetObjectItem(meta, "booking_id"))
            : NULL;
        const char *pay_status = object
            ? cJSON_GetStringValue(cJSON_GetObjectItem(object, "payment_status"))
            : NULL;

        if (pay_status && strcmp(pay_status, "paid") == 0 && booking_id && *booking_id) {
            DbStmt *upd = NULL;
            upd = db_prepare(db,
                "UPDATE bookings SET status='confirmed' WHERE id=? AND status='pending_payment'");
            db_bind_text(upd, 1, booking_id);
            db_step(upd);
            int changed = db_changes(db);
            db_finalize(upd);
            fprintf(stdout, "[stripe] booking %s confirmed via checkout.session.completed\n",
                    booking_id);

            if (changed > 0) {
                DbStmt *info = NULL;
                info = db_prepare(db,
                    "SELECT u.email, p.title, s.date, s.start_time, b.total_price "
                    "FROM bookings b JOIN users u ON u.id=b.user_id "
                    "JOIN plans p ON p.id=b.plan_id "
                    "JOIN schedules s ON s.id=b.schedule_id "
                    "WHERE b.id=?");
                db_bind_text(info, 1, booking_id);
                if (db_step(info) == 1) {
                    const char *email = db_col_text(info, 0);
                    const char *title = db_col_text(info, 1);
                    const char *date  = db_col_text(info, 2);
                    const char *stime = db_col_text(info, 3);
                    long total = db_col_int(info, 4);
                    if (email)
                        send_booking_confirmation_email(email, booking_id, title, date, stime, total);
                }
                db_finalize(info);
            }
        } else if (pay_status && strcmp(pay_status, "paid") == 0) {
            /* booking_id なし = standalone checkout（予約紐付けなし）*/
            fprintf(stdout, "[stripe] checkout.session.completed (no booking_id)\n");
        }

    } else if (strcmp(evt_type, "payment_intent.payment_failed") == 0) {
        cJSON *data   = cJSON_GetObjectItem(event, "data");
        cJSON *object = data ? cJSON_GetObjectItem(data, "object") : NULL;
        cJSON *meta   = object ? cJSON_GetObjectItem(object, "metadata") : NULL;
        const char *booking_id = meta
            ? cJSON_GetStringValue(cJSON_GetObjectItem(meta, "booking_id"))
            : NULL;

        if (booking_id && *booking_id) {
            DbStmt *upd = NULL;
            upd = db_prepare(db,
                "UPDATE bookings SET status='cancelled' WHERE id=? AND status='pending_payment'");
            db_bind_text(upd, 1, booking_id);
            db_step(upd);
            db_finalize(upd);
            fprintf(stdout, "[stripe] booking %s cancelled (payment failed)\n", booking_id);
        }
    }

    cJSON_Delete(event);
    /* Stripe は 2xx を受け取れればよい */
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "{\"received\":true}");
}

/* ─── POST /api/v1/bookmarks ────────────────────────────────────────────────── */

void handle_create_bookmark(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    /* ユーザー単位書き込みレート制限 */
    if (rate_check_uid(auth_uid)) {
        send_error_json(c, 429, "リクエスト数が多すぎます。しばらく経ってから再試行してください");
        return;
    }

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    long plan_id = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "plan_id"));
    cJSON_Delete(body);

    if (plan_id <= 0) {
        send_error_json(c, 400, "plan_id は必須です"); return;
    }

    /* プランの存在確認 */
    DbStmt *chk = NULL;
    chk = db_prepare(db, "SELECT id FROM plans WHERE id=? AND is_active=1");
    db_bind_int(chk, 1, plan_id);
    if (db_step(chk) != 1) {
        db_finalize(chk);
        send_error_json(c, 404, "plan not found"); return;
    }
    db_finalize(chk);

    DbStmt *ins = NULL;
    ins = db_prepare(db,
        SQL_INSERT_OR_IGNORE " INTO bookmarks(user_id,plan_id) VALUES(?,?)" SQL_ON_CONFLICT_IGNORE);
    db_bind_int(ins, 1, auth_uid);
    db_bind_int(ins, 2, plan_id);
    db_step(ins);
    db_finalize(ins);

    long bm_id = (long)db_last_id(db);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id",      bm_id);
    cJSON_AddNumberToObject(res, "user_id", auth_uid);
    cJSON_AddNumberToObject(res, "plan_id", plan_id);
    send_cjson(c, 201, res);
    cJSON_Delete(res);
}

/* ─── DELETE /api/v1/bookmarks/:plan_id ────────────────────────────────────── */

void handle_delete_bookmark(struct mg_connection *c, struct mg_http_message *hm,
                             DbConn *db, long plan_id) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    DbStmt *del = NULL;
    del = db_prepare(db,
        "DELETE FROM bookmarks WHERE user_id=? AND plan_id=?");
    db_bind_int(del, 1, auth_uid);
    db_bind_int(del, 2, plan_id);
    db_step(del);
    int changes = db_changes(db);
    db_finalize(del);

    if (changes == 0) {
        send_error_json(c, 404, "bookmark not found"); return;
    }
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"ブックマークを削除しました\"}");
}

/* ─── GET /api/v1/users/:id/bookmarks ──────────────────────────────────────── */

void handle_list_user_bookmarks(struct mg_connection *c, struct mg_http_message *hm,
                                 DbConn *db, long user_id) {
    /* JWT 必須 + 自分のブックマークのみ */
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;
    if (auth_uid != user_id) {
        send_error_json(c, 403, "他のユーザーのブックマークは取得できません"); return;
    }
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT bm.id, bm.plan_id, p.title, p.duration_minutes, v.name AS venue_name, "
        "bm.created_at "
        "FROM bookmarks bm "
        "JOIN plans p ON p.id = bm.plan_id "
        "JOIN venues v ON v.id = p.venue_id "
        "WHERE bm.user_id = ? "
        "ORDER BY bm.created_at DESC");
    db_bind_int(st, 1, user_id);

    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *bm = cJSON_CreateObject();
        cJSON_AddNumberToObject(bm, "id",               db_col_int(st, 0));
        cJSON_AddNumberToObject(bm, "plan_id",          db_col_int(st, 1));
        cJSON_AddStringToObject(bm, "plan_title",       db_col_text(st, 2));
        if (!db_col_is_null(st, 3))
            cJSON_AddNumberToObject(bm, "duration_minutes", db_col_int(st, 3));
        else cJSON_AddNullToObject(bm, "duration_minutes");
        cJSON_AddStringToObject(bm, "venue_name",       db_col_text(st, 4));
        cJSON_AddStringToObject(bm, "created_at",       db_col_text(st, 5));
        cJSON_AddItemToArray(arr, bm);
    }
    db_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── PATCH /api/v1/auth/change-password ───────────────────────────────────── */

void handle_change_password(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *cur_pw = cJSON_GetStringValue(cJSON_GetObjectItem(body, "current_password"));
    const char *new_pw = cJSON_GetStringValue(cJSON_GetObjectItem(body, "new_password"));

    if (!cur_pw || !new_pw) {
        send_error_json(c, 400, "current_password と new_password は必須");
        cJSON_Delete(body); return;
    }
    if ((int)strlen(new_pw) < 8) {
        send_error_json(c, 400, "パスワードは8文字以上で指定してください");
        cJSON_Delete(body); return;
    }

    DbStmt *st = NULL;
    st = db_prepare(db, "SELECT password_hash FROM users WHERE id=?");
    db_bind_int(st, 1, auth_uid);
    if (db_step(st) != 1) {
        db_finalize(st); cJSON_Delete(body);
        send_error_json(c, 404, "user not found"); return;
    }
    char hash_buf[128] = {0};
    const char *h = db_col_text(st, 0);
    if (h) strncpy(hash_buf, h, sizeof(hash_buf)-1);
    db_finalize(st);

    if (!verify_password(cur_pw, hash_buf)) {
        cJSON_Delete(body);
        send_error_json(c, 400, "現在のパスワードが正しくありません"); return;
    }

    char new_hash[128];
    hash_password(new_pw, new_hash, sizeof(new_hash));
    cJSON_Delete(body);

    DbStmt *upd = NULL;
    upd = db_prepare(db, "UPDATE users SET password_hash=? WHERE id=?");
    db_bind_text(upd, 1, new_hash);
    db_bind_int(upd, 2, auth_uid);
    db_step(upd); db_finalize(upd);

    /* 現在のトークンをブラックリストに追加（パスワード変更後はログアウト扱い） */
    struct mg_str *auth_hdr = mg_http_get_header(hm, "Authorization");
    if (auth_hdr && auth_hdr->len > 7) {
        char cur_tok[512] = {0};
        size_t ct_len = auth_hdr->len - 7;
        if (ct_len < sizeof(cur_tok)) {
            memcpy(cur_tok, auth_hdr->buf + 7, ct_len);
            const char *sig = strrchr(cur_tok, '.');
            if (sig && sig[1]) {
                sig++;
                DbStmt *bl = NULL;
                bl = db_prepare(db,
                    "INSERT INTO jwt_blocklist(jti, expires_at)"
                    "VALUES(?, " SQL_NOW_PLUS_DAY(7) ")");
                db_bind_text(bl, 1, sig);
                db_step(bl); db_finalize(bl);
            }
        }
    }

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"パスワードを変更しました\"}");
}

/* ─── POST /api/v1/auth/forgot-password ────────────────────────────────────── */

void handle_forgot_password(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *email = cJSON_GetStringValue(cJSON_GetObjectItem(body, "email"));
    if (!email) {
        send_error_json(c, 400, "email は必須"); cJSON_Delete(body); return;
    }
    char email_lower[256] = {0};
    strncpy(email_lower, email, sizeof(email_lower)-1);
    str_lower(email_lower);
    cJSON_Delete(body);

    /* メール存在有無に関わらず同じレスポンスを返す（列挙攻撃防止） */
    DbStmt *st = NULL;
    st = db_prepare(db, "SELECT id FROM users WHERE email=?");
    db_bind_text(st, 1, email_lower);
    if (db_step(st) != 1) {
        db_finalize(st);
        send_json_str(c, 200, CORS_HEADERS,
            "{\"message\":\"登録済みの場合はリセット手順をメールで送信しました\"}");
        return;
    }
    long uid = db_col_int(st, 0);
    db_finalize(st);

    /* 32 文字ランダムトークン（UUID のダッシュ除去） */
    char uuid_str[37];
    generate_uuid(uuid_str);
    char token[33] = {0};
    int j = 0;
    for (int i = 0; uuid_str[i] && j < 32; i++)
        if (uuid_str[i] != '-') token[j++] = uuid_str[i];

    /* 既存トークンを削除して新規挿入（1時間有効）
       DB にはトークンの SHA-256 ハッシュを保存（平文漏洩対策）*/
    char token_hash[65];
    sha256_hex(token, strlen(token), token_hash);

    DbStmt *del = NULL;
    del = db_prepare(db, "DELETE FROM password_reset_tokens WHERE user_id=?");
    db_bind_int(del, 1, uid);
    db_step(del); db_finalize(del);

    DbStmt *ins = NULL;
    ins = db_prepare(db,
        "INSERT INTO password_reset_tokens(token,user_id,expires_at)"
        " VALUES(?,?," SQL_NOW_PLUS_HOUR(1) ")");
    db_bind_text(ins, 1, token_hash); /* ハッシュを保存 */
    db_bind_int(ins, 2, uid);
    db_step(ins); db_finalize(ins);

    /* メール送信（平文トークンをリンクに埋め込む）*/
    send_password_reset_email(email_lower, token);

    /* 開発環境では reset_token をレスポンスに含める（RESEND_API_KEY 未設定時のみ） */
    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "登録済みの場合はリセット手順をメールで送信しました");
    const char *api_key = getenv("RESEND_API_KEY");
    if (!api_key || !*api_key) {
        cJSON_AddStringToObject(res, "reset_token", token); /* 開発用 */
    }
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* ─── POST /api/v1/auth/reset-password ─────────────────────────────────────── */

void handle_reset_password(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *token_raw  = cJSON_GetStringValue(cJSON_GetObjectItem(body, "token"));
    const char *new_pw     = cJSON_GetStringValue(cJSON_GetObjectItem(body, "new_password"));

    if (!token_raw || !new_pw) {
        send_error_json(c, 400, "token と new_password は必須"); cJSON_Delete(body); return;
    }
    if ((int)strlen(new_pw) < 8) {
        send_error_json(c, 400, "パスワードは8文字以上で指定してください");
        cJSON_Delete(body); return;
    }

    /* body を解放した後でも使えるようローカルバッファにコピー */
    char token[64] = {0};
    strncpy(token, token_raw, sizeof(token)-1);

    /* 入力トークンをハッシュしてから DB と照合 */
    char token_hash[65];
    sha256_hex(token, strlen(token), token_hash);

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT user_id FROM password_reset_tokens"
        " WHERE token=? AND used=0 AND expires_at > " SQL_NOW_STR);
    db_bind_text(st, 1, token_hash);
    if (db_step(st) != 1) {
        db_finalize(st); cJSON_Delete(body);
        send_error_json(c, 400, "トークンが無効または期限切れです"); return;
    }
    long uid = db_col_int(st, 0);
    db_finalize(st);

    char new_hash[128];
    hash_password(new_pw, new_hash, sizeof(new_hash));
    cJSON_Delete(body);  /* これ以降 token_raw/new_pw は使えない。token/new_hash を使う */

    DbStmt *upd = NULL;
    upd = db_prepare(db, "UPDATE users SET password_hash=? WHERE id=?");
    db_bind_text(upd, 1, new_hash);
    db_bind_int(upd, 2, uid);
    db_step(upd); db_finalize(upd);

    DbStmt *mark = NULL;
    mark = db_prepare(db, "UPDATE password_reset_tokens SET used=1 WHERE token=?");
    db_bind_text(mark, 1, token_hash); /* ハッシュで照合 */
    db_step(mark); db_finalize(mark);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"パスワードをリセットしました\"}");
}

/* ─── DELETE /api/v1/reviews/:id ────────────────────────────────────────────── */

void handle_delete_review(struct mg_connection *c, struct mg_http_message *hm,
                           DbConn *db, long id) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    /* 存在確認 + オーナー確認 */
    DbStmt *chk = NULL;
    chk = db_prepare(db, "SELECT user_id FROM reviews WHERE id=?");
    db_bind_int(chk, 1, id);
    if (db_step(chk) != 1) {
        db_finalize(chk);
        send_error_json(c, 404, "review not found"); return;
    }
    long owner_id = db_col_int(chk, 0);
    db_finalize(chk);

    if (owner_id != auth_uid) {
        send_error_json(c, 403, "このレビューを削除する権限がありません"); return;
    }

    /* DELETE（DELETE トリガーが venue の review_count/avg を自動更新） */
    DbStmt *del = NULL;
    del = db_prepare(db, "DELETE FROM reviews WHERE id=?");
    db_bind_int(del, 1, id);
    db_step(del); db_finalize(del);

    /* 監査ログ */
    {
        char ip[48] = {0}; get_client_ip(c, ip, sizeof(ip));
        char uid_str[24]; snprintf(uid_str, sizeof(uid_str), "%ld", auth_uid);
        char id_str[24];  snprintf(id_str,  sizeof(id_str),  "%ld", id);
        audit_log(db, uid_str, "review.delete", "review", id_str, NULL, ip);
    }

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"レビューを削除しました\"}");
}

/* ─── POST /api/v1/auth/refresh ─────────────────────────────────────────────
   有効な JWT を受け取り、有効期限を延長した新しい JWT を返す              */

void handle_auth_refresh(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    /* Body: {"refresh_token": "..."} */
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *rt = cJSON_GetStringValue(cJSON_GetObjectItem(body, "refresh_token"));
    if (!rt || !*rt) {
        cJSON_Delete(body);
        send_error_json(c, 400, "refresh_token は必須");
        return;
    }
    /* コピーしてから body を解放 */
    char rt_buf[512] = {0};
    if (strlen(rt) >= sizeof(rt_buf)) {
        cJSON_Delete(body);
        send_error_json(c, 400, "refresh_token が長すぎます");
        return;
    }
    strncpy(rt_buf, rt, sizeof(rt_buf)-1);
    cJSON_Delete(body);

    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "asoview-jwt-secret-dev";

    /* type="refresh" のトークンのみ受け付ける */
    char tok_type[16] = {0};
    long uid = jwt_verify_typed(rt_buf, secret, tok_type, sizeof(tok_type));
    if (uid <= 0 || strcmp(tok_type, "refresh") != 0) {
        send_error_json(c, 401, "有効な refresh token が必要です");
        return;
    }

    /* ブラックリスト確認 */
    if (db) {
        const char *sig = strrchr(rt_buf, '.');
        if (sig && sig[1]) {
            sig++;
            DbStmt *bl = db_prepare(db,
                "SELECT 1 FROM jwt_blocklist WHERE jti=?");
            db_bind_text(bl, 1, sig);
            int blocked = (db_step(bl) == 1);
            db_finalize(bl);
            if (blocked) {
                send_error_json(c, 401, "このトークンは無効化されています");
                return;
            }
        }
    }

    /* 古い refresh token をブラックリストに追加（rotation） */
    {
        const char *sig = strrchr(rt_buf, '.');
        if (sig && sig[1]) {
            sig++;
            DbStmt *bl = db_prepare(db,
                "INSERT OR IGNORE INTO jwt_blocklist(jti, expires_at)"
                "VALUES(?, " SQL_NOW_PLUS_DAY(15) ")");
            db_bind_text(bl, 1, sig);
            db_step(bl); db_finalize(bl);
        }
    }

    /* 新しい access token + refresh token を発行 */
    char *new_token   = jwt_create(uid, secret);
    char *new_refresh = jwt_create_refresh(uid, secret);
    if (!new_token || !new_refresh) {
        free(new_token); free(new_refresh);
        send_error_json(c, 500, "token generation failed");
        return;
    }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "token",         new_token);
    cJSON_AddStringToObject(res, "refresh_token", new_refresh);
    free(new_token);
    free(new_refresh);
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* ─── POST /api/v1/auth/logout ──────────────────────────────────────────────
   現在の JWT をブラックリストに追加してログアウト                          */

void handle_auth_logout(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    struct mg_str *hdr = mg_http_get_header(hm, "Authorization");
    if (!hdr || hdr->len <= 7 || strncasecmp(hdr->buf, "Bearer ", 7) != 0) {
        send_error_json(c, 401, "認証が必要です"); return;
    }
    size_t tok_len = hdr->len - 7;
    char tok[512] = {0};
    if (tok_len >= sizeof(tok)) { send_error_json(c, 401, "token too long"); return; }
    memcpy(tok, hdr->buf + 7, tok_len);
    tok[tok_len] = '\0';

    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "asoview-jwt-secret-dev";
    long uid = jwt_verify_typed(tok, secret, NULL, 0);
    if (uid <= 0) { send_error_json(c, 401, "トークンが無効または期限切れです"); return; }

    /* access token をブラックリストに追加（TTL: 2日で十分、access は1h） */
    const char *sig = strrchr(tok, '.');
    if (sig && sig[1]) {
        sig++;
        DbStmt *bl = db_prepare(db,
            "INSERT OR IGNORE INTO jwt_blocklist(jti, expires_at)"
            "VALUES(?, " SQL_NOW_PLUS_DAY(2) ")");
        db_bind_text(bl, 1, sig);
        db_step(bl); db_finalize(bl);
    }

    /* オプション: body に refresh_token があれば一緒にブラックリスト追加 */
    if (hm->body.len > 2) {
        cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
        if (body) {
            const char *rt = cJSON_GetStringValue(cJSON_GetObjectItem(body, "refresh_token"));
            if (rt && *rt && strlen(rt) < 512) {
                char rt_copy[512]; strncpy(rt_copy, rt, sizeof(rt_copy)-1); rt_copy[sizeof(rt_copy)-1]='\0';
                long rt_uid = jwt_verify_typed(rt_copy, secret, NULL, 0);
                if (rt_uid == uid) {  /* 自分のトークンのみ無効化 */
                    const char *rt_sig = strrchr(rt_copy, '.');
                    if (rt_sig && rt_sig[1]) {
                        rt_sig++;
                        DbStmt *bl2 = db_prepare(db,
                            "INSERT OR IGNORE INTO jwt_blocklist(jti, expires_at)"
                            "VALUES(?, " SQL_NOW_PLUS_DAY(15) ")");
                        db_bind_text(bl2, 1, rt_sig);
                        db_step(bl2); db_finalize(bl2);
                    }
                }
            }
            cJSON_Delete(body);
        }
    }

    /* 監査ログ */
    {
        char ip[48] = {0}; get_client_ip(c, ip, sizeof(ip));
        char uid_str[24]; snprintf(uid_str, sizeof(uid_str), "%ld", uid);
        audit_log(db, uid_str, "logout", "user", uid_str, NULL, ip);
    }
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"ログアウトしました\"}");
}

/* ─── DELETE /api/v1/users/me (PIPA 退会・データ匿名化) ─────────────────────── */

void handle_delete_user_account(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    /* アクティブな予約をキャンセル */
    DbStmt *cst = NULL;
    cst = db_prepare(db,
        "UPDATE bookings SET status='cancelled' WHERE user_id=? AND status NOT IN ('cancelled','refunded')");
    db_bind_int(cst, 1, auth_uid);
    db_step(cst); db_finalize(cst);

    /* ブックマーク削除 */
    DbStmt *bst = NULL;
    bst = db_prepare(db, "DELETE FROM bookmarks WHERE user_id=?");
    db_bind_int(bst, 1, auth_uid);
    db_step(bst); db_finalize(bst);

    /* レビュー削除 */
    DbStmt *rst = NULL;
    rst = db_prepare(db, "DELETE FROM reviews WHERE user_id=?");
    db_bind_int(rst, 1, auth_uid);
    db_step(rst); db_finalize(rst);

    /* ウェイトリスト削除 */
    DbStmt *wst = NULL;
    wst = db_prepare(db, "DELETE FROM waitlist WHERE user_id=?");
    db_bind_int(wst, 1, auth_uid);
    db_step(wst); db_finalize(wst);

    /* ユーザー匿名化（財務監査のため予約レコードは残す） */
    char anon_email[64];
    snprintf(anon_email, sizeof(anon_email), "deleted_%ld@deleted.invalid", auth_uid);
    DbStmt *ust = NULL;
    ust = db_prepare(db,
        "UPDATE users SET email=?, name='退会済みユーザー', phone=NULL, password_hash='deleted'"
        " WHERE id=?");
    db_bind_text(ust, 1, anon_email);
    db_bind_int(ust, 2, auth_uid);
    db_step(ust); db_finalize(ust);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"アカウントを削除しました\"}");
}

/* ─── GET /api/v1/users/me/export (PIPA データエクスポート CSV) ─────────────── */

void handle_export_user_data(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    /* バッファに CSV を組み立てる */
    char *buf  = NULL;
    size_t len = 0;
    size_t cap = 65536;
    buf = (char *)malloc(cap);
    if (!buf) { send_error_json(c, 500, "memory error"); return; }
    buf[0] = '\0';

#define CSV_APPEND(fmt, ...) do { \
    int _n = snprintf(buf + len, cap - len, fmt, ##__VA_ARGS__); \
    if (_n > 0) len += (size_t)_n; \
    if (len + 4096 > cap) { \
        cap *= 2; \
        char *_nb = (char *)realloc(buf, cap); \
        if (!_nb) { free(buf); send_error_json(c, 500, "memory error"); return; } \
        buf = _nb; \
    } \
} while (0)

    /* ── ユーザー情報 ── */
    CSV_APPEND("# ユーザー情報\r\n");
    CSV_APPEND("id,name,email,created_at\r\n");
    DbStmt *ust = NULL;
    ust = db_prepare(db, "SELECT id,name,email,created_at FROM users WHERE id=?");
    db_bind_int(ust, 1, auth_uid);
    if (db_step(ust) == 1) {
        CSV_APPEND("%lld,\"%s\",\"%s\",\"%s\"\r\n",
            (long long)db_col_int(ust, 0),
            db_col_text(ust, 1) ? db_col_text(ust, 1) : "",
            db_col_text(ust, 2) ? db_col_text(ust, 2) : "",
            db_col_text(ust, 3) ? db_col_text(ust, 3) : "");
    }
    db_finalize(ust);

    /* ── 予約履歴 ── */
    CSV_APPEND("\r\n# 予約履歴\r\n");
    CSV_APPEND("id,plan_title,date,status,total_price,created_at\r\n");
    DbStmt *bst = NULL;
    bst = db_prepare(db,
        "SELECT b.id, p.title, s.date, b.status, b.total_price, b.created_at "
        "FROM bookings b "
        "JOIN plans p ON p.id = b.plan_id "
        "JOIN schedules s ON s.id = b.schedule_id "
        "WHERE b.user_id=? ORDER BY b.created_at DESC");
    db_bind_int(bst, 1, auth_uid);
    while (db_step(bst) == 1) {
        CSV_APPEND("\"%s\",\"%s\",\"%s\",\"%s\",%lld,\"%s\"\r\n",
            db_col_text(bst, 0) ? db_col_text(bst, 0) : "",
            db_col_text(bst, 1) ? db_col_text(bst, 1) : "",
            db_col_text(bst, 2) ? db_col_text(bst, 2) : "",
            db_col_text(bst, 3) ? db_col_text(bst, 3) : "",
            (long long)db_col_int(bst, 4),
            db_col_text(bst, 5) ? db_col_text(bst, 5) : "");
    }
    db_finalize(bst);

    /* ── レビュー ── */
    CSV_APPEND("\r\n# レビュー\r\n");
    CSV_APPEND("plan_title,rating,comment,created_at\r\n");
    DbStmt *rst = NULL;
    rst = db_prepare(db,
        "SELECT p.title, r.rating, r.comment, r.created_at "
        "FROM reviews r JOIN plans p ON p.id = r.plan_id "
        "WHERE r.user_id=? ORDER BY r.created_at DESC");
    db_bind_int(rst, 1, auth_uid);
    while (db_step(rst) == 1) {
        CSV_APPEND("\"%s\",%lld,\"%s\",\"%s\"\r\n",
            db_col_text(rst, 0) ? db_col_text(rst, 0) : "",
            (long long)db_col_int(rst, 1),
            db_col_text(rst, 2) ? db_col_text(rst, 2) : "",
            db_col_text(rst, 3) ? db_col_text(rst, 3) : "");
    }
    db_finalize(rst);

#undef CSV_APPEND

    /* 今日の日付をファイル名に付ける */
    time_t now = time(NULL);
    char date_str[16];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d", gmtime(&now));
    char disp[64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"my_data_%s.csv\"", date_str);

    char hdrs[256];
    snprintf(hdrs, sizeof(hdrs),
        "Content-Type: text/csv; charset=UTF-8\r\n"
        "Content-Disposition: %s\r\n"
        "Access-Control-Allow-Origin: *\r\n",
        disp);

    mg_http_reply(c, 200, hdrs, "%.*s", (int)len, buf);
    free(buf);
}

/* ─── GET /api/v1/bookings/:id/ical ─────────────────────────────────────── */

void handle_ical_booking(struct mg_connection *c, struct mg_http_message *hm,
                          DbConn *db, const char *id) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    DbStmt *st = db_prepare(db,
        "SELECT b.user_id, p.title, p.description, v.name, v.address, "
        "s.date, s.start_time, s.end_time, b.total_price, b.status "
        "FROM bookings b "
        "JOIN plans p ON p.id=b.plan_id "
        "JOIN venues v ON v.id=p.venue_id "
        "JOIN schedules s ON s.id=b.schedule_id "
        "WHERE b.id=?");
    db_bind_text(st, 1, id);
    if (db_step(st) != 1) {
        db_finalize(st);
        send_error_json(c, 404, "booking not found"); return;
    }

    long owner_id    = db_col_int(st, 0);
    char title[256]  = {0}; const char *tv = db_col_text(st, 1); if (tv) strncpy(title, tv, sizeof(title)-1);
    char desc[512]   = {0}; const char *dv = db_col_text(st, 2); if (dv) strncpy(desc, dv, sizeof(desc)-1);
    char venue[256]  = {0}; const char *vv = db_col_text(st, 3); if (vv) strncpy(venue, vv, sizeof(venue)-1);
    char addr[256]   = {0}; const char *av = db_col_text(st, 4); if (av) strncpy(addr, av, sizeof(addr)-1);
    char date[16]    = {0}; const char *sdv= db_col_text(st, 5); if (sdv) strncpy(date, sdv, sizeof(date)-1);
    char stime[8]    = {0}; const char *stv= db_col_text(st, 6); if (stv) strncpy(stime, stv, sizeof(stime)-1);
    char etime[8]    = {0}; const char *etv= db_col_text(st, 7); if (etv) strncpy(etime, etv, sizeof(etime)-1);
    long price       = db_col_int(st, 8);
    char status[32]  = {0}; const char *sv = db_col_text(st, 9); if (sv) strncpy(status, sv, sizeof(status)-1);
    db_finalize(st);

    if (owner_id != auth_uid) {
        send_error_json(c, 403, "この予約を取得する権限がありません"); return;
    }
    if (strcmp(status, "cancelled") == 0) {
        send_error_json(c, 400, "キャンセル済みの予約は iCal エクスポートできません"); return;
    }

    /* DTSTART / DTEND を組み立てる: YYYYMMDDTHHMMSS */
    char dtstart[20] = {0}, dtend[20] = {0};
    /* date = "YYYY-MM-DD", stime = "HH:MM" */
    char dy[5], dm[3], dd[3], sh[3], smin[3];
    sscanf(date,  "%4s-%2s-%2s", dy, dm, dd);
    sscanf(stime, "%2s:%2s", sh, smin);
    snprintf(dtstart, sizeof(dtstart), "%s%s%sT%s%s00", dy, dm, dd, sh, smin);
    if (etime[0]) {
        char eh[3], emin[3];
        sscanf(etime, "%2s:%2s", eh, emin);
        snprintf(dtend, sizeof(dtend), "%s%s%sT%s%s00", dy, dm, dd, eh, emin);
    } else {
        /* end time 不明の場合は 2 時間後 */
        int sh_i = atoi(sh); (void)smin;
        sh_i = (sh_i + 2) % 24;
        snprintf(dtend, sizeof(dtend), "%s%s%sT%02d%s00", dy, dm, dd, sh_i, smin);
    }

    time_t now = time(NULL);
    char dtstamp[20];
    struct tm *gmt = gmtime(&now);
    strftime(dtstamp, sizeof(dtstamp), "%Y%m%dT%H%M%SZ", gmt);

    char ical[2048];
    snprintf(ical, sizeof(ical),
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//Asoview//Booking//JA\r\n"
        "CALSCALE:GREGORIAN\r\n"
        "METHOD:PUBLISH\r\n"
        "BEGIN:VEVENT\r\n"
        "UID:%s@asoview\r\n"
        "DTSTAMP:%s\r\n"
        "DTSTART;TZID=Asia/Tokyo:%s\r\n"
        "DTEND;TZID=Asia/Tokyo:%s\r\n"
        "SUMMARY:%s\r\n"
        "DESCRIPTION:%s\\n\\n会場: %s\\n料金: \\%ld\r\n"
        "LOCATION:%s\r\n"
        "STATUS:CONFIRMED\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n",
        id, dtstamp, dtstart, dtend,
        title, desc, venue, price, addr);

    char disp_hdr[256];
    snprintf(disp_hdr, sizeof(disp_hdr),
        "Content-Type: text/calendar; charset=UTF-8\r\n"
        "Content-Disposition: attachment; filename=\"booking_%s.ics\"\r\n",
        id);
    mg_http_reply(c, 200, disp_hdr, "%s", ical);
}

/* ─── GET /api/v1/plans/:id/availability ────────────────────────────────── */

void handle_plan_availability(struct mg_connection *c, struct mg_http_message *hm,
                               DbConn *db, long plan_id) {
    /* ?from=YYYY-MM-DD  デフォルト: 今日 */
    /* ?to=YYYY-MM-DD    デフォルト: 30 日後 */
    /* ?adults=N         デフォルト: 1 */
    char from_buf[16] = {0}, to_buf[16] = {0};
    long adults = query_long(hm, "adults", 1);
    if (adults < 1) adults = 1;

    /* デフォルト: 今日〜30日後 */
    time_t now = time(NULL);
    if (!query_str(hm, "from", from_buf, sizeof(from_buf)) || !from_buf[0]) {
        struct tm *tm_now = gmtime(&now);
        strftime(from_buf, sizeof(from_buf), "%Y-%m-%d", tm_now);
    }
    if (!query_str(hm, "to", to_buf, sizeof(to_buf)) || !to_buf[0]) {
        time_t t30 = now + 30 * 86400;
        struct tm *tm30 = gmtime(&t30);
        strftime(to_buf, sizeof(to_buf), "%Y-%m-%d", tm30);
    }

    /* プランの存在確認 */
    DbStmt *chk = db_prepare(db, "SELECT id FROM plans WHERE id=? AND is_active=1");
    db_bind_int(chk, 1, plan_id);
    if (db_step(chk) != 1) {
        db_finalize(chk);
        send_error_json(c, 404, "プランが見つかりません");
        return;
    }
    db_finalize(chk);

    /* 空きスケジュール一覧 */
    DbStmt *st = db_prepare(db,
        "SELECT id, date, start_time, end_time, capacity, booked_count, "
        "       (capacity - booked_count) AS available "
        "FROM schedules "
        "WHERE plan_id=? AND date>=? AND date<=? "
        "  AND (capacity - booked_count) >= ? "
        "ORDER BY date, start_time");
    db_bind_int(st, 1, plan_id);
    db_bind_text(st, 2, from_buf);
    db_bind_text(st, 3, to_buf);
    db_bind_int(st, 4, adults);

    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *s = cJSON_CreateObject();
        cJSON_AddNumberToObject(s, "id",           db_col_int(st, 0));
        const char *d = db_col_text(st, 1);
        cJSON_AddStringToObject(s, "date",         d ? d : "");
        const char *st_ = db_col_text(st, 2);
        cJSON_AddStringToObject(s, "start_time",   st_ ? st_ : "");
        const char *et = db_col_text(st, 3);
        if (et) cJSON_AddStringToObject(s, "end_time", et);
        else    cJSON_AddNullToObject  (s, "end_time");
        cJSON_AddNumberToObject(s, "capacity",     db_col_int(st, 4));
        cJSON_AddNumberToObject(s, "booked_count", db_col_int(st, 5));
        cJSON_AddNumberToObject(s, "available",    db_col_int(st, 6));
        cJSON_AddItemToArray(arr, s);
    }
    db_finalize(st);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "plan_id",  plan_id);
    cJSON_AddStringToObject(root, "from",     from_buf);
    cJSON_AddStringToObject(root, "to",       to_buf);
    cJSON_AddNumberToObject(root, "adults",   adults);
    cJSON_AddItemToObject  (root, "schedules", arr);

    send_cjson_etag(c, hm, root);
    cJSON_Delete(root);
}

/* ─── GET /api/v1/coupons/:code ─────────────────────────────────────────── */

void handle_validate_coupon(struct mg_connection *c, struct mg_http_message *hm,
                             DbConn *db, const char *code) {
    (void)hm;
    DbStmt *st = db_prepare(db,
        "SELECT id,description,discount_type,discount_value,max_uses,used_count,expires_at,is_active"
        " FROM coupons WHERE code=? COLLATE NOCASE");
    db_bind_text(st, 1, code);
    if (db_step(st) != 1) {
        db_finalize(st);
        send_error_json(c, 404, "クーポンが見つかりません"); return;
    }
    long cid      = db_col_int(st, 0);
    long dval     = db_col_int(st, 3);
    long max_uses = db_col_int(st, 4);
    long used_cnt = db_col_int(st, 5);
    int active    = (int)db_col_int(st, 7);
    /* Copy strings before db_finalize invalidates SQLite's internal buffers */
    char cdesc_buf[256] = {0};
    char dtype_buf[32]  = {0};
    char exp_buf[32]    = {0};
    const char *cdesc_ptr = db_col_text(st, 1);
    const char *dtype_ptr = db_col_text(st, 2);
    const char *exp_ptr   = db_col_text(st, 6);
    if (cdesc_ptr) strncpy(cdesc_buf, cdesc_ptr, sizeof(cdesc_buf)-1);
    if (dtype_ptr) strncpy(dtype_buf, dtype_ptr, sizeof(dtype_buf)-1);
    if (exp_ptr)   strncpy(exp_buf,   exp_ptr,   sizeof(exp_buf)-1);
    db_finalize(st);

    int valid = active;
    const char *invalid_reason = NULL;
    if (!active)                              { valid = 0; invalid_reason = "無効なクーポン"; }
    if (max_uses > 0 && used_cnt >= max_uses) { valid = 0; invalid_reason = "使用回数上限に達しています"; }
    if (exp_buf[0]) {
        time_t now = time(NULL); char now_str[16];
        strftime(now_str, sizeof(now_str), "%Y-%m-%d", gmtime(&now));
        if (strcmp(now_str, exp_buf) > 0) { valid = 0; invalid_reason = "有効期限切れ"; }
    }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id",             cid);
    cJSON_AddStringToObject(res, "code",           code);
    if (cdesc_buf[0]) cJSON_AddStringToObject(res, "description", cdesc_buf);
    cJSON_AddStringToObject(res, "discount_type",  dtype_buf[0] ? dtype_buf : "percent");
    cJSON_AddNumberToObject(res, "discount_value", dval);
    cJSON_AddBoolToObject(res,   "valid",          valid);
    if (!valid && invalid_reason)
        cJSON_AddStringToObject(res, "invalid_reason", invalid_reason);
    if (exp_buf[0]) cJSON_AddStringToObject(res, "expires_at", exp_buf);
    char *s = cJSON_PrintUnformatted(res);
    send_json_str(c, valid ? 200 : 200, CORS_HEADERS, s);
    cJSON_free(s); cJSON_Delete(res);
}

/* ─── 2FA TOTP ───────────────────────────────────────────────────────────── */

#include "platform.h"
#include <stdint.h>

/* Base32 エンコード（RFC 4648 — TOTP アプリが読める形式） */
static const char B32CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static void base32_encode(const uint8_t *in, size_t in_len, char *out, size_t out_sz) {
    size_t i = 0, j = 0;
    uint32_t buf = 0; int bits = 0;
    while (i < in_len && j + 1 < out_sz) {
        buf = (buf << 8) | in[i++]; bits += 8;
        while (bits >= 5 && j + 1 < out_sz) {
            bits -= 5;
            out[j++] = B32CHARS[(buf >> bits) & 0x1f];
        }
    }
    if (bits > 0 && j + 1 < out_sz) out[j++] = B32CHARS[(buf << (5 - bits)) & 0x1f];
    /* padding */
    while (j % 8 != 0 && j + 1 < out_sz) out[j++] = '=';
    out[j] = '\0';
}

/* HOTP(secret, counter) → 6 桁コード */
uint32_t hotp(const uint8_t *secret, size_t sec_len, uint64_t counter) {
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) { msg[i] = counter & 0xff; counter >>= 8; }
    uint8_t mac[20];
    platform_hmac_sha1(secret, sec_len, msg, 8, mac);
    int off = mac[19] & 0x0f;
    uint32_t code = ((uint32_t)(mac[off]   & 0x7f) << 24)
                  | ((uint32_t) mac[off+1]          << 16)
                  | ((uint32_t) mac[off+2]          <<  8)
                  | ((uint32_t) mac[off+3]);
    return code % 1000000;
}

/* TOTP 検証（±1 ステップ = ±30 秒の誤差を許容） */
int totp_verify(const char *b32_secret, const char *code_str) {
    /* base32 デコード */
    uint8_t sec[32]; size_t sec_len = 0;
    const char *p = b32_secret;
    uint32_t buf = 0; int bits = 0;
    while (*p && *p != '=' && sec_len < sizeof(sec)) {
        char c = *p++;
        int v = -1;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        if (v < 0) continue;
        buf = (buf << 5) | (uint32_t)v; bits += 5;
        if (bits >= 8) { bits -= 8; sec[sec_len++] = (buf >> bits) & 0xff; }
    }
    if (sec_len == 0) return 0;

    long code = strtol(code_str, NULL, 10);
    if (code < 0 || code > 999999) return 0;

    uint64_t T = (uint64_t)time(NULL) / 30;
    /* ±1 step の許容 */
    for (int d = -1; d <= 1; d++) {
        if ((long)hotp(sec, sec_len, (uint64_t)((int64_t)T + d)) == code) return 1;
    }
    return 0;
}

/* POST /api/v1/auth/2fa/setup — TOTP シークレット生成・返却 */
void handle_auth_2fa_setup(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;
    (void)hm;

    /* ユーザーのメールアドレスを取得 */
    DbStmt *st = db_prepare(db, "SELECT email,totp_enabled FROM users WHERE id=?");
    db_bind_int(st, 1, auth_uid);
    if (db_step(st) != 1) { db_finalize(st); send_error_json(c, 404, "user not found"); return; }
    char email[256] = {0};
    const char *ev = db_col_text(st, 0); if (ev) strncpy(email, ev, sizeof(email)-1);
    int already = (int)db_col_int(st, 1);
    db_finalize(st);

    if (already) { send_error_json(c, 400, "2FA はすでに有効です"); return; }

    /* 20 バイトのランダムシークレット生成 */
    uint8_t raw[20];
    platform_random(raw, sizeof(raw));
    char b32[40];
    base32_encode(raw, sizeof(raw), b32, sizeof(b32));

    /* temp_totp_secret を DB に保存（有効化前）*/
    DbStmt *upd = db_prepare(db, "UPDATE users SET totp_secret=? WHERE id=?");
    db_bind_text(upd, 1, b32);
    db_bind_int(upd, 2, auth_uid);
    db_step(upd); db_finalize(upd);

    /* otpauth URI */
    char qr_uri[512];
    snprintf(qr_uri, sizeof(qr_uri),
             "otpauth://totp/Asoview:%s?secret=%s&issuer=Asoview&algorithm=SHA1&digits=6&period=30",
             email, b32);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "secret", b32);
    cJSON_AddStringToObject(res, "qr_uri", qr_uri);
    cJSON_AddStringToObject(res, "message",
        "QR コードをオーセンティケーターアプリで読み取り、/auth/2fa/enable で有効化してください");
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* POST /api/v1/auth/2fa/enable — コード確認して 2FA を有効化 */
void handle_auth_2fa_enable(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    const char *code = body ? cJSON_GetStringValue(cJSON_GetObjectItem(body, "code")) : NULL;
    if (!code) { if (body) cJSON_Delete(body); send_error_json(c, 400, "code は必須です"); return; }

    DbStmt *st = db_prepare(db, "SELECT totp_secret FROM users WHERE id=?");
    db_bind_int(st, 1, auth_uid);
    if (db_step(st) != 1) { db_finalize(st); cJSON_Delete(body); send_error_json(c, 404, "user not found"); return; }
    char secret[40] = {0};
    const char *sv = db_col_text(st, 0); if (sv) strncpy(secret, sv, sizeof(secret)-1);
    db_finalize(st);

    if (!secret[0]) { cJSON_Delete(body); send_error_json(c, 400, "まず /auth/2fa/setup を呼び出してください"); return; }
    if (!totp_verify(secret, code)) { cJSON_Delete(body); send_error_json(c, 400, "コードが正しくありません"); return; }

    DbStmt *upd = db_prepare(db, "UPDATE users SET totp_enabled=1 WHERE id=?");
    db_bind_int(upd, 1, auth_uid);
    db_step(upd); db_finalize(upd);

    cJSON_Delete(body);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"2FA が有効になりました\"}");
}

/* POST /api/v1/auth/2fa/verify — ログイン後の TOTP 検証（temp_token → JWT） */
void handle_auth_2fa_verify(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    const char *temp_token = body ? cJSON_GetStringValue(cJSON_GetObjectItem(body, "temp_token")) : NULL;
    const char *code       = body ? cJSON_GetStringValue(cJSON_GetObjectItem(body, "code"))       : NULL;

    if (!temp_token || !code) {
        if (body) cJSON_Delete(body);
        send_error_json(c, 400, "temp_token と code は必須です"); return;
    }

    /* temp_token は通常の JWT (2FA未確認状態) — 検証して user_id を取得 */
    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "asoview-jwt-secret-dev";
    extern long jwt_verify(const char *token, const char *secret);
    long uid = jwt_verify(temp_token, secret);
    if (uid <= 0) {
        cJSON_Delete(body);
        send_error_json(c, 401, "temp_token が無効です"); return;
    }

    /* TOTP シークレット取得 */
    DbStmt *st = db_prepare(db,
        "SELECT totp_secret, totp_enabled FROM users WHERE id=?");
    db_bind_int(st, 1, uid);
    if (db_step(st) != 1) {
        db_finalize(st); cJSON_Delete(body);
        send_error_json(c, 404, "user not found"); return;
    }
    char totp_secret[40] = {0};
    const char *tsv = db_col_text(st, 0); if (tsv) strncpy(totp_secret, tsv, sizeof(totp_secret)-1);
    int enabled = (int)db_col_int(st, 1);
    db_finalize(st);

    if (!enabled || !totp_secret[0]) {
        cJSON_Delete(body);
        send_error_json(c, 400, "2FA が有効になっていません"); return;
    }
    if (!totp_verify(totp_secret, code)) {
        cJSON_Delete(body);
        send_error_json(c, 401, "コードが正しくありません"); return;
    }

    /* 正規の JWT を発行 */
    extern char *jwt_create(long user_id, const char *secret);
    char *tok = jwt_create(uid, secret);
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "token", tok ? tok : "");
    cJSON_AddStringToObject(res, "message", "2FA 認証成功");
    send_cjson(c, 200, res);
    cJSON_Delete(res);
    free(tok);
}

/* ─── PATCH /api/v1/bookings/:id/reschedule ───────────────────────────────── */

void handle_reschedule_booking(struct mg_connection *c, struct mg_http_message *hm,
                               DbConn *db, const char *id) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, T("無効な JSON", "invalid JSON")); return; }

    cJSON *sid_j = cJSON_GetObjectItem(body, "schedule_id");
    if (!sid_j || !cJSON_IsNumber(sid_j)) {
        cJSON_Delete(body);
        send_error_json(c, 400, T("schedule_id が必要です", "schedule_id is required"));
        return;
    }
    long new_sched_id = (long)cJSON_GetNumberValue(sid_j);
    cJSON_Delete(body);

    /* 元の予約を取得 */
    DbStmt *st = db_prepare(db,
        "SELECT b.user_id, b.status, b.schedule_id, b.total_price, "
        "       s.plan_id, u.email, p.title "
        "FROM bookings b "
        "JOIN schedules s ON s.id=b.schedule_id "
        "JOIN plans p     ON p.id=s.plan_id "
        "JOIN users u     ON u.id=b.user_id "
        "WHERE b.id=?");
    db_bind_text(st, 1, id);
    if (db_step(st) != 1) {
        db_finalize(st);
        send_error_json(c, 404, T("予約が見つかりません", "booking not found")); return;
    }
    long owner_id     = db_col_int(st, 0);
    char old_status[32] = {0};
    const char *osv = db_col_text(st, 1); if (osv) strncpy(old_status, osv, sizeof(old_status)-1);
    long old_sched_id = db_col_int(st, 2);
    long total_people_col = db_col_int(st, 3); (void)total_people_col;
    long plan_id      = db_col_int(st, 4);
    char user_email[256] = {0};
    const char *ev = db_col_text(st, 5); if (ev) strncpy(user_email, ev, sizeof(user_email)-1);
    char plan_title[256] = {0};
    const char *pv = db_col_text(st, 6); if (pv) strncpy(plan_title, pv, sizeof(plan_title)-1);
    db_finalize(st);

    if (owner_id != auth_uid) {
        send_error_json(c, 403, T("この予約を変更する権限がありません", "forbidden")); return;
    }
    if (strcmp(old_status, "cancelled") == 0) {
        send_error_json(c, 400, T("キャンセル済みの予約は変更できません", "booking already cancelled")); return;
    }
    if (old_sched_id == new_sched_id) {
        send_error_json(c, 400, T("同じ日程です", "same schedule selected")); return;
    }

    /* 参加者合計 */
    DbStmt *pst = db_prepare(db,
        "SELECT COALESCE(SUM(count),0) FROM booking_participants WHERE booking_id=?");
    db_bind_text(pst, 1, id);
    db_step(pst);
    long total_people = db_col_int(pst, 0);
    db_finalize(pst);

    /* 新スケジュール確認（同プランかつ空きあり） */
    db_begin(db);
    st = db_prepare(db,
        "SELECT capacity, booked_count, date, start_time "
        "FROM schedules WHERE id=? AND plan_id=?");
    db_bind_int(st, 1, new_sched_id);
    db_bind_int(st, 2, plan_id);
    if (db_step(st) != 1) {
        db_finalize(st); db_rollback(db);
        send_error_json(c, 404, T("指定のスケジュールは存在しないか別プランです",
                                   "schedule not found or different plan")); return;
    }
    long cap   = db_col_int(st, 0);
    long booked= db_col_int(st, 1);
    char new_date[16]  = {0}; const char *ndv = db_col_text(st, 2); if (ndv) strncpy(new_date, ndv, sizeof(new_date)-1);
    char new_stime[8]  = {0}; const char *nsv = db_col_text(st, 3); if (nsv) strncpy(new_stime, nsv, sizeof(new_stime)-1);
    db_finalize(st);

    if (cap - booked < total_people) {
        db_rollback(db);
        send_error_json(c, 409, T("新しいスケジュールの空きが不足しています",
                                   "not enough capacity in new schedule")); return;
    }

    /* 予約のスケジュールを更新 */
    DbStmt *upd = db_prepare(db, "UPDATE bookings SET schedule_id=? WHERE id=?");
    db_bind_int(upd, 1, new_sched_id);
    db_bind_text(upd, 2, id);
    db_step(upd); db_finalize(upd);

    /* 旧スケジュールの booked_count を減らす */
    DbStmt *dec = db_prepare(db,
        "UPDATE schedules SET booked_count = MAX(0, booked_count - ?) WHERE id=?");
    db_bind_int(dec, 1, total_people);
    db_bind_int(dec, 2, old_sched_id);
    db_step(dec); db_finalize(dec);

    /* 新スケジュールの booked_count を増やす */
    DbStmt *inc = db_prepare(db,
        "UPDATE schedules SET booked_count = booked_count + ? WHERE id=?");
    db_bind_int(inc, 1, total_people);
    db_bind_int(inc, 2, new_sched_id);
    db_step(inc); db_finalize(inc);

    db_commit(db);

    /* メール送信 */
    if (user_email[0]) {
        send_booking_reschedule_email(user_email, id, plan_title, new_date, new_stime);
    }

    /* 監査ログ */
    {
        char ip[48] = {0}; get_client_ip(c, ip, sizeof(ip));
        char uid_str[24]; snprintf(uid_str, sizeof(uid_str), "%ld", auth_uid);
        char detail[64]; snprintf(detail, sizeof(detail), "sched:%ld->%ld", old_sched_id, new_sched_id);
        audit_log(db, uid_str, "booking.reschedule", "booking", id, detail, ip);
    }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message",    T("日程を変更しました", "rescheduled successfully"));
    cJSON_AddStringToObject(res, "new_date",   new_date);
    cJSON_AddStringToObject(res, "new_start_time", new_stime);
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/gift-cards/:code ───────────────────────────────────────── */

void handle_validate_giftcard(struct mg_connection *c, struct mg_http_message *hm,
                               DbConn *db, const char *code) {
    (void)hm;
    DbStmt *st = db_prepare(db,
        "SELECT id, initial_amount, remaining_balance, issued_to_email, "
        "       expires_at, is_active, created_at "
        "FROM gift_cards WHERE code=?");
    db_bind_text(st, 1, code);
    if (db_step(st) != 1) {
        db_finalize(st);
        send_error_json(c, 404, T("ギフト券が見つかりません", "gift card not found")); return;
    }
    long   gc_id    = db_col_int(st, 0);
    long   initial  = db_col_int(st, 1);
    long   balance  = db_col_int(st, 2);
    int    active   = (int)db_col_int(st, 5);
    char   expires[32] = {0}; const char *ev = db_col_text(st, 4); if (ev) strncpy(expires, ev, sizeof(expires)-1);
    char   created_at[32] = {0}; const char *cv = db_col_text(st, 6); if (cv) strncpy(created_at, cv, sizeof(created_at)-1);
    db_finalize(st);

    if (!active) {
        send_error_json(c, 410, T("このギフト券は無効です", "gift card is inactive")); return;
    }
    if (expires[0]) {
        /* 期限チェック */
        DbStmt *exp_st = db_prepare(db, "SELECT ? < date('now')");
        db_bind_text(exp_st, 1, expires);
        db_step(exp_st);
        int expired = (int)db_col_int(exp_st, 0);
        db_finalize(exp_st);
        if (expired) {
            send_error_json(c, 410, T("このギフト券は期限切れです", "gift card expired")); return;
        }
    }
    if (balance <= 0) {
        send_error_json(c, 410, T("このギフト券の残高がありません", "gift card balance is zero")); return;
    }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id",                gc_id);
    cJSON_AddStringToObject(res, "code",              code);
    cJSON_AddNumberToObject(res, "initial_amount",    initial);
    cJSON_AddNumberToObject(res, "remaining_balance", balance);
    if (expires[0]) cJSON_AddStringToObject(res, "expires_at", expires);
    else cJSON_AddNullToObject(res, "expires_at");
    cJSON_AddStringToObject(res, "created_at", created_at);
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/staff/bookings  (スタッフ: 担当会場の予約一覧) ──────────── */

static int require_staff_auth(struct mg_connection *c, struct mg_http_message *hm,
                               DbConn *db) {
    long uid = require_auth(c, hm, db);
    if (uid < 0) return -1;
    /* ロール確認 */
    DbStmt *st = db_prepare(db, "SELECT role FROM users WHERE id=?");
    db_bind_int(st, 1, uid);
    if (db_step(st) != 1) { db_finalize(st); send_error_json(c, 403, T("権限がありません", "forbidden")); return -1; }
    char role[16] = {0}; const char *rv = db_col_text(st, 0); if (rv) strncpy(role, rv, sizeof(role)-1);
    db_finalize(st);
    if (strcmp(role, "staff") != 0 && strcmp(role, "admin") != 0) {
        send_error_json(c, 403, T("スタッフ権限が必要です", "staff role required")); return -1;
    }
    return (int)uid;
}

void handle_staff_list_bookings(struct mg_connection *c, struct mg_http_message *hm,
                                DbConn *db) {
    int uid = require_staff_auth(c, hm, db);
    if (uid < 0) return;

    long page  = query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit = query_long(hm, "limit", 20); if (limit > 100) limit = 100;
    long offset = (page - 1) * limit;

    DbStmt *st = db_prepare(db,
        "SELECT b.id, p.title, u.name, u.email, b.status, b.total_price, "
        "       s.date, s.start_time, b.created_at "
        "FROM bookings b "
        "JOIN schedules s ON s.id=b.schedule_id "
        "JOIN plans p     ON p.id=s.plan_id "
        "JOIN venues v    ON v.id=p.venue_id "
        "JOIN users u     ON u.id=b.user_id "
        "JOIN staff_venues sv ON sv.venue_id=v.id AND sv.user_id=? "
        "ORDER BY b.created_at DESC LIMIT ? OFFSET ?");
    db_bind_int(st, 1, uid);
    db_bind_int(st, 2, limit);
    db_bind_int(st, 3, offset);

    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *b = cJSON_CreateObject();
        cJSON_AddStringToObject(b, "id",          db_col_text(st, 0));
        cJSON_AddStringToObject(b, "plan_title",  db_col_text(st, 1));
        cJSON_AddStringToObject(b, "user_name",   db_col_text(st, 2));
        cJSON_AddStringToObject(b, "user_email",  db_col_text(st, 3));
        cJSON_AddStringToObject(b, "status",      db_col_text(st, 4));
        cJSON_AddNumberToObject(b, "total_price", db_col_int(st, 5));
        cJSON_AddStringToObject(b, "date",        db_col_text(st, 6));
        cJSON_AddStringToObject(b, "start_time",  db_col_text(st, 7));
        cJSON_AddStringToObject(b, "created_at",  db_col_text(st, 8));
        cJSON_AddItemToArray(arr, b);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "bookings", arr);
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/staff/venues  (スタッフ: 担当会場一覧) ─────────────────── */

void handle_staff_list_venues(struct mg_connection *c, struct mg_http_message *hm,
                               DbConn *db) {
    int uid = require_staff_auth(c, hm, db);
    if (uid < 0) return;

    DbStmt *st = db_prepare(db,
        "SELECT v.id, v.name, v.area_id, a.name, v.address, v.created_at "
        "FROM venues v "
        "JOIN staff_venues sv ON sv.venue_id=v.id AND sv.user_id=? "
        "LEFT JOIN areas a ON a.id=v.area_id "
        "ORDER BY v.name");
    db_bind_int(st, 1, uid);

    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *v = cJSON_CreateObject();
        cJSON_AddNumberToObject(v, "id",         db_col_int(st, 0));
        cJSON_AddStringToObject(v, "name",       db_col_text(st, 1));
        cJSON_AddNumberToObject(v, "area_id",    db_col_int(st, 2));
        if (!db_col_is_null(st, 3))
            cJSON_AddStringToObject(v, "area_name", db_col_text(st, 3));
        else cJSON_AddNullToObject(v, "area_name");
        if (!db_col_is_null(st, 4))
            cJSON_AddStringToObject(v, "address", db_col_text(st, 4));
        else cJSON_AddNullToObject(v, "address");
        cJSON_AddStringToObject(v, "created_at", db_col_text(st, 5));
        cJSON_AddItemToArray(arr, v);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "venues", arr);
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* ─── Google OAuth ──────────────────────────────────────────────────────── */

/* libcurl 用レスポンスバッファ */
typedef struct { char *buf; size_t len; } OAuthBuf;
static size_t oauth_write_cb(char *ptr, size_t sz, size_t nmemb, void *ud) {
    OAuthBuf *b = (OAuthBuf*)ud;
    size_t add = sz * nmemb;
    char *tmp = realloc(b->buf, b->len + add + 1);
    if (!tmp) return 0;
    b->buf = tmp;
    memcpy(b->buf + b->len, ptr, add);
    b->len += add;
    b->buf[b->len] = '\0';
    return add;
}

void handle_auth_google(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    (void)hm; (void)db;
    const char *cid      = getenv("GOOGLE_CLIENT_ID");
    const char *redir    = getenv("GOOGLE_REDIRECT_URI");
    if (!cid || !*cid) {
        send_error_json(c, 503, T("Google OAuth が設定されていません", "Google OAuth not configured")); return;
    }
    if (!redir || !*redir) redir = "http://localhost:3001/api/v1/auth/google/callback";

    char url[1024];
    snprintf(url, sizeof(url),
        "https://accounts.google.com/o/oauth2/v2/auth"
        "?client_id=%s"
        "&redirect_uri=%s"
        "&response_type=code"
        "&scope=openid%%20email%%20profile"
        "&access_type=offline",
        cid, redir);

    mg_printf(c,
        "HTTP/1.1 302 Found\r\n"
        "Location: %s\r\n"
        "Content-Length: 0\r\n\r\n",
        url);
}

void handle_auth_google_callback(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    const char *cid    = getenv("GOOGLE_CLIENT_ID");
    const char *csec   = getenv("GOOGLE_CLIENT_SECRET");
    const char *redir  = getenv("GOOGLE_REDIRECT_URI");
    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "dev-secret-key";
    if (!redir || !*redir) redir = "http://localhost:3001/api/v1/auth/google/callback";

    if (!cid || !csec) {
        send_error_json(c, 503, T("Google OAuth が設定されていません", "Google OAuth not configured")); return;
    }

    char code[512] = {0};
    if (!query_str(hm, "code", code, sizeof(code)) || !code[0]) {
        send_error_json(c, 400, T("code が見つかりません", "missing code")); return;
    }

    /* ── Step 1: access_token を取得 ────────────────────────────────────── */
    CURL *curl = curl_easy_init();
    if (!curl) { send_error_json(c, 500, "curl init failed"); return; }

    char post[2048];
    snprintf(post, sizeof(post),
        "code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code",
        code, cid, csec, redir);

    OAuthBuf tok_resp = {NULL, 0};
    curl_easy_setopt(curl, CURLOPT_URL, "https://oauth2.googleapis.com/token");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &tok_resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    CURLcode cc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (cc != CURLE_OK || !tok_resp.buf) {
        free(tok_resp.buf);
        send_error_json(c, 502, T("Google との通信に失敗しました", "Google token exchange failed")); return;
    }

    cJSON *tok_json = cJSON_Parse(tok_resp.buf);
    free(tok_resp.buf);
    if (!tok_json) { send_error_json(c, 502, "token parse error"); return; }

    const char *access_token = cJSON_GetStringValue(cJSON_GetObjectItem(tok_json, "access_token"));
    if (!access_token) {
        cJSON_Delete(tok_json);
        send_error_json(c, 401, T("Google 認証失敗", "Google auth failed")); return;
    }
    char at_buf[1024];
    strncpy(at_buf, access_token, sizeof(at_buf)-1); at_buf[sizeof(at_buf)-1] = '\0';
    cJSON_Delete(tok_json);

    /* ── Step 2: ユーザー情報を取得 ─────────────────────────────────────── */
    curl = curl_easy_init();
    if (!curl) { send_error_json(c, 500, "curl init failed"); return; }

    char auth_hdr[1100];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", at_buf);
    struct curl_slist *hdrs = curl_slist_append(NULL, auth_hdr);

    OAuthBuf user_resp = {NULL, 0};
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.googleapis.com/oauth2/v2/userinfo");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &user_resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    cc = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (cc != CURLE_OK || !user_resp.buf) {
        free(user_resp.buf);
        send_error_json(c, 502, T("ユーザー情報の取得に失敗しました", "userinfo fetch failed")); return;
    }

    cJSON *uinfo = cJSON_Parse(user_resp.buf);
    free(user_resp.buf);
    if (!uinfo) { send_error_json(c, 502, "userinfo parse error"); return; }

    const char *google_id  = cJSON_GetStringValue(cJSON_GetObjectItem(uinfo, "id"));
    const char *g_email    = cJSON_GetStringValue(cJSON_GetObjectItem(uinfo, "email"));
    const char *g_name     = cJSON_GetStringValue(cJSON_GetObjectItem(uinfo, "name"));
    if (!google_id || !g_email) {
        cJSON_Delete(uinfo);
        send_error_json(c, 400, T("メールアドレスが取得できませんでした", "email unavailable")); return;
    }
    char gid_buf[64], email_buf[256], name_buf[128];
    strncpy(gid_buf,   google_id, sizeof(gid_buf)-1);   gid_buf[sizeof(gid_buf)-1] = '\0';
    strncpy(email_buf, g_email,   sizeof(email_buf)-1); email_buf[sizeof(email_buf)-1] = '\0';
    strncpy(name_buf,  g_name ? g_name : g_email, sizeof(name_buf)-1); name_buf[sizeof(name_buf)-1] = '\0';
    cJSON_Delete(uinfo);

    /* ── Step 3: ユーザーを作成 or 取得 ─────────────────────────────────── */
    /* google_id で検索 */
    DbStmt *st = db_prepare(db, "SELECT id FROM users WHERE google_id=?");
    db_bind_text(st, 1, gid_buf);
    long user_id = 0;
    if (db_step(st) == 1) user_id = db_col_int(st, 0);
    db_finalize(st);

    if (!user_id) {
        /* email で検索（既存アカウント連携） */
        st = db_prepare(db, "SELECT id FROM users WHERE email=?");
        db_bind_text(st, 1, email_buf);
        if (db_step(st) == 1) {
            user_id = db_col_int(st, 0);
            db_finalize(st);
            /* google_id を紐付け */
            DbStmt *upd = db_prepare(db, "UPDATE users SET google_id=? WHERE id=?");
            db_bind_text(upd, 1, gid_buf);
            db_bind_int(upd,  2, user_id);
            db_step(upd); db_finalize(upd);
        } else {
            db_finalize(st);
            /* 新規ユーザー作成（パスワードなし） */
            st = db_prepare(db,
                "INSERT INTO users(email,name,password_hash,google_id) VALUES(?,?,?,?) "
                "RETURNING id");
            db_bind_text(st, 1, email_buf);
            db_bind_text(st, 2, name_buf);
            db_bind_text(st, 3, "oauth2");   /* パスワードログイン不可のマーカー */
            db_bind_text(st, 4, gid_buf);
            if (db_step(st) == 1) user_id = db_col_int(st, 0);
            db_finalize(st);
        }
    }

    if (!user_id) {
        send_error_json(c, 500, T("ユーザーの作成に失敗しました", "user creation failed")); return;
    }

    /* JWT 発行 */
    char *tok = jwt_create(user_id, secret);
    char *rtok = jwt_create_refresh(user_id, secret);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "user_id",       user_id);
    cJSON_AddStringToObject(res, "name",          name_buf);
    cJSON_AddStringToObject(res, "email",         email_buf);
    cJSON_AddStringToObject(res, "token",         tok  ? tok  : "");
    cJSON_AddStringToObject(res, "refresh_token", rtok ? rtok : "");
    cJSON_AddStringToObject(res, "message",       T("Google ログイン成功", "Google login successful"));
    send_cjson(c, 200, res);
    cJSON_Delete(res);
    free(tok); free(rtok);
}
