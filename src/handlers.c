#include "handlers.h"
#include "utils.h"
#include "stripe.h"
#include "mailer.h"
#include "metrics.h"
#include "waitlist.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define MAX_BUF 256

/* ─── X-Request-ID（main.c から設定される） ──────────────────────────────── */
char g_request_id[40] = "none";

/* ─── 動的 CORS ヘッダー（CORS_ORIGIN 環境変数 + X-Request-ID 対応） ─────── */

static const char *get_cors_headers(void) {
    static char buf[600];
    const char *origin = getenv("CORS_ORIGIN");
    if (!origin || !*origin) origin = "*";
    snprintf(buf, sizeof(buf),
             "Content-Type: application/json\r\n"
             "Access-Control-Allow-Origin: %s\r\n"
             "X-Request-ID: %s\r\n",
             origin, g_request_id);
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

static void send_cjson(struct mg_connection *c, int status, cJSON *obj) {
    char *s = cJSON_PrintUnformatted(obj);
    send_json_str(c, status, CORS_HEADERS, s);
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
    long uid = jwt_verify(tok, secret);
    if (uid <= 0) { send_error_json(c, 401, "トークンが無効または期限切れです"); return -1; }

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
    long page    = query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit   = query_long(hm, "limit", 20); if (limit > 100) limit = 100;
    long offset  = (page - 1) * limit;
    long area_id = query_long(hm, "area_id", 0);

    /* total */
    DbStmt *ct = NULL;
    ct = db_prepare(db,
        "SELECT COUNT(*) FROM venues v WHERE (? = 0 OR v.area_id = ?)");
    db_bind_int(ct, 1, area_id);
    db_bind_int(ct, 2, area_id);
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT v.id,v.name,v.description,v.area_id,a.name,"
        "v.address,v.latitude,v.longitude,v.review_count,v.review_avg,v.created_at "
        "FROM venues v LEFT JOIN areas a ON a.id=v.area_id "
        "WHERE (? = 0 OR v.area_id = ?) ORDER BY v.id LIMIT ? OFFSET ?");
    db_bind_int(st, 1, area_id);
    db_bind_int(st, 2, area_id);
    db_bind_int(st, 3, limit);
    db_bind_int(st, 4, offset);

    cJSON *venues = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON_AddItemToArray(venues, venue_row(st));
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "venues", venues);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
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
    return p;
}

static const char *PLAN_SELECT =
    "SELECT p.id,p.venue_id,v.name,p.category_id,c.name,"
    "p.title,p.description,p.duration_minutes,"
    "p.min_participants,p.max_participants,p.min_age,"
    "p.images,p.tags,p.is_active,p.created_at "
    "FROM plans p "
    "JOIN venues v ON v.id=p.venue_id "
    "JOIN categories c ON c.id=p.category_id";

void handle_list_plans(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long page      = query_long(hm, "page", 1);     if (page < 1) page = 1;
    long limit     = query_long(hm, "limit", 20);   if (limit > 100) limit = 100;
    long offset    = (page - 1) * limit;
    long area_id   = query_long(hm, "area_id", 0);
    long cat_id    = query_long(hm, "category_id", 0);
    long adults    = query_long(hm, "adults", 0);
    long children  = query_long(hm, "children", 0);
    long required  = (adults + children) > 0 ? adults + children : 1;
    char date[32]  = {0};
    int has_date   = query_str(hm, "date", date, sizeof(date));

    char cnt_sql[512], qsql[1024];
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

    DbStmt *ct = NULL;
    ct = db_prepare(db, cnt_sql);
    db_bind_int(ct, 1, cat_id); db_bind_int(ct, 2, cat_id);
    db_bind_int(ct, 3, area_id); db_bind_int(ct, 4, area_id);
    db_bind_int(ct, 5, has_date ? 1 : 0);
    db_bind_text(ct, 6, date);
    db_bind_int(ct, 7, required);
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    st = db_prepare(db, qsql);
    db_bind_int(st, 1, cat_id); db_bind_int(st, 2, cat_id);
    db_bind_int(st, 3, area_id); db_bind_int(st, 4, area_id);
    db_bind_int(st, 5, has_date ? 1 : 0);
    db_bind_text(st, 6, date);
    db_bind_int(st, 7, required);
    db_bind_int(st, 8, limit); db_bind_int(st, 9, offset);

    cJSON *plans = cJSON_CreateArray();
    while (db_step(st) == 1) {
        long plan_id = db_col_int(st, 0);
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
        cJSON_Delete(body);
        return;
    }
    if (!is_valid_email(email)) {
        send_error_json(c, 400, "メールアドレスの形式が正しくありません");
        cJSON_Delete(body);
        return;
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
            "SELECT locked_until > " SQL_NOW_STR " FROM users WHERE id=?");
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
    char *tok = jwt_create(uid, secret);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "user_id", uid);
    cJSON_AddStringToObject(res, "name",    name_buf);
    cJSON_AddStringToObject(res, "token",   tok ? tok : "");
    cJSON_AddStringToObject(res, "message", "ログインしました");
    send_cjson(c, 200, res);
    cJSON_Delete(res);
    free(tok);
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

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    long plan_id    = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "plan_id"));
    long sched_id   = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "schedule_id"));
    cJSON *parts    = cJSON_GetObjectItem(body, "participants");
    const char *note= cJSON_GetStringValue(cJSON_GetObjectItem(body, "note"));

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

    /* 空き枠チェック */
    DbStmt *cap_st = NULL;
    cap_st = db_prepare(db,
        "SELECT capacity,booked_count FROM schedules WHERE id=? AND plan_id=?");
    db_bind_int(cap_st, 1, sched_id);
    db_bind_int(cap_st, 2, plan_id);
    if (db_step(cap_st) != 1) {
        db_finalize(cap_st); cJSON_Delete(body);
        send_error_json(c, 404, "schedule not found"); return;
    }
    long cap    = db_col_int(cap_st, 0);
    long booked = db_col_int(cap_st, 1);
    db_finalize(cap_st);

    /* サーバー側で価格を確定 */
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

    if (cap - booked < total_people) {
        char msg[64];
        snprintf(msg, sizeof(msg), "空き枠が不足しています（残 %ld 席）", cap - booked);
        send_error_json(c, 409, msg);
        cJSON_Delete(body); return;
    }

    char booking_id[37];
    generate_uuid(booking_id);

    /* STRIPE_SECRET_KEY が設定されていれば pending_payment で作成 */
    const char *stripe_sk = getenv("STRIPE_SECRET_KEY");
    const char *init_status = (stripe_sk && *stripe_sk) ? "pending_payment" : "confirmed";

    DbStmt *ins = NULL;
    ins = db_prepare(db,
        "INSERT INTO bookings(id,user_id,plan_id,schedule_id,status,total_price,note)"
        " VALUES(?,?,?,?,?,?,?)");
    db_bind_text(ins, 1, booking_id);
    db_bind_int(ins, 2, auth_uid);
    db_bind_int(ins, 3, plan_id);
    db_bind_int(ins, 4, sched_id);
    db_bind_text(ins, 5, init_status);
    db_bind_int(ins, 6, total_price);
    db_bind_text(ins, 7, note ? note : "");
    int rc = db_step(ins);
    db_finalize(ins);

    if (rc == -1) {
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
        cJSON_AddStringToObject(bk, "status",     db_col_text(sel, 7));
        cJSON_AddNumberToObject(bk, "total_price",db_col_int(sel, 8));
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

    if (bk) { send_cjson(c, 201, bk); cJSON_Delete(bk); }
    else      send_error_json(c, 500, "failed to fetch booking");
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
        cJSON_Delete(body);
        return;
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

    /* FTS5 サブクエリ方式（JOIN より信頼性が高い） */
    const char *cnt_fts_sql =
        "SELECT COUNT(DISTINCT p.id) FROM plans p "
        "JOIN venues v ON v.id=p.venue_id "
        "WHERE p.is_active=1 "
        "AND p.id IN (SELECT rowid FROM plans_fts WHERE plans_fts MATCH ?) "
        "AND (? = 0 OR p.category_id=?) "
        "AND (? = 0 OR v.area_id=?) "
        "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
        "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?))";

    const char *cnt_like_sql =
        "SELECT COUNT(DISTINCT p.id) FROM plans p "
        "JOIN venues v ON v.id=p.venue_id "
        "WHERE p.is_active=1 "
        "AND (? = 0 OR p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\' OR v.name LIKE ? ESCAPE '\\') "
        "AND (? = 0 OR p.category_id=?) "
        "AND (? = 0 OR v.area_id=?) "
        "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
        "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?))";

    char qsql_fts[1200], qsql_like[1200];
    snprintf(qsql_fts, sizeof(qsql_fts),
        "%s WHERE p.is_active=1 "
        "AND p.id IN (SELECT rowid FROM plans_fts WHERE plans_fts MATCH ?) "
        "AND (? = 0 OR p.category_id=?) "
        "AND (? = 0 OR v.area_id=?) "
        "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
        "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?)) "
        "ORDER BY p.id LIMIT ? OFFSET ?", PLAN_SELECT);
    snprintf(qsql_like, sizeof(qsql_like),
        "%s WHERE p.is_active=1 "
        "AND (? = 0 OR p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\' OR v.name LIKE ? ESCAPE '\\') "
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

void handle_cancel_booking(struct mg_connection *c, struct mg_http_message *hm,
                            DbConn *db, const char *id) {
    long auth_uid = require_auth(c, hm, db);
    if (auth_uid < 0) return;

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT b.user_id, b.status, b.schedule_id, b.stripe_payment_intent_id, "
        "u.email, p.title "
        "FROM bookings b "
        "JOIN users u ON u.id = b.user_id "
        "JOIN plans p ON p.id = b.plan_id "
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
    db_finalize(st);

    if (owner_id != auth_uid) {
        send_error_json(c, 403, "この予約をキャンセルする権限がありません"); return;
    }
    if (strcmp(status_buf, "cancelled") == 0) {
        send_error_json(c, 400, "既にキャンセル済みです"); return;
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

    /* Stripe 返金（payment_intent_id がある場合） */
    int refunded = 0;
    if (pi_id[0]) {
        refunded = (stripe_create_refund(pi_id) == 0) ? 1 : 0;
        if (refunded)
            fprintf(stdout, "[stripe] refund issued for booking %s (pi=%s)\n", id, pi_id);
    }

    /* キャンセルメール送信 */
    if (user_email[0]) {
        send_booking_cancellation_email(user_email, id, plan_title, refunded);
    }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "予約をキャンセルしました");
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
            "INSERT INTO webhook_events(event_id) VALUES(?) ON CONFLICT DO NOTHING");
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
        "INSERT INTO bookmarks(user_id,plan_id) VALUES(?,?) ON CONFLICT DO NOTHING");
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

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"レビューを削除しました\"}");
}

/* ─── POST /api/v1/auth/refresh ─────────────────────────────────────────────
   有効な JWT を受け取り、有効期限を延長した新しい JWT を返す              */

void handle_auth_refresh(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    long uid = require_auth(c, hm, db);
    if (uid < 0) return;

    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "asoview-jwt-secret-dev";

    char *new_token = jwt_create(uid, secret);
    if (!new_token) { send_error_json(c, 500, "token generation failed"); return; }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "token", new_token);
    free(new_token);
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
    long uid = jwt_verify(tok, secret);
    if (uid <= 0) { send_error_json(c, 401, "トークンが無効または期限切れです"); return; }

    /* 署名部分（最後のドット以降）をブラックリストキーとして使用 */
    const char *sig = strrchr(tok, '.');
    if (sig && sig[1]) {
        sig++;
        DbStmt *bl = NULL;
        bl = db_prepare(db,
            "INSERT INTO jwt_blocklist(jti, expires_at)"
            "VALUES(?, " SQL_NOW_PLUS_DAY(7) ")");
        db_bind_text(bl, 1, sig);
        db_step(bl); db_finalize(bl);
    }
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"ログアウトしました\"}");
}
