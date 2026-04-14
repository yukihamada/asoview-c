#include "handlers.h"
#include "utils.h"
#include "stripe.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CORS_HEADERS "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n"
#define MAX_BUF 256

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
    cJSON *e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "error", msg);
    send_cjson(c, status, e);
    cJSON_Delete(e);
}

/* ─── Auth helper ────────────────────────────────────────────────────────── */

/* Authorization: Bearer <token> を検証し user_id を返す。失敗時は 401 を送信して -1 */
static long require_auth(struct mg_connection *c, struct mg_http_message *hm) {
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
    return uid;
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
static cJSON *fetch_prices(sqlite3 *db, long plan_id) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT id,participant_type,label,price FROM plan_prices WHERE plan_id=? ORDER BY id",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, plan_id);
    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *p = cJSON_CreateObject();
        cJSON_AddNumberToObject(p, "id",               sqlite3_column_int64(st, 0));
        cJSON_AddStringToObject(p, "participant_type", (const char*)sqlite3_column_text(st, 1));
        cJSON_AddStringToObject(p, "label",            (const char*)sqlite3_column_text(st, 2));
        cJSON_AddNumberToObject(p, "price",            sqlite3_column_int64(st, 3));
        cJSON_AddItemToArray(arr, p);
    }
    sqlite3_finalize(st);
    return arr;
}

/* booking の参加者リストを cJSON array として返す */
static cJSON *fetch_participants(sqlite3 *db, const char *booking_id) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT participant_type,label,count,unit_price FROM booking_participants WHERE booking_id=?",
        -1, &st, NULL);
    sqlite3_bind_text(st, 1, booking_id, -1, SQLITE_STATIC);
    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *p = cJSON_CreateObject();
        cJSON_AddStringToObject(p, "participant_type", (const char*)sqlite3_column_text(st, 0));
        cJSON_AddStringToObject(p, "label",      (const char*)sqlite3_column_text(st, 1));
        cJSON_AddNumberToObject(p, "count",      sqlite3_column_int64(st, 2));
        cJSON_AddNumberToObject(p, "unit_price", sqlite3_column_int64(st, 3));
        cJSON_AddItemToArray(arr, p);
    }
    sqlite3_finalize(st);
    return arr;
}

/* ─── Health ──────────────────────────────────────────────────────────────── */

void handle_health(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    (void)hm; (void)db;
    send_json_str(c, 200, CORS_HEADERS,
                  "{\"status\":\"ok\",\"service\":\"asoview\",\"version\":\"0.1.0\"}");
}

/* ─── Areas ───────────────────────────────────────────────────────────────── */

void handle_list_areas(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    (void)hm;
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT id,name,name_kana,parent_id,level,slug FROM areas ORDER BY level,id",
        -1, &st, NULL);
    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddNumberToObject(a, "id",    sqlite3_column_int64(st, 0));
        cJSON_AddStringToObject(a, "name",  (const char*)sqlite3_column_text(st, 1));
        if (sqlite3_column_type(st, 2) != SQLITE_NULL)
            cJSON_AddStringToObject(a, "name_kana", (const char*)sqlite3_column_text(st, 2));
        else cJSON_AddNullToObject(a, "name_kana");
        if (sqlite3_column_type(st, 3) != SQLITE_NULL)
            cJSON_AddNumberToObject(a, "parent_id", sqlite3_column_int64(st, 3));
        else cJSON_AddNullToObject(a, "parent_id");
        cJSON_AddNumberToObject(a, "level", sqlite3_column_int64(st, 4));
        cJSON_AddStringToObject(a, "slug",  (const char*)sqlite3_column_text(st, 5));
        cJSON_AddItemToArray(arr, a);
    }
    sqlite3_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── Categories ──────────────────────────────────────────────────────────── */

void handle_list_categories(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    (void)hm;
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT id,name,slug,parent_id,icon FROM categories ORDER BY id",
        -1, &st, NULL);
    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *a = cJSON_CreateObject();
        cJSON_AddNumberToObject(a, "id",   sqlite3_column_int64(st, 0));
        cJSON_AddStringToObject(a, "name", (const char*)sqlite3_column_text(st, 1));
        cJSON_AddStringToObject(a, "slug", (const char*)sqlite3_column_text(st, 2));
        if (sqlite3_column_type(st, 3) != SQLITE_NULL)
            cJSON_AddNumberToObject(a, "parent_id", sqlite3_column_int64(st, 3));
        else cJSON_AddNullToObject(a, "parent_id");
        if (sqlite3_column_type(st, 4) != SQLITE_NULL)
            cJSON_AddStringToObject(a, "icon", (const char*)sqlite3_column_text(st, 4));
        else cJSON_AddNullToObject(a, "icon");
        cJSON_AddItemToArray(arr, a);
    }
    sqlite3_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── Venues ──────────────────────────────────────────────────────────────── */

static cJSON *venue_row(sqlite3_stmt *st) {
    cJSON *v = cJSON_CreateObject();
    cJSON_AddNumberToObject(v, "id",     sqlite3_column_int64(st, 0));
    cJSON_AddStringToObject(v, "name",   (const char*)sqlite3_column_text(st, 1));
    if (sqlite3_column_type(st, 2) != SQLITE_NULL)
        cJSON_AddStringToObject(v, "description", (const char*)sqlite3_column_text(st, 2));
    else cJSON_AddNullToObject(v, "description");
    cJSON_AddNumberToObject(v, "area_id", sqlite3_column_int64(st, 3));
    if (sqlite3_column_type(st, 4) != SQLITE_NULL)
        cJSON_AddStringToObject(v, "area_name", (const char*)sqlite3_column_text(st, 4));
    else cJSON_AddNullToObject(v, "area_name");
    if (sqlite3_column_type(st, 5) != SQLITE_NULL)
        cJSON_AddStringToObject(v, "address", (const char*)sqlite3_column_text(st, 5));
    else cJSON_AddNullToObject(v, "address");
    cJSON_AddNumberToObject(v, "latitude",     sqlite3_column_double(st, 6));
    cJSON_AddNumberToObject(v, "longitude",    sqlite3_column_double(st, 7));
    cJSON_AddNumberToObject(v, "review_count", sqlite3_column_int64(st, 8));
    cJSON_AddNumberToObject(v, "review_avg",   sqlite3_column_double(st, 9));
    cJSON_AddStringToObject(v, "created_at",   (const char*)sqlite3_column_text(st, 10));
    return v;
}

void handle_list_venues(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    long page    = query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit   = query_long(hm, "limit", 20); if (limit > 100) limit = 100;
    long offset  = (page - 1) * limit;
    long area_id = query_long(hm, "area_id", 0);

    /* total */
    sqlite3_stmt *ct;
    sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM venues v WHERE (? = 0 OR v.area_id = ?)",
        -1, &ct, NULL);
    sqlite3_bind_int64(ct, 1, area_id);
    sqlite3_bind_int64(ct, 2, area_id);
    sqlite3_step(ct);
    long total = sqlite3_column_int64(ct, 0);
    sqlite3_finalize(ct);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT v.id,v.name,v.description,v.area_id,a.name,"
        "v.address,v.latitude,v.longitude,v.review_count,v.review_avg,v.created_at "
        "FROM venues v LEFT JOIN areas a ON a.id=v.area_id "
        "WHERE (? = 0 OR v.area_id = ?) ORDER BY v.id LIMIT ? OFFSET ?",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, area_id);
    sqlite3_bind_int64(st, 2, area_id);
    sqlite3_bind_int64(st, 3, limit);
    sqlite3_bind_int64(st, 4, offset);

    cJSON *venues = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON_AddItemToArray(venues, venue_row(st));
    }
    sqlite3_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "venues", venues);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

void handle_get_venue(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id) {
    (void)hm;
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT v.id,v.name,v.description,v.area_id,a.name,"
        "v.address,v.latitude,v.longitude,v.review_count,v.review_avg,v.created_at "
        "FROM venues v LEFT JOIN areas a ON a.id=v.area_id WHERE v.id=?",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, id);
    if (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *v = venue_row(st);
        sqlite3_finalize(st);
        send_cjson(c, 200, v);
        cJSON_Delete(v);
    } else {
        sqlite3_finalize(st);
        send_error_json(c, 404, "venue not found");
    }
}

/* ─── Plans ───────────────────────────────────────────────────────────────── */

static cJSON *plan_row(sqlite3_stmt *st) {
    cJSON *p = cJSON_CreateObject();
    cJSON_AddNumberToObject(p, "id",          sqlite3_column_int64(st, 0));
    cJSON_AddNumberToObject(p, "venue_id",    sqlite3_column_int64(st, 1));
    cJSON_AddStringToObject(p, "venue_name",  (const char*)sqlite3_column_text(st, 2));
    cJSON_AddNumberToObject(p, "category_id", sqlite3_column_int64(st, 3));
    cJSON_AddStringToObject(p, "category_name",(const char*)sqlite3_column_text(st, 4));
    cJSON_AddStringToObject(p, "title",       (const char*)sqlite3_column_text(st, 5));
    if (sqlite3_column_type(st, 6) != SQLITE_NULL)
        cJSON_AddStringToObject(p, "description", (const char*)sqlite3_column_text(st, 6));
    else cJSON_AddNullToObject(p, "description");
    if (sqlite3_column_type(st, 7) != SQLITE_NULL)
        cJSON_AddNumberToObject(p, "duration_minutes", sqlite3_column_int64(st, 7));
    else cJSON_AddNullToObject(p, "duration_minutes");
    cJSON_AddNumberToObject(p, "min_participants", sqlite3_column_int64(st, 8));
    if (sqlite3_column_type(st, 9) != SQLITE_NULL)
        cJSON_AddNumberToObject(p, "max_participants", sqlite3_column_int64(st, 9));
    else cJSON_AddNullToObject(p, "max_participants");
    if (sqlite3_column_type(st, 10) != SQLITE_NULL)
        cJSON_AddNumberToObject(p, "min_age", sqlite3_column_int64(st, 10));
    else cJSON_AddNullToObject(p, "min_age");
    /* images / tags stored as JSON strings */
    const char *imgs = (const char*)sqlite3_column_text(st, 11);
    const char *tags = (const char*)sqlite3_column_text(st, 12);
    cJSON *imgs_arr = cJSON_Parse(imgs ? imgs : "[]");
    cJSON *tags_arr = cJSON_Parse(tags ? tags : "[]");
    cJSON_AddItemToObject(p, "images", imgs_arr ? imgs_arr : cJSON_CreateArray());
    cJSON_AddItemToObject(p, "tags",   tags_arr ? tags_arr : cJSON_CreateArray());
    cJSON_AddBoolToObject(p, "is_active", sqlite3_column_int(st, 13) == 1);
    cJSON_AddStringToObject(p, "created_at", (const char*)sqlite3_column_text(st, 14));
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

void handle_list_plans(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
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

    sqlite3_stmt *ct;
    sqlite3_prepare_v2(db, cnt_sql, -1, &ct, NULL);
    sqlite3_bind_int64(ct, 1, cat_id); sqlite3_bind_int64(ct, 2, cat_id);
    sqlite3_bind_int64(ct, 3, area_id); sqlite3_bind_int64(ct, 4, area_id);
    sqlite3_bind_int64(ct, 5, has_date ? 1 : 0);
    sqlite3_bind_text(ct, 6, date, -1, SQLITE_STATIC);
    sqlite3_bind_int64(ct, 7, required);
    sqlite3_step(ct);
    long total = sqlite3_column_int64(ct, 0);
    sqlite3_finalize(ct);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, qsql, -1, &st, NULL);
    sqlite3_bind_int64(st, 1, cat_id); sqlite3_bind_int64(st, 2, cat_id);
    sqlite3_bind_int64(st, 3, area_id); sqlite3_bind_int64(st, 4, area_id);
    sqlite3_bind_int64(st, 5, has_date ? 1 : 0);
    sqlite3_bind_text(st, 6, date, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 7, required);
    sqlite3_bind_int64(st, 8, limit); sqlite3_bind_int64(st, 9, offset);

    cJSON *plans = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        long plan_id = sqlite3_column_int64(st, 0);
        cJSON *p = plan_row(st);
        cJSON_AddItemToObject(p, "prices", fetch_prices(db, plan_id));
        cJSON_AddItemToArray(plans, p);
    }
    sqlite3_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "plans", plans);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

void handle_get_plan(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id) {
    (void)hm;
    char qsql[512];
    snprintf(qsql, sizeof(qsql), "%s WHERE p.id=? AND p.is_active=1", PLAN_SELECT);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, qsql, -1, &st, NULL);
    sqlite3_bind_int64(st, 1, id);
    if (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *p = plan_row(st);
        sqlite3_finalize(st);
        cJSON_AddItemToObject(p, "prices", fetch_prices(db, id));
        send_cjson(c, 200, p);
        cJSON_Delete(p);
    } else {
        sqlite3_finalize(st);
        send_error_json(c, 404, "plan not found");
    }
}

/* ─── Schedules ───────────────────────────────────────────────────────────── */

void handle_list_schedules(struct mg_connection *c, struct mg_http_message *hm,
                           sqlite3 *db, long plan_id) {
    char date[32] = {0};
    int has_date = query_str(hm, "date", date, sizeof(date));

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT id,plan_id,date,start_time,end_time,capacity,booked_count "
        "FROM schedules WHERE plan_id=? AND (? = 0 OR date=?) ORDER BY date,start_time",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, plan_id);
    sqlite3_bind_int64(st, 2, has_date ? 1 : 0);
    sqlite3_bind_text(st, 3, date, -1, SQLITE_STATIC);

    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        long cap    = sqlite3_column_int64(st, 5);
        long booked = sqlite3_column_int64(st, 6);
        cJSON *s = cJSON_CreateObject();
        cJSON_AddNumberToObject(s, "id",          sqlite3_column_int64(st, 0));
        cJSON_AddNumberToObject(s, "plan_id",     sqlite3_column_int64(st, 1));
        cJSON_AddStringToObject(s, "date",        (const char*)sqlite3_column_text(st, 2));
        cJSON_AddStringToObject(s, "start_time",  (const char*)sqlite3_column_text(st, 3));
        if (sqlite3_column_type(st, 4) != SQLITE_NULL)
            cJSON_AddStringToObject(s, "end_time",(const char*)sqlite3_column_text(st, 4));
        else cJSON_AddNullToObject(s, "end_time");
        cJSON_AddNumberToObject(s, "capacity",    cap);
        cJSON_AddNumberToObject(s, "booked_count",booked);
        cJSON_AddNumberToObject(s, "available",   cap - booked);
        cJSON_AddItemToArray(arr, s);
    }
    sqlite3_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── Users ───────────────────────────────────────────────────────────────── */

void handle_create_user(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
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

    char email_lower[256];
    strncpy(email_lower, email, sizeof(email_lower) - 1);
    email_lower[sizeof(email_lower)-1] = '\0';
    str_lower(email_lower);

    char hash[128];
    hash_password(password, hash, sizeof(hash));

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "INSERT INTO users(email,name,phone,password_hash) VALUES(?,?,?,?)",
        -1, &st, NULL);
    sqlite3_bind_text(st, 1, email_lower, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, name,        -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, phone,       -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, hash,        -1, SQLITE_STATIC);

    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    cJSON_Delete(body);

    if (rc == SQLITE_CONSTRAINT) {
        send_error_json(c, 409, "このメールアドレスは既に登録されています");
        return;
    }
    if (rc != SQLITE_DONE) {
        send_error_json(c, 500, "database error");
        return;
    }

    long uid = sqlite3_last_insert_rowid(db);
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db,
        "SELECT id,email,name,phone,created_at FROM users WHERE id=?",
        -1, &sel, NULL);
    sqlite3_bind_int64(sel, 1, uid);
    cJSON *u = NULL;
    if (sqlite3_step(sel) == SQLITE_ROW) {
        u = cJSON_CreateObject();
        cJSON_AddNumberToObject(u, "id",    sqlite3_column_int64(sel, 0));
        cJSON_AddStringToObject(u, "email", (const char*)sqlite3_column_text(sel, 1));
        cJSON_AddStringToObject(u, "name",  (const char*)sqlite3_column_text(sel, 2));
        if (sqlite3_column_type(sel, 3) != SQLITE_NULL)
            cJSON_AddStringToObject(u, "phone", (const char*)sqlite3_column_text(sel, 3));
        else cJSON_AddNullToObject(u, "phone");
        cJSON_AddStringToObject(u, "created_at", (const char*)sqlite3_column_text(sel, 4));
    }
    sqlite3_finalize(sel);

    if (u) { send_cjson(c, 201, u); cJSON_Delete(u); }
    else     send_error_json(c, 500, "failed to fetch created user");
}

void handle_login(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
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

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT id,name,password_hash FROM users WHERE email=?",
        -1, &st, NULL);
    sqlite3_bind_text(st, 1, email_lower, -1, SQLITE_STATIC);

    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        cJSON_Delete(body);
        send_error_json(c, 400, "メールアドレスまたはパスワードが違います");
        return;
    }

    long uid        = sqlite3_column_int64(st, 0);
    const char *nm  = (const char*)sqlite3_column_text(st, 1);
    const char *hash= (const char*)sqlite3_column_text(st, 2);
    char name_buf[128] = {0};
    strncpy(name_buf, nm ? nm : "", sizeof(name_buf)-1);
    char hash_buf[128] = {0};
    strncpy(hash_buf, hash ? hash : "", sizeof(hash_buf)-1);
    sqlite3_finalize(st);

    if (!verify_password(password, hash_buf)) {
        cJSON_Delete(body);
        send_error_json(c, 400, "メールアドレスまたはパスワードが違います");
        return;
    }
    cJSON_Delete(body);

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
                                sqlite3 *db, long user_id) {
    /* JWT 必須 + 自分の予約のみ */
    long auth_uid = require_auth(c, hm);
    if (auth_uid < 0) return;
    if (auth_uid != user_id) {
        send_error_json(c, 403, "他のユーザーの予約一覧は取得できません"); return;
    }
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT b.id,b.user_id,b.plan_id,p.title,b.schedule_id,"
        "s.date,s.start_time,b.status,b.total_price,b.note,b.created_at "
        "FROM bookings b "
        "JOIN plans p ON p.id=b.plan_id "
        "JOIN schedules s ON s.id=b.schedule_id "
        "WHERE b.user_id=? ORDER BY b.created_at DESC",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, user_id);

    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *bid = (const char*)sqlite3_column_text(st, 0);
        cJSON *b = cJSON_CreateObject();
        cJSON_AddStringToObject(b, "id",         bid);
        cJSON_AddNumberToObject(b, "user_id",    sqlite3_column_int64(st, 1));
        cJSON_AddNumberToObject(b, "plan_id",    sqlite3_column_int64(st, 2));
        cJSON_AddStringToObject(b, "plan_title", (const char*)sqlite3_column_text(st, 3));
        cJSON_AddNumberToObject(b, "schedule_id",sqlite3_column_int64(st, 4));
        cJSON_AddStringToObject(b, "schedule_date", (const char*)sqlite3_column_text(st, 5));
        cJSON_AddStringToObject(b, "schedule_start_time",(const char*)sqlite3_column_text(st, 6));
        cJSON_AddStringToObject(b, "status",     (const char*)sqlite3_column_text(st, 7));
        cJSON_AddNumberToObject(b, "total_price",sqlite3_column_int64(st, 8));
        if (sqlite3_column_type(st, 9) != SQLITE_NULL)
            cJSON_AddStringToObject(b, "note",   (const char*)sqlite3_column_text(st, 9));
        else cJSON_AddNullToObject(b, "note");
        cJSON_AddStringToObject(b, "created_at",(const char*)sqlite3_column_text(st, 10));
        cJSON_AddItemToObject(b, "participants", fetch_participants(db, bid));
        cJSON_AddItemToArray(arr, b);
    }
    sqlite3_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── Bookings ────────────────────────────────────────────────────────────── */

/* 参加者ごとの価格情報を一時保存するバッファ */
#define MAX_PART_TYPES 8
typedef struct { char pt[32]; char lb[128]; long cnt; long unit_price; } PartEntry;

void handle_create_booking(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    /* JWT 認証 */
    long auth_uid = require_auth(c, hm);
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
    sqlite3_stmt *cap_st;
    sqlite3_prepare_v2(db,
        "SELECT capacity,booked_count FROM schedules WHERE id=? AND plan_id=?",
        -1, &cap_st, NULL);
    sqlite3_bind_int64(cap_st, 1, sched_id);
    sqlite3_bind_int64(cap_st, 2, plan_id);
    if (sqlite3_step(cap_st) != SQLITE_ROW) {
        sqlite3_finalize(cap_st); cJSON_Delete(body);
        send_error_json(c, 404, "schedule not found"); return;
    }
    long cap    = sqlite3_column_int64(cap_st, 0);
    long booked = sqlite3_column_int64(cap_st, 1);
    sqlite3_finalize(cap_st);

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
        sqlite3_stmt *ps;
        sqlite3_prepare_v2(db,
            "SELECT label,price FROM plan_prices WHERE plan_id=? AND participant_type=?",
            -1, &ps, NULL);
        sqlite3_bind_int64(ps, 1, plan_id);
        sqlite3_bind_text(ps, 2, pt, -1, SQLITE_STATIC);
        if (sqlite3_step(ps) != SQLITE_ROW) {
            sqlite3_finalize(ps); cJSON_Delete(body);
            send_error_json(c, 400, "指定された participant_type の価格がありません"); return;
        }
        strncpy(entries[i].pt, pt, sizeof(entries[i].pt)-1);
        entries[i].pt[sizeof(entries[i].pt)-1] = '\0';
        const char *lb = (const char*)sqlite3_column_text(ps, 0);
        strncpy(entries[i].lb, lb ? lb : "", sizeof(entries[i].lb)-1);
        entries[i].lb[sizeof(entries[i].lb)-1] = '\0';
        entries[i].cnt        = cnt;
        entries[i].unit_price = sqlite3_column_int64(ps, 1);
        sqlite3_finalize(ps);

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

    sqlite3_stmt *ins;
    sqlite3_prepare_v2(db,
        "INSERT INTO bookings(id,user_id,plan_id,schedule_id,status,total_price,note)"
        " VALUES(?,?,?,?,?,?,?)",
        -1, &ins, NULL);
    sqlite3_bind_text(ins, 1, booking_id,   -1, SQLITE_STATIC);
    sqlite3_bind_int64(ins, 2, auth_uid);
    sqlite3_bind_int64(ins, 3, plan_id);
    sqlite3_bind_int64(ins, 4, sched_id);
    sqlite3_bind_text(ins, 5, init_status,  -1, SQLITE_STATIC);
    sqlite3_bind_int64(ins, 6, total_price);
    sqlite3_bind_text(ins, 7, note ? note : "", -1, SQLITE_STATIC);
    int rc = sqlite3_step(ins);
    sqlite3_finalize(ins);

    if (rc != SQLITE_DONE) {
        cJSON_Delete(body);
        send_error_json(c, 500, "failed to create booking"); return;
    }

    /* 参加者挿入（確定済み価格を使用） */
    for (int i = 0; i < n; i++) {
        sqlite3_stmt *pi;
        sqlite3_prepare_v2(db,
            "INSERT INTO booking_participants(booking_id,participant_type,label,count,unit_price)"
            " VALUES(?,?,?,?,?)",
            -1, &pi, NULL);
        sqlite3_bind_text(pi, 1, booking_id,       -1, SQLITE_STATIC);
        sqlite3_bind_text(pi, 2, entries[i].pt,    -1, SQLITE_STATIC);
        sqlite3_bind_text(pi, 3, entries[i].lb,    -1, SQLITE_STATIC);
        sqlite3_bind_int64(pi, 4, entries[i].cnt);
        sqlite3_bind_int64(pi, 5, entries[i].unit_price);
        sqlite3_step(pi);
        sqlite3_finalize(pi);
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
            sqlite3_stmt *upd;
            sqlite3_prepare_v2(db,
                "UPDATE bookings SET stripe_payment_intent_id=? WHERE id=?",
                -1, &upd, NULL);
            sqlite3_bind_text(upd, 1, pi_id,      -1, SQLITE_STATIC);
            sqlite3_bind_text(upd, 2, booking_id, -1, SQLITE_STATIC);
            sqlite3_step(upd);
            sqlite3_finalize(upd);
            stripe_ok = 1;
        } else {
            /* Stripe 呼び出し失敗 → booking を削除してエラーを返す */
            sqlite3_stmt *del;
            sqlite3_prepare_v2(db,
                "DELETE FROM bookings WHERE id=?", -1, &del, NULL);
            sqlite3_bind_text(del, 1, booking_id, -1, SQLITE_STATIC);
            sqlite3_step(del);
            sqlite3_finalize(del);
            send_error_json(c, 502, "Stripe への接続に失敗しました");
            return;
        }
    }

    /* 返却 */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db,
        "SELECT b.id,b.user_id,b.plan_id,p.title,b.schedule_id,"
        "s.date,s.start_time,b.status,b.total_price,b.note,b.created_at "
        "FROM bookings b JOIN plans p ON p.id=b.plan_id "
        "JOIN schedules s ON s.id=b.schedule_id WHERE b.id=?",
        -1, &sel, NULL);
    sqlite3_bind_text(sel, 1, booking_id, -1, SQLITE_STATIC);
    cJSON *bk = NULL;
    if (sqlite3_step(sel) == SQLITE_ROW) {
        const char *bid = (const char*)sqlite3_column_text(sel, 0);
        bk = cJSON_CreateObject();
        cJSON_AddStringToObject(bk, "id", bid);
        cJSON_AddNumberToObject(bk, "user_id",    sqlite3_column_int64(sel, 1));
        cJSON_AddNumberToObject(bk, "plan_id",    sqlite3_column_int64(sel, 2));
        cJSON_AddStringToObject(bk, "plan_title", (const char*)sqlite3_column_text(sel, 3));
        cJSON_AddNumberToObject(bk, "schedule_id",sqlite3_column_int64(sel, 4));
        cJSON_AddStringToObject(bk, "schedule_date",       (const char*)sqlite3_column_text(sel, 5));
        cJSON_AddStringToObject(bk, "schedule_start_time", (const char*)sqlite3_column_text(sel, 6));
        cJSON_AddStringToObject(bk, "status",     (const char*)sqlite3_column_text(sel, 7));
        cJSON_AddNumberToObject(bk, "total_price",sqlite3_column_int64(sel, 8));
        if (sqlite3_column_type(sel, 9) != SQLITE_NULL)
            cJSON_AddStringToObject(bk, "note",   (const char*)sqlite3_column_text(sel, 9));
        else cJSON_AddNullToObject(bk, "note");
        cJSON_AddStringToObject(bk, "created_at",(const char*)sqlite3_column_text(sel, 10));
        cJSON_AddItemToObject(bk, "participants", fetch_participants(db, bid));
        /* Stripe client_secret をレスポンスに含める */
        if (stripe_ok && client_secret[0]) {
            cJSON_AddStringToObject(bk, "client_secret",        client_secret);
            cJSON_AddStringToObject(bk, "stripe_payment_intent_id", pi_id);
        }
    }
    sqlite3_finalize(sel);

    if (bk) { send_cjson(c, 201, bk); cJSON_Delete(bk); }
    else      send_error_json(c, 500, "failed to fetch booking");
}

void handle_get_booking(struct mg_connection *c, struct mg_http_message *hm,
                        sqlite3 *db, const char *id) {
    /* JWT 必須 + 予約のオーナーのみ */
    long auth_uid = require_auth(c, hm);
    if (auth_uid < 0) return;
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT b.id,b.user_id,b.plan_id,p.title,b.schedule_id,"
        "s.date,s.start_time,b.status,b.total_price,b.note,b.created_at "
        "FROM bookings b JOIN plans p ON p.id=b.plan_id "
        "JOIN schedules s ON s.id=b.schedule_id WHERE b.id=?",
        -1, &st, NULL);
    sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);

    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        send_error_json(c, 404, "booking not found"); return;
    }
    long owner_id = sqlite3_column_int64(st, 1);
    if (owner_id != auth_uid) {
        sqlite3_finalize(st);
        send_error_json(c, 403, "この予約にアクセスする権限がありません"); return;
    }
    const char *bid = (const char*)sqlite3_column_text(st, 0);
    cJSON *bk = cJSON_CreateObject();
    cJSON_AddStringToObject(bk, "id", bid);
    cJSON_AddNumberToObject(bk, "user_id",    owner_id);
    cJSON_AddNumberToObject(bk, "plan_id",    sqlite3_column_int64(st, 2));
    cJSON_AddStringToObject(bk, "plan_title", (const char*)sqlite3_column_text(st, 3));
    cJSON_AddNumberToObject(bk, "schedule_id",sqlite3_column_int64(st, 4));
    cJSON_AddStringToObject(bk, "schedule_date",       (const char*)sqlite3_column_text(st, 5));
    cJSON_AddStringToObject(bk, "schedule_start_time", (const char*)sqlite3_column_text(st, 6));
    cJSON_AddStringToObject(bk, "status",     (const char*)sqlite3_column_text(st, 7));
    cJSON_AddNumberToObject(bk, "total_price",sqlite3_column_int64(st, 8));
    if (sqlite3_column_type(st, 9) != SQLITE_NULL)
        cJSON_AddStringToObject(bk, "note",   (const char*)sqlite3_column_text(st, 9));
    else cJSON_AddNullToObject(bk, "note");
    cJSON_AddStringToObject(bk, "created_at",(const char*)sqlite3_column_text(st, 10));
    cJSON_AddItemToObject(bk, "participants", fetch_participants(db, bid));
    sqlite3_finalize(st);
    send_cjson(c, 200, bk);
    cJSON_Delete(bk);
}

/* ─── Reviews ─────────────────────────────────────────────────────────────── */

void handle_create_review(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    /* JWT 認証 — user_id はトークンから取得（ボディの値は無視） */
    long auth_uid = require_auth(c, hm);
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
        sqlite3_stmt *bchk;
        sqlite3_prepare_v2(db,
            "SELECT id FROM bookings WHERE id=? AND user_id=? AND plan_id=?",
            -1, &bchk, NULL);
        sqlite3_bind_text(bchk, 1, booking_id, -1, SQLITE_STATIC);
        sqlite3_bind_int64(bchk, 2, auth_uid);
        sqlite3_bind_int64(bchk, 3, plan_id);
        int found = (sqlite3_step(bchk) == SQLITE_ROW);
        sqlite3_finalize(bchk);
        if (!found) {
            send_error_json(c, 403, "指定された予約はこのプランの予約ではありません");
            cJSON_Delete(body); return;
        }
    } else {
        /* booking_id なしの場合: confirmed/cancelled 予約が少なくとも1件あるか */
        sqlite3_stmt *bchk;
        sqlite3_prepare_v2(db,
            "SELECT id FROM bookings WHERE user_id=? AND plan_id=? AND status IN ('confirmed','cancelled') LIMIT 1",
            -1, &bchk, NULL);
        sqlite3_bind_int64(bchk, 1, auth_uid);
        sqlite3_bind_int64(bchk, 2, plan_id);
        int found = (sqlite3_step(bchk) == SQLITE_ROW);
        sqlite3_finalize(bchk);
        if (!found) {
            send_error_json(c, 403, "このプランを予約したユーザーのみレビューを投稿できます");
            cJSON_Delete(body); return;
        }
    }

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "INSERT INTO reviews(booking_id,user_id,plan_id,rating,comment) VALUES(?,?,?,?,?)",
        -1, &st, NULL);
    sqlite3_bind_text(st, 1, booking_id ? booking_id : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, user_id);
    sqlite3_bind_int64(st, 3, plan_id);
    sqlite3_bind_int64(st, 4, rating);
    sqlite3_bind_text(st, 5, comment ? comment : NULL, -1, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);
    cJSON_Delete(body);

    long rid = sqlite3_last_insert_rowid(db);
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db,
        "SELECT r.id,r.user_id,u.name,r.plan_id,r.rating,r.comment,r.created_at "
        "FROM reviews r LEFT JOIN users u ON u.id=r.user_id WHERE r.id=?",
        -1, &sel, NULL);
    sqlite3_bind_int64(sel, 1, rid);
    if (sqlite3_step(sel) == SQLITE_ROW) {
        cJSON *rv = cJSON_CreateObject();
        cJSON_AddNumberToObject(rv, "id",      sqlite3_column_int64(sel, 0));
        cJSON_AddNumberToObject(rv, "user_id", sqlite3_column_int64(sel, 1));
        if (sqlite3_column_type(sel, 2) != SQLITE_NULL)
            cJSON_AddStringToObject(rv, "user_name", (const char*)sqlite3_column_text(sel, 2));
        else cJSON_AddNullToObject(rv, "user_name");
        cJSON_AddNumberToObject(rv, "plan_id", sqlite3_column_int64(sel, 3));
        cJSON_AddNumberToObject(rv, "rating",  sqlite3_column_int64(sel, 4));
        if (sqlite3_column_type(sel, 5) != SQLITE_NULL)
            cJSON_AddStringToObject(rv, "comment", (const char*)sqlite3_column_text(sel, 5));
        else cJSON_AddNullToObject(rv, "comment");
        cJSON_AddStringToObject(rv, "created_at", (const char*)sqlite3_column_text(sel, 6));
        sqlite3_finalize(sel);
        send_cjson(c, 201, rv);
        cJSON_Delete(rv);
    } else {
        sqlite3_finalize(sel);
        send_error_json(c, 500, "failed to fetch review");
    }
}

/* ─── Search ──────────────────────────────────────────────────────────────── */

void handle_search(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
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

    char q_esc[512] = {0};
    if (has_q && q_raw[0]) escape_like(q_raw, q_esc, sizeof(q_esc));
    char kw[520] = {0};
    if (has_q && q_esc[0]) snprintf(kw, sizeof(kw), "%%%s%%", q_esc);

    const char *cnt_sql =
        "SELECT COUNT(DISTINCT p.id) FROM plans p "
        "JOIN venues v ON v.id=p.venue_id "
        "WHERE p.is_active=1 "
        "AND (? = 0 OR p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\' OR v.name LIKE ? ESCAPE '\\') "
        "AND (? = 0 OR p.category_id=?) "
        "AND (? = 0 OR v.area_id=?) "
        "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
        "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?))";

    char qsql[1024];
    snprintf(qsql, sizeof(qsql),
        "%s WHERE p.is_active=1 "
        "AND (? = 0 OR p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\' OR v.name LIKE ? ESCAPE '\\') "
        "AND (? = 0 OR p.category_id=?) "
        "AND (? = 0 OR v.area_id=?) "
        "AND (? = 0 OR EXISTS (SELECT 1 FROM schedules s "
        "  WHERE s.plan_id=p.id AND s.date=? AND (s.capacity-s.booked_count)>=?)) "
        "ORDER BY p.id LIMIT ? OFFSET ?", PLAN_SELECT);

    int kw_flag = (has_q && kw[0]) ? 1 : 0;

    sqlite3_stmt *ct;
    sqlite3_prepare_v2(db, cnt_sql, -1, &ct, NULL);
    sqlite3_bind_int64(ct, 1, kw_flag);
    sqlite3_bind_text(ct, 2, kw, -1, SQLITE_STATIC);
    sqlite3_bind_text(ct, 3, kw, -1, SQLITE_STATIC);
    sqlite3_bind_text(ct, 4, kw, -1, SQLITE_STATIC);
    sqlite3_bind_int64(ct, 5, cat_id); sqlite3_bind_int64(ct, 6, cat_id);
    sqlite3_bind_int64(ct, 7, area_id); sqlite3_bind_int64(ct, 8, area_id);
    sqlite3_bind_int64(ct, 9, has_date ? 1 : 0);
    sqlite3_bind_text(ct, 10, date, -1, SQLITE_STATIC);
    sqlite3_bind_int64(ct, 11, adults);
    sqlite3_step(ct);
    long total = sqlite3_column_int64(ct, 0);
    sqlite3_finalize(ct);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, qsql, -1, &st, NULL);
    sqlite3_bind_int64(st, 1, kw_flag);
    sqlite3_bind_text(st, 2, kw, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, kw, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, kw, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, cat_id); sqlite3_bind_int64(st, 6, cat_id);
    sqlite3_bind_int64(st, 7, area_id); sqlite3_bind_int64(st, 8, area_id);
    sqlite3_bind_int64(st, 9, has_date ? 1 : 0);
    sqlite3_bind_text(st, 10, date, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 11, adults);
    sqlite3_bind_int64(st, 12, limit); sqlite3_bind_int64(st, 13, offset);

    cJSON *plans = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        long pid = sqlite3_column_int64(st, 0);
        cJSON *p = plan_row(st);
        cJSON_AddItemToObject(p, "prices", fetch_prices(db, pid));
        cJSON_AddItemToArray(plans, p);
    }
    sqlite3_finalize(st);

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
                            sqlite3 *db, const char *id) {
    long auth_uid = require_auth(c, hm);
    if (auth_uid < 0) return;

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT user_id, status, schedule_id FROM bookings WHERE id=?",
        -1, &st, NULL);
    sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        send_error_json(c, 404, "booking not found"); return;
    }
    long owner_id = sqlite3_column_int64(st, 0);
    char status_buf[32] = {0};
    const char *sv = (const char*)sqlite3_column_text(st, 1);
    strncpy(status_buf, sv ? sv : "", sizeof(status_buf)-1);
    long sched_id = sqlite3_column_int64(st, 2);
    sqlite3_finalize(st);

    if (owner_id != auth_uid) {
        send_error_json(c, 403, "この予約をキャンセルする権限がありません"); return;
    }
    if (strcmp(status_buf, "cancelled") == 0) {
        send_error_json(c, 400, "既にキャンセル済みです"); return;
    }

    /* 参加者合計 → booked_count を戻す */
    sqlite3_stmt *pst;
    sqlite3_prepare_v2(db,
        "SELECT COALESCE(SUM(count),0) FROM booking_participants WHERE booking_id=?",
        -1, &pst, NULL);
    sqlite3_bind_text(pst, 1, id, -1, SQLITE_STATIC);
    sqlite3_step(pst);
    long total_people = sqlite3_column_int64(pst, 0);
    sqlite3_finalize(pst);

    sqlite3_stmt *upd;
    sqlite3_prepare_v2(db, "UPDATE bookings SET status='cancelled' WHERE id=?", -1, &upd, NULL);
    sqlite3_bind_text(upd, 1, id, -1, SQLITE_STATIC);
    sqlite3_step(upd); sqlite3_finalize(upd);

    sqlite3_stmt *dec;
    sqlite3_prepare_v2(db,
        "UPDATE schedules SET booked_count = MAX(0, booked_count - ?) WHERE id=?",
        -1, &dec, NULL);
    sqlite3_bind_int64(dec, 1, total_people);
    sqlite3_bind_int64(dec, 2, sched_id);
    sqlite3_step(dec); sqlite3_finalize(dec);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"予約をキャンセルしました\"}");
}

/* ─── GET /api/v1/plans/:id/reviews ────────────────────────────────────────── */

void handle_list_plan_reviews(struct mg_connection *c, struct mg_http_message *hm,
                               sqlite3 *db, long plan_id) {
    long page  = query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit = query_long(hm, "limit", 20); if (limit > 100) limit = 100;
    long offset = (page - 1) * limit;

    /* 総件数 */
    sqlite3_stmt *ct;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM reviews WHERE plan_id=?", -1, &ct, NULL);
    sqlite3_bind_int64(ct, 1, plan_id);
    sqlite3_step(ct);
    long total = sqlite3_column_int64(ct, 0);
    sqlite3_finalize(ct);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT r.id, r.user_id, u.name, r.rating, r.comment, r.created_at "
        "FROM reviews r "
        "LEFT JOIN users u ON u.id = r.user_id "
        "WHERE r.plan_id = ? "
        "ORDER BY r.created_at DESC LIMIT ? OFFSET ?",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, plan_id);
    sqlite3_bind_int64(st, 2, limit);
    sqlite3_bind_int64(st, 3, offset);

    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *rv = cJSON_CreateObject();
        cJSON_AddNumberToObject(rv, "id",      sqlite3_column_int64(st, 0));
        cJSON_AddNumberToObject(rv, "user_id", sqlite3_column_int64(st, 1));
        if (sqlite3_column_type(st, 2) != SQLITE_NULL)
            cJSON_AddStringToObject(rv, "user_name", (const char*)sqlite3_column_text(st, 2));
        else cJSON_AddNullToObject(rv, "user_name");
        cJSON_AddNumberToObject(rv, "rating",  sqlite3_column_int64(st, 3));
        if (sqlite3_column_type(st, 4) != SQLITE_NULL)
            cJSON_AddStringToObject(rv, "comment", (const char*)sqlite3_column_text(st, 4));
        else cJSON_AddNullToObject(rv, "comment");
        cJSON_AddStringToObject(rv, "created_at", (const char*)sqlite3_column_text(st, 5));
        cJSON_AddItemToArray(arr, rv);
    }
    sqlite3_finalize(st);

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
                              sqlite3 *db, long venue_id) {
    (void)hm;
    char qsql[512];
    snprintf(qsql, sizeof(qsql),
        "%s WHERE p.venue_id=? AND p.is_active=1 ORDER BY p.id", PLAN_SELECT);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, qsql, -1, &st, NULL);
    sqlite3_bind_int64(st, 1, venue_id);

    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        long pid = sqlite3_column_int64(st, 0);
        cJSON *p = plan_row(st);
        cJSON_AddItemToObject(p, "prices", fetch_prices(db, pid));
        cJSON_AddItemToArray(arr, p);
    }
    sqlite3_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── GET /api/v1/users/:id ────────────────────────────────────────────────── */

void handle_get_user(struct mg_connection *c, struct mg_http_message *hm,
                     sqlite3 *db, long id) {
    (void)hm;
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT id,email,name,phone,created_at FROM users WHERE id=?",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, id);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        send_error_json(c, 404, "user not found"); return;
    }
    cJSON *u = cJSON_CreateObject();
    cJSON_AddNumberToObject(u, "id",     sqlite3_column_int64(st, 0));
    cJSON_AddStringToObject(u, "email",  (const char*)sqlite3_column_text(st, 1));
    cJSON_AddStringToObject(u, "name",   (const char*)sqlite3_column_text(st, 2));
    if (sqlite3_column_type(st, 3) != SQLITE_NULL)
        cJSON_AddStringToObject(u, "phone", (const char*)sqlite3_column_text(st, 3));
    else cJSON_AddNullToObject(u, "phone");
    cJSON_AddStringToObject(u, "created_at", (const char*)sqlite3_column_text(st, 4));
    sqlite3_finalize(st);
    send_cjson(c, 200, u);
    cJSON_Delete(u);
}

/* ─── PATCH /api/v1/users/:id ──────────────────────────────────────────────── */

void handle_update_user(struct mg_connection *c, struct mg_http_message *hm,
                        sqlite3 *db, long id) {
    long auth_uid = require_auth(c, hm);
    if (auth_uid < 0) return;
    if (auth_uid != id) {
        send_error_json(c, 403, "他のユーザーの情報は変更できません"); return;
    }

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    cJSON *it;
    it = cJSON_GetObjectItem(body, "name");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u;
        sqlite3_prepare_v2(db, "UPDATE users SET name=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id);
        sqlite3_step(u); sqlite3_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "phone");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u;
        sqlite3_prepare_v2(db, "UPDATE users SET phone=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id);
        sqlite3_step(u); sqlite3_finalize(u);
    }
    cJSON_Delete(body);

    /* 更新後のユーザーを返す */
    sqlite3_stmt *sel;
    sqlite3_prepare_v2(db,
        "SELECT id,email,name,phone,created_at FROM users WHERE id=?",
        -1, &sel, NULL);
    sqlite3_bind_int64(sel, 1, id);
    if (sqlite3_step(sel) != SQLITE_ROW) {
        sqlite3_finalize(sel);
        send_error_json(c, 404, "user not found"); return;
    }
    cJSON *u = cJSON_CreateObject();
    cJSON_AddNumberToObject(u, "id",     sqlite3_column_int64(sel, 0));
    cJSON_AddStringToObject(u, "email",  (const char*)sqlite3_column_text(sel, 1));
    cJSON_AddStringToObject(u, "name",   (const char*)sqlite3_column_text(sel, 2));
    if (sqlite3_column_type(sel, 3) != SQLITE_NULL)
        cJSON_AddStringToObject(u, "phone", (const char*)sqlite3_column_text(sel, 3));
    else cJSON_AddNullToObject(u, "phone");
    cJSON_AddStringToObject(u, "created_at", (const char*)sqlite3_column_text(sel, 4));
    sqlite3_finalize(sel);
    send_cjson(c, 200, u);
    cJSON_Delete(u);
}

/* ─── POST /api/v1/webhooks/stripe ─────────────────────────────────────────── */

void handle_stripe_webhook(struct mg_connection *c, struct mg_http_message *hm,
                            sqlite3 *db) {
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

    if (strcmp(evt_type, "payment_intent.succeeded") == 0) {
        /* data.object.metadata.booking_id を取得 */
        cJSON *data   = cJSON_GetObjectItem(event, "data");
        cJSON *object = data ? cJSON_GetObjectItem(data, "object") : NULL;
        cJSON *meta   = object ? cJSON_GetObjectItem(object, "metadata") : NULL;
        const char *booking_id = meta
            ? cJSON_GetStringValue(cJSON_GetObjectItem(meta, "booking_id"))
            : NULL;

        if (booking_id && *booking_id) {
            sqlite3_stmt *upd;
            sqlite3_prepare_v2(db,
                "UPDATE bookings SET status='confirmed' WHERE id=? AND status='pending_payment'",
                -1, &upd, NULL);
            sqlite3_bind_text(upd, 1, booking_id, -1, SQLITE_STATIC);
            sqlite3_step(upd);
            sqlite3_finalize(upd);
            fprintf(stdout, "[stripe] booking %s confirmed via webhook\n", booking_id);
        }

    } else if (strcmp(evt_type, "payment_intent.payment_failed") == 0) {
        cJSON *data   = cJSON_GetObjectItem(event, "data");
        cJSON *object = data ? cJSON_GetObjectItem(data, "object") : NULL;
        cJSON *meta   = object ? cJSON_GetObjectItem(object, "metadata") : NULL;
        const char *booking_id = meta
            ? cJSON_GetStringValue(cJSON_GetObjectItem(meta, "booking_id"))
            : NULL;

        if (booking_id && *booking_id) {
            sqlite3_stmt *upd;
            sqlite3_prepare_v2(db,
                "UPDATE bookings SET status='cancelled' WHERE id=? AND status='pending_payment'",
                -1, &upd, NULL);
            sqlite3_bind_text(upd, 1, booking_id, -1, SQLITE_STATIC);
            sqlite3_step(upd);
            sqlite3_finalize(upd);
            fprintf(stdout, "[stripe] booking %s cancelled (payment failed)\n", booking_id);
        }
    }

    cJSON_Delete(event);
    /* Stripe は 2xx を受け取れればよい */
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "{\"received\":true}");
}

/* ─── POST /api/v1/bookmarks ────────────────────────────────────────────────── */

void handle_create_bookmark(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    long auth_uid = require_auth(c, hm);
    if (auth_uid < 0) return;

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    long plan_id = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "plan_id"));
    cJSON_Delete(body);

    if (plan_id <= 0) {
        send_error_json(c, 400, "plan_id は必須です"); return;
    }

    /* プランの存在確認 */
    sqlite3_stmt *chk;
    sqlite3_prepare_v2(db, "SELECT id FROM plans WHERE id=? AND is_active=1", -1, &chk, NULL);
    sqlite3_bind_int64(chk, 1, plan_id);
    if (sqlite3_step(chk) != SQLITE_ROW) {
        sqlite3_finalize(chk);
        send_error_json(c, 404, "plan not found"); return;
    }
    sqlite3_finalize(chk);

    sqlite3_stmt *ins;
    sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO bookmarks(user_id,plan_id) VALUES(?,?)",
        -1, &ins, NULL);
    sqlite3_bind_int64(ins, 1, auth_uid);
    sqlite3_bind_int64(ins, 2, plan_id);
    sqlite3_step(ins);
    sqlite3_finalize(ins);

    long bm_id = (long)sqlite3_last_insert_rowid(db);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id",      bm_id);
    cJSON_AddNumberToObject(res, "user_id", auth_uid);
    cJSON_AddNumberToObject(res, "plan_id", plan_id);
    send_cjson(c, 201, res);
    cJSON_Delete(res);
}

/* ─── DELETE /api/v1/bookmarks/:plan_id ────────────────────────────────────── */

void handle_delete_bookmark(struct mg_connection *c, struct mg_http_message *hm,
                             sqlite3 *db, long plan_id) {
    long auth_uid = require_auth(c, hm);
    if (auth_uid < 0) return;

    sqlite3_stmt *del;
    sqlite3_prepare_v2(db,
        "DELETE FROM bookmarks WHERE user_id=? AND plan_id=?",
        -1, &del, NULL);
    sqlite3_bind_int64(del, 1, auth_uid);
    sqlite3_bind_int64(del, 2, plan_id);
    sqlite3_step(del);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(del);

    if (changes == 0) {
        send_error_json(c, 404, "bookmark not found"); return;
    }
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"ブックマークを削除しました\"}");
}

/* ─── GET /api/v1/users/:id/bookmarks ──────────────────────────────────────── */

void handle_list_user_bookmarks(struct mg_connection *c, struct mg_http_message *hm,
                                 sqlite3 *db, long user_id) {
    /* JWT 必須 + 自分のブックマークのみ */
    long auth_uid = require_auth(c, hm);
    if (auth_uid < 0) return;
    if (auth_uid != user_id) {
        send_error_json(c, 403, "他のユーザーのブックマークは取得できません"); return;
    }
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT bm.id, bm.plan_id, p.title, p.duration_minutes, v.name AS venue_name, "
        "bm.created_at "
        "FROM bookmarks bm "
        "JOIN plans p ON p.id = bm.plan_id "
        "JOIN venues v ON v.id = p.venue_id "
        "WHERE bm.user_id = ? "
        "ORDER BY bm.created_at DESC",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, user_id);

    cJSON *arr = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *bm = cJSON_CreateObject();
        cJSON_AddNumberToObject(bm, "id",               sqlite3_column_int64(st, 0));
        cJSON_AddNumberToObject(bm, "plan_id",          sqlite3_column_int64(st, 1));
        cJSON_AddStringToObject(bm, "plan_title",       (const char*)sqlite3_column_text(st, 2));
        if (sqlite3_column_type(st, 3) != SQLITE_NULL)
            cJSON_AddNumberToObject(bm, "duration_minutes", sqlite3_column_int64(st, 3));
        else cJSON_AddNullToObject(bm, "duration_minutes");
        cJSON_AddStringToObject(bm, "venue_name",       (const char*)sqlite3_column_text(st, 4));
        cJSON_AddStringToObject(bm, "created_at",       (const char*)sqlite3_column_text(st, 5));
        cJSON_AddItemToArray(arr, bm);
    }
    sqlite3_finalize(st);
    send_cjson(c, 200, arr);
    cJSON_Delete(arr);
}

/* ─── PATCH /api/v1/auth/change-password ───────────────────────────────────── */

void handle_change_password(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    long auth_uid = require_auth(c, hm);
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

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT password_hash FROM users WHERE id=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, auth_uid);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st); cJSON_Delete(body);
        send_error_json(c, 404, "user not found"); return;
    }
    char hash_buf[128] = {0};
    const char *h = (const char*)sqlite3_column_text(st, 0);
    if (h) strncpy(hash_buf, h, sizeof(hash_buf)-1);
    sqlite3_finalize(st);

    if (!verify_password(cur_pw, hash_buf)) {
        cJSON_Delete(body);
        send_error_json(c, 400, "現在のパスワードが正しくありません"); return;
    }

    char new_hash[128];
    hash_password(new_pw, new_hash, sizeof(new_hash));
    cJSON_Delete(body);

    sqlite3_stmt *upd;
    sqlite3_prepare_v2(db, "UPDATE users SET password_hash=? WHERE id=?", -1, &upd, NULL);
    sqlite3_bind_text(upd, 1, new_hash, -1, SQLITE_STATIC);
    sqlite3_bind_int64(upd, 2, auth_uid);
    sqlite3_step(upd); sqlite3_finalize(upd);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"パスワードを変更しました\"}");
}

/* ─── POST /api/v1/auth/forgot-password ────────────────────────────────────── */

void handle_forgot_password(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
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
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT id FROM users WHERE email=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, email_lower, -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        send_json_str(c, 200, CORS_HEADERS,
            "{\"message\":\"登録済みの場合はリセット手順をメールで送信しました\"}");
        return;
    }
    long uid = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);

    /* 32 文字ランダムトークン（UUID のダッシュ除去） */
    char uuid_str[37];
    generate_uuid(uuid_str);
    char token[33] = {0};
    int j = 0;
    for (int i = 0; uuid_str[i] && j < 32; i++)
        if (uuid_str[i] != '-') token[j++] = uuid_str[i];

    /* 既存トークンを削除して新規挿入（1時間有効） */
    sqlite3_stmt *del;
    sqlite3_prepare_v2(db, "DELETE FROM password_reset_tokens WHERE user_id=?", -1, &del, NULL);
    sqlite3_bind_int64(del, 1, uid);
    sqlite3_step(del); sqlite3_finalize(del);

    sqlite3_stmt *ins;
    sqlite3_prepare_v2(db,
        "INSERT INTO password_reset_tokens(token,user_id,expires_at)"
        " VALUES(?,?,datetime('now','+1 hour'))",
        -1, &ins, NULL);
    sqlite3_bind_text(ins, 1, token, -1, SQLITE_STATIC);
    sqlite3_bind_int64(ins, 2, uid);
    sqlite3_step(ins); sqlite3_finalize(ins);

    /* 本番はメール送信。開発環境ではレスポンスにトークンを含める */
    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "登録済みの場合はリセット手順をメールで送信しました");
    cJSON_AddStringToObject(res, "reset_token", token); /* 開発用 */
    send_cjson(c, 200, res);
    cJSON_Delete(res);
}

/* ─── POST /api/v1/auth/reset-password ─────────────────────────────────────── */

void handle_reset_password(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
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

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT user_id FROM password_reset_tokens"
        " WHERE token=? AND used=0 AND expires_at > datetime('now')",
        -1, &st, NULL);
    sqlite3_bind_text(st, 1, token, -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st); cJSON_Delete(body);
        send_error_json(c, 400, "トークンが無効または期限切れです"); return;
    }
    long uid = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);

    char new_hash[128];
    hash_password(new_pw, new_hash, sizeof(new_hash));
    cJSON_Delete(body);  /* これ以降 token_raw/new_pw は使えない。token/new_hash を使う */

    sqlite3_stmt *upd;
    sqlite3_prepare_v2(db, "UPDATE users SET password_hash=? WHERE id=?", -1, &upd, NULL);
    sqlite3_bind_text(upd, 1, new_hash, -1, SQLITE_STATIC);
    sqlite3_bind_int64(upd, 2, uid);
    sqlite3_step(upd); sqlite3_finalize(upd);

    sqlite3_stmt *mark;
    sqlite3_prepare_v2(db, "UPDATE password_reset_tokens SET used=1 WHERE token=?",
                        -1, &mark, NULL);
    sqlite3_bind_text(mark, 1, token, -1, SQLITE_STATIC);
    sqlite3_step(mark); sqlite3_finalize(mark);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"パスワードをリセットしました\"}");
}
