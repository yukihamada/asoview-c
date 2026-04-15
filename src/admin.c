#include "admin.h"
#include "handlers.h"   /* send_json_str, send_error_json */
#include "audit.h"
#include "cJSON.h"
#include "stripe.h"
#include "mailer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* JSON の数値フィールドを安全に long に変換（NaN/inf → 0） */
static long cjson_long(cJSON *item) {
    if (!item || !cJSON_IsNumber(item)) return 0;
    double v = cJSON_GetNumberValue(item);
    if (v != v || v > 2147483647.0 || v < -2147483648.0) return 0; /* NaN or out of int range */
    return (long)v;
}

#define CORS_HEADERS "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n"

/* ─── Admin 認証 ──────────────────────────────────────────────────────────── */

/* 定数時間文字列比較（タイミング攻撃対策） */
static int const_time_strcmp(const char *a, size_t a_len,
                              const char *b, size_t b_len) {
    /* 長さが違えば必ず不一致。長さ差もタイミングから漏らさないよう最大長まで走査する */
    unsigned char diff = (unsigned char)(a_len != b_len);
    size_t n = a_len > b_len ? a_len : b_len;
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = i < a_len ? (unsigned char)a[i] : 0;
        unsigned char cb = i < b_len ? (unsigned char)b[i] : 0;
        diff |= ca ^ cb;
    }
    return diff == 0 ? 1 : 0;
}

static int require_admin(struct mg_connection *c, struct mg_http_message *hm) {
    struct mg_str *hdr = mg_http_get_header(hm, "X-Admin-Key");
    if (!hdr) { send_error_json(c, 403, "管理者キーが必要です"); return 0; }
    const char *expected = getenv("ADMIN_KEY");
    if (!expected || !*expected) expected = "asoview-admin-dev";
    /* 定数時間比較でタイミング攻撃を防ぐ */
    if (!const_time_strcmp(hdr->buf, hdr->len, expected, strlen(expected))) {
        send_error_json(c, 403, "管理者キーが不正です"); return 0;
    }
    return 1;
}

static void send_cjson_admin(struct mg_connection *c, int status, cJSON *obj) {
    char *s = cJSON_PrintUnformatted(obj);
    send_json_str(c, status, CORS_HEADERS, s);
    cJSON_free(s);
}

/* ─── Helpers ─────────────────────────────────────────────────────────────── */

static long admin_query_long(struct mg_http_message *hm, const char *k, long def) {
    char buf[32] = {0};
    return mg_http_get_var(&hm->query, k, buf, sizeof(buf)) > 0
           ? strtol(buf, NULL, 10) : def;
}

/* ─── Venues ──────────────────────────────────────────────────────────────── */

void handle_admin_list_venues(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    long page  = admin_query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit = admin_query_long(hm, "limit", 50); if (limit > 200) limit = 200;
    long offset = (page - 1) * limit;

    DbStmt *ct = NULL;
    ct = db_prepare(db, "SELECT COUNT(*) FROM venues");
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT v.id,v.name,v.description,v.area_id,a.name,"
        "v.address,v.phone,v.website,v.review_count,v.review_avg,v.created_at "
        "FROM venues v LEFT JOIN areas a ON a.id=v.area_id "
        "ORDER BY v.id LIMIT ? OFFSET ?");
    db_bind_int(st, 1, limit);
    db_bind_int(st, 2, offset);

    cJSON *venues = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *v = cJSON_CreateObject();
        cJSON_AddNumberToObject(v, "id",           db_col_int(st, 0));
        cJSON_AddStringToObject(v, "name",         db_col_text(st, 1));
        if (!db_col_is_null(st, 2))
            cJSON_AddStringToObject(v, "description", db_col_text(st, 2));
        else cJSON_AddNullToObject(v, "description");
        cJSON_AddNumberToObject(v, "area_id",      db_col_int(st, 3));
        if (!db_col_is_null(st, 4))
            cJSON_AddStringToObject(v, "area_name", db_col_text(st, 4));
        else cJSON_AddNullToObject(v, "area_name");
        if (!db_col_is_null(st, 5))
            cJSON_AddStringToObject(v, "address",  db_col_text(st, 5));
        else cJSON_AddNullToObject(v, "address");
        if (!db_col_is_null(st, 6))
            cJSON_AddStringToObject(v, "phone",    db_col_text(st, 6));
        else cJSON_AddNullToObject(v, "phone");
        if (!db_col_is_null(st, 7))
            cJSON_AddStringToObject(v, "website",  db_col_text(st, 7));
        else cJSON_AddNullToObject(v, "website");
        cJSON_AddNumberToObject(v, "review_count", db_col_int(st, 8));
        cJSON_AddNumberToObject(v, "review_avg",   db_col_double(st, 9));
        cJSON_AddStringToObject(v, "created_at",   db_col_text(st, 10));
        cJSON_AddItemToArray(venues, v);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "venues", venues);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_create_venue(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *name    = cJSON_GetStringValue(cJSON_GetObjectItem(body, "name"));
    const char *desc    = cJSON_GetStringValue(cJSON_GetObjectItem(body, "description"));
    long area_id        = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "area_id"));
    const char *address = cJSON_GetStringValue(cJSON_GetObjectItem(body, "address"));
    double lat  = cJSON_GetNumberValue(cJSON_GetObjectItem(body, "latitude"));
    double lon  = cJSON_GetNumberValue(cJSON_GetObjectItem(body, "longitude"));
    const char *phone   = cJSON_GetStringValue(cJSON_GetObjectItem(body, "phone"));
    cJSON *imgs = cJSON_GetObjectItem(body, "images");
    char *imgs_str = imgs ? cJSON_PrintUnformatted(imgs) : NULL;

    if (!name || !*name || area_id <= 0) {
        cJSON_Delete(body); if (imgs_str) cJSON_free(imgs_str);
        send_error_json(c, 400, "name と area_id は必須です");
        return;
    }

    DbStmt *st = NULL;
    st = db_prepare(db,
        "INSERT INTO venues(name,description,area_id,address,latitude,longitude,phone,images)"
        " VALUES(?,?,?,?,?,?,?,?)");
    db_bind_text(st, 1, name);
    db_bind_text(st, 2, desc ? desc : "");
    db_bind_int(st, 3, area_id);
    db_bind_text(st, 4, address ? address : "");
    db_bind_double(st, 5, lat);
    db_bind_double(st, 6, lon);
    db_bind_text(st, 7, phone ? phone : "");
    db_bind_text(st, 8, imgs_str ? imgs_str : "[]");
    db_step(st);
    long vid = db_last_id(db);
    db_finalize(st);
    if (imgs_str) cJSON_free(imgs_str);

    char vid_str[32]; snprintf(vid_str, sizeof(vid_str), "%ld", vid);
    audit_log(db, "admin", "create_venue", "venue", vid_str, name, NULL);

    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id", vid);
    cJSON_AddStringToObject(res, "message", "施設を作成しました");
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_update_venue(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    /* 対象の存在確認 */
    DbStmt *chk = NULL;
    chk = db_prepare(db, "SELECT id FROM venues WHERE id=?");
    db_bind_int(chk, 1, id);
    if (db_step(chk) != 1) {
        db_finalize(chk); cJSON_Delete(body);
        send_error_json(c, 404, "venue not found"); return;
    }
    db_finalize(chk);

    /* partial update — あるフィールドだけ更新 */
    cJSON *it;
    it = cJSON_GetObjectItem(body, "name");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE venues SET name=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "description");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE venues SET description=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "address");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE venues SET address=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "phone");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE venues SET phone=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "施設を更新しました");
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_delete_venue(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    /* active plans があれば 409 */
    DbStmt *chk = NULL;
    chk = db_prepare(db, "SELECT COUNT(*) FROM plans WHERE venue_id=? AND is_active=1");
    db_bind_int(chk, 1, id);
    db_step(chk);
    long active = db_col_int(chk, 0);
    db_finalize(chk);
    if (active > 0) { send_error_json(c, 409, "この施設にはアクティブなプランがあります"); return; }
    /* soft-deleted plans の関連データを順にカスケード削除 */
    const char *cascade[] = {
        "DELETE FROM plan_prices WHERE plan_id IN (SELECT id FROM plans WHERE venue_id=? AND is_active=0)",
        "DELETE FROM reviews    WHERE plan_id IN (SELECT id FROM plans WHERE venue_id=? AND is_active=0)",
        "DELETE FROM schedules  WHERE plan_id IN (SELECT id FROM plans WHERE venue_id=? AND is_active=0)",
        "DELETE FROM plans WHERE venue_id=? AND is_active=0",
        NULL
    };
    for (int ci = 0; cascade[ci]; ci++) {
        DbStmt *dp = NULL;
        dp = db_prepare(db, cascade[ci]);
        db_bind_int(dp, 1, id);
        db_step(dp); db_finalize(dp);
    }
    /* venue を削除 */
    DbStmt *st = NULL;
    st = db_prepare(db, "DELETE FROM venues WHERE id=?");
    db_bind_int(st, 1, id);
    int rc = db_step(st);
    db_finalize(st);
    if (rc == -1 || db_changes(db) == 0) {
        send_error_json(c, 404, "venue not found"); return;
    }
    char vid_str2[32]; snprintf(vid_str2, sizeof(vid_str2), "%ld", id);
    audit_log(db, "admin", "delete_venue", "venue", vid_str2, "", NULL);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"施設を削除しました\"}");
}

/* ─── Plans ───────────────────────────────────────────────────────────────── */

void handle_admin_create_plan(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    long venue_id    = cjson_long(cJSON_GetObjectItem(body, "venue_id"));
    long category_id = cjson_long(cJSON_GetObjectItem(body, "category_id"));
    const char *title= cJSON_GetStringValue(cJSON_GetObjectItem(body, "title"));
    const char *desc = cJSON_GetStringValue(cJSON_GetObjectItem(body, "description"));
    long dur   = cjson_long(cJSON_GetObjectItem(body, "duration_minutes"));
    long minp  = cjson_long(cJSON_GetObjectItem(body, "min_participants"));
    long maxp  = cjson_long(cJSON_GetObjectItem(body, "max_participants"));
    long minage= cjson_long(cJSON_GetObjectItem(body, "min_age"));
    cJSON *imgs = cJSON_GetObjectItem(body, "images");
    cJSON *tags = cJSON_GetObjectItem(body, "tags");
    char *imgs_str = imgs ? cJSON_PrintUnformatted(imgs) : NULL;
    char *tags_str = tags ? cJSON_PrintUnformatted(tags) : NULL;
    /* キャンセルポリシー（未指定時はデフォルト値） */
    cJSON *cdft = cJSON_GetObjectItem(body, "cancel_days_full");
    cJSON *cdpt = cJSON_GetObjectItem(body, "cancel_days_partial");
    cJSON *cppt = cJSON_GetObjectItem(body, "cancel_pct_partial");
    long cancel_days_full    = cdft ? (long)cJSON_GetNumberValue(cdft) : 7;
    long cancel_days_partial = cdpt ? (long)cJSON_GetNumberValue(cdpt) : 3;
    long cancel_pct_partial  = cppt ? (long)cJSON_GetNumberValue(cppt) : 50;

    if (!title || !*title || venue_id<=0 || category_id<=0) {
        cJSON_Delete(body);
        if (imgs_str) cJSON_free(imgs_str);
        if (tags_str) cJSON_free(tags_str);
        send_error_json(c, 400, "title, venue_id, category_id は必須です");
        return;
    }

    DbStmt *st = NULL;
    st = db_prepare(db,
        "INSERT INTO plans(venue_id,category_id,title,description,duration_minutes,"
        "min_participants,max_participants,min_age,images,tags,"
        "cancel_days_full,cancel_days_partial,cancel_pct_partial)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");
    db_bind_int(st, 1, venue_id);
    db_bind_int(st, 2, category_id);
    db_bind_text(st, 3, title);
    db_bind_text(st, 4, desc ? desc : "");
    db_bind_int(st, 5, dur);
    db_bind_int(st, 6, minp > 0 ? minp : 1);
    db_bind_int(st, 7, maxp);
    db_bind_int(st, 8, minage);
    db_bind_text(st, 9, imgs_str ? imgs_str : "[]");
    db_bind_text(st, 10, tags_str ? tags_str : "[]");
    db_bind_int(st, 11, cancel_days_full);
    db_bind_int(st, 12, cancel_days_partial);
    db_bind_int(st, 13, cancel_pct_partial);
    db_step(st);
    long pid = db_last_id(db);
    db_finalize(st);
    if (imgs_str) cJSON_free(imgs_str);
    if (tags_str) cJSON_free(tags_str);

    /* insert prices if provided */
    cJSON *prices = cJSON_GetObjectItem(body, "prices");
    if (prices && cJSON_IsArray(prices)) {
        int np = cJSON_GetArraySize(prices);
        for (int i = 0; i < np; i++) {
            cJSON *pr = cJSON_GetArrayItem(prices, i);
            const char *pt = cJSON_GetStringValue(cJSON_GetObjectItem(pr, "participant_type"));
            const char *lb = cJSON_GetStringValue(cJSON_GetObjectItem(pr, "label"));
            long price     = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(pr, "price"));
            if (!pt || !lb || price <= 0) continue;
            DbStmt *pi = NULL;
            pi = db_prepare(db,
                "INSERT INTO plan_prices(plan_id,participant_type,label,price) VALUES(?,?,?,?)");
            db_bind_int(pi, 1, pid);
            db_bind_text(pi, 2, pt);
            db_bind_text(pi, 3, lb);
            db_bind_int(pi, 4, price);
            db_step(pi); db_finalize(pi);
        }
    }
    char pid_str[32]; snprintf(pid_str, sizeof(pid_str), "%ld", pid);
    audit_log(db, "admin", "create_plan", "plan", pid_str, title, NULL);

    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id", pid);
    cJSON_AddStringToObject(res, "message", "プランを作成しました");
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_update_plan(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    DbStmt *chk = NULL;
    chk = db_prepare(db, "SELECT id FROM plans WHERE id=?");
    db_bind_int(chk, 1, id);
    if (db_step(chk) != 1) {
        db_finalize(chk); cJSON_Delete(body);
        send_error_json(c, 404, "plan not found"); return;
    }
    db_finalize(chk);

    cJSON *it;
    it = cJSON_GetObjectItem(body, "title");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE plans SET title=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "description");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE plans SET description=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "is_active");
    if (it && cJSON_IsBool(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE plans SET is_active=? WHERE id=?");
        db_bind_int(u, 1, cJSON_IsTrue(it) ? 1 : 0);
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "cancel_days_full");
    if (it && cJSON_IsNumber(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE plans SET cancel_days_full=? WHERE id=?");
        db_bind_int(u, 1, (long)cJSON_GetNumberValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "cancel_days_partial");
    if (it && cJSON_IsNumber(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE plans SET cancel_days_partial=? WHERE id=?");
        db_bind_int(u, 1, (long)cJSON_GetNumberValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "cancel_pct_partial");
    if (it && cJSON_IsNumber(it)) {
        DbStmt *u = NULL; u = db_prepare(db, "UPDATE plans SET cancel_pct_partial=? WHERE id=?");
        db_bind_int(u, 1, (long)cJSON_GetNumberValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "プランを更新しました");
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_delete_plan(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    /* soft delete — is_active=0 */
    DbStmt *st = NULL;
    st = db_prepare(db, "UPDATE plans SET is_active=0 WHERE id=?");
    db_bind_int(st, 1, id);
    db_step(st); db_finalize(st);
    if (db_changes(db) == 0) {
        send_error_json(c, 404, "plan not found"); return;
    }
    char dpid_str[32]; snprintf(dpid_str, sizeof(dpid_str), "%ld", id);
    audit_log(db, "admin", "delete_plan", "plan", dpid_str, "", NULL);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"プランを非公開にしました\"}");
}

/* ─── Schedules ───────────────────────────────────────────────────────────── */

void handle_admin_create_schedule(struct mg_connection *c, struct mg_http_message *hm,
                                   DbConn *db, long plan_id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *date  = cJSON_GetStringValue(cJSON_GetObjectItem(body, "date"));
    const char *start = cJSON_GetStringValue(cJSON_GetObjectItem(body, "start_time"));
    const char *end   = cJSON_GetStringValue(cJSON_GetObjectItem(body, "end_time"));
    long cap = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "capacity"));

    if (!date || !start || cap <= 0) {
        cJSON_Delete(body);
        send_error_json(c, 400, "date, start_time, capacity は必須です");
        return;
    }

    DbStmt *st = NULL;
    st = db_prepare(db,
        "INSERT INTO schedules(plan_id,date,start_time,end_time,capacity)"
        " VALUES(?,?,?,?,?)");
    db_bind_int(st, 1, plan_id);
    db_bind_text(st, 2, date);
    db_bind_text(st, 3, start);
    db_bind_text(st, 4, end ? end : "");
    db_bind_int(st, 5, cap);
    db_step(st);
    long sid = db_last_id(db);
    db_finalize(st);
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id", sid);
    cJSON_AddStringToObject(res, "message", "スケジュールを作成しました");
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_delete_schedule(struct mg_connection *c, struct mg_http_message *hm,
                                   DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    /* 予約があれば削除不可 */
    DbStmt *chk = NULL;
    chk = db_prepare(db,
        "SELECT COUNT(*) FROM bookings WHERE schedule_id=? AND status!='cancelled'");
    db_bind_int(chk, 1, id);
    db_step(chk);
    long cnt = db_col_int(chk, 0);
    db_finalize(chk);
    if (cnt > 0) {
        send_error_json(c, 409, "このスケジュールには有効な予約があるため削除できません");
        return;
    }

    DbStmt *st = NULL;
    st = db_prepare(db, "DELETE FROM schedules WHERE id=?");
    db_bind_int(st, 1, id);
    db_step(st); db_finalize(st);
    if (db_changes(db) == 0) {
        send_error_json(c, 404, "schedule not found"); return;
    }
    char dsid_str[32]; snprintf(dsid_str, sizeof(dsid_str), "%ld", id);
    audit_log(db, "admin", "delete_schedule", "schedule", dsid_str, "", NULL);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"スケジュールを削除しました\"}");
}

/* ─── Plan Prices ─────────────────────────────────────────────────────────── */

void handle_admin_set_prices(struct mg_connection *c, struct mg_http_message *hm,
                              DbConn *db, long plan_id) {
    if (!require_admin(c, hm)) return;
    cJSON *arr = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!arr || !cJSON_IsArray(arr)) {
        if (arr) cJSON_Delete(arr);
        send_error_json(c, 400, "配列で送信してください"); return;
    }

    /* 既存価格を削除して置き換え */
    DbStmt *del = NULL;
    del = db_prepare(db, "DELETE FROM plan_prices WHERE plan_id=?");
    db_bind_int(del, 1, plan_id);
    db_step(del); db_finalize(del);

    int n = cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        cJSON *pr = cJSON_GetArrayItem(arr, i);
        const char *pt = cJSON_GetStringValue(cJSON_GetObjectItem(pr, "participant_type"));
        const char *lb = cJSON_GetStringValue(cJSON_GetObjectItem(pr, "label"));
        long price     = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(pr, "price"));
        if (!pt || !lb || price <= 0) continue;
        DbStmt *ins = NULL;
        ins = db_prepare(db,
            "INSERT INTO plan_prices(plan_id,participant_type,label,price) VALUES(?,?,?,?)");
        db_bind_int(ins, 1, plan_id);
        db_bind_text(ins, 2, pt);
        db_bind_text(ins, 3, lb);
        db_bind_int(ins, 4, price);
        db_step(ins); db_finalize(ins);
    }
    cJSON_Delete(arr);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"価格を更新しました\"}");
}

/* ─── GET /api/v1/admin/plans ─────────────────────────────────────────────── */

void handle_admin_list_plans(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    long page  = admin_query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit = admin_query_long(hm, "limit", 50); if (limit > 200) limit = 200;
    long offset = (page - 1) * limit;

    /* is_active フィルタ（デフォルト: 全件） */
    char active_str[8] = {0};
    int has_active = mg_http_get_var(&hm->query, "is_active", active_str, sizeof(active_str)) > 0;
    int active_val = has_active ? (int)strtol(active_str, NULL, 10) : -1;

    DbStmt *ct = NULL;
    ct = db_prepare(db,
        "SELECT COUNT(*) FROM plans WHERE (? < 0 OR is_active=?)");
    db_bind_int(ct, 1, active_val);
    db_bind_int(ct, 2, active_val);
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT p.id,p.venue_id,v.name,p.category_id,c.name,"
        "p.title,p.is_active,p.min_participants,p.max_participants,"
        "p.duration_minutes,p.created_at "
        "FROM plans p "
        "JOIN venues v ON v.id=p.venue_id "
        "JOIN categories c ON c.id=p.category_id "
        "WHERE (? < 0 OR p.is_active=?) "
        "ORDER BY p.id LIMIT ? OFFSET ?");
    db_bind_int(st, 1, active_val);
    db_bind_int(st, 2, active_val);
    db_bind_int(st, 3, limit);
    db_bind_int(st, 4, offset);

    cJSON *plans = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *p = cJSON_CreateObject();
        cJSON_AddNumberToObject(p, "id",             db_col_int(st, 0));
        cJSON_AddNumberToObject(p, "venue_id",       db_col_int(st, 1));
        cJSON_AddStringToObject(p, "venue_name",     db_col_text(st, 2));
        cJSON_AddNumberToObject(p, "category_id",    db_col_int(st, 3));
        cJSON_AddStringToObject(p, "category_name",  db_col_text(st, 4));
        cJSON_AddStringToObject(p, "title",          db_col_text(st, 5));
        cJSON_AddBoolToObject(p, "is_active",        (int)db_col_int(st, 6) == 1);
        cJSON_AddNumberToObject(p, "min_participants",db_col_int(st, 7));
        if (!db_col_is_null(st, 8))
            cJSON_AddNumberToObject(p, "max_participants", db_col_int(st, 8));
        else cJSON_AddNullToObject(p, "max_participants");
        if (!db_col_is_null(st, 9))
            cJSON_AddNumberToObject(p, "duration_minutes", db_col_int(st, 9));
        else cJSON_AddNullToObject(p, "duration_minutes");
        cJSON_AddStringToObject(p, "created_at",     db_col_text(st, 10));
        cJSON_AddItemToArray(plans, p);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "plans", plans);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

/* ─── PATCH /api/v1/admin/schedules/:id ────────────────────────────────────── */

void handle_admin_update_schedule(struct mg_connection *c, struct mg_http_message *hm,
                                   DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    /* 存在確認 */
    DbStmt *chk = NULL;
    chk = db_prepare(db, "SELECT booked_count FROM schedules WHERE id=?");
    db_bind_int(chk, 1, id);
    if (db_step(chk) != 1) {
        db_finalize(chk); cJSON_Delete(body);
        send_error_json(c, 404, "schedule not found"); return;
    }
    long booked = db_col_int(chk, 0);
    db_finalize(chk);

    /* capacity 変更 — booked_count を下回る値は拒否 */
    cJSON *cap_item = cJSON_GetObjectItem(body, "capacity");
    if (cap_item && cJSON_IsNumber(cap_item)) {
        long new_cap = (long)cJSON_GetNumberValue(cap_item);
        if (new_cap < booked) {
            cJSON_Delete(body);
            send_error_json(c, 400, "capacity は現在の予約数を下回ることはできません"); return;
        }
        DbStmt *u = NULL;
        u = db_prepare(db, "UPDATE schedules SET capacity=? WHERE id=?");
        db_bind_int(u, 1, new_cap); db_bind_int(u, 2, id);
        db_step(u); db_finalize(u);
    }
    cJSON *it;
    it = cJSON_GetObjectItem(body, "date");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL;
        u = db_prepare(db, "UPDATE schedules SET date=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "start_time");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL;
        u = db_prepare(db, "UPDATE schedules SET start_time=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "end_time");
    if (it && cJSON_IsString(it)) {
        DbStmt *u = NULL;
        u = db_prepare(db, "UPDATE schedules SET end_time=? WHERE id=?");
        db_bind_text(u, 1, cJSON_GetStringValue(it));
        db_bind_int(u, 2, id); db_step(u); db_finalize(u);
    }
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "スケジュールを更新しました");
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/admin/bookings ────────────────────────────────────────────── */

void handle_admin_list_bookings(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    long page  = admin_query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit = admin_query_long(hm, "limit", 50); if (limit > 200) limit = 200;
    long offset = (page - 1) * limit;
    long plan_id_f = admin_query_long(hm, "plan_id", 0);
    long user_id_f = admin_query_long(hm, "user_id", 0);
    char status_f[32]  = {0};
    char date_f[32]    = {0};
    int has_status = mg_http_get_var(&hm->query, "status", status_f, sizeof(status_f)) > 0;
    int has_date   = mg_http_get_var(&hm->query, "date",   date_f,   sizeof(date_f))   > 0;

    /* COUNT */
    const char *cnt_sql =
        "SELECT COUNT(*) FROM bookings b "
        "JOIN schedules s ON s.id=b.schedule_id "
        "WHERE (? = 0 OR b.plan_id=?) "
        "AND (? = 0 OR b.user_id=?) "
        "AND (? = 0 OR b.status=?) "
        "AND (? = 0 OR s.date=?)";
    DbStmt *ct = NULL;
    ct = db_prepare(db, cnt_sql);
    db_bind_int(ct, 1, plan_id_f); db_bind_int(ct, 2, plan_id_f);
    db_bind_int(ct, 3, user_id_f); db_bind_int(ct, 4, user_id_f);
    db_bind_int(ct,  5, has_status); db_bind_text(ct, 6, status_f);
    db_bind_int(ct,  7, has_date);   db_bind_text(ct, 8, date_f);
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    const char *sel_sql =
        "SELECT b.id, b.user_id, u.name, u.email, "
        "b.plan_id, p.title, b.schedule_id, s.date, s.start_time, "
        "b.status, b.total_price, b.created_at "
        "FROM bookings b "
        "JOIN users u ON u.id=b.user_id "
        "JOIN plans p ON p.id=b.plan_id "
        "JOIN schedules s ON s.id=b.schedule_id "
        "WHERE (? = 0 OR b.plan_id=?) "
        "AND (? = 0 OR b.user_id=?) "
        "AND (? = 0 OR b.status=?) "
        "AND (? = 0 OR s.date=?) "
        "ORDER BY b.created_at DESC LIMIT ? OFFSET ?";
    DbStmt *st = NULL;
    st = db_prepare(db, sel_sql);
    db_bind_int(st, 1, plan_id_f); db_bind_int(st, 2, plan_id_f);
    db_bind_int(st, 3, user_id_f); db_bind_int(st, 4, user_id_f);
    db_bind_int(st,  5, has_status); db_bind_text(st, 6, status_f);
    db_bind_int(st,  7, has_date);   db_bind_text(st, 8, date_f);
    db_bind_int(st, 9, limit); db_bind_int(st, 10, offset);

    cJSON *bookings = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *b = cJSON_CreateObject();
        cJSON_AddStringToObject(b, "id",           db_col_text(st, 0));
        cJSON_AddNumberToObject(b, "user_id",       db_col_int(st, 1));
        if (!db_col_is_null(st, 2))
            cJSON_AddStringToObject(b, "user_name", db_col_text(st, 2));
        else cJSON_AddNullToObject(b, "user_name");
        cJSON_AddStringToObject(b, "user_email",    db_col_text(st, 3));
        cJSON_AddNumberToObject(b, "plan_id",        db_col_int(st, 4));
        cJSON_AddStringToObject(b, "plan_title",     db_col_text(st, 5));
        cJSON_AddNumberToObject(b, "schedule_id",    db_col_int(st, 6));
        cJSON_AddStringToObject(b, "schedule_date",  db_col_text(st, 7));
        cJSON_AddStringToObject(b, "schedule_start", db_col_text(st, 8));
        cJSON_AddStringToObject(b, "status",         db_col_text(st, 9));
        cJSON_AddNumberToObject(b, "total_price",    db_col_int(st, 10));
        cJSON_AddStringToObject(b, "created_at",     db_col_text(st, 11));
        cJSON_AddItemToArray(bookings, b);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "bookings", bookings);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/admin/reviews ─────────────────────────────────────────────── */

void handle_admin_list_reviews(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    long page    = admin_query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit   = admin_query_long(hm, "limit", 50); if (limit > 200) limit = 200;
    long offset  = (page - 1) * limit;
    long plan_id_f  = admin_query_long(hm, "plan_id", 0);
    long rating_f   = admin_query_long(hm, "rating", 0);

    DbStmt *ct = NULL;
    ct = db_prepare(db,
        "SELECT COUNT(*) FROM reviews WHERE (? = 0 OR plan_id=?) AND (? = 0 OR rating=?)");
    db_bind_int(ct, 1, plan_id_f); db_bind_int(ct, 2, plan_id_f);
    db_bind_int(ct, 3, rating_f);  db_bind_int(ct, 4, rating_f);
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT r.id, r.user_id, u.name, r.plan_id, p.title, "
        "r.rating, r.comment, r.created_at "
        "FROM reviews r "
        "LEFT JOIN users u ON u.id=r.user_id "
        "LEFT JOIN plans p ON p.id=r.plan_id "
        "WHERE (? = 0 OR r.plan_id=?) AND (? = 0 OR r.rating=?) "
        "ORDER BY r.created_at DESC LIMIT ? OFFSET ?");
    db_bind_int(st, 1, plan_id_f); db_bind_int(st, 2, plan_id_f);
    db_bind_int(st, 3, rating_f);  db_bind_int(st, 4, rating_f);
    db_bind_int(st, 5, limit); db_bind_int(st, 6, offset);

    cJSON *reviews = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *rv = cJSON_CreateObject();
        cJSON_AddNumberToObject(rv, "id",       db_col_int(st, 0));
        cJSON_AddNumberToObject(rv, "user_id",  db_col_int(st, 1));
        if (!db_col_is_null(st, 2))
            cJSON_AddStringToObject(rv, "user_name", db_col_text(st, 2));
        else cJSON_AddNullToObject(rv, "user_name");
        cJSON_AddNumberToObject(rv, "plan_id",  db_col_int(st, 3));
        if (!db_col_is_null(st, 4))
            cJSON_AddStringToObject(rv, "plan_title", db_col_text(st, 4));
        else cJSON_AddNullToObject(rv, "plan_title");
        cJSON_AddNumberToObject(rv, "rating",   db_col_int(st, 5));
        if (!db_col_is_null(st, 6))
            cJSON_AddStringToObject(rv, "comment", db_col_text(st, 6));
        else cJSON_AddNullToObject(rv, "comment");
        cJSON_AddStringToObject(rv, "created_at", db_col_text(st, 7));
        cJSON_AddItemToArray(reviews, rv);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "reviews", reviews);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

/* ─── DELETE /api/v1/admin/reviews/:id ──────────────────────────────────────── */

void handle_admin_delete_review(struct mg_connection *c, struct mg_http_message *hm,
                                 DbConn *db, long id) {
    if (!require_admin(c, hm)) return;

    DbStmt *chk = NULL;
    chk = db_prepare(db, "SELECT id FROM reviews WHERE id=?");
    db_bind_int(chk, 1, id);
    if (db_step(chk) != 1) {
        db_finalize(chk);
        send_error_json(c, 404, "review not found"); return;
    }
    db_finalize(chk);

    DbStmt *del = NULL;
    del = db_prepare(db, "DELETE FROM reviews WHERE id=?");
    db_bind_int(del, 1, id);
    db_step(del); db_finalize(del);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"レビューを削除しました\"}");
}

/* ─── GET /api/v1/admin/users ───────────────────────────────────────────────── */

void handle_admin_list_users(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    long page  = admin_query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit = admin_query_long(hm, "limit", 50); if (limit > 200) limit = 200;
    long offset = (page - 1) * limit;
    char q_raw[128] = {0};
    int has_q = mg_http_get_var(&hm->query, "q", q_raw, sizeof(q_raw)) > 0 && q_raw[0];

    /* email LIKE フィルタ */
    char q_esc[256] = {0};
    if (has_q) {
        int k = 0;
        for (int i = 0; q_raw[i] && k < (int)sizeof(q_esc)-3; i++) {
            char ch = q_raw[i];
            if (ch == '%' || ch == '_' || ch == '\\') q_esc[k++] = '\\';
            q_esc[k++] = ch;
        }
    }
    char kw[260] = {0};
    if (has_q && q_esc[0]) snprintf(kw, sizeof(kw), "%%%s%%", q_esc);

    DbStmt *ct = NULL;
    ct = db_prepare(db,
        "SELECT COUNT(*) FROM users WHERE (? = 0 OR email LIKE ? ESCAPE '!')");
    db_bind_int(ct, 1, has_q); db_bind_text(ct, 2, kw);
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT u.id, u.name, u.email, u.created_at, "
        "(SELECT COUNT(*) FROM bookings b WHERE b.user_id=u.id AND b.status='confirmed') AS booking_count "
        "FROM users u "
        "WHERE (? = 0 OR u.email LIKE ? ESCAPE '!') "
        "ORDER BY u.id LIMIT ? OFFSET ?");
    db_bind_int(st, 1, has_q); db_bind_text(st, 2, kw);
    db_bind_int(st, 3, limit); db_bind_int(st, 4, offset);

    cJSON *users = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *u = cJSON_CreateObject();
        cJSON_AddNumberToObject(u, "id",            db_col_int(st, 0));
        if (!db_col_is_null(st, 1))
            cJSON_AddStringToObject(u, "name",      db_col_text(st, 1));
        else cJSON_AddNullToObject(u, "name");
        cJSON_AddStringToObject(u, "email",         db_col_text(st, 2));
        cJSON_AddStringToObject(u, "created_at",    db_col_text(st, 3));
        cJSON_AddNumberToObject(u, "booking_count", db_col_int(st, 4));
        cJSON_AddItemToArray(users, u);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "users", users);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

/* ─── POST /api/v1/admin/plans/:id/schedules/bulk ──────────────────────────── */

void handle_admin_bulk_create_schedules(struct mg_connection *c, struct mg_http_message *hm,
                                        DbConn *db, long plan_id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *start_date_s = cJSON_GetStringValue(cJSON_GetObjectItem(body, "start_date"));
    const char *end_date_s   = cJSON_GetStringValue(cJSON_GetObjectItem(body, "end_date"));
    const char *start_time   = cJSON_GetStringValue(cJSON_GetObjectItem(body, "start_time"));
    const char *end_time     = cJSON_GetStringValue(cJSON_GetObjectItem(body, "end_time"));
    long cap = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "capacity"));
    cJSON *weekdays_arr = cJSON_GetObjectItem(body, "weekdays");

    if (!start_date_s || !end_date_s || !start_time || cap <= 0) {
        cJSON_Delete(body);
        send_error_json(c, 400, "start_date, end_date, start_time, capacity は必須です");
        return;
    }

    /* Parse start and end dates */
    int sy, sm, sd, ey, em, ed;
    if (sscanf(start_date_s, "%d-%d-%d", &sy, &sm, &sd) != 3 ||
        sscanf(end_date_s,   "%d-%d-%d", &ey, &em, &ed) != 3) {
        cJSON_Delete(body);
        send_error_json(c, 400, "日付形式は YYYY-MM-DD で指定してください");
        return;
    }

    /* Build weekdays bitmask: bit N set means day N (0=Sun) is allowed */
    int weekday_filter = 0;
    int use_weekday_filter = 0;
    if (weekdays_arr && cJSON_IsArray(weekdays_arr) && cJSON_GetArraySize(weekdays_arr) > 0) {
        use_weekday_filter = 1;
        int wn = cJSON_GetArraySize(weekdays_arr);
        for (int i = 0; i < wn; i++) {
            cJSON *wd = cJSON_GetArrayItem(weekdays_arr, i);
            if (cJSON_IsNumber(wd)) {
                int d = (int)cJSON_GetNumberValue(wd);
                if (d >= 0 && d <= 6) weekday_filter |= (1 << d);
            }
        }
    }

    /* Iterate dates from start to end (inclusive), up to 366 */
    struct tm t = {0};
    t.tm_year = sy - 1900; t.tm_mon = sm - 1; t.tm_mday = sd;
    t.tm_isdst = -1;
    mktime(&t);

    struct tm tend = {0};
    tend.tm_year = ey - 1900; tend.tm_mon = em - 1; tend.tm_mday = ed;
    tend.tm_isdst = -1;
    time_t end_epoch = mktime(&tend);

    long created = 0;
    char date_buf[12];

    while (created < 366) {
        time_t cur_epoch = mktime(&t);
        if (cur_epoch > end_epoch) break;

        /* Check weekday filter */
        if (!use_weekday_filter || (weekday_filter & (1 << t.tm_wday))) {
            strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", &t);

            DbStmt *ins = NULL;
            ins = db_prepare(db,
                "INSERT INTO schedules(plan_id,date,start_time,end_time,capacity)"
                " VALUES(?,?,?,?,?)");
            db_bind_int(ins, 1, plan_id);
            db_bind_text(ins, 2, date_buf);
            db_bind_text(ins, 3, start_time);
            db_bind_text(ins, 4, end_time ? end_time : "");
            db_bind_int(ins, 5, cap);
            db_step(ins); db_finalize(ins);
            created++;
        }

        /* Advance by 1 day */
        t.tm_mday++;
        t.tm_isdst = -1;
        mktime(&t);
    }
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "created", created);
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

/* ─── POST /api/v1/admin/bookings/:id/refund ────────────────────────────────── */

void handle_admin_refund_booking(struct mg_connection *c, struct mg_http_message *hm,
                                  DbConn *db, const char *id) {
    if (!require_admin(c, hm)) return;

    /* Look up booking */
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT status, stripe_payment_intent_id FROM bookings WHERE id=?");
    db_bind_text(st, 1, id);
    if (db_step(st) != 1) {
        db_finalize(st);
        send_error_json(c, 404, "booking not found"); return;
    }
    const char *status_raw = db_col_text(st, 0);
    char status[32] = {0};
    if (status_raw) strncpy(status, status_raw, sizeof(status) - 1);

    const char *pi_raw = db_col_text(st, 1);
    char pi_id[256] = {0};
    if (pi_raw) strncpy(pi_id, pi_raw, sizeof(pi_id) - 1);
    db_finalize(st);

    /* Guard: already cancelled or refunded */
    if (strcmp(status, "cancelled") == 0 || strcmp(status, "refunded") == 0) {
        send_error_json(c, 400, "この予約はすでにキャンセル済みまたは返金済みです");
        return;
    }

    /* Guard: no Stripe PI */
    if (!pi_id[0]) {
        send_error_json(c, 400, "Stripe決済情報がありません");
        return;
    }

    /* Call Stripe refund */
    if (stripe_create_refund(pi_id) != 0) {
        send_error_json(c, 502, "Stripe返金に失敗しました");
        return;
    }

    /* Update booking status */
    DbStmt *upd = NULL;
    upd = db_prepare(db, "UPDATE bookings SET status='refunded' WHERE id=?");
    db_bind_text(upd, 1, id);
    db_step(upd); db_finalize(upd);

    audit_log(db, "admin", "refund", "booking", id, "", NULL);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddBoolToObject(res, "refunded", 1);
    cJSON_AddStringToObject(res, "booking_id", id);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/admin/backup ──────────────────────────────────────────────── */

void handle_admin_backup_db(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;

#ifdef USE_SQLITE
    /* Generate backup filename with timestamp */
    time_t now = time(NULL);
    struct tm *tm_now = gmtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm_now);
    char backup_path[128];
    snprintf(backup_path, sizeof(backup_path), "/tmp/asoview_backup_%s.db", ts);

    /* SQLite online backup API */
    sqlite3 *dest = NULL;
    if (sqlite3_open(backup_path, &dest) != SQLITE_OK) {
        if (dest) sqlite3_close(dest);
        send_error_json(c, 500, "バックアップファイルの作成に失敗しました");
        return;
    }

    sqlite3_backup *bk = sqlite3_backup_init(dest, "main", (sqlite3 *)db, "main");
    if (!bk) {
        sqlite3_close(dest);
        send_error_json(c, 500, "バックアップの初期化に失敗しました");
        return;
    }
    sqlite3_backup_step(bk, -1);  /* copy all pages */
    sqlite3_backup_finish(bk);
    sqlite3_close(dest);

    /* Read backup file into memory */
    FILE *f = fopen(backup_path, "rb");
    if (!f) {
        remove(backup_path);
        send_error_json(c, 500, "バックアップファイルの読み込みに失敗しました");
        return;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* Max 50 MB guard */
    if (fsize > 50L * 1024 * 1024) {
        fclose(f);
        remove(backup_path);
        send_error_json(c, 413, "バックアップファイルが50MBを超えています");
        return;
    }

    char *buf = (char *)malloc((size_t)fsize);
    if (!buf) {
        fclose(f);
        remove(backup_path);
        send_error_json(c, 500, "メモリ確保に失敗しました");
        return;
    }
    size_t nread = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    remove(backup_path);

    /* Build filename for Content-Disposition */
    char disp_fn[128];
    snprintf(disp_fn, sizeof(disp_fn), "asoview_backup_%s.db", ts);

    char headers[512];
    snprintf(headers, sizeof(headers),
             "Content-Type: application/octet-stream\r\n"
             "Content-Disposition: attachment; filename=\"%s\"\r\n"
             "Content-Length: %ld\r\n"
             "Access-Control-Allow-Origin: *\r\n",
             disp_fn, (long)nread);

    mg_printf(c,
              "HTTP/1.1 200 OK\r\n"
              "%s\r\n", headers);
    mg_send(c, buf, nread);
    free(buf);

#else
    (void)db;
    send_error_json(c, 501, "バックアップはSQLiteバックエンドのみサポートされています");
#endif
}

/* ─── GET /admin/ui ─────────────────────────────────────────────────────────── */

void handle_admin_ui(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    (void)hm; (void)db;

    static const char HTML[] =
"<!DOCTYPE html>\n"
"<html lang='ja'>\n"
"<head>\n"
"<meta charset='UTF-8'>\n"
"<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
"<title>Asoview Admin</title>\n"
"<style>\n"
":root{--bg:#0f0f23;--sidebar:#1a1a2e;--accent:#e94560;--text:#eee;--muted:#999;--card:#1e1e3a;--border:#2a2a4a;--input:#16213e;--success:#4caf50;--danger:#e94560;}\n"
"*{box-sizing:border-box;margin:0;padding:0;}\n"
"body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;display:flex;height:100vh;overflow:hidden;}\n"
"#sidebar{width:200px;background:var(--sidebar);display:flex;flex-direction:column;border-right:1px solid var(--border);flex-shrink:0;}\n"
"#sidebar h1{padding:20px 16px;font-size:18px;font-weight:700;color:var(--accent);border-bottom:1px solid var(--border);}\n"
"#sidebar nav a{display:block;padding:12px 16px;color:var(--muted);text-decoration:none;font-size:14px;transition:background 0.15s,color 0.15s;}\n"
"#sidebar nav a:hover,#sidebar nav a.active{background:var(--bg);color:var(--text);border-left:3px solid var(--accent);}\n"
"#main{flex:1;display:flex;flex-direction:column;overflow:hidden;}\n"
"#topbar{background:var(--sidebar);padding:10px 20px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border);}\n"
"#topbar label{font-size:13px;color:var(--muted);}\n"
"#topbar input{background:var(--input);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px;width:260px;}\n"
"#topbar button{padding:6px 12px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:13px;}\n"
"#content{flex:1;overflow-y:auto;padding:20px;}\n"
".tab{display:none;}.tab.active{display:block;}\n"
"h2{font-size:20px;margin-bottom:16px;color:var(--text);}\n"
"table{width:100%;border-collapse:collapse;font-size:13px;}\n"
"th{background:var(--card);padding:8px 12px;text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--border);}\n"
"td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top;}\n"
"tr:hover td{background:rgba(233,69,96,0.05);}\n"
".btn{padding:5px 12px;border:none;border-radius:4px;cursor:pointer;font-size:12px;}\n"
".btn-primary{background:var(--accent);color:#fff;}\n"
".btn-secondary{background:var(--card);color:var(--text);border:1px solid var(--border);}\n"
".btn-danger{background:#c0392b;color:#fff;}\n"
".btn-success{background:#27ae60;color:#fff;}\n"
".actions{display:flex;gap:6px;}\n"
".toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;}\n"
".toolbar input{background:var(--input);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px;width:200px;}\n"
"/* Modal */\n"
".overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:100;justify-content:center;align-items:center;}\n"
".overlay.open{display:flex;}\n"
".modal{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;min-width:400px;max-width:600px;max-height:90vh;overflow-y:auto;}\n"
".modal h3{margin-bottom:16px;font-size:16px;}\n"
".form-group{margin-bottom:12px;}\n"
".form-group label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px;}\n"
".form-group input,.form-group select,.form-group textarea{width:100%;background:var(--input);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:4px;font-size:13px;}\n"
".form-group textarea{min-height:80px;resize:vertical;}\n"
".form-row{display:flex;gap:10px;}.form-row .form-group{flex:1;}\n"
".modal-footer{display:flex;justify-content:flex-end;gap:8px;margin-top:16px;}\n"
".msg{padding:8px 12px;border-radius:4px;font-size:13px;margin-bottom:12px;}\n"
".msg.ok{background:#1b4332;color:#52c41a;}\n"
".msg.err{background:#4a1020;color:#ff6b6b;}\n"
".badge{padding:2px 8px;border-radius:12px;font-size:11px;}\n"
".badge-green{background:#1b4332;color:#52c41a;}\n"
".badge-red{background:#4a1020;color:#ff6b6b;}\n"
".badge-blue{background:#0d2b45;color:#5bc0eb;}\n"
".badge-grey{background:#2a2a4a;color:#999;}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div id='sidebar'>\n"
"  <h1>&#9965; Asoview</h1>\n"
"  <nav>\n"
"    <a href='#' onclick='showTab(\"venues\")' id='nav-venues'>Venues</a>\n"
"    <a href='#' onclick='showTab(\"plans\")' id='nav-plans'>Plans</a>\n"
"    <a href='#' onclick='showTab(\"schedules\")' id='nav-schedules'>Schedules</a>\n"
"    <a href='#' onclick='showTab(\"bookings\")' id='nav-bookings'>Bookings</a>\n"
"    <a href='#' onclick='showTab(\"users\")' id='nav-users'>Users</a>\n"
"  </nav>\n"
"</div>\n"
"<div id='main'>\n"
"  <div id='topbar'>\n"
"    <label>Admin Key:</label>\n"
"    <input type='password' id='admin-key' placeholder='X-Admin-Key を入力...'>\n"
"    <button onclick='saveKey()'>保存</button>\n"
"    <button class='btn btn-secondary' onclick='clearKey()' style='padding:6px 10px;'>クリア</button>\n"
"  </div>\n"
"  <div id='content'>\n"
"\n"
"  <!-- VENUES TAB -->\n"
"  <div class='tab' id='tab-venues'>\n"
"    <div id='venues-msg'></div>\n"
"    <div class='toolbar'>\n"
"      <h2>Venues</h2>\n"
"      <button class='btn btn-primary' onclick='openVenueModal()'>+ 追加</button>\n"
"    </div>\n"
"    <table id='venues-table'><thead><tr><th>ID</th><th>Name</th><th>Area</th><th>Address</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- PLANS TAB -->\n"
"  <div class='tab' id='tab-plans'>\n"
"    <div id='plans-msg'></div>\n"
"    <div class='toolbar'>\n"
"      <h2>Plans</h2>\n"
"      <button class='btn btn-primary' onclick='openPlanModal()'>+ 追加</button>\n"
"    </div>\n"
"    <table id='plans-table'><thead><tr><th>ID</th><th>Title</th><th>Venue</th><th>Active</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- SCHEDULES TAB -->\n"
"  <div class='tab' id='tab-schedules'>\n"
"    <div id='schedules-msg'></div>\n"
"    <div class='toolbar'>\n"
"      <h2>Schedules</h2>\n"
"      <div style='display:flex;gap:8px;align-items:center;'>\n"
"        <select id='sched-plan-sel' onchange='loadSchedules()' style='background:var(--input);border:1px solid var(--border);color:var(--text);padding:6px;border-radius:4px;font-size:13px;'><option value=''>-- Plan を選択 --</option></select>\n"
"        <button class='btn btn-primary' onclick='openSchedModal()'>+ 追加</button>\n"
"        <button class='btn btn-secondary' onclick='openBulkModal()'>Bulk生成</button>\n"
"      </div>\n"
"    </div>\n"
"    <table id='schedules-table'><thead><tr><th>ID</th><th>Date</th><th>Start</th><th>End</th><th>Capacity</th><th>Booked</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- BOOKINGS TAB -->\n"
"  <div class='tab' id='tab-bookings'>\n"
"    <div class='toolbar'>\n"
"      <h2>Bookings</h2>\n"
"      <input type='text' id='bookings-search' placeholder='検索...' oninput='loadBookings()'>\n"
"    </div>\n"
"    <table id='bookings-table'><thead><tr><th>ID</th><th>User</th><th>Schedule</th><th>Status</th><th>Amount</th><th>Created</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- USERS TAB -->\n"
"  <div class='tab' id='tab-users'>\n"
"    <div class='toolbar'>\n"
"      <h2>Users</h2>\n"
"      <input type='text' id='users-search' placeholder='検索...' oninput='loadUsers()'>\n"
"    </div>\n"
"    <table id='users-table'><thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Bookings</th><th>Created</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  </div><!-- /content -->\n"
"</div><!-- /main -->\n"
"\n"
"<!-- VENUE MODAL -->\n"
"<div class='overlay' id='venue-modal'>\n"
"  <div class='modal'>\n"
"    <h3 id='venue-modal-title'>施設を追加</h3>\n"
"    <div id='venue-modal-msg'></div>\n"
"    <input type='hidden' id='venue-id'>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>名前 *</label><input id='venue-name' type='text'></div>\n"
"      <div class='form-group'><label>Area ID *</label><input id='venue-area-id' type='number'></div>\n"
"    </div>\n"
"    <div class='form-group'><label>住所</label><input id='venue-address' type='text'></div>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>電話</label><input id='venue-phone' type='text'></div>\n"
"      <div class='form-group'><label>Website</label><input id='venue-website' type='text'></div>\n"
"    </div>\n"
"    <div class='form-group'><label>説明</label><textarea id='venue-desc'></textarea></div>\n"
"    <div class='modal-footer'>\n"
"      <button class='btn btn-secondary' onclick='closeModal(\"venue-modal\")'>キャンセル</button>\n"
"      <button class='btn btn-primary' onclick='saveVenue()'>保存</button>\n"
"    </div>\n"
"  </div>\n"
"</div>\n"
"\n"
"<!-- PLAN MODAL -->\n"
"<div class='overlay' id='plan-modal'>\n"
"  <div class='modal'>\n"
"    <h3 id='plan-modal-title'>プランを追加</h3>\n"
"    <div id='plan-modal-msg'></div>\n"
"    <input type='hidden' id='plan-id'>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>Venue ID *</label><input id='plan-venue-id' type='number'></div>\n"
"      <div class='form-group'><label>Category ID *</label><input id='plan-cat-id' type='number'></div>\n"
"    </div>\n"
"    <div class='form-group'><label>タイトル *</label><input id='plan-title' type='text'></div>\n"
"    <div class='form-group'><label>説明</label><textarea id='plan-desc'></textarea></div>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>所要時間(分)</label><input id='plan-dur' type='number'></div>\n"
"      <div class='form-group'><label>最小人数</label><input id='plan-minp' type='number'></div>\n"
"      <div class='form-group'><label>最大人数</label><input id='plan-maxp' type='number'></div>\n"
"    </div>\n"
"    <div class='modal-footer'>\n"
"      <button class='btn btn-secondary' onclick='closeModal(\"plan-modal\")'>キャンセル</button>\n"
"      <button class='btn btn-primary' onclick='savePlan()'>保存</button>\n"
"    </div>\n"
"  </div>\n"
"</div>\n"
"\n"
"<!-- SCHEDULE MODAL -->\n"
"<div class='overlay' id='sched-modal'>\n"
"  <div class='modal'>\n"
"    <h3>スケジュールを追加</h3>\n"
"    <div id='sched-modal-msg'></div>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>日付 *</label><input id='sched-date' type='date'></div>\n"
"      <div class='form-group'><label>定員 *</label><input id='sched-cap' type='number' value='10'></div>\n"
"    </div>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>開始時刻 *</label><input id='sched-start' type='time'></div>\n"
"      <div class='form-group'><label>終了時刻</label><input id='sched-end' type='time'></div>\n"
"    </div>\n"
"    <div class='modal-footer'>\n"
"      <button class='btn btn-secondary' onclick='closeModal(\"sched-modal\")'>キャンセル</button>\n"
"      <button class='btn btn-primary' onclick='saveSched()'>保存</button>\n"
"    </div>\n"
"  </div>\n"
"</div>\n"
"\n"
"<!-- BULK SCHEDULE MODAL -->\n"
"<div class='overlay' id='bulk-modal'>\n"
"  <div class='modal'>\n"
"    <h3>一括スケジュール生成</h3>\n"
"    <div id='bulk-modal-msg'></div>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>開始日 *</label><input id='bulk-start-date' type='date'></div>\n"
"      <div class='form-group'><label>終了日 *</label><input id='bulk-end-date' type='date'></div>\n"
"    </div>\n"
"    <div class='form-group'><label>曜日フィルタ（空=全日）</label>\n"
"      <div style='display:flex;gap:10px;flex-wrap:wrap;margin-top:6px;font-size:13px;'>\n"
"        <label><input type='checkbox' name='wd' value='0'> 日</label>\n"
"        <label><input type='checkbox' name='wd' value='1'> 月</label>\n"
"        <label><input type='checkbox' name='wd' value='2'> 火</label>\n"
"        <label><input type='checkbox' name='wd' value='3'> 水</label>\n"
"        <label><input type='checkbox' name='wd' value='4'> 木</label>\n"
"        <label><input type='checkbox' name='wd' value='5'> 金</label>\n"
"        <label><input type='checkbox' name='wd' value='6'> 土</label>\n"
"      </div>\n"
"    </div>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>開始時刻 *</label><input id='bulk-start' type='time' value='10:00'></div>\n"
"      <div class='form-group'><label>終了時刻</label><input id='bulk-end' type='time'></div>\n"
"      <div class='form-group'><label>定員 *</label><input id='bulk-cap' type='number' value='10'></div>\n"
"    </div>\n"
"    <div class='modal-footer'>\n"
"      <button class='btn btn-secondary' onclick='closeModal(\"bulk-modal\")'>キャンセル</button>\n"
"      <button class='btn btn-primary' onclick='saveBulk()'>生成</button>\n"
"    </div>\n"
"  </div>\n"
"</div>\n"
"\n"
"<script>\n"
"// ─── Key Management ──────────────────────────────────────────────────────────\n"
"let adminKey = localStorage.getItem('asoview_admin_key') || '';\n"
"document.getElementById('admin-key').value = adminKey;\n"
"function saveKey() {\n"
"  adminKey = document.getElementById('admin-key').value.trim();\n"
"  localStorage.setItem('asoview_admin_key', adminKey);\n"
"  showTab(currentTab || 'venues');\n"
"}\n"
"function clearKey() {\n"
"  adminKey = ''; localStorage.removeItem('asoview_admin_key');\n"
"  document.getElementById('admin-key').value = '';\n"
"}\n"
"function headers() { return {'Content-Type':'application/json','X-Admin-Key':adminKey}; }\n"
"async function api(method, path, body) {\n"
"  const opts = {method, headers: headers()};\n"
"  if (body) opts.body = JSON.stringify(body);\n"
"  const r = await fetch(path, opts);\n"
"  return {ok: r.ok, status: r.status, data: await r.json().catch(()=>{})};\n"
"}\n"
"\n"
"// ─── Tab Navigation ───────────────────────────────────────────────────────────\n"
"let currentTab = 'venues';\n"
"function showTab(tab) {\n"
"  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));\n"
"  document.querySelectorAll('#sidebar nav a').forEach(a => a.classList.remove('active'));\n"
"  document.getElementById('tab-' + tab).classList.add('active');\n"
"  document.getElementById('nav-' + tab).classList.add('active');\n"
"  currentTab = tab;\n"
"  if (tab === 'venues')    loadVenues();\n"
"  if (tab === 'plans')     { loadPlans(); loadPlanSelect(); }\n"
"  if (tab === 'schedules') { loadPlanSelect(); }\n"
"  if (tab === 'bookings')  loadBookings();\n"
"  if (tab === 'users')     loadUsers();\n"
"}\n"
"\n"
"// ─── Modal helpers ────────────────────────────────────────────────────────────\n"
"function openModal(id) { document.getElementById(id).classList.add('open'); }\n"
"function closeModal(id) { document.getElementById(id).classList.remove('open'); }\n"
"function showMsg(elId, ok, txt) {\n"
"  const el = document.getElementById(elId);\n"
"  if (!el) return;\n"
"  el.innerHTML = `<div class='msg ${ok?'ok':'err'}'>${txt}</div>`;\n"
"  setTimeout(() => { el.innerHTML = ''; }, 4000);\n"
"}\n"
"function statusBadge(s) {\n"
"  const cls = s==='confirmed'?'badge-green':s==='cancelled'||s==='refunded'?'badge-red':'badge-blue';\n"
"  return `<span class='badge ${cls}'>${s}</span>`;\n"
"}\n"
"\n"
"// ─── VENUES ───────────────────────────────────────────────────────────────────\n"
"async function loadVenues() {\n"
"  const r = await api('GET', '/api/v1/admin/venues?limit=200');\n"
"  if (!r.ok) { showMsg('venues-msg', false, r.data?.error || 'エラー'); return; }\n"
"  const tbody = document.querySelector('#venues-table tbody');\n"
"  tbody.innerHTML = (r.data.venues || []).map(v =>\n"
"    `<tr><td>${v.id}</td><td>${v.name}</td><td>${v.area_name||v.area_id}</td><td>${v.address||''}</td>\n"
"     <td class='actions'>\n"
"       <button class='btn btn-secondary' onclick='editVenue(${v.id},${JSON.stringify(v).replace(/\"/g,\"&quot;\")})'>編集</button>\n"
"       <button class='btn btn-danger' onclick='deleteVenue(${v.id})'>削除</button>\n"
"     </td></tr>`\n"
"  ).join('');\n"
"}\n"
"function openVenueModal() {\n"
"  document.getElementById('venue-id').value = '';\n"
"  document.getElementById('venue-modal-title').textContent = '施設を追加';\n"
"  ['venue-name','venue-area-id','venue-address','venue-phone','venue-website','venue-desc'].forEach(id => document.getElementById(id).value = '');\n"
"  openModal('venue-modal');\n"
"}\n"
"function editVenue(id, v) {\n"
"  document.getElementById('venue-id').value = id;\n"
"  document.getElementById('venue-modal-title').textContent = '施設を編集';\n"
"  document.getElementById('venue-name').value = v.name || '';\n"
"  document.getElementById('venue-area-id').value = v.area_id || '';\n"
"  document.getElementById('venue-address').value = v.address || '';\n"
"  document.getElementById('venue-phone').value = v.phone || '';\n"
"  document.getElementById('venue-website').value = v.website || '';\n"
"  document.getElementById('venue-desc').value = v.description || '';\n"
"  openModal('venue-modal');\n"
"}\n"
"async function saveVenue() {\n"
"  const id = document.getElementById('venue-id').value;\n"
"  const body = {\n"
"    name: document.getElementById('venue-name').value,\n"
"    area_id: +document.getElementById('venue-area-id').value,\n"
"    address: document.getElementById('venue-address').value,\n"
"    phone: document.getElementById('venue-phone').value,\n"
"    website: document.getElementById('venue-website').value,\n"
"    description: document.getElementById('venue-desc').value\n"
"  };\n"
"  const r = id ? await api('PATCH',`/api/v1/admin/venues/${id}`,body)\n"
"               : await api('POST','/api/v1/admin/venues',body);\n"
"  showMsg('venue-modal-msg', r.ok, r.ok ? '保存しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) { closeModal('venue-modal'); loadVenues(); }\n"
"}\n"
"async function deleteVenue(id) {\n"
"  if (!confirm('この施設を削除しますか？')) return;\n"
"  const r = await api('DELETE', `/api/v1/admin/venues/${id}`);\n"
"  showMsg('venues-msg', r.ok, r.ok ? '削除しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) loadVenues();\n"
"}\n"
"\n"
"// ─── PLANS ────────────────────────────────────────────────────────────────────\n"
"async function loadPlans() {\n"
"  const r = await api('GET', '/api/v1/admin/plans?limit=200');\n"
"  if (!r.ok) { showMsg('plans-msg', false, r.data?.error || 'エラー'); return; }\n"
"  const tbody = document.querySelector('#plans-table tbody');\n"
"  tbody.innerHTML = (r.data.plans || []).map(p =>\n"
"    `<tr><td>${p.id}</td><td>${p.title}</td><td>${p.venue_name||p.venue_id}</td>\n"
"     <td>${p.is_active?`<span class='badge badge-green'>Yes</span>`:`<span class='badge badge-grey'>No</span>`}</td>\n"
"     <td class='actions'>\n"
"       <button class='btn btn-secondary' onclick='editPlan(${p.id},${JSON.stringify(p).replace(/\"/g,\"&quot;\")})'>編集</button>\n"
"       <button class='btn btn-danger' onclick='deletePlan(${p.id})'>削除</button>\n"
"     </td></tr>`\n"
"  ).join('');\n"
"}\n"
"async function loadPlanSelect() {\n"
"  const r = await api('GET', '/api/v1/admin/plans?limit=200');\n"
"  if (!r.ok) return;\n"
"  const sel = document.getElementById('sched-plan-sel');\n"
"  const cur = sel.value;\n"
"  sel.innerHTML = '<option value=\"\">-- Plan を選択 --</option>' +\n"
"    (r.data.plans || []).map(p => `<option value='${p.id}'>${p.id}: ${p.title}</option>`).join('');\n"
"  if (cur) sel.value = cur;\n"
"}\n"
"function openPlanModal() {\n"
"  document.getElementById('plan-id').value = '';\n"
"  document.getElementById('plan-modal-title').textContent = 'プランを追加';\n"
"  ['plan-venue-id','plan-cat-id','plan-title','plan-desc','plan-dur','plan-minp','plan-maxp'].forEach(id => document.getElementById(id).value = '');\n"
"  openModal('plan-modal');\n"
"}\n"
"function editPlan(id, p) {\n"
"  document.getElementById('plan-id').value = id;\n"
"  document.getElementById('plan-modal-title').textContent = 'プランを編集';\n"
"  document.getElementById('plan-venue-id').value = p.venue_id || '';\n"
"  document.getElementById('plan-cat-id').value = p.category_id || '';\n"
"  document.getElementById('plan-title').value = p.title || '';\n"
"  document.getElementById('plan-desc').value = p.description || '';\n"
"  document.getElementById('plan-dur').value = p.duration_minutes || '';\n"
"  document.getElementById('plan-minp').value = p.min_participants || '';\n"
"  document.getElementById('plan-maxp').value = p.max_participants || '';\n"
"  openModal('plan-modal');\n"
"}\n"
"async function savePlan() {\n"
"  const id = document.getElementById('plan-id').value;\n"
"  const body = {\n"
"    venue_id: +document.getElementById('plan-venue-id').value,\n"
"    category_id: +document.getElementById('plan-cat-id').value,\n"
"    title: document.getElementById('plan-title').value,\n"
"    description: document.getElementById('plan-desc').value,\n"
"    duration_minutes: +document.getElementById('plan-dur').value,\n"
"    min_participants: +document.getElementById('plan-minp').value,\n"
"    max_participants: +document.getElementById('plan-maxp').value\n"
"  };\n"
"  const r = id ? await api('PATCH',`/api/v1/admin/plans/${id}`,body)\n"
"               : await api('POST','/api/v1/admin/plans',body);\n"
"  showMsg('plan-modal-msg', r.ok, r.ok ? '保存しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) { closeModal('plan-modal'); loadPlans(); }\n"
"}\n"
"async function deletePlan(id) {\n"
"  if (!confirm('このプランを非公開にしますか？')) return;\n"
"  const r = await api('DELETE', `/api/v1/admin/plans/${id}`);\n"
"  showMsg('plans-msg', r.ok, r.ok ? '非公開にしました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) loadPlans();\n"
"}\n"
"\n"
"// ─── SCHEDULES ────────────────────────────────────────────────────────────────\n"
"async function loadSchedules() {\n"
"  const pid = document.getElementById('sched-plan-sel').value;\n"
"  if (!pid) return;\n"
"  const r = await api('GET', `/api/v1/plans/${pid}/schedules`);\n"
"  const tbody = document.querySelector('#schedules-table tbody');\n"
"  tbody.innerHTML = (!r.ok ? '<tr><td colspan=7>読み込みエラー</td></tr>' :\n"
"    (r.data.schedules || []).map(s =>\n"
"      `<tr><td>${s.id}</td><td>${s.date}</td><td>${s.start_time}</td><td>${s.end_time||''}</td>\n"
"       <td>${s.capacity}</td><td>${s.booked_count||0}</td>\n"
"       <td class='actions'>\n"
"         <button class='btn btn-danger' onclick='deleteSched(${s.id})'>削除</button>\n"
"       </td></tr>`\n"
"    ).join('') || '<tr><td colspan=7>データなし</td></tr>'\n"
"  );\n"
"}\n"
"function openSchedModal() {\n"
"  const pid = document.getElementById('sched-plan-sel').value;\n"
"  if (!pid) { alert('先に Plan を選択してください'); return; }\n"
"  ['sched-date','sched-start','sched-end'].forEach(id => document.getElementById(id).value = '');\n"
"  document.getElementById('sched-cap').value = '10';\n"
"  openModal('sched-modal');\n"
"}\n"
"async function saveSched() {\n"
"  const pid = document.getElementById('sched-plan-sel').value;\n"
"  const body = {\n"
"    date: document.getElementById('sched-date').value,\n"
"    start_time: document.getElementById('sched-start').value,\n"
"    end_time: document.getElementById('sched-end').value || null,\n"
"    capacity: +document.getElementById('sched-cap').value\n"
"  };\n"
"  const r = await api('POST', `/api/v1/admin/plans/${pid}/schedules`, body);\n"
"  showMsg('sched-modal-msg', r.ok, r.ok ? '追加しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) { closeModal('sched-modal'); loadSchedules(); }\n"
"}\n"
"async function deleteSched(id) {\n"
"  if (!confirm('このスケジュールを削除しますか？')) return;\n"
"  const r = await api('DELETE', `/api/v1/admin/schedules/${id}`);\n"
"  showMsg('schedules-msg', r.ok, r.ok ? '削除しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) loadSchedules();\n"
"}\n"
"function openBulkModal() {\n"
"  const pid = document.getElementById('sched-plan-sel').value;\n"
"  if (!pid) { alert('先に Plan を選択してください'); return; }\n"
"  document.querySelectorAll('input[name=wd]').forEach(cb => cb.checked = false);\n"
"  ['bulk-start-date','bulk-end-date','bulk-end'].forEach(id => document.getElementById(id).value = '');\n"
"  document.getElementById('bulk-start').value = '10:00';\n"
"  document.getElementById('bulk-cap').value = '10';\n"
"  openModal('bulk-modal');\n"
"}\n"
"async function saveBulk() {\n"
"  const pid = document.getElementById('sched-plan-sel').value;\n"
"  const wds = [...document.querySelectorAll('input[name=wd]:checked')].map(cb => +cb.value);\n"
"  const body = {\n"
"    start_date: document.getElementById('bulk-start-date').value,\n"
"    end_date: document.getElementById('bulk-end-date').value,\n"
"    start_time: document.getElementById('bulk-start').value,\n"
"    end_time: document.getElementById('bulk-end').value || null,\n"
"    capacity: +document.getElementById('bulk-cap').value\n"
"  };\n"
"  if (wds.length > 0) body.weekdays = wds;\n"
"  const r = await api('POST', `/api/v1/admin/plans/${pid}/schedules/bulk`, body);\n"
"  showMsg('bulk-modal-msg', r.ok,\n"
"    r.ok ? `${r.data.created} 件生成しました` : (r.data?.error || 'エラー'));\n"
"  if (r.ok) { closeModal('bulk-modal'); loadSchedules(); }\n"
"}\n"
"\n"
"// ─── BOOKINGS ─────────────────────────────────────────────────────────────────\n"
"async function loadBookings() {\n"
"  const q = document.getElementById('bookings-search').value;\n"
"  const r = await api('GET', `/api/v1/admin/bookings?limit=100${q?'&q='+encodeURIComponent(q):''}`);\n"
"  if (!r.ok) return;\n"
"  const tbody = document.querySelector('#bookings-table tbody');\n"
"  tbody.innerHTML = (r.data.bookings || []).map(b =>\n"
"    `<tr><td style='font-size:11px;max-width:100px;overflow:hidden;text-overflow:ellipsis;'>${b.id}</td>\n"
"     <td>${b.user_email||b.user_id||''}</td>\n"
"     <td>${b.schedule_id}</td>\n"
"     <td>${statusBadge(b.status)}</td>\n"
"     <td>${b.total_amount!=null?'¥'+b.total_amount.toLocaleString():''}</td>\n"
"     <td style='font-size:11px;'>${(b.created_at||'').slice(0,16)}</td>\n"
"     <td class='actions'>\n"
"       ${b.status!=='refunded'&&b.status!=='cancelled'?`<button class='btn btn-secondary' onclick='refundBooking(\"${b.id}\")'>返金</button>`:''}\n"
"     </td></tr>`\n"
"  ).join('');\n"
"}\n"
"async function refundBooking(id) {\n"
"  if (!confirm('この予約を返金しますか？（取り消せません）')) return;\n"
"  const r = await api('POST', `/api/v1/admin/bookings/${id}/refund`);\n"
"  alert(r.ok ? '返金しました' : (r.data?.error || '返金エラー'));\n"
"  if (r.ok) loadBookings();\n"
"}\n"
"\n"
"// ─── USERS ────────────────────────────────────────────────────────────────────\n"
"async function loadUsers() {\n"
"  const q = document.getElementById('users-search').value;\n"
"  const r = await api('GET', `/api/v1/admin/users?limit=100${q?'&q='+encodeURIComponent(q):''}`);\n"
"  if (!r.ok) return;\n"
"  const tbody = document.querySelector('#users-table tbody');\n"
"  tbody.innerHTML = (r.data.users || []).map(u =>\n"
"    `<tr><td>${u.id}</td><td>${u.name||''}</td><td>${u.email}</td>\n"
"     <td>${u.booking_count}</td>\n"
"     <td style='font-size:11px;'>${(u.created_at||'').slice(0,10)}</td></tr>`\n"
"  ).join('');\n"
"}\n"
"\n"
"// ─── Init ─────────────────────────────────────────────────────────────────────\n"
"showTab('venues');\n"
"</script>\n"
"</body></html>\n";

    mg_http_reply(c, 200, "Content-Type: text/html; charset=utf-8\r\n", "%s", HTML);
}

/* ─── GET /api/v1/admin/audit-logs ─────────────────────────────────────────── */

void handle_admin_audit_logs(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;

    long page  = 1, limit = 50;
    char pv[16] = {0}, lv[16] = {0};
    mg_http_get_var(&hm->query, "page",  pv, sizeof(pv));
    mg_http_get_var(&hm->query, "limit", lv, sizeof(lv));
    if (pv[0])  page  = atol(pv);
    if (lv[0])  limit = atol(lv);
    if (page  < 1)   page  = 1;
    if (limit < 1)   limit = 1;
    if (limit > 200) limit = 200;
    long offset = (page - 1) * limit;

    /* 総件数 */
    DbStmt *ct = NULL;
    ct = db_prepare(db, "SELECT COUNT(*) FROM audit_logs");
    db_step(ct);
    long total = db_col_int(ct, 0);
    db_finalize(ct);

    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT id,ts,actor,action,target_type,target_id,detail,ip "
        "FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?");
    db_bind_int(st, 1, limit);
    db_bind_int(st, 2, offset);

    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *row = cJSON_CreateObject();
        cJSON_AddNumberToObject(row, "id",          db_col_int(st, 0));
        cJSON_AddStringToObject(row, "ts",          db_col_text(st, 1) ? db_col_text(st, 1) : "");
        cJSON_AddStringToObject(row, "actor",       db_col_text(st, 2) ? db_col_text(st, 2) : "");
        cJSON_AddStringToObject(row, "action",      db_col_text(st, 3) ? db_col_text(st, 3) : "");
        cJSON_AddStringToObject(row, "target_type", db_col_text(st, 4) ? db_col_text(st, 4) : "");
        cJSON_AddStringToObject(row, "target_id",   db_col_text(st, 5) ? db_col_text(st, 5) : "");
        cJSON_AddStringToObject(row, "detail",      db_col_text(st, 6) ? db_col_text(st, 6) : "");
        cJSON_AddStringToObject(row, "ip",          db_col_text(st, 7) ? db_col_text(st, 7) : "");
        cJSON_AddItemToArray(arr, row);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "logs",  arr);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}
