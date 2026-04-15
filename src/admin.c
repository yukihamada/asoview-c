#include "admin.h"
#include "handlers.h"   /* send_json_str, send_error_json, totp_verify */
#include "audit.h"
#include "platform.h"
#include "cJSON.h"
#include "stripe.h"
#include "mailer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
    /* ADMIN_TOTP_SECRET が設定されている場合は X-Admin-TOTP ヘッダも検証 */
    const char *totp_secret = getenv("ADMIN_TOTP_SECRET");
    if (totp_secret && *totp_secret) {
        struct mg_str *totp_hdr = mg_http_get_header(hm, "X-Admin-TOTP");
        if (!totp_hdr) {
            send_error_json(c, 403, "管理者 TOTP コードが必要です (X-Admin-TOTP)"); return 0;
        }
        char code_buf[8] = {0};
        size_t n = totp_hdr->len < 7 ? totp_hdr->len : 7;
        memcpy(code_buf, totp_hdr->buf, n);
        if (!totp_verify(totp_secret, code_buf)) {
            send_error_json(c, 403, "TOTP コードが不正です"); return 0;
        }
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
"    <a href='#' onclick='showTab(\"reviews\")' id='nav-reviews'>Reviews</a>\n"
"    <a href='#' onclick='showTab(\"coupons\")' id='nav-coupons'>Coupons</a>\n"
"    <a href='#' onclick='showTab(\"webhooks\")' id='nav-webhooks'>Webhooks</a>\n"
"    <a href='#' onclick='showTab(\"audit\")' id='nav-audit'>Audit Log</a>\n"
"    <a href='#' onclick='showTab(\"dashboard\")' id='nav-dashboard'>&#128200; Dashboard</a>\n"
"    <a href='#' onclick='showTab(\"tenants\")' id='nav-tenants'>Tenants</a>\n"
"    <a href='#' onclick='showTab(\"giftcards\")' id='nav-giftcards'>Gift Cards</a>\n"
"    <a href='#' onclick='showTab(\"staff\")' id='nav-staff'>Staff</a>\n"
"    <a href='/docs' target='_blank' style='margin-top:auto;border-top:1px solid var(--border);'>&#128196; API Docs</a>\n"
"    <a href='/ui' target='_blank'>&#127760; ユーザーサイト</a>\n"
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
"    <div id='prices-section' style='display:none;margin-top:20px;'>\n"
"      <h3 id='prices-title' style='font-size:15px;margin-bottom:8px;'>料金設定</h3>\n"
"      <div id='prices-msg'></div>\n"
"      <div id='prices-list' style='margin-bottom:10px;'></div>\n"
"      <button class='btn btn-secondary' onclick='addPriceRow()'>+ 料金を追加</button>\n"
"      <button class='btn btn-primary' style='margin-left:8px;' onclick='savePrices()'>保存</button>\n"
"      <button class='btn btn-secondary' style='margin-left:8px;' onclick='closePrices()'>閉じる</button>\n"
"    </div>\n"
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
"  <!-- REVIEWS TAB -->\n"
"  <div class='tab' id='tab-reviews'>\n"
"    <div id='reviews-msg'></div>\n"
"    <div class='toolbar'><h2>Reviews</h2></div>\n"
"    <table id='reviews-table'><thead><tr><th>ID</th><th>Plan</th><th>User</th><th>Rating</th><th>Comment</th><th>Created</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- COUPONS TAB -->\n"
"  <div class='tab' id='tab-coupons'>\n"
"    <div id='coupons-msg'></div>\n"
"    <div class='toolbar'><h2>Coupons</h2><button class='btn btn-primary' onclick='openCouponModal()'>+ 追加</button></div>\n"
"    <table id='coupons-table'><thead><tr><th>ID</th><th>Code</th><th>Type</th><th>Value</th><th>Used/Max</th><th>Expires</th><th>Active</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- WEBHOOKS TAB -->\n"
"  <div class='tab' id='tab-webhooks'>\n"
"    <div id='webhooks-msg'></div>\n"
"    <div class='toolbar'><h2>Webhooks</h2><button class='btn btn-primary' onclick='openWebhookModal()'>+ 追加</button></div>\n"
"    <table id='webhooks-table'><thead><tr><th>ID</th><th>URL</th><th>Events</th><th>Active</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- AUDIT LOG TAB -->\n"
"  <div class='tab' id='tab-audit'>\n"
"    <div class='toolbar'>\n"
"      <h2>Audit Log</h2>\n"
"      <div style='display:flex;gap:8px;align-items:center;'>\n"
"        <span style='font-size:12px;color:var(--muted)'>直近200件</span>\n"
"        <button class='btn btn-secondary' onclick='loadAudit()'>&#8635; 更新</button>\n"
"      </div>\n"
"    </div>\n"
"    <table id='audit-table'><thead><tr><th>時刻</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- TENANTS TAB -->\n"
"  <div class='tab' id='tab-tenants'>\n"
"    <div id='tenants-msg'></div>\n"
"    <div class='toolbar'><h2>Tenants</h2><button class='btn btn-primary' onclick='openTenantModal()'>+ 追加</button></div>\n"
"    <table id='tenants-table'><thead><tr><th>ID</th><th>Slug</th><th>Name</th><th>API Key</th><th>Plan Limit</th><th>Active</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- DASHBOARD TAB -->\n"
"  <div class='tab' id='tab-dashboard'>\n"
"    <div class='toolbar'><h2>Dashboard</h2><div style='display:flex;gap:8px;'>"
"<input type='date' id='dash-from' style='background:var(--input);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:4px;font-size:12px;'>"
"<input type='date' id='dash-to'   style='background:var(--input);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:4px;font-size:12px;'>"
"<button class='btn btn-secondary' onclick='loadDashboard()'>更新</button>"
"</div></div>\n"
"    <div id='dash-kpi' style='display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:20px;'></div>\n"
"    <div style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:20px;'>\n"
"      <h3 style='font-size:14px;color:var(--muted);margin-bottom:12px;'>日別売上（確定予約）</h3>\n"
"      <canvas id='dash-chart' height='80'></canvas>\n"
"    </div>\n"
"    <div style='display:grid;grid-template-columns:1fr 1fr;gap:16px;'>\n"
"      <div>\n"
"        <h3 style='font-size:14px;color:var(--muted);margin-bottom:8px;'>プラン別売上 Top10</h3>\n"
"        <table id='dash-plan-table'><thead><tr><th>Plan</th><th>件数</th><th>売上</th></tr></thead><tbody></tbody></table>\n"
"      </div>\n"
"      <div>\n"
"        <h3 style='font-size:14px;color:var(--muted);margin-bottom:8px;'>会場別売上 Top10</h3>\n"
"        <table id='dash-venue-table'><thead><tr><th>Venue</th><th>件数</th><th>売上</th></tr></thead><tbody></tbody></table>\n"
"      </div>\n"
"    </div>\n"
"  </div>\n"
"\n"
"  <!-- GIFT CARDS TAB -->\n"
"  <div class='tab' id='tab-giftcards'>\n"
"    <div id='giftcards-msg'></div>\n"
"    <div class='toolbar'><h2>Gift Cards</h2><button class='btn btn-primary' onclick='openGiftCardModal()'>+ 発行</button></div>\n"
"    <table id='giftcards-table'><thead><tr><th>ID</th><th>Code</th><th>初期金額</th><th>残高</th><th>発行先</th><th>有効期限</th><th>状態</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
"  </div>\n"
"\n"
"  <!-- STAFF TAB -->\n"
"  <div class='tab' id='tab-staff'>\n"
"    <div id='staff-msg'></div>\n"
"    <div class='toolbar'><h2>Staff</h2><button class='btn btn-primary' onclick='openStaffModal()'>+ 割り当て</button></div>\n"
"    <table id='staff-table'><thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>担当会場</th><th>Actions</th></tr></thead><tbody></tbody></table>\n"
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
"<!-- COUPON MODAL -->\n"
"<div class='overlay' id='coupon-modal'>\n"
"  <div class='modal'>\n"
"    <h3>クーポンを追加</h3>\n"
"    <div id='coupon-modal-msg'></div>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>コード *</label><input id='coupon-code' type='text' placeholder='SUMMER20'></div>\n"
"      <div class='form-group'><label>種別</label>\n"
"        <select id='coupon-type'><option value='percent'>割引率(%)</option><option value='amount'>固定額(円)</option></select>\n"
"      </div>\n"
"    </div>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>割引値 *</label><input id='coupon-value' type='number' min='1'></div>\n"
"      <div class='form-group'><label>最大利用数</label><input id='coupon-maxuses' type='number' placeholder='無制限'></div>\n"
"    </div>\n"
"    <div class='form-group'><label>有効期限</label><input id='coupon-expires' type='date'></div>\n"
"    <div class='form-group'><label>説明</label><input id='coupon-desc' type='text'></div>\n"
"    <div class='modal-footer'>\n"
"      <button class='btn btn-secondary' onclick='closeModal(\"coupon-modal\")'>キャンセル</button>\n"
"      <button class='btn btn-primary' onclick='saveCoupon()'>保存</button>\n"
"    </div>\n"
"  </div>\n"
"</div>\n"
"\n"
"<!-- WEBHOOK MODAL -->\n"
"<div class='overlay' id='webhook-modal'>\n"
"  <div class='modal'>\n"
"    <h3>Webhook エンドポイントを追加</h3>\n"
"    <div id='webhook-modal-msg'></div>\n"
"    <div class='form-group'><label>URL *</label><input id='wh-url' type='url' placeholder='https://example.com/webhook'></div>\n"
"    <div class='form-group'><label>シークレット *</label><input id='wh-secret' type='text' placeholder='署名検証用シークレット'></div>\n"
"    <div class='form-group'><label>イベント（カンマ区切り）</label><input id='wh-events' type='text' placeholder='booking.created,booking.cancelled'></div>\n"
"    <div class='modal-footer'>\n"
"      <button class='btn btn-secondary' onclick='closeModal(\"webhook-modal\")'>キャンセル</button>\n"
"      <button class='btn btn-primary' onclick='saveWebhook()'>保存</button>\n"
"    </div>\n"
"  </div>\n"
"</div>\n"
"\n"
"<!-- TENANT MODAL -->\n"
"<div class='overlay' id='tenant-modal'>\n"
"  <div class='modal'>\n"
"    <h3 id='tenant-modal-title'>テナントを追加</h3>\n"
"    <div id='tenant-modal-msg'></div>\n"
"    <input type='hidden' id='tenant-id'>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>Slug *</label><input id='tenant-slug' type='text' placeholder='acme'></div>\n"
"      <div class='form-group'><label>名前 *</label><input id='tenant-name' type='text' placeholder='Acme Corp'></div>\n"
"    </div>\n"
"    <div class='form-row'>\n"
"      <div class='form-group'><label>Plan上限</label><input id='tenant-limit' type='number' value='100'></div>\n"
"      <div class='form-group'><label>有効</label>\n"
"        <select id='tenant-active'><option value='true'>有効</option><option value='false'>無効</option></select>\n"
"      </div>\n"
"    </div>\n"
"    <div class='modal-footer'>\n"
"      <button class='btn btn-secondary' onclick='closeModal(\"tenant-modal\")'>キャンセル</button>\n"
"      <button class='btn btn-primary' onclick='saveTenant()'>保存</button>\n"
"    </div>\n"
"  </div>\n"
"</div>\n"
"\n"
"<!-- GIFT CARD MODAL -->\n"
"<div class='overlay' id='giftcard-modal'>\n"
"  <div class='modal'>\n"
"    <h3>ギフトカードを発行</h3>\n"
"    <div id='giftcard-modal-msg'></div>\n"
"    <div class='form-group'><label>金額（円） *</label><input id='gc-amount' type='number' min='100' placeholder='5000'></div>\n"
"    <div class='form-group'><label>発行先メール（任意）</label><input id='gc-email' type='email' placeholder='user@example.com'></div>\n"
"    <div class='form-group'><label>有効期限（任意）</label><input id='gc-expires' type='date'></div>\n"
"    <div class='modal-footer'>\n"
"      <button class='btn btn-secondary' onclick='closeModal(\"giftcard-modal\")'>キャンセル</button>\n"
"      <button class='btn btn-primary' onclick='saveGiftCard()'>発行</button>\n"
"    </div>\n"
"  </div>\n"
"</div>\n"
"\n"
"<!-- STAFF MODAL -->\n"
"<div class='overlay' id='staff-modal'>\n"
"  <div class='modal'>\n"
"    <h3>スタッフに会場を割り当て</h3>\n"
"    <div id='staff-modal-msg'></div>\n"
"    <div class='form-group'><label>ユーザーID *</label><input id='staff-uid' type='number' placeholder='ユーザーID'></div>\n"
"    <div class='form-group'><label>会場ID *</label><input id='staff-vid' type='number' placeholder='会場ID'></div>\n"
"    <div class='form-group'><label>ロール</label><select id='staff-role'><option value='staff'>Staff</option><option value='admin'>Admin</option></select></div>\n"
"    <div class='modal-footer'>\n"
"      <button class='btn btn-secondary' onclick='closeModal(\"staff-modal\")'>キャンセル</button>\n"
"      <button class='btn btn-primary' onclick='saveStaff()'>割り当て</button>\n"
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
"  if (tab === 'reviews')   loadReviews();\n"
"  if (tab === 'coupons')   loadCoupons();\n"
"  if (tab === 'webhooks')  loadWebhooks();\n"
"  if (tab === 'audit')     loadAudit();\n"
"  if (tab === 'tenants')   loadTenants();\n"
"  if (tab === 'giftcards') loadGiftCards();\n"
"  if (tab === 'staff')     loadStaff();\n"
"  if (tab === 'dashboard') loadDashboard();\n"
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
"       <button class='btn btn-secondary' onclick='openPrices(${p.id},${JSON.stringify(p.title||'').replace(/\"/g,\"&quot;\")})'>料金</button>\n"
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
"// ─── PLAN PRICES ────────────────────────────────────────────────────────────────\n"
"let currentPricesPlanId = null;\n"
"async function openPrices(pid, title) {\n"
"  currentPricesPlanId = pid;\n"
"  document.getElementById('prices-title').textContent = `料金設定 — Plan ${pid}: ${title}`;\n"
"  document.getElementById('prices-section').style.display = 'block';\n"
"  document.getElementById('prices-section').scrollIntoView({behavior:'smooth'});\n"
"  // 既存料金を取得して表示\n"
"  const r = await api('GET', `/api/v1/plans/${pid}`);\n"
"  const prices = r.ok ? (r.data.prices || []) : [];\n"
"  document.getElementById('prices-list').innerHTML = '';\n"
"  if (prices.length === 0) { addPriceRow(); } else { prices.forEach(p => addPriceRow(p)); }\n"
"}\n"
"function closePrices() {\n"
"  document.getElementById('prices-section').style.display = 'none';\n"
"  currentPricesPlanId = null;\n"
"}\n"
"function addPriceRow(p={}) {\n"
"  const list = document.getElementById('prices-list');\n"
"  const row = document.createElement('div');\n"
"  row.style.cssText = 'display:flex;gap:8px;align-items:center;margin-bottom:8px;';\n"
"  row.innerHTML = `\n"
"    <input type='text' placeholder='participant_type (adult)' value='${p.participant_type||'adult'}' style='width:140px;background:var(--input);border:1px solid var(--border);color:var(--text);padding:6px;border-radius:4px;font-size:12px;'>\n"
"    <input type='text' placeholder='ラベル (大人)' value='${p.label||'大人'}' style='width:120px;background:var(--input);border:1px solid var(--border);color:var(--text);padding:6px;border-radius:4px;font-size:12px;'>\n"
"    <input type='number' placeholder='価格(円)' value='${p.price||0}' style='width:100px;background:var(--input);border:1px solid var(--border);color:var(--text);padding:6px;border-radius:4px;font-size:12px;'>\n"
"    <button style='background:var(--danger);color:#fff;border:none;border-radius:4px;padding:5px 8px;cursor:pointer;font-size:12px;' onclick='this.parentElement.remove()'>✕</button>\n"
"  `;\n"
"  list.appendChild(row);\n"
"}\n"
"async function savePrices() {\n"
"  if (!currentPricesPlanId) return;\n"
"  const rows = document.querySelectorAll('#prices-list > div');\n"
"  const prices = [...rows].map(row => {\n"
"    const inputs = row.querySelectorAll('input');\n"
"    return { participant_type: inputs[0].value, label: inputs[1].value, price: +inputs[2].value };\n"
"  }).filter(p => p.participant_type && p.price > 0);\n"
"  const r = await api('PUT', `/api/v1/admin/plans/${currentPricesPlanId}/prices`, {prices});\n"
"  showMsg('prices-msg', r.ok, r.ok ? '保存しました' : (r.data?.error || 'エラー'));\n"
"}\n"
"\n"
"// ─── REVIEWS ──────────────────────────────────────────────────────────────────\n"
"async function loadReviews() {\n"
"  const r = await api('GET', '/api/v1/admin/reviews?limit=100');\n"
"  if (!r.ok) { showMsg('reviews-msg', false, r.data?.error || 'エラー'); return; }\n"
"  const tbody = document.querySelector('#reviews-table tbody');\n"
"  tbody.innerHTML = (r.data.reviews || []).map(v =>\n"
"    `<tr><td>${v.id}</td><td>${v.plan_id}</td><td>${v.user_id}</td>\n"
"     <td>${'★'.repeat(v.rating||0)}</td>\n"
"     <td style='max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>${v.comment||''}</td>\n"
"     <td style='font-size:11px;'>${(v.created_at||'').slice(0,10)}</td>\n"
"     <td class='actions'>\n"
"       <button class='btn btn-danger' onclick='deleteReview(${v.id})'>削除</button>\n"
"     </td></tr>`\n"
"  ).join('');\n"
"}\n"
"async function deleteReview(id) {\n"
"  if (!confirm('このレビューを削除しますか？')) return;\n"
"  const r = await api('DELETE', `/api/v1/admin/reviews/${id}`);\n"
"  showMsg('reviews-msg', r.ok, r.ok ? '削除しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) loadReviews();\n"
"}\n"
"\n"
"// ─── COUPONS ──────────────────────────────────────────────────────────────────\n"
"async function loadCoupons() {\n"
"  const r = await api('GET', '/api/v1/admin/coupons');\n"
"  if (!r.ok) { showMsg('coupons-msg', false, r.data?.error || 'エラー'); return; }\n"
"  const tbody = document.querySelector('#coupons-table tbody');\n"
"  tbody.innerHTML = (r.data.coupons || []).map(cp =>\n"
"    `<tr><td>${cp.id}</td><td><code>${cp.code}</code></td>\n"
"     <td>${cp.discount_type}</td>\n"
"     <td>${cp.discount_type==='percent'?cp.discount_value+'%':'¥'+cp.discount_value}</td>\n"
"     <td>${cp.used_count}/${cp.max_uses||'∞'}</td>\n"
"     <td style='font-size:11px;'>${cp.expires_at||'無期限'}</td>\n"
"     <td>${cp.is_active?\"<span class='badge badge-green'>有効</span>\":\"<span class='badge badge-grey'>無効</span>\"}</td>\n"
"     <td class='actions'>\n"
"       <button class='btn btn-danger' onclick='deleteCoupon(${cp.id})'>削除</button>\n"
"     </td></tr>`\n"
"  ).join('');\n"
"}\n"
"function openCouponModal() {\n"
"  ['coupon-code','coupon-value','coupon-maxuses','coupon-expires','coupon-desc'].forEach(id => document.getElementById(id).value = '');\n"
"  document.getElementById('coupon-type').value = 'percent';\n"
"  openModal('coupon-modal');\n"
"}\n"
"async function saveCoupon() {\n"
"  const mu = document.getElementById('coupon-maxuses').value;\n"
"  const ex = document.getElementById('coupon-expires').value;\n"
"  const body = {\n"
"    code: document.getElementById('coupon-code').value,\n"
"    discount_type: document.getElementById('coupon-type').value,\n"
"    discount_value: +document.getElementById('coupon-value').value,\n"
"    description: document.getElementById('coupon-desc').value || undefined\n"
"  };\n"
"  if (mu) body.max_uses = +mu;\n"
"  if (ex) body.expires_at = ex;\n"
"  const r = await api('POST', '/api/v1/admin/coupons', body);\n"
"  showMsg('coupon-modal-msg', r.ok, r.ok ? '作成しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) { closeModal('coupon-modal'); loadCoupons(); }\n"
"}\n"
"async function deleteCoupon(id) {\n"
"  if (!confirm('このクーポンを削除しますか？')) return;\n"
"  const r = await api('DELETE', `/api/v1/admin/coupons/${id}`);\n"
"  showMsg('coupons-msg', r.ok, r.ok ? '削除しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) loadCoupons();\n"
"}\n"
"\n"
"// ─── WEBHOOKS ─────────────────────────────────────────────────────────────────\n"
"async function loadWebhooks() {\n"
"  const r = await api('GET', '/api/v1/admin/webhooks');\n"
"  if (!r.ok) { showMsg('webhooks-msg', false, r.data?.error || 'エラー'); return; }\n"
"  const tbody = document.querySelector('#webhooks-table tbody');\n"
"  tbody.innerHTML = (r.data.endpoints || []).map(wh =>\n"
"    `<tr><td>${wh.id}</td>\n"
"     <td style='max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;'>${wh.url}</td>\n"
"     <td style='font-size:11px;'>${wh.events||'[]'}</td>\n"
"     <td>${wh.is_active?\"<span class='badge badge-green'>有効</span>\":\"<span class='badge badge-grey'>無効</span>\"}</td>\n"
"     <td class='actions'>\n"
"       <button class='btn btn-danger' onclick='deleteWebhook(${wh.id})'>削除</button>\n"
"     </td></tr>`\n"
"  ).join('');\n"
"}\n"
"function openWebhookModal() {\n"
"  ['wh-url','wh-secret','wh-events'].forEach(id => document.getElementById(id).value = '');\n"
"  openModal('webhook-modal');\n"
"}\n"
"async function saveWebhook() {\n"
"  const evStr = document.getElementById('wh-events').value;\n"
"  const events = evStr ? evStr.split(',').map(e=>e.trim()).filter(Boolean) : [];\n"
"  const body = {\n"
"    url: document.getElementById('wh-url').value,\n"
"    secret: document.getElementById('wh-secret').value,\n"
"    events\n"
"  };\n"
"  const r = await api('POST', '/api/v1/admin/webhooks', body);\n"
"  showMsg('webhook-modal-msg', r.ok, r.ok ? '追加しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) { closeModal('webhook-modal'); loadWebhooks(); }\n"
"}\n"
"async function deleteWebhook(id) {\n"
"  if (!confirm('このWebhookを削除しますか？')) return;\n"
"  const r = await api('DELETE', `/api/v1/admin/webhooks/${id}`);\n"
"  showMsg('webhooks-msg', r.ok, r.ok ? '削除しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) loadWebhooks();\n"
"}\n"
"\n"
"// ─── AUDIT LOG ────────────────────────────────────────────────────────────────\n"
"async function loadAudit() {\n"
"  const r = await api('GET', '/api/v1/admin/audit-logs?limit=200');\n"
"  if (!r.ok) return;\n"
"  const tbody = document.querySelector('#audit-table tbody');\n"
"  tbody.innerHTML = (r.data.logs || []).map(l =>\n"
"    `<tr>\n"
"     <td style='font-size:11px;white-space:nowrap;'>${(l.ts||'').slice(0,19)}</td>\n"
"     <td style='font-size:12px;'>${l.actor||''}</td>\n"
"     <td><code style='font-size:11px;'>${l.action||''}</code></td>\n"
"     <td style='font-size:11px;'>${l.target_type||''} ${l.target_id||''}</td>\n"
"     <td style='font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>${l.detail||''}</td>\n"
"     <td style='font-size:11px;color:var(--muted);'>${l.ip||''}</td>\n"
"    </tr>`\n"
"  ).join('');\n"
"}\n"
"\n"
"// ─── TENANTS ──────────────────────────────────────────────────────────────────\n"
"async function loadTenants() {\n"
"  const r = await api('GET', '/api/v1/admin/tenants');\n"
"  if (!r.ok) { showMsg('tenants-msg', false, r.data?.error || 'エラー'); return; }\n"
"  const tbody = document.querySelector('#tenants-table tbody');\n"
"  tbody.innerHTML = (r.data.tenants || []).map(t =>\n"
"    `<tr><td>${t.id}</td><td><code>${t.slug}</code></td><td>${t.name}</td>\n"
"     <td style='font-size:10px;font-family:monospace;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' title='${t.api_key}'>${t.api_key}</td>\n"
"     <td>${t.plan_limit}</td>\n"
"     <td>${t.is_active?\"<span class='badge badge-green'>有効</span>\":\"<span class='badge badge-grey'>無効</span>\"}</td>\n"
"     <td class='actions'>\n"
"       <button class='btn btn-secondary' onclick='editTenant(${t.id},${JSON.stringify(t).replace(/\"/g,\"&quot;\")})'>編集</button>\n"
"       <button class='btn btn-danger' onclick='deleteTenant(${t.id})'>削除</button>\n"
"     </td></tr>`\n"
"  ).join('');\n"
"}\n"
"function openTenantModal() {\n"
"  document.getElementById('tenant-id').value = '';\n"
"  document.getElementById('tenant-modal-title').textContent = 'テナントを追加';\n"
"  document.getElementById('tenant-slug').disabled = false;\n"
"  ['tenant-slug','tenant-name'].forEach(id => document.getElementById(id).value = '');\n"
"  document.getElementById('tenant-limit').value = '100';\n"
"  document.getElementById('tenant-active').value = 'true';\n"
"  openModal('tenant-modal');\n"
"}\n"
"function editTenant(id, t) {\n"
"  document.getElementById('tenant-id').value = id;\n"
"  document.getElementById('tenant-modal-title').textContent = 'テナントを編集';\n"
"  document.getElementById('tenant-slug').value = t.slug;\n"
"  document.getElementById('tenant-slug').disabled = true;  // slug は変更不可\n"
"  document.getElementById('tenant-name').value = t.name;\n"
"  document.getElementById('tenant-limit').value = t.plan_limit;\n"
"  document.getElementById('tenant-active').value = t.is_active ? 'true' : 'false';\n"
"  openModal('tenant-modal');\n"
"}\n"
"async function saveTenant() {\n"
"  const id = document.getElementById('tenant-id').value;\n"
"  const body = {\n"
"    slug: document.getElementById('tenant-slug').value,\n"
"    name: document.getElementById('tenant-name').value,\n"
"    plan_limit: +document.getElementById('tenant-limit').value,\n"
"    is_active: document.getElementById('tenant-active').value === 'true'\n"
"  };\n"
"  const r = id ? await api('PATCH', `/api/v1/admin/tenants/${id}`, body)\n"
"              : await api('POST', '/api/v1/admin/tenants', body);\n"
"  showMsg('tenant-modal-msg', r.ok, r.ok ? '保存しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) { closeModal('tenant-modal'); loadTenants(); }\n"
"}\n"
"async function deleteTenant(id) {\n"
"  if (!confirm('このテナントを削除しますか？関連Venueのtenant_idが解除されます。')) return;\n"
"  const r = await api('DELETE', `/api/v1/admin/tenants/${id}`);\n"
"  showMsg('tenants-msg', r.ok, r.ok ? '削除しました' : (r.data?.error || 'エラー'));\n"
"  if (r.ok) loadTenants();\n"
"}\n"
"\n"
"// ─── Gift Cards ──────────────────────────────────────────────────────────────\n"
"async function loadGiftCards() {\n"
"  const r = await api('GET', '/api/v1/admin/gift-cards');\n"
"  const tbody = document.querySelector('#giftcards-table tbody');\n"
"  if (!r.ok) { showMsg('giftcards-msg', false, r.data?.error || 'エラー'); return; }\n"
"  const cards = r.data.gift_cards || [];\n"
"  tbody.innerHTML = cards.map(g => `\n"
"    <tr>\n"
"      <td>${g.id}</td>\n"
"      <td><code style='font-size:12px;background:var(--bg);padding:2px 6px;border-radius:4px;'>${g.code}</code></td>\n"
"      <td>¥${(g.initial_amount||0).toLocaleString()}</td>\n"
"      <td>¥${(g.remaining_balance||0).toLocaleString()}</td>\n"
"      <td>${g.issued_to_email||'-'}</td>\n"
"      <td>${g.expires_at||'なし'}</td>\n"
"      <td><span class='badge ${g.is_active?'badge-green':'badge-grey'}'>${g.is_active?'有効':'無効'}</span></td>\n"
"      <td class='actions'>\n"
"        ${g.is_active?`<button class='btn btn-danger' onclick='deleteGiftCard(${g.id})'>無効化</button>`:''}\n"
"      </td>\n"
"    </tr>`).join('');\n"
"}\n"
"function openGiftCardModal() {\n"
"  document.getElementById('gc-amount').value='';\n"
"  document.getElementById('gc-email').value='';\n"
"  document.getElementById('gc-expires').value='';\n"
"  showMsg('giftcard-modal-msg','',false);\n"
"  openModal('giftcard-modal');\n"
"}\n"
"async function saveGiftCard() {\n"
"  const amount=parseInt(document.getElementById('gc-amount').value);\n"
"  if(!amount||amount<100){showMsg('giftcard-modal-msg',false,'金額は100円以上');return;}\n"
"  const body={initial_amount:amount};\n"
"  const email=document.getElementById('gc-email').value.trim();\n"
"  const exp=document.getElementById('gc-expires').value;\n"
"  if(email) body.issued_to_email=email;\n"
"  if(exp) body.expires_at=exp;\n"
"  const r=await api('POST','/api/v1/admin/gift-cards',body);\n"
"  if(r.ok){\n"
"    const code=r.data.code||'?';\n"
"    showMsg('giftcard-modal-msg',true,'発行完了。コード: '+code);\n"
"    loadGiftCards();\n"
"  } else showMsg('giftcard-modal-msg',false,r.data?.error||'エラー');\n"
"}\n"
"async function deleteGiftCard(id) {\n"
"  if(!confirm('このギフトカードを無効化しますか？')) return;\n"
"  const r=await api('DELETE',`/api/v1/admin/gift-cards/${id}`);\n"
"  showMsg('giftcards-msg',r.ok,r.ok?'無効化しました':(r.data?.error||'エラー'));\n"
"  if(r.ok) loadGiftCards();\n"
"}\n"
"\n"
"// ─── Staff ────────────────────────────────────────────────────────────────────\n"
"async function loadStaff() {\n"
"  const r = await api('GET', '/api/v1/admin/staff');\n"
"  const tbody = document.querySelector('#staff-table tbody');\n"
"  if (!r.ok) { showMsg('staff-msg', false, r.data?.error || 'エラー'); return; }\n"
"  const staff = r.data.staff || [];\n"
"  tbody.innerHTML = staff.map(s => `\n"
"    <tr>\n"
"      <td>${s.id}</td>\n"
"      <td>${s.name||'-'}</td>\n"
"      <td>${s.email}</td>\n"
"      <td><span class='badge ${s.role==='admin'?'badge-red':'badge-blue'}'>${s.role}</span></td>\n"
"      <td>${(s.venues||[]).join(', ')||'-'}</td>\n"
"      <td class='actions'>\n"
"        <button class='btn btn-danger' onclick='removeStaff(${s.id})' title='role を user に戻す'>解除</button>\n"
"      </td>\n"
"    </tr>`).join('');\n"
"}\n"
"function openStaffModal() {\n"
"  document.getElementById('staff-uid').value='';\n"
"  document.getElementById('staff-vid').value='';\n"
"  showMsg('staff-modal-msg','',false);\n"
"  openModal('staff-modal');\n"
"}\n"
"async function saveStaff() {\n"
"  const uid=parseInt(document.getElementById('staff-uid').value);\n"
"  const vid=parseInt(document.getElementById('staff-vid').value);\n"
"  const role=document.getElementById('staff-role').value;\n"
"  if(!uid||!vid){showMsg('staff-modal-msg',false,'ユーザーIDと会場IDを入力してください');return;}\n"
"  const r=await api('POST','/api/v1/admin/staff/venues',{user_id:uid,venue_id:vid,role});\n"
"  if(r.ok){showMsg('staff-modal-msg',true,'割り当て完了');loadStaff();}\n"
"  else showMsg('staff-modal-msg',false,r.data?.error||'エラー');\n"
"}\n"
"async function removeStaff(userId) {\n"
"  const vid=prompt('解除する会場IDを入力してください（空白で全解除）:');\n"
"  if(vid===null) return;\n"
"  if(vid){\n"
"    const r=await api('DELETE',`/api/v1/admin/staff/${userId}/venues/${vid}`);\n"
"    showMsg('staff-msg',r.ok,r.ok?'解除しました':(r.data?.error||'エラー'));\n"
"  }\n"
"  loadStaff();\n"
"}\n"
"\n"
"// ─── Dashboard ───────────────────────────────────────────────────────────────\n"
"let dashChart = null;\n"
"async function loadDashboard() {\n"
"  const today = new Date();\n"
"  const d30 = new Date(); d30.setDate(d30.getDate()-30);\n"
"  const toFmt = today.toISOString().slice(0,10);\n"
"  const frFmt = d30.toISOString().slice(0,10);\n"
"  let fromEl = document.getElementById('dash-from');\n"
"  let toEl   = document.getElementById('dash-to');\n"
"  if (!fromEl.value) fromEl.value = frFmt;\n"
"  if (!toEl.value)   toEl.value   = toFmt;\n"
"  const r = await api('GET', `/api/v1/admin/reports/sales?from=${fromEl.value}&to=${toEl.value}`);\n"
"  if (!r.ok) return;\n"
"  const csv = r.data._text || '';\n"
"  const rows = csv.trim().split('\\n').slice(1).filter(Boolean).map(line => {\n"
"    const cols = line.split(',').map(c=>c.replace(/^\"|\"$/g,''));\n"
"    return { date:cols[5], plan:cols[3], venue:cols[4], price:parseInt(cols[7])||0 };\n"
"  });\n"
"  const total = rows.reduce((s,r)=>s+r.price,0);\n"
"  const cnt = rows.length;\n"
"  const avg = cnt ? Math.round(total/cnt) : 0;\n"
"  const kpiCard = (label,val,color) =>\n"
"    `<div style='background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;'>`\n"
"   +`<div style='font-size:12px;color:var(--muted);margin-bottom:4px;'>${label}</div>`\n"
"   +`<div style='font-size:22px;font-weight:800;color:${color};'>${val}</div></div>`;\n"
"  document.getElementById('dash-kpi').innerHTML =\n"
"    kpiCard('総売上', '¥'+total.toLocaleString(), '#a855f7')\n"
"   +kpiCard('予約件数', cnt+'件', '#5bc0eb')\n"
"   +kpiCard('平均単価', '¥'+avg.toLocaleString(), '#52c41a')\n"
"   +kpiCard('集計期間', `${fromEl.value}〜${toEl.value}`, '#999');\n"
"  const byDate = {};\n"
"  rows.forEach(r=>{ byDate[r.date]=(byDate[r.date]||0)+r.price; });\n"
"  const labels = Object.keys(byDate).sort();\n"
"  const values = labels.map(d=>byDate[d]);\n"
"  const ctx = document.getElementById('dash-chart').getContext('2d');\n"
"  if (dashChart) dashChart.destroy();\n"
"  if (typeof Chart !== 'undefined') {\n"
"    dashChart = new Chart(ctx, {\n"
"      type:'bar',\n"
"      data:{ labels, datasets:[{ label:'売上(¥)', data:values,\n"
"        backgroundColor:'rgba(168,85,247,0.6)', borderColor:'#a855f7',\n"
"        borderWidth:1, borderRadius:4 }] },\n"
"      options:{ plugins:{legend:{display:false}},\n"
"        scales:{\n"
"          x:{ticks:{color:'#888',font:{size:10}},grid:{color:'#222232'}},\n"
"          y:{ticks:{color:'#888',callback:v=>'¥'+v.toLocaleString()},grid:{color:'#222232'}}\n"
"        }}\n"
"    });\n"
"  }\n"
"  const byPlan = {};\n"
"  rows.forEach(r=>{ if(!byPlan[r.plan]) byPlan[r.plan]={cnt:0,total:0}; byPlan[r.plan].cnt++; byPlan[r.plan].total+=r.price; });\n"
"  document.querySelector('#dash-plan-table tbody').innerHTML =\n"
"    Object.entries(byPlan).sort((a,b)=>b[1].total-a[1].total).slice(0,10)\n"
"    .map(([p,v])=>`<tr><td>${p}</td><td>${v.cnt}</td><td>¥${v.total.toLocaleString()}</td></tr>`).join('');\n"
"  const byVenue = {};\n"
"  rows.forEach(r=>{ if(!byVenue[r.venue]) byVenue[r.venue]={cnt:0,total:0}; byVenue[r.venue].cnt++; byVenue[r.venue].total+=r.price; });\n"
"  document.querySelector('#dash-venue-table tbody').innerHTML =\n"
"    Object.entries(byVenue).sort((a,b)=>b[1].total-a[1].total).slice(0,10)\n"
"    .map(([v,d])=>`<tr><td>${v}</td><td>${d.cnt}</td><td>¥${d.total.toLocaleString()}</td></tr>`).join('');\n"
"}\n"
"\n"
"// ─── Init ─────────────────────────────────────────────────────────────────────\n"
"showTab('dashboard');\n"
"</script>\n"
"<script src='https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js'></script>\n"
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

/* ─── GET /api/v1/admin/reports/sales ───────────────────────────────────── */

void handle_admin_sales_report(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;

    /* ?from=YYYY-MM-DD&to=YYYY-MM-DD */
    char from_date[16] = "2000-01-01";
    char to_date[16]   = "2099-12-31";
    char tmp[16] = {0};
    if (mg_http_get_var(&hm->query, "from", tmp, sizeof(tmp)) > 0)
        strncpy(from_date, tmp, sizeof(from_date)-1);
    memset(tmp, 0, sizeof(tmp));
    if (mg_http_get_var(&hm->query, "to", tmp, sizeof(tmp)) > 0)
        strncpy(to_date, tmp, sizeof(to_date)-1);

    DbStmt *st = db_prepare(db,
        "SELECT b.id, u.name, u.email, p.title, v.name, "
        "s.date, s.start_time, b.total_price, b.discount_amount, b.status, b.created_at "
        "FROM bookings b "
        "JOIN users u ON u.id=b.user_id "
        "JOIN plans p ON p.id=b.plan_id "
        "JOIN venues v ON v.id=p.venue_id "
        "JOIN schedules s ON s.id=b.schedule_id "
        "WHERE b.status != 'cancelled' "
        "AND date(b.created_at) >= ? AND date(b.created_at) <= ? "
        "ORDER BY b.created_at DESC");
    db_bind_text(st, 1, from_date);
    db_bind_text(st, 2, to_date);

    /* CSV バッファ */
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (!buf) { db_finalize(st); send_error_json(c, 500, "OOM"); return; }

#define CSV(fmt, ...) do { \
    int _n = snprintf(buf + len, cap - len, fmt, ##__VA_ARGS__); \
    if (_n > 0) len += (size_t)_n; \
    if (len + 512 > cap) { cap *= 2; char *_r = realloc(buf, cap); if (_r) buf = _r; } \
} while(0)

    CSV("booking_id,customer_name,customer_email,plan_title,venue_name,"
        "schedule_date,start_time,total_price,discount_amount,status,created_at\r\n");

    long grand_total = 0, row_count = 0;
    while (db_step(st) == 1) {
        long price    = db_col_int(st, 7);
        long discount = db_col_int(st, 8);
        grand_total  += price;
        row_count++;
        CSV("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%ld,%ld,\"%s\",\"%s\"\r\n",
            db_col_text(st, 0)  ? db_col_text(st, 0)  : "",
            db_col_text(st, 1)  ? db_col_text(st, 1)  : "",
            db_col_text(st, 2)  ? db_col_text(st, 2)  : "",
            db_col_text(st, 3)  ? db_col_text(st, 3)  : "",
            db_col_text(st, 4)  ? db_col_text(st, 4)  : "",
            db_col_text(st, 5)  ? db_col_text(st, 5)  : "",
            db_col_text(st, 6)  ? db_col_text(st, 6)  : "",
            price, discount,
            db_col_text(st, 9)  ? db_col_text(st, 9)  : "",
            db_col_text(st, 10) ? db_col_text(st, 10) : "");
    }
    db_finalize(st);
    CSV("\r\n# 集計,件数,%ld,合計売上,%ld\r\n", row_count, grand_total);
#undef CSV

    time_t now = time(NULL);
    char date_str[16];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d", gmtime(&now));
    char disp[64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"sales_%s.csv\"", date_str);

    char hdrs[256];
    snprintf(hdrs, sizeof(hdrs),
        "Content-Type: text/csv; charset=UTF-8\r\n"
        "Content-Disposition: %s\r\n"
        "Access-Control-Allow-Origin: *\r\n", disp);
    mg_http_reply(c, 200, hdrs, "%.*s", (int)len, buf);
    free(buf);
}

/* ─── Webhook エンドポイント CRUD ────────────────────────────────────────── */

void handle_admin_list_webhooks(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    DbStmt *st = db_prepare(db,
        "SELECT id,url,events,is_active,created_at FROM webhook_endpoints ORDER BY id DESC");
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *w = cJSON_CreateObject();
        cJSON_AddNumberToObject(w, "id",         db_col_int(st, 0));
        cJSON_AddStringToObject(w, "url",        db_col_text(st, 1) ? db_col_text(st, 1) : "");
        cJSON_AddStringToObject(w, "events",     db_col_text(st, 2) ? db_col_text(st, 2) : "[]");
        cJSON_AddBoolToObject(w,   "is_active",  (int)db_col_int(st, 3));
        cJSON_AddStringToObject(w, "created_at", db_col_text(st, 4) ? db_col_text(st, 4) : "");
        cJSON_AddItemToArray(arr, w);
    }
    db_finalize(st);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "webhooks", arr);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_create_webhook(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *url    = cJSON_GetStringValue(cJSON_GetObjectItem(body, "url"));
    cJSON *events_arr  = cJSON_GetObjectItem(body, "events");
    if (!url || !events_arr) {
        cJSON_Delete(body); send_error_json(c, 400, "url と events は必須です"); return;
    }

    /* ランダムな Webhook シークレット生成（32 バイト hex） */
    unsigned char raw[16];
    extern void platform_random(void *buf, size_t len);
    platform_random(raw, sizeof(raw));
    char secret[33] = {0};
    for (int i = 0; i < 16; i++) snprintf(secret + i*2, 3, "%02x", raw[i]);

    char *events_str = cJSON_PrintUnformatted(events_arr);
    DbStmt *ins = db_prepare(db,
        "INSERT INTO webhook_endpoints(url,secret,events) VALUES(?,?,?)");
    db_bind_text(ins, 1, url);
    db_bind_text(ins, 2, secret);
    db_bind_text(ins, 3, events_str ? events_str : "[]");
    db_step(ins); db_finalize(ins);
    cJSON_free(events_str);

    long wid = (long)db_last_id(db);
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id",     wid);
    cJSON_AddStringToObject(res, "secret", secret);
    cJSON_AddStringToObject(res, "message", "Webhook エンドポイントを登録しました");
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_delete_webhook(struct mg_connection *c, struct mg_http_message *hm,
                                  DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    DbStmt *del = db_prepare(db, "DELETE FROM webhook_endpoints WHERE id=?");
    db_bind_int(del, 1, id);
    db_step(del); db_finalize(del);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"Webhook エンドポイントを削除しました\"}");
}

/* ─── クーポン CRUD ─────────────────────────────────────────────────────── */

void handle_admin_list_coupons(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    DbStmt *st = db_prepare(db,
        "SELECT id,code,description,discount_type,discount_value,"
        "max_uses,used_count,expires_at,is_active,created_at "
        "FROM coupons ORDER BY id DESC");
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *cp = cJSON_CreateObject();
        cJSON_AddNumberToObject(cp, "id",             db_col_int(st, 0));
        cJSON_AddStringToObject(cp, "code",           db_col_text(st, 1) ? db_col_text(st, 1) : "");
        if (!db_col_is_null(st, 2)) cJSON_AddStringToObject(cp, "description", db_col_text(st, 2));
        cJSON_AddStringToObject(cp, "discount_type",  db_col_text(st, 3) ? db_col_text(st, 3) : "percent");
        cJSON_AddNumberToObject(cp, "discount_value", db_col_int(st, 4));
        if (!db_col_is_null(st, 5)) cJSON_AddNumberToObject(cp, "max_uses", db_col_int(st, 5));
        cJSON_AddNumberToObject(cp, "used_count",     db_col_int(st, 6));
        if (!db_col_is_null(st, 7)) cJSON_AddStringToObject(cp, "expires_at", db_col_text(st, 7));
        cJSON_AddBoolToObject(cp,   "is_active",      (int)db_col_int(st, 8));
        cJSON_AddStringToObject(cp, "created_at",     db_col_text(st, 9) ? db_col_text(st, 9) : "");
        cJSON_AddItemToArray(arr, cp);
    }
    db_finalize(st);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "coupons", arr);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_create_coupon(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *code  = cJSON_GetStringValue(cJSON_GetObjectItem(body, "code"));
    const char *dtype = cJSON_GetStringValue(cJSON_GetObjectItem(body, "discount_type"));
    long dval         = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "discount_value"));
    const char *desc  = cJSON_GetStringValue(cJSON_GetObjectItem(body, "description"));
    long max_uses     = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "max_uses"));
    const char *exp   = cJSON_GetStringValue(cJSON_GetObjectItem(body, "expires_at"));

    if (!code || !dtype || dval <= 0) {
        cJSON_Delete(body);
        send_error_json(c, 400, "code, discount_type, discount_value は必須です"); return;
    }

    /* Copy strings before cJSON_Delete(body) invalidates the pointers */
    char code_buf[64]  = {0};
    char dtype_buf[32] = {0};
    char desc_buf[256] = {0};
    char exp_buf[32]   = {0};
    strncpy(code_buf,  code,          sizeof(code_buf)-1);
    strncpy(dtype_buf, dtype,         sizeof(dtype_buf)-1);
    if (desc) strncpy(desc_buf, desc, sizeof(desc_buf)-1);
    if (exp)  strncpy(exp_buf,  exp,  sizeof(exp_buf)-1);
    cJSON_Delete(body);

    DbStmt *ins = db_prepare(db,
        "INSERT INTO coupons(code,description,discount_type,discount_value,max_uses,expires_at)"
        " VALUES(?,?,?,?,?,?)");
    db_bind_text(ins, 1, code_buf);
    db_bind_text(ins, 2, desc_buf);
    db_bind_text(ins, 3, dtype_buf);
    db_bind_int(ins,  4, dval);
    db_bind_int(ins,  5, max_uses);  /* 0 = unlimited */
    db_bind_text(ins, 6, exp_buf);
    int rc = db_step(ins); db_finalize(ins);

    if (rc == -1) { send_error_json(c, 409, "クーポンコードが重複しています"); return; }

    long cid = (long)db_last_id(db);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id",   cid);
    cJSON_AddStringToObject(res, "code", code_buf);
    cJSON_AddStringToObject(res, "message", "クーポンを作成しました");
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_delete_coupon(struct mg_connection *c, struct mg_http_message *hm,
                                 DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    DbStmt *del = db_prepare(db, "DELETE FROM coupons WHERE id=?");
    db_bind_int(del, 1, id);
    db_step(del); db_finalize(del);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"クーポンを削除しました\"}");
}

/* ─── プラン追加画像 CRUD ────────────────────────────────────────────────── */

void handle_admin_create_plan_image(struct mg_connection *c, struct mg_http_message *hm,
                                     DbConn *db, long plan_id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *url_ptr = cJSON_GetStringValue(cJSON_GetObjectItem(body, "url"));
    long order          = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "display_order"));
    if (!url_ptr) { cJSON_Delete(body); send_error_json(c, 400, "url は必須です"); return; }

    /* Copy before cJSON_Delete invalidates the pointer */
    char url_buf[1024] = {0};
    strncpy(url_buf, url_ptr, sizeof(url_buf)-1);
    cJSON_Delete(body);

    DbStmt *ins = db_prepare(db,
        "INSERT INTO plan_images(plan_id,url,display_order) VALUES(?,?,?)");
    db_bind_int(ins,  1, plan_id);
    db_bind_text(ins, 2, url_buf);
    db_bind_int(ins,  3, order);
    db_step(ins); db_finalize(ins);
    long img_id = (long)db_last_id(db);

    audit_log(db, "admin", "plan_image.create", "plan_image", NULL, url_buf, NULL);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id",       img_id);
    cJSON_AddNumberToObject(res, "plan_id",  plan_id);
    cJSON_AddStringToObject(res, "url",      url_buf);
    cJSON_AddNumberToObject(res, "display_order", order);
    cJSON_AddStringToObject(res, "message",  "画像を追加しました");
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_delete_plan_image(struct mg_connection *c, struct mg_http_message *hm,
                                     DbConn *db, long img_id) {
    if (!require_admin(c, hm)) return;
    DbStmt *del = db_prepare(db, "DELETE FROM plan_images WHERE id=?");
    db_bind_int(del, 1, img_id);
    db_step(del); db_finalize(del);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"画像を削除しました\"}");
}

/* ─── 管理者 2FA セットアップ ────────────────────────────────────────────── */

/* GET /api/v1/admin/2fa/setup
 * 初回のみ ADMIN_KEY 認証（TOTP 未設定状態での取得なのでTOTP検証スキップ）。
 * ADMIN_TOTP_SECRET を環境変数に設定して再起動後、全APIに X-Admin-TOTP が必須になる。 */
void handle_admin_2fa_setup(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    (void)db;
    /* TOTP検証を除いた認証（キーのみ） */
    struct mg_str *hdr = mg_http_get_header(hm, "X-Admin-Key");
    if (!hdr) { send_error_json(c, 403, "管理者キーが必要です"); return; }
    const char *expected = getenv("ADMIN_KEY");
    if (!expected || !*expected) expected = "asoview-admin-dev";
    if (!const_time_strcmp(hdr->buf, hdr->len, expected, strlen(expected))) {
        send_error_json(c, 403, "管理者キーが不正です"); return;
    }

    const char *existing = getenv("ADMIN_TOTP_SECRET");
    if (existing && *existing) {
        /* すでに設定済み — シークレットは返さず、設定済みであることだけ伝える */
        send_json_str(c, 200, CORS_HEADERS,
            "{\"status\":\"already_configured\","
            "\"message\":\"ADMIN_TOTP_SECRET は設定済みです。再設定する場合は環境変数を削除してください\"}");
        return;
    }

    /* 新規シークレット生成（20 バイト = 160bit） */
    unsigned char raw[20];
    platform_random(raw, sizeof(raw));

    /* Base32 エンコード */
    static const char B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    char b32[40] = {0};
    size_t j = 0;
    uint32_t buf = 0; int bits = 0;
    for (size_t i = 0; i < sizeof(raw) && j + 1 < sizeof(b32); i++) {
        buf = (buf << 8) | raw[i]; bits += 8;
        while (bits >= 5 && j + 1 < sizeof(b32)) {
            bits -= 5; b32[j++] = B32[(buf >> bits) & 0x1f];
        }
    }
    if (bits > 0 && j + 1 < sizeof(b32)) b32[j++] = B32[(buf << (5 - bits)) & 0x1f];
    while (j % 8 && j + 1 < sizeof(b32)) b32[j++] = '=';
    b32[j] = '\0';

    char otpauth[256];
    snprintf(otpauth, sizeof(otpauth),
        "otpauth://totp/Asoview%%3AAdmin?secret=%s&issuer=Asoview&algorithm=SHA1&digits=6&period=30",
        b32);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "totp_secret", b32);
    cJSON_AddStringToObject(res, "otpauth_uri", otpauth);
    cJSON_AddStringToObject(res, "next_step",
        "1) 認証アプリ(Google Authenticator等)でQRを読み取る "
        "2) .env に ADMIN_TOTP_SECRET=" "... を追加してサーバーを再起動 "
        "3) 以降の管理APIリクエストに X-Admin-TOTP: <6桁> ヘッダを付与");
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_list_plan_images(struct mg_connection *c, struct mg_http_message *hm,
                                    DbConn *db, long plan_id) {
    if (!require_admin(c, hm)) return;
    DbStmt *st = db_prepare(db,
        "SELECT id,url,display_order,created_at FROM plan_images WHERE plan_id=? ORDER BY display_order,id");
    db_bind_int(st, 1, plan_id);
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *img = cJSON_CreateObject();
        cJSON_AddNumberToObject(img, "id",            db_col_int(st, 0));
        cJSON_AddStringToObject(img, "url",           db_col_text(st, 1) ? db_col_text(st, 1) : "");
        cJSON_AddNumberToObject(img, "display_order", db_col_int(st, 2));
        cJSON_AddStringToObject(img, "created_at",    db_col_text(st, 3) ? db_col_text(st, 3) : "");
        cJSON_AddItemToArray(arr, img);
    }
    db_finalize(st);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "plan_id", plan_id);
    cJSON_AddItemToObject(res, "images", arr);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

/* ─── テナント CRUD ──────────────────────────────────────────────────────── */

static cJSON *tenant_row(DbStmt *st) {
    cJSON *t = cJSON_CreateObject();
    cJSON_AddNumberToObject(t, "id",          db_col_int(st,  0));
    cJSON_AddStringToObject(t, "slug",        db_col_text(st, 1) ? db_col_text(st, 1) : "");
    cJSON_AddStringToObject(t, "name",        db_col_text(st, 2) ? db_col_text(st, 2) : "");
    cJSON_AddStringToObject(t, "api_key",     db_col_text(st, 3) ? db_col_text(st, 3) : "");
    cJSON_AddNumberToObject(t, "plan_limit",  db_col_int(st,  4));
    cJSON_AddBoolToObject(t,   "is_active",   db_col_int(st,  5) != 0);
    cJSON_AddStringToObject(t, "created_at",  db_col_text(st, 6) ? db_col_text(st, 6) : "");
    return t;
}

void handle_admin_list_tenants(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    DbStmt *st = db_prepare(db,
        "SELECT id,slug,name,api_key,plan_limit,is_active,created_at FROM tenants ORDER BY id");
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) cJSON_AddItemToArray(arr, tenant_row(st));
    db_finalize(st);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "tenants", arr);
    cJSON_AddNumberToObject(res, "total", (double)cJSON_GetArraySize(arr));
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_create_tenant(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    const char *slug = cJSON_GetStringValue(cJSON_GetObjectItem(body, "slug"));
    const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(body, "name"));
    if (!slug || !*slug || !name || !*name) {
        cJSON_Delete(body);
        send_error_json(c, 400, "slug と name は必須");
        return;
    }

    /* slugとnameをコピーしておく（body解放後も使用するため） */
    char slug_in[64]={0}, name_in[256]={0};
    strncpy(slug_in, slug, sizeof(slug_in)-1);
    strncpy(name_in, name, sizeof(name_in)-1);

    /* api_key を自動生成（指定があれば使用） */
    const char *api_key_in_p = cJSON_GetStringValue(cJSON_GetObjectItem(body, "api_key"));
    char api_key_in[65] = {0};
    if (api_key_in_p && *api_key_in_p) {
        strncpy(api_key_in, api_key_in_p, sizeof(api_key_in)-1);
    } else {
        uint8_t rnd[32];
        platform_random(rnd, sizeof(rnd));
        for (int i = 0; i < 32; i++) snprintf(api_key_in + i*2, 3, "%02x", rnd[i]);
    }
    long plan_limit = 100;
    cJSON *pl = cJSON_GetObjectItem(body, "plan_limit");
    if (cJSON_IsNumber(pl)) plan_limit = (long)cJSON_GetNumberValue(pl);
    cJSON_Delete(body);

    DbStmt *st = db_prepare(db,
        "INSERT INTO tenants(slug,name,api_key,plan_limit) VALUES(?,?,?,?)");
    db_bind_text(st, 1, slug_in);
    db_bind_text(st, 2, name_in);
    db_bind_text(st, 3, api_key_in);
    db_bind_int(st,  4, plan_limit);
    int rc = db_step(st);
    db_finalize(st);

    if (rc < 0) { send_error_json(c, 409, "slug が既に存在します"); return; }

    /* 作成したテナントを返す */
    DbStmt *sel = db_prepare(db,
        "SELECT id,slug,name,api_key,plan_limit,is_active,created_at FROM tenants WHERE slug=?");
    db_bind_text(sel, 1, slug_in);
    if (db_step(sel) != 1) { db_finalize(sel); send_error_json(c, 500, "fetch failed"); return; }
    cJSON *res = tenant_row(sel);
    db_finalize(sel);
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_get_tenant(struct mg_connection *c, struct mg_http_message *hm,
                              DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    DbStmt *st = db_prepare(db,
        "SELECT id,slug,name,api_key,plan_limit,is_active,created_at FROM tenants WHERE id=?");
    db_bind_int(st, 1, id);
    if (db_step(st) != 1) { db_finalize(st); send_error_json(c, 404, "テナントが見つかりません"); return; }
    cJSON *res = tenant_row(st);
    db_finalize(st);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_update_tenant(struct mg_connection *c, struct mg_http_message *hm,
                                 DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    /* 既存値を読み込む */
    DbStmt *cur = db_prepare(db,
        "SELECT slug,name,plan_limit,is_active FROM tenants WHERE id=?");
    db_bind_int(cur, 1, id);
    if (db_step(cur) != 1) { db_finalize(cur); cJSON_Delete(body); send_error_json(c, 404, "テナントが見つかりません"); return; }
    char slug_buf[64]={0}, name_buf[256]={0};
    strncpy(slug_buf, db_col_text(cur,0) ? db_col_text(cur,0) : "", sizeof(slug_buf)-1);
    strncpy(name_buf, db_col_text(cur,1) ? db_col_text(cur,1) : "", sizeof(name_buf)-1);
    long plan_limit  = db_col_int(cur, 2);
    long is_active   = db_col_int(cur, 3);
    db_finalize(cur);

    const char *new_name = cJSON_GetStringValue(cJSON_GetObjectItem(body, "name"));
    if (new_name && *new_name) strncpy(name_buf, new_name, sizeof(name_buf)-1);
    cJSON *pl = cJSON_GetObjectItem(body, "plan_limit");
    if (cJSON_IsNumber(pl)) plan_limit = (long)cJSON_GetNumberValue(pl);
    cJSON *ia = cJSON_GetObjectItem(body, "is_active");
    if (cJSON_IsBool(ia)) is_active = cJSON_IsTrue(ia) ? 1 : 0;

    DbStmt *upd = db_prepare(db,
        "UPDATE tenants SET name=?,plan_limit=?,is_active=? WHERE id=?");
    db_bind_text(upd, 1, name_buf);
    db_bind_int(upd,  2, plan_limit);
    db_bind_int(upd,  3, is_active);
    db_bind_int(upd,  4, id);
    db_step(upd); db_finalize(upd);
    cJSON_Delete(body);

    DbStmt *sel = db_prepare(db,
        "SELECT id,slug,name,api_key,plan_limit,is_active,created_at FROM tenants WHERE id=?");
    db_bind_int(sel, 1, id);
    if (db_step(sel) != 1) { db_finalize(sel); send_error_json(c, 404, "not found"); return; }
    cJSON *res = tenant_row(sel);
    db_finalize(sel);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_delete_tenant(struct mg_connection *c, struct mg_http_message *hm,
                                 DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    /* 関連 venues の tenant_id を NULL に戻す */
    DbStmt *unlink = db_prepare(db,
        "UPDATE venues SET tenant_id=NULL WHERE tenant_id=?");
    db_bind_int(unlink, 1, id);
    db_step(unlink); db_finalize(unlink);

    DbStmt *del = db_prepare(db, "DELETE FROM tenants WHERE id=?");
    db_bind_int(del, 1, id);
    db_step(del); db_finalize(del);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"テナントを削除しました\"}");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ギフト券 CRUD
 * ═══════════════════════════════════════════════════════════════════════════ */

void handle_admin_list_giftcards(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    DbStmt *st = db_prepare(db,
        "SELECT id,code,initial_amount,remaining_balance,issued_to_email,"
        "       expires_at,is_active,created_at "
        "FROM gift_cards ORDER BY id DESC");
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *g = cJSON_CreateObject();
        cJSON_AddNumberToObject(g, "id",                db_col_int(st, 0));
        cJSON_AddStringToObject(g, "code",              db_col_text(st, 1));
        cJSON_AddNumberToObject(g, "initial_amount",    db_col_int(st, 2));
        cJSON_AddNumberToObject(g, "remaining_balance", db_col_int(st, 3));
        if (!db_col_is_null(st, 4)) cJSON_AddStringToObject(g, "issued_to_email", db_col_text(st, 4));
        else cJSON_AddNullToObject(g, "issued_to_email");
        if (!db_col_is_null(st, 5)) cJSON_AddStringToObject(g, "expires_at", db_col_text(st, 5));
        else cJSON_AddNullToObject(g, "expires_at");
        cJSON_AddBoolToObject(g, "is_active", (int)db_col_int(st, 6));
        cJSON_AddStringToObject(g, "created_at", db_col_text(st, 7));
        cJSON_AddItemToArray(arr, g);
    }
    db_finalize(st);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "gift_cards", arr);
    char *s = cJSON_PrintUnformatted(res);
    send_json_str(c, 200, CORS_HEADERS, s);
    cJSON_free(s); cJSON_Delete(res);
}

void handle_admin_create_giftcard(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    cJSON *amt_j = cJSON_GetObjectItem(body, "amount");
    if (!amt_j || !cJSON_IsNumber(amt_j)) {
        cJSON_Delete(body);
        send_error_json(c, 400, "amount は必須です（整数、円単位）"); return;
    }
    long amount = (long)cJSON_GetNumberValue(amt_j);
    if (amount <= 0) { cJSON_Delete(body); send_error_json(c, 400, "amount は1以上"); return; }

    const char *email_p  = cJSON_GetStringValue(cJSON_GetObjectItem(body, "issued_to_email"));
    const char *expires_p= cJSON_GetStringValue(cJSON_GetObjectItem(body, "expires_at"));
    char email_buf[256]  = {0};
    char expires_buf[32] = {0};
    if (email_p)  strncpy(email_buf,  email_p,  sizeof(email_buf)-1);
    if (expires_p)strncpy(expires_buf,expires_p,sizeof(expires_buf)-1);

    /* ギフト券コードを自動生成（16文字 hex） */
    uint8_t rnd[8]; platform_random(rnd, sizeof(rnd));
    char code[20] = {0};
    for (int i = 0; i < 8; i++) snprintf(code + i*2, 3, "%02X", rnd[i]);

    cJSON_Delete(body);

    DbStmt *st = db_prepare(db,
        "INSERT INTO gift_cards(code,initial_amount,remaining_balance,issued_to_email,expires_at)"
        " VALUES(?,?,?,nullif(?,\"\"),nullif(?,\"\"))"
        " RETURNING id,code,initial_amount,remaining_balance,issued_to_email,expires_at,created_at");
    db_bind_text(st, 1, code);
    db_bind_int(st,  2, amount);
    db_bind_int(st,  3, amount);
    db_bind_text(st, 4, email_buf);
    db_bind_text(st, 5, expires_buf);
    if (db_step(st) != 1) {
        db_finalize(st); send_error_json(c, 500, "insert failed"); return;
    }
    cJSON *g = cJSON_CreateObject();
    cJSON_AddNumberToObject(g, "id",                db_col_int(st, 0));
    cJSON_AddStringToObject(g, "code",              db_col_text(st, 1));
    cJSON_AddNumberToObject(g, "initial_amount",    db_col_int(st, 2));
    cJSON_AddNumberToObject(g, "remaining_balance", db_col_int(st, 3));
    if (!db_col_is_null(st, 4)) cJSON_AddStringToObject(g, "issued_to_email", db_col_text(st, 4));
    else cJSON_AddNullToObject(g, "issued_to_email");
    if (!db_col_is_null(st, 5)) cJSON_AddStringToObject(g, "expires_at", db_col_text(st, 5));
    else cJSON_AddNullToObject(g, "expires_at");
    cJSON_AddStringToObject(g, "created_at", db_col_text(st, 6));
    db_finalize(st);
    char *s = cJSON_PrintUnformatted(g);
    send_json_str(c, 201, CORS_HEADERS, s);
    cJSON_free(s); cJSON_Delete(g);
}

void handle_admin_delete_giftcard(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id) {
    if (!require_admin(c, hm)) return;
    DbStmt *chk = db_prepare(db, "SELECT id FROM gift_cards WHERE id=?");
    db_bind_int(chk, 1, id);
    if (db_step(chk) != 1) {
        db_finalize(chk); send_error_json(c, 404, "gift card not found"); return;
    }
    db_finalize(chk);
    /* 論理削除 */
    DbStmt *upd = db_prepare(db, "UPDATE gift_cards SET is_active=0 WHERE id=?");
    db_bind_int(upd, 1, id);
    db_step(upd); db_finalize(upd);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"ギフト券を無効化しました\"}");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * スタッフ管理
 * ═══════════════════════════════════════════════════════════════════════════ */

void handle_admin_list_staff(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    DbStmt *st = db_prepare(db,
        "SELECT u.id,u.name,u.email,u.role,"
        "       GROUP_CONCAT(v.name,'|') AS venue_names,"
        "       GROUP_CONCAT(sv.venue_id,'|') AS venue_ids "
        "FROM users u "
        "LEFT JOIN staff_venues sv ON sv.user_id=u.id "
        "LEFT JOIN venues v ON v.id=sv.venue_id "
        "WHERE u.role IN ('staff','admin') "
        "GROUP BY u.id ORDER BY u.id");
    cJSON *arr = cJSON_CreateArray();
    while (db_step(st) == 1) {
        cJSON *u = cJSON_CreateObject();
        cJSON_AddNumberToObject(u, "id",    db_col_int(st, 0));
        cJSON_AddStringToObject(u, "name",  db_col_text(st, 1));
        cJSON_AddStringToObject(u, "email", db_col_text(st, 2));
        cJSON_AddStringToObject(u, "role",  db_col_text(st, 3));
        if (!db_col_is_null(st, 4))
            cJSON_AddStringToObject(u, "venue_names", db_col_text(st, 4));
        else cJSON_AddNullToObject(u, "venue_names");
        cJSON_AddItemToArray(arr, u);
    }
    db_finalize(st);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "staff", arr);
    char *s = cJSON_PrintUnformatted(res);
    send_json_str(c, 200, CORS_HEADERS, s);
    cJSON_free(s); cJSON_Delete(res);
}

void handle_admin_assign_staff_venue(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    cJSON *uid_j = cJSON_GetObjectItem(body, "user_id");
    cJSON *vid_j = cJSON_GetObjectItem(body, "venue_id");
    if (!uid_j || !cJSON_IsNumber(uid_j) || !vid_j || !cJSON_IsNumber(vid_j)) {
        cJSON_Delete(body);
        send_error_json(c, 400, "user_id と venue_id が必要です"); return;
    }
    long uid = (long)cJSON_GetNumberValue(uid_j);
    long vid = (long)cJSON_GetNumberValue(vid_j);

    /* role を staff に昇格（まだ staff/admin でなければ） */
    const char *role_p = cJSON_GetStringValue(cJSON_GetObjectItem(body, "role"));
    cJSON_Delete(body);

    DbStmt *upd = db_prepare(db,
        "UPDATE users SET role=? WHERE id=? AND role='user'");
    db_bind_text(upd, 1, (role_p && strcmp(role_p,"admin")==0) ? "admin" : "staff");
    db_bind_int(upd, 2, uid);
    db_step(upd); db_finalize(upd);

    DbStmt *ins = db_prepare(db,
        "INSERT OR IGNORE INTO staff_venues(user_id,venue_id) VALUES(?,?)");
    db_bind_int(ins, 1, uid);
    db_bind_int(ins, 2, vid);
    db_step(ins); db_finalize(ins);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"スタッフを会場に割り当てました\"}");
}

void handle_admin_remove_staff_venue(struct mg_connection *c, struct mg_http_message *hm,
                                     DbConn *db, long user_id, long venue_id) {
    if (!require_admin(c, hm)) return;
    DbStmt *del = db_prepare(db,
        "DELETE FROM staff_venues WHERE user_id=? AND venue_id=?");
    db_bind_int(del, 1, user_id);
    db_bind_int(del, 2, venue_id);
    db_step(del); db_finalize(del);
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"スタッフの担当会場を解除しました\"}");
}
