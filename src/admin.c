#include "admin.h"
#include "handlers.h"   /* send_json_str, send_error_json */
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CORS_HEADERS "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n"

/* ─── Admin 認証 ──────────────────────────────────────────────────────────── */

/* 定数時間文字列比較（タイミング攻撃対策） */
static int const_time_strcmp(const char *a, size_t a_len,
                              const char *b, size_t b_len) {
    /* 長さが違えば必ず不一致。ただし長さ自体も漏らさないよう両方走査する */
    unsigned char diff = (unsigned char)(a_len != b_len);
    size_t n = a_len < b_len ? a_len : b_len;
    for (size_t i = 0; i < n; i++) {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
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

void handle_admin_list_venues(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    if (!require_admin(c, hm)) return;
    long page  = admin_query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit = admin_query_long(hm, "limit", 50); if (limit > 200) limit = 200;
    long offset = (page - 1) * limit;

    sqlite3_stmt *ct;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM venues", -1, &ct, NULL);
    sqlite3_step(ct);
    long total = sqlite3_column_int64(ct, 0);
    sqlite3_finalize(ct);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT v.id,v.name,v.description,v.area_id,a.name,"
        "v.address,v.phone,v.website,v.review_count,v.review_avg,v.created_at "
        "FROM venues v LEFT JOIN areas a ON a.id=v.area_id "
        "ORDER BY v.id LIMIT ? OFFSET ?",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, limit);
    sqlite3_bind_int64(st, 2, offset);

    cJSON *venues = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *v = cJSON_CreateObject();
        cJSON_AddNumberToObject(v, "id",           sqlite3_column_int64(st, 0));
        cJSON_AddStringToObject(v, "name",         (const char*)sqlite3_column_text(st, 1));
        if (sqlite3_column_type(st, 2) != SQLITE_NULL)
            cJSON_AddStringToObject(v, "description", (const char*)sqlite3_column_text(st, 2));
        else cJSON_AddNullToObject(v, "description");
        cJSON_AddNumberToObject(v, "area_id",      sqlite3_column_int64(st, 3));
        if (sqlite3_column_type(st, 4) != SQLITE_NULL)
            cJSON_AddStringToObject(v, "area_name", (const char*)sqlite3_column_text(st, 4));
        else cJSON_AddNullToObject(v, "area_name");
        if (sqlite3_column_type(st, 5) != SQLITE_NULL)
            cJSON_AddStringToObject(v, "address",  (const char*)sqlite3_column_text(st, 5));
        else cJSON_AddNullToObject(v, "address");
        if (sqlite3_column_type(st, 6) != SQLITE_NULL)
            cJSON_AddStringToObject(v, "phone",    (const char*)sqlite3_column_text(st, 6));
        else cJSON_AddNullToObject(v, "phone");
        if (sqlite3_column_type(st, 7) != SQLITE_NULL)
            cJSON_AddStringToObject(v, "website",  (const char*)sqlite3_column_text(st, 7));
        else cJSON_AddNullToObject(v, "website");
        cJSON_AddNumberToObject(v, "review_count", sqlite3_column_int64(st, 8));
        cJSON_AddNumberToObject(v, "review_avg",   sqlite3_column_double(st, 9));
        cJSON_AddStringToObject(v, "created_at",   (const char*)sqlite3_column_text(st, 10));
        cJSON_AddItemToArray(venues, v);
    }
    sqlite3_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "venues", venues);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_create_venue(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
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

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "INSERT INTO venues(name,description,area_id,address,latitude,longitude,phone,images)"
        " VALUES(?,?,?,?,?,?,?,?)", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name,   -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, desc ? desc : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, area_id);
    sqlite3_bind_text(st, 4, address ? address : "", -1, SQLITE_STATIC);
    sqlite3_bind_double(st, 5, lat);
    sqlite3_bind_double(st, 6, lon);
    sqlite3_bind_text(st, 7, phone ? phone : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 8, imgs_str ? imgs_str : "[]", -1, SQLITE_STATIC);
    sqlite3_step(st);
    long vid = sqlite3_last_insert_rowid(db);
    sqlite3_finalize(st);
    if (imgs_str) cJSON_free(imgs_str);
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id", vid);
    cJSON_AddStringToObject(res, "message", "施設を作成しました");
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_update_venue(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    /* 対象の存在確認 */
    sqlite3_stmt *chk;
    sqlite3_prepare_v2(db, "SELECT id FROM venues WHERE id=?", -1, &chk, NULL);
    sqlite3_bind_int64(chk, 1, id);
    if (sqlite3_step(chk) != SQLITE_ROW) {
        sqlite3_finalize(chk); cJSON_Delete(body);
        send_error_json(c, 404, "venue not found"); return;
    }
    sqlite3_finalize(chk);

    /* partial update — あるフィールドだけ更新 */
    cJSON *it;
    it = cJSON_GetObjectItem(body, "name");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u; sqlite3_prepare_v2(db, "UPDATE venues SET name=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "description");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u; sqlite3_prepare_v2(db, "UPDATE venues SET description=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "address");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u; sqlite3_prepare_v2(db, "UPDATE venues SET address=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "phone");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u; sqlite3_prepare_v2(db, "UPDATE venues SET phone=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "施設を更新しました");
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_delete_venue(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id) {
    if (!require_admin(c, hm)) return;
    /* active plans があれば 409 */
    sqlite3_stmt *chk;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM plans WHERE venue_id=? AND is_active=1", -1, &chk, NULL);
    sqlite3_bind_int64(chk, 1, id);
    sqlite3_step(chk);
    long active = sqlite3_column_int64(chk, 0);
    sqlite3_finalize(chk);
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
        sqlite3_stmt *dp;
        sqlite3_prepare_v2(db, cascade[ci], -1, &dp, NULL);
        sqlite3_bind_int64(dp, 1, id);
        sqlite3_step(dp); sqlite3_finalize(dp);
    }
    /* venue を削除 */
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "DELETE FROM venues WHERE id=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(db) == 0) {
        send_error_json(c, 404, "venue not found"); return;
    }
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"施設を削除しました\"}");
}

/* ─── Plans ───────────────────────────────────────────────────────────────── */

void handle_admin_create_plan(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    long venue_id    = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "venue_id"));
    long category_id = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "category_id"));
    const char *title= cJSON_GetStringValue(cJSON_GetObjectItem(body, "title"));
    const char *desc = cJSON_GetStringValue(cJSON_GetObjectItem(body, "description"));
    long dur   = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "duration_minutes"));
    long minp  = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "min_participants"));
    long maxp  = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "max_participants"));
    long minage= (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "min_age"));
    cJSON *imgs = cJSON_GetObjectItem(body, "images");
    cJSON *tags = cJSON_GetObjectItem(body, "tags");
    char *imgs_str = imgs ? cJSON_PrintUnformatted(imgs) : NULL;
    char *tags_str = tags ? cJSON_PrintUnformatted(tags) : NULL;

    if (!title || !*title || venue_id<=0 || category_id<=0) {
        cJSON_Delete(body);
        if (imgs_str) cJSON_free(imgs_str);
        if (tags_str) cJSON_free(tags_str);
        send_error_json(c, 400, "title, venue_id, category_id は必須です");
        return;
    }

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "INSERT INTO plans(venue_id,category_id,title,description,duration_minutes,"
        "min_participants,max_participants,min_age,images,tags)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, venue_id);
    sqlite3_bind_int64(st, 2, category_id);
    sqlite3_bind_text(st, 3, title, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, desc ? desc : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, dur);
    sqlite3_bind_int64(st, 6, minp > 0 ? minp : 1);
    sqlite3_bind_int64(st, 7, maxp);
    sqlite3_bind_int64(st, 8, minage);
    sqlite3_bind_text(st, 9, imgs_str ? imgs_str : "[]", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 10, tags_str ? tags_str : "[]", -1, SQLITE_STATIC);
    sqlite3_step(st);
    long pid = sqlite3_last_insert_rowid(db);
    sqlite3_finalize(st);
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
            sqlite3_stmt *pi;
            sqlite3_prepare_v2(db,
                "INSERT INTO plan_prices(plan_id,participant_type,label,price) VALUES(?,?,?,?)",
                -1, &pi, NULL);
            sqlite3_bind_int64(pi, 1, pid);
            sqlite3_bind_text(pi, 2, pt, -1, SQLITE_STATIC);
            sqlite3_bind_text(pi, 3, lb, -1, SQLITE_STATIC);
            sqlite3_bind_int64(pi, 4, price);
            sqlite3_step(pi); sqlite3_finalize(pi);
        }
    }
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id", pid);
    cJSON_AddStringToObject(res, "message", "プランを作成しました");
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_update_plan(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    sqlite3_stmt *chk;
    sqlite3_prepare_v2(db, "SELECT id FROM plans WHERE id=?", -1, &chk, NULL);
    sqlite3_bind_int64(chk, 1, id);
    if (sqlite3_step(chk) != SQLITE_ROW) {
        sqlite3_finalize(chk); cJSON_Delete(body);
        send_error_json(c, 404, "plan not found"); return;
    }
    sqlite3_finalize(chk);

    cJSON *it;
    it = cJSON_GetObjectItem(body, "title");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u; sqlite3_prepare_v2(db, "UPDATE plans SET title=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "description");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u; sqlite3_prepare_v2(db, "UPDATE plans SET description=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "is_active");
    if (it && cJSON_IsBool(it)) {
        sqlite3_stmt *u; sqlite3_prepare_v2(db, "UPDATE plans SET is_active=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_int(u, 1, cJSON_IsTrue(it) ? 1 : 0);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "プランを更新しました");
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

void handle_admin_delete_plan(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id) {
    if (!require_admin(c, hm)) return;
    /* soft delete — is_active=0 */
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "UPDATE plans SET is_active=0 WHERE id=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, id);
    sqlite3_step(st); sqlite3_finalize(st);
    if (sqlite3_changes(db) == 0) {
        send_error_json(c, 404, "plan not found"); return;
    }
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"プランを非公開にしました\"}");
}

/* ─── Schedules ───────────────────────────────────────────────────────────── */

void handle_admin_create_schedule(struct mg_connection *c, struct mg_http_message *hm,
                                   sqlite3 *db, long plan_id) {
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

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "INSERT INTO schedules(plan_id,date,start_time,end_time,capacity)"
        " VALUES(?,?,?,?,?)", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, plan_id);
    sqlite3_bind_text(st, 2, date,  -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, start, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, end ? end : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, cap);
    sqlite3_step(st);
    long sid = sqlite3_last_insert_rowid(db);
    sqlite3_finalize(st);
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id", sid);
    cJSON_AddStringToObject(res, "message", "スケジュールを作成しました");
    send_cjson_admin(c, 201, res);
    cJSON_Delete(res);
}

void handle_admin_delete_schedule(struct mg_connection *c, struct mg_http_message *hm,
                                   sqlite3 *db, long id) {
    if (!require_admin(c, hm)) return;
    /* 予約があれば削除不可 */
    sqlite3_stmt *chk;
    sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM bookings WHERE schedule_id=? AND status!='cancelled'",
        -1, &chk, NULL);
    sqlite3_bind_int64(chk, 1, id);
    sqlite3_step(chk);
    long cnt = sqlite3_column_int64(chk, 0);
    sqlite3_finalize(chk);
    if (cnt > 0) {
        send_error_json(c, 409, "このスケジュールには有効な予約があるため削除できません");
        return;
    }

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "DELETE FROM schedules WHERE id=?", -1, &st, NULL);
    sqlite3_bind_int64(st, 1, id);
    sqlite3_step(st); sqlite3_finalize(st);
    if (sqlite3_changes(db) == 0) {
        send_error_json(c, 404, "schedule not found"); return;
    }
    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"スケジュールを削除しました\"}");
}

/* ─── Plan Prices ─────────────────────────────────────────────────────────── */

void handle_admin_set_prices(struct mg_connection *c, struct mg_http_message *hm,
                              sqlite3 *db, long plan_id) {
    if (!require_admin(c, hm)) return;
    cJSON *arr = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!arr || !cJSON_IsArray(arr)) {
        if (arr) cJSON_Delete(arr);
        send_error_json(c, 400, "配列で送信してください"); return;
    }

    /* 既存価格を削除して置き換え */
    sqlite3_stmt *del;
    sqlite3_prepare_v2(db, "DELETE FROM plan_prices WHERE plan_id=?", -1, &del, NULL);
    sqlite3_bind_int64(del, 1, plan_id);
    sqlite3_step(del); sqlite3_finalize(del);

    int n = cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        cJSON *pr = cJSON_GetArrayItem(arr, i);
        const char *pt = cJSON_GetStringValue(cJSON_GetObjectItem(pr, "participant_type"));
        const char *lb = cJSON_GetStringValue(cJSON_GetObjectItem(pr, "label"));
        long price     = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(pr, "price"));
        if (!pt || !lb || price <= 0) continue;
        sqlite3_stmt *ins;
        sqlite3_prepare_v2(db,
            "INSERT INTO plan_prices(plan_id,participant_type,label,price) VALUES(?,?,?,?)",
            -1, &ins, NULL);
        sqlite3_bind_int64(ins, 1, plan_id);
        sqlite3_bind_text(ins, 2, pt,    -1, SQLITE_STATIC);
        sqlite3_bind_text(ins, 3, lb,    -1, SQLITE_STATIC);
        sqlite3_bind_int64(ins, 4, price);
        sqlite3_step(ins); sqlite3_finalize(ins);
    }
    cJSON_Delete(arr);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"価格を更新しました\"}");
}

/* ─── GET /api/v1/admin/plans ─────────────────────────────────────────────── */

void handle_admin_list_plans(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    if (!require_admin(c, hm)) return;
    long page  = admin_query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit = admin_query_long(hm, "limit", 50); if (limit > 200) limit = 200;
    long offset = (page - 1) * limit;

    /* is_active フィルタ（デフォルト: 全件） */
    char active_str[8] = {0};
    int has_active = mg_http_get_var(&hm->query, "is_active", active_str, sizeof(active_str)) > 0;
    int active_val = has_active ? (int)strtol(active_str, NULL, 10) : -1;

    sqlite3_stmt *ct;
    sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM plans WHERE (? < 0 OR is_active=?)",
        -1, &ct, NULL);
    sqlite3_bind_int64(ct, 1, active_val);
    sqlite3_bind_int64(ct, 2, active_val);
    sqlite3_step(ct);
    long total = sqlite3_column_int64(ct, 0);
    sqlite3_finalize(ct);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT p.id,p.venue_id,v.name,p.category_id,c.name,"
        "p.title,p.is_active,p.min_participants,p.max_participants,"
        "p.duration_minutes,p.created_at "
        "FROM plans p "
        "JOIN venues v ON v.id=p.venue_id "
        "JOIN categories c ON c.id=p.category_id "
        "WHERE (? < 0 OR p.is_active=?) "
        "ORDER BY p.id LIMIT ? OFFSET ?",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, active_val);
    sqlite3_bind_int64(st, 2, active_val);
    sqlite3_bind_int64(st, 3, limit);
    sqlite3_bind_int64(st, 4, offset);

    cJSON *plans = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *p = cJSON_CreateObject();
        cJSON_AddNumberToObject(p, "id",             sqlite3_column_int64(st, 0));
        cJSON_AddNumberToObject(p, "venue_id",       sqlite3_column_int64(st, 1));
        cJSON_AddStringToObject(p, "venue_name",     (const char*)sqlite3_column_text(st, 2));
        cJSON_AddNumberToObject(p, "category_id",    sqlite3_column_int64(st, 3));
        cJSON_AddStringToObject(p, "category_name",  (const char*)sqlite3_column_text(st, 4));
        cJSON_AddStringToObject(p, "title",          (const char*)sqlite3_column_text(st, 5));
        cJSON_AddBoolToObject(p, "is_active",        sqlite3_column_int(st, 6) == 1);
        cJSON_AddNumberToObject(p, "min_participants",sqlite3_column_int64(st, 7));
        if (sqlite3_column_type(st, 8) != SQLITE_NULL)
            cJSON_AddNumberToObject(p, "max_participants", sqlite3_column_int64(st, 8));
        else cJSON_AddNullToObject(p, "max_participants");
        if (sqlite3_column_type(st, 9) != SQLITE_NULL)
            cJSON_AddNumberToObject(p, "duration_minutes", sqlite3_column_int64(st, 9));
        else cJSON_AddNullToObject(p, "duration_minutes");
        cJSON_AddStringToObject(p, "created_at",     (const char*)sqlite3_column_text(st, 10));
        cJSON_AddItemToArray(plans, p);
    }
    sqlite3_finalize(st);

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
                                   sqlite3 *db, long id) {
    if (!require_admin(c, hm)) return;
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    /* 存在確認 */
    sqlite3_stmt *chk;
    sqlite3_prepare_v2(db, "SELECT booked_count FROM schedules WHERE id=?", -1, &chk, NULL);
    sqlite3_bind_int64(chk, 1, id);
    if (sqlite3_step(chk) != SQLITE_ROW) {
        sqlite3_finalize(chk); cJSON_Delete(body);
        send_error_json(c, 404, "schedule not found"); return;
    }
    long booked = sqlite3_column_int64(chk, 0);
    sqlite3_finalize(chk);

    /* capacity 変更 — booked_count を下回る値は拒否 */
    cJSON *cap_item = cJSON_GetObjectItem(body, "capacity");
    if (cap_item && cJSON_IsNumber(cap_item)) {
        long new_cap = (long)cJSON_GetNumberValue(cap_item);
        if (new_cap < booked) {
            cJSON_Delete(body);
            send_error_json(c, 400, "capacity は現在の予約数を下回ることはできません"); return;
        }
        sqlite3_stmt *u;
        sqlite3_prepare_v2(db, "UPDATE schedules SET capacity=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_int64(u, 1, new_cap); sqlite3_bind_int64(u, 2, id);
        sqlite3_step(u); sqlite3_finalize(u);
    }
    cJSON *it;
    it = cJSON_GetObjectItem(body, "date");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u;
        sqlite3_prepare_v2(db, "UPDATE schedules SET date=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "start_time");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u;
        sqlite3_prepare_v2(db, "UPDATE schedules SET start_time=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    it = cJSON_GetObjectItem(body, "end_time");
    if (it && cJSON_IsString(it)) {
        sqlite3_stmt *u;
        sqlite3_prepare_v2(db, "UPDATE schedules SET end_time=? WHERE id=?", -1, &u, NULL);
        sqlite3_bind_text(u, 1, cJSON_GetStringValue(it), -1, SQLITE_STATIC);
        sqlite3_bind_int64(u, 2, id); sqlite3_step(u); sqlite3_finalize(u);
    }
    cJSON_Delete(body);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "message", "スケジュールを更新しました");
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/admin/bookings ────────────────────────────────────────────── */

void handle_admin_list_bookings(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
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
    sqlite3_stmt *ct;
    sqlite3_prepare_v2(db, cnt_sql, -1, &ct, NULL);
    sqlite3_bind_int64(ct, 1, plan_id_f); sqlite3_bind_int64(ct, 2, plan_id_f);
    sqlite3_bind_int64(ct, 3, user_id_f); sqlite3_bind_int64(ct, 4, user_id_f);
    sqlite3_bind_int(ct,  5, has_status); sqlite3_bind_text(ct,  6, status_f, -1, SQLITE_STATIC);
    sqlite3_bind_int(ct,  7, has_date);   sqlite3_bind_text(ct,  8, date_f,   -1, SQLITE_STATIC);
    sqlite3_step(ct);
    long total = sqlite3_column_int64(ct, 0);
    sqlite3_finalize(ct);

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
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, sel_sql, -1, &st, NULL);
    sqlite3_bind_int64(st, 1, plan_id_f); sqlite3_bind_int64(st, 2, plan_id_f);
    sqlite3_bind_int64(st, 3, user_id_f); sqlite3_bind_int64(st, 4, user_id_f);
    sqlite3_bind_int(st,  5, has_status); sqlite3_bind_text(st,  6, status_f, -1, SQLITE_STATIC);
    sqlite3_bind_int(st,  7, has_date);   sqlite3_bind_text(st,  8, date_f,   -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 9, limit); sqlite3_bind_int64(st, 10, offset);

    cJSON *bookings = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *b = cJSON_CreateObject();
        cJSON_AddStringToObject(b, "id",           (const char*)sqlite3_column_text(st, 0));
        cJSON_AddNumberToObject(b, "user_id",       sqlite3_column_int64(st, 1));
        if (sqlite3_column_type(st, 2) != SQLITE_NULL)
            cJSON_AddStringToObject(b, "user_name", (const char*)sqlite3_column_text(st, 2));
        else cJSON_AddNullToObject(b, "user_name");
        cJSON_AddStringToObject(b, "user_email",    (const char*)sqlite3_column_text(st, 3));
        cJSON_AddNumberToObject(b, "plan_id",        sqlite3_column_int64(st, 4));
        cJSON_AddStringToObject(b, "plan_title",     (const char*)sqlite3_column_text(st, 5));
        cJSON_AddNumberToObject(b, "schedule_id",    sqlite3_column_int64(st, 6));
        cJSON_AddStringToObject(b, "schedule_date",  (const char*)sqlite3_column_text(st, 7));
        cJSON_AddStringToObject(b, "schedule_start", (const char*)sqlite3_column_text(st, 8));
        cJSON_AddStringToObject(b, "status",         (const char*)sqlite3_column_text(st, 9));
        cJSON_AddNumberToObject(b, "total_price",    sqlite3_column_int64(st, 10));
        cJSON_AddStringToObject(b, "created_at",     (const char*)sqlite3_column_text(st, 11));
        cJSON_AddItemToArray(bookings, b);
    }
    sqlite3_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "bookings", bookings);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/admin/reviews ─────────────────────────────────────────────── */

void handle_admin_list_reviews(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
    if (!require_admin(c, hm)) return;
    long page    = admin_query_long(hm, "page", 1);  if (page < 1) page = 1;
    long limit   = admin_query_long(hm, "limit", 50); if (limit > 200) limit = 200;
    long offset  = (page - 1) * limit;
    long plan_id_f  = admin_query_long(hm, "plan_id", 0);
    long rating_f   = admin_query_long(hm, "rating", 0);

    sqlite3_stmt *ct;
    sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM reviews WHERE (? = 0 OR plan_id=?) AND (? = 0 OR rating=?)",
        -1, &ct, NULL);
    sqlite3_bind_int64(ct, 1, plan_id_f); sqlite3_bind_int64(ct, 2, plan_id_f);
    sqlite3_bind_int64(ct, 3, rating_f);  sqlite3_bind_int64(ct, 4, rating_f);
    sqlite3_step(ct);
    long total = sqlite3_column_int64(ct, 0);
    sqlite3_finalize(ct);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT r.id, r.user_id, u.name, r.plan_id, p.title, "
        "r.rating, r.comment, r.created_at "
        "FROM reviews r "
        "LEFT JOIN users u ON u.id=r.user_id "
        "LEFT JOIN plans p ON p.id=r.plan_id "
        "WHERE (? = 0 OR r.plan_id=?) AND (? = 0 OR r.rating=?) "
        "ORDER BY r.created_at DESC LIMIT ? OFFSET ?",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, plan_id_f); sqlite3_bind_int64(st, 2, plan_id_f);
    sqlite3_bind_int64(st, 3, rating_f);  sqlite3_bind_int64(st, 4, rating_f);
    sqlite3_bind_int64(st, 5, limit); sqlite3_bind_int64(st, 6, offset);

    cJSON *reviews = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *rv = cJSON_CreateObject();
        cJSON_AddNumberToObject(rv, "id",       sqlite3_column_int64(st, 0));
        cJSON_AddNumberToObject(rv, "user_id",  sqlite3_column_int64(st, 1));
        if (sqlite3_column_type(st, 2) != SQLITE_NULL)
            cJSON_AddStringToObject(rv, "user_name", (const char*)sqlite3_column_text(st, 2));
        else cJSON_AddNullToObject(rv, "user_name");
        cJSON_AddNumberToObject(rv, "plan_id",  sqlite3_column_int64(st, 3));
        if (sqlite3_column_type(st, 4) != SQLITE_NULL)
            cJSON_AddStringToObject(rv, "plan_title", (const char*)sqlite3_column_text(st, 4));
        else cJSON_AddNullToObject(rv, "plan_title");
        cJSON_AddNumberToObject(rv, "rating",   sqlite3_column_int64(st, 5));
        if (sqlite3_column_type(st, 6) != SQLITE_NULL)
            cJSON_AddStringToObject(rv, "comment", (const char*)sqlite3_column_text(st, 6));
        else cJSON_AddNullToObject(rv, "comment");
        cJSON_AddStringToObject(rv, "created_at", (const char*)sqlite3_column_text(st, 7));
        cJSON_AddItemToArray(reviews, rv);
    }
    sqlite3_finalize(st);

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
                                 sqlite3 *db, long id) {
    if (!require_admin(c, hm)) return;

    sqlite3_stmt *chk;
    sqlite3_prepare_v2(db, "SELECT id FROM reviews WHERE id=?", -1, &chk, NULL);
    sqlite3_bind_int64(chk, 1, id);
    if (sqlite3_step(chk) != SQLITE_ROW) {
        sqlite3_finalize(chk);
        send_error_json(c, 404, "review not found"); return;
    }
    sqlite3_finalize(chk);

    sqlite3_stmt *del;
    sqlite3_prepare_v2(db, "DELETE FROM reviews WHERE id=?", -1, &del, NULL);
    sqlite3_bind_int64(del, 1, id);
    sqlite3_step(del); sqlite3_finalize(del);

    send_json_str(c, 200, CORS_HEADERS, "{\"message\":\"レビューを削除しました\"}");
}

/* ─── GET /api/v1/admin/users ───────────────────────────────────────────────── */

void handle_admin_list_users(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db) {
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

    sqlite3_stmt *ct;
    sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM users WHERE (? = 0 OR email LIKE ? ESCAPE '\\')",
        -1, &ct, NULL);
    sqlite3_bind_int(ct, 1, has_q); sqlite3_bind_text(ct, 2, kw, -1, SQLITE_STATIC);
    sqlite3_step(ct);
    long total = sqlite3_column_int64(ct, 0);
    sqlite3_finalize(ct);

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db,
        "SELECT u.id, u.name, u.email, u.created_at, "
        "(SELECT COUNT(*) FROM bookings b WHERE b.user_id=u.id AND b.status='confirmed') AS booking_count "
        "FROM users u "
        "WHERE (? = 0 OR u.email LIKE ? ESCAPE '\\') "
        "ORDER BY u.id LIMIT ? OFFSET ?",
        -1, &st, NULL);
    sqlite3_bind_int(st, 1, has_q); sqlite3_bind_text(st, 2, kw, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, limit); sqlite3_bind_int64(st, 4, offset);

    cJSON *users = cJSON_CreateArray();
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *u = cJSON_CreateObject();
        cJSON_AddNumberToObject(u, "id",            sqlite3_column_int64(st, 0));
        if (sqlite3_column_type(st, 1) != SQLITE_NULL)
            cJSON_AddStringToObject(u, "name",      (const char*)sqlite3_column_text(st, 1));
        else cJSON_AddNullToObject(u, "name");
        cJSON_AddStringToObject(u, "email",         (const char*)sqlite3_column_text(st, 2));
        cJSON_AddStringToObject(u, "created_at",    (const char*)sqlite3_column_text(st, 3));
        cJSON_AddNumberToObject(u, "booking_count", sqlite3_column_int64(st, 4));
        cJSON_AddItemToArray(users, u);
    }
    sqlite3_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "users", users);
    cJSON_AddNumberToObject(res, "total", total);
    cJSON_AddNumberToObject(res, "page",  page);
    cJSON_AddNumberToObject(res, "limit", limit);
    send_cjson_admin(c, 200, res);
    cJSON_Delete(res);
}
