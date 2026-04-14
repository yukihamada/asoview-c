#include "admin.h"
#include "handlers.h"   /* send_json_str, send_error_json */
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CORS_HEADERS "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n"

/* ─── Admin 認証 ──────────────────────────────────────────────────────────── */

static int require_admin(struct mg_connection *c, struct mg_http_message *hm) {
    struct mg_str *hdr = mg_http_get_header(hm, "X-Admin-Key");
    if (!hdr) { send_error_json(c, 403, "管理者キーが必要です"); return 0; }
    const char *expected = getenv("ADMIN_KEY");
    if (!expected || !*expected) expected = "asoview-admin-dev";
    char key[256] = {0};
    size_t kl = hdr->len < sizeof(key)-1 ? hdr->len : sizeof(key)-1;
    memcpy(key, hdr->buf, kl);
    if (strcmp(key, expected) != 0) { send_error_json(c, 403, "管理者キーが不正です"); return 0; }
    return 1;
}

static void send_cjson_admin(struct mg_connection *c, int status, cJSON *obj) {
    char *s = cJSON_PrintUnformatted(obj);
    send_json_str(c, status, CORS_HEADERS, s);
    cJSON_free(s);
}

/* ─── Venues ──────────────────────────────────────────────────────────────── */

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
