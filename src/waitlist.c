#include "waitlist.h"
#include "handlers.h"
#include "mailer.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── POST /api/v1/waitlist ────────────────────────────────────────────────── */

void handle_create_waitlist(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    /* JWT 必須 */
    struct mg_str *hdr = mg_http_get_header(hm, "Authorization");
    if (!hdr || hdr->len <= 7) {
        send_error_json(c, 401, "認証が必要です"); return;
    }
    /* JWT を検証して user_id を取得 */
    extern char g_request_id[];
    (void)g_request_id;

    /* Auth: call the internal require_auth via a helper approach.
       Since require_auth is static in handlers.c, we duplicate the token check here. */
    size_t tok_len = hdr->len - 7;
    char tok[512] = {0};
    if (tok_len >= sizeof(tok)) { send_error_json(c, 401, "token too long"); return; }
    if (strncasecmp(hdr->buf, "Bearer ", 7) != 0) {
        send_error_json(c, 401, "Bearer トークンが必要です"); return;
    }
    memcpy(tok, hdr->buf + 7, tok_len);
    tok[tok_len] = '\0';

    /* Use jwt_verify — declared in utils.h */
    extern long jwt_verify(const char *token, const char *secret);
    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "asoview-jwt-secret-dev";
    long auth_uid = jwt_verify(tok, secret);
    if (auth_uid <= 0) {
        send_error_json(c, 401, "トークンが無効または期限切れです"); return;
    }

    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) { send_error_json(c, 400, "invalid JSON"); return; }

    long schedule_id = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(body, "schedule_id"));
    cJSON_Delete(body);

    if (schedule_id <= 0) {
        send_error_json(c, 400, "schedule_id は必須です"); return;
    }

    /* スケジュール存在確認 */
    DbStmt *chk = NULL;
    chk = db_prepare(db, "SELECT id FROM schedules WHERE id=?");
    db_bind_int(chk, 1, schedule_id);
    if (db_step(chk) != 1) {
        db_finalize(chk);
        send_error_json(c, 404, "schedule not found"); return;
    }
    db_finalize(chk);

    DbStmt *ins = NULL;
    ins = db_prepare(db,
        "INSERT OR IGNORE INTO waitlist(user_id, schedule_id) VALUES(?,?)");
    db_bind_int(ins, 1, auth_uid);
    db_bind_int(ins, 2, schedule_id);
    db_step(ins);
    int changes = db_changes(db);
    db_finalize(ins);

    if (changes == 0) {
        send_error_json(c, 409, "既にウェイトリストに登録されています"); return;
    }

    long wid = (long)db_last_id(db);

    /* 現在のウェイトリスト順位 */
    DbStmt *pos = NULL;
    pos = db_prepare(db,
        "SELECT COUNT(*) FROM waitlist WHERE schedule_id=? AND id<=?");
    db_bind_int(pos, 1, schedule_id);
    db_bind_int(pos, 2, wid);
    db_step(pos);
    long position = db_col_int(pos, 0);
    db_finalize(pos);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "id",          wid);
    cJSON_AddNumberToObject(res, "user_id",     auth_uid);
    cJSON_AddNumberToObject(res, "schedule_id", schedule_id);
    cJSON_AddNumberToObject(res, "position",    position);
    cJSON_AddStringToObject(res, "message",     "ウェイトリストに登録しました");
    char *s = cJSON_PrintUnformatted(res);
    send_json_str(c, 201, "Content-Type: application/json\r\n", s);
    cJSON_free(s);
    cJSON_Delete(res);
}

/* ─── GET /api/v1/waitlist/:schedule_id ────────────────────────────────────── */

void handle_list_waitlist(struct mg_connection *c, struct mg_http_message *hm,
                          DbConn *db, long schedule_id) {
    (void)hm;
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT w.id, w.user_id, u.name, w.schedule_id, w.created_at "
        "FROM waitlist w JOIN users u ON u.id=w.user_id "
        "WHERE w.schedule_id=? ORDER BY w.id");
    db_bind_int(st, 1, schedule_id);

    cJSON *arr = cJSON_CreateArray();
    long pos = 0;
    while (db_step(st) == 1) {
        pos++;
        cJSON *w = cJSON_CreateObject();
        cJSON_AddNumberToObject(w, "id",          db_col_int(st, 0));
        cJSON_AddNumberToObject(w, "user_id",     db_col_int(st, 1));
        cJSON_AddStringToObject(w, "user_name",   db_col_text(st, 2));
        cJSON_AddNumberToObject(w, "schedule_id", db_col_int(st, 3));
        cJSON_AddNumberToObject(w, "position",    pos);
        cJSON_AddStringToObject(w, "created_at",  db_col_text(st, 4));
        cJSON_AddItemToArray(arr, w);
    }
    db_finalize(st);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddItemToObject(res, "waitlist",    arr);
    cJSON_AddNumberToObject(res, "schedule_id", schedule_id);
    char *s = cJSON_PrintUnformatted(res);
    send_json_str(c, 200, "Content-Type: application/json\r\n", s);
    cJSON_free(s);
    cJSON_Delete(res);
}

/* ─── DELETE /api/v1/waitlist/:id ──────────────────────────────────────────── */

void handle_delete_waitlist(struct mg_connection *c, struct mg_http_message *hm,
                             DbConn *db, long id) {
    /* JWT 必須 */
    struct mg_str *hdr = mg_http_get_header(hm, "Authorization");
    if (!hdr || hdr->len <= 7 || strncasecmp(hdr->buf, "Bearer ", 7) != 0) {
        send_error_json(c, 401, "認証が必要です"); return;
    }
    size_t tok_len = hdr->len - 7;
    char tok[512] = {0};
    if (tok_len >= sizeof(tok)) { send_error_json(c, 401, "token too long"); return; }
    memcpy(tok, hdr->buf + 7, tok_len);
    tok[tok_len] = '\0';

    extern long jwt_verify(const char *token, const char *secret);
    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "asoview-jwt-secret-dev";
    long auth_uid = jwt_verify(tok, secret);
    if (auth_uid <= 0) {
        send_error_json(c, 401, "トークンが無効または期限切れです"); return;
    }

    /* 自分のエントリのみ削除可 */
    DbStmt *del = NULL;
    del = db_prepare(db,
        "DELETE FROM waitlist WHERE id=? AND user_id=?");
    db_bind_int(del, 1, id);
    db_bind_int(del, 2, auth_uid);
    db_step(del);
    int changes = db_changes(db);
    db_finalize(del);

    if (changes == 0) {
        send_error_json(c, 404, "ウェイトリストエントリが見つかりません"); return;
    }
    send_json_str(c, 200, "Content-Type: application/json\r\n",
                  "{\"message\":\"ウェイトリストから削除しました\"}");
}

/* ─── 空き発生時のウェイトリスト通知 ────────────────────────────────────────── */

void notify_waitlist(DbConn *db, long schedule_id) {
    /* 最初のウェイトリストユーザーにメール通知 */
    DbStmt *st = NULL;
    st = db_prepare(db,
        "SELECT w.id, u.email, p.title, s.date, s.start_time "
        "FROM waitlist w "
        "JOIN users u ON u.id=w.user_id "
        "JOIN schedules s ON s.id=w.schedule_id "
        "JOIN plans p ON p.id=s.plan_id "
        "WHERE w.schedule_id=? AND w.notified=0 "
        "ORDER BY w.id LIMIT 1");
    db_bind_int(st, 1, schedule_id);

    if (db_step(st) == 1) {
        long wid        = db_col_int(st, 0);
        const char *email = db_col_text(st, 1);
        const char *title = db_col_text(st, 2);
        const char *date  = db_col_text(st, 3);
        const char *stime = db_col_text(st, 4);

        if (email) {
            char subj[256], html[1024];
            snprintf(subj, sizeof(subj), "【空き発生】%s", title ? title : "");
            snprintf(html, sizeof(html),
                "<h2>空きが発生しました</h2>"
                "<p>%s (%s %s) のキャンセルにより空きが発生しました。"
                "お早めにご予約ください。</p>",
                title ? title : "", date ? date : "", stime ? stime : "");
            send_email(email, subj, html);
        }

        /* 通知済みマーク */
        DbStmt *upd = NULL;
        upd = db_prepare(db,
            "UPDATE waitlist SET notified=1 WHERE id=?");
        db_bind_int(upd, 1, wid);
        db_step(upd); db_finalize(upd);
    }
    db_finalize(st);
}
