#pragma once
#include "mongoose.h"
#include <sqlite3.h>

/* JSON レスポンス送信ヘルパー */
void send_json_str(struct mg_connection *c, int status,
                   const char *headers_extra, const char *json_body);
void send_error_json(struct mg_connection *c, int status, const char *msg);

/* ─── Route handlers ──────────────────────────────────────────────────── */
void handle_health           (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_list_areas       (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_list_categories  (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_list_venues      (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_get_venue        (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_list_plans       (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_get_plan         (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_list_schedules   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long plan_id);
void handle_create_user      (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_login            (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_create_booking   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_get_booking      (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, const char *id);
void handle_list_user_bookings(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long user_id);
void handle_create_review    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_search           (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_cancel_booking   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, const char *id);
void handle_list_plan_reviews(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long plan_id);
void handle_list_venue_plans (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long venue_id);
void handle_get_user         (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_update_user      (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_stripe_webhook   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_create_bookmark    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_delete_bookmark    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long plan_id);
void handle_list_user_bookmarks(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long user_id);
/* Auth */
void handle_change_password  (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_forgot_password  (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_reset_password   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
/* Reviews */
void handle_delete_review    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
/* Auth */
void handle_auth_refresh     (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
