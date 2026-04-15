#pragma once
#include "mongoose.h"
#include <sqlite3.h>

/* 管理者API — X-Admin-Key ヘッダで認証 */
/* Venues */
void handle_admin_list_venues    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_admin_create_venue   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_admin_update_venue   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_admin_delete_venue   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
/* Plans */
void handle_admin_list_plans     (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_admin_create_plan    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_admin_update_plan    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_admin_delete_plan    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
/* Schedules */
void handle_admin_create_schedule(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long plan_id);
void handle_admin_update_schedule(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_admin_delete_schedule(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
/* Prices */
void handle_admin_set_prices     (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long plan_id);
/* Bookings */
void handle_admin_list_bookings  (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
/* Reviews */
void handle_admin_list_reviews   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_admin_delete_review  (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
/* Users */
void handle_admin_list_users     (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
