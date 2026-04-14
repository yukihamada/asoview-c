#pragma once
#include "mongoose.h"
#include <sqlite3.h>

/* 管理者API — X-Admin-Key ヘッダで認証 */
void handle_admin_list_venues    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_admin_create_venue   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_admin_list_plans     (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_admin_update_venue   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_admin_delete_venue   (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_admin_create_plan    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db);
void handle_admin_update_plan    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_admin_delete_plan    (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_admin_create_schedule(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long plan_id);
void handle_admin_delete_schedule(struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long id);
void handle_admin_set_prices     (struct mg_connection *c, struct mg_http_message *hm, sqlite3 *db, long plan_id);
