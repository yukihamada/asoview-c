#pragma once
#include "mongoose.h"
#include "db_driver.h"

void handle_create_waitlist(struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
void handle_list_waitlist  (struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long schedule_id);
void handle_delete_waitlist(struct mg_connection *c, struct mg_http_message *hm, DbConn *db, long id);
void notify_waitlist       (DbConn *db, long schedule_id);
