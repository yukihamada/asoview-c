#pragma once
#include "mongoose.h"
#include "db_driver.h"

void handle_portal(struct mg_connection *c, struct mg_http_message *hm, DbConn *db);
