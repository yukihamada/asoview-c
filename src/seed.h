#pragma once
#include "db_driver.h"

/* DB が空なら初期データを挿入する */
int seed_if_empty(DbConn *db);
