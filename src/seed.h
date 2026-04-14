#pragma once
#include <sqlite3.h>

/* DB が空なら初期データを挿入する */
int seed_if_empty(sqlite3 *db);
