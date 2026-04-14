#pragma once
#include <sqlite3.h>

/* データベース初期化 (スキーマ適用込み)
   成功時は sqlite3* を返す、失敗時は NULL */
sqlite3 *db_open(const char *path);
void     db_close(sqlite3 *db);

/* スキーマ (migrations/schema.sql) を適用 */
int db_migrate(sqlite3 *db);
