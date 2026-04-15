#pragma once
#include "db_driver.h"

/* データベース初期化 (スキーマ適用込み)
   成功時は DbConn* を返す、失敗時は NULL */
DbConn *db_open(const char *path);
void    db_close(DbConn *db);

/* スキーマ (migrations/schema.sql) を適用 */
int db_migrate(DbConn *db);

/* トランザクション制御
   SQLite: BEGIN IMMEDIATE / COMMIT / ROLLBACK
   PG/MySQL: BEGIN / COMMIT / ROLLBACK */
void db_begin(DbConn *db);
void db_commit(DbConn *db);
void db_rollback(DbConn *db);
