#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *SCHEMA_SQL =
#include "schema_embed.h"
;

static int exec_ok(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[db] SQL error: %s\n", err ? err : "unknown");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int db_migrate(sqlite3 *db) {
    return exec_ok(db, SCHEMA_SQL);
}

sqlite3 *db_open(const char *path) {
    sqlite3 *db;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        fprintf(stderr, "[db] Cannot open: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }
    exec_ok(db, "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    if (db_migrate(db) != 0) {
        sqlite3_close(db);
        return NULL;
    }
    /* 既存 DB への後方互換マイグレーション（失敗は無視） */
    sqlite3_exec(db,
        "ALTER TABLE bookings ADD COLUMN stripe_payment_intent_id TEXT",
        NULL, NULL, NULL);
    /* password_reset_tokens は CREATE TABLE IF NOT EXISTS で自動作成される */
    return db;
}

void db_close(sqlite3 *db) {
    if (db) sqlite3_close(db);
}
