#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── SQLite バックエンド ─────────────────────────────────────────────────── */
#if !defined(USE_POSTGRES) && !defined(USE_MYSQL)

static const char *SCHEMA_SQL =
#include "schema_embed.h"
;

static int exec_ok(DbConn *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[db] SQL error: %s\n", err ? err : "unknown");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int db_migrate(DbConn *db) {
    return exec_ok(db, SCHEMA_SQL);
}

DbConn *db_open(const char *path) {
    sqlite3 *raw;
    if (sqlite3_open(path, &raw) != SQLITE_OK) {
        fprintf(stderr, "[db] Cannot open: %s\n", sqlite3_errmsg(raw));
        sqlite3_close(raw);
        return NULL;
    }
    DbConn *db = raw; /* DbConn == sqlite3 for SQLite backend */
    exec_ok(db, "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA wal_autocheckpoint=100;");
    if (db_migrate(db) != 0) {
        sqlite3_close(db);
        return NULL;
    }
    /* 既存 DB への後方互換マイグレーション（失敗は無視） */
    sqlite3_exec(db,
        "ALTER TABLE bookings ADD COLUMN stripe_payment_intent_id TEXT",
        NULL, NULL, NULL);
    sqlite3_exec(db,
        "ALTER TABLE users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0",
        NULL, NULL, NULL);
    sqlite3_exec(db,
        "ALTER TABLE users ADD COLUMN locked_until TEXT",
        NULL, NULL, NULL);
    /* FTS5 インデックスを既存データで再構築（INSERT トリガーで新規データは自動追加） */
    sqlite3_exec(db,
        "INSERT INTO plans_fts(plans_fts) VALUES('rebuild')",
        NULL, NULL, NULL);
    return db;
}

void db_close(DbConn *db) {
    if (db) sqlite3_close(db);
}

/* ─── PostgreSQL / MySQL バックエンド ─────────────────────────────────────── */
#else

/*
 * スキーマは外部で適用済み（psql -f schema_postgres.sql / mysql < schema_mysql.sql）。
 * db_migrate() は接続確認のみ行う。
 */
int db_migrate(DbConn *db) {
    if (db_exec(db, "SELECT 1") != 0) {
        fprintf(stderr, "[db] connectivity check failed\n");
        return -1;
    }
    return 0;
}

DbConn *db_open(const char *path) {
    /* DATABASE_URL 環境変数を優先。未設定なら path を URI として使う */
    const char *uri = getenv("DATABASE_URL");
    if (!uri || !*uri) uri = path;

    DbConn *db = db_open_backend(uri);
    if (!db) return NULL;

    if (db_migrate(db) != 0) {
        db_close_backend(db);
        return NULL;
    }
    return db;
}

void db_close(DbConn *db) {
    db_close_backend(db);
}

#endif /* USE_POSTGRES || USE_MYSQL */
