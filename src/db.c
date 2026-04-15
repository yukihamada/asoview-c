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
    /* マイグレーションバージョン管理テーブル */
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS schema_migrations("
        "version INTEGER PRIMARY KEY,"
        "applied_at TEXT NOT NULL DEFAULT (datetime('now')))",
        NULL, NULL, NULL);

    /* ヘルパー: バージョンが未適用なら SQL を実行して記録 */
    /* NOTE: defined as a static nested helper using a block-scope lambda pattern */
#define APPLY_MIGRATION(ver, sql) do { \
    sqlite3_stmt *_chk = NULL; \
    sqlite3_prepare_v2(db, "SELECT 1 FROM schema_migrations WHERE version=?", -1, &_chk, NULL); \
    sqlite3_bind_int(_chk, 1, (ver)); \
    int _found = (sqlite3_step(_chk) == SQLITE_ROW); \
    sqlite3_finalize(_chk); \
    if (!_found) { \
        sqlite3_exec(db, (sql), NULL, NULL, NULL); \
        sqlite3_stmt *_ins = NULL; \
        sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO schema_migrations(version) VALUES(?)", -1, &_ins, NULL); \
        sqlite3_bind_int(_ins, 1, (ver)); \
        sqlite3_step(_ins); \
        sqlite3_finalize(_ins); \
    } \
} while (0)

    /* 既存 DB への後方互換マイグレーション（バージョン管理付き） */
    APPLY_MIGRATION(1, "ALTER TABLE bookings ADD COLUMN stripe_payment_intent_id TEXT");
    APPLY_MIGRATION(2, "ALTER TABLE users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0");
    APPLY_MIGRATION(3, "ALTER TABLE users ADD COLUMN locked_until TEXT");
    APPLY_MIGRATION(4, "ALTER TABLE plans ADD COLUMN cancel_days_full INTEGER NOT NULL DEFAULT 7");
    APPLY_MIGRATION(5, "ALTER TABLE plans ADD COLUMN cancel_days_partial INTEGER NOT NULL DEFAULT 3");
    APPLY_MIGRATION(6, "ALTER TABLE plans ADD COLUMN cancel_pct_partial INTEGER NOT NULL DEFAULT 50");
    /* 2FA TOTP */
    APPLY_MIGRATION(7, "ALTER TABLE users ADD COLUMN totp_secret TEXT");
    APPLY_MIGRATION(8, "ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0");
    /* クーポン */
    APPLY_MIGRATION(9,
        "CREATE TABLE IF NOT EXISTS coupons("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "code TEXT UNIQUE NOT NULL COLLATE NOCASE,"
        "description TEXT,"
        "discount_type TEXT NOT NULL DEFAULT 'percent',"
        "discount_value INTEGER NOT NULL,"
        "max_uses INTEGER,"
        "used_count INTEGER NOT NULL DEFAULT 0,"
        "expires_at TEXT,"
        "is_active INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL DEFAULT (datetime('now')))");
    /* Webhook エンドポイント */
    APPLY_MIGRATION(10,
        "CREATE TABLE IF NOT EXISTS webhook_endpoints("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "url TEXT NOT NULL,"
        "secret TEXT NOT NULL,"
        "events TEXT NOT NULL DEFAULT '[]',"
        "is_active INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL DEFAULT (datetime('now')))");
    APPLY_MIGRATION(11,
        "CREATE TABLE IF NOT EXISTS webhook_deliveries("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "endpoint_id INTEGER NOT NULL REFERENCES webhook_endpoints(id),"
        "event TEXT NOT NULL,"
        "payload TEXT NOT NULL,"
        "response_code INTEGER,"
        "delivered_at TEXT NOT NULL DEFAULT (datetime('now')),"
        "success INTEGER NOT NULL DEFAULT 0)");
    /* プラン追加画像 */
    APPLY_MIGRATION(12,
        "CREATE TABLE IF NOT EXISTS plan_images("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "plan_id INTEGER NOT NULL REFERENCES plans(id),"
        "url TEXT NOT NULL,"
        "display_order INTEGER NOT NULL DEFAULT 0,"
        "created_at TEXT NOT NULL DEFAULT (datetime('now')))");
    /* 予約にクーポン適用列 */
    APPLY_MIGRATION(13, "ALTER TABLE bookings ADD COLUMN coupon_id INTEGER REFERENCES coupons(id)");
    APPLY_MIGRATION(14, "ALTER TABLE bookings ADD COLUMN discount_amount INTEGER NOT NULL DEFAULT 0");

    /* ─── パフォーマンスインデックス ─────────────────────────────────────── */
    APPLY_MIGRATION(15,
        "CREATE INDEX IF NOT EXISTS idx_bookings_user_id   ON bookings(user_id);"
        "CREATE INDEX IF NOT EXISTS idx_bookings_plan_id   ON bookings(plan_id);"
        "CREATE INDEX IF NOT EXISTS idx_bookings_schedule  ON bookings(schedule_id);"
        "CREATE INDEX IF NOT EXISTS idx_bookings_status    ON bookings(status);"
        "CREATE INDEX IF NOT EXISTS idx_bookings_created   ON bookings(created_at DESC)");
    APPLY_MIGRATION(16,
        "CREATE INDEX IF NOT EXISTS idx_reviews_plan_id    ON reviews(plan_id);"
        "CREATE INDEX IF NOT EXISTS idx_reviews_user_id    ON reviews(user_id);"
        "CREATE INDEX IF NOT EXISTS idx_reviews_created    ON reviews(created_at DESC)");
    APPLY_MIGRATION(17,
        "CREATE INDEX IF NOT EXISTS idx_bookmarks_user_id  ON bookmarks(user_id);"
        "CREATE INDEX IF NOT EXISTS idx_bookmarks_plan_id  ON bookmarks(plan_id);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_bookmarks_uniq ON bookmarks(user_id, plan_id)");
    APPLY_MIGRATION(18,
        "CREATE INDEX IF NOT EXISTS idx_schedules_plan_id  ON schedules(plan_id);"
        "CREATE INDEX IF NOT EXISTS idx_schedules_date     ON schedules(start_date)");
    APPLY_MIGRATION(19,
        "CREATE INDEX IF NOT EXISTS idx_plans_venue_id     ON plans(venue_id);"
        "CREATE INDEX IF NOT EXISTS idx_plans_category_id  ON plans(category_id)");
    APPLY_MIGRATION(20,
        "CREATE INDEX IF NOT EXISTS idx_audit_actor        ON audit_logs(actor_id);"
        "CREATE INDEX IF NOT EXISTS idx_audit_created      ON audit_logs(created_at DESC)");
    APPLY_MIGRATION(21,
        "CREATE INDEX IF NOT EXISTS idx_jwt_blocklist_jti  ON jwt_blocklist(jti);"
        "CREATE INDEX IF NOT EXISTS idx_jwt_blocklist_exp  ON jwt_blocklist(expires_at)");
    APPLY_MIGRATION(22,
        "CREATE INDEX IF NOT EXISTS idx_users_email        ON users(email)");

    /* ─── マルチテナント基盤 ──────────────────────────────────────────────── */
    APPLY_MIGRATION(23,
        "CREATE TABLE IF NOT EXISTS tenants("
        "id         INTEGER PRIMARY KEY AUTOINCREMENT,"
        "slug       TEXT UNIQUE NOT NULL COLLATE NOCASE,"
        "name       TEXT NOT NULL,"
        "api_key    TEXT UNIQUE NOT NULL,"
        "plan_limit INTEGER NOT NULL DEFAULT 100,"
        "is_active  INTEGER NOT NULL DEFAULT 1,"
        "created_at TEXT NOT NULL DEFAULT (datetime('now')))");
    APPLY_MIGRATION(24,
        "ALTER TABLE venues ADD COLUMN tenant_id INTEGER REFERENCES tenants(id)");
    APPLY_MIGRATION(25,
        "CREATE INDEX IF NOT EXISTS idx_venues_tenant_id ON venues(tenant_id);"
        "CREATE INDEX IF NOT EXISTS idx_tenants_slug     ON tenants(slug)");

    /* ─── スタッフロール / ギフト券 / OAuth / リマインダー ───────────────── */
    APPLY_MIGRATION(26,
        "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
    APPLY_MIGRATION(27,
        "CREATE TABLE IF NOT EXISTS staff_venues("
        "user_id  INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,"
        "venue_id INTEGER NOT NULL REFERENCES venues(id) ON DELETE CASCADE,"
        "PRIMARY KEY (user_id, venue_id))");
    APPLY_MIGRATION(28,
        "ALTER TABLE bookings ADD COLUMN reminder_sent INTEGER NOT NULL DEFAULT 0");
    APPLY_MIGRATION(29,
        "CREATE TABLE IF NOT EXISTS gift_cards("
        "id                INTEGER PRIMARY KEY AUTOINCREMENT,"
        "code              TEXT UNIQUE NOT NULL,"
        "initial_amount    INTEGER NOT NULL,"
        "remaining_balance INTEGER NOT NULL,"
        "issued_to_email   TEXT,"
        "expires_at        TEXT,"
        "is_active         INTEGER NOT NULL DEFAULT 1,"
        "created_at        TEXT NOT NULL DEFAULT (datetime('now')))");
    APPLY_MIGRATION(30,
        "ALTER TABLE bookings ADD COLUMN gift_card_id INTEGER REFERENCES gift_cards(id)");
    APPLY_MIGRATION(31,
        "ALTER TABLE bookings ADD COLUMN gift_discount INTEGER NOT NULL DEFAULT 0");
    APPLY_MIGRATION(32,
        "ALTER TABLE users ADD COLUMN google_id TEXT");
    APPLY_MIGRATION(33,
        "CREATE INDEX IF NOT EXISTS idx_gift_cards_code  ON gift_cards(code);"
        "CREATE INDEX IF NOT EXISTS idx_users_role       ON users(role);"
        "CREATE INDEX IF NOT EXISTS idx_users_google_id  ON users(google_id);"
        "CREATE INDEX IF NOT EXISTS idx_staff_venues_uid ON staff_venues(user_id)");
#undef APPLY_MIGRATION
    /* FTS5 インデックスを既存データで再構築（INSERT トリガーで新規データは自動追加） */
    sqlite3_exec(db,
        "INSERT INTO plans_fts(plans_fts) VALUES('rebuild')",
        NULL, NULL, NULL);
    return db;
}

void db_close(DbConn *db) {
    if (db) sqlite3_close(db);
}

void db_begin(DbConn *db) {
    /* BEGIN IMMEDIATE: SQLite では書き込みロックを即座に取得し競合を防ぐ */
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
}
void db_commit(DbConn *db)   { sqlite3_exec(db, "COMMIT",   NULL, NULL, NULL); }
void db_rollback(DbConn *db) { sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL); }

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

void db_begin(DbConn *db)    { db_exec(db, "BEGIN"); }
void db_commit(DbConn *db)   { db_exec(db, "COMMIT"); }
void db_rollback(DbConn *db) { db_exec(db, "ROLLBACK"); }

#endif /* USE_POSTGRES || USE_MYSQL */
