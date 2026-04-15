/*
 * db_driver.h — データベース抽象化レイヤー
 *
 * コンパイル時に -DUSE_POSTGRES / -DUSE_MYSQL / (デフォルト) SQLite を選択:
 *   make DB=sqlite    (デフォルト)
 *   make DB=postgres  → -DUSE_POSTGRES -lpq
 *   make DB=mysql     → -DUSE_MYSQL    -lmysqlclient
 *
 * 各バックエンドは同一の db_* API を提供する。
 * SQLite バックエンドでは typedef で sqlite3/sqlite3_stmt に透過マップするため
 * 既存コードはほぼ変更不要。
 */
#pragma once
#include <stddef.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * SQLite バックエンド（デフォルト）
 * ═══════════════════════════════════════════════════════════════════════════ */
#if defined(USE_POSTGRES)
/* ─── PostgreSQL ─ (db_postgres.c で実装) ─────────────────────────────────── */

typedef struct DbConn DbConn;
typedef struct DbStmt DbStmt;

DbConn      *db_open_backend(const char *uri);
void         db_close_backend(DbConn *db);
int          db_exec(DbConn *db, const char *sql);
DbStmt      *db_prepare(DbConn *db, const char *sql);
void         db_bind_int(DbStmt *st, int idx, long long val);
void         db_bind_text(DbStmt *st, int idx, const char *val);
void         db_bind_double(DbStmt *st, int idx, double val);
int          db_step(DbStmt *st);          /* 1=行あり, 0=完了, -1=エラー */
long long    db_col_int(DbStmt *st, int col);
const char  *db_col_text(DbStmt *st, int col);
double       db_col_double(DbStmt *st, int col);
int          db_col_is_null(DbStmt *st, int col);
void         db_finalize(DbStmt *st);
void         db_reset(DbStmt *st);
long long    db_last_id(DbConn *db);
int          db_changes(DbConn *db);
const char  *db_errmsg(DbConn *db);

/* SQL ダイアレクト: PostgreSQL */
#define SQL_NOW_STR           "CURRENT_TIMESTAMP"
#define SQL_NOW_PLUS_MIN(n)   "CURRENT_TIMESTAMP + INTERVAL '" #n " minutes'"
#define SQL_NOW_PLUS_HOUR(n)  "CURRENT_TIMESTAMP + INTERVAL '" #n " hours'"
#define SQL_NOW_PLUS_DAY(n)   "CURRENT_TIMESTAMP + INTERVAL '" #n " days'"
/* FTS: PostgreSQL は tsvector/tsquery を使用。plans_fts FTS5 は不要 */
#define SQL_FTS_MATCH(col, param) \
    "(search_vector @@ plainto_tsquery('simple', " param "))"
#define SQL_USES_POSTGRES_FTS 1
/* INSERT 重複無視: PostgreSQL は ON CONFLICT DO NOTHING */
#define SQL_INSERT_OR_IGNORE  "INSERT"
#define SQL_ON_CONFLICT_IGNORE " ON CONFLICT DO NOTHING"

/* ─── MySQL ─ (db_mysql.c で実装) ────────────────────────────────────────── */
#elif defined(USE_MYSQL)

typedef struct DbConn DbConn;
typedef struct DbStmt DbStmt;

DbConn      *db_open_backend(const char *uri);
void         db_close_backend(DbConn *db);
int          db_exec(DbConn *db, const char *sql);
DbStmt      *db_prepare(DbConn *db, const char *sql);
void         db_bind_int(DbStmt *st, int idx, long long val);
void         db_bind_text(DbStmt *st, int idx, const char *val);
void         db_bind_double(DbStmt *st, int idx, double val);
int          db_step(DbStmt *st);
long long    db_col_int(DbStmt *st, int col);
const char  *db_col_text(DbStmt *st, int col);
double       db_col_double(DbStmt *st, int col);
int          db_col_is_null(DbStmt *st, int col);
void         db_finalize(DbStmt *st);
void         db_reset(DbStmt *st);
long long    db_last_id(DbConn *db);
int          db_changes(DbConn *db);
const char  *db_errmsg(DbConn *db);

/* SQL ダイアレクト: MySQL */
#define SQL_NOW_STR           "NOW()"
#define SQL_NOW_PLUS_MIN(n)   "DATE_ADD(NOW(), INTERVAL " #n " MINUTE)"
#define SQL_NOW_PLUS_HOUR(n)  "DATE_ADD(NOW(), INTERVAL " #n " HOUR)"
#define SQL_NOW_PLUS_DAY(n)   "DATE_ADD(NOW(), INTERVAL " #n " DAY)"
/* FTS: MySQL は FULLTEXT か LIKE フォールバック */
#define SQL_FTS_MATCH(col, param) \
    "(p.title LIKE CONCAT('%'," param ",'%') OR p.description LIKE CONCAT('%'," param ",'%') OR v.name LIKE CONCAT('%'," param ",'%'))"
/* INSERT 重複無視: MySQL は INSERT IGNORE INTO ... (末尾何も付けない) */
#define SQL_INSERT_OR_IGNORE  "INSERT IGNORE"
#define SQL_ON_CONFLICT_IGNORE ""

/* ─── SQLite（デフォルト）─ inline ラッパー ──────────────────────────────── */
#else
#define USE_SQLITE 1
#include <sqlite3.h>

/* 透過的な型エイリアス: 既存の sqlite3_* 呼び出しはそのままコンパイル可能 */
typedef sqlite3       DbConn;
typedef sqlite3_stmt  DbStmt;

/* SQL ダイアレクト: SQLite */
#define SQL_NOW_STR           "datetime('now')"
#define SQL_NOW_PLUS_MIN(n)   "datetime('now', '+" #n " minutes')"
#define SQL_NOW_PLUS_HOUR(n)  "datetime('now', '+" #n " hours')"
#define SQL_NOW_PLUS_DAY(n)   "datetime('now', '+" #n " days')"
/* FTS: SQLite は FTS5 の plans_fts を使用 */
#define SQL_FTS_MATCH(col, param) \
    "(p.id IN (SELECT rowid FROM plans_fts WHERE plans_fts MATCH " param "))"
/* INSERT 重複無視: SQLite は INSERT OR IGNORE INTO ... */
#define SQL_INSERT_OR_IGNORE  "INSERT OR IGNORE"
#define SQL_ON_CONFLICT_IGNORE ""

/* Inline ラッパー: PgSQL/MySQL 版と同じ名前で使える ─────────────────────── */

static inline DbStmt *db_prepare(DbConn *db, const char *sql) {
    DbStmt *st = NULL;
    sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    return st;
}
static inline void db_bind_int(DbStmt *st, int idx, long long v) {
    sqlite3_bind_int64(st, idx, v);
}
static inline void db_bind_text(DbStmt *st, int idx, const char *v) {
    sqlite3_bind_text(st, idx, v, -1, SQLITE_STATIC);
}
static inline void db_bind_double(DbStmt *st, int idx, double v) {
    sqlite3_bind_double(st, idx, v);
}
static inline int db_step(DbStmt *st) {
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW)  return 1;
    if (rc == SQLITE_DONE) return 0;
    return -1;
}
static inline long long   db_col_int(DbStmt *st, int c)    { return sqlite3_column_int64(st, c); }
static inline const char *db_col_text(DbStmt *st, int c)   { return (const char*)sqlite3_column_text(st, c); }
static inline double      db_col_double(DbStmt *st, int c) { return sqlite3_column_double(st, c); }
static inline int         db_col_is_null(DbStmt *st, int c){ return sqlite3_column_type(st, c) == SQLITE_NULL; }
static inline void        db_finalize(DbStmt *st)          { sqlite3_finalize(st); }
static inline void        db_reset(DbStmt *st)             { sqlite3_reset(st); }
static inline long long   db_last_id(DbConn *db)           { return sqlite3_last_insert_rowid(db); }
static inline int         db_changes(DbConn *db)           { return sqlite3_changes(db); }
static inline const char *db_errmsg(DbConn *db)            { return sqlite3_errmsg(db); }
static inline int         db_exec(DbConn *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

#endif /* backend selection */
