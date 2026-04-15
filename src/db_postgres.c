/*
 * db_postgres.c — PostgreSQL バックエンド実装
 *
 * libpq (PostgreSQL C クライアントライブラリ) を使用。
 * コンパイル: make DB=postgres
 * 接続 URI 例: postgres://user:pass@localhost:5432/asoview
 */
#ifdef USE_POSTGRES

#include "db_driver.h"
#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── 内部構造体 ─────────────────────────────────────────────────────────── */

struct DbConn {
    PGconn     *pg;
    long long   last_id;
    int         last_changes;
    char        errmsg[256];
};

struct DbStmt {
    DbConn     *conn;
    char        name[64];      /* プリペアドステートメント名 */
    char       *sql;           /* 元の SQL（$1/$2 プレースホルダー形式） */
    int         nparams;       /* バインドパラメータ数 */
    char      **param_values;  /* バインド値の文字列表現 */
    int        *param_lengths;
    int        *param_formats; /* 0=text */
    PGresult   *res;           /* 現在の実行結果 */
    int         row;           /* 現在の行インデックス */
    int         nrows;         /* 総行数 */
    int         prepared;      /* 既にプリペアされているか */
    long long   stmt_id;       /* 一意なステートメント ID */
};

/* ─── グローバルステートメントカウンター ─────────────────────────────────── */
static long long g_stmt_seq = 0;

/* ─── SQLite の "?" プレースホルダーを PostgreSQL の "$N" に変換 ──────────── */
/* シングルクォート文字列内・ダブルクォート識別子内の "?" は置換しない        */
static char *convert_placeholders(const char *sql) {
    size_t len = strlen(sql);
    /* 最悪ケース: 各 "?" を "$999" (4 bytes) に置換 */
    char *out = malloc(len * 4 + 1);
    if (!out) return NULL;
    size_t oi = 0;
    int n = 1;
    int in_single = 0; /* シングルクォート文字列中 */
    int in_double = 0; /* ダブルクォート識別子中 */
    for (size_t i = 0; i < len; i++) {
        char ch = sql[i];
        if (!in_double && ch == '\'') {
            /* '' は escaped quote — toggle 後すぐ再 toggle */
            if (in_single && i + 1 < len && sql[i+1] == '\'') {
                out[oi++] = ch; /* 1文字目 */
                out[oi++] = sql[++i]; /* 2文字目 */
                continue;
            }
            in_single = !in_single;
        } else if (!in_single && ch == '"') {
            in_double = !in_double;
        } else if (!in_single && !in_double && ch == '?') {
            oi += (size_t)snprintf(out + oi, 16, "$%d", n++);
            continue;
        }
        out[oi++] = ch;
    }
    out[oi] = '\0';
    return out;
}

/* ─── パラメータ数をカウント ─────────────────────────────────────────────── */
static int count_params(const char *sql) {
    int n = 0;
    for (const char *p = sql; *p; p++) {
        if (*p == '$' && p[1] >= '1' && p[1] <= '9') n++;
    }
    return n;
}

/* ─── DbConn 操作 ────────────────────────────────────────────────────────── */

DbConn *db_open_backend(const char *uri) {
    DbConn *db = calloc(1, sizeof(DbConn));
    if (!db) return NULL;
    db->pg = PQconnectdb(uri);
    if (PQstatus(db->pg) != CONNECTION_OK) {
        fprintf(stderr, "[db_postgres] Connection failed: %s\n", PQerrorMessage(db->pg));
        PQfinish(db->pg);
        free(db);
        return NULL;
    }
    return db;
}

void db_close_backend(DbConn *db) {
    if (!db) return;
    PQfinish(db->pg);
    free(db);
}

int db_exec(DbConn *db, const char *sql) {
    PGresult *res = PQexec(db->pg, sql);
    ExecStatusType st = PQresultStatus(res);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
        snprintf(db->errmsg, sizeof(db->errmsg), "%s", PQerrorMessage(db->pg));
        fprintf(stderr, "[db_postgres] exec error: %s\n", db->errmsg);
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

/* ─── DbStmt 操作 ────────────────────────────────────────────────────────── */

DbStmt *db_prepare(DbConn *db, const char *sql) {
    DbStmt *st = calloc(1, sizeof(DbStmt));
    if (!st) return NULL;
    st->conn = db;
    st->stmt_id = ++g_stmt_seq;
    snprintf(st->name, sizeof(st->name), "stmt_%lld", st->stmt_id);

    /* "?" → "$N" 変換 */
    st->sql = convert_placeholders(sql);
    if (!st->sql) { free(st); return NULL; }
    st->nparams = count_params(st->sql);

    if (st->nparams > 0) {
        st->param_values  = calloc((size_t)st->nparams, sizeof(char *));
        st->param_lengths = calloc((size_t)st->nparams, sizeof(int));
        st->param_formats = calloc((size_t)st->nparams, sizeof(int));
        if (!st->param_values || !st->param_lengths || !st->param_formats) {
            free(st->param_values); free(st->param_lengths);
            free(st->param_formats); free(st->sql); free(st);
            return NULL;
        }
    }

    /* プリペア */
    PGresult *res = PQprepare(db->pg, st->name, st->sql, 0, NULL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db_postgres] prepare failed: %s\nSQL: %s\n",
                PQerrorMessage(db->pg), st->sql);
        PQclear(res);
        free(st->param_values); free(st->param_lengths);
        free(st->param_formats); free(st->sql); free(st);
        return NULL;
    }
    PQclear(res);
    st->prepared = 1;
    st->row = -1;
    return st;
}

static void free_param_strings(DbStmt *st) {
    for (int i = 0; i < st->nparams; i++) {
        free(st->param_values[i]);
        st->param_values[i] = NULL;
    }
}

void db_bind_int(DbStmt *st, int idx, long long v) {
    if (idx < 1 || idx > st->nparams) return;
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", v);
    free(st->param_values[idx-1]);
    st->param_values[idx-1] = strdup(buf);
    st->param_lengths[idx-1] = 0;
    st->param_formats[idx-1] = 0;
}

void db_bind_text(DbStmt *st, int idx, const char *v) {
    if (idx < 1 || idx > st->nparams) return;
    free(st->param_values[idx-1]);
    st->param_values[idx-1] = v ? strdup(v) : NULL;
    st->param_lengths[idx-1] = 0;
    st->param_formats[idx-1] = 0;
}

void db_bind_double(DbStmt *st, int idx, double v) {
    if (idx < 1 || idx > st->nparams) return;
    char buf[64];
    snprintf(buf, sizeof(buf), "%.17g", v);
    free(st->param_values[idx-1]);
    st->param_values[idx-1] = strdup(buf);
    st->param_lengths[idx-1] = 0;
    st->param_formats[idx-1] = 0;
}

int db_step(DbStmt *st) {
    if (!st) return -1;
    if (st->row == -1) {
        /* 初回: 実行 */
        if (st->res) { PQclear(st->res); st->res = NULL; }
        st->res = PQexecPrepared(st->conn->pg, st->name,
                                  st->nparams,
                                  (const char * const *)st->param_values,
                                  st->param_lengths, st->param_formats, 0);
        ExecStatusType status = PQresultStatus(st->res);
        if (status == PGRES_COMMAND_OK) {
            /* INSERT/UPDATE/DELETE */
            const char *ct = PQcmdTuples(st->res);
            st->conn->last_changes = ct && *ct ? atoi(ct) : 0;
            /* RETURNING 句があれば最初の列を last_id に使う */
            st->nrows = PQntuples(st->res);
            st->row = 0;
            if (st->nrows > 0) {
                st->conn->last_id = strtoll(PQgetvalue(st->res, 0, 0), NULL, 10);
                return 1;
            }
            /* INSERT 後に lastval() で自動採番 ID を取得 */
            const char *cmd_status = PQcmdStatus(st->res);
            if (cmd_status && strncmp(cmd_status, "INSERT", 6) == 0) {
                PGresult *lid = PQexec(st->conn->pg, "SELECT lastval()");
                if (PQresultStatus(lid) == PGRES_TUPLES_OK && PQntuples(lid) > 0)
                    st->conn->last_id = strtoll(PQgetvalue(lid, 0, 0), NULL, 10);
                PQclear(lid);
            }
            return 0;
        } else if (status == PGRES_TUPLES_OK) {
            st->nrows = PQntuples(st->res);
            st->row = 0;
            if (st->nrows > 0) {
                return 1;
            }
            return 0;
        } else {
            snprintf(st->conn->errmsg, sizeof(st->conn->errmsg),
                     "%s", PQerrorMessage(st->conn->pg));
            fprintf(stderr, "[db_postgres] step error: %s\n", st->conn->errmsg);
            st->row = 0; st->nrows = 0;
            return -1;
        }
    } else {
        /* 次の行 */
        st->row++;
        if (st->row < st->nrows) return 1;
        return 0;
    }
}

long long db_col_int(DbStmt *st, int col) {
    if (!st->res || st->row < 0 || st->row >= st->nrows) return 0;
    const char *v = PQgetvalue(st->res, st->row, col);
    return v ? strtoll(v, NULL, 10) : 0;
}

const char *db_col_text(DbStmt *st, int col) {
    if (!st->res || st->row < 0 || st->row >= st->nrows) return NULL;
    if (PQgetisnull(st->res, st->row, col)) return NULL;
    return PQgetvalue(st->res, st->row, col);
}

double db_col_double(DbStmt *st, int col) {
    if (!st->res || st->row < 0 || st->row >= st->nrows) return 0.0;
    const char *v = PQgetvalue(st->res, st->row, col);
    return v ? strtod(v, NULL) : 0.0;
}

int db_col_is_null(DbStmt *st, int col) {
    if (!st->res || st->row < 0 || st->row >= st->nrows) return 1;
    return PQgetisnull(st->res, st->row, col);
}

void db_finalize(DbStmt *st) {
    if (!st) return;
    if (st->res) { PQclear(st->res); st->res = NULL; }
    /* プリペアドステートメントをサーバーから削除 */
    if (st->prepared) {
        char sql[128];
        snprintf(sql, sizeof(sql), "DEALLOCATE \"%s\"", st->name);
        PGresult *r = PQexec(st->conn->pg, sql);
        if (r) PQclear(r);
    }
    free_param_strings(st);
    free(st->param_values);
    free(st->param_lengths);
    free(st->param_formats);
    free(st->sql);
    free(st);
}

void db_reset(DbStmt *st) {
    if (!st) return;
    if (st->res) { PQclear(st->res); st->res = NULL; }
    st->row = -1;
    st->nrows = 0;
    free_param_strings(st);
}

long long db_last_id(DbConn *db) {
    if (!db) return 0;
    /* RETURNING id カラムで取得済みの値を返す */
    return db->last_id;
}

int db_changes(DbConn *db) {
    return db ? db->last_changes : 0;
}

const char *db_errmsg(DbConn *db) {
    return db ? db->errmsg : "unknown";
}

#endif /* USE_POSTGRES */
