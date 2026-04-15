/*
 * db_mysql.c — MySQL/MariaDB バックエンド実装
 *
 * libmysqlclient を使用。
 * コンパイル: make DB=mysql
 * 接続 URI 例: mysql://user:pass@localhost:3306/asoview
 *   または環境変数: MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE
 */
#ifdef USE_MYSQL

#include "db_driver.h"
#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* my_bool was removed in MySQL 8.0.26+ / MariaDB Connector/C 3.x */
#ifndef my_bool
typedef char my_bool;
#endif

/* ─── 内部構造体 ─────────────────────────────────────────────────────────── */

#define MAX_COLS   64
#define MAX_STR    4096

struct DbConn {
    MYSQL      *mysql;
    long long   last_id;
    int         last_changes;
    char        errmsg[256];
};

/* バインド用バッファ（1 列分） */
typedef struct {
    MYSQL_BIND  bind;
    char        str_buf[MAX_STR];
    unsigned long str_len;
    long long   int_val;
    double      dbl_val;
    my_bool     is_null;
    my_bool     error;
} ColBuf;

struct DbStmt {
    DbConn     *conn;
    MYSQL_STMT *stmt;
    int         nparams;
    MYSQL_BIND *param_binds; /* 入力バインド */
    char      **param_strs;  /* 文字列バッファ（text バインド用） */
    long long  *param_ints;
    double     *param_dbls;
    unsigned long *param_lens;
    my_bool    *param_nulls;
    /* 出力バインド */
    int         ncols;
    ColBuf     *col_bufs;
    MYSQL_BIND *result_binds;
    int         has_result;  /* SELECT 系か */
    int         row_fetched; /* 最初の fetch 済みか */
};

/* ─── URI パーサー（mysql://user:pass@host:port/db） ──────────────────────── */
static void parse_mysql_uri(const char *uri,
                             char *host, int *port, char *user,
                             char *pass, char *dbname) {
    /* デフォルト（snprintf で安全にコピー） */
    snprintf(host,   128, "%s", getenv("MYSQL_HOST")     ? getenv("MYSQL_HOST")     : "127.0.0.1");
    *port        = getenv("MYSQL_PORT")     ? atoi(getenv("MYSQL_PORT")): 3306;
    snprintf(user,   128, "%s", getenv("MYSQL_USER")     ? getenv("MYSQL_USER")     : "root");
    snprintf(pass,   128, "%s", getenv("MYSQL_PASSWORD") ? getenv("MYSQL_PASSWORD") : "");
    snprintf(dbname, 128, "%s", getenv("MYSQL_DATABASE") ? getenv("MYSQL_DATABASE") : "asoview");

    if (!uri || strncmp(uri, "mysql://", 8) != 0) return;
    /* mysql://user:pass@host:port/dbname — uri+8 で "mysql://" の直後を指す */
    char tmp[512];
    strncpy(tmp, uri + 8, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = '\0';

    char *at = strrchr(tmp, '@');
    if (at) {
        *at = '\0';
        char *colon = strchr(tmp, ':');
        if (colon) { *colon = '\0'; strncpy(user, tmp, 128); strncpy(pass, colon+1, 128); }
        else { strncpy(user, tmp, 128); }
        /* re-parse host:port/db from (at+1) */
        char *hostpart = at + 1;
        char *slash = strchr(hostpart, '/');
        if (slash) { *slash = '\0'; strncpy(dbname, slash+1, 128); }
        char *portcolon = strchr(hostpart, ':');
        if (portcolon) { *portcolon = '\0'; *port = atoi(portcolon+1); }
        strncpy(host, hostpart, 128);
    }
}

/* ─── DbConn 操作 ────────────────────────────────────────────────────────── */

DbConn *db_open_backend(const char *uri) {
    DbConn *db = calloc(1, sizeof(DbConn));
    if (!db) return NULL;
    db->mysql = mysql_init(NULL);
    if (!db->mysql) { free(db); return NULL; }

    char host[128], user[128], pass[128], dbname[128];
    int port = 3306;
    parse_mysql_uri(uri, host, &port, user, pass, dbname);

    my_bool reconnect = 1;
    mysql_options(db->mysql, MYSQL_OPT_RECONNECT, &reconnect);

    if (!mysql_real_connect(db->mysql, host, user, pass, dbname,
                            (unsigned int)port, NULL, 0)) {
        fprintf(stderr, "[db_mysql] Connect failed: %s\n", mysql_error(db->mysql));
        mysql_close(db->mysql);
        free(db);
        return NULL;
    }
    /* UTF-8 */
    mysql_set_character_set(db->mysql, "utf8mb4");
    return db;
}

void db_close_backend(DbConn *db) {
    if (!db) return;
    mysql_close(db->mysql);
    free(db);
}

int db_exec(DbConn *db, const char *sql) {
    if (mysql_query(db->mysql, sql) != 0) {
        snprintf(db->errmsg, sizeof(db->errmsg), "%s", mysql_error(db->mysql));
        fprintf(stderr, "[db_mysql] exec error: %s\n", db->errmsg);
        return -1;
    }
    /* 結果セットを解放 */
    MYSQL_RES *res = mysql_store_result(db->mysql);
    if (res) mysql_free_result(res);
    return 0;
}

/* ─── DbStmt 操作 ────────────────────────────────────────────────────────── */

static int count_qmarks(const char *sql) {
    int n = 0;
    for (const char *p = sql; *p; p++) if (*p == '?') n++;
    return n;
}

DbStmt *db_prepare(DbConn *db, const char *sql) {
    DbStmt *st = calloc(1, sizeof(DbStmt));
    if (!st) return NULL;
    st->conn = db;

    st->stmt = mysql_stmt_init(db->mysql);
    if (!st->stmt) { free(st); return NULL; }

    if (mysql_stmt_prepare(st->stmt, sql, (unsigned long)strlen(sql)) != 0) {
        fprintf(stderr, "[db_mysql] prepare failed: %s\nSQL: %s\n",
                mysql_stmt_error(st->stmt), sql);
        mysql_stmt_close(st->stmt);
        free(st);
        return NULL;
    }

    st->nparams = count_qmarks(sql);
    if (st->nparams > 0) {
        st->param_binds = calloc((size_t)st->nparams, sizeof(MYSQL_BIND));
        st->param_strs  = calloc((size_t)st->nparams, sizeof(char *));
        st->param_ints  = calloc((size_t)st->nparams, sizeof(long long));
        st->param_dbls  = calloc((size_t)st->nparams, sizeof(double));
        st->param_lens  = calloc((size_t)st->nparams, sizeof(unsigned long));
        st->param_nulls = calloc((size_t)st->nparams, sizeof(my_bool));
    }

    /* 出力列数 */
    MYSQL_RES *meta = mysql_stmt_result_metadata(st->stmt);
    if (meta) {
        st->ncols = (int)mysql_num_fields(meta);
        mysql_free_result(meta);
        if (st->ncols > MAX_COLS) {
            fprintf(stderr, "[db_mysql] query returns %d columns (max %d) — truncating\n",
                    st->ncols, MAX_COLS);
            st->ncols = MAX_COLS;
        }
        st->col_bufs    = calloc((size_t)st->ncols, sizeof(ColBuf));
        st->result_binds = calloc((size_t)st->ncols, sizeof(MYSQL_BIND));
        for (int i = 0; i < st->ncols; i++) {
            ColBuf *cb = &st->col_bufs[i];
            cb->is_null = 0; cb->error = 0;
            st->result_binds[i].buffer_type   = MYSQL_TYPE_STRING;
            st->result_binds[i].buffer        = cb->str_buf;
            st->result_binds[i].buffer_length = MAX_STR;
            st->result_binds[i].length        = &cb->str_len;
            st->result_binds[i].is_null       = &cb->is_null;
            st->result_binds[i].error         = &cb->error;
        }
        st->has_result = 1;
    }
    return st;
}

void db_bind_int(DbStmt *st, int idx, long long v) {
    if (idx < 1 || idx > st->nparams) return;
    int i = idx - 1;
    st->param_ints[i] = v;
    st->param_binds[i].buffer_type   = MYSQL_TYPE_LONGLONG;
    st->param_binds[i].buffer        = &st->param_ints[i];
    st->param_binds[i].is_null       = &st->param_nulls[i];
    st->param_binds[i].length        = NULL;
    st->param_nulls[i] = 0;
}

void db_bind_text(DbStmt *st, int idx, const char *v) {
    if (idx < 1 || idx > st->nparams) return;
    int i = idx - 1;
    free(st->param_strs[i]);
    st->param_strs[i] = v ? strdup(v) : NULL;
    if (v) {
        st->param_lens[i] = (unsigned long)strlen(v);
        st->param_binds[i].buffer_type   = MYSQL_TYPE_STRING;
        st->param_binds[i].buffer        = st->param_strs[i];
        st->param_binds[i].buffer_length = st->param_lens[i];
        st->param_binds[i].length        = &st->param_lens[i];
        st->param_binds[i].is_null       = &st->param_nulls[i];
        st->param_nulls[i] = 0;
    } else {
        st->param_binds[i].buffer_type = MYSQL_TYPE_NULL;
        st->param_nulls[i] = 1;
    }
}

void db_bind_double(DbStmt *st, int idx, double v) {
    if (idx < 1 || idx > st->nparams) return;
    int i = idx - 1;
    st->param_dbls[i] = v;
    st->param_binds[i].buffer_type   = MYSQL_TYPE_DOUBLE;
    st->param_binds[i].buffer        = &st->param_dbls[i];
    st->param_binds[i].is_null       = &st->param_nulls[i];
    st->param_binds[i].length        = NULL;
    st->param_nulls[i] = 0;
}

int db_step(DbStmt *st) {
    if (!st) return -1;

    if (!st->row_fetched) {
        /* 初回: パラメータバインド＆実行 */
        if (st->nparams > 0 && mysql_stmt_bind_param(st->stmt, st->param_binds) != 0) {
            snprintf(st->conn->errmsg, sizeof(st->conn->errmsg),
                     "%s", mysql_stmt_error(st->stmt));
            return -1;
        }
        if (mysql_stmt_execute(st->stmt) != 0) {
            snprintf(st->conn->errmsg, sizeof(st->conn->errmsg),
                     "%s", mysql_stmt_error(st->stmt));
            fprintf(stderr, "[db_mysql] execute error: %s\n", st->conn->errmsg);
            return -1;
        }
        st->conn->last_id      = (long long)mysql_stmt_insert_id(st->stmt);
        st->conn->last_changes = (int)mysql_stmt_affected_rows(st->stmt);

        if (st->has_result) {
            if (mysql_stmt_bind_result(st->stmt, st->result_binds) != 0) {
                return -1;
            }
            mysql_stmt_store_result(st->stmt);
        }
        st->row_fetched = 1;

        if (!st->has_result) return 0; /* INSERT/UPDATE/DELETE */
    }

    if (!st->has_result) return 0;

    int rc = mysql_stmt_fetch(st->stmt);
    if (rc == 0)              return 1;  /* 行あり */
    if (rc == MYSQL_NO_DATA)  return 0;  /* 完了 */
    return -1;                           /* エラー */
}

long long db_col_int(DbStmt *st, int col) {
    if (!st || col < 0 || col >= st->ncols) return 0;
    if (st->col_bufs[col].is_null) return 0;
    return strtoll(st->col_bufs[col].str_buf, NULL, 10);
}

const char *db_col_text(DbStmt *st, int col) {
    if (!st || col < 0 || col >= st->ncols) return NULL;
    if (st->col_bufs[col].is_null) return NULL;
    return st->col_bufs[col].str_buf;
}

double db_col_double(DbStmt *st, int col) {
    if (!st || col < 0 || col >= st->ncols) return 0.0;
    if (st->col_bufs[col].is_null) return 0.0;
    return strtod(st->col_bufs[col].str_buf, NULL);
}

int db_col_is_null(DbStmt *st, int col) {
    if (!st || col < 0 || col >= st->ncols) return 1;
    return (int)st->col_bufs[col].is_null;
}

void db_finalize(DbStmt *st) {
    if (!st) return;
    if (st->stmt) {
        mysql_stmt_free_result(st->stmt);
        mysql_stmt_close(st->stmt);
    }
    for (int i = 0; i < st->nparams; i++) free(st->param_strs[i]);
    free(st->param_binds); free(st->param_strs);
    free(st->param_ints);  free(st->param_dbls);
    free(st->param_lens);  free(st->param_nulls);
    free(st->col_bufs);    free(st->result_binds);
    free(st);
}

void db_reset(DbStmt *st) {
    if (!st || !st->stmt) return;
    mysql_stmt_reset(st->stmt);
    st->row_fetched = 0;
}

long long db_last_id(DbConn *db) { return db ? db->last_id : 0; }
int       db_changes(DbConn *db) { return db ? db->last_changes : 0; }

const char *db_errmsg(DbConn *db) {
    return db ? db->errmsg : "unknown";
}

#endif /* USE_MYSQL */
