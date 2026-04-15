#include "rate_limit.h"
#include <string.h>
#include <time.h>

#define BUCKET_COUNT  4096
#define WINDOW_SECS    60
#define GENERAL_LIMIT 500
#define AUTH_LIMIT     60

/* ユーザー単位レート制限 */
#define UID_BUCKET_COUNT  2048
#define UID_WRITE_LIMIT    30   /* 認証ユーザー: 書き込み操作 30 回/min */

typedef struct {
    char  ip[48];        /* IPv4/IPv6 文字列 */
    long  window_start;
    int   count;
    int   auth_count;
} RateBucket;

typedef struct {
    long uid;
    long window_start;
    int  count;
} UidBucket;

static RateBucket buckets[BUCKET_COUNT];
static UidBucket  uid_buckets[UID_BUCKET_COUNT];

static unsigned int hash_ip(const char *ip) {
    unsigned int h = 5381;
    for (const char *p = ip; *p; p++) h = h * 33u + (unsigned char)*p;
    return h % BUCKET_COUNT;
}

int rate_check(const char *ip, int is_auth) {
    if (!ip || !*ip) return 0;

    unsigned int idx = hash_ip(ip);
    RateBucket  *b   = &buckets[idx];
    long         now = (long)time(NULL);

    /* スロット未使用・別 IP・ウィンドウ期限切れ → リセット */
    if (b->ip[0] == '\0' ||
        strncmp(b->ip, ip, sizeof(b->ip) - 1) != 0 ||
        now - b->window_start >= WINDOW_SECS) {
        strncpy(b->ip, ip, sizeof(b->ip) - 1);
        b->ip[sizeof(b->ip) - 1] = '\0';
        b->window_start = now;
        b->count        = 0;
        b->auth_count   = 0;
    }

    b->count++;
    if (is_auth) b->auth_count++;

    if (b->count      > GENERAL_LIMIT) return 1;
    if (is_auth && b->auth_count > AUTH_LIMIT) return 1;
    return 0;
}

/* ユーザー単位の書き込み操作レート制限
 * 返り値: 0 = OK, 1 = レート超過 */
int rate_check_uid(long uid) {
    if (uid <= 0) return 0;

    unsigned int idx = (unsigned int)(uid % UID_BUCKET_COUNT);
    UidBucket   *b   = &uid_buckets[idx];
    long         now = (long)time(NULL);

    /* スロット未使用・別ユーザー・ウィンドウ期限切れ → リセット */
    if (b->uid == 0 || b->uid != uid || now - b->window_start >= WINDOW_SECS) {
        b->uid          = uid;
        b->window_start = now;
        b->count        = 0;
    }

    b->count++;
    return b->count > UID_WRITE_LIMIT ? 1 : 0;
}
