#include "webhooks.h"
#include "db.h"
#include "platform.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

/* ─── HMAC-SHA256 → hex string ─────────────────────────────────────────── */

static void hmac_hex(const char *secret, const char *data, char *out, size_t out_sz) {
    uint8_t mac[32];
    platform_hmac_sha256(secret, strlen(secret), data, strlen(data), mac);
    out[0] = '\0';
    for (int i = 0; i < 32 && (size_t)(i*2+3) < out_sz; i++)
        snprintf(out + i*2, 3, "%02x", mac[i]);
}

/* ─── 非同期配信タスク ──────────────────────────────────────────────────── */

typedef struct {
    long   endpoint_id;
    char  *url;
    char  *secret;
    char  *event;
    char  *payload;
    DbConn *db;     /* 配信結果を記録するため */
} WebhookTask;

static size_t discard_cb(void *ptr, size_t sz, size_t n, void *ud) {
    (void)ptr; (void)ud; return sz * n;
}

static void *webhook_thread(void *arg) {
    WebhookTask *t = (WebhookTask *)arg;

    /* HMAC 署名 */
    char sig[72];
    hmac_hex(t->secret, t->payload, sig, sizeof(sig));
    char sig_hdr[80];
    snprintf(sig_hdr, sizeof(sig_hdr), "X-Asoview-Signature: sha256=%s", sig);

    char event_hdr[128];
    snprintf(event_hdr, sizeof(event_hdr), "X-Asoview-Event: %s", t->event);

    CURL *curl = curl_easy_init();
    long http_code = 0;
    int success = 0;

    if (curl) {
        struct curl_slist *hdrs = NULL;
        hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
        hdrs = curl_slist_append(hdrs, sig_hdr);
        hdrs = curl_slist_append(hdrs, event_hdr);
        hdrs = curl_slist_append(hdrs, "User-Agent: Asoview-Webhook/0.4");

        curl_easy_setopt(curl, CURLOPT_URL,           t->url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    t->payload);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL,      1L);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);

        success = (res == CURLE_OK && http_code >= 200 && http_code < 300);
        if (!success) {
            fprintf(stderr, "[webhook] delivery to %s failed: curl=%d http=%ld\n",
                    t->url, (int)res, http_code);
        }
    }

    /* 配信ログ記録 */
    if (t->db) {
        DbStmt *ins = db_prepare(t->db,
            "INSERT INTO webhook_deliveries"
            "(endpoint_id, event, payload, response_code, success)"
            " VALUES(?,?,?,?,?)");
        db_bind_int(ins,  1, t->endpoint_id);
        db_bind_text(ins, 2, t->event);
        db_bind_text(ins, 3, t->payload);
        db_bind_int(ins,  4, (long)http_code);
        db_bind_int(ins,  5, success);
        db_step(ins);
        db_finalize(ins);
    }

    free(t->url);
    free(t->secret);
    free(t->event);
    free(t->payload);
    free(t);
    return NULL;
}

/* ─── 公開 API ──────────────────────────────────────────────────────────── */

void webhooks_fire(DbConn *db, const char *event, const char *payload_json) {
    /* アクティブなエンドポイントを取得 */
    DbStmt *st = db_prepare(db,
        "SELECT id, url, secret, events FROM webhook_endpoints WHERE is_active=1");
    if (!st) return;

    while (db_step(st) == 1) {
        long eid          = db_col_int(st, 0);
        const char *url    = db_col_text(st, 1);
        const char *secret = db_col_text(st, 2);
        const char *events = db_col_text(st, 3);  /* JSON array */

        /* events 配列にこのイベントが含まれるか（簡易文字列検索） */
        if (!url || !secret || !events) continue;
        /* events = '["booking.created","booking.cancelled"]' など */
        /* strstr で event 名を探す（JSON 内の文字列一致） */
        if (strstr(events, "\"*\"") == NULL && strstr(events, event) == NULL) continue;

        /* 非同期配信タスクを生成 */
        WebhookTask *t = calloc(1, sizeof(WebhookTask));
        if (!t) continue;
        t->endpoint_id = eid;
        t->url    = strdup(url);
        t->secret = strdup(secret);
        t->event  = strdup(event);
        t->payload = strdup(payload_json);
        t->db     = db;

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, webhook_thread, t) != 0) {
            free(t->url); free(t->secret); free(t->event);
            free(t->payload); free(t);
        }
        pthread_attr_destroy(&attr);
    }
    db_finalize(st);
}
