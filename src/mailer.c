#include "mailer.h"
#include "cJSON.h"
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *data; size_t len; size_t cap; } MailBuf;

static size_t mail_write_cb(void *ptr, size_t sz, size_t n, void *ud) {
    MailBuf *b = (MailBuf *)ud;
    size_t add = sz * n;
    if (b->len + add + 1 > b->cap) {
        size_t nc = (b->len + add + 1) * 2;
        char *tmp = realloc(b->data, nc);
        if (!tmp) return 0;
        b->data = tmp; b->cap = nc;
    }
    memcpy(b->data + b->len, ptr, add);
    b->len += add;
    b->data[b->len] = '\0';
    return add;
}

/* ─── 非同期送信スレッド ──────────────────────────────────────────────────── */

typedef struct {
    char to[256];
    char subject[256];
    char *html_body; /* heap allocated */
} MailTask;

static void *mail_thread(void *arg) {
    MailTask *t = (MailTask *)arg;

    const char *api_key = getenv("RESEND_API_KEY");
    if (!api_key || !*api_key) {
        fprintf(stderr, "[mailer] RESEND_API_KEY 未設定 — メール送信をスキップ: %s\n", t->to);
        free(t->html_body); free(t); return NULL;
    }
    const char *from = getenv("RESEND_FROM");
    if (!from || !*from) from = "noreply@asoview.example.com";

    CURL *curl = curl_easy_init();
    if (!curl) { free(t->html_body); free(t); return NULL; }

    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "from",    from);
    cJSON_AddStringToObject(j, "to",      t->to);
    cJSON_AddStringToObject(j, "subject", t->subject);
    cJSON_AddStringToObject(j, "html",    t->html_body);
    char *body_str = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);

    char auth_hdr[512];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", api_key);

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, auth_hdr);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    MailBuf buf = { calloc(1, 256), 0, 256 };

    curl_easy_setopt(curl, CURLOPT_URL, "https://api.resend.com/emails");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mail_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    cJSON_free(body_str);
    free(buf.data);

    if (res != CURLE_OK)
        fprintf(stderr, "[mailer] curl エラー: %s\n", curl_easy_strerror(res));
    else if (http_code < 200 || http_code >= 300)
        fprintf(stderr, "[mailer] Resend API HTTP %ld → %s\n", http_code, t->to);

    free(t->html_body);
    free(t);
    return NULL;
}

/* 非ブロッキング送信 — スレッドを生成してすぐリターン */
int send_email(const char *to, const char *subject, const char *html_body) {
    MailTask *t = calloc(1, sizeof(MailTask));
    if (!t) return -1;
    strncpy(t->to,      to,      sizeof(t->to)      - 1);
    strncpy(t->subject, subject, sizeof(t->subject) - 1);
    t->html_body = strdup(html_body);
    if (!t->html_body) { free(t); return -1; }

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, mail_thread, t) != 0) {
        free(t->html_body); free(t);
        pthread_attr_destroy(&attr);
        return -1;
    }
    pthread_attr_destroy(&attr);
    return 0;
}

/* ─── テンプレート ────────────────────────────────────────────────────────── */

void send_password_reset_email(const char *to, const char *reset_token) {
    const char *frontend = getenv("FRONTEND_URL");
    if (!frontend || !*frontend) frontend = "http://localhost:3000";

    char reset_link[512];
    snprintf(reset_link, sizeof(reset_link),
             "%s/reset-password?token=%s", frontend, reset_token);

    char html[2048];
    snprintf(html, sizeof(html),
        "<h2>パスワードリセットのご案内</h2>"
        "<p>以下のリンクをクリックしてパスワードをリセットしてください。</p>"
        "<p><a href=\"%s\" style=\"background:#0066cc;color:#fff;"
        "padding:12px 24px;border-radius:4px;text-decoration:none\">"
        "パスワードをリセットする</a></p>"
        "<p>このリンクは<strong>1時間</strong>有効です。</p>"
        "<p style=\"color:#888\">心当たりがない場合はこのメールを無視してください。</p>",
        reset_link);

    send_email(to, "【asoview】パスワードリセットのご案内", html);
}

void send_booking_confirmation_email(const char *to,
                                     const char *booking_id,
                                     const char *plan_title,
                                     const char *date,
                                     const char *start_time,
                                     long total_price) {
    const char *frontend = getenv("FRONTEND_URL");
    if (!frontend || !*frontend) frontend = "http://localhost:3000";

    char html[2048];
    snprintf(html, sizeof(html),
        "<h2>ご予約確定のお知らせ</h2>"
        "<p>以下の内容でご予約が確定しました。</p>"
        "<table style=\"border-collapse:collapse\">"
        "<tr><th style=\"text-align:left;padding:8px 16px\">予約ID</th>"
        "<td style=\"padding:8px 16px\">%s</td></tr>"
        "<tr><th style=\"text-align:left;padding:8px 16px\">プラン</th>"
        "<td style=\"padding:8px 16px\">%s</td></tr>"
        "<tr><th style=\"text-align:left;padding:8px 16px\">日程</th>"
        "<td style=\"padding:8px 16px\">%s %s</td></tr>"
        "<tr><th style=\"text-align:left;padding:8px 16px\">合計金額</th>"
        "<td style=\"padding:8px 16px\">¥%ld</td></tr>"
        "</table>"
        "<p><a href=\"%s/bookings/%s\">予約詳細を確認する</a></p>",
        booking_id ? booking_id : "",
        plan_title  ? plan_title  : "",
        date        ? date        : "",
        start_time  ? start_time  : "",
        total_price,
        frontend,
        booking_id ? booking_id : "");

    send_email(to, "【asoview】ご予約確定のお知らせ", html);
}

void send_booking_cancellation_email(const char *to,
                                     const char *booking_id,
                                     const char *plan_title,
                                     int refunded) {
    char html[1024];
    snprintf(html, sizeof(html),
        "<h2>予約キャンセルのお知らせ</h2>"
        "<p>以下の予約がキャンセルされました。</p>"
        "<table style=\"border-collapse:collapse\">"
        "<tr><th style=\"text-align:left;padding:8px 16px\">予約ID</th>"
        "<td style=\"padding:8px 16px\">%s</td></tr>"
        "<tr><th style=\"text-align:left;padding:8px 16px\">プラン</th>"
        "<td style=\"padding:8px 16px\">%s</td></tr>"
        "</table>"
        "%s",
        booking_id ? booking_id : "",
        plan_title  ? plan_title  : "",
        refunded
            ? "<p>お支払い済みの金額は<strong>5〜10営業日以内</strong>に返金されます。</p>"
            : "");

    send_email(to, "【asoview】予約キャンセルのお知らせ", html);
}
