#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include "mongoose.h"
#include "db_driver.h"
#include "db.h"
#include "seed.h"
#include "handlers.h"
#include "admin.h"
#include "uploader.h"
#include "rate_limit.h"
#include "metrics.h"
#include "waitlist.h"
#include "setup.h"
#include "webhooks.h"
#include "mailer.h"
#include "portal.h"

#define MAX_BODY_BYTES (64 * 1024)  /* 64 KB リクエストボディ上限 */

static volatile int g_quit = 0;
static void handle_signal(int sig) { (void)sig; g_quit = 1; }

/* ─── 予約リマインダースレッド ──────────────────────────────────────────── */
static void *reminder_thread(void *arg) {
    const char *db_path = (const char *)arg;
    while (!g_quit) {
        /* 毎時 00 分に近いタイミングで起動 */
        time_t now = time(NULL);
        /* 次の 00:00 秒まで待つ（最大3600秒） */
        int sleep_secs = 3600 - (int)(now % 3600);
        for (int i = 0; i < sleep_secs && !g_quit; i++) {
            struct timespec ts = {1, 0};
            nanosleep(&ts, NULL);
        }
        if (g_quit) break;

        DbConn *rdb = db_open(db_path);
        if (!rdb) continue;

        /* 明日の confirmed 予約で reminder_sent=0 のもの */
        DbStmt *st = NULL;
        st = db_prepare(rdb,
            "SELECT b.id, u.email, p.title, s.date, s.start_time, v.name "
            "FROM bookings b "
            "JOIN users u     ON u.id=b.user_id "
            "JOIN schedules s ON s.id=b.schedule_id "
            "JOIN plans p     ON p.id=s.plan_id "
            "JOIN venues v    ON v.id=p.venue_id "
            "WHERE b.status='confirmed' "
            "  AND b.reminder_sent=0 "
            "  AND s.date = date('now', '+1 day')");
        if (!st) { db_close(rdb); continue; }

        /* 複数の結果を収集してから送信（DB ロック時間を短く） */
        typedef struct {
            char id[64], email[256], title[256], date[16], stime[8], venue[256];
        } REntry;
        REntry entries[64]; int n = 0;
        while (db_step(st) == 1 && n < 64) {
            REntry *e = &entries[n++];
            const char *v;
            v = db_col_text(st, 0); strncpy(e->id,    v?v:"", sizeof(e->id)-1);
            v = db_col_text(st, 1); strncpy(e->email, v?v:"", sizeof(e->email)-1);
            v = db_col_text(st, 2); strncpy(e->title, v?v:"", sizeof(e->title)-1);
            v = db_col_text(st, 3); strncpy(e->date,  v?v:"", sizeof(e->date)-1);
            v = db_col_text(st, 4); strncpy(e->stime, v?v:"", sizeof(e->stime)-1);
            v = db_col_text(st, 5); strncpy(e->venue, v?v:"", sizeof(e->venue)-1);
        }
        db_finalize(st);

        for (int i = 0; i < n; i++) {
            REntry *e = &entries[i];
            if (e->email[0]) {
                send_booking_reminder_email(e->email, e->id, e->title, e->date, e->stime, e->venue);
            }
            /* reminder_sent フラグを立てる */
            DbStmt *upd = db_prepare(rdb,
                "UPDATE bookings SET reminder_sent=1 WHERE id=?");
            db_bind_text(upd, 1, e->id);
            db_step(upd); db_finalize(upd);
            fprintf(stdout, "[reminder] sent for booking %s\n", e->id);
        }

        db_close(rdb);
    }
    return NULL;
}

/* シンプル UUID 生成（ログ用） */
static void gen_uuid(char *out, size_t sz) {
    unsigned int a = (unsigned int)rand(), b = (unsigned int)rand(),
                 c = (unsigned int)rand(), d = (unsigned int)rand();
    snprintf(out, sz, "%08x-%04x-4%03x-%04x-%08x%04x",
             a, b & 0xffff, c & 0xfff, (d & 0x3fff) | 0x8000,
             (unsigned int)rand(), b >> 16);
}

/* ─── SVG ファビコン（32×32 ブランドカラー マウンテンアイコン） ───────── */
static const char FAVICON_SVG[] =
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
    "<rect width='32' height='32' rx='7' fill='#1a1a2e'/>"
    "<polygon points='16,5 29,27 3,27' fill='#e94560'/>"
    "<polygon points='16,5 21,15 11,15' fill='white'/>"
    "</svg>";

/* ─── OGP ソーシャルプレビュー画像（1200×630） ──────────────────────── */
static const char OGP_IMAGE_SVG[] =
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1200 630'>"
    "<defs>"
    "<linearGradient id='bg' x1='0' y1='0' x2='1200' y2='630' gradientUnits='userSpaceOnUse'>"
    "<stop offset='0' stop-color='#1a1a2e'/><stop offset='1' stop-color='#0f0f23'/>"
    "</linearGradient>"
    "</defs>"
    "<rect width='1200' height='630' fill='url(#bg)'/>"
    "<polygon points='1100,630 1200,220 1200,630' fill='#e94560' opacity='0.08'/>"
    "<polygon points='950,630 1150,360 1200,630' fill='#e94560' opacity='0.12'/>"
    "<polygon points='860,630 1100,290 1200,630' fill='white' opacity='0.03'/>"
    "<polygon points='1200,220 1200,310 1170,250' fill='white' opacity='0.15'/>"
    "<polygon points='1150,360 1178,440 1122,440' fill='white' opacity='0.10'/>"
    "<rect x='0' y='0' width='8' height='630' fill='#e94560'/>"
    "<polygon points='96,82 116,110 76,110' fill='#e94560'/>"
    "<polygon points='96,82 104,96 88,96' fill='white'/>"
    "<text x='130' y='109' font-size='40' font-weight='700'"
    " font-family='system-ui,-apple-system,sans-serif' fill='white' letter-spacing='-1'>Asoview</text>"
    "<rect x='80' y='138' width='1040' height='1' fill='rgba(255,255,255,0.1)'/>"
    "<text x='80' y='248' font-size='68' font-weight='700'"
    " font-family='system-ui,-apple-system,sans-serif' fill='white' letter-spacing='-2'>Admin Dashboard</text>"
    "<text x='80' y='312' font-size='34' font-family='system-ui,-apple-system,sans-serif' fill='#e94560'>"
    "アクティビティ予約管理システム</text>"
    "<text x='80' y='378' font-size='24' font-family='system-ui,-apple-system,sans-serif'"
    " fill='rgba(255,255,255,0.45)'>"
    "日本全国の体験プランを一元管理。C11 + SQLite3 で動く 285KB のシングルバイナリ。</text>"
    "<rect x='80'  y='430' width='210' height='108' rx='12'"
    " fill='rgba(255,255,255,0.06)' stroke='rgba(255,255,255,0.10)' stroke-width='1'/>"
    "<text x='185' y='486' font-size='46' font-weight='700'"
    " font-family='system-ui,-apple-system,sans-serif' fill='white' text-anchor='middle'>44+</text>"
    "<text x='185' y='522' font-size='17' font-family='system-ui,-apple-system,sans-serif'"
    " fill='rgba(255,255,255,0.40)' text-anchor='middle'>API Endpoints</text>"
    "<rect x='308' y='430' width='210' height='108' rx='12'"
    " fill='rgba(255,255,255,0.06)' stroke='rgba(255,255,255,0.10)' stroke-width='1'/>"
    "<text x='413' y='486' font-size='46' font-weight='700'"
    " font-family='system-ui,-apple-system,sans-serif' fill='white' text-anchor='middle'>285KB</text>"
    "<text x='413' y='522' font-size='17' font-family='system-ui,-apple-system,sans-serif'"
    " fill='rgba(255,255,255,0.40)' text-anchor='middle'>Single Binary</text>"
    "<rect x='536' y='430' width='210' height='108' rx='12'"
    " fill='rgba(233,69,96,0.15)' stroke='rgba(233,69,96,0.30)' stroke-width='1'/>"
    "<text x='641' y='486' font-size='46' font-weight='700'"
    " font-family='system-ui,-apple-system,sans-serif' fill='#e94560' text-anchor='middle'>C11</text>"
    "<text x='641' y='522' font-size='17' font-family='system-ui,-apple-system,sans-serif'"
    " fill='rgba(233,69,96,0.60)' text-anchor='middle'>+ SQLite3</text>"
    "<rect x='764' y='430' width='210' height='108' rx='12'"
    " fill='rgba(255,255,255,0.06)' stroke='rgba(255,255,255,0.10)' stroke-width='1'/>"
    "<text x='869' y='486' font-size='46' font-weight='700'"
    " font-family='system-ui,-apple-system,sans-serif' fill='#4ade80' text-anchor='middle'>69/69</text>"
    "<text x='869' y='522' font-size='17' font-family='system-ui,-apple-system,sans-serif'"
    " fill='rgba(255,255,255,0.40)' text-anchor='middle'>Tests Passing</text>"
    "</svg>";

/* ─── 管理者ダッシュボード HTML テンプレート ─────────────────────────────
 *   %s[0] = og:image の絶対 URL
 *   %s[1] = og:url の絶対 URL
 *   %s[2] = twitter:image の絶対 URL (= og:image と同値)
 *   %s[3] = セットアップ警告バナー HTML（空文字列 or バナー）
 * ─────────────────────────────────────────────────────────────────────── */
static const char ADMIN_HTML_TEMPLATE[] =
    "<!DOCTYPE html>\n"
    "<html lang='ja'>\n"
    "<head>\n"
    "<meta charset='UTF-8'>\n"
    "<title>Asoview Admin \xe2\x80\x94 \xe3\x82\xa2\xe3\x82\xaf\xe3\x83\x86\xe3\x82\xa3\xe3\x83\x93\xe3\x83\x86\xe3\x82\xa3\xe4\xba\x88\xe7\xb4\x84\xe7\xae\xa1\xe7\x90\x86</title>\n"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
    "<meta name='description' content='\xe6\x97\xa5\xe6\x9c\xac\xe5\x85\xa8\xe5\x9b\xbd\xe3\x81\xae\xe3\x82\xa2\xe3\x82\xaf\xe3\x83\x86\xe3\x82\xa3\xe3\x83\x93\xe3\x83\x86\xe3\x82\xa3\xe3\x83\xbb\xe4\xbd\x93\xe9\xaa\x8c\xe3\x83\x97\xe3\x83\xa9\xe3\x83\xb3\xe3\x82\x92\xe7\xae\xa1\xe7\x90\x86\xe3\x81\x99\xe3\x82\x8b\xe7\xae\xa1\xe7\x90\x86\xe8\x80\x85\xe3\x83\x80\xe3\x83\x83\xe3\x82\xb7\xe3\x83\xa5\xe3\x83\x9c\xe3\x83\xbc\xe3\x83\x89'>\n"
    /* Favicon */
    "<link rel='icon' type='image/svg+xml' href='/favicon.svg'>\n"
    "<link rel='alternate icon' href='/favicon.ico'>\n"
    "<link rel='apple-touch-icon' href='/favicon.svg'>\n"
    /* OGP */
    "<meta property='og:type' content='website'>\n"
    "<meta property='og:site_name' content='Asoview'>\n"
    "<meta property='og:title' content='Asoview Admin \xe2\x80\x94 \xe3\x82\xa2\xe3\x82\xaf\xe3\x83\x86\xe3\x82\xa3\xe3\x83\x93\xe3\x83\x86\xe3\x82\xa3\xe4\xba\x88\xe7\xb4\x84\xe7\xae\xa1\xe7\x90\x86'>\n"
    "<meta property='og:description' content='C11 + SQLite3 \xe3\x81\xa7\xe5\x8b\x95\xe3\x81\x8f 285KB \xe3\x81\xae\xe3\x82\xb7\xe3\x83\xb3\xe3\x82\xb0\xe3\x83\xab\xe3\x83\x90\xe3\x82\xa4\xe3\x83\x8a\xe3\x83\xaa\xe4\xba\x88\xe7\xb4\x84\xe7\xae\xa1\xe7\x90\x86\xe3\x82\xb7\xe3\x82\xb9\xe3\x83\x86\xe3\x83\xa0'>\n"
    "<meta property='og:image' content='%s'>\n"
    "<meta property='og:image:width' content='1200'>\n"
    "<meta property='og:image:height' content='630'>\n"
    "<meta property='og:image:type' content='image/svg+xml'>\n"
    "<meta property='og:url' content='%s'>\n"
    "<meta property='og:locale' content='ja_JP'>\n"
    /* Twitter Card */
    "<meta name='twitter:card' content='summary_large_image'>\n"
    "<meta name='twitter:title' content='Asoview Admin'>\n"
    "<meta name='twitter:description' content='C11 + SQLite3, 285KB single binary. 44+ API endpoints, 69/69 tests passing.'>\n"
    "<meta name='twitter:image' content='%s'>\n"
    /* Styles */
    "<style>\n"
    "*{box-sizing:border-box}\n"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f0f2f5;color:#333}\n"
    ".header{background:#1a1a2e;color:white;padding:16px 24px;display:flex;align-items:center;gap:12px}\n"
    ".header h1{margin:0;font-size:20px;display:flex;align-items:center;gap:8px}\n"
    ".badge{background:#e94560;color:white;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}\n"
    ".container{max-width:900px;margin:24px auto;padding:0 16px}\n"
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}\n"
    ".card{background:white;border-radius:12px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.08)}\n"
    ".card h2{margin:0 0 8px;font-size:12px;color:#888;text-transform:uppercase;letter-spacing:.6px}\n"
    ".card .val{font-size:32px;font-weight:700;color:#1a1a2e;line-height:1}\n"
    ".card .sub{font-size:12px;color:#aaa;margin-top:4px}\n"
    ".links{background:white;border-radius:12px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.08)}\n"
    ".links h2{margin:0 0 16px;font-size:15px;font-weight:600}\n"
    ".link-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px}\n"
    ".link-btn{display:block;padding:10px 14px;background:#f7f7f7;border-radius:8px;"
    "text-decoration:none;color:#333;font-size:13px;transition:background .15s;text-align:center;"
    "border:1px solid #eee}\n"
    ".link-btn:hover{background:#e8eaf0;border-color:#dde}\n"
    ".note{color:#aaa;font-size:12px;margin-top:20px;text-align:center}\n"
    ".note code{background:#f0f0f0;padding:1px 6px;border-radius:4px;font-size:11px}\n"
    ".setup-banner{background:#fff3cd;border:1px solid #ffc107;border-radius:8px;"
    "padding:12px 16px;margin-bottom:20px;font-size:13px;color:#856404;"
    "display:flex;align-items:center;justify-content:space-between;gap:12px}\n"
    ".setup-banner a{background:#e94560;color:#fff;padding:6px 16px;border-radius:6px;"
    "text-decoration:none;font-weight:600;font-size:12px;white-space:nowrap}\n"
    ".setup-banner a:hover{background:#c73552}\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "<div class='header'>"
    "<svg width='24' height='24' viewBox='0 0 32 32' style='flex-shrink:0'>"
    "<polygon points='16,3 30,29 2,29' fill='#e94560'/>"
    "<polygon points='16,3 22,15 10,15' fill='white'/>"
    "</svg>"
    "<h1>Asoview Admin</h1>"
    "<span class='badge'>\xe7\xae\xa1\xe7\x90\x86\xe7\x94\xbb\xe9\x9d\xa2</span>"
    "</div>\n"
    "<div class='container'>\n"
    "%s"  /* [3] setup warning banner (empty or HTML) */
    "<div class='grid'>\n"
    "<div class='card'><h2>API</h2><div class='val'>44+</div><div class='sub'>\xe3\x82\xa8\xe3\x83\xb3\xe3\x83\x89\xe3\x83\x9d\xe3\x82\xa4\xe3\x83\xb3\xe3\x83\x88</div></div>\n"
    "<div class='card'><h2>Binary</h2><div class='val'>~285</div><div class='sub'>KB</div></div>\n"
    "<div class='card'><h2>Stack</h2><div class='val'>C11</div><div class='sub'>+ SQLite3</div></div>\n"
    "<div class='card'><h2>Tests</h2><div class='val' style='color:#16a34a'>69/69</div><div class='sub'>all passing</div></div>\n"
    "</div>\n"
    "<div class='links'>\n"
    "<h2>\xe7\xae\xa1\xe7\x90\x86\xe3\x82\xa8\xe3\x83\xb3\xe3\x83\x89\xe3\x83\x9d\xe3\x82\xa4\xe3\x83\xb3\xe3\x83\x88</h2>\n"
    "<div class='link-grid'>\n"
    "<a class='link-btn' href='/api/v1/admin/venues'>\xf0\x9f\x93\x8d \xe4\xbc\x9a\xe5\xa0\xb4\xe4\xb8\x80\xe8\xa6\xa7</a>\n"
    "<a class='link-btn' href='/api/v1/admin/plans'>\xf0\x9f\x93\x8b \xe3\x83\x97\xe3\x83\xa9\xe3\x83\xb3\xe4\xb8\x80\xe8\xa6\xa7</a>\n"
    "<a class='link-btn' href='/api/v1/admin/bookings'>\xf0\x9f\x93\x85 \xe4\xba\x88\xe7\xb4\x84\xe4\xb8\x80\xe8\xa6\xa7</a>\n"
    "<a class='link-btn' href='/api/v1/admin/users'>\xf0\x9f\x91\xa5 \xe3\x83\xa6\xe3\x83\xbc\xe3\x82\xb6\xe3\x83\xbc\xe4\xb8\x80\xe8\xa6\xa7</a>\n"
    "<a class='link-btn' href='/api/v1/admin/reviews'>\xe2\xad\x90 \xe3\x83\xac\xe3\x83\x93\xe3\x83\xa5\xe3\x83\xbc\xe4\xb8\x80\xe8\xa6\xa7</a>\n"
    "<a class='link-btn' href='/api/v1/health'>\xe2\x9d\xa4\xef\xb8\x8f \xe3\x83\x98\xe3\x83\xab\xe3\x82\xb9\xe3\x83\x81\xe3\x82\xa7\xe3\x83\x83\xe3\x82\xaf</a>\n"
    "<a class='link-btn' href='/api/v1/metrics'>\xf0\x9f\x93\x8a Prometheus</a>\n"
    "<a class='link-btn' href='/api/v1/venues'>\xf0\x9f\x8f\xa0 \xe4\xbc\x9a\xe5\xa0\xb4 (Public)</a>\n"
    "<a class='link-btn' href='/api/v1/plans'>\xf0\x9f\x97\x92\xef\xb8\x8f \xe3\x83\x97\xe3\x83\xa9\xe3\x83\xb3 (Public)</a>\n"
    "<a class='link-btn' href='/setup' style='border-color:#e94560;color:#e94560'>"
    "&#9881; \xe3\x82\xbb\xe3\x83\x83\xe3\x83\x88\xe3\x82\xa2\xe3\x83\x83\xe3\x83\x97</a>\n"
    "</div>\n"
    "</div>\n"
    "<p class='note'>\xe7\xae\xa1\xe7\x90\x86\xe8\x80\x85\xe3\x82\xa8\xe3\x83\xb3\xe3\x83\x89\xe3\x83\x9d\xe3\x82\xa4\xe3\x83\xb3\xe3\x83\x88\xe3\x81\xab\xe3\x81\xaf <code>X-Admin-Key</code> \xe3\x83\x98\xe3\x83\x83\xe3\x83\x80\xe3\x83\xbc\xe3\x81\x8c\xe5\xbf\x85\xe8\xa6\x81\xe3\x81\xa7\xe3\x81\x99</p>\n"
    "</div>\n"
    "</body></html>\n";

static void event_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev != MG_EV_HTTP_MSG) return;
    struct mg_http_message *hm = (struct mg_http_message *)ev_data;
    DbConn *db = (DbConn *)c->fn_data;

    char uri[256] = {0};
    snprintf(uri, sizeof(uri), "%.*s", (int)hm->uri.len, hm->uri.buf);

    /* X-Request-ID 生成 */
    gen_uuid(g_request_id, sizeof(g_request_id));

    /* Per-request フラグを設定 */
    g_hm_current  = hm;
    g_accept_gzip = 0;
    g_lang_en     = 0;
    {
        struct mg_str *ae = mg_http_get_header(hm, "Accept-Encoding");
        if (ae) {
            char ae_buf[256] = {0};
            snprintf(ae_buf, sizeof(ae_buf), "%.*s", (int)ae->len, ae->buf);
            if (strstr(ae_buf, "gzip")) g_accept_gzip = 1;
        }
        struct mg_str *al = mg_http_get_header(hm, "Accept-Language");
        if (al) {
            char al_buf[64] = {0};
            snprintf(al_buf, sizeof(al_buf), "%.*s", (int)al->len, al->buf);
            if (strstr(al_buf, "en")) g_lang_en = 1;
        }
    }

    /* IP ベースレート制限 */
    char client_ip[48] = {0};
    mg_snprintf(client_ip, sizeof(client_ip), "%M", mg_print_ip, &c->rem);

    /* リクエストログ（JSON 構造化ログ） */
    {
        time_t now = time(NULL);
        char ts[24];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
        /* JSON エスケープが必要な文字（URI/IPには通常不要だが念のため最小限対応） */
        fprintf(stderr,
                "{\"ts\":\"%s\",\"level\":\"info\",\"method\":\"%.*s\","
                "\"uri\":\"%s\",\"ip\":\"%s\",\"req_id\":\"%s\"}\n",
                ts, (int)hm->method.len, hm->method.buf,
                uri, client_ip, g_request_id);
    }

    /* メトリクス: 総リクエスト数をカウント */
    metrics_incr_req();

    /* jwt_blocklist 定期クリーンアップ（1000 リクエストに 1 回） */
    static unsigned long g_req_count = 0;
    if (++g_req_count % 1000 == 0) {
        db_exec(db, "DELETE FROM jwt_blocklist WHERE expires_at < " SQL_NOW_STR);
    }

    /* リクエストボディサイズ上限 */
    if (hm->body.len > MAX_BODY_BYTES) {
        mg_http_reply(c, 413, "Content-Type: application/json\r\n",
                      "{\"error\":\"リクエストボディが大きすぎます（上限 64KB）\"}");
        return;
    }
    /* auth/registration endpoints get strict limit; /users/:id/... uses general limit */
    int uri_is_users_exact = (strncmp(hm->uri.buf, "/api/v1/users", 13) == 0 &&
                               (hm->uri.len <= 13 || hm->uri.buf[13] != '/'));
    int is_auth_ep = (strncmp(hm->uri.buf, "/api/v1/auth", 12) == 0 || uri_is_users_exact);
    if (rate_check(client_ip, is_auth_ep)) {
        mg_http_reply(c, 429, "Content-Type: application/json\r\n",
                      "{\"error\":\"リクエスト数が多すぎます。しばらく経ってから再試行してください\"}");
        return;
    }

    /* CORS プリフライト */
    if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
        const char *cors_origin = getenv("CORS_ORIGIN");
        if (!cors_origin || !*cors_origin) {
            static int cors_warned = 0;
            if (!cors_warned) {
                cors_warned = 1;
                fprintf(stderr, "[WARN] CORS_ORIGIN is not set — defaulting to '*' (allow all origins). "
                        "Set CORS_ORIGIN in production!\n");
            }
            cors_origin = "*";
        }
        char cors_hdrs[512];
        snprintf(cors_hdrs, sizeof(cors_hdrs),
            "Access-Control-Allow-Origin: %s\r\n"
            "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization, X-Admin-Key, X-Tenant-ID\r\n"
            "Access-Control-Max-Age: 86400\r\n",
            cors_origin);
        mg_http_reply(c, 204, cors_hdrs, "");
        return;
    }

    long id = 0;
    char booking_id[64] = {0};

#define IS_GET    (mg_strcmp(hm->method, mg_str("GET"))    == 0)
#define IS_POST   (mg_strcmp(hm->method, mg_str("POST"))   == 0)
#define IS_PATCH  (mg_strcmp(hm->method, mg_str("PATCH"))  == 0)
#define IS_DELETE (mg_strcmp(hm->method, mg_str("DELETE")) == 0)
#define IS_PUT    (mg_strcmp(hm->method, mg_str("PUT"))    == 0)

    /* ── Favicon ────────────────────────────────────────────────────────── */
    if (strcmp(uri, "/favicon.svg") == 0) {
        if (IS_GET)
            mg_http_reply(c, 200,
                "Content-Type: image/svg+xml\r\n"
                "Cache-Control: public,max-age=604800,immutable\r\n",
                "%s", FAVICON_SVG);

    } else if (strcmp(uri, "/favicon.ico") == 0) {
        if (IS_GET)
            mg_http_reply(c, 302,
                "Location: /favicon.svg\r\n"
                "Cache-Control: public,max-age=604800\r\n", "");

    /* ── OGP ソーシャルプレビュー画像 ────────────────────────────────────── */
    } else if (strcmp(uri, "/og-image.svg") == 0) {
        if (IS_GET)
            mg_http_reply(c, 200,
                "Content-Type: image/svg+xml\r\n"
                "Cache-Control: public,max-age=3600\r\n",
                "%s", OGP_IMAGE_SVG);

    /* ── Admin ダッシュボード HTML ────────────────────────────────────────── */
    } else if (strcmp(uri, "/admin") == 0 || strcmp(uri, "/admin/") == 0) {
        if (IS_GET) {
            /* Host ヘッダーから og:image / og:url の絶対 URL を組み立てる */
            char base[256] = "http://localhost:3001";
            struct mg_str *host_h  = mg_http_get_header(hm, "Host");
            struct mg_str *proto_h = mg_http_get_header(hm, "X-Forwarded-Proto");
            if (host_h && host_h->len > 0) {
                const char *scheme =
                    (proto_h && mg_strcmp(*proto_h, mg_str("https")) == 0)
                    ? "https" : "http";
                snprintf(base, sizeof(base), "%s://%.*s",
                         scheme, (int)host_h->len, host_h->buf);
            }
            char og_image[300], og_url[300];
            snprintf(og_image, sizeof(og_image), "%s/og-image.svg", base);
            snprintf(og_url,   sizeof(og_url),   "%s/admin",        base);
            const char *setup_banner =
                setup_is_unconfigured()
                ? "<div class='setup-banner'>"
                  "&#9888; <strong>初期設定が必要です</strong> "
                  "&mdash; JWT_SECRET / ADMIN_KEY / Stripe / Resend キーを設定してください"
                  "<a href='/setup'>&#9881; セットアップ</a>"
                  "</div>\n"
                : "";
            mg_http_reply(c, 200,
                "Content-Type: text/html; charset=UTF-8\r\n"
                "Cache-Control: no-cache\r\n"
                "X-Frame-Options: DENY\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "Content-Security-Policy: default-src 'self'; "
                "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'\r\n"
                "Referrer-Policy: strict-origin-when-cross-origin\r\n",
                ADMIN_HTML_TEMPLATE, og_image, og_url, og_image, setup_banner);
        }

    /* ── Prometheus メトリクス ────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/metrics") == 0) {
        if (IS_GET) {
            char mbuf[2048] = {0};
            metrics_render(mbuf, sizeof(mbuf));
            mg_http_reply(c, 200,
                "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n",
                "%s", mbuf);
        }

    /* ── Public endpoints ─────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/health") == 0) {
        if (IS_GET) handle_health(c, hm, db);

    } else if (strcmp(uri, "/api/v1/areas") == 0) {
        if (IS_GET) handle_list_areas(c, hm, db);

    } else if (strcmp(uri, "/api/v1/categories") == 0) {
        if (IS_GET) handle_list_categories(c, hm, db);

    } else if (strcmp(uri, "/api/v1/venues") == 0) {
        if (IS_GET) handle_list_venues(c, hm, db);

    } else if (sscanf(uri, "/api/v1/venues/%ld/plans", &id) == 1
               && strstr(uri, "/plans") != NULL) {
        if (IS_GET) handle_list_venue_plans(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/venues/%ld", &id) == 1
               && strstr(uri, "/plans") == NULL) {
        if (IS_GET) handle_get_venue(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/plans/%ld/availability", &id) == 1
               && strstr(uri, "/availability") != NULL) {
        if (IS_GET) handle_plan_availability(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/plans/%ld/schedules", &id) == 1
               && strstr(uri, "/schedules") != NULL) {
        if (IS_GET) handle_list_schedules(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/plans/%ld/reviews", &id) == 1
               && strstr(uri, "/reviews") != NULL) {
        if (IS_GET) handle_list_plan_reviews(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/plans") == 0) {
        if (IS_GET) handle_list_plans(c, hm, db);

    } else if (sscanf(uri, "/api/v1/plans/%ld", &id) == 1
               && strstr(uri, "/schedules") == NULL
               && strstr(uri, "/reviews") == NULL) {
        if (IS_GET) handle_get_plan(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/users") == 0) {
        if (IS_POST) handle_create_user(c, hm, db);

    } else if (strcmp(uri, "/api/v1/users/me/export") == 0) {
        if (IS_GET) handle_export_user_data(c, hm, db);

    } else if (strcmp(uri, "/api/v1/users/me") == 0) {
        if (IS_DELETE) handle_delete_user_account(c, hm, db);

    } else if (sscanf(uri, "/api/v1/users/%ld/bookings", &id) == 1
               && strstr(uri, "/bookings") != NULL) {
        if (IS_GET) handle_list_user_bookings(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/users/%ld/bookmarks", &id) == 1
               && strstr(uri, "/bookmarks") != NULL) {
        if (IS_GET) handle_list_user_bookmarks(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/users/%ld", &id) == 1
               && strstr(uri, "/bookings") == NULL
               && strstr(uri, "/bookmarks") == NULL) {
        if (IS_GET)   handle_get_user(c, hm, db, id);
        else if (IS_PATCH) handle_update_user(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/auth/login") == 0) {
        if (IS_POST) handle_login(c, hm, db);

    } else if (strcmp(uri, "/api/v1/auth/logout") == 0) {
        if (IS_POST) handle_auth_logout(c, hm, db);

    } else if (strcmp(uri, "/api/v1/auth/change-password") == 0) {
        if (IS_PATCH) handle_change_password(c, hm, db);

    } else if (strcmp(uri, "/api/v1/auth/forgot-password") == 0) {
        if (IS_POST) handle_forgot_password(c, hm, db);

    } else if (strcmp(uri, "/api/v1/auth/reset-password") == 0) {
        if (IS_POST) handle_reset_password(c, hm, db);

    } else if (strcmp(uri, "/api/v1/auth/refresh") == 0) {
        if (IS_POST) handle_auth_refresh(c, hm, db);

    } else if (strcmp(uri, "/api/v1/bookings") == 0) {
        if (IS_POST) handle_create_booking(c, hm, db);

    } else if (sscanf(uri, "/api/v1/bookings/%36[^/]", booking_id) == 1) {
        /* check suffix after the UUID to distinguish /:id vs /:id/cancel vs /:id/ical */
        size_t pfx = strlen("/api/v1/bookings/") + strlen(booking_id);
        if (strcmp(uri + pfx, "/cancel") == 0) {
            if (IS_PATCH) handle_cancel_booking(c, hm, db, booking_id);
        } else if (strcmp(uri + pfx, "/ical") == 0) {
            if (IS_GET)   handle_ical_booking(c, hm, db, booking_id);
        } else if (strcmp(uri + pfx, "/reschedule") == 0) {
            if (IS_PATCH) handle_reschedule_booking(c, hm, db, booking_id);
        } else if (uri[pfx] == '\0') {
            if (IS_GET) handle_get_booking(c, hm, db, booking_id);
        } else {
            mg_http_reply(c, 404, "Content-Type: application/json\r\n", "{\"error\":\"not found\"}");
        }

    } else if (strcmp(uri, "/api/v1/reviews") == 0) {
        if (IS_POST) handle_create_review(c, hm, db);

    } else if (strcmp(uri, "/api/v1/search") == 0) {
        if (IS_GET) handle_search(c, hm, db);

    } else if (strcmp(uri, "/api/v1/webhooks/stripe") == 0) {
        if (IS_POST) handle_stripe_webhook(c, hm, db);

    /* ── Checkout Session（4ページ目→決済→次へ） ─────────────────────────── */
    } else if (strcmp(uri, "/api/v1/checkout/session") == 0) {
        if (IS_POST) handle_create_checkout_session(c, hm, db);

    /* ── 決済完了・キャンセルページ ──────────────────────────────────────── */
    } else if (strcmp(uri, "/payment/success") == 0) {
        if (IS_GET) {
            char amt_str[32] = {0};
            mg_http_get_var(&hm->query, "amount", amt_str, sizeof(amt_str));
            long amount = amt_str[0] ? atol(amt_str) : 0;
            char amount_display[64];
            if (amount > 0)
                snprintf(amount_display, sizeof(amount_display),
                         "&#165;%ld", amount);
            else
                snprintf(amount_display, sizeof(amount_display), "お支払い");
            mg_http_reply(c, 200,
                "Content-Type: text/html; charset=UTF-8\r\n"
                "Cache-Control: no-cache\r\n",
                "<!doctype html><html lang='ja'><head><meta charset='UTF-8'>"
                "<title>お支払い完了 - asoview</title>"
                "<style>body{font-family:sans-serif;display:flex;align-items:center;"
                "justify-content:center;min-height:100vh;margin:0;background:#f0fdf4;}"
                ".box{text-align:center;padding:48px;background:#fff;border-radius:16px;"
                "box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:480px;width:90%%;}"
                "h1{color:#16a34a;font-size:2rem;margin-bottom:.5rem}"
                "p{color:#555;margin:1rem 0 2rem}"
                ".amount{font-size:2.5rem;font-weight:900;color:#16a34a;margin:1rem 0;}"
                ".btn{display:inline-block;background:#7c3aed;color:#fff;padding:14px 32px;"
                "border-radius:8px;text-decoration:none;font-weight:700;font-size:1rem}"
                ".btn:hover{opacity:.85}</style></head>"
                "<body><div class='box'>"
                "<div style='font-size:3.5rem;margin-bottom:.5rem'>&#9989;</div>"
                "<h1>お支払い完了</h1>"
                "<div class='amount'>%s</div>"
                "<p>ご予約が確定しました。<br>確認メールをお送りします。</p>"
                "<a class='btn' href='/ui'>&#8594;&nbsp;マイ予約を確認する</a>"
                "</div></body></html>", amount_display);
        }

    } else if (strcmp(uri, "/payment/cancel") == 0) {
        if (IS_GET)
            mg_http_reply(c, 200,
                "Content-Type: text/html; charset=UTF-8\r\n"
                "Cache-Control: no-cache\r\n",
                "<!doctype html><html lang='ja'><head><meta charset='UTF-8'>"
                "<title>お支払いキャンセル - asoview</title>"
                "<style>body{font-family:sans-serif;display:flex;align-items:center;"
                "justify-content:center;min-height:100vh;margin:0;background:#fff7ed;}"
                ".box{text-align:center;padding:48px;background:#fff;border-radius:16px;"
                "box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:480px;width:90%%;}"
                "h1{color:#ea580c;font-size:2rem;margin-bottom:.5rem}"
                "p{color:#555;margin:1rem 0 2rem}"
                ".btn{display:inline-block;background:#e94560;color:#fff;padding:14px 32px;"
                "border-radius:8px;text-decoration:none;font-weight:700;font-size:1rem}"
                ".btn:hover{background:#c73552}</style></head>"
                "<body><div class='box'>"
                "<div style='font-size:3rem'>&#9888;</div>"
                "<h1>お支払いがキャンセルされました</h1>"
                "<p>お支払いはキャンセルされました。<br>"
                "もう一度お試しください。</p>"
                "<a class='btn' href='javascript:history.back()'>&#8592;&nbsp;前のページに戻る</a>"
                "</div></body></html>%s", "");

    } else if (strcmp(uri, "/api/v1/bookmarks") == 0) {
        if (IS_POST) handle_create_bookmark(c, hm, db);

    } else if (sscanf(uri, "/api/v1/bookmarks/%ld", &id) == 1) {
        if (IS_DELETE) handle_delete_bookmark(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/reviews/%ld", &id) == 1) {
        if (IS_DELETE) handle_delete_review(c, hm, db, id);

    /* ── Waitlist ────────────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/waitlist") == 0) {
        if (IS_POST) handle_create_waitlist(c, hm, db);

    } else if (sscanf(uri, "/api/v1/waitlist/schedule/%ld", &id) == 1) {
        if (IS_GET) handle_list_waitlist(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/waitlist/%ld", &id) == 1) {
        if (IS_DELETE) handle_delete_waitlist(c, hm, db, id);

    /* Admin endpoints: /api/v1/admin/ ──────────────────────── */
    } else if (strcmp(uri, "/api/v1/admin/venues") == 0) {
        if (IS_GET)  handle_admin_list_venues(c, hm, db);
        else if (IS_POST) handle_admin_create_venue(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/venues/%ld", &id) == 1) {
        if (IS_PATCH)  handle_admin_update_venue(c, hm, db, id);
        else if (IS_DELETE) handle_admin_delete_venue(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/admin/plans") == 0) {
        if (IS_GET)  handle_admin_list_plans(c, hm, db);
        else if (IS_POST) handle_admin_create_plan(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/plans/%ld/schedules/bulk", &id) == 1
               && strstr(uri, "/schedules/bulk") != NULL) {
        if (IS_POST) handle_admin_bulk_create_schedules(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/admin/plans/%ld/schedules", &id) == 1
               && strstr(uri, "/schedules") != NULL
               && strstr(uri, "/bulk") == NULL) {
        if (IS_POST) handle_admin_create_schedule(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/admin/plans/%ld/prices", &id) == 1
               && strstr(uri, "/prices") != NULL) {
        if (IS_PUT) handle_admin_set_prices(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/admin/plans/%ld", &id) == 1
               && strstr(uri, "/schedules") == NULL
               && strstr(uri, "/prices") == NULL
               && strstr(uri, "/images") == NULL) {
        if (IS_PATCH)  handle_admin_update_plan(c, hm, db, id);
        else if (IS_DELETE) handle_admin_delete_plan(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/admin/schedules/%ld", &id) == 1) {
        if (IS_PATCH)  handle_admin_update_schedule(c, hm, db, id);
        else if (IS_DELETE) handle_admin_delete_schedule(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/admin/bookings") == 0) {
        if (IS_GET) handle_admin_list_bookings(c, hm, db);

    } else if (strcmp(uri, "/api/v1/admin/reviews") == 0) {
        if (IS_GET) handle_admin_list_reviews(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/reviews/%ld", &id) == 1) {
        if (IS_DELETE) handle_admin_delete_review(c, hm, db, id);

    } else if (strcmp(uri, "/api/v1/admin/users") == 0) {
        if (IS_GET) handle_admin_list_users(c, hm, db);

    } else if (strcmp(uri, "/api/v1/admin/upload-url") == 0) {
        if (IS_POST) handle_admin_get_upload_url(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/bookings/%63[^/]/refund", booking_id) == 1
               && strstr(uri, "/refund") != NULL) {
        if (IS_POST) handle_admin_refund_booking(c, hm, db, booking_id);

    } else if (strcmp(uri, "/api/v1/admin/audit-logs") == 0) {
        if (IS_GET) handle_admin_audit_logs(c, hm, db);

    } else if (strcmp(uri, "/api/v1/admin/backup") == 0) {
        if (IS_GET) handle_admin_backup_db(c, hm, db);

    } else if (strcmp(uri, "/admin/ui") == 0 || strcmp(uri, "/admin/ui/") == 0) {
        if (IS_GET) handle_admin_ui(c, hm, db);

    /* ── 2FA ─────────────────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/auth/2fa/setup") == 0) {
        if (IS_POST) handle_auth_2fa_setup(c, hm, db);

    } else if (strcmp(uri, "/api/v1/auth/2fa/enable") == 0) {
        if (IS_POST) handle_auth_2fa_enable(c, hm, db);

    } else if (strcmp(uri, "/api/v1/auth/2fa/verify") == 0) {
        if (IS_POST) handle_auth_2fa_verify(c, hm, db);

    /* ── クーポン ────────────────────────────────────────────────────────── */
    } else if (sscanf(uri, "/api/v1/coupons/%63s", booking_id) == 1) {
        if (IS_GET) handle_validate_coupon(c, hm, db, booking_id);

    /* ── Admin: 売上レポート ─────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/admin/reports/sales") == 0) {
        if (IS_GET) handle_admin_sales_report(c, hm, db);

    /* ── Admin: Webhook ──────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/admin/webhooks") == 0) {
        if (IS_GET)  handle_admin_list_webhooks(c, hm, db);
        else if (IS_POST) handle_admin_create_webhook(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/webhooks/%ld", &id) == 1) {
        if (IS_DELETE) handle_admin_delete_webhook(c, hm, db, id);

    /* ── Admin: クーポン ─────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/admin/coupons") == 0) {
        if (IS_GET)  handle_admin_list_coupons(c, hm, db);
        else if (IS_POST) handle_admin_create_coupon(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/coupons/%ld", &id) == 1) {
        if (IS_DELETE) handle_admin_delete_coupon(c, hm, db, id);

    /* ── Admin: プラン画像 ───────────────────────────────────────────────── */
    } else if (sscanf(uri, "/api/v1/admin/plans/%ld/images", &id) == 1
               && strstr(uri, "/images") != NULL) {
        if (IS_GET)  handle_admin_list_plan_images(c, hm, db, id);
        else if (IS_POST) handle_admin_create_plan_image(c, hm, db, id);

    } else if (sscanf(uri, "/api/v1/admin/plan-images/%ld", &id) == 1) {
        if (IS_DELETE) handle_admin_delete_plan_image(c, hm, db, id);

    /* ── Admin 2FA セットアップ ─────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/admin/2fa/setup") == 0) {
        if (IS_GET) handle_admin_2fa_setup(c, hm, db);

    /* ── ギフト券（公開）────────────────────────────────────────────────── */
    } else if (sscanf(uri, "/api/v1/gift-cards/%63s", booking_id) == 1) {
        if (IS_GET) handle_validate_giftcard(c, hm, db, booking_id);

    /* ── ギフト券（管理）────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/admin/gift-cards") == 0) {
        if (IS_GET)  handle_admin_list_giftcards(c, hm, db);
        else if (IS_POST) handle_admin_create_giftcard(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/gift-cards/%ld", &id) == 1) {
        if (IS_DELETE) handle_admin_delete_giftcard(c, hm, db, id);

    /* ── スタッフ ────────────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/staff/bookings") == 0) {
        if (IS_GET) handle_staff_list_bookings(c, hm, db);

    } else if (strcmp(uri, "/api/v1/staff/venues") == 0) {
        if (IS_GET) handle_staff_list_venues(c, hm, db);

    /* ── Admin: スタッフ管理 ─────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/admin/staff") == 0) {
        if (IS_GET)  handle_admin_list_staff(c, hm, db);
        else if (IS_POST) handle_admin_assign_staff_venue(c, hm, db);

    } else if (strncmp(uri, "/api/v1/admin/staff/", 20) == 0 && strstr(uri, "/venues/")) {
        long staff_id = 0, venue_id2 = 0;
        sscanf(uri, "/api/v1/admin/staff/%ld/venues/%ld", &staff_id, &venue_id2);
        if (IS_DELETE) handle_admin_remove_staff_venue(c, hm, db, staff_id, venue_id2);

    /* ── Google OAuth ────────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/auth/google") == 0) {
        if (IS_GET) handle_auth_google(c, hm, db);

    } else if (strcmp(uri, "/api/v1/auth/google/callback") == 0) {
        if (IS_GET) handle_auth_google_callback(c, hm, db);

    /* ── テナント管理 ──────────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/api/v1/admin/tenants") == 0) {
        if (IS_GET)  handle_admin_list_tenants(c, hm, db);
        if (IS_POST) handle_admin_create_tenant(c, hm, db);

    } else if (sscanf(uri, "/api/v1/admin/tenants/%ld", &id) == 1) {
        if (IS_GET)    handle_admin_get_tenant(c, hm, db, id);
        if (IS_PATCH)  handle_admin_update_tenant(c, hm, db, id);
        if (IS_DELETE) handle_admin_delete_tenant(c, hm, db, id);

    /* ── OpenAPI スペック ────────────────────────────────────────────────── */
    } else if (strcmp(uri, "/openapi.yaml") == 0 ||
               strcmp(uri, "/api/v1/openapi.json") == 0 ||
               strcmp(uri, "/openapi.json") == 0) {
        if (IS_GET) {
            FILE *f = fopen("openapi.yaml", "r");
            if (!f) f = fopen("/app/openapi.yaml", "r");
            if (!f) f = fopen("openapi.yml",  "r");
            if (!f) f = fopen("/app/openapi.yml",  "r");
            if (f) {
                fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
                char *yml = malloc((size_t)sz + 1);
                if (yml) {
                    fread(yml, 1, (size_t)sz, f); yml[sz] = '\0';
                    const char *ct = strstr(uri, ".json")
                        ? "application/json" : "text/yaml; charset=UTF-8";
                    mg_http_reply(c, 200,
                        "Content-Type: %s\r\n"
                        "Access-Control-Allow-Origin: *\r\n",
                        ct, "%s", yml);
                    free(yml);
                } else {
                    send_error_json(c, 500, "OOM");
                }
                fclose(f);
            } else {
                send_error_json(c, 404, "openapi.yaml not found");
            }
        }

    /* ── API ドキュメント（Scalar UI） ──────────────────────────────────── */
    } else if (strcmp(uri, "/docs") == 0 || strcmp(uri, "/docs/") == 0) {
        if (IS_GET) {
            static const char DOCS_HTML[] =
"<!DOCTYPE html>\n"
"<html>\n"
"<head>\n"
"<meta charset='UTF-8'>\n"
"<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
"<title>Asoview API Reference</title>\n"
"<style>body{margin:0;}</style>\n"
"</head>\n"
"<body>\n"
"<script id='api-reference' data-url='/openapi.yaml'></script>\n"
"<script src='https://cdn.jsdelivr.net/npm/@scalar/api-reference'></script>\n"
"</body>\n"
"</html>\n";
            mg_http_reply(c, 200,
                "Content-Type: text/html; charset=UTF-8\r\n"
                "Cache-Control: no-cache\r\n",
                "%s", DOCS_HTML);
        }

    /* ── ユーザーポータル ─────────────────────────────────────────────── */
    } else if (strcmp(uri, "/ui") == 0 || strcmp(uri, "/ui/") == 0 ||
               strcmp(uri, "/") == 0) {
        if (IS_GET) handle_portal(c, hm, db);

    /* ── セットアップウィザード ───────────────────────────────────────────── */
    } else if (strcmp(uri, "/setup") == 0 || strcmp(uri, "/setup/") == 0) {
        if (IS_GET) handle_setup_page(c, hm, db);

    } else if (strcmp(uri, "/api/v1/setup") == 0) {
        if (IS_POST) handle_setup_save(c, hm, db);

    } else {
        mg_http_reply(c, 404, "Content-Type: application/json\r\n",
                      "{\"error\":\"not found\"}");
    }
#undef IS_GET
#undef IS_POST
#undef IS_PATCH
#undef IS_DELETE
#undef IS_PUT
}

int main(int argc, char *argv[]) {
    const char *db_path = getenv("DATABASE_URL");
    if (!db_path) db_path = "asoview.db";
    const char *port = getenv("PORT");
    if (!port) port = "3001";
    if (argc >= 2) db_path = argv[1];
    if (argc >= 3) port = argv[2];

    /* ── セキュリティ起動チェック ──────────────────────────────────────── */
    const char *jwt_secret   = getenv("JWT_SECRET");
    const char *admin_key    = getenv("ADMIN_KEY");
    const char *stripe_sk    = getenv("STRIPE_SECRET_KEY");
    const char *stripe_whsec = getenv("STRIPE_WEBHOOK_SECRET");

    if (!jwt_secret || !*jwt_secret) {
        fprintf(stderr,
            "[WARN] JWT_SECRET is not set — using insecure default. "
            "Set JWT_SECRET in production!\n");
    } else if (strlen(jwt_secret) < 32) {
        fprintf(stderr,
            "[WARN] JWT_SECRET is too short (%zu chars). "
            "Use at least 32 random characters.\n", strlen(jwt_secret));
    }
    if (!admin_key || !*admin_key) {
        fprintf(stderr,
            "[WARN] ADMIN_KEY is not set — using insecure default. "
            "Set ADMIN_KEY in production!\n");
    }
    if (stripe_sk && *stripe_sk && (!stripe_whsec || !*stripe_whsec)) {
        fprintf(stderr,
            "[WARN] STRIPE_SECRET_KEY is set but STRIPE_WEBHOOK_SECRET is missing. "
            "Webhooks will be rejected.\n");
    }

    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);

    metrics_init();

    DbConn *db = db_open(db_path);
    if (!db) return 1;
    seed_if_empty(db);

    /* ── リマインダースレッド起動 ──────────────────────────────────────── */
    pthread_t reminder_tid;
    static char reminder_db_path[256];
    strncpy(reminder_db_path, db_path, sizeof(reminder_db_path)-1);
    pthread_create(&reminder_tid, NULL, reminder_thread, reminder_db_path);
    pthread_detach(reminder_tid);

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);

    /* ── systemd socket activation (LISTEN_FDS) ──────────────────────────
     * systemd が fd 3 以降に listen ソケットを渡してくれている場合はそれを使う。
     * これにより systemd --no-block restart でゼロダウンタイム再起動が可能。 */
    const char *listen_fds_env = getenv("LISTEN_FDS");
    int listen_fds = listen_fds_env ? atoi(listen_fds_env) : 0;
    char listen_addr[64];
    snprintf(listen_addr, sizeof(listen_addr), "0.0.0.0:%s", port);

    if (listen_fds > 0) {
        /* systemd socket activation: fd 3 = 最初の listen ソケット */
        if (!mg_http_listen_fd(&mgr, 3, event_handler, db)) {
            fprintf(stderr, "Failed to wrap systemd socket fd 3\n");
            return 1;
        }
        printf("[asoview-c] Listening on systemd socket (fd=3)\n");
    } else {
        if (!mg_http_listen(&mgr, listen_addr, event_handler, db)) {
            fprintf(stderr, "Failed to listen on %s\n", listen_addr);
            return 1;
        }
        printf("[asoview-c] Listening on http://%s\n", listen_addr);
    }

    printf("[asoview-c] Press Ctrl-C to stop\n");
    while (!g_quit) mg_mgr_poll(&mgr, 100);
    printf("[asoview-c] Shutting down — draining in-flight requests...\n");

    /* グレースフルシャットダウン: 最大 5 秒間ポーリングを続けて
     * 既存接続が正常にクローズされるのを待つ */
    time_t drain_start = time(NULL);
    while (time(NULL) - drain_start < 5) {
        mg_mgr_poll(&mgr, 100);
    }
    printf("[asoview-c] Shutdown complete.\n");

    mg_mgr_free(&mgr);
    db_close(db);
    return 0;
}
